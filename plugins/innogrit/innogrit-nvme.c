// SPDX-License-Identifier: GPL-2.0-or-later
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>

#include "common.h"
#include "nvme.h"
#include "libnvme.h"
#include "nvme-print.h"
#include "typedef.h"
#include "util/cleanup.h"

#define CREATE_CMD
#include "innogrit-nvme.h"

static int nvme_vucmd(struct nvme_transport_handle *hdl, unsigned char opcode,
		      unsigned int cdw12, unsigned int cdw13,
		      unsigned int cdw14, unsigned int cdw15, char *data,
		      int data_len)
{
	struct nvme_passthru_cmd cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = opcode;
	cmd.cdw2  = IGVSC_SIG;
	cmd.cdw10 = data_len / 4;
	cmd.cdw12 = cdw12;
	cmd.cdw13 = cdw13;
	cmd.cdw14 = cdw14;
	cmd.cdw15 = cdw15;
	cmd.nsid = 0xffffffff;
	cmd.addr = (__u64)(__u64)(uintptr_t)data;
	cmd.data_len = data_len;
	return nvme_submit_admin_passthru(hdl, &cmd, NULL);
}

static int getlogpage(struct nvme_transport_handle *hdl, unsigned char ilogid,
		      unsigned char ilsp, char *data, int data_len,
		      unsigned int *result)
{
	struct nvme_get_log_args args = {
		.args_size	= sizeof(args),
		.lid		= ilogid,
		.nsid		= 0xffffffff,
		.lpo		= 0,
		.lsp		= ilsp,
		.lsi		= 0,
		.rae		= true,
		.uuidx		= 0,
		.csi		= NVME_CSI_NVM,
		.ot		= false,
		.len		= data_len,
		.log		= (void *)data,
		.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
		.result		= result,
	};
	return nvme_get_log(hdl, &args);
}

static int getvsctype(struct nvme_transport_handle *hdl)
{
	unsigned char ilogid;
	char data[4096];
	struct drvinfo_t *pdrvinfo = (struct drvinfo_t *)data;

	memset(data, 0, 4096);
	// pdrvinfo by getlogpage
	for (ilogid = 0xe1; ilogid < 0xe2; ilogid++) {
		getlogpage(hdl, ilogid, 0, data, 4096, NULL);
		if (pdrvinfo->signature == 0x5A)
			return 1;
	}

	//pdrvinfo by vucmd
	nvme_vucmd(hdl, 0xfe, 0x82, 0X03, 0x00, 0, (char *)data, 4096);
	if (pdrvinfo->signature == 0x5A)
		return 1;

	return 0;
}

static int getvsc_eventlog(struct nvme_transport_handle *hdl, FILE *fp)
{
	unsigned int errcnt, rxlen, start_flag;
	int ivsctype = getvsctype(hdl);
	struct evlg_flush_hdr *pevlog;
	unsigned long long end_flag;
	char data[4096];
	int ret = -1;

	pevlog = (struct evlg_flush_hdr *)data;
	start_flag = 0;
	rxlen = 0;
	errcnt = 0;

	while (1) {
		memset(data, 0, 4096);
		if (ivsctype == 0) {
			ret = nvme_vucmd(hdl, NVME_VSC_GET_EVENT_LOG, 0, 0,
					(SRB_SIGNATURE >> 32),
					(SRB_SIGNATURE & 0xFFFFFFFF),
					(char *)data, 4096);
		} else {
			ret = nvme_vucmd(hdl, NVME_VSC_TYPE1_GET, 0x60, 0,
					0, 0, (char *)data, 4096);
		}

		if (ret == -1) {
			printf("(error)\n");
			return IG_ERROR;
		}

		if (pevlog->signature == EVLOG_SIG) {
			errcnt = 0;
		} else {
			errcnt++;
			if (errcnt > 16) {
				printf("(invalid data error)\n");
				return IG_ERROR;
			}
		}

		if (start_flag == 1) {
			end_flag = *(unsigned long long *)&data[4096 - 32];
			if (end_flag == 0xffffffff00000000)
				break;
			fwrite(data, 1, 4096, fp);
			rxlen += 4096;
			printf("\rget eventlog : %d.%d MB ", rxlen / SIZE_MB,
				(rxlen % SIZE_MB) * 100 / SIZE_MB);
		} else if (errcnt == 0) {
			printf("get eventlog by vsc command\n");
			start_flag = 1;
			fwrite(data, 1, 4096, fp);
			rxlen += 4096;
		}
	}
	printf("\n");
	return IG_SUCCESS;
}

int getlogpage_eventlog(struct nvme_transport_handle *hdl, FILE *fp)
{
	unsigned int i, result, total_size;
	char data[4096];
	int ret = 0;

	result = 0;
	ret = getlogpage(hdl, 0xcb, 0x01, data, 4096, NULL);
	if (ret)
		return IG_UNSUPPORT;

	ret = getlogpage(hdl, 0xcb, 0x02, data, 4096, &result);
	if ((ret) || (result == 0))
		return IG_UNSUPPORT;

	total_size = result * 4096;
	printf("total eventlog : %d.%d MB\n", total_size / SIZE_MB,
		(total_size % SIZE_MB) * 100 / SIZE_MB);
	for (i = 0; i <= total_size; i += 4096) {
		ret = getlogpage(hdl, 0xcb, 0x00, data, 4096, NULL);
		printf("\rget eventlog   : %d.%d MB ", i / SIZE_MB,
			(i % SIZE_MB) * 100 / SIZE_MB);
		if (ret) {
			printf("(error)\n");
			return IG_ERROR;
		}
		fwrite(data, 1, 4096, fp);
	}
	printf("\n");
	return IG_SUCCESS;
}

static int innogrit_geteventlog(int argc, char **argv,
				struct command *command,
				struct plugin *plugin)
{
	const char *desc = "Recrieve event log for the given device ";
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_file_ FILE *fp = NULL;
	char currentdir[128], filename[512];
	struct tm *logtime;
	time_t timep;
	int ret = -1;

	OPT_ARGS(opts) = {
		OPT_END()
	};

	ret = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (ret)
		return ret;

	if (getcwd(currentdir, 128) == NULL)
		return -1;

	time(&timep);
	logtime = localtime(&timep);
	sprintf(filename, "%s/eventlog_%02d%02d-%02d%02d%02d.eraw", currentdir,
		logtime->tm_mon + 1, logtime->tm_mday, logtime->tm_hour,
		logtime->tm_min, logtime->tm_sec);
	printf("output eventlog file : %s\n", filename);

	fp = fopen(filename, "a+");
	getvsctype(hdl);
	ret = getlogpage_eventlog(hdl, fp);
	if (ret == IG_UNSUPPORT)
		ret = getvsc_eventlog(hdl, fp);

	chmod(filename, 0666);

	return ret;
}

static int innogrit_vsc_getcdump(int argc, char **argv, struct command *command,
				 struct plugin *plugin)
{
	const char *desc = "Recrieve cdump data for the given device ";
	char currentdir[128], filename[512], fname[128];
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	unsigned int itotal, icur, ivsctype;
	unsigned int ipackcount, ipackindex;
	unsigned char busevsc = false;
	struct cdumpinfo cdumpinfo;
	struct tm *logtime;
	FILE *fp = NULL;
	char data[4096];
	char fwvera[32];
	time_t timep;
	int ret = -1;

	OPT_ARGS(opts) = {
		OPT_END()
	};

	ret = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (ret)
		return ret;

	ivsctype = getvsctype(hdl);

	if (getcwd(currentdir, 128) == NULL)
		return -1;

	time(&timep);
	logtime = localtime(&timep);

	ipackindex = 0;
	memset(data, 0, 4096);

	if (ivsctype == 0) {
		ret = nvme_vucmd(hdl, NVME_VSC_GET, VSC_FN_GET_CDUMP, 0x00,
		       (SRB_SIGNATURE >> 32), (SRB_SIGNATURE & 0xFFFFFFFF),
		       (char *)data, 4096);
	} else {
		ret = nvme_vucmd(hdl, NVME_VSC_TYPE1_GET, 0x82, 0x00,
		       0, 0, (char *)data, 4096);
	}

	if (ret == 0) {
		memcpy(&cdumpinfo, &data[3072], sizeof(cdumpinfo));
		if (cdumpinfo.sig == 0x5a5b5c5d) {
			busevsc = true;
			ipackcount = cdumpinfo.ipackcount;
			if (ipackcount == 0) {
				itotal = 0;
			} else {
				itotal = cdumpinfo.cdumppack[ipackindex].ilenth;
				memset(fwvera, 0, sizeof(fwvera));
				memcpy(fwvera, cdumpinfo.cdumppack[ipackindex].fwver, 8);
				sprintf(fname, "cdump_%02d%02d-%02d%02d%02d_%d_%s.cdp",
					logtime->tm_mon+1, logtime->tm_mday, logtime->tm_hour,
					logtime->tm_min, logtime->tm_sec, ipackindex, fwvera);
				sprintf(filename, "%s/%s", currentdir, fname);
				if (fp != NULL)
					fclose(fp);
				fp = fopen(filename, "a+");
			}
		}
	}

	if (busevsc == false) {
		memset(data, 0, 4096);
		ret = nvme_get_nsid_log(hdl, true, 0x07,
					NVME_NSID_ALL,
					4096, data);
		if (ret != 0)
			return ret;

		ipackcount = 1;
		memcpy(&itotal, &data[4092], 4);
		sprintf(fname, "cdump_%02d%02d-%02d%02d%02d.cdp", logtime->tm_mon+1,
			logtime->tm_mday, logtime->tm_hour, logtime->tm_min, logtime->tm_sec);
		sprintf(filename, "%s/%s", currentdir, fname);
		if (fp != NULL)
			fclose(fp);
		fp = fopen(filename, "a+");
	}

	if (itotal == 0) {
		printf("no cdump data\n");
		return 0;
	}

	while (ipackindex < ipackcount) {
		memset(data, 0, 4096);
		strcpy((char *)data, "cdumpstart");
		fwrite(data, 1, strlen((char *)data), fp);
		for (icur = 0; icur < itotal; icur += 4096) {
			memset(data, 0, 4096);
			if (busevsc) {
				if (ivsctype == 0) {
					ret = nvme_vucmd(hdl, NVME_VSC_GET,
							VSC_FN_GET_CDUMP, 0x00,
							(SRB_SIGNATURE >> 32),
							(SRB_SIGNATURE & 0xFFFFFFFF),
							(char *)data, 4096);
				} else {
					ret = nvme_vucmd(hdl, NVME_VSC_TYPE1_GET,
						0x82, 0x00,	0, 0, (char *)data, 4096);
				}
			} else {
				ret = nvme_get_nsid_log(hdl, true,
							0x07,
							NVME_NSID_ALL, 4096, data);
			}
			if (ret != 0)
				return ret;

			fwrite(data, 1, 4096, fp);
			printf("\rWait for dump data %d%%" XCLEAN_LINE,
			       ((icur + 4096) * 100 / itotal));
		}
		memset(data, 0, 4096);
		strcpy((char *)data, "cdumpend");
		fwrite(data, 1, strlen((char *)data), fp);
		printf("\r%s\n", fname);
		ipackindex++;
		if (ipackindex != ipackcount) {
			memset(data, 0, 4096);
			if (busevsc) {
				if (ivsctype == 0) {
					ret = nvme_vucmd(hdl, NVME_VSC_GET,
							VSC_FN_GET_CDUMP, 0x00,
							(SRB_SIGNATURE >> 32),
							(SRB_SIGNATURE & 0xFFFFFFFF),
							(char *)data, 4096);
				} else {
					ret = nvme_vucmd(hdl, NVME_VSC_TYPE1_GET,
						0x82, 0x00,	0, 0, (char *)data, 4096);
				}
			} else {
				ret = nvme_get_nsid_log(hdl, true,
							0x07,
							NVME_NSID_ALL, 4096,
							data);
			}
			if (ret != 0)
				return ret;

			itotal = cdumpinfo.cdumppack[ipackindex].ilenth;
			memset(fwvera, 0, sizeof(fwvera));
			memcpy(fwvera, cdumpinfo.cdumppack[ipackindex].fwver, 8);
			sprintf(fname, "cdump_%02d%02d-%02d%02d%02d_%d_%s.cdp", logtime->tm_mon+1,
				logtime->tm_mday, logtime->tm_hour, logtime->tm_min, logtime->tm_sec,
				ipackindex,	fwvera);
			if (fp != NULL)
				fclose(fp);
			fp = fopen(filename, "a+");
		}

	}

	printf("\n");
	if (fp != NULL)
		fclose(fp);
	return ret;
}
