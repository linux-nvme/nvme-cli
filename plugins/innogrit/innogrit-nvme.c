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

#define CREATE_CMD
#include "innogrit-nvme.h"

static int innogrit_smart_log_additional(int argc, char **argv,
					 struct command *command,
					 struct plugin *plugin)
{
	struct nvme_smart_log smart_log = { 0 };
	struct vsc_smart_log *pvsc_smart = (struct vsc_smart_log *)smart_log.rsvd232;
	const char *desc = "Retrieve additional SMART log for the given device ";
	const char *namespace = "(optional) desired namespace";
	struct nvme_dev *dev;
	int err, i, iindex;

	struct config {
		__u32 namespace_id;
	};

	struct config cfg = {
		.namespace_id = NVME_NSID_ALL,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id,   namespace),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	nvme_get_log_smart(dev_fd(dev), cfg.namespace_id, false, &smart_log);
	nvme_show_smart_log(&smart_log, cfg.namespace_id, dev->name, NORMAL);

	printf("DW0[0-1]  Defect Cnt                    : %u\n", pvsc_smart->defect_cnt);
	printf("DW0[2-3]  Slc Spb Cnt                   : %u\n", pvsc_smart->slc_spb_cnt);
	printf("DW1       Slc Total Ec Cnt              : %u\n", pvsc_smart->slc_total_ec_cnt);
	printf("DW2       Slc Max Ec Cnt                : %u\n", pvsc_smart->slc_max_ec_cnt);
	printf("DW3       Slc Min Ec Cnt                : %u\n", pvsc_smart->slc_min_ec_cnt);
	printf("DW4       Slc Avg Ec Cnt                : %u\n", pvsc_smart->slc_avg_ec_cnt);
	printf("DW5       Total Ec Cnt                  : %u\n", pvsc_smart->total_ec_cnt);
	printf("DW6       Max Ec Cnt                    : %u\n", pvsc_smart->max_ec_cnt);
	printf("DW7       Min Ec Cnt                    : %u\n", pvsc_smart->min_ec_cnt);
	printf("DW8       Avg Ec Cnt                    : %u\n", pvsc_smart->avg_ec_cnt);
	printf("DW9       Mrd Rr Good Cnt               : %u\n", pvsc_smart->mrd_rr_good_cnt);
	printf("DW10      Ard Rr Good Cnt               : %u\n", pvsc_smart->ard_rr_good_cnt);
	printf("DW11      Preset Cnt                    : %u\n", pvsc_smart->preset_cnt);
	printf("DW12      Nvme Reset Cnt                : %u\n", pvsc_smart->nvme_reset_cnt);
	printf("DW13      Low Pwr Cnt                   : %u\n", pvsc_smart->low_pwr_cnt);
	printf("DW14      Wa                            : %u\n", pvsc_smart->wa);
	printf("DW15      Ps3 Entry Cnt                 : %u\n", pvsc_smart->ps3_entry_cnt);
	printf("DW16[0]   highest_temp[0]               : %u\n", pvsc_smart->highest_temp[0]);
	printf("DW16[1]   highest_temp[1]               : %u\n", pvsc_smart->highest_temp[1]);
	printf("DW16[2]   highest_temp[2]               : %u\n", pvsc_smart->highest_temp[2]);
	printf("DW16[3]   highest_temp[3]               : %u\n", pvsc_smart->highest_temp[3]);
	printf("DW17      weight_ec                     : %u\n", pvsc_smart->weight_ec);
	printf("DW18      slc_cap_mb                    : %u\n", pvsc_smart->slc_cap_mb);
	printf("DW19-20   nand_page_write_cnt           : %llu\n", pvsc_smart->nand_page_write_cnt);
	printf("DW21      program_error_cnt             : %u\n", pvsc_smart->program_error_cnt);
	printf("DW22      erase_error_cnt               : %u\n", pvsc_smart->erase_error_cnt);
	printf("DW23[0]   flash_type                    : %u\n", pvsc_smart->flash_type);
	printf("DW24      hs_crc_err_cnt                : %u\n", pvsc_smart->hs_crc_err_cnt);
	printf("DW25      ddr_ecc_err_cnt               : %u\n", pvsc_smart->ddr_ecc_err_cnt);
	iindex = 26;
	for (i = 0; i < (sizeof(pvsc_smart->reserved3)/4); i++) {
		if (pvsc_smart->reserved3[i] != 0)
			printf("DW%-37d : %u\n", iindex, pvsc_smart->reserved3[i]);
		iindex++;
	}

	return 0;
}

static int sort_eventlog_fn(const void *a, const void *b)
{
	const struct eventlog_addindex *l = a;
	const struct eventlog_addindex *r = b;
	int rc;

	if (l->ms > r->ms) {
		rc = 1;
	} else if (l->ms < r->ms) {
		rc = -1;
	} else {
		if (l->iindex < r->iindex)
			rc = -1;
		else
			rc = 1;
	}

	return rc;
}

static void sort_eventlog(struct eventlog *data16ksrc, unsigned int icount)
{
	struct eventlog_addindex peventlogadd[512];
	unsigned int i;

	for (i = 0; i < icount; i++) {
		memcpy(&peventlogadd[i], &data16ksrc[i], sizeof(struct eventlog));
		peventlogadd[i].iindex = i;
	}

	qsort(peventlogadd, icount, sizeof(struct eventlog_addindex), sort_eventlog_fn);

	for (i = 0; i < icount; i++)
		memcpy(&data16ksrc[i], &peventlogadd[i], sizeof(struct eventlog));
}

static unsigned char setfilecontent(char *filenamea, unsigned char *buffer,
				    unsigned int buffersize)
{
	FILE *fp = NULL;
	int rc;

	if (buffersize == 0)
		return true;
	fp = fopen(filenamea, "a+");
	rc = fwrite(buffer, 1, buffersize, fp);
	fclose(fp);
	if (rc != buffersize)
		return false;
	return true;
}

static int nvme_vucmd(int fd, unsigned char opcode, unsigned int cdw12,
		      unsigned int cdw13, unsigned int cdw14,
		      unsigned int cdw15, char *data, int data_len)
{
	struct nvme_passthru_cmd cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = opcode;
	cmd.cdw12 = cdw12;
	cmd.cdw13 = cdw13;
	cmd.cdw14 = cdw14;
	cmd.cdw15 = cdw15;
	cmd.nsid = 0;
	cmd.addr = (__u64)(__u64)(uintptr_t)data;
	cmd.data_len = data_len;
	return nvme_submit_admin_passthru(fd, &cmd, NULL);
}

static int innogrit_vsc_geteventlog(int argc, char **argv,
				    struct command *command,
				    struct plugin *plugin)
{
	time_t timep;
	struct tm *logtime;
	int icount, ioffset16k, iblock;
	char currentdir[128], filename[512];
	unsigned char data[4096], data16k[SIZE_16K], zerob[32];
	unsigned int *pcheckdata;
	unsigned int isize, icheck_stopvalue, iend;
	unsigned char bSortLog = false, bget_nextlog = true;
	struct evlg_flush_hdr *pevlog = (struct evlg_flush_hdr *)data;
	const char *desc = "Recrieve event log for the given device ";
	const char *clean_opt = "(optional) 1 for clean event log";
	struct nvme_dev *dev;
	int ret = -1;

	struct config {
		__u32 clean_flg;
	};

	struct config cfg = {
		.clean_flg = 0,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("clean_flg",   'c', &cfg.clean_flg,   clean_opt),
		OPT_END()
	};

	ret = parse_and_open(&dev, argc, argv, desc, opts);
	if (ret)
		return ret;


	if (getcwd(currentdir, 128) == NULL)
		return -1;

	time(&timep);
	logtime = localtime(&timep);
	sprintf(filename, "%s/eventlog_%02d%02d-%02d%02d%02d.elog", currentdir, logtime->tm_mon+1,
		logtime->tm_mday, logtime->tm_hour, logtime->tm_min, logtime->tm_sec);

	iblock = 0;
	ioffset16k = 0;
	memset(data16k, 0, SIZE_16K);
	memset(zerob, 0, 32);

	icount = 0;
	while (bget_nextlog) {
		if (icount % 100 == 0) {
			printf("\rWait for Dump EventLog " XCLEAN_LINE);
			fflush(stdout);
			icount = 0;
		} else if (icount % 5 == 0) {
			printf(".");
			fflush(stdout);
		}
		icount++;

		memset(data, 0, 4096);
		ret = nvme_vucmd(dev_fd(dev), NVME_VSC_GET_EVENT_LOG, 0, 0,
				 (SRB_SIGNATURE >> 32),
				 (SRB_SIGNATURE & 0xFFFFFFFF),
				 (char *)data, 4096);
		if (ret == -1)
			return ret;

		pcheckdata = (unsigned int *)&data[4096 - 32];
		icheck_stopvalue = pcheckdata[1];

		if (icheck_stopvalue == 0xFFFFFFFF) {
			isize = pcheckdata[0];
			if (isize == 0) {
				/* Finish Log */
				bget_nextlog = false;
			} else if (bSortLog) {
				/* No Full 4K Package */
				for (iend = 0; iend < isize - 32; iend += sizeof(struct eventlog)) {
					if (memcmp(&data[iend], zerob, sizeof(struct eventlog)) != 0) {
						memcpy(&data16k[ioffset16k], &data[iend], sizeof(struct eventlog));
						ioffset16k += sizeof(struct eventlog);
					}
				}
			} else {
				setfilecontent(filename, data, isize);
			}
		} else {
			/* Full 4K Package */
			if ((pevlog->signature == EVLOG_SIG) && (pevlog->log_type == 1))
				bSortLog = true;

			if (bSortLog) {
				for (iend = 0; iend < SIZE_4K; iend += sizeof(struct eventlog)) {
					if (memcmp(&data[iend], zerob, sizeof(struct eventlog)) != 0) {
						memcpy(&data16k[ioffset16k], &data[iend], sizeof(struct eventlog));
						ioffset16k += sizeof(struct eventlog);
					}
				}

				iblock++;
				if (iblock == 4) {
					sort_eventlog((struct eventlog *)(data16k + sizeof(struct evlg_flush_hdr)),
						(ioffset16k - sizeof(struct evlg_flush_hdr))/sizeof(struct eventlog));
					setfilecontent(filename, data16k, ioffset16k);
					ioffset16k = 0;
					iblock = 0;
					memset(data16k, 0, SIZE_16K);
				}
			} else {
				setfilecontent(filename, data, SIZE_4K);
			}

		}
	}

	if (bSortLog) {
		if (ioffset16k > 0) {
			sort_eventlog((struct eventlog *)(data16k + sizeof(struct evlg_flush_hdr)),
				(ioffset16k - sizeof(struct evlg_flush_hdr))/sizeof(struct eventlog));
			setfilecontent(filename, data16k, ioffset16k);
		}
	}

	printf("\r" XCLEAN_LINE "Dump eventLog finish to %s\n", filename);
	chmod(filename, 0666);

	if (cfg.clean_flg == 1) {
		printf("Clean eventlog\n");
		nvme_vucmd(dev_fd(dev), NVME_VSC_CLEAN_EVENT_LOG, 0, 0,
			   (SRB_SIGNATURE >> 32),
			   (SRB_SIGNATURE & 0xFFFFFFFF), (char *)NULL, 0);
	}

	dev_close(dev);

	return ret;
}

static int innogrit_vsc_getcdump(int argc, char **argv, struct command *command,
	struct plugin *plugin)
{
	time_t timep;
	struct tm *logtime;
	char currentdir[128], filename[512], fname[128];
	unsigned int itotal, icur;
	unsigned char data[4096];
	struct cdumpinfo cdumpinfo;
	unsigned char busevsc = false;
	unsigned int ipackcount, ipackindex;
	char fwvera[32];
	const char *desc = "Recrieve cdump data for the given device ";
	struct nvme_dev *dev;
	int ret = -1;

	OPT_ARGS(opts) = {
		OPT_END()
	};

	ret = parse_and_open(&dev, argc, argv, desc, opts);
	if (ret)
		return ret;

	if (getcwd(currentdir, 128) == NULL)
		return -1;

	time(&timep);
	logtime = localtime(&timep);

	ipackindex = 0;
	memset(data, 0, 4096);
	if (nvme_vucmd(dev_fd(dev), NVME_VSC_GET, VSC_FN_GET_CDUMP, 0x00,
		       (SRB_SIGNATURE >> 32), (SRB_SIGNATURE & 0xFFFFFFFF),
		       (char *)data, 4096) == 0) {
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
				sprintf(fname, "cdump_%02d%02d-%02d%02d%02d_%d_%s.cdp", logtime->tm_mon+1,
					logtime->tm_mday, logtime->tm_hour, logtime->tm_min, logtime->tm_sec,
					ipackindex, fwvera);
				sprintf(filename, "%s/%s", currentdir, fname);
			}
		}
	}

	if (busevsc == false) {
		memset(data, 0, 4096);
		ret = nvme_get_nsid_log(dev_fd(dev), true, 0x07,
					NVME_NSID_ALL,
					4096, data);
		if (ret != 0)
			return ret;

		ipackcount = 1;
		memcpy(&itotal, &data[4092], 4);
		sprintf(fname, "cdump_%02d%02d-%02d%02d%02d.cdp", logtime->tm_mon+1, logtime->tm_mday,
			logtime->tm_hour, logtime->tm_min, logtime->tm_sec);
		sprintf(filename, "%s/%s", currentdir, fname);
	}

	if (itotal == 0) {
		printf("no cdump data\n");
		return 0;
	}

	while (ipackindex < ipackcount) {
		memset(data, 0, 4096);
		strcpy((char *)data, "cdumpstart");
		setfilecontent(filename, data, strlen((char *)data));
		for (icur = 0; icur < itotal; icur += 4096) {
			memset(data, 0, 4096);
			if (busevsc)
				ret = nvme_vucmd(dev_fd(dev), NVME_VSC_GET,
						 VSC_FN_GET_CDUMP, 0x00,
						 (SRB_SIGNATURE >> 32),
						 (SRB_SIGNATURE & 0xFFFFFFFF),
						 (char *)data, 4096);
			else
				ret = nvme_get_nsid_log(dev_fd(dev), true,
							0x07,
							NVME_NSID_ALL, 4096, data);
			if (ret != 0)
				return ret;

			setfilecontent(filename, data, 4096);

			printf("\rWait for dump data %d%%" XCLEAN_LINE, ((icur+4096) * 100/itotal));
		}
		memset(data, 0, 4096);
		strcpy((char *)data, "cdumpend");
		setfilecontent(filename, data, strlen((char *)data));
		printf("\r%s\n", fname);
		ipackindex++;
		if (ipackindex != ipackcount) {
			memset(data, 0, 4096);
			if (busevsc)
				ret = nvme_vucmd(dev_fd(dev), NVME_VSC_GET,
						 VSC_FN_GET_CDUMP, 0x00,
						 (SRB_SIGNATURE >> 32),
						 (SRB_SIGNATURE & 0xFFFFFFFF),
						 (char *)data, 4096);
			else
				ret = nvme_get_nsid_log(dev_fd(dev), true,
							0x07,
							NVME_NSID_ALL, 4096,
							data);
			if (ret != 0)
				return ret;

			itotal = cdumpinfo.cdumppack[ipackindex].ilenth;
			memset(fwvera, 0, sizeof(fwvera));
			memcpy(fwvera, cdumpinfo.cdumppack[ipackindex].fwver, 8);
			sprintf(fname, "cdump_%02d%02d-%02d%02d%02d_%d_%s.cdp", logtime->tm_mon+1,
				logtime->tm_mday, logtime->tm_hour, logtime->tm_min, logtime->tm_sec,
				ipackindex,	fwvera);
			sprintf(filename, "%s/%s", currentdir, fname);
		}

	}

	printf("\n");
	dev_close(dev);
	return ret;
}
