/*
 * Copyright (c) 2015-2017 Western Digital Corporation or its affiliates.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA  02110-1301, USA.
 *
 *   Author: Chaitanya Kulkarni <chaitanya.kulkarni@hgst.com>,
 *           Dong Ho <dong.ho@hgst.com>
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>

#include "linux/nvme_ioctl.h"

#include "nvme.h"
#include "nvme-print.h"
#include "nvme-ioctl.h"
#include "plugin.h"
#include "json.h"

#include "argconfig.h"
#include "suffix.h"
#include <sys/ioctl.h>
#define CREATE_CMD
#include "wdc-nvme.h"

#define WRITE_SIZE	(sizeof(__u8) * 4096)

#define WDC_NVME_SUBCMD_SHIFT	8

#define WDC_NVME_LOG_SIZE_DATA_LEN			0x08

/* Device Config */
#define WDC_NVME_VID  			0x1c58
#define WDC_NVME_SN100_CNTL_ID	0x0003
#define WDC_NVME_SN200_CNTL_ID	0x0023

/* Capture Diagnostics */
#define WDC_NVME_CAP_DIAG_HEADER_TOC_SIZE	WDC_NVME_LOG_SIZE_DATA_LEN
#define WDC_NVME_CAP_DIAG_OPCODE			0xE6
#define WDC_NVME_CAP_DIAG_CMD_OPCODE		0xC6
#define WDC_NVME_CAP_DIAG_SUBCMD			0x00
#define WDC_NVME_CAP_DIAG_CMD				0x00

/* Crash dump */
#define WDC_NVME_CRASH_DUMP_SIZE_OPCODE		WDC_NVME_CAP_DIAG_CMD_OPCODE
#define WDC_NVME_CRASH_DUMP_SIZE_DATA_LEN	WDC_NVME_LOG_SIZE_DATA_LEN
#define WDC_NVME_CRASH_DUMP_SIZE_NDT		0x02
#define WDC_NVME_CRASH_DUMP_SIZE_CMD		0x20
#define WDC_NVME_CRASH_DUMP_SIZE_SUBCMD		0x03

#define WDC_NVME_CRASH_DUMP_OPCODE			WDC_NVME_CAP_DIAG_CMD_OPCODE
#define WDC_NVME_CRASH_DUMP_CMD				0x20
#define WDC_NVME_CRASH_DUMP_SUBCMD			0x04

/* Drive Log */
#define WDC_NVME_DRIVE_LOG_SIZE_OPCODE		WDC_NVME_CAP_DIAG_CMD_OPCODE
#define WDC_NVME_DRIVE_LOG_SIZE_DATA_LEN	WDC_NVME_LOG_SIZE_DATA_LEN
#define WDC_NVME_DRIVE_LOG_SIZE_NDT			0x02
#define WDC_NVME_DRIVE_LOG_SIZE_CMD			0x20
#define WDC_NVME_DRIVE_LOG_SIZE_SUBCMD		0x01

#define WDC_NVME_DRIVE_LOG_OPCODE			WDC_NVME_CAP_DIAG_CMD_OPCODE
#define WDC_NVME_DRIVE_LOG_CMD				WDC_NVME_LOG_SIZE_DATA_LEN
#define WDC_NVME_DRIVE_LOG_SUBCMD			0x00

/* Purge and Purge Monitor */
#define WDC_NVME_PURGE_CMD_OPCODE			0xDD
#define WDC_NVME_PURGE_MONITOR_OPCODE		0xDE
#define WDC_NVME_PURGE_MONITOR_DATA_LEN		0x2F
#define WDC_NVME_PURGE_MONITOR_CMD_CDW10	0x0000000C
#define WDC_NVME_PURGE_MONITOR_TIMEOUT		0x7530
#define WDC_NVME_PURGE_CMD_SEQ_ERR			0x0C
#define WDC_NVME_PURGE_INT_DEV_ERR			0x06

#define WDC_NVME_PURGE_STATE_IDLE			0x00
#define WDC_NVME_PURGE_STATE_DONE			0x01
#define WDC_NVME_PURGE_STATE_BUSY			0x02
#define WDC_NVME_PURGE_STATE_REQ_PWR_CYC	0x03
#define WDC_NVME_PURGE_STATE_PWR_CYC_PURGE	0x04

/* Clear dumps */
#define WDC_NVME_CLEAR_DUMP_OPCODE			0xFF
#define WDC_NVME_CLEAR_CRASH_DUMP_CMD		0x03
#define WDC_NVME_CLEAR_CRASH_DUMP_SUBCMD	0x05

/* Additional Smart Log */
#define WDC_ADD_LOG_BUF_LEN							0x4000
#define WDC_NVME_ADD_LOG_OPCODE						0xC1
#define WDC_GET_LOG_PAGE_SSD_PERFORMANCE			0x37
#define WDC_NVME_GET_STAT_PERF_INTERVAL_LIFETIME	0x0F

/* C2 Log Page */
#define WDC_NVME_GET_AVAILABLE_LOG_PAGES_OPCODE		0xC2
#define WDC_C2_LOG_BUF_LEN							0x1000
#define WDC_C2_LOG_PAGES_SUPPORTED_ID				0x08

/* CA Log Page */
#define WDC_NVME_GET_DEVICE_INFO_LOG_OPCODE			0xCA
#define WDC_CA_LOG_BUF_LEN							0x80

static int wdc_get_serial_name(int fd, char *file, size_t len, char *suffix);
static int wdc_create_log_file(char *file, __u8 *drive_log_data,
		__u32 drive_log_length);
static int wdc_do_clear_dump(int fd, __u8 opcode, __u32 cdw12);
static int wdc_do_dump(int fd, __u32 opcode,__u32 data_len, __u32 cdw10,
		__u32 cdw12, __u32 dump_length, char *file);
static int wdc_do_crash_dump(int fd, char *file);
static int wdc_crash_dump(int fd, char *file);
static int wdc_get_crash_dump(int argc, char **argv, struct command *command,
		struct plugin *plugin);
static int wdc_do_drive_log(int fd, char *file);
static int wdc_drive_log(int argc, char **argv, struct command *command,
		struct plugin *plugin);
static const char* wdc_purge_mon_status_to_string(__u32 status);
static int wdc_purge(int argc, char **argv,
		struct command *command, struct plugin *plugin);
static int wdc_purge_monitor(int argc, char **argv,
		struct command *command, struct plugin *plugin);
static int wdc_nvme_check_supported_log_page(int fd, __u8 log_id);

/* Drive log data size */
struct wdc_log_size {
	__le32	log_size;
};

/* Purge monitor response */
struct wdc_nvme_purge_monitor_data {
	__le16 	rsvd1;
	__le16 	rsvd2;
	__le16 	first_erase_failure_cnt;
	__le16 	second_erase_failure_cnt;
	__le16 	rsvd3;
	__le16 	programm_failure_cnt;
	__le32 	rsvd4;
	__le32 	rsvd5;
	__le32 	entire_progress_total;
	__le32 	entire_progress_current;
	__u8   	rsvd6[14];
};

/* Additional Smart Log */
struct wdc_log_page_header {
	uint8_t	num_subpages;
	uint8_t	reserved;
	__le16	total_log_size;
};

struct wdc_log_page_subpage_header {
	uint8_t	spcode;
	uint8_t	pcset;
	__le16	subpage_length;
};

struct wdc_ssd_perf_stats {
	__le64	hr_cmds;		/* Host Read Commands				*/
	__le64	hr_blks;		/* Host Read Blocks					*/
	__le64	hr_ch_cmds;		/* Host Read Cache Hit Commands		*/
	__le64	hr_ch_blks;		/* Host Read Cache Hit Blocks		*/
	__le64	hr_st_cmds;		/* Host Read Stalled Commands		*/
	__le64	hw_cmds;		/* Host Write Commands				*/
	__le64	hw_blks;		/* Host Write Blocks				*/
	__le64	hw_os_cmds;		/* Host Write Odd Start Commands	*/
	__le64	hw_oe_cmds;		/* Host Write Odd End Commands		*/
	__le64	hw_st_cmds;		/* Host Write Commands Stalled		*/
	__le64	nr_cmds;		/* NAND Read Commands				*/
	__le64	nr_blks;		/* NAND Read Blocks					*/
	__le64	nw_cmds;		/* NAND Write Commands				*/
	__le64	nw_blks;		/* NAND Write Blocks				*/
	__le64	nrbw;			/* NAND Read Before Write			*/
};

/* Additional C2 Log Page */
struct wdc_c2_log_page_header {
	__le32	length;
	__le32	version;
};

struct wdc_c2_log_subpage_header {
	__le32	length;
	__le32	entry_id;
	__le32	data;
};

struct wdc_c2_cbs_data {
	__le32	length;
	__u8	data[];
};

struct __attribute__((__packed__)) wdc_ssd_ca_perf_stats {
	__le64	nand_bytes_wr_lo;			/* 0x00 - NAND Bytes Written lo				*/
	__le64	nand_bytes_wr_hi;			/* 0x08 - NAND Bytes Written hi				*/
	__le64	nand_bytes_rd_lo;			/* 0x10 - NAND Bytes Read lo				*/
	__le64	nand_bytes_rd_hi;			/* 0x18 - NAND Bytes Read hi				*/
	__le64	nand_bad_block;				/* 0x20 - NAND Bad Block Count				*/
	__le64	uncorr_read_count;			/* 0x28 - Uncorrectable Read Count			*/
	__le64	ecc_error_count;			/* 0x30 - Soft ECC Error Count				*/
	__le32	ssd_detect_count;			/* 0x38 - SSD End to End Detection Count	*/
	__le32	ssd_correct_count;			/* 0x3C - SSD End to End Correction Count	*/
	__le32	data_percent_used;			/* 0x40 - System Data Percent Used			*/
	__le32	data_erase_max;				/* 0x44 - User Data Erase Counts			*/
	__le32	data_erase_min;				/* 0x48 - User Data Erase Counts			*/
	__le64	refresh_count;				/* 0x4c - Refresh Count						*/
	__le64	program_fail;				/* 0x54 - Program Fail Count				*/
	__le64	user_erase_fail;			/* 0x5C - User Data Erase Fail Count		*/
	__le64	system_erase_fail;			/* 0x64 - System Area Erase Fail Count		*/
	__le16	thermal_throttle_status;	/* 0x6C - Thermal Throttling Status			*/
	__le16	thermal_throttle_count;		/* 0x6E - Thermal Throttling Count			*/
	__le64	pcie_corr_error;			/* 0x70 - pcie Correctable Error Count		*/
	__le32	rsvd1;						/* 0x78 - Reserved							*/
	__le32	rsvd2;						/* 0x7C - Reserved							*/
};

static double safe_div_fp(double numerator, double denominator)
{
	return denominator ? numerator / denominator : 0;
}

static double calc_percent(uint64_t numerator, uint64_t denominator)
{
	return denominator ?
		(uint64_t)(((double)numerator / (double)denominator) * 100) : 0;
}

static int wdc_check_device(int fd)
{
	int ret;
	struct nvme_id_ctrl ctrl;

	memset(&ctrl, 0, sizeof (struct nvme_id_ctrl));
	ret = nvme_identify_ctrl(fd, &ctrl);
	if (ret) {
		fprintf(stderr, "ERROR : WDC : nvme_identify_ctrl() failed "
				"0x%x\n", ret);
		return -1;
	}
	ret = -1;
	/* WDC : ctrl->cntlid == PCI Device ID, use that with VID to identify WDC Devices */
	if ((le32_to_cpu(ctrl.vid) == WDC_NVME_VID) &&
		((le32_to_cpu(ctrl.cntlid) == WDC_NVME_SN100_CNTL_ID) ||
		(le32_to_cpu(ctrl.cntlid) == WDC_NVME_SN200_CNTL_ID)))
		ret = 0;
	else
		fprintf(stderr, "WARNING : WDC : Device not supported\n");

	return ret;
}

static bool wdc_check_device_sn100(int fd)
{
	bool ret;
	struct nvme_id_ctrl ctrl;

	memset(&ctrl, 0, sizeof (struct nvme_id_ctrl));
	ret = nvme_identify_ctrl(fd, &ctrl);
	if (ret) {
		fprintf(stderr, "ERROR : WDC : nvme_identify_ctrl() failed "
				"0x%x\n", ret);
		return false;
	}

	/* WDC : ctrl->cntlid == PCI Device ID, use that with VID to identify WDC Devices */
	if ((le32_to_cpu(ctrl.vid) == WDC_NVME_VID) &&
		(le32_to_cpu(ctrl.cntlid) == WDC_NVME_SN100_CNTL_ID))
		ret = true;
	else
		ret = false;

	return ret;
}

static bool wdc_check_device_sn200(int fd)
{
	bool ret;
	struct nvme_id_ctrl ctrl;

	memset(&ctrl, 0, sizeof (struct nvme_id_ctrl));
	ret = nvme_identify_ctrl(fd, &ctrl);
	if (ret) {
		fprintf(stderr, "ERROR : WDC : nvme_identify_ctrl() failed "
				"0x%x\n", ret);
		return false;
	}

	/* WDC : ctrl->cntlid == PCI Device ID, use that with VID to identify WDC Devices */
	if ((le32_to_cpu(ctrl.vid) == WDC_NVME_VID) &&
		(le32_to_cpu(ctrl.cntlid) == WDC_NVME_SN200_CNTL_ID))
		ret = true;
	else
		ret = false;

	return ret;
}


static int wdc_get_serial_name(int fd, char *file, size_t len, char *suffix)
{
	int i;
	int ret;
	char orig[PATH_MAX] = {0};
	struct nvme_id_ctrl ctrl;

	i = sizeof (ctrl.sn) - 1;
	strncpy(orig, file, PATH_MAX);
	memset(file, 0, len);
	memset(&ctrl, 0, sizeof (struct nvme_id_ctrl));
	ret = nvme_identify_ctrl(fd, &ctrl);
	if (ret) {
		fprintf(stderr, "ERROR : WDC : nvme_identify_ctrl() failed "
				"0x%x\n", ret);
		return -1;
	}
	/* Remove trailing spaces from the name */
	while (i && ctrl.sn[i] == ' ') {
		ctrl.sn[i] = '\0';
		i--;
	}
	snprintf(file, len, "%s%s%s.bin", orig, ctrl.sn, suffix);
	return 0;
}

static int wdc_create_log_file(char *file, __u8 *drive_log_data,
		__u32 drive_log_length)
{
	int fd;
	int ret;

	if (drive_log_length == 0) {
		fprintf(stderr, "ERROR : WDC: invalid log file length\n");
		return -1;
	}

	fd = open(file, O_WRONLY | O_CREAT | O_TRUNC, 0666);
	if (fd < 0) {
		fprintf(stderr, "ERROR : WDC: open : %s\n", strerror(errno));
		return -1;
	}

	while (drive_log_length > WRITE_SIZE) {
		ret = write(fd, drive_log_data, WRITE_SIZE);
		if (ret < 0) {
			fprintf (stderr, "ERROR : WDC: write : %s\n", strerror(errno));
			return -1;
		}
		drive_log_data += WRITE_SIZE;
		drive_log_length -= WRITE_SIZE;
	}

	ret = write(fd, drive_log_data, drive_log_length);
	if (ret < 0) {
		fprintf(stderr, "ERROR : WDC : write : %s\n", strerror(errno));
		return -1;
	}

	if (fsync(fd) < 0) {
		fprintf(stderr, "ERROR : WDC : fsync : %s\n", strerror(errno));
		return -1;
	}
	close(fd);
	return 0;
}

static int wdc_nvme_check_supported_log_page(int fd, __u8 log_id)
{
	int i;
	int ret = -1;
	int found = 0;
	__u8* data;
	__u32 length = 0;
	struct wdc_c2_cbs_data *cbs_data;
	struct wdc_c2_log_page_header *hdr_ptr;
	struct wdc_c2_log_subpage_header *sph;

	if ((data = (__u8*) malloc(sizeof (__u8) * WDC_C2_LOG_BUF_LEN)) == NULL) {
		fprintf(stderr, "ERROR : WDC : malloc : %s\n", strerror(errno));
		return ret;
	}
	memset(data, 0, sizeof (__u8) * WDC_C2_LOG_BUF_LEN);

	/* get the log page length */
	ret = nvme_get_log(fd, 0xFFFFFFFF, WDC_NVME_GET_AVAILABLE_LOG_PAGES_OPCODE,
			   NVME_NO_LOG_LSP, NVME_NO_LOG_LPO,
			   WDC_C2_LOG_BUF_LEN, data);
	if (ret) {
		fprintf(stderr, "ERROR : WDC : Unable to get C2 Log Page length, ret = %d\n", ret);
		goto out;
	}

	hdr_ptr = (struct wdc_c2_log_page_header *)data;

	if (hdr_ptr->length > WDC_C2_LOG_BUF_LEN) {
		fprintf(stderr, "ERROR : WDC : data length > buffer size : 0x%x\n", hdr_ptr->length);
		goto out;
	}

	ret = nvme_get_log(fd, 0xFFFFFFFF, WDC_NVME_GET_AVAILABLE_LOG_PAGES_OPCODE,
			   NVME_NO_LOG_LSP, NVME_NO_LOG_LPO,
			   hdr_ptr->length, data);
	/* parse the data until the List of log page ID's is found */
	if (ret) {
		fprintf(stderr, "ERROR : WDC : Unable to read C2 Log Page data, ret = %d\n", ret);
		goto out;
	}

	length = sizeof(struct wdc_c2_log_page_header);
	while (length < hdr_ptr->length) {
		sph = (struct wdc_c2_log_subpage_header *)(data + length);

		if (sph->entry_id == WDC_C2_LOG_PAGES_SUPPORTED_ID) {
			cbs_data = (struct wdc_c2_cbs_data *)&sph->data;

			for (i = 0; i < cbs_data->length; i++) {
				if (log_id == cbs_data->data[i]) {
					found = 1;
					ret = 0;
					break;
				}
			}

			if (!found) {
				fprintf(stderr, "ERROR : WDC : Log Page 0x%x not supported\n", log_id);
				fprintf(stderr, "WDC : Supported Log Pages:\n");
				/* print the supported pages */
				d((__u8 *)&sph->data + 4, sph->length - 12, 16, 1);
				ret = -1;
			}
			break;
		}
		length += le32_to_cpu(sph->length);
	}
out:
	free(data);
	return ret;
}

static int wdc_do_clear_dump(int fd, __u8 opcode, __u32 cdw12)
{
	int ret;
	struct nvme_admin_cmd admin_cmd;

	memset(&admin_cmd, 0, sizeof (struct nvme_admin_cmd));
	admin_cmd.opcode = opcode;
	admin_cmd.cdw12 = cdw12;
	ret = nvme_submit_passthru(fd, NVME_IOCTL_ADMIN_CMD, &admin_cmd);
	if (ret != 0) {
		fprintf(stdout, "ERROR : WDC : Crash dump erase failed\n");
	}
	fprintf(stderr, "NVMe Status:%s(%x)\n", nvme_status_to_string(ret), ret);
	return ret;
}

static __u32 wdc_dump_length(int fd, __u32 opcode, __u32 cdw10, __u32 cdw12, __u32 *dump_length)
{
	int ret;
	__u8 buf[WDC_NVME_LOG_SIZE_DATA_LEN] = {0};
	struct wdc_log_size *l;
	struct nvme_admin_cmd admin_cmd;

	l = (struct wdc_log_size *) buf;
	memset(&admin_cmd, 0, sizeof (struct nvme_admin_cmd));
	admin_cmd.opcode = opcode;
	admin_cmd.addr = (__u64)(uintptr_t)buf;
	admin_cmd.data_len = WDC_NVME_LOG_SIZE_DATA_LEN;
	admin_cmd.cdw10 = cdw10;
	admin_cmd.cdw12 = cdw12;

	ret = nvme_submit_passthru(fd, NVME_IOCTL_ADMIN_CMD, &admin_cmd);
	if (ret != 0) {
		l->log_size = 0;
		ret = -1;
		fprintf(stderr, "ERROR : WDC : reading dump length failed\n");
		fprintf(stderr, "NVMe Status:%s(%x)\n", nvme_status_to_string(ret), ret);
		return ret;
	}

	if (opcode == WDC_NVME_CAP_DIAG_OPCODE)
		*dump_length = buf[0x04] << 24 | buf[0x05] << 16 | buf[0x06] << 8 | buf[0x07];
	else
		*dump_length = le32_to_cpu(l->log_size);
	return ret;
}

static int wdc_do_dump(int fd, __u32 opcode,__u32 data_len, __u32 cdw10,
		__u32 cdw12, __u32 dump_length, char *file)
{
	int ret;
	__u8 *dump_data;
	struct nvme_admin_cmd admin_cmd;

	dump_data = (__u8 *) malloc(sizeof (__u8) * dump_length);
	if (dump_data == NULL) {
		fprintf(stderr, "ERROR : malloc : %s\n", strerror(errno));
		return -1;
	}
	memset(dump_data, 0, sizeof (__u8) * dump_length);
	memset(&admin_cmd, 0, sizeof (struct nvme_admin_cmd));
	admin_cmd.opcode = opcode;
	admin_cmd.addr = (__u64)(uintptr_t)dump_data;
	admin_cmd.data_len = data_len;
	admin_cmd.cdw10 = cdw10;
	admin_cmd.cdw12 = cdw12;

	ret = nvme_submit_passthru(fd, NVME_IOCTL_ADMIN_CMD, &admin_cmd);
	fprintf(stderr, "NVMe Status:%s(%x)\n", nvme_status_to_string(ret), ret);
	if (ret == 0) {
		ret = wdc_create_log_file(file, dump_data, dump_length);
	}
	free(dump_data);
	return ret;
}

static int wdc_do_cap_diag(int fd, char *file)
{
	int ret;
	__u32 cap_diag_length;

	ret = wdc_dump_length(fd, WDC_NVME_CAP_DIAG_OPCODE,
						WDC_NVME_CAP_DIAG_HEADER_TOC_SIZE,
						0x00,
						&cap_diag_length);
	if (ret == -1) {
		return -1;
	}
	if (cap_diag_length == 0) {
		fprintf(stderr, "INFO : WDC : Capture Dignostics log is empty\n");
	} else {
		ret = wdc_do_dump(fd, WDC_NVME_CAP_DIAG_OPCODE, cap_diag_length,
				cap_diag_length,
				(WDC_NVME_CAP_DIAG_SUBCMD << WDC_NVME_SUBCMD_SHIFT) |
				 WDC_NVME_CAP_DIAG_CMD, cap_diag_length, file);

	}
	return ret;
}

static int wdc_cap_diag(int argc, char **argv, struct command *command,
		struct plugin *plugin)
{
	char *desc = "Capture Diagnostics Log.";
	char *file = "Output file pathname.";
	char f[PATH_MAX] = {0};
	int fd;

	struct config {
		char *file;
	};

	struct config cfg = {
		.file = NULL
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"output-file", 'o', "FILE", CFG_STRING, &cfg.file, required_argument, file},
		{ NULL, '\0', NULL, CFG_NONE, NULL, no_argument, desc},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, NULL, 0);
	if (fd < 0)
		return fd;

	wdc_check_device(fd);
	if (cfg.file != NULL) {
		strncpy(f, cfg.file, PATH_MAX);
	}
	if (wdc_get_serial_name(fd, f, PATH_MAX, "cap_diag") == -1) {
		fprintf(stderr, "ERROR : WDC: failed to generate file name\n");
		return -1;
	}
	return wdc_do_cap_diag(fd, f);
}

static int wdc_do_crash_dump(int fd, char *file)
{
	int ret;
	__u32 crash_dump_length;
	__u8 opcode = WDC_NVME_CLEAR_DUMP_OPCODE;
	__u32 cdw12 = ((WDC_NVME_CLEAR_CRASH_DUMP_SUBCMD << WDC_NVME_SUBCMD_SHIFT) |
			WDC_NVME_CLEAR_CRASH_DUMP_CMD);

	ret = wdc_dump_length(fd, WDC_NVME_CRASH_DUMP_SIZE_OPCODE,
			WDC_NVME_CRASH_DUMP_SIZE_NDT,
			((WDC_NVME_CRASH_DUMP_SIZE_SUBCMD <<
			WDC_NVME_SUBCMD_SHIFT) | WDC_NVME_CRASH_DUMP_SIZE_CMD),
			&crash_dump_length);
	if (ret == -1) {
		return -1;
	}
	if (crash_dump_length == 0) {
		fprintf(stderr, "INFO : WDC: Crash dump is empty\n");
	} else {
		ret = wdc_do_dump(fd, WDC_NVME_CRASH_DUMP_OPCODE, crash_dump_length,
				crash_dump_length,
				(WDC_NVME_CRASH_DUMP_SUBCMD << WDC_NVME_SUBCMD_SHIFT) |
				 WDC_NVME_CRASH_DUMP_CMD, crash_dump_length, file);
		if (ret == 0)
			ret = wdc_do_clear_dump(fd, opcode, cdw12);
	}
	return ret;
}

static int wdc_crash_dump(int fd, char *file)
{
	char f[PATH_MAX] = {0};

	if (file != NULL) {
		strncpy(f, file, PATH_MAX);
	}
	if (wdc_get_serial_name(fd, f, PATH_MAX, "crash_dump") == -1) {
		fprintf(stderr, "ERROR : WDC : failed to generate file name\n");
		return -1;
	}
	return wdc_do_crash_dump(fd, f);
}

static int wdc_do_drive_log(int fd, char *file)
{
	int ret;
	__u8 *drive_log_data;
	__u32 drive_log_length;
	struct nvme_admin_cmd admin_cmd;

	ret = wdc_dump_length(fd, WDC_NVME_DRIVE_LOG_SIZE_OPCODE,
			WDC_NVME_DRIVE_LOG_SIZE_NDT,
			(WDC_NVME_DRIVE_LOG_SIZE_SUBCMD <<
			WDC_NVME_SUBCMD_SHIFT | WDC_NVME_DRIVE_LOG_SIZE_CMD),
			&drive_log_length);
	if (ret == -1) {
		return -1;
	}

	drive_log_data = (__u8 *) malloc(sizeof (__u8) * drive_log_length);
	if (drive_log_data == NULL) {
		fprintf(stderr, "ERROR : WDC : malloc : %s\n", strerror(errno));
		return -1;
	}

	memset(drive_log_data, 0, sizeof (__u8) * drive_log_length);
	memset(&admin_cmd, 0, sizeof (struct nvme_admin_cmd));
	admin_cmd.opcode = WDC_NVME_DRIVE_LOG_OPCODE;
	admin_cmd.addr = (__u64)(uintptr_t)drive_log_data;
	admin_cmd.data_len = drive_log_length;
	admin_cmd.cdw10 = drive_log_length;
	admin_cmd.cdw12 = ((WDC_NVME_DRIVE_LOG_SUBCMD <<
				WDC_NVME_SUBCMD_SHIFT) | WDC_NVME_DRIVE_LOG_SIZE_CMD);

	ret = nvme_submit_passthru(fd, NVME_IOCTL_ADMIN_CMD, &admin_cmd);
	fprintf(stderr, "NVMe Status:%s(%x)\n", nvme_status_to_string(ret),
			ret);
	if (ret == 0) {
		ret = wdc_create_log_file(file, drive_log_data, drive_log_length);
	}
	free(drive_log_data);
	return ret;
}

static int wdc_drive_log(int argc, char **argv, struct command *command,
		struct plugin *plugin)
{
	char *desc = "Capture Drive Log.";
	char *file = "Output file pathname.";
	char f[PATH_MAX] = {0};
	int fd;
	struct config {
		char *file;
	};

	struct config cfg = {
		.file = NULL
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"output-file", 'o', "FILE", CFG_STRING, &cfg.file, required_argument, file},
		{ NULL, '\0', NULL, CFG_NONE, NULL, no_argument, desc},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, NULL, 0);
	if (fd < 0)
		return fd;

	wdc_check_device(fd);
	if (cfg.file != NULL) {
		strncpy(f, cfg.file, PATH_MAX);
	}
	if (wdc_get_serial_name(fd, f, PATH_MAX, "drive_log") == -1) {
		fprintf(stderr, "ERROR : WDC : failed to generate file name\n");
		return -1;
	}
	return wdc_do_drive_log(fd, f);
}

static int wdc_get_crash_dump(int argc, char **argv, struct command *command,
		struct plugin *plugin)
{
	char *desc = "Get Crash Dump.";
	char *file = "Output file pathname.";
	int fd;
	int ret;
	struct config {
		char *file;
	};

	struct config cfg = {
		.file = NULL,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"output-file", 'o', "FILE", CFG_STRING, &cfg.file, required_argument, file},
		{ NULL, '\0', NULL, CFG_NONE, NULL, no_argument, desc},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, NULL, 0);
	if (fd < 0)
		return fd;

	wdc_check_device(fd);
	ret = wdc_crash_dump(fd, cfg.file);
	if (ret != 0) {
		fprintf(stderr, "ERROR : WDC : failed to read crash dump\n");
	}
	return ret;
}

static void wdc_do_id_ctrl(__u8 *vs, struct json_object *root)
{
	char vsn[24] = {0};
	int base = 3072;
	int vsn_start = 3081;

	memcpy(vsn, &vs[vsn_start - base], sizeof(vsn));
	if (root)
		json_object_add_value_string(root, "wdc vsn", strlen(vsn) > 1 ? vsn : "NULL");
	else
		printf("wdc vsn : %s\n", strlen(vsn) > 1 ? vsn : "NULL");
}

static int wdc_id_ctrl(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	return __id_ctrl(argc, argv, cmd, plugin, wdc_do_id_ctrl);
}

static const char* wdc_purge_mon_status_to_string(__u32 status)
{
	const char *str;

	switch (status) {
	case WDC_NVME_PURGE_STATE_IDLE:
		str = "Purge State Idle.";
		break;
	case WDC_NVME_PURGE_STATE_DONE:
		str = "Purge State Done.";
		break;
	case WDC_NVME_PURGE_STATE_BUSY:
		str = "Purge State Busy.";
		break;
	case WDC_NVME_PURGE_STATE_REQ_PWR_CYC:
		str = "Purge Operation resulted in an error that requires "
			"power cycle.";
		break;
	case WDC_NVME_PURGE_STATE_PWR_CYC_PURGE:
		str = "The previous purge operation was interrupted by a power "
			"cycle\nor reset interruption. Other commands may be "
			"rejected until\nPurge Execute is issued and "
			"completed.";
		break;
	default:
		str = "Unknown.";
	}
	return str;
}

static int wdc_purge(int argc, char **argv,
		struct command *command, struct plugin *plugin)
{
	char *desc = "Send a Purge command.";
	char *err_str;
	int fd;
	int ret;
	struct nvme_passthru_cmd admin_cmd;
	const struct argconfig_commandline_options command_line_options[] = {
		{ NULL, '\0', NULL, CFG_NONE, NULL, no_argument, desc },
		{NULL}
	};

	err_str = "";
	memset(&admin_cmd, 0, sizeof (admin_cmd));
	admin_cmd.opcode = WDC_NVME_PURGE_CMD_OPCODE;

	fd = parse_and_open(argc, argv, desc, command_line_options, NULL, 0);
	if (fd < 0)
		return fd;

	wdc_check_device(fd);
	ret = nvme_submit_passthru(fd, NVME_IOCTL_ADMIN_CMD, &admin_cmd);
	if (ret > 0) {
		switch (ret) {
		case WDC_NVME_PURGE_CMD_SEQ_ERR:
			err_str = "ERROR : WDC : Cannot execute purge, "
					"Purge operation is in progress.\n";
			break;
		case WDC_NVME_PURGE_INT_DEV_ERR:
			err_str = "ERROR : WDC : Internal Device Error.\n";
			break;
		default:
			err_str = "ERROR : WDC\n";
		}
	}
	fprintf(stderr, "%s", err_str);
	fprintf(stderr, "NVMe Status:%s(%x)\n", nvme_status_to_string(ret), ret);
	return ret;
}

static int wdc_purge_monitor(int argc, char **argv,
		struct command *command, struct plugin *plugin)
{
	char *desc = "Send a Purge Monitor command.";
	int fd;
	int ret;
	__u8 output[WDC_NVME_PURGE_MONITOR_DATA_LEN];
	double progress_percent;
	struct nvme_passthru_cmd admin_cmd;
	struct wdc_nvme_purge_monitor_data *mon;
	const struct argconfig_commandline_options command_line_options[] = {
		{ NULL, '\0', NULL, CFG_NONE, NULL, no_argument, desc },
		{NULL}
	};

	memset(output, 0, sizeof (output));
	memset(&admin_cmd, 0, sizeof (struct nvme_admin_cmd));
	admin_cmd.opcode = WDC_NVME_PURGE_MONITOR_OPCODE;
	admin_cmd.addr = (__u64)(uintptr_t)output;
	admin_cmd.data_len = WDC_NVME_PURGE_MONITOR_DATA_LEN;
	admin_cmd.cdw10 = WDC_NVME_PURGE_MONITOR_CMD_CDW10;
	admin_cmd.timeout_ms = WDC_NVME_PURGE_MONITOR_TIMEOUT;

	fd = parse_and_open(argc, argv, desc, command_line_options, NULL, 0);
	if (fd < 0)
		return fd;

	wdc_check_device(fd);
	ret = nvme_submit_passthru(fd, NVME_IOCTL_ADMIN_CMD, &admin_cmd);
	if (ret == 0) {
		mon = (struct wdc_nvme_purge_monitor_data *) output;
		printf("Purge state = 0x%0x\n", admin_cmd.result);
		printf("%s\n", wdc_purge_mon_status_to_string(admin_cmd.result));
		if (admin_cmd.result == WDC_NVME_PURGE_STATE_BUSY) {
			progress_percent =
				((double)le32_to_cpu(mon->entire_progress_current) * 100) /
				le32_to_cpu(mon->entire_progress_total);
			printf("Purge Progress = %f%%\n", progress_percent);
		}
	}
	fprintf(stderr, "NVMe Status:%s(%x)\n", nvme_status_to_string(ret), ret);
	return ret;
}

static void wdc_print_log_normal(struct wdc_ssd_perf_stats *perf)
{
	printf("  C1 Log Page Performance Statistics :- \n");
	printf("  Host Read Commands                             %20"PRIu64"\n",
			(uint64_t)le64_to_cpu(perf->hr_cmds));
	printf("  Host Read Blocks                               %20"PRIu64"\n",
			(uint64_t)le64_to_cpu(perf->hr_blks));
	printf("  Average Read Size                              %20lf\n",
			safe_div_fp((le64_to_cpu(perf->hr_blks)), (le64_to_cpu(perf->hr_cmds))));
	printf("  Host Read Cache Hit Commands                   %20"PRIu64"\n",
			(uint64_t)le64_to_cpu(perf->hr_ch_cmds));
	printf("  Host Read Cache Hit_Percentage                 %20"PRIu64"%%\n",
			(uint64_t) calc_percent(le64_to_cpu(perf->hr_ch_cmds), le64_to_cpu(perf->hr_cmds)));
	printf("  Host Read Cache Hit Blocks                     %20"PRIu64"\n",
			(uint64_t)le64_to_cpu(perf->hr_ch_blks));
	printf("  Average Read Cache Hit Size                    %20f\n",
			safe_div_fp((le64_to_cpu(perf->hr_ch_blks)), (le64_to_cpu(perf->hr_ch_cmds))));
	printf("  Host Read Commands Stalled                     %20"PRIu64"\n",
			(uint64_t)le64_to_cpu(perf->hr_st_cmds));
	printf("  Host Read Commands Stalled Percentage          %20"PRIu64"%%\n",
			(uint64_t)calc_percent((le64_to_cpu(perf->hr_st_cmds)), le64_to_cpu(perf->hr_cmds)));
	printf("  Host Write Commands                            %20"PRIu64"\n",
			(uint64_t)le64_to_cpu(perf->hw_cmds));
	printf("  Host Write Blocks                              %20"PRIu64"\n",
			(uint64_t)le64_to_cpu(perf->hw_blks));
	printf("  Average Write Size                             %20f\n",
			safe_div_fp((le64_to_cpu(perf->hw_blks)), (le64_to_cpu(perf->hw_cmds))));
	printf("  Host Write Odd Start Commands                  %20"PRIu64"\n",
			(uint64_t)le64_to_cpu(perf->hw_os_cmds));
	printf("  Host Write Odd Start Commands Percentage       %20"PRIu64"%%\n",
			(uint64_t)calc_percent((le64_to_cpu(perf->hw_os_cmds)), (le64_to_cpu(perf->hw_cmds))));
	printf("  Host Write Odd End Commands                    %20"PRIu64"\n",
			(uint64_t)le64_to_cpu(perf->hw_oe_cmds));
	printf("  Host Write Odd End Commands Percentage         %20"PRIu64"%%\n",
			(uint64_t)calc_percent((le64_to_cpu(perf->hw_oe_cmds)), (le64_to_cpu((perf->hw_cmds)))));
	printf("  Host Write Commands Stalled                    %20"PRIu64"\n",
		(uint64_t)le64_to_cpu(perf->hw_st_cmds));
	printf("  Host Write Commands Stalled Percentage         %20"PRIu64"%%\n",
		(uint64_t)calc_percent((le64_to_cpu(perf->hw_st_cmds)), (le64_to_cpu(perf->hw_cmds))));
	printf("  NAND Read Commands                             %20"PRIu64"\n",
		(uint64_t)le64_to_cpu(perf->nr_cmds));
	printf("  NAND Read Blocks Commands                      %20"PRIu64"\n",
		(uint64_t)le64_to_cpu(perf->nr_blks));
	printf("  Average NAND Read Size                         %20f\n",
		safe_div_fp((le64_to_cpu(perf->nr_blks)), (le64_to_cpu((perf->nr_cmds)))));
	printf("  Host Write Odd Start Commands                  %20"PRIu64"\n",
			(uint64_t)le64_to_cpu(perf->hw_os_cmds));
	printf("  Nand Write Commands                            %20"PRIu64"\n",
			(uint64_t)le64_to_cpu(perf->nw_cmds));
	printf("  NAND Write Blocks                              %20"PRIu64"\n",
			(uint64_t)le64_to_cpu(perf->nw_blks));
	printf("  Average NAND Write Size                        %20f\n",
			safe_div_fp((le64_to_cpu(perf->nw_blks)), (le64_to_cpu(perf->nw_cmds))));
	printf("  NAND Read Before Write                         %20"PRIu64"\n",
			(uint64_t)le64_to_cpu(perf->nrbw));
}

static void wdc_print_log_json(struct wdc_ssd_perf_stats *perf)
{
	struct json_object *root;

	root = json_create_object();
	json_object_add_value_int(root, "Host Read Commands", le64_to_cpu(perf->hr_cmds));
	json_object_add_value_int(root, "Host Read Blocks", le64_to_cpu(perf->hr_blks));
	json_object_add_value_int(root, "Average Read Size",
			safe_div_fp((le64_to_cpu(perf->hr_blks)), (le64_to_cpu(perf->hr_cmds))));
	json_object_add_value_int(root, "Host Read Cache Hit Commands",
			(uint64_t)le64_to_cpu(perf->hr_ch_cmds));
	json_object_add_value_int(root, "Host Read Cache Hit Percentage",
			(uint64_t) calc_percent(le64_to_cpu(perf->hr_ch_cmds), le64_to_cpu(perf->hr_cmds)));
	json_object_add_value_int(root, "Host Read Cache Hit Blocks",
			(uint64_t)le64_to_cpu(perf->hr_ch_blks));
	json_object_add_value_int(root, "Average Read Cache Hit Size",
			safe_div_fp((le64_to_cpu(perf->hr_ch_blks)), (le64_to_cpu(perf->hr_ch_cmds))));
	json_object_add_value_int(root, "Host Read Commands Stalled",
			(uint64_t)le64_to_cpu(perf->hr_st_cmds));
	json_object_add_value_int(root, "Host Read Commands Stalled Percentage",
			(uint64_t)calc_percent((le64_to_cpu(perf->hr_st_cmds)), le64_to_cpu(perf->hr_cmds)));
	json_object_add_value_int(root, "Host Write Commands",
			(uint64_t)le64_to_cpu(perf->hw_cmds));
	json_object_add_value_int(root, "Host Write Blocks",
			(uint64_t)le64_to_cpu(perf->hw_blks));
	json_object_add_value_int(root, "Average Write Size",
			safe_div_fp((le64_to_cpu(perf->hw_blks)), (le64_to_cpu(perf->hw_cmds))));
	json_object_add_value_int(root, "Host Write Odd Start Commands",
			(uint64_t)le64_to_cpu(perf->hw_os_cmds));
	json_object_add_value_int(root, "Host Write Odd Start Commands Percentage",
			(uint64_t)calc_percent((le64_to_cpu(perf->hw_os_cmds)), (le64_to_cpu(perf->hw_cmds))));
	json_object_add_value_int(root, "Host Write Odd End Commands",
			(uint64_t)le64_to_cpu(perf->hw_oe_cmds));
	json_object_add_value_int(root, "Host Write Odd End Commands Percentage",
			(uint64_t)calc_percent((le64_to_cpu(perf->hw_oe_cmds)), (le64_to_cpu((perf->hw_cmds)))));
	json_object_add_value_int(root, "Host Write Commands Stalled",
		(uint64_t)le64_to_cpu(perf->hw_st_cmds));
	json_object_add_value_int(root, "Host Write Commands Stalled Percentage",
		(uint64_t)calc_percent((le64_to_cpu(perf->hw_st_cmds)), (le64_to_cpu(perf->hw_cmds))));
	json_object_add_value_int(root, "NAND Read Commands",
		(uint64_t)le64_to_cpu(perf->nr_cmds));
	json_object_add_value_int(root, "NAND Read Blocks Commands",
		(uint64_t)le64_to_cpu(perf->nr_blks));
	json_object_add_value_int(root, "Average NAND Read Size",
		safe_div_fp((le64_to_cpu(perf->nr_blks)), (le64_to_cpu((perf->nr_cmds)))));
	json_object_add_value_int(root, "Host Write Odd Start Commands",
			(uint64_t)le64_to_cpu(perf->hw_os_cmds));
	json_object_add_value_int(root, "Nand Write Commands",
			(uint64_t)le64_to_cpu(perf->nw_cmds));
	json_object_add_value_int(root, "NAND Write Blocks",
			(uint64_t)le64_to_cpu(perf->nw_blks));
	json_object_add_value_int(root, "Average NAND Write Size",
			safe_div_fp((le64_to_cpu(perf->nw_blks)), (le64_to_cpu(perf->nw_cmds))));
	json_object_add_value_int(root, "NAND Read Before Written",
			(uint64_t)le64_to_cpu(perf->nrbw));
	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static int wdc_print_log(struct wdc_ssd_perf_stats *perf, int fmt)
{
	if (!perf) {
		fprintf(stderr, "ERROR : WDC : Invalid buffer to read perf stats\n");
		return -1;
	}
	switch (fmt) {
	case NORMAL:
		wdc_print_log_normal(perf);
		break;
	case JSON:
		wdc_print_log_json(perf);
		break;
	}
	return 0;
}

static void wdc_print_ca_log_normal(struct wdc_ssd_ca_perf_stats *perf)
{
	printf("  CA Log Page Performance Statistics :- \n");
	printf("  NAND Bytes Written                             %20"PRIu64 "%20"PRIu64"\n",
			(uint64_t)le64_to_cpu(perf->nand_bytes_wr_hi), (uint64_t)le64_to_cpu(perf->nand_bytes_wr_lo));
	printf("  NAND Bytes Read                                %20"PRIu64 "%20"PRIu64"\n",
			(uint64_t)le64_to_cpu(perf->nand_bytes_rd_hi), (uint64_t)le64_to_cpu(perf->nand_bytes_rd_lo));
	printf("  NAND Bad Block Count (Normalized)              %20"PRIu16"\n",
			(uint16_t)le16_to_cpu(perf->nand_bad_block & 0x000000000000FFFF));
	printf("  NAND Bad Block Count (Raw)                     %20"PRIu64"\n",
			(uint64_t)le64_to_cpu(perf->nand_bad_block & 0xFFFFFFFFFFFF0000)>>16);
	printf("  Uncorrectable Read Count                       %20"PRIu64"\n",
			(uint64_t)le64_to_cpu(perf->uncorr_read_count));
	printf("  Soft ECC Error Count                           %20"PRIu64"\n",
			(uint64_t)le64_to_cpu(perf->ecc_error_count));
	printf("  SSD End to End Detected Correction Count       %20"PRIu32"\n",
			(uint32_t)le32_to_cpu(perf->ssd_detect_count));
	printf("  SSD End to End Corrected Correction Count      %20"PRIu32"\n",
			(uint32_t)le32_to_cpu(perf->ssd_correct_count));
	printf("  System Data Percent Used                       %20"PRIu32"%%\n",
			(uint32_t)le32_to_cpu(perf->data_percent_used));
	printf("  User Data Erase Counts Max                     %20"PRIu32"\n",
			(uint32_t)le32_to_cpu(perf->data_erase_max));
	printf("  User Data Erase Counts Min                     %20"PRIu32"\n",
			(uint32_t)le32_to_cpu(perf->data_erase_min));
	printf("  Refresh Count                                  %20"PRIu64"\n",
			(uint64_t)le64_to_cpu(perf->refresh_count));
	printf("  Program Fail Count (Normalized)                %20"PRIu16"\n",
			(uint16_t)le16_to_cpu(perf->program_fail & 0x000000000000FFFF));
	printf("  Program Fail Count (Raw)                       %20"PRIu64"\n",
			(uint64_t)le64_to_cpu(perf->program_fail & 0xFFFFFFFFFFFF0000)>>16);
	printf("  User Data Erase Fail Count (Normalized)        %20"PRIu16"\n",
			(uint16_t)le16_to_cpu(perf->user_erase_fail & 0x000000000000FFFF));
	printf("  User Data Erase Fail Count (Raw)               %20"PRIu64"\n",
			(uint64_t)le64_to_cpu(perf->user_erase_fail & 0xFFFFFFFFFFFF0000)>>16);
	printf("  System Area Erase Fail Count (Normalized)      %20"PRIu16"\n",
			(uint16_t)le16_to_cpu(perf->system_erase_fail & 0x000000000000FFFF));
	printf("  System Area Erase Fail Count (Raw)             %20"PRIu64"\n",
			(uint64_t)le64_to_cpu(perf->system_erase_fail & 0xFFFFFFFFFFFF0000)>>16);
	printf("  Thermal Throttling Status                      %20"PRIu16"\n",
			(uint16_t)le16_to_cpu(perf->thermal_throttle_status));
	printf("  Thermal Throttling Count                       %20"PRIu16"\n",
			(uint16_t)le16_to_cpu(perf->thermal_throttle_count));
	printf("  PCIe Correctable Error Count                   %20"PRIu64"\n",
			(uint64_t)le64_to_cpu(perf->pcie_corr_error));
}

static void wdc_print_ca_log_json(struct wdc_ssd_ca_perf_stats *perf)
{
	struct json_object *root;

	root = json_create_object();
	json_object_add_value_int(root, "NAND Bytes Written Hi", le64_to_cpu(perf->nand_bytes_wr_hi));
	json_object_add_value_int(root, "NAND Bytes Written Lo", le64_to_cpu(perf->nand_bytes_wr_lo));
	json_object_add_value_int(root, "NAND Bytes Read Hi", le64_to_cpu(perf->nand_bytes_rd_hi));
	json_object_add_value_int(root, "NAND Bytes Read Lo", le64_to_cpu(perf->nand_bytes_rd_lo));
	json_object_add_value_int(root, "NAND Bad Block Count (Normalized)",
			le16_to_cpu(perf->nand_bad_block & 0x000000000000FFFF));
	json_object_add_value_int(root, "NAND Bad Block Count (Raw)",
			le64_to_cpu(perf->nand_bad_block & 0xFFFFFFFFFFFF0000)>>16);
	json_object_add_value_int(root, "Uncorrectable Read Count", le64_to_cpu(perf->uncorr_read_count));
	json_object_add_value_int(root, "Soft ECC Error Count",	le64_to_cpu(perf->ecc_error_count));
	json_object_add_value_int(root, "SSD End to End Detected Correction Count",
			le32_to_cpu(perf->ssd_detect_count));
	json_object_add_value_int(root, "SSD End to End Corrected Correction Count",
			le32_to_cpu(perf->ssd_correct_count));
	json_object_add_value_int(root, "System Data Percent Used",
			le32_to_cpu(perf->data_percent_used));
	json_object_add_value_int(root, "User Data Erase Counts Max",
			le32_to_cpu(perf->data_erase_max));
	json_object_add_value_int(root, "User Data Erase Counts Min",
			le32_to_cpu(perf->data_erase_min));
	json_object_add_value_int(root, "Refresh Count", le64_to_cpu(perf->refresh_count));
	json_object_add_value_int(root, "Program Fail Count (Normalized)",
			le16_to_cpu(perf->program_fail & 0x000000000000FFFF));
	json_object_add_value_int(root, "Program Fail Count (Raw)",
			le64_to_cpu(perf->program_fail & 0xFFFFFFFFFFFF0000)>>16);
	json_object_add_value_int(root, "User Data Erase Fail Count (Normalized)",
			le16_to_cpu(perf->user_erase_fail & 0x000000000000FFFF));
	json_object_add_value_int(root, "User Data Erase Fail Count (Raw)",
			le64_to_cpu(perf->user_erase_fail & 0xFFFFFFFFFFFF0000)>>16);
	json_object_add_value_int(root, "System Area Erase Fail Count (Normalized)",
			le16_to_cpu(perf->system_erase_fail & 0x000000000000FFFF));
	json_object_add_value_int(root, "System Area Erase Fail Count (Raw)",
			le64_to_cpu(perf->system_erase_fail & 0xFFFFFFFFFFFF0000)>>16);
	json_object_add_value_int(root, "Thermal Throttling Status",
			le16_to_cpu(perf->thermal_throttle_status));
	json_object_add_value_int(root, "Thermal Throttling Count",
			le16_to_cpu(perf->thermal_throttle_count));
	json_object_add_value_int(root, "PCIe Correctable Error", le64_to_cpu(perf->pcie_corr_error));
	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static int wdc_print_ca_log(struct wdc_ssd_ca_perf_stats *perf, int fmt)
{
	if (!perf) {
		fprintf(stderr, "ERROR : WDC : Invalid buffer to read perf stats\n");
		return -1;
	}
	switch (fmt) {
	case NORMAL:
		wdc_print_ca_log_normal(perf);
		break;
	case JSON:
		wdc_print_ca_log_json(perf);
		break;
	}
	return 0;
}

static int wdc_get_ca_log_page(int fd, char *format)
{
	int ret = 0;
	int fmt = -1;
	__u8 *data;
	struct wdc_ssd_ca_perf_stats *perf;


	wdc_check_device(fd);
	fmt = validate_output_format(format);
	if (fmt < 0) {
		fprintf(stderr, "ERROR : WDC : invalid output format\n");
		return fmt;
	}

	/* verify the 0xCA log page is supported */
	if (wdc_nvme_check_supported_log_page(fd, WDC_NVME_GET_DEVICE_INFO_LOG_OPCODE)) {
		fprintf(stderr, "ERROR : WDC : 0xCA Log Page not supported\n");
		return -1;
	}

	if ((data = (__u8*) malloc(sizeof (__u8) * WDC_CA_LOG_BUF_LEN)) == NULL) {
		fprintf(stderr, "ERROR : WDC : malloc : %s\n", strerror(errno));
		return -1;
	}
	memset(data, 0, sizeof (__u8) * WDC_CA_LOG_BUF_LEN);

	ret = nvme_get_log(fd, 0xFFFFFFFF, WDC_NVME_GET_DEVICE_INFO_LOG_OPCODE,
			   NVME_NO_LOG_LSP, NVME_NO_LOG_LPO,
			   WDC_CA_LOG_BUF_LEN, data);
	if (strcmp(format, "json"))
		fprintf(stderr, "NVMe Status:%s(%x)\n", nvme_status_to_string(ret), ret);

	if (ret == 0) {
		/* parse the data */
		perf = (struct wdc_ssd_ca_perf_stats *)(data);
		ret = wdc_print_ca_log(perf, fmt);
	} else {
		fprintf(stderr, "ERROR : WDC : Unable to read CA Log Page data\n");
		ret = -1;
	}

	free(data);
	return ret;
}

static int wdc_get_c1_log_page(int fd, char *format, uint8_t interval)
{
	int ret = 0;
	int fmt = -1;
	__u8 *data;
	__u8 *p;
	int i;
	int skip_cnt = 4;
	int total_subpages;
	struct wdc_log_page_header *l;
	struct wdc_log_page_subpage_header *sph;
	struct wdc_ssd_perf_stats *perf;

	wdc_check_device(fd);
	fmt = validate_output_format(format);
	if (fmt < 0) {
		fprintf(stderr, "ERROR : WDC : invalid output format\n");
		return fmt;
	}

	if (interval < 1 || interval > 15) {
		fprintf(stderr, "ERROR : WDC : interval out of range [1-15]\n");
		return -1;
	}

	if ((data = (__u8*) malloc(sizeof (__u8) * WDC_ADD_LOG_BUF_LEN)) == NULL) {
		fprintf(stderr, "ERROR : WDC : malloc : %s\n", strerror(errno));
		return -1;
	}
	memset(data, 0, sizeof (__u8) * WDC_ADD_LOG_BUF_LEN);

	ret = nvme_get_log(fd, 0x01, WDC_NVME_ADD_LOG_OPCODE,
			   NVME_NO_LOG_LSP, NVME_NO_LOG_LPO,
			   WDC_ADD_LOG_BUF_LEN, data);
	if (strcmp(format, "json"))
		fprintf(stderr, "NVMe Status:%s(%x)\n", nvme_status_to_string(ret), ret);
	if (ret == 0) {
		l = (struct wdc_log_page_header*)data;
		total_subpages = l->num_subpages + WDC_NVME_GET_STAT_PERF_INTERVAL_LIFETIME - 1;
		for (i = 0, p = data + skip_cnt; i < total_subpages; i++, p += skip_cnt) {
			sph = (struct wdc_log_page_subpage_header *) p;
			if (sph->spcode == WDC_GET_LOG_PAGE_SSD_PERFORMANCE) {
				if (sph->pcset == interval) {
					perf = (struct wdc_ssd_perf_stats *) (p + 4);
					ret = wdc_print_log(perf, fmt);
					break;
				}
			}
			skip_cnt = le32_to_cpu(sph->subpage_length) + 4;
		}
		if (ret) {
			fprintf(stderr, "ERROR : WDC : Unable to read data from buffer\n");
		}
	}
	free(data);
	return ret;
}

static int wdc_smart_add_log(int argc, char **argv, struct command *command,
		struct plugin *plugin)
{
	char *desc = "Retrieve additional performance statistics.";
	char *interval = "Interval to read the statistics from [1, 15].";
	int fd;
	int ret;

	struct config {
		uint8_t interval;
		int   vendor_specific;
		char *output_format;
	};

	struct config cfg = {
		.interval = 14,
		.output_format = "normal",
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"interval", 'i', "NUM", CFG_POSITIVE, &cfg.interval, required_argument, interval},
		{"output-format", 'o', "FMT", CFG_STRING, &cfg.output_format, required_argument, "Output Format: normal|json" },
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, NULL, 0);
	if (fd < 0)
		return fd;


	if (wdc_check_device_sn100(fd)) {
		// Get the C1 Log Page
		ret = wdc_get_c1_log_page(fd, cfg.output_format, cfg.interval);

		if (ret) {
			fprintf(stderr, "ERROR : WDC : Unable to read C1 Log Page data from buffer\n");
			return ret;
		}
	}
	else if (wdc_check_device_sn200(fd)) {
		// Get the CA and C1 Log Page
		ret = wdc_get_ca_log_page(fd, cfg.output_format);
		if (ret) {
			fprintf(stderr, "ERROR : WDC : Unable to read CA Log Page data from buffer\n");
			return ret;
		}

		ret = wdc_get_c1_log_page(fd, cfg.output_format, cfg.interval);
		if (ret) {
			fprintf(stderr, "ERROR : WDC : Unable to read C1 Log Page data from buffer\n");
			return ret;
		}
	}
	else {
		fprintf(stderr, "INFO : WDC : Command not supported in this devicer\n");
	}

	return 0;
}
