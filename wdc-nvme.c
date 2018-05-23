/*
 * Copyright (c) 2015-2018 Western Digital Corporation or its affiliates.
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
 *           Dong Ho <dong.ho@hgst.com>,
 *           Jeff Lien <jeff.lien@wdc.com>
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
#include "wdc-utils.h"

#define WRITE_SIZE	(sizeof(__u8) * 4096)

#define WDC_NVME_SUBCMD_SHIFT	8

#define WDC_NVME_LOG_SIZE_DATA_LEN			0x08

/* Device Config */
#define WDC_NVME_VID  					0x1c58
#define WDC_NVME_SN100_CNTL_ID			0x0003
#define WDC_NVME_SN200_CNTL_ID			0x0023
#define WDC_NVME_SNDK_VID		        0x15b7
#define WDC_NVME_SXSLCL_CNTRL_ID		0x0000

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

/* Clear PCIe Correctable Errors */
#define WDC_NVME_CLEAR_PCIE_CORR_OPCODE  	WDC_NVME_CAP_DIAG_CMD_OPCODE
#define WDC_NVME_CLEAR_PCIE_CORR_CMD		0x22
#define WDC_NVME_CLEAR_PCIE_CORR_SUBCMD		0x04

/* Drive Essentials */
#define WDC_DE_DEFAULT_NUMBER_OF_ERROR_ENTRIES		64
#define WDC_DE_GENERIC_BUFFER_SIZE					80
#define WDC_DE_GLOBAL_NSID							0xFFFFFFFF
#define WDC_DE_DEFAULT_NAMESPACE_ID					0x01
#define WDC_DE_PATH_SEPARATOR						"/"
#define WDC_DE_TAR_FILES							"*.bin"
#define WDC_DE_TAR_FILE_EXTN						".tar.gz"
#define WDC_DE_TAR_CMD								"tar -czf"

/* VU Opcodes */
#define WDC_DE_VU_READ_SIZE_OPCODE					0xC0
#define WDC_DE_VU_READ_BUFFER_OPCODE				0xC2

#define WDC_DE_FILE_HEADER_SIZE                     4
#define WDC_DE_FILE_OFFSET_SIZE                     2
#define WDC_DE_FILE_NAME_SIZE                       32
#define WDC_DE_VU_READ_BUFFER_STANDARD_OFFSET		0x8000
#define WDC_DE_READ_MAX_TRANSFER_SIZE				0x8000

#define WDC_DE_MANUFACTURING_INFO_PAGE_FILE_NAME	"manufacturing_info"  /* Unique log entry page name. */
#define WDC_DE_CORE_DUMP_FILE_NAME					"core_dump"
#define WDC_DE_EVENT_LOG_FILE_NAME					"event_log"
#define WDC_DE_DESTN_SPI							1
#define WDC_DE_DUMPTRACE_DESTINATION				6

typedef enum _NVME_FEATURES_SELECT
{
    FS_CURRENT                      = 0,
    FS_DEFAULT                      = 1,
    FS_SAVED                        = 2,
    FS_SUPPORTED_CAPBILITIES        = 3
} NVME_FEATURES_SELECT;

typedef enum _NVME_FEATURE_IDENTIFIERS
{
    FID_ARBITRATION                                 = 0x01,
    FID_POWER_MANAGEMENT                            = 0x02,
    FID_LBA_RANGE_TYPE                              = 0x03,
    FID_TEMPERATURE_THRESHOLD                       = 0x04,
    FID_ERROR_RECOVERY                              = 0x05,
    FID_VOLATILE_WRITE_CACHE                        = 0x06,
    FID_NUMBER_OF_QUEUES                            = 0x07,
    FID_INTERRUPT_COALESCING                        = 0x08,
    FID_INTERRUPT_VECTOR_CONFIGURATION              = 0x09,
    FID_WRITE_ATOMICITY                             = 0x0A,
    FID_ASYNCHRONOUS_EVENT_CONFIGURATION            = 0x0B,
    FID_AUTONOMOUS_POWER_STATE_TRANSITION           = 0x0C,
/*Below FID's are NVM Command Set Specific*/
    FID_SOFTWARE_PROGRESS_MARKER                    = 0x80,
    FID_HOST_IDENTIFIER                             = 0x81,
    FID_RESERVATION_NOTIFICATION_MASK               = 0x82,
    FID_RESERVATION_PERSISTENCE                     = 0x83
} NVME_FEATURE_IDENTIFIERS;

typedef enum
{
	WDC_DE_TYPE_IDENTIFY            = 0x1,
	WDC_DE_TYPE_SMARTATTRIBUTEDUMP  = 0x2,
	WDC_DE_TYPE_EVENTLOG            = 0x4,
	WDC_DE_TYPE_DUMPTRACE           = 0x8,
	WDC_DE_TYPE_DUMPSNAPSHOT        = 0x10,
	WDC_DE_TYPE_ATA_LOGS            = 0x20,
	WDC_DE_TYPE_SMART_LOGS          = 0x40,
	WDC_DE_TYPE_SCSI_LOGS           = 0x80,
	WDC_DE_TYPE_SCSI_MODE_PAGES     = 0x100,
	WDC_DE_TYPE_NVMe_FEATURES       = 0x200,
	WDC_DE_TYPE_DUMPSMARTERRORLOG3  = 0x400,
	WDC_DE_TYPE_DUMPLOG3E           = 0x800,
	WDC_DE_TYPE_DUMPSCRAM           = 0x1000,
	WDC_DE_TYPE_PCU_LOG             = 0x2000,
	WDC_DE_TYPE_DUMP_ERROR_LOGS     = 0x4000,
	WDC_DE_TYPE_FW_SLOT_LOGS        = 0x8000,
	WDC_DE_TYPE_MEDIA_SETTINGS      = 0x10000,
	WDC_DE_TYPE_SMART_DATA          = 0x20000,
	WDC_DE_TYPE_NVME_SETTINGS       = 0x40000,
	WDC_DE_TYPE_NVME_ERROR_LOGS     = 0x80000,
	WDC_DE_TYPE_NVME_LOGS           = 0x100000,
	WDC_DE_TYPE_UART_LOGS           = 0x200000,
	WDC_DE_TYPE_DLOGS_SPI           = 0x400000,
	WDC_DE_TYPE_DLOGS_RAM           = 0x800000,
	WDC_DE_TYPE_NVME_MANF_INFO      = 0x2000000,
	WDC_DE_TYPE_NONE                = 0x1000000,
	WDC_DE_TYPE_ALL                 = 0xFFFFFFF,
} WDC_DRIVE_ESSENTIAL_TYPE;

typedef struct __attribute__((__packed__)) _WDC_DE_VU_FILE_META_DATA
{
    __u8 fileName[WDC_DE_FILE_NAME_SIZE];
    __u16 fileID;
    __u64 fileSize;
} WDC_DE_VU_FILE_META_DATA, *PWDC_DE_VU_FILE_META_DATA;

typedef struct _WDC_DRIVE_ESSENTIALS
{
    WDC_DE_VU_FILE_META_DATA metaData;
    WDC_DRIVE_ESSENTIAL_TYPE essentialType;
} WDC_DRIVE_ESSENTIALS;

typedef struct _WDC_DE_VU_LOG_DIRECTORY
{
    WDC_DRIVE_ESSENTIALS *logEntry;		/* Caller to allocate memory        */
    __u32 maxNumLogEntries; 			/* Caller to input memory allocated */
    __u32 numOfValidLogEntries;			/* API will output this value       */
} WDC_DE_VU_LOG_DIRECTORY,*PWDC_DE_VU_LOG_DIRECTORY;

typedef struct _WDC_DE_CSA_FEATURE_ID_LIST
{
    NVME_FEATURE_IDENTIFIERS featureId;
    __u8 featureName[WDC_DE_GENERIC_BUFFER_SIZE];
} WDC_DE_CSA_FEATURE_ID_LIST;

WDC_DE_CSA_FEATURE_ID_LIST deFeatureIdList[] =
{
	{0x00                                   , "Dummy Placeholder"},
	{FID_ARBITRATION                        , "Arbitration"},
	{FID_POWER_MANAGEMENT                   , "PowerMgmnt"},
	{FID_LBA_RANGE_TYPE                     , "LbaRangeType"},
	{FID_TEMPERATURE_THRESHOLD              , "TempThreshold"},
	{FID_ERROR_RECOVERY                     , "ErrorRecovery"},
	{FID_VOLATILE_WRITE_CACHE               , "VolatileWriteCache"},
	{FID_NUMBER_OF_QUEUES                   , "NumOfQueues"},
	{FID_INTERRUPT_COALESCING               , "InterruptCoalesing"},
	{FID_INTERRUPT_VECTOR_CONFIGURATION     , "InterruptVectorConfig"},
	{FID_WRITE_ATOMICITY                    , "WriteAtomicity"},
	{FID_ASYNCHRONOUS_EVENT_CONFIGURATION   , "AsynEventConfig"},
	{FID_AUTONOMOUS_POWER_STATE_TRANSITION  , "AutonomousPowerState"},
};

typedef enum _NVME_VU_DE_LOGPAGE_NAMES
{
    NVME_DE_LOGPAGE_E3 = 0x01,
    NVME_DE_LOGPAGE_C0 = 0x02
} NVME_VU_DE_LOGPAGE_NAMES;
typedef struct _NVME_VU_DE_LOGPAGE_LIST
{
    NVME_VU_DE_LOGPAGE_NAMES logPageName;
    __u32 logPageId;
    __u32 logPageLen;
    char  logPageIdStr[4];
} NVME_VU_DE_LOGPAGE_LIST, *PNVME_VU_DE_LOGPAGE_LIST;

typedef struct _WDC_NVME_DE_VU_LOGPAGES
{
    NVME_VU_DE_LOGPAGE_NAMES vuLogPageReqd;
    __u32 numOfVULogPages;
} WDC_NVME_DE_VU_LOGPAGES, *PWDC_NVME_DE_VU_LOGPAGES;

NVME_VU_DE_LOGPAGE_LIST deVULogPagesList[] =
{
    { NVME_DE_LOGPAGE_E3, 0xE3, 1072, "0xe3"},
    { NVME_DE_LOGPAGE_C0, 0xC0, 512, "0xc0"}
};

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
static int wdc_clear_pcie_corr(int argc, char **argv, struct command *command,
		struct plugin *plugin);
static int wdc_do_drive_essentials(int fd, char *dir, char *key);
static int wdc_drive_essentials(int argc, char **argv, struct command *command,
		struct plugin *plugin);

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
	else if ((le32_to_cpu(ctrl.vid) == WDC_NVME_SNDK_VID) &&
			(le32_to_cpu(ctrl.cntlid) == WDC_NVME_SXSLCL_CNTRL_ID))
		ret = 0;
	else
		fprintf(stderr, "WARNING : WDC : Device not supported\n");

	return ret;
}

static int wdc_check_device_sxslcl(int fd)
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
	if ((le32_to_cpu(ctrl.vid) == WDC_NVME_SNDK_VID) &&
			(le32_to_cpu(ctrl.cntlid) == WDC_NVME_SXSLCL_CNTRL_ID))
		ret = 0;

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
	int res_len = 0;
	char orig[PATH_MAX] = {0};
	struct nvme_id_ctrl ctrl;
	int ctrl_sn_len = sizeof (ctrl.sn);

	i = sizeof (ctrl.sn) - 1;
	strncpy(orig, file, PATH_MAX - 1);
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

	if (ctrl.sn[sizeof (ctrl.sn) - 1] == '\0') {
		ctrl_sn_len = strlen(ctrl.sn);
	}

	res_len = snprintf(file, len, "%s%.*s%s.bin", orig, ctrl_sn_len, ctrl.sn, suffix);
	if (len <= res_len) {
		fprintf(stderr, "ERROR : WDC : cannot format serial number due to data "
				"of unexpected length\n");
		return -1;
	}

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
	const char *desc = "Capture Diagnostics Log.";
	const char *file = "Output file pathname.";
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
		strncpy(f, cfg.file, PATH_MAX - 1);
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
		strncpy(f, file, PATH_MAX - 1);
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
	const char *desc = "Capture Drive Log.";
	const char *file = "Output file pathname.";
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
		strncpy(f, cfg.file, PATH_MAX - 1);
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
	const char *desc = "Get Crash Dump.";
	const char *file = "Output file pathname.";
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
	const char *desc = "Send a Purge command.";
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
	const char *desc = "Send a Purge Monitor command.";
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
	uint64_t converted = 0;

	printf("  CA Log Page Performance Statistics :- \n");
	printf("  NAND Bytes Written                             %20"PRIu64 "%20"PRIu64"\n",
			(uint64_t)le64_to_cpu(perf->nand_bytes_wr_hi), (uint64_t)le64_to_cpu(perf->nand_bytes_wr_lo));
	printf("  NAND Bytes Read                                %20"PRIu64 "%20"PRIu64"\n",
			(uint64_t)le64_to_cpu(perf->nand_bytes_rd_hi), (uint64_t)le64_to_cpu(perf->nand_bytes_rd_lo));

	converted = le64_to_cpu(perf->nand_bad_block);
	printf("  NAND Bad Block Count (Normalized)              %20"PRIu64"\n",
			converted & 0xFFFF);
	printf("  NAND Bad Block Count (Raw)                     %20"PRIu64"\n",
			converted >> 16);

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

	converted = le64_to_cpu(perf->program_fail);
	printf("  Program Fail Count (Normalized)                %20"PRIu64"\n",
			converted & 0xFFFF);
	printf("  Program Fail Count (Raw)                       %20"PRIu64"\n",
			converted >> 16);

	converted = le64_to_cpu(perf->user_erase_fail);
	printf("  User Data Erase Fail Count (Normalized)        %20"PRIu64"\n",
			converted & 0xFFFF);
	printf("  User Data Erase Fail Count (Raw)               %20"PRIu64"\n",
			converted >> 16);

	converted = le64_to_cpu(perf->system_erase_fail);
	printf("  System Area Erase Fail Count (Normalized)      %20"PRIu64"\n",
			converted & 0xFFFF);
	printf("  System Area Erase Fail Count (Raw)             %20"PRIu64"\n",
			converted >> 16);

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
	uint64_t converted = 0;

	root = json_create_object();
	json_object_add_value_int(root, "NAND Bytes Written Hi", le64_to_cpu(perf->nand_bytes_wr_hi));
	json_object_add_value_int(root, "NAND Bytes Written Lo", le64_to_cpu(perf->nand_bytes_wr_lo));
	json_object_add_value_int(root, "NAND Bytes Read Hi", le64_to_cpu(perf->nand_bytes_rd_hi));
	json_object_add_value_int(root, "NAND Bytes Read Lo", le64_to_cpu(perf->nand_bytes_rd_lo));

	converted = le64_to_cpu(perf->nand_bad_block);
	json_object_add_value_int(root, "NAND Bad Block Count (Normalized)",
			converted & 0xFFFF);
	json_object_add_value_int(root, "NAND Bad Block Count (Raw)",
			converted >> 16);

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

	converted = le64_to_cpu(perf->program_fail);
	json_object_add_value_int(root, "Program Fail Count (Normalized)",
			converted & 0xFFFF);
	json_object_add_value_int(root, "Program Fail Count (Raw)",
			converted >> 16);

	converted = le64_to_cpu(perf->user_erase_fail);
	json_object_add_value_int(root, "User Data Erase Fail Count (Normalized)",
			converted & 0xFFFF);
	json_object_add_value_int(root, "User Data Erase Fail Count (Raw)",
			converted >> 16);

	converted = le64_to_cpu(perf->system_erase_fail);
	json_object_add_value_int(root, "System Area Erase Fail Count (Normalized)",
			converted & 0xFFFF);
	json_object_add_value_int(root, "System Area Erase Fail Count (Raw)",
			converted >> 16);

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
	const char *desc = "Retrieve additional performance statistics.";
	const char *interval = "Interval to read the statistics from [1, 15].";
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
		fprintf(stderr, "INFO : WDC : Command not supported in this device\n");
	}

	return 0;
}

static int wdc_clear_pcie_corr(int argc, char **argv, struct command *command,
		struct plugin *plugin)
{
	char *desc = "Clear PCIE Correctable Errors.";
	int fd;
	int ret;
	struct nvme_passthru_cmd admin_cmd;
	const struct argconfig_commandline_options command_line_options[] = {
		{ NULL, '\0', NULL, CFG_NONE, NULL, no_argument, desc },
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, NULL, 0);
	if (fd < 0)
		return fd;

	wdc_check_device(fd);

	memset(&admin_cmd, 0, sizeof (admin_cmd));
	admin_cmd.opcode = WDC_NVME_CLEAR_PCIE_CORR_OPCODE;
	admin_cmd.cdw12 = ((WDC_NVME_CLEAR_PCIE_CORR_SUBCMD << WDC_NVME_SUBCMD_SHIFT) |
			WDC_NVME_CLEAR_PCIE_CORR_CMD);

	ret = nvme_submit_passthru(fd, NVME_IOCTL_ADMIN_CMD, &admin_cmd);
	fprintf(stderr, "NVMe Status:%s(%x)\n", nvme_status_to_string(ret), ret);
	return ret;
}

static int wdc_get_serial_and_fw_rev(int fd, char *sn, char *fw_rev)
{
	int i;
	int ret;
	struct nvme_id_ctrl ctrl;

	i = sizeof (ctrl.sn) - 1;
	memset(sn, 0, WDC_SERIAL_NO_LEN);
	memset(fw_rev, 0, WDC_NVME_FIRMWARE_REV_LEN);
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
	snprintf(sn, WDC_SERIAL_NO_LEN, "%s", ctrl.sn);
	snprintf(fw_rev, WDC_NVME_FIRMWARE_REV_LEN, "%s", ctrl.fr);

	return 0;
}

static int wdc_get_max_transfer_len(int fd, __u32 *maxTransferLen)
{
	int ret = 0;
	struct nvme_id_ctrl ctrl;

	__u32 maxTransferLenDevice = 0;

	memset(&ctrl, 0, sizeof (struct nvme_id_ctrl));
	ret = nvme_identify_ctrl(fd, &ctrl);
	if (ret) {
		fprintf(stderr, "ERROR : WDC : nvme_identify_ctrl() failed 0x%x\n", ret);
		return -1;
	}

	maxTransferLenDevice = (1 << ctrl.mdts) * getpagesize();
	*maxTransferLen = maxTransferLenDevice;

	return ret;
}

int wdc_de_VU_read_size(int fd, __u32 fileId, __u16 spiDestn, __u32* logSize)
{
	int ret = WDC_STATUS_FAILURE;
	struct nvme_admin_cmd cmd;

	if(!fd || !logSize )
	{
		ret = WDC_STATUS_INVALID_PARAMETER;
		goto end;
	}

	memset(&cmd,0,sizeof(struct nvme_admin_cmd));
	cmd.opcode = WDC_DE_VU_READ_SIZE_OPCODE;
	cmd.nsid = WDC_DE_DEFAULT_NAMESPACE_ID;
	cmd.cdw13 = fileId<<16;
	cmd.cdw14 = spiDestn;

	ret = nvme_submit_passthru(fd, NVME_IOCTL_ADMIN_CMD, &cmd);

	if (!ret && logSize)
		*logSize = cmd.result;
	if( ret != WDC_STATUS_SUCCESS)
		fprintf(stderr, "ERROR : WDC : VUReadSize() failed, status:%s(0x%x)\n", nvme_status_to_string(ret), ret);

	end:
	return ret;
}

int wdc_de_VU_read_buffer(int fd, __u32 fileId, __u16 spiDestn, __u32 offsetInDwords, __u8* dataBuffer, __u32* bufferSize)
{
	int ret = WDC_STATUS_FAILURE;
	struct nvme_admin_cmd cmd;
	__u32 noOfDwordExpected = 0;

	if(!fd || !dataBuffer || !bufferSize)
	{
		ret = WDC_STATUS_INVALID_PARAMETER;
		goto end;
	}

	memset(&cmd,0,sizeof(struct nvme_admin_cmd));
	noOfDwordExpected = *bufferSize/sizeof(__u32);
	cmd.opcode = WDC_DE_VU_READ_BUFFER_OPCODE;
	cmd.nsid = WDC_DE_DEFAULT_NAMESPACE_ID;
	cmd.cdw10 = noOfDwordExpected;
	cmd.cdw13 = fileId<<16;
	cmd.cdw14 = spiDestn;
	cmd.cdw15 = offsetInDwords;

	cmd.addr = (__u64)(__u64)(uintptr_t)dataBuffer;
	cmd.data_len = *bufferSize;

	ret = nvme_submit_passthru(fd, NVME_IOCTL_ADMIN_CMD, &cmd);

	if( ret != WDC_STATUS_SUCCESS)
		fprintf(stderr, "ERROR : WDC : VUReadBuffer() failed, status:%s(0x%x)\n", nvme_status_to_string(ret), ret);

	end:
	return ret;
}

int wdc_get_log_dir_max_entries(int fd, __u32* maxNumOfEntries)
{
	int     		ret = WDC_STATUS_FAILURE;
	__u32           headerPayloadSize = 0;
	__u8*           fileIdOffsetsBuffer = NULL;
	__u32           fileIdOffsetsBufferSize = 0;
	__u32           fileNum = 0;
	__u16           fileOffset = 0;


	if (!fd || !maxNumOfEntries)
	{
		ret = WDC_STATUS_INVALID_PARAMETER;
		return ret;
	}
	/* 1.Get log directory first four bytes */
	if (WDC_STATUS_SUCCESS != (ret = wdc_de_VU_read_size(fd, 0, 5, (__u32*)&headerPayloadSize)))
	{
		fprintf(stderr, "ERROR : WDC : %s: Failed to get headerPayloadSize from file directory 0x%x\n",
				__func__, ret);
		goto end;
	}

	fileIdOffsetsBufferSize = WDC_DE_FILE_HEADER_SIZE + (headerPayloadSize * WDC_DE_FILE_OFFSET_SIZE);
	fileIdOffsetsBuffer = (__u8*)calloc(1, fileIdOffsetsBufferSize);

	/* 2.Read to get file offsets */
	if (WDC_STATUS_SUCCESS != (ret = wdc_de_VU_read_buffer(fd, 0, 5, 0, fileIdOffsetsBuffer, &fileIdOffsetsBufferSize)))
	{
		fprintf(stderr, "ERROR : WDC : %s: Failed to get fileIdOffsets from file directory 0x%x\n",
				__func__, ret);
		goto end;
	}
	/* 3.Determine valid entries */
	for (fileNum = 0; fileNum < (headerPayloadSize - WDC_DE_FILE_HEADER_SIZE) / WDC_DE_FILE_OFFSET_SIZE; fileNum++)
	{
		fileOffset = (fileIdOffsetsBuffer[WDC_DE_FILE_HEADER_SIZE + (fileNum * WDC_DE_FILE_OFFSET_SIZE)] << 8) +
				fileIdOffsetsBuffer[WDC_DE_FILE_HEADER_SIZE + (fileNum * WDC_DE_FILE_OFFSET_SIZE) + 1];
		if (!fileOffset)
			continue;
		(*maxNumOfEntries)++;
	}
	end:
	if (!fileIdOffsetsBuffer)
		free(fileIdOffsetsBuffer);
	return ret;
}

WDC_DRIVE_ESSENTIAL_TYPE wdc_get_essential_type(__u8 fileName[])
{
	WDC_DRIVE_ESSENTIAL_TYPE essentialType = WDC_DE_TYPE_NONE;

	if (wdc_UtilsStrCompare((char*)fileName, WDC_DE_CORE_DUMP_FILE_NAME) == 0)
	{
		essentialType = WDC_DE_TYPE_DUMPSNAPSHOT;
	}
	else if (wdc_UtilsStrCompare((char*)fileName, WDC_DE_EVENT_LOG_FILE_NAME) == 0)
	{
		essentialType = WDC_DE_TYPE_EVENTLOG;
	}
	else if (wdc_UtilsStrCompare((char*)fileName, WDC_DE_MANUFACTURING_INFO_PAGE_FILE_NAME) == 0)
	{
		essentialType = WDC_DE_TYPE_NVME_MANF_INFO;
	}

	return essentialType;
}

int wdc_fetch_log_directory(int fd, PWDC_DE_VU_LOG_DIRECTORY directory)
{
	int             ret = WDC_STATUS_FAILURE;
	__u8            *fileOffset = NULL;
	__u8            *fileDirectory = NULL;
	__u32           headerSize = 0;
	__u32           fileNum = 0, startIdx = 0;
	__u16           fileOffsetTemp = 0;
	__u32           entryId = 0;
	__u32           fileDirectorySize = 0;

	if (!fd || !directory)
	{
		ret = WDC_STATUS_INVALID_PARAMETER;
		goto end;
	}

	if (WDC_STATUS_SUCCESS != (ret = wdc_de_VU_read_size(fd, 0, 5, &fileDirectorySize)))
	{
		fprintf(stderr, "ERROR : WDC : %s: Failed to get filesystem directory size, ret = %d\n",
				__func__, ret);
		goto end;
	}

	fileDirectory = (__u8*)calloc(1, fileDirectorySize);
	if (WDC_STATUS_SUCCESS != (ret = wdc_de_VU_read_buffer(fd, 0, 5, 0, fileDirectory, &fileDirectorySize)))
	{
		fprintf(stderr, "ERROR : WDC : %s: Failed to get filesystem directory, ret = %d\n",
				__func__, ret);
		goto end;
	}

	/* First four bytes of header directory is headerSize */
	memcpy(&headerSize, fileDirectory, WDC_DE_FILE_HEADER_SIZE);

	if (directory->maxNumLogEntries == 0) //minimum buffer for 1 entry is required
	{
		ret = WDC_STATUS_INVALID_PARAMETER;
		goto end;
	}

	for (fileNum = 0; fileNum < (headerSize - WDC_DE_FILE_HEADER_SIZE) / WDC_DE_FILE_OFFSET_SIZE; fileNum++)
	{
		if (entryId >= directory->maxNumLogEntries)
			break;
		startIdx = WDC_DE_FILE_HEADER_SIZE + (fileNum * WDC_DE_FILE_OFFSET_SIZE);
		memcpy(&fileOffsetTemp, fileDirectory + startIdx, sizeof(fileOffsetTemp));
		fileOffset = fileDirectory + fileOffsetTemp;

		if (0 == fileOffsetTemp)
		{
			continue;
		}

		memset(&directory->logEntry[entryId], 0, sizeof(WDC_DRIVE_ESSENTIALS));
		memcpy(&directory->logEntry[entryId].metaData, fileOffset, sizeof(WDC_DE_VU_FILE_META_DATA));
		directory->logEntry[entryId].metaData.fileName[WDC_DE_FILE_NAME_SIZE - 1] = '\0';
		wdc_UtilsDeleteCharFromString((char*)directory->logEntry[entryId].metaData.fileName, WDC_DE_FILE_NAME_SIZE, ' ');
		if (0 == directory->logEntry[entryId].metaData.fileID)
		{
			continue;
		}
		directory->logEntry[entryId].essentialType = wdc_get_essential_type(directory->logEntry[entryId].metaData.fileName);
		/*fprintf(stderr, "WDC : %s: NVMe VU Log Entry %d, fileName = %s, fileSize = 0x%lx, fileId = 0x%x\n",
			__func__, entryId, directory->logEntry[entryId].metaData.fileName,
			(long unsigned int)directory->logEntry[entryId].metaData.fileSize, directory->logEntry[entryId].metaData.fileID);
		 */
		entryId++;
	}
	directory->numOfValidLogEntries = entryId;
	end:
	if (fileDirectory != NULL)
		free(fileDirectory);

	return ret;
}

int wdc_fetch_log_file_from_device(int fd, __u32 fileId, __u16 spiDestn, __u64 fileSize, __u8* dataBuffer)
{
	int ret = WDC_STATUS_FAILURE;
	__u32                     chunckSize = WDC_DE_VU_READ_BUFFER_STANDARD_OFFSET;
	__u32                     maximumTransferLength = 0;
	__u32                     buffSize = 0;
	__u64                     offsetIdx = 0;

	if (!fd || !dataBuffer || !fileSize)
	{
		ret = WDC_STATUS_INVALID_PARAMETER;
		goto end;
	}

	wdc_get_max_transfer_len(fd, &maximumTransferLength);

	/* Fetch Log File Data */
	if ((fileSize >= maximumTransferLength) || (fileSize > 0xffffffff))
	{
		chunckSize = WDC_DE_VU_READ_BUFFER_STANDARD_OFFSET;
		if (maximumTransferLength < WDC_DE_VU_READ_BUFFER_STANDARD_OFFSET)
			chunckSize = maximumTransferLength;

		buffSize = chunckSize;
		for (offsetIdx = 0; (offsetIdx * chunckSize) < fileSize; offsetIdx++)
		{
			if (((offsetIdx * chunckSize) + buffSize) > fileSize)
				buffSize = (__u32)(fileSize - (offsetIdx * chunckSize));
			/* Limitation in VU read buffer - offsetIdx and bufferSize are not greater than u32 */
			ret = wdc_de_VU_read_buffer(fd, fileId, spiDestn,
					(__u32)((offsetIdx * chunckSize) / sizeof(__u32)), dataBuffer + (offsetIdx * chunckSize), &buffSize);
			if (ret != WDC_STATUS_SUCCESS)
			{
				fprintf(stderr, "ERROR : WDC : %s: wdc_de_VU_read_buffer failed with ret = %d, fileId = 0x%x, fileSize = 0x%lx\n",
						__func__, ret, fileId, (long unsigned int)fileSize);
				break;
			}
		}
	} else {
		buffSize = (__u32)fileSize;
		ret = wdc_de_VU_read_buffer(fd, fileId, spiDestn,
				(__u32)((offsetIdx * chunckSize) / sizeof(__u32)), dataBuffer, &buffSize);
		if (ret != WDC_STATUS_SUCCESS)
		{
			fprintf(stderr, "ERROR : WDC : %s: wdc_de_VU_read_buffer failed with ret = %d, fileId = 0x%x, fileSize = 0x%lx\n",
					__func__, ret, fileId, (long unsigned int)fileSize);
		}
	}

	end:
	return ret;
}

int wdc_de_get_dump_trace(int fd, char * filePath, __u16 binFileNameLen, char *binFileName)
{
	int                     ret = WDC_STATUS_FAILURE;
	__u8                    *readBuffer = NULL;
	__u32                   readBufferLen = 0;
	__u32                   lastPktReadBufferLen = 0;
	__u32                   maxTransferLen = 0;
	__u32                   dumptraceSize = 0;
	__u32                   chunkSize = 0;
	__u32                   chunks = 0;
	__u32                   offset = 0;
	__u8                    loop = 0;
	__u16					i = 0;
	__u32                   maximumTransferLength = 0;

	if (!fd || !binFileName || !filePath)
	{
		ret = WDC_STATUS_INVALID_PARAMETER;
		return ret;
	}

	wdc_get_max_transfer_len(fd, &maximumTransferLength);

	do
	{
		/* Get dumptrace size */
		ret = wdc_de_VU_read_size(fd, 0, WDC_DE_DUMPTRACE_DESTINATION, &dumptraceSize);
		if (ret != WDC_STATUS_SUCCESS)
		{
			fprintf(stderr, "ERROR : WDC : %s: wdc_de_VU_read_size failed with ret = %d\n",
					__func__, ret);
			break;
		}

		/* Make sure the size requested is greater than dword */
		if (dumptraceSize < 4)
		{
			ret = WDC_STATUS_FAILURE;
			fprintf(stderr, "ERROR : WDC : %s: wdc_de_VU_read_size failed, read size is less than 4 bytes, dumptraceSize = 0x%x\n",
					__func__, dumptraceSize);
			break;
		}

		/* Choose the least max transfer length */
		maxTransferLen = maximumTransferLength < WDC_DE_READ_MAX_TRANSFER_SIZE ? maximumTransferLength : WDC_DE_READ_MAX_TRANSFER_SIZE;

		/* Comment from  FW Team:
		 * The max non - block transfer size is 0xFFFF (16 bits allowed as the block size).Use 0x8000
		 * to keep it on a word - boundary.
		 * max_xfer = int(pow(2, id_data['MDTS'])) * 4096 # 4k page size as reported in pcie capabiltiies
		 */
		chunkSize = dumptraceSize < maxTransferLen ? dumptraceSize : maxTransferLen;
		chunks = (dumptraceSize / maxTransferLen) + ((dumptraceSize % maxTransferLen) ? 1 : 0);

		readBuffer = (unsigned char *)calloc(dumptraceSize, sizeof(unsigned char));
		readBufferLen = chunkSize;
		lastPktReadBufferLen = (dumptraceSize % maxTransferLen) ? (dumptraceSize % maxTransferLen) : chunkSize;

		if (readBuffer == NULL)
		{
			fprintf(stderr, "ERROR : WDC : %s: readBuffer calloc failed\n", __func__);
			ret = WDC_STATUS_INSUFFICIENT_MEMORY;
			break;
		}

		for (i = 0; i < chunks; i++)
		{
			offset = ((i*chunkSize) / 4);

			/* Last loop call, Assign readBufferLen to read only left over bytes */
			if (i == (chunks - 1))
			{
				readBufferLen = lastPktReadBufferLen;
			}

			ret = wdc_de_VU_read_buffer(fd, 0, WDC_DE_DUMPTRACE_DESTINATION, 0, readBuffer + offset, &readBufferLen);
			if (ret != WDC_STATUS_SUCCESS)
			{
				fprintf(stderr, "ERROR : WDC : %s: wdc_de_VU_read_buffer failed, ret = %d on offset 0x%x\n",
						__func__, ret, offset);
				break;
			}
		}
	} while (loop);

	if (ret == WDC_STATUS_SUCCESS)
	{
		ret = wdc_WriteToFile(binFileName, (char*)readBuffer, dumptraceSize);
		if (ret != WDC_STATUS_SUCCESS)
			fprintf(stderr, "ERROR : WDC : %s: wdc_WriteToFile failed, ret = %d\n", __func__, ret);
	} else {
		fprintf(stderr, "ERROR : WDC : %s: Read Buffer Loop failed, ret = %d\n", __func__, ret);
	}

	if (readBuffer)
	{
		free(readBuffer);
	}

	return ret;
}

static int wdc_do_drive_essentials(int fd, char *dir, char *key)
{
	int ret = 0;
	void *retPtr;
	char                      fileName[MAX_PATH_LEN];
	__s8                      bufferFolderPath[MAX_PATH_LEN];
	char                      bufferFolderName[MAX_PATH_LEN];
	char                      tarFileName[MAX_PATH_LEN];
	char                      tarFiles[MAX_PATH_LEN];
	char                      tarCmd[MAX_PATH_LEN+MAX_PATH_LEN];
	UtilsTimeInfo             timeInfo;
	__u8                      timeString[MAX_PATH_LEN];
	__u8                      serialNo[WDC_SERIAL_NO_LEN];
	__u8                      firmwareRevision[WDC_NVME_FIRMWARE_REV_LEN];
	__u8                      idSerialNo[WDC_SERIAL_NO_LEN];
	__u8                      idFwRev[WDC_NVME_FIRMWARE_REV_LEN];
	__u8                      featureIdBuff[4];
	char                      currDir[MAX_PATH_LEN];
	char                      *dataBuffer     = NULL;
	__u32 					  elogNumEntries, elogBufferSize;
	__u32 					  dataBufferSize;
	__u32                     listIdx = 0;
	__u32                     vuLogIdx = 0;
	__u32 					  result;
	__u32                     maxNumOfVUFiles = 0;
	struct nvme_id_ctrl ctrl;
	struct nvme_id_ns ns;
	struct nvme_error_log_page *elogBuffer;
	struct nvme_smart_log smart_log;
	struct nvme_firmware_log_page fw_log;
	PWDC_NVME_DE_VU_LOGPAGES vuLogInput = NULL;
	WDC_DE_VU_LOG_DIRECTORY deEssentialsList;

	memset(bufferFolderPath,0,sizeof(bufferFolderPath));
	memset(bufferFolderName,0,sizeof(bufferFolderName));
	memset(tarFileName,0,sizeof(tarFileName));
	memset(tarFiles,0,sizeof(tarFiles));
	memset(tarCmd,0,sizeof(tarCmd));
	memset(&timeInfo,0,sizeof(timeInfo));
	memset(&vuLogInput, 0, sizeof(vuLogInput));

	if (wdc_get_serial_and_fw_rev(fd, (char *)idSerialNo, (char *)idFwRev))
	{
		fprintf(stderr, "ERROR : WDC : get serial # and fw revision failed\n");
		return -1;
	} else {
		fprintf(stderr, "Get Drive Essentials Data for device serial #: %s and fw revision: %s\n",
				idSerialNo, idFwRev);
	}

	/* Create Drive Essentials directory  */
	wdc_UtilsGetTime(&timeInfo);
	memset(timeString, 0, sizeof(timeString));
	wdc_UtilsSnprintf((char*)timeString, MAX_PATH_LEN, "%02u%02u%02u_%02u%02u%02u",
			timeInfo.year, timeInfo.month, timeInfo.dayOfMonth,
			timeInfo.hour, timeInfo.minute, timeInfo.second);

	wdc_UtilsSnprintf((char*)serialNo,WDC_SERIAL_NO_LEN,(char*)idSerialNo);
	/* Remove any space form serialNo */
	wdc_UtilsDeleteCharFromString((char*)serialNo, WDC_SERIAL_NO_LEN, ' ');

	memset(firmwareRevision, 0, sizeof(firmwareRevision));
	wdc_UtilsSnprintf((char*)firmwareRevision, WDC_NVME_FIRMWARE_REV_LEN, (char*)idFwRev);
	/* Remove any space form FirmwareRevision */
	wdc_UtilsDeleteCharFromString((char*)firmwareRevision, WDC_NVME_FIRMWARE_REV_LEN, ' ');

	wdc_UtilsSnprintf((char*)bufferFolderName, MAX_PATH_LEN, "%s_%s_%s_%s",
			"DRIVE_ESSENTIALS", (char*)serialNo, (char*)firmwareRevision, (char*)timeString);

	if (dir != NULL) {
		wdc_UtilsSnprintf((char*)bufferFolderPath, MAX_PATH_LEN, "%s%s%s",
				(char *)dir, WDC_DE_PATH_SEPARATOR, (char *)bufferFolderName);
	} else {
		retPtr = getcwd((char*)currDir, MAX_PATH_LEN);
		if (retPtr != NULL)
			wdc_UtilsSnprintf((char*)bufferFolderPath, MAX_PATH_LEN, "%s%s%s",
					(char *)currDir, WDC_DE_PATH_SEPARATOR, (char *)bufferFolderName);
		else {
			fprintf(stderr, "ERROR : WDC : get current working directory failed\n");
			return -1;
		}
	}

	ret = wdc_UtilsCreateDir((char*)bufferFolderPath);
	if (ret != 0)
	{
		fprintf(stderr, "ERROR : WDC : create directory failed, ret = %d, dir = %s\n", ret, bufferFolderPath);
		return -1;
	} else {
		fprintf(stderr, "Store Drive Essentials bin files in directory: %s\n", bufferFolderPath);
	}

	/* Get Identify Controller Data */
	memset(&ctrl, 0, sizeof (struct nvme_id_ctrl));
	ret = nvme_identify_ctrl(fd, &ctrl);
	if (ret) {
		fprintf(stderr, "ERROR : WDC : nvme_identify_ctrl() failed, ret = %d\n", ret);
		return -1;
	} else {
		wdc_UtilsSnprintf(fileName, MAX_PATH_LEN, "%s%s%s_%s_%s.bin", (char*)bufferFolderPath, WDC_DE_PATH_SEPARATOR,
				"IdentifyController", (char*)serialNo, (char*)timeString);
		wdc_WriteToFile(fileName, (char*)&ctrl, sizeof (struct nvme_id_ctrl));
	}

	memset(&ns, 0, sizeof (struct nvme_id_ns));
	ret = nvme_identify_ns(fd, 1, 0, &ns);
	if (ret) {
		fprintf(stderr, "ERROR : WDC : nvme_identify_ns() failed, ret = %d\n", ret);
	} else {
		wdc_UtilsSnprintf(fileName, MAX_PATH_LEN, "%s%s%s_%s_%s.bin", (char*)bufferFolderPath, WDC_DE_PATH_SEPARATOR,
				"IdentifyNamespace", (char*)serialNo, (char*)timeString);
		wdc_WriteToFile(fileName, (char*)&ns, sizeof (struct nvme_id_ns));
	}

	/* Get Log Pages (0x01, 0x02, 0x03, 0xC0 and 0xE3) */
	elogNumEntries = WDC_DE_DEFAULT_NUMBER_OF_ERROR_ENTRIES;
	elogBufferSize = elogNumEntries*sizeof(struct nvme_error_log_page);
	dataBuffer = calloc(1, elogBufferSize);
	elogBuffer = (struct nvme_error_log_page *)dataBuffer;

	ret = nvme_error_log(fd, elogNumEntries, elogBuffer);
	if (ret) {
		fprintf(stderr, "ERROR : WDC : nvme_error_log() failed, ret = %d\n", ret);
	} else {
		wdc_UtilsSnprintf(fileName, MAX_PATH_LEN, "%s%s%s_%s_%s.bin", (char*)bufferFolderPath, WDC_DE_PATH_SEPARATOR,
				"ErrorLog", (char*)serialNo, (char*)timeString);
		wdc_WriteToFile(fileName, (char*)elogBuffer, elogBufferSize);
	}

	free(dataBuffer);
	dataBuffer = NULL;

	/* Get Smart log page  */
	memset(&smart_log, 0, sizeof (struct nvme_smart_log));
	ret = nvme_smart_log(fd, NVME_NSID_ALL, &smart_log);
	if (ret) {
		fprintf(stderr, "ERROR : WDC : nvme_smart_log() failed, ret = %d\n", ret);
	} else {
		wdc_UtilsSnprintf(fileName, MAX_PATH_LEN, "%s%s%s_%s_%s.bin", (char*)bufferFolderPath, WDC_DE_PATH_SEPARATOR,
				"SmartLog", (char*)serialNo, (char*)timeString);
		wdc_WriteToFile(fileName, (char*)&smart_log, sizeof(struct nvme_smart_log));
	}

	/* Get FW Slot log page  */
	memset(&fw_log, 0, sizeof (struct nvme_firmware_log_page));
	ret = nvme_fw_log(fd, &fw_log);
	if (ret) {
		fprintf(stderr, "ERROR : WDC : nvme_fw_log() failed, ret = %d\n", ret);
	} else {
		wdc_UtilsSnprintf(fileName, MAX_PATH_LEN, "%s%s%s_%s_%s.bin", (char*)bufferFolderPath, WDC_DE_PATH_SEPARATOR,
				"FwSLotLog", (char*)serialNo, (char*)timeString);
		wdc_WriteToFile(fileName, (char*)&fw_log, sizeof(struct nvme_firmware_log_page));
	}

	/* Get VU log pages  */
	/* define inputs for vendor unique log pages */
	vuLogInput = (PWDC_NVME_DE_VU_LOGPAGES)calloc(1, sizeof(WDC_NVME_DE_VU_LOGPAGES));
	vuLogInput->numOfVULogPages = sizeof(deVULogPagesList) / sizeof(deVULogPagesList[0]);

	for (vuLogIdx = 0; vuLogIdx < vuLogInput->numOfVULogPages; vuLogIdx++)
	{
		dataBufferSize = deVULogPagesList[vuLogIdx].logPageLen;
		dataBuffer = calloc(1, dataBufferSize);
		memset(dataBuffer, 0, dataBufferSize);

		ret = nvme_get_log(fd, WDC_DE_GLOBAL_NSID, deVULogPagesList[vuLogIdx].logPageId,
				   dataBufferSize, dataBuffer);
		if (ret) {
			fprintf(stderr, "ERROR : WDC : nvme_get_log() for log page 0x%x failed, ret = %d\n",
					deVULogPagesList[vuLogIdx].logPageId, ret);
		} else {
			wdc_UtilsDeleteCharFromString((char*)deVULogPagesList[vuLogIdx].logPageIdStr, 4, ' ');
			wdc_UtilsSnprintf(fileName, MAX_PATH_LEN, "%s%s%s_%s_%s_%s.bin", (char*)bufferFolderPath, WDC_DE_PATH_SEPARATOR,
					"LogPage", (char*)&deVULogPagesList[vuLogIdx].logPageIdStr, (char*)serialNo, (char*)timeString);
			wdc_WriteToFile(fileName, (char*)dataBuffer, dataBufferSize);
		}

		free(dataBuffer);
		dataBuffer = NULL;
	}

	free(vuLogInput);

	/* Get NVMe Features (0x01, 0x02, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C) */
	for (listIdx = 1; listIdx < (sizeof(deFeatureIdList) / sizeof(deFeatureIdList[0])); listIdx++)
	{
		memset(featureIdBuff, 0, sizeof(featureIdBuff));
		/* skipping  LbaRangeType as it is an optional nvme command and not supported */
		if (deFeatureIdList[listIdx].featureId == FID_LBA_RANGE_TYPE)
			continue;
		ret = nvme_get_feature(fd, WDC_DE_GLOBAL_NSID, deFeatureIdList[listIdx].featureId, FS_CURRENT, 0,
				sizeof(featureIdBuff), &featureIdBuff, &result);

		if (ret) {
			fprintf(stderr, "ERROR : WDC : nvme_get_feature id 0x%x failed, ret = %d\n",
					deFeatureIdList[listIdx].featureId, ret);
		} else {
			wdc_UtilsSnprintf(fileName, MAX_PATH_LEN, "%s%s%s0x%x_%s_%s_%s.bin", (char*)bufferFolderPath, WDC_DE_PATH_SEPARATOR,
					"FEATURE_ID_", deFeatureIdList[listIdx].featureId,
					deFeatureIdList[listIdx].featureName, serialNo, timeString);
			wdc_WriteToFile(fileName, (char*)featureIdBuff, sizeof(featureIdBuff));
		}
	}

	/* Read Debug Directory */
	ret = wdc_get_log_dir_max_entries(fd, &maxNumOfVUFiles);
	if (ret == WDC_STATUS_SUCCESS)
	{
		memset(&deEssentialsList, 0, sizeof(deEssentialsList));
		deEssentialsList.logEntry = (WDC_DRIVE_ESSENTIALS*)calloc(1, sizeof(WDC_DRIVE_ESSENTIALS)*maxNumOfVUFiles);
		deEssentialsList.maxNumLogEntries = maxNumOfVUFiles;

		/* Fetch VU File Directory */
		ret = wdc_fetch_log_directory(fd, &deEssentialsList);
		if (ret == WDC_STATUS_SUCCESS)
		{
			/* Get Debug Data Files */
			for (listIdx = 0; listIdx < deEssentialsList.numOfValidLogEntries; listIdx++)
			{
				if (0 == deEssentialsList.logEntry[listIdx].metaData.fileSize)
				{
					fprintf(stderr, "ERROR : WDC : File Size for %s is 0\n",
							deEssentialsList.logEntry[listIdx].metaData.fileName);
					ret = WDC_STATUS_FILE_SIZE_ZERO;
				} else {
					/* Fetch Log File Data */
					dataBuffer = (char *)calloc(1, (size_t)deEssentialsList.logEntry[listIdx].metaData.fileSize);
					ret = wdc_fetch_log_file_from_device(fd, deEssentialsList.logEntry[listIdx].metaData.fileID, WDC_DE_DESTN_SPI, deEssentialsList.logEntry[listIdx].metaData.fileSize,
							(__u8 *)dataBuffer);

					/* Write databuffer to file */
					if (ret == WDC_STATUS_SUCCESS)
					{
						memset(fileName, 0, sizeof(fileName));
						wdc_UtilsSnprintf(fileName, MAX_PATH_LEN, "%s%s%s_%s_%s.bin", bufferFolderPath, WDC_DE_PATH_SEPARATOR,
								deEssentialsList.logEntry[listIdx].metaData.fileName, serialNo, timeString);
						if (deEssentialsList.logEntry[listIdx].metaData.fileSize > 0xffffffff)
						{
							wdc_WriteToFile(fileName, dataBuffer, 0xffffffff);
							wdc_WriteToFile(fileName, dataBuffer + 0xffffffff, (__u32)(deEssentialsList.logEntry[listIdx].metaData.fileSize - 0xffffffff));
						} else {
							wdc_WriteToFile(fileName, dataBuffer, (__u32)deEssentialsList.logEntry[listIdx].metaData.fileSize);
						}
					} else {
						fprintf(stderr, "ERROR : WDC : wdc_fetch_log_file_from_device: %s failed, ret = %d\n",
								deEssentialsList.logEntry[listIdx].metaData.fileName, ret);
					}
					free(dataBuffer);
					dataBuffer = NULL;
				}
			}
		} else {
			fprintf(stderr, "WDC : wdc_fetch_log_directory failed, ret = %d\n", ret);
		}

		free(deEssentialsList.logEntry);
		deEssentialsList.logEntry = NULL;
	} else {
		fprintf(stderr, "WDC : wdc_get_log_dir_max_entries failed, ret = %d\n", ret);
	}

	/* Get Dump Trace Data */
	wdc_UtilsSnprintf(fileName, MAX_PATH_LEN, "%s%s%s_%s_%s.bin", (char*)bufferFolderPath, WDC_DE_PATH_SEPARATOR, "dumptrace", serialNo, timeString);
	if (WDC_STATUS_SUCCESS != (ret = wdc_de_get_dump_trace(fd, (char*)bufferFolderPath, 0, fileName)))
	{
		fprintf(stderr, "ERROR : WDC : wdc_de_get_dump_trace failed, ret = %d\n", ret);
	}

	/* Tar the Drive Essentials directory */
	wdc_UtilsSnprintf(tarFileName, sizeof(tarFileName), "%s%s", (char*)bufferFolderPath, WDC_DE_TAR_FILE_EXTN);
	if (dir != NULL) {
		wdc_UtilsSnprintf(tarFiles, sizeof(tarFiles), "%s%s%s%s%s",
				(char*)dir, WDC_DE_PATH_SEPARATOR, (char*)bufferFolderName, WDC_DE_PATH_SEPARATOR, WDC_DE_TAR_FILES);
	} else {
		wdc_UtilsSnprintf(tarFiles, sizeof(tarFiles), "%s%s%s", (char*)bufferFolderName, WDC_DE_PATH_SEPARATOR, WDC_DE_TAR_FILES);
	}
	wdc_UtilsSnprintf(tarCmd, sizeof(tarCmd), "%s %s %s", WDC_DE_TAR_CMD, (char*)tarFileName, (char*)tarFiles);

	ret = system(tarCmd);

	if (ret) {
		fprintf(stderr, "ERROR : WDC : Tar of Drive Essentials data failed, ret = %d\n", ret);
	}

	fprintf(stderr, "Get of Drive Essentials data successful\n");
	return 0;
}

static int wdc_drive_essentials(int argc, char **argv, struct command *command,
		struct plugin *plugin)
{
	char *desc = "Capture Drive Essentials.";
	char *dirName = "Output directory pathname.";

	char d[PATH_MAX] = {0};
	char k[PATH_MAX] = {0};
	char *d_ptr;
	int fd;
	struct config {
		char *dirName;
	};

	struct config cfg = {
			.dirName = NULL,
	};

	const struct argconfig_commandline_options command_line_options[] = {
			{"dir-name", 'd', "DIRECTORY", CFG_STRING, &cfg.dirName, required_argument, dirName},
			{ NULL, '\0', NULL, CFG_NONE, NULL, no_argument, desc},
			{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, NULL, 0);
	if (fd < 0)
		return fd;

	if ( wdc_check_device_sxslcl(fd) < 0) {
		fprintf(stderr, "WARNING : WDC : Device not supported\n");
		return -1;
	}

	if (cfg.dirName != NULL) {
		strncpy(d, cfg.dirName, PATH_MAX - 1);
		d_ptr = d;
	} else {
		d_ptr = NULL;
	}

	return wdc_do_drive_essentials(fd, d_ptr, k);
}
