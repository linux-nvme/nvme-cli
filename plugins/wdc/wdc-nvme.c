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

#include "common.h"
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

#define WDC_NVME_SUBCMD_SHIFT				8

#define WDC_NVME_LOG_SIZE_DATA_LEN			0x08
#define WDC_NVME_LOG_SIZE_HDR_LEN			0x08

/* Device Config */
#define WDC_NVME_VID					0x1c58
#define WDC_NVME_VID_2					0x1b96
#define WDC_NVME_SNDK_VID				0x15b7

#define WDC_NVME_SN100_DEV_ID				0x0003
#define WDC_NVME_SN200_DEV_ID				0x0023
#define WDC_NVME_SN630_DEV_ID				0x2200
#define WDC_NVME_SN630_DEV_ID_1				0x2201
#define WDC_NVME_SN840_DEV_ID				0x2300
#define WDC_NVME_SN840_DEV_ID_1				0x2500
#define WDC_NVME_SN640_DEV_ID				0x2400
#define WDC_NVME_SN640_DEV_ID_1				0x2401
#define WDC_NVME_SN640_DEV_ID_2				0x2402
#define WDC_NVME_SXSLCL_DEV_ID				0x2001
#define WDC_NVME_SN520_DEV_ID				0x5003
#define WDC_NVME_SN520_DEV_ID_1				0x5004
#define WDC_NVME_SN520_DEV_ID_2				0x5005
#define WDC_NVME_SN720_DEV_ID				0x5002
#define WDC_NVME_SN730A_DEV_ID				0x5006
#define WDC_NVME_SN730B_DEV_ID				0x3714
#define WDC_NVME_SN730B_DEV_ID_1			0x3734
#define WDC_NVME_SN340_DEV_ID				0x500d

#define WDC_DRIVE_CAP_CAP_DIAG				0x0000000000000001
#define WDC_DRIVE_CAP_INTERNAL_LOG			0x0000000000000002
#define WDC_DRIVE_CAP_C1_LOG_PAGE			0x0000000000000004
#define WDC_DRIVE_CAP_CA_LOG_PAGE			0x0000000000000008
#define WDC_DRIVE_CAP_D0_LOG_PAGE			0x0000000000000010
#define WDC_DRIVE_CAP_DRIVE_STATUS			0x0000000000000020
#define WDC_DRIVE_CAP_CLEAR_ASSERT			0x0000000000000040
#define WDC_DRIVE_CAP_CLEAR_PCIE			0x0000000000000080
#define WDC_DRIVE_CAP_RESIZE				0x0000000000000100
#define WDC_DRIVE_CAP_NAND_STATS			0x0000000000000200
#define WDC_DRIVE_CAP_DRIVE_LOG				0x0000000000000400
#define WDC_DRIVE_CAP_CRASH_DUMP			0x0000000000000800
#define WDC_DRIVE_CAP_PFAIL_DUMP			0x0000000000001000


#define WDC_DRIVE_CAP_DRIVE_ESSENTIALS			0x0000000100000000
#define WDC_DRIVE_CAP_DUI_DATA				0x0000000200000000
#define WDC_SN730B_CAP_VUC_LOG				0x0000000400000000
#define WDC_DRIVE_CAP_SN340_DUI				0x0000000800000000
#define WDC_DRIVE_CAP_SMART_LOG_MASK	(WDC_DRIVE_CAP_C1_LOG_PAGE | WDC_DRIVE_CAP_CA_LOG_PAGE | \
					 WDC_DRIVE_CAP_D0_LOG_PAGE)

/* SN730 Get Log Capabilities */
#define SN730_NVME_GET_LOG_OPCODE			0xc2
#define SN730_GET_FULL_LOG_LENGTH			0x00080009
#define SN730_GET_KEY_LOG_LENGTH			0x00090009
#define SN730_GET_COREDUMP_LOG_LENGTH			0x00120009
#define SN730_GET_EXTENDED_LOG_LENGTH			0x00420009

#define SN730_GET_FULL_LOG_SUBOPCODE			0x00010009
#define SN730_GET_KEY_LOG_SUBOPCODE			0x00020009
#define SN730_GET_CORE_LOG_SUBOPCODE			0x00030009
#define SN730_GET_EXTEND_LOG_SUBOPCODE			0x00040009
#define SN730_LOG_CHUNK_SIZE				0x1000

/* Drive Resize */
#define WDC_NVME_DRIVE_RESIZE_OPCODE			0xCC
#define WDC_NVME_DRIVE_RESIZE_CMD			0x03
#define WDC_NVME_DRIVE_RESIZE_SUBCMD			0x01

/* Capture Diagnostics */
#define WDC_NVME_CAP_DIAG_HEADER_TOC_SIZE		WDC_NVME_LOG_SIZE_DATA_LEN
#define WDC_NVME_CAP_DIAG_OPCODE			0xE6
#define WDC_NVME_CAP_DIAG_CMD_OPCODE			0xC6
#define WDC_NVME_CAP_DIAG_SUBCMD			0x00
#define WDC_NVME_CAP_DIAG_CMD				0x00

#define WDC_NVME_CRASH_DUMP_TYPE			1
#define WDC_NVME_PFAIL_DUMP_TYPE			2

/* Capture Device Unit Info */
#define WDC_NVME_CAP_DUI_HEADER_SIZE			0x400
#define WDC_NVME_CAP_DUI_OPCODE				0xFA
#define WDC_NVME_CAP_DUI_DISABLE_IO         0x01
#define WDC_NVME_DUI_MAX_SECTION			0x3A
#define WDC_NVME_DUI_MAX_SECTION_V2			0x26
#define WDC_NVME_DUI_MAX_DATA_AREA			0x05

/* Crash dump */
#define WDC_NVME_CRASH_DUMP_SIZE_DATA_LEN		WDC_NVME_LOG_SIZE_DATA_LEN
#define WDC_NVME_CRASH_DUMP_SIZE_NDT			0x02
#define WDC_NVME_CRASH_DUMP_SIZE_CMD			0x20
#define WDC_NVME_CRASH_DUMP_SIZE_SUBCMD			0x03

#define WDC_NVME_CRASH_DUMP_OPCODE			WDC_NVME_CAP_DIAG_CMD_OPCODE
#define WDC_NVME_CRASH_DUMP_CMD				0x20
#define WDC_NVME_CRASH_DUMP_SUBCMD			0x04

/* PFail Crash dump */
#define WDC_NVME_PF_CRASH_DUMP_SIZE_DATA_LEN		WDC_NVME_LOG_SIZE_HDR_LEN
#define WDC_NVME_PF_CRASH_DUMP_SIZE_NDT			0x02
#define WDC_NVME_PF_CRASH_DUMP_SIZE_CMD			0x20
#define WDC_NVME_PF_CRASH_DUMP_SIZE_SUBCMD		0x05

#define WDC_NVME_PF_CRASH_DUMP_OPCODE			WDC_NVME_CAP_DIAG_CMD_OPCODE
#define WDC_NVME_PF_CRASH_DUMP_CMD			0x20
#define WDC_NVME_PF_CRASH_DUMP_SUBCMD			0x06

/* Drive Log */
#define WDC_NVME_DRIVE_LOG_SIZE_OPCODE			 WDC_NVME_CAP_DIAG_CMD_OPCODE
#define WDC_NVME_DRIVE_LOG_SIZE_DATA_LEN		WDC_NVME_LOG_SIZE_DATA_LEN
#define WDC_NVME_DRIVE_LOG_SIZE_NDT			0x02
#define WDC_NVME_DRIVE_LOG_SIZE_CMD			0x20
#define WDC_NVME_DRIVE_LOG_SIZE_SUBCMD			0x01

#define WDC_NVME_DRIVE_LOG_OPCODE			WDC_NVME_CAP_DIAG_CMD_OPCODE
#define WDC_NVME_DRIVE_LOG_CMD				0x20
#define WDC_NVME_DRIVE_LOG_SUBCMD			0x00

/* Purge and Purge Monitor */
#define WDC_NVME_PURGE_CMD_OPCODE			0xDD
#define WDC_NVME_PURGE_MONITOR_OPCODE			0xDE
#define WDC_NVME_PURGE_MONITOR_DATA_LEN			0x2F
#define WDC_NVME_PURGE_MONITOR_CMD_CDW10		0x0000000C
#define WDC_NVME_PURGE_MONITOR_TIMEOUT			0x7530
#define WDC_NVME_PURGE_CMD_SEQ_ERR			0x0C
#define WDC_NVME_PURGE_INT_DEV_ERR			0x06

#define WDC_NVME_PURGE_STATE_IDLE			0x00
#define WDC_NVME_PURGE_STATE_DONE			0x01
#define WDC_NVME_PURGE_STATE_BUSY			0x02
#define WDC_NVME_PURGE_STATE_REQ_PWR_CYC		0x03
#define WDC_NVME_PURGE_STATE_PWR_CYC_PURGE		0x04

/* Clear dumps */
#define WDC_NVME_CLEAR_DUMP_OPCODE			0xFF
#define WDC_NVME_CLEAR_CRASH_DUMP_CMD			0x03
#define WDC_NVME_CLEAR_CRASH_DUMP_SUBCMD		0x05
#define WDC_NVME_CLEAR_PF_CRASH_DUMP_SUBCMD		0x06

/* Additional Smart Log */
#define WDC_ADD_LOG_BUF_LEN				0x4000
#define WDC_NVME_ADD_LOG_OPCODE				0xC1
#define WDC_GET_LOG_PAGE_SSD_PERFORMANCE		0x37
#define WDC_NVME_GET_STAT_PERF_INTERVAL_LIFETIME	0x0F

/* C2 Log Page */
#define WDC_NVME_GET_DEV_MGMNT_LOG_PAGE_OPCODE		0xC2
#define WDC_C2_LOG_BUF_LEN				0x1000
#define WDC_C2_LOG_PAGES_SUPPORTED_ID			0x08
#define WDC_C2_THERMAL_THROTTLE_STATUS_ID		0x18
#define WDC_C2_ASSERT_DUMP_PRESENT_ID			0x19
#define WDC_C2_USER_EOL_STATUS_ID			0x1A
#define WDC_C2_USER_EOL_STATE_ID			0x1C
#define WDC_C2_SYSTEM_EOL_STATE_ID			0x1D
#define WDC_C2_FORMAT_CORRUPT_REASON_ID			0x1E
#define WDC_EOL_STATUS_NORMAL				cpu_to_le32(0x00000000)
#define WDC_EOL_STATUS_END_OF_LIFE			cpu_to_le32(0x00000001)
#define WDC_EOL_STATUS_READ_ONLY			cpu_to_le32(0x00000002)
#define WDC_ASSERT_DUMP_NOT_PRESENT			cpu_to_le32(0x00000000)
#define WDC_ASSERT_DUMP_PRESENT				cpu_to_le32(0x00000001)
#define WDC_THERMAL_THROTTLING_OFF			cpu_to_le32(0x00000000)
#define WDC_THERMAL_THROTTLING_ON			cpu_to_le32(0x00000001)
#define WDC_THERMAL_THROTTLING_UNAVAILABLE		cpu_to_le32(0x00000002)
#define WDC_FORMAT_NOT_CORRUPT				cpu_to_le32(0x00000000)
#define WDC_FORMAT_CORRUPT_FW_ASSERT			cpu_to_le32(0x00000001)
#define WDC_FORMAT_CORRUPT_UNKNOWN			cpu_to_le32(0x000000FF)

/* CA Log Page */
#define WDC_NVME_GET_DEVICE_INFO_LOG_OPCODE		0xCA
#define WDC_CA_LOG_BUF_LEN				0x80

/* C0 EOL Status Log Page */
#define WDC_NVME_GET_EOL_STATUS_LOG_OPCODE		0xC0
#define WDC_NVME_EOL_STATUS_LOG_LEN			0x200

/* D0 Smart Log Page */
#define WDC_NVME_GET_VU_SMART_LOG_OPCODE		0xD0
#define WDC_NVME_VU_SMART_LOG_LEN			0x200

/* Clear PCIe Correctable Errors */
#define WDC_NVME_CLEAR_PCIE_CORR_OPCODE			WDC_NVME_CAP_DIAG_CMD_OPCODE
#define WDC_NVME_CLEAR_PCIE_CORR_CMD			0x22
#define WDC_NVME_CLEAR_PCIE_CORR_SUBCMD			0x04

/* Clear Assert Dump Status */
#define WDC_NVME_CLEAR_ASSERT_DUMP_OPCODE		0xD8
#define WDC_NVME_CLEAR_ASSERT_DUMP_CMD			0x03
#define WDC_NVME_CLEAR_ASSERT_DUMP_SUBCMD		0x05

/* Drive Essentials */
#define WDC_DE_DEFAULT_NUMBER_OF_ERROR_ENTRIES		64
#define WDC_DE_GENERIC_BUFFER_SIZE			80
#define WDC_DE_GLOBAL_NSID				0xFFFFFFFF
#define WDC_DE_DEFAULT_NAMESPACE_ID			0x01
#define WDC_DE_PATH_SEPARATOR				"/"
#define WDC_DE_TAR_FILES				"*.bin"
#define WDC_DE_TAR_FILE_EXTN				".tar.gz"
#define WDC_DE_TAR_CMD					"tar -czf"

/* VS NAND Stats */
#define WDC_NVME_NAND_STATS_LOG_ID			0xFB
#define WDC_NVME_NAND_STATS_SIZE			0x200

/* VU Opcodes */
#define WDC_DE_VU_READ_SIZE_OPCODE			0xC0
#define WDC_DE_VU_READ_BUFFER_OPCODE			0xC2

#define WDC_DE_FILE_HEADER_SIZE				4
#define WDC_DE_FILE_OFFSET_SIZE				2
#define WDC_DE_FILE_NAME_SIZE				32
#define WDC_DE_VU_READ_BUFFER_STANDARD_OFFSET		0x8000
#define WDC_DE_READ_MAX_TRANSFER_SIZE			0x8000

#define WDC_DE_MANUFACTURING_INFO_PAGE_FILE_NAME	"manufacturing_info"  /* Unique log entry page name. */
#define WDC_DE_CORE_DUMP_FILE_NAME			"core_dump"
#define WDC_DE_EVENT_LOG_FILE_NAME			"event_log"
#define WDC_DE_DESTN_SPI				1
#define WDC_DE_DUMPTRACE_DESTINATION			6

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

typedef struct tarfile_metadata {
	char fileName[MAX_PATH_LEN];
	int8_t bufferFolderPath[MAX_PATH_LEN];
	char bufferFolderName[MAX_PATH_LEN];
	char tarFileName[MAX_PATH_LEN];
	char tarFiles[MAX_PATH_LEN];
	char tarCmd[MAX_PATH_LEN+MAX_PATH_LEN];
	char currDir[MAX_PATH_LEN];
	UtilsTimeInfo timeInfo;
	uint8_t* timeString[MAX_PATH_LEN];
} tarfile_metadata;

static WDC_DE_CSA_FEATURE_ID_LIST deFeatureIdList[] =
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
	__u32	logPageId;
	__u32	logPageLen;
	char	logPageIdStr[5];
} NVME_VU_DE_LOGPAGE_LIST, *PNVME_VU_DE_LOGPAGE_LIST;

typedef struct _WDC_NVME_DE_VU_LOGPAGES
{
    NVME_VU_DE_LOGPAGE_NAMES vuLogPageReqd;
    __u32 numOfVULogPages;
} WDC_NVME_DE_VU_LOGPAGES, *PWDC_NVME_DE_VU_LOGPAGES;

static NVME_VU_DE_LOGPAGE_LIST deVULogPagesList[] =
{
    { NVME_DE_LOGPAGE_E3, 0xE3, 1072, "0xe3"},
    { NVME_DE_LOGPAGE_C0, 0xC0, 512, "0xc0"}
};

static int wdc_get_serial_name(int fd, char *file, size_t len, const char *suffix);
static int wdc_create_log_file(char *file, __u8 *drive_log_data,
		__u32 drive_log_length);
static int wdc_do_clear_dump(int fd, __u8 opcode, __u32 cdw12);
static int wdc_do_dump(int fd, __u32 opcode,__u32 data_len,
		__u32 cdw12, char *file, __u32 xfer_size);
static int wdc_do_crash_dump(int fd, char *file, int type);
static int wdc_crash_dump(int fd, char *file, int type);
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
static bool wdc_nvme_check_supported_log_page(int fd, __u8 log_id);
static int wdc_clear_pcie_correctable_errors(int argc, char **argv, struct command *command,
		struct plugin *plugin);
static int wdc_do_drive_essentials(int fd, char *dir, char *key);
static int wdc_drive_essentials(int argc, char **argv, struct command *command,
		struct plugin *plugin);
static int wdc_drive_status(int argc, char **argv, struct command *command,
		struct plugin *plugin);
static int wdc_clear_assert_dump(int argc, char **argv, struct command *command,
		struct plugin *plugin);
static int wdc_drive_resize(int argc, char **argv,
		struct command *command, struct plugin *plugin);
static int wdc_do_drive_resize(int fd, uint64_t new_size);

/* Drive log data size */
struct wdc_log_size {
	__le32	log_size;
};

/* E6 log header */
struct wdc_e6_log_hdr {
	__le32  eye_catcher;
	__u8	log_size[4];
};

/* DUI log header */
struct wdc_dui_log_section {
	__le16	section_type;
	__le16	data_area_id;
	__le32	section_size;
};

/* DUI log header V2 */
struct __attribute__((__packed__)) wdc_dui_log_section_v2 {
	__le16	section_type;
	__le16	data_area_id;
	__le64	section_size;
};

struct wdc_dui_log_hdr {
	__u8    telemetry_hdr[512];
	__le16	hdr_version;
	__le16	section_count;
	__le32	log_size;
	struct	wdc_dui_log_section log_section[WDC_NVME_DUI_MAX_SECTION];
	__u8    log_data[40];
};

struct __attribute__((__packed__)) wdc_dui_log_hdr_v2 {
	__u8    telemetry_hdr[512];
	__le16	hdr_version;
	__le16	section_count;
	__le64	log_size;
	struct	wdc_dui_log_section_v2 log_section[WDC_NVME_DUI_MAX_SECTION_V2];
	__u8    log_data[40];
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
	__le64  nand_bytes_wr_lo;                       /* 0x00 - NAND Bytes Written lo             */
	__le64  nand_bytes_wr_hi;                       /* 0x08 - NAND Bytes Written hi             */
	__le64  nand_bytes_rd_lo;                       /* 0x10 - NAND Bytes Read lo                */
	__le64  nand_bytes_rd_hi;                       /* 0x18 - NAND Bytes Read hi                */
	__le64  nand_bad_block;                         /* 0x20 - NAND Bad Block Count              */
	__le64  uncorr_read_count;                      /* 0x28 - Uncorrectable Read Count          */
	__le64  ecc_error_count;                        /* 0x30 - Soft ECC Error Count              */
	__le32  ssd_detect_count;                       /* 0x38 - SSD End to End Detection Count    */
	__le32  ssd_correct_count;                      /* 0x3C - SSD End to End Correction Count   */
	__u8    data_percent_used;                      /* 0x40 - System Data Percent Used          */
	__le32  data_erase_max;                         /* 0x41 - User Data Erase Counts            */
	__le32  data_erase_min;                         /* 0x45 - User Data Erase Counts            */
	__le64  refresh_count;                          /* 0x49 - Refresh Count                     */
	__le64  program_fail;                           /* 0x51 - Program Fail Count                */
	__le64  user_erase_fail;                        /* 0x59 - User Data Erase Fail Count        */
	__le64  system_erase_fail;                      /* 0x61 - System Area Erase Fail Count      */
	__u8    thermal_throttle_status;                /* 0x69 - Thermal Throttling Status         */
	__u8    thermal_throttle_count;                 /* 0x6A - Thermal Throttling Count          */
	__le64  pcie_corr_error;                        /* 0x6B - pcie Correctable Error Count      */
	__le32  incomplete_shutdown_count;              /* 0x73 - Incomplete Shutdown Count         */
	__u8    percent_free_blocks;                    /* 0x77 - Percent Free Blocks               */
	__u8    rsvd[392];                              /* 0x78 - Reserved bytes 120-511            */
};

struct __attribute__((__packed__)) wdc_ssd_d0_smart_log {
    __le32  smart_log_page_header;                 /* 0x00 - Smart Log Page Header                       */
    __le32  lifetime_realloc_erase_block_count;    /* 0x04 - Lifetime reallocated erase block count      */
    __le32  lifetime_power_on_hours;               /* 0x08 - Lifetime power on hours                     */
    __le32  lifetime_uecc_count;                   /* 0x0C - Lifetime UECC count                         */
    __le32  lifetime_wrt_amp_factor;               /* 0x10 - Lifetime write amplification factor         */
    __le32  trailing_hr_wrt_amp_factor;            /* 0x14 - Trailing hour write amplification factor    */
    __le32  reserve_erase_block_count;             /* 0x18 - Reserve erase block count                   */
    __le32  lifetime_program_fail_count;           /* 0x1C - Lifetime program fail count                 */
    __le32  lifetime_block_erase_fail_count;       /* 0x20 - Lifetime block erase fail count             */
    __le32  lifetime_die_failure_count;            /* 0x24 - Lifetime die failure count                  */
    __le32  lifetime_link_rate_downgrade_count;    /* 0x28 - Lifetime link rate downgrade count          */
    __le32  lifetime_clean_shutdown_count;         /* 0x2C - Lifetime clean shutdown count on power loss */
    __le32  lifetime_unclean_shutdown_count;       /* 0x30 - Lifetime unclean shutdowns on power loss    */
    __le32  current_temp;                          /* 0x34 - Current temperature                         */
    __le32  max_recorded_temp;                     /* 0x38 - Max recorded temperature                    */
    __le32  lifetime_retired_block_count;          /* 0x3C - Lifetime retired block count                */
    __le32  lifetime_read_disturb_realloc_events;  /* 0x40 - Lifetime read disturb reallocation events   */
    __le64  lifetime_nand_writes;                  /* 0x44 - Lifetime NAND write Lpages                  */
    __le32  capacitor_health;                      /* 0x4C - Capacitor health                            */
    __le64  lifetime_user_writes;                  /* 0x50 - Lifetime user writes                        */
    __le64  lifetime_user_reads;                   /* 0x58 - Lifetime user reads                         */
    __le32  lifetime_thermal_throttle_act;         /* 0x60 - Lifetime thermal throttle activations       */
    __le32  percentage_pe_cycles_remaining;        /* 0x64 - Percentage of P/E cycles remaining          */
    __u8    rsvd[408];                             /* 0x68 - 408 Reserved bytes                          */
};

/* NAND Stats */
struct __attribute__((__packed__)) wdc_nand_stats {
	__u8		nand_write_tlc[16];
	__u8		nand_write_slc[16];
	__le32		nand_prog_failure;
	__le32		nand_erase_failure;
	__le32		bad_block_count;
	__le64		nand_rec_trigger_event;
	__u8		rsvd[460];
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

static long double int128_to_double(__u8 *data)
{
	int i;
	long double result = 0;

	for (i = 0; i < 16; i++) {
		result *= 256;
		result += data[15 - i];
	}
	return result;
}

static int wdc_get_pci_ids(uint32_t *device_id, uint32_t *vendor_id)
{
	int fd, ret = -1;
	char *block, path[512], *id;

	id = calloc(1, 32);
	if (!id) {
		fprintf(stderr, "ERROR : WDC : %s : calloc failed\n", __func__);
		return -1;
	}

	block = nvme_char_from_block((char *)devicename);

	/* read the vendor ID from sys fs  */
	sprintf(path, "/sys/class/nvme/%s/device/vendor", block);

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		sprintf(path, "/sys/class/misc/%s/device/vendor", block);
		fd = open(path, O_RDONLY);
	}
	if (fd < 0) {
		fprintf(stderr, "ERROR : WDC : %s : Open vendor file failed\n", __func__);
		ret = -1;
		goto free_id;
	}

	ret = read(fd, id, 32);
	if (ret < 0) {
		fprintf(stderr, "%s: Read of pci vendor id failed\n", __func__);
		ret = -1;
		goto close_fd;
	} else {
		if (id[strlen(id) - 1] == '\n')
			id[strlen(id) - 1] = '\0';

		/* convert the device id string to an int  */
		*vendor_id = (int)strtol(&id[2], NULL, 16);
		ret = 0;
	}

	/* read the device ID from sys fs */
	sprintf(path, "/sys/class/nvme/%s/device/device", block);

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		sprintf(path, "/sys/class/misc/%s/device/device", block);
		fd = open(path, O_RDONLY);
	}
	if (fd < 0) {
		fprintf(stderr, "ERROR : WDC : %s : Open device file failed\n", __func__);
		ret = -1;
		goto close_fd;
	}

	ret = read(fd, id, 32);
	if (ret < 0) {
		fprintf(stderr, "%s: Read of pci device id failed\n", __func__);
		ret = -1;
	} else {
		if (id[strlen(id) - 1] == '\n')
			id[strlen(id) - 1] = '\0';

		/* convert the device id string to an int  */
		*device_id = strtol(&id[2], NULL, 16);
		ret = 0;
	}

close_fd:
	close(fd);
free_id:
	free(id);
	return ret;
}

static bool wdc_check_device(int fd)
{
	int ret;
	bool supported;
	uint32_t read_device_id, read_vendor_id;

	ret = wdc_get_pci_ids(&read_device_id, &read_vendor_id);
	if (ret < 0)
		return false;

	supported = false;

	if (read_vendor_id == WDC_NVME_VID ||
	    read_vendor_id == WDC_NVME_VID_2 ||
	    read_vendor_id == WDC_NVME_SNDK_VID)
		supported = true;
	else
		fprintf(stderr, "ERROR : WDC: unsupported WDC device, Vendor ID = 0x%x, Device ID = 0x%x\n",
				read_vendor_id, read_device_id);

	return supported;
}

static __u64 wdc_get_drive_capabilities(int fd) {
	int ret;
	uint32_t read_device_id, read_vendor_id;
	__u64 capabilities = 0;

	ret = wdc_get_pci_ids(&read_device_id, &read_vendor_id);
	if (ret < 0)
		return capabilities;

	switch (read_vendor_id) {
	case WDC_NVME_VID:
		switch (read_device_id) {
		case WDC_NVME_SN100_DEV_ID:
			capabilities = (WDC_DRIVE_CAP_CAP_DIAG | WDC_DRIVE_CAP_INTERNAL_LOG | WDC_DRIVE_CAP_C1_LOG_PAGE |
					WDC_DRIVE_CAP_DRIVE_LOG | WDC_DRIVE_CAP_CRASH_DUMP | WDC_DRIVE_CAP_PFAIL_DUMP);
			break;
		case WDC_NVME_SN200_DEV_ID:
			capabilities = (WDC_DRIVE_CAP_CAP_DIAG | WDC_DRIVE_CAP_INTERNAL_LOG | WDC_DRIVE_CAP_CLEAR_PCIE |
					WDC_DRIVE_CAP_DRIVE_LOG | WDC_DRIVE_CAP_CRASH_DUMP | WDC_DRIVE_CAP_PFAIL_DUMP);

			/* verify the 0xCA log page is supported */
			if (wdc_nvme_check_supported_log_page(fd, WDC_NVME_GET_DEVICE_INFO_LOG_OPCODE) == true)
				capabilities |= WDC_DRIVE_CAP_CA_LOG_PAGE;

			/* verify the 0xC1 log page is supported */
			if (wdc_nvme_check_supported_log_page(fd, WDC_NVME_ADD_LOG_OPCODE) == true)
				capabilities |= WDC_DRIVE_CAP_C1_LOG_PAGE;
			break;
		default:
			capabilities = 0;
		}
		break;
	case WDC_NVME_VID_2:
		switch (read_device_id) {
		case WDC_NVME_SN630_DEV_ID:
		/* FALLTHRU */
		case WDC_NVME_SN630_DEV_ID_1:
		/* FALLTHRU */
		case WDC_NVME_SN640_DEV_ID:
		/* FALLTHRU */
		case WDC_NVME_SN640_DEV_ID_1:
		/* FALLTHRU */
		case WDC_NVME_SN640_DEV_ID_2:
		/* FALLTHRU */
		case WDC_NVME_SN840_DEV_ID:
		/* FALLTHRU */
		case WDC_NVME_SN840_DEV_ID_1:
			capabilities = (WDC_DRIVE_CAP_CAP_DIAG | WDC_DRIVE_CAP_INTERNAL_LOG |
					WDC_DRIVE_CAP_DRIVE_STATUS | WDC_DRIVE_CAP_CLEAR_ASSERT |
					WDC_DRIVE_CAP_RESIZE | WDC_DRIVE_CAP_CLEAR_PCIE);

			/* verify the 0xCA log page is supported */
			if (wdc_nvme_check_supported_log_page(fd, WDC_NVME_GET_DEVICE_INFO_LOG_OPCODE) == true)
				capabilities |= WDC_DRIVE_CAP_CA_LOG_PAGE;

			/* verify the 0xD0 log page is supported */
			if (wdc_nvme_check_supported_log_page(fd, WDC_NVME_GET_VU_SMART_LOG_OPCODE) == true)
				capabilities |= WDC_DRIVE_CAP_D0_LOG_PAGE;
			break;
		case WDC_NVME_SN730B_DEV_ID:
		/* FALLTHRU */
		case WDC_NVME_SN730B_DEV_ID_1:
			capabilities = WDC_SN730B_CAP_VUC_LOG;
			break;
		default:
			capabilities = 0;
		}
		break;
	case WDC_NVME_SNDK_VID:
		switch (read_device_id) {
		case WDC_NVME_SXSLCL_DEV_ID:
			capabilities = WDC_DRIVE_CAP_DRIVE_ESSENTIALS;
			break;
		case WDC_NVME_SN520_DEV_ID:
		/* FALLTHRU */
		case WDC_NVME_SN520_DEV_ID_1:
		/* FALLTHRU */
		case WDC_NVME_SN520_DEV_ID_2:
			capabilities = WDC_DRIVE_CAP_DUI_DATA;
		case WDC_NVME_SN720_DEV_ID:
		/* FALLTHRU */
		case WDC_NVME_SN730A_DEV_ID:
			capabilities = WDC_DRIVE_CAP_DUI_DATA | WDC_DRIVE_CAP_NAND_STATS;
			break;
		case WDC_NVME_SN340_DEV_ID:
			capabilities = WDC_DRIVE_CAP_SN340_DUI;
			break;
		default:
			capabilities = 0;
		}
		break;
	default:
		capabilities = 0;
	}

	return capabilities;
}

static int wdc_get_serial_name(int fd, char *file, size_t len, const char *suffix)
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

	res_len = snprintf(file, len, "%s%.*s%s", orig, ctrl_sn_len, ctrl.sn, suffix);
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

static bool get_dev_mgment_cbs_data(int fd, __u8 log_id, void **cbs_data)
{
	int ret = -1;
	__u8* data;
	struct wdc_c2_log_page_header *hdr_ptr;
	struct wdc_c2_log_subpage_header *sph;
	__u32 length = 0;
	bool found = false;

	*cbs_data = NULL;

	if ((data = (__u8*) malloc(sizeof (__u8) * WDC_C2_LOG_BUF_LEN)) == NULL) {
		fprintf(stderr, "ERROR : WDC : malloc : %s\n", strerror(errno));
		return false;
	}
	memset(data, 0, sizeof (__u8) * WDC_C2_LOG_BUF_LEN);

	/* get the log page length */
	ret = nvme_get_log(fd, 0xFFFFFFFF, WDC_NVME_GET_DEV_MGMNT_LOG_PAGE_OPCODE,
			   false, WDC_C2_LOG_BUF_LEN, data);
	if (ret) {
		fprintf(stderr, "ERROR : WDC : Unable to get C2 Log Page length, ret = 0x%x\n", ret);
		goto end;
	}

	hdr_ptr = (struct wdc_c2_log_page_header *)data;

	if (le32_to_cpu(hdr_ptr->length) > WDC_C2_LOG_BUF_LEN) {
		/* Log Page buffer too small, free and reallocate the necessary size */
		free(data);
		data = calloc(le32_to_cpu(hdr_ptr->length), sizeof(__u8));
		if (data == NULL) {
			fprintf(stderr, "ERROR : WDC : malloc : %s\n", strerror(errno));
			return false;
		}
	}

	ret = nvme_get_log(fd, 0xFFFFFFFF, WDC_NVME_GET_DEV_MGMNT_LOG_PAGE_OPCODE,
			   false, le32_to_cpu(hdr_ptr->length), data);
	/* parse the data until the List of log page ID's is found */
	if (ret) {
		fprintf(stderr, "ERROR : WDC : Unable to read C2 Log Page data, ret = 0x%x\n", ret);
		goto end;
	}

	length = sizeof(struct wdc_c2_log_page_header);
	hdr_ptr = (struct wdc_c2_log_page_header *)data;

	while (length < le32_to_cpu(hdr_ptr->length)) {
		sph = (struct wdc_c2_log_subpage_header *)(data + length);

		if (le32_to_cpu(sph->entry_id) == log_id) {
			*cbs_data = (void *)&sph->data;
			found = true;
			break;
		}
		length += le32_to_cpu(sph->length);
	}

end:
	free(data);
	return found;
}

static bool wdc_nvme_check_supported_log_page(int fd, __u8 log_id)
{
	int i;
	bool found = false;
	struct wdc_c2_cbs_data *cbs_data = NULL;

	if (get_dev_mgment_cbs_data(fd, WDC_C2_LOG_PAGES_SUPPORTED_ID, (void *)&cbs_data)) {
		if (cbs_data != NULL) {
			for (i = 0; i < le32_to_cpu(cbs_data->length); i++) {
				if (log_id == cbs_data->data[i]) {
					found = true;
					break;
				}
			}

#ifdef WDC_NVME_CLI_DEBUG
			if (!found) {
				fprintf(stderr, "ERROR : WDC : Log Page 0x%x not supported\n", log_id);
				fprintf(stderr, "WDC : Supported Log Pages:\n");
				/* print the supported pages */
				d((__u8 *)cbs_data->data, le32_to_cpu(cbs_data->length), 16, 1);
			}
#endif
		} else
			fprintf(stderr, "ERROR : WDC : cbs_data ptr = NULL\n");
	} else
		fprintf(stderr, "ERROR : WDC : 0xC2 Log Page entry ID 0x%x not found\n", WDC_C2_LOG_PAGES_SUPPORTED_ID);

	return found;
}

static bool wdc_nvme_get_dev_status_log_data(int fd, __le32 *ret_data,
		__u8 log_id)
{
	__u32 *cbs_data = NULL;
	bool found = false;

	if (get_dev_mgment_cbs_data(fd, log_id, (void *)&cbs_data)) {
		if (cbs_data != NULL) {
			memcpy((void *)ret_data, (void *)cbs_data, 4);
			found = true;
		}
	}
	return found;
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

static __u32 wdc_dump_length_e6(int fd, __u32 opcode, __u32 cdw10, __u32 cdw12, struct wdc_e6_log_hdr *dump_hdr)
{
	int ret;
	struct nvme_admin_cmd admin_cmd;

	memset(&admin_cmd, 0, sizeof (struct nvme_admin_cmd));
	admin_cmd.opcode = opcode;
	admin_cmd.addr = (__u64)(uintptr_t)dump_hdr;
	admin_cmd.data_len = WDC_NVME_LOG_SIZE_HDR_LEN;
	admin_cmd.cdw10 = cdw10;
	admin_cmd.cdw12 = cdw12;

	ret = nvme_submit_passthru(fd, NVME_IOCTL_ADMIN_CMD, &admin_cmd);
	if (ret != 0) {
		fprintf(stderr, "ERROR : WDC : reading dump length failed\n");
		fprintf(stderr, "NVMe Status:%s(%x)\n", nvme_status_to_string(ret), ret);
	}

	return ret;
}

static __u32 wdc_dump_dui_data(int fd, __u32 dataLen, __u32 offset, __u8 *dump_data, bool last_xfer)
{
	int ret;
	struct nvme_admin_cmd admin_cmd;

	memset(&admin_cmd, 0, sizeof (struct nvme_admin_cmd));
	admin_cmd.opcode = WDC_NVME_CAP_DUI_OPCODE;
	admin_cmd.nsid = 0xFFFFFFFF;
	admin_cmd.addr = (__u64)(uintptr_t)dump_data;
	admin_cmd.data_len = dataLen;
	admin_cmd.cdw10 = ((dataLen >> 2) - 1);
	admin_cmd.cdw12 = offset;
	if (last_xfer)
		admin_cmd.cdw14 = 0;
	else
		admin_cmd.cdw14 = WDC_NVME_CAP_DUI_DISABLE_IO;


	ret = nvme_submit_passthru(fd, NVME_IOCTL_ADMIN_CMD, &admin_cmd);
	if (ret != 0) {
		fprintf(stderr, "ERROR : WDC : reading DUI data failed\n");
		fprintf(stderr, "NVMe Status:%s(%x)\n", nvme_status_to_string(ret), ret);
	}

	return ret;
}

static __u32 wdc_dump_dui_data_v2(int fd, __u32 dataLen, __u64 offset, __u8 *dump_data, bool last_xfer)
{
	int ret;
	struct nvme_admin_cmd admin_cmd;

	memset(&admin_cmd, 0, sizeof (struct nvme_admin_cmd));
	admin_cmd.opcode = WDC_NVME_CAP_DUI_OPCODE;
	admin_cmd.nsid = 0xFFFFFFFF;
	admin_cmd.addr = (__u64)(uintptr_t)dump_data;
	admin_cmd.data_len = dataLen;
	admin_cmd.cdw10 = ((dataLen >> 2) - 1);
	admin_cmd.cdw12 = (__u32)(offset & 0x00000000FFFFFFFF);
	admin_cmd.cdw13 = (__u32)(offset >> 32);
	if (last_xfer)
		admin_cmd.cdw14 = 0;
	else
		admin_cmd.cdw14 = WDC_NVME_CAP_DUI_DISABLE_IO;

	ret = nvme_submit_passthru(fd, NVME_IOCTL_ADMIN_CMD, &admin_cmd);
	if (ret != 0) {
		fprintf(stderr, "ERROR : WDC : reading DUI data V2 failed\n");
		fprintf(stderr, "NVMe Status:%s(%x)\n", nvme_status_to_string(ret), ret);
	}

	return ret;
}

static int wdc_do_dump(int fd, __u32 opcode,__u32 data_len,
		__u32 cdw12, char *file, __u32 xfer_size)
{
	int ret = 0;
	__u8 *dump_data;
	__u32 curr_data_offset, curr_data_len;
	int i;
	struct nvme_admin_cmd admin_cmd;
	__u32 dump_length = data_len;

	dump_data = (__u8 *) malloc(sizeof (__u8) * dump_length);
	if (dump_data == NULL) {
		fprintf(stderr, "%s: ERROR : malloc : %s\n", __func__, strerror(errno));
		return -1;
	}
	memset(dump_data, 0, sizeof (__u8) * dump_length);
	memset(&admin_cmd, 0, sizeof (struct nvme_admin_cmd));
	curr_data_offset = 0;
	curr_data_len = xfer_size;
	i = 0;

	admin_cmd.opcode = opcode;
	admin_cmd.addr = (__u64)(uintptr_t)dump_data;
	admin_cmd.data_len = curr_data_len;
	admin_cmd.cdw10 = curr_data_len >> 2;
	admin_cmd.cdw12 = cdw12;
	admin_cmd.cdw13 = curr_data_offset;

	while (curr_data_offset < data_len) {
		ret = nvme_submit_passthru(fd, NVME_IOCTL_ADMIN_CMD, &admin_cmd);
		if (ret != 0) {
			fprintf(stderr, "%s: ERROR : WDC : NVMe Status:%s(%x)\n",
				__func__, nvme_status_to_string(ret), ret);
			fprintf(stderr, "%s: ERROR : WDC : Get chunk %d, size = 0x%x, offset = 0x%x, addr = 0x%lx\n",
				__func__, i, admin_cmd.data_len, curr_data_offset, (long unsigned int)admin_cmd.addr);
			break;
		}

		if ((curr_data_offset + xfer_size) <= data_len)
			curr_data_len = xfer_size;
		else
			curr_data_len = data_len - curr_data_offset;   // last transfer

		curr_data_offset += curr_data_len;
		admin_cmd.addr = (__u64)(uintptr_t)dump_data + (__u64)curr_data_offset;
		admin_cmd.data_len = curr_data_len;
		admin_cmd.cdw10 = curr_data_len >> 2;
		admin_cmd.cdw13 = curr_data_offset >> 2;
		i++;
	}

	if (ret == 0) {
		fprintf(stderr, "%s:  NVMe Status:%s(%x)\n", __func__, nvme_status_to_string(ret), ret);
		ret = wdc_create_log_file(file, dump_data, dump_length);
	}
	free(dump_data);
	return ret;
}

static int wdc_do_dump_e6(int fd, __u32 opcode,__u32 data_len,
		__u32 cdw12, char *file, __u32 xfer_size, __u8 *log_hdr)
{
	int ret = 0;
	__u8 *dump_data;
	__u32 curr_data_offset, log_size;
	int i;
	struct nvme_admin_cmd admin_cmd;

	dump_data = (__u8 *) malloc(sizeof (__u8) * data_len);

	if (dump_data == NULL) {
		fprintf(stderr, "%s: ERROR : malloc : %s\n", __func__, strerror(errno));
		return -1;
	}
	memset(dump_data, 0, sizeof (__u8) * data_len);
	memset(&admin_cmd, 0, sizeof (struct nvme_admin_cmd));
	curr_data_offset = WDC_NVME_LOG_SIZE_HDR_LEN;
	i = 0;

	/* copy the 8 byte header into the dump_data buffer */
	memcpy(dump_data, log_hdr, WDC_NVME_LOG_SIZE_HDR_LEN);

	admin_cmd.opcode = opcode;
	admin_cmd.cdw12 = cdw12;

	log_size = data_len;
	while (log_size > 0) {
		xfer_size = min(xfer_size, log_size);

		admin_cmd.addr = (__u64)(uintptr_t)dump_data + (__u64)curr_data_offset;
		admin_cmd.data_len = xfer_size;
		admin_cmd.cdw10 = xfer_size >> 2;
		admin_cmd.cdw13 = curr_data_offset >> 2;

		ret = nvme_submit_passthru(fd, NVME_IOCTL_ADMIN_CMD, &admin_cmd);
		if (ret != 0) {
			fprintf(stderr, "%s: ERROR : WDC : NVMe Status:%s(%x)\n", __func__, nvme_status_to_string(ret), ret);
			fprintf(stderr, "%s: ERROR : WDC : Get chunk %d, size = 0x%x, offset = 0x%x, addr = 0x%lx\n",
					__func__, i, admin_cmd.data_len, curr_data_offset, (long unsigned int)admin_cmd.addr);
			break;
		}

		log_size         -= xfer_size;
		curr_data_offset += xfer_size;
		i++;
	}

	if (ret == 0) {
		fprintf(stderr, "%s:  NVMe Status:%s(%x)\n", __func__, nvme_status_to_string(ret), ret);
	} else {
		fprintf(stderr, "%s:  FAILURE: NVMe Status:%s(%x)\n", __func__, nvme_status_to_string(ret), ret);
		fprintf(stderr, "%s:  Partial data may have been captured\n", __func__);
		snprintf(file + strlen(file), PATH_MAX, "%s", "-PARTIAL");
	}

	ret = wdc_create_log_file(file, dump_data, data_len);

	free(dump_data);
	return ret;
}

static int wdc_do_cap_diag(int fd, char *file, __u32 xfer_size)
{
	int ret;
	__u32 e6_log_hdr_size = WDC_NVME_CAP_DIAG_HEADER_TOC_SIZE;
	struct wdc_e6_log_hdr *log_hdr;
	__u32 cap_diag_length;

	log_hdr = (struct wdc_e6_log_hdr *) malloc(e6_log_hdr_size);
	if (log_hdr == NULL) {
		fprintf(stderr, "%s: ERROR : malloc : %s\n", __func__, strerror(errno));
		ret = -1;
		goto out;
	}
	memset(log_hdr, 0, e6_log_hdr_size);

	ret = wdc_dump_length_e6(fd, WDC_NVME_CAP_DIAG_OPCODE,
						WDC_NVME_CAP_DIAG_HEADER_TOC_SIZE>>2,
						0x00,
						log_hdr);
	if (ret == -1) {
		ret = -1;
		goto out;
	}

	cap_diag_length = (log_hdr->log_size[0] << 24 | log_hdr->log_size[1] << 16 |
			log_hdr->log_size[2] << 8 | log_hdr->log_size[3]);

	if (cap_diag_length == 0) {
		fprintf(stderr, "INFO : WDC : Capture Diagnostics log is empty\n");
	} else {
		ret = wdc_do_dump_e6(fd, WDC_NVME_CAP_DIAG_OPCODE, cap_diag_length,
						(WDC_NVME_CAP_DIAG_SUBCMD << WDC_NVME_SUBCMD_SHIFT) | WDC_NVME_CAP_DIAG_CMD,
						file, xfer_size, (__u8 *)log_hdr);

		fprintf(stderr, "INFO : WDC : Capture Diagnostics log, length = 0x%x\n", cap_diag_length);
	}

out:
	free(log_hdr);
	return ret;
}

static int wdc_do_cap_dui(int fd, char *file, __u32 xfer_size, int data_area, int verbose)
{
	int ret = 0;
	__u32 dui_log_hdr_size = WDC_NVME_CAP_DUI_HEADER_SIZE;
	struct wdc_dui_log_hdr *log_hdr;
	struct wdc_dui_log_hdr_v2 *log_hdr_v2;
	__u32 cap_dui_length;
	__u64 cap_dui_length_v2;
	__u8 *dump_data = NULL;
	__u64 buffer_addr;
	__s64 total_size = 0;
	int i;
	bool last_xfer = false;
	int err = 0, output = 0;

	log_hdr = (struct wdc_dui_log_hdr *) malloc(dui_log_hdr_size);
	if (log_hdr == NULL) {
		fprintf(stderr, "%s: ERROR : log header malloc failed : status %s, size 0x%x\n",
				__func__, strerror(errno), dui_log_hdr_size);
		return -1;
	}
	memset(log_hdr, 0, dui_log_hdr_size);

	/* get the dui telemetry and log headers  */
	ret = wdc_dump_dui_data(fd, WDC_NVME_CAP_DUI_HEADER_SIZE, 0x00,	(__u8 *)log_hdr, last_xfer);
	if (ret != 0) {
		fprintf(stderr, "%s: ERROR : WDC : Get DUI headers failed\n", __func__);
		fprintf(stderr, "%s: ERROR : WDC : NVMe Status:%s(%x)\n", __func__, nvme_status_to_string(ret), ret);
		goto out;
	}

	/* Check the Log Header version  */
	if (log_hdr->hdr_version == 2) {								/* Process Version 2 of the header */
		__s64 log_size = 0;
		__u64 curr_data_offset = 0;
		__u64 xfer_size_long = (__u64)xfer_size;

		log_hdr_v2 = (struct wdc_dui_log_hdr_v2 *)log_hdr;

		cap_dui_length_v2 = le64_to_cpu(log_hdr_v2->log_size);

		if (verbose)
			fprintf(stderr, "INFO : WDC : Capture V2 Device Unit Info log, data area = %d\n", data_area);

		if (cap_dui_length_v2 == 0) {
			fprintf(stderr, "INFO : WDC : Capture V2 Device Unit Info log is empty\n");
		} else {
			/* parse log header for all sections up to specified data area inclusively */
			if (data_area != WDC_NVME_DUI_MAX_DATA_AREA) {
				for(int i = 0; i < WDC_NVME_DUI_MAX_SECTION_V2; i++) {
					if (log_hdr_v2->log_section[i].data_area_id <= data_area &&
							log_hdr_v2->log_section[i].data_area_id != 0) {
						log_size += log_hdr_v2->log_section[i].section_size;
						if (verbose)
							fprintf(stderr, "%s: Data area ID %d : section size 0x%x, total size = 0x%lx\n",
								__func__, log_hdr_v2->log_section[i].data_area_id, (unsigned int)log_hdr_v2->log_section[i].section_size, (long unsigned int)log_size);
					}
					else {
						if (verbose)
							fprintf(stderr, "%s: break, total size = 0x%lx\n", 	__func__, (long unsigned int)log_size);
						break;
					}
				}
			} else
				log_size = cap_dui_length_v2;

			total_size = log_size;

			dump_data = (__u8 *) malloc(sizeof (__u8) * xfer_size_long);
			if (dump_data == NULL) {
				fprintf(stderr, "%s: ERROR : dump data V2 malloc failed : status %s, size = 0x%lx\n",
						__func__, strerror(errno), (long unsigned int)xfer_size_long);
				ret = -1;
				goto out;
			}
			memset(dump_data, 0, sizeof (__u8) * xfer_size_long);

			output = open(file, O_WRONLY | O_CREAT | O_TRUNC, 0666);
			if (output < 0) {
				fprintf(stderr, "%s: Failed to open output file %s: %s!\n",
						__func__, file, strerror(errno));
				ret = output;
				goto out;
			}

			/* write the telemetry and log headers into the dump_file */
			err = write(output, (void *)log_hdr, WDC_NVME_CAP_DUI_HEADER_SIZE);
			if (err != WDC_NVME_CAP_DUI_HEADER_SIZE) {
				fprintf(stderr, "%s:  Failed to flush header data to file!\n", __func__);
				goto free_mem;
			}

			log_size -= WDC_NVME_CAP_DUI_HEADER_SIZE;
			curr_data_offset = WDC_NVME_CAP_DUI_HEADER_SIZE;
			i = 0;
			buffer_addr = (__u64)(uintptr_t)dump_data;

			for(; log_size > 0; log_size -= xfer_size_long) {
				xfer_size_long = min(xfer_size_long, log_size);

				if (log_size <= xfer_size_long)
					last_xfer = true;

				ret = wdc_dump_dui_data_v2(fd, (__u32)xfer_size_long, curr_data_offset, (__u8 *)buffer_addr, last_xfer);
				if (ret != 0) {
					fprintf(stderr, "%s: ERROR : WDC : Get chunk %d, size = 0x%lx, offset = 0x%lx, addr = 0x%lx\n",
							__func__, i, (long unsigned int)total_size, (long unsigned int)curr_data_offset, (long unsigned int)buffer_addr);
					fprintf(stderr, "%s: ERROR : WDC : NVMe Status:%s(%x)\n", __func__, nvme_status_to_string(ret), ret);
					break;
				}

				/* write the dump data into the file */
				err = write(output, (void *)buffer_addr, xfer_size_long);
				if (err != xfer_size_long) {
					fprintf(stderr, "%s: ERROR : WDC : Failed to flush DUI data to file! chunk %d, err = 0x%x, xfer_size = 0x%lx\n",
							__func__, i, err, (long unsigned int)xfer_size_long);
					goto free_mem;
				}

				curr_data_offset += xfer_size_long;
				i++;
			}
		}
	} else	{
		__s32 log_size = 0;
		__u32 curr_data_offset = 0;

		cap_dui_length = le32_to_cpu(log_hdr->log_size);

		if (verbose)
			fprintf(stderr, "INFO : WDC : Capture V1 Device Unit Info log, data area = %d\n", data_area);

		if (cap_dui_length == 0) {
			fprintf(stderr, "INFO : WDC : Capture V1 Device Unit Info log is empty\n");
		} else {
			/* parse log header for all sections up to specified data area inclusively */
			if (data_area != WDC_NVME_DUI_MAX_DATA_AREA) {
				for(int i = 0; i < WDC_NVME_DUI_MAX_SECTION; i++) {
					if (log_hdr->log_section[i].data_area_id <= data_area &&
							log_hdr->log_section[i].data_area_id != 0) {
						log_size += log_hdr->log_section[i].section_size;
						if (verbose)
							fprintf(stderr, "%s: Data area ID %d : section size 0x%x, total size = 0x%x\n",
								__func__, log_hdr->log_section[i].data_area_id, (unsigned int)log_hdr->log_section[i].section_size, (unsigned int)log_size);

					}
					else {
						if (verbose)
							fprintf(stderr, "%s: break, total size = 0x%x\n", 	__func__, (unsigned int)log_size);
						break;
					}
				}
			} else
				log_size = cap_dui_length;

			total_size = log_size;

			dump_data = (__u8 *) malloc(sizeof (__u8) * xfer_size);
			if (dump_data == NULL) {
				fprintf(stderr, "%s: ERROR : dump data V1 malloc failed : status %s, size = 0x%x\n",
						__func__, strerror(errno), (unsigned int)xfer_size);
				ret = -1;
				goto out;
			}
			memset(dump_data, 0, sizeof (__u8) * xfer_size);

			output = open(file, O_WRONLY | O_CREAT | O_TRUNC, 0666);
			if (output < 0) {
				fprintf(stderr, "%s: Failed to open output file %s: %s!\n",
						__func__, file, strerror(errno));
				ret = output;
				goto out;
			}

			/* write the telemetry and log headers into the dump_file */
			err = write(output, (void *)log_hdr, WDC_NVME_CAP_DUI_HEADER_SIZE);
			if (err != WDC_NVME_CAP_DUI_HEADER_SIZE) {
				fprintf(stderr, "%s:  Failed to flush header data to file!\n", __func__);
				goto free_mem;
			}

			log_size -= WDC_NVME_CAP_DUI_HEADER_SIZE;
			curr_data_offset = WDC_NVME_CAP_DUI_HEADER_SIZE;
			i = 0;
			buffer_addr = (__u64)(uintptr_t)dump_data;

			for(; log_size > 0; log_size -= xfer_size) {
				xfer_size = min(xfer_size, log_size);

				if (log_size <= xfer_size)
					last_xfer = true;

				ret = wdc_dump_dui_data(fd, xfer_size, curr_data_offset, (__u8 *)buffer_addr, last_xfer);
				if (ret != 0) {
					fprintf(stderr, "%s: ERROR : WDC : Get chunk %d, size = 0x%lx, offset = 0x%x, addr = 0x%lx\n",
							__func__, i, (long unsigned int)log_size, curr_data_offset, (long unsigned int)buffer_addr);
					fprintf(stderr, "%s: ERROR : WDC : NVMe Status:%s(%x)\n", __func__, nvme_status_to_string(ret), ret);
					break;
				}

				/* write the dump data into the file */
				err = write(output, (void *)buffer_addr, xfer_size);
				if (err != xfer_size) {
					fprintf(stderr, "%s: ERROR : WDC : Failed to flush DUI data to file! chunk %d, err = 0x%x, xfer_size = 0x%x\n",
							__func__, i, err, xfer_size);
					goto free_mem;
				}

				curr_data_offset += xfer_size;
				i++;
			}
		}
	}

	fprintf(stderr, "%s:  NVMe Status:%s(%x)\n", __func__, nvme_status_to_string(ret), ret);
	if (verbose)
		fprintf(stderr, "INFO : WDC : Capture Device Unit Info log, length = 0x%lx\n", (long unsigned int)total_size);

 free_mem:
	close(output);
	free(dump_data);

 out:
	free(log_hdr);
	return ret;
}

static int wdc_cap_diag(int argc, char **argv, struct command *command,
		struct plugin *plugin)
{
	char *desc = "Capture Diagnostics Log.";
	char *file = "Output file pathname.";
	char *size = "Data retrieval transfer size.";
	char f[PATH_MAX] = {0};
	__u32 xfer_size = 0;
	int fd;
	__u64 capabilities = 0;

	struct config {
		char *file;
		__u32 xfer_size;
	};

	struct config cfg = {
		.file = NULL,
		.xfer_size = 0x10000
	};

	const struct argconfig_commandline_options command_line_options[] = {
			{"output-file", 'o', "FILE", CFG_STRING, &cfg.file, required_argument, file},
			{"transfer-size", 's', "NUM", CFG_POSITIVE, &cfg.xfer_size, required_argument, size},
			{ NULL, '\0', NULL, CFG_NONE, NULL, no_argument, desc},
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, NULL, 0);
	if (fd < 0)
		return fd;

	if (cfg.file != NULL) {
		strncpy(f, cfg.file, PATH_MAX - 1);
	}
	if (cfg.xfer_size != 0) {
		xfer_size = cfg.xfer_size;
	}
	if (wdc_get_serial_name(fd, f, PATH_MAX, "cap_diag") == -1) {
		fprintf(stderr, "ERROR : WDC: failed to generate file name\n");
		return -1;
	}
	if (cfg.file == NULL)
		snprintf(f + strlen(f), PATH_MAX, "%s", ".bin");

	capabilities = wdc_get_drive_capabilities(fd);
	if ((capabilities & WDC_DRIVE_CAP_CAP_DIAG) == WDC_DRIVE_CAP_CAP_DIAG) {
		return wdc_do_cap_diag(fd, f, xfer_size);
	} else
		fprintf(stderr, "ERROR : WDC: unsupported device for this command\n");

	return 0;
}

static int wdc_do_get_sn730_log_len(int fd, uint32_t *len_buf, uint32_t subopcode)
{
	int ret;
	uint32_t *output = NULL;
	struct nvme_admin_cmd admin_cmd;

	if ((output = (uint32_t*)malloc(sizeof(uint32_t))) == NULL) {
		fprintf(stderr, "ERROR : WDC : malloc : %s\n", strerror(errno));
		return -1;
	}
	memset(output, 0, sizeof (uint32_t));
	memset(&admin_cmd, 0, sizeof (struct nvme_admin_cmd));

	admin_cmd.data_len = 8;
	admin_cmd.opcode = SN730_NVME_GET_LOG_OPCODE;
	admin_cmd.addr = (uintptr_t)output;
	admin_cmd.cdw12 = subopcode;
	admin_cmd.cdw10 = SN730_LOG_CHUNK_SIZE / 4;

	ret = nvme_submit_passthru(fd, NVME_IOCTL_ADMIN_CMD, &admin_cmd);
	if (ret == 0)
		*len_buf = *output;
	free(output);
	return ret;
}

static int wdc_do_get_sn730_log(int fd, void * log_buf, uint32_t offset, uint32_t subopcode)
{
	int ret;
	uint8_t *output = NULL;
	struct nvme_admin_cmd admin_cmd;

	if ((output = (uint8_t*)calloc(SN730_LOG_CHUNK_SIZE, sizeof(uint8_t))) == NULL) {
		fprintf(stderr, "ERROR : WDC : calloc : %s\n", strerror(errno));
		return -1;
	}
	memset(&admin_cmd, 0, sizeof (struct nvme_admin_cmd));
	admin_cmd.data_len = SN730_LOG_CHUNK_SIZE;
	admin_cmd.opcode = SN730_NVME_GET_LOG_OPCODE;
	admin_cmd.addr = (uintptr_t)output;
	admin_cmd.cdw12 = subopcode;
	admin_cmd.cdw13 = offset;
	admin_cmd.cdw10 = SN730_LOG_CHUNK_SIZE / 4;

	ret = nvme_submit_passthru(fd, NVME_IOCTL_ADMIN_CMD, &admin_cmd);
	if (!ret)
		memcpy(log_buf, output, SN730_LOG_CHUNK_SIZE);
	return ret;
}

static int get_sn730_log_chunks(int fd, uint8_t* log_buf, uint32_t log_len, uint32_t subopcode)
{
	int ret = 0;
	uint8_t* chunk_buf = NULL;
	int remaining = log_len;
	int curr_offset = 0;

	if ((chunk_buf = (uint8_t*) malloc(sizeof (uint8_t) * SN730_LOG_CHUNK_SIZE)) == NULL) {
		fprintf(stderr, "ERROR : WDC : malloc : %s\n", strerror(errno));
		ret = -1;
		goto out;
	}

	while (remaining > 0) {
		memset(chunk_buf, 0, SN730_LOG_CHUNK_SIZE);
		ret = wdc_do_get_sn730_log(fd, chunk_buf, curr_offset, subopcode);
		if (!ret) {
			if (remaining >= SN730_LOG_CHUNK_SIZE) {
				memcpy(log_buf + (curr_offset * SN730_LOG_CHUNK_SIZE),
						chunk_buf, SN730_LOG_CHUNK_SIZE);
			} else {
				memcpy(log_buf + (curr_offset * SN730_LOG_CHUNK_SIZE),
						chunk_buf, remaining);
			}
			remaining -= SN730_LOG_CHUNK_SIZE;
			curr_offset += 1;
		} else
			goto out;
	}
out:
	free(chunk_buf);
	return ret;
}

static int wdc_do_sn730_get_and_tar(int fd, char * outputName)
{
	int ret = 0;
	void *retPtr;
	uint8_t* full_log_buf = NULL;
	uint8_t* key_log_buf = NULL;
	uint8_t* core_dump_log_buf = NULL;
	uint8_t* extended_log_buf = NULL;
	uint32_t full_log_len = 0;
	uint32_t key_log_len = 0;
	uint32_t core_dump_log_len = 0;
	uint32_t extended_log_len = 0;
	tarfile_metadata* tarInfo = NULL;

	tarInfo = (struct tarfile_metadata*) malloc(sizeof(tarfile_metadata));
	if (tarInfo == NULL) {
		fprintf(stderr, "ERROR : WDC : malloc : %s\n", strerror(errno));
		ret = -1;
		goto free_buf;
	}
	memset(tarInfo, 0, sizeof(tarfile_metadata));

	/* Create Logs directory  */
	wdc_UtilsGetTime(&tarInfo->timeInfo);
	memset(tarInfo->timeString, 0, sizeof(tarInfo->timeString));
	wdc_UtilsSnprintf((char*)tarInfo->timeString, MAX_PATH_LEN, "%02u%02u%02u_%02u%02u%02u",
			tarInfo->timeInfo.year, tarInfo->timeInfo.month, tarInfo->timeInfo.dayOfMonth,
			tarInfo->timeInfo.hour, tarInfo->timeInfo.minute, tarInfo->timeInfo.second);

	wdc_UtilsSnprintf((char*)tarInfo->bufferFolderName, MAX_PATH_LEN, "%s",
			(char*)outputName);

	retPtr = getcwd((char*)tarInfo->currDir, MAX_PATH_LEN);
	if (retPtr != NULL)
		wdc_UtilsSnprintf((char*)tarInfo->bufferFolderPath, MAX_PATH_LEN, "%s%s%s",
				(char *)tarInfo->currDir, WDC_DE_PATH_SEPARATOR, (char *)tarInfo->bufferFolderName);
	else {
		fprintf(stderr, "ERROR : WDC : get current working directory failed\n");
		goto free_buf;
	}

	ret = wdc_UtilsCreateDir((char*)tarInfo->bufferFolderPath);
	if (ret)
	{
		fprintf(stderr, "ERROR : WDC : create directory failed, ret = %d, dir = %s\n", ret, tarInfo->bufferFolderPath);
		goto free_buf;
	} else {
		fprintf(stderr, "Stored log files in directory: %s\n", tarInfo->bufferFolderPath);
	}

	ret = wdc_do_get_sn730_log_len(fd, &full_log_len, SN730_GET_FULL_LOG_LENGTH);
	if (ret) {
		fprintf(stderr, "NVMe Status:%s(%x)\n", nvme_status_to_string(ret), ret);
		goto free_buf;
	}
	ret = wdc_do_get_sn730_log_len(fd, &key_log_len, SN730_GET_KEY_LOG_LENGTH);
	if (ret) {
		fprintf(stderr, "NVMe Status:%s(%x)\n", nvme_status_to_string(ret), ret);
		goto free_buf;
	}
	ret = wdc_do_get_sn730_log_len(fd, &core_dump_log_len, SN730_GET_COREDUMP_LOG_LENGTH);
	if (ret) {
		fprintf(stderr, "NVMe Status:%s(%x)\n", nvme_status_to_string(ret), ret);
		goto free_buf;
	}
	ret = wdc_do_get_sn730_log_len(fd, &extended_log_len, SN730_GET_EXTENDED_LOG_LENGTH);
	if (ret) {
		fprintf(stderr, "NVMe Status:%s(%x)\n", nvme_status_to_string(ret), ret);
		goto free_buf;
	}

	full_log_buf = (uint8_t*) calloc(full_log_len, sizeof (uint8_t));
	key_log_buf = (uint8_t*) calloc(key_log_len, sizeof (uint8_t));
	core_dump_log_buf = (uint8_t*) calloc(core_dump_log_len, sizeof (uint8_t));
	extended_log_buf = (uint8_t*) calloc(extended_log_len, sizeof (uint8_t));

	if (!full_log_buf || !key_log_buf || !core_dump_log_buf || !extended_log_buf) {
		fprintf(stderr, "ERROR : WDC : malloc : %s\n", strerror(errno));
		ret = -1;
		goto free_buf;
	}

	/* Get the full log */
	ret = get_sn730_log_chunks(fd, full_log_buf, full_log_len, SN730_GET_FULL_LOG_SUBOPCODE);
	if (ret) {
		fprintf(stderr, "NVMe Status:%s(%x)\n", nvme_status_to_string(ret), ret);
		goto free_buf;
	}

	/* Get the key log */
	ret = get_sn730_log_chunks(fd, key_log_buf, key_log_len, SN730_GET_KEY_LOG_SUBOPCODE);
	if (ret) {
		fprintf(stderr, "NVMe Status:%s(%x)\n", nvme_status_to_string(ret), ret);
		goto free_buf;
	}

	/* Get the core dump log */
	ret = get_sn730_log_chunks(fd, core_dump_log_buf, core_dump_log_len, SN730_GET_CORE_LOG_SUBOPCODE);
	if (ret) {
		fprintf(stderr, "NVMe Status:%s(%x)\n", nvme_status_to_string(ret), ret);
		goto free_buf;
	}

	/* Get the extended log */
	ret = get_sn730_log_chunks(fd, extended_log_buf, extended_log_len, SN730_GET_EXTEND_LOG_SUBOPCODE);
	if (ret) {
		fprintf(stderr, "NVMe Status:%s(%x)\n", nvme_status_to_string(ret), ret);
		goto free_buf;
	}

	/* Write log files */
	wdc_UtilsSnprintf(tarInfo->fileName, MAX_PATH_LEN, "%s%s%s_%s.bin", (char*)tarInfo->bufferFolderPath, WDC_DE_PATH_SEPARATOR,
			"full_log", (char*)tarInfo->timeString);
	wdc_WriteToFile(tarInfo->fileName, (char*)full_log_buf, full_log_len);

	wdc_UtilsSnprintf(tarInfo->fileName, MAX_PATH_LEN, "%s%s%s_%s.bin", (char*)tarInfo->bufferFolderPath, WDC_DE_PATH_SEPARATOR,
			"key_log", (char*)tarInfo->timeString);
	wdc_WriteToFile(tarInfo->fileName, (char*)key_log_buf, key_log_len);

	wdc_UtilsSnprintf(tarInfo->fileName, MAX_PATH_LEN, "%s%s%s_%s.bin", (char*)tarInfo->bufferFolderPath, WDC_DE_PATH_SEPARATOR,
			"core_dump_log", (char*)tarInfo->timeString);
	wdc_WriteToFile(tarInfo->fileName, (char*)core_dump_log_buf, core_dump_log_len);

	wdc_UtilsSnprintf(tarInfo->fileName, MAX_PATH_LEN, "%s%s%s_%s.bin", (char*)tarInfo->bufferFolderPath, WDC_DE_PATH_SEPARATOR,
			"extended_log", (char*)tarInfo->timeString);
	wdc_WriteToFile(tarInfo->fileName, (char*)extended_log_buf, extended_log_len);

	/* Tar the log directory */
	wdc_UtilsSnprintf(tarInfo->tarFileName, sizeof(tarInfo->tarFileName), "%s%s", (char*)tarInfo->bufferFolderPath, WDC_DE_TAR_FILE_EXTN);
	wdc_UtilsSnprintf(tarInfo->tarFiles, sizeof(tarInfo->tarFiles), "%s%s%s", (char*)tarInfo->bufferFolderName, WDC_DE_PATH_SEPARATOR, WDC_DE_TAR_FILES);
	wdc_UtilsSnprintf(tarInfo->tarCmd, sizeof(tarInfo->tarCmd), "%s %s %s", WDC_DE_TAR_CMD, (char*)tarInfo->tarFileName, (char*)tarInfo->tarFiles);

	ret = system(tarInfo->tarCmd);

	if (ret)
		fprintf(stderr, "ERROR : WDC : Tar of log data failed, ret = %d\n", ret);

free_buf:
	free(tarInfo);
	free(full_log_buf);
	free(core_dump_log_buf);
	free(key_log_buf);
	free(extended_log_buf);
	return ret;
}

static int wdc_vs_internal_fw_log(int argc, char **argv, struct command *command,
               struct plugin *plugin)
{
	char *desc = "Internal Firmware Log.";
	char *file = "Output file pathname.";
	char *size = "Data retrieval transfer size.";
	char *data_area = "Data area to retrieve up to.";
	char *verbose = "Display more debug messages.";
	char f[PATH_MAX] = {0};
	char fileSuffix[PATH_MAX] = {0};
	__u32 xfer_size = 0;
	int fd;
	UtilsTimeInfo             timeInfo;
	__u8                      timeStamp[MAX_PATH_LEN];
	__u64 capabilities = 0;

	struct config {
		char *file;
		__u32 xfer_size;
		int data_area;
		int verbose;
	};

	struct config cfg = {
		.file = NULL,
		.xfer_size = 0x10000,
		.data_area = 5,
		.verbose = 0,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"output-file", 'o', "FILE", CFG_STRING, &cfg.file, required_argument, file},
		{"transfer-size", 's', "NUM", CFG_POSITIVE, &cfg.xfer_size, required_argument, size},
		{"data-area", 'd', "NUM", CFG_POSITIVE, &cfg.data_area, required_argument, data_area},
		{"verbose", 'v', "",     CFG_NONE,     &cfg.verbose, no_argument, verbose},
		{ NULL, '\0', NULL, CFG_NONE, NULL, no_argument, desc},
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, NULL, 0);
	if (fd < 0)
		return fd;

	if (!wdc_check_device(fd))
		return -1;
	if (cfg.xfer_size != 0)
		xfer_size = cfg.xfer_size;
	else {
		fprintf(stderr, "ERROR : WDC : Invalid length\n");
		return -1;
	}

	if (cfg.file != NULL) {
		int verify_file;

		/* verify the passed in file name and path is valid before getting the dump data */
		verify_file = open(cfg.file, O_WRONLY | O_CREAT | O_TRUNC, 0666);
		if (verify_file < 0) {
			fprintf(stderr, "ERROR : WDC: open : %s\n", strerror(errno));
			return -1;
		}
		close(verify_file);
		strncpy(f, cfg.file, PATH_MAX - 1);
	} else {
		wdc_UtilsGetTime(&timeInfo);
		memset(timeStamp, 0, sizeof(timeStamp));
		wdc_UtilsSnprintf((char*)timeStamp, MAX_PATH_LEN, "%02u%02u%02u_%02u%02u%02u",
			timeInfo.year, timeInfo.month, timeInfo.dayOfMonth,
			timeInfo.hour, timeInfo.minute, timeInfo.second);
		snprintf(fileSuffix, PATH_MAX, "_internal_fw_log_%s", (char*)timeStamp);

		if (wdc_get_serial_name(fd, f, PATH_MAX, fileSuffix) == -1) {
			fprintf(stderr, "ERROR : WDC: failed to generate file name\n");
			return -1;
		}
	}
	if (cfg.file == NULL)
		snprintf(f + strlen(f), PATH_MAX, "%s", ".bin");
	fprintf(stderr, "%s: filename = %s\n", __func__, f);

	if (cfg.data_area > 5 || cfg.data_area == 0) {
		fprintf(stderr, "ERROR : WDC: Data area must be 1-5\n");
		return -1;
	}

	capabilities = wdc_get_drive_capabilities(fd);
	if ((capabilities & WDC_DRIVE_CAP_INTERNAL_LOG) == WDC_DRIVE_CAP_INTERNAL_LOG) {
		return wdc_do_cap_diag(fd, f, xfer_size);
	} else if ((capabilities & WDC_DRIVE_CAP_SN340_DUI) == WDC_DRIVE_CAP_SN340_DUI) {
		return wdc_do_cap_dui(fd, f, xfer_size, cfg.data_area, cfg.verbose);
	} else if ((capabilities & WDC_DRIVE_CAP_DUI_DATA) == WDC_DRIVE_CAP_DUI_DATA) {
		return wdc_do_cap_dui(fd, f, xfer_size, cfg.data_area, cfg.verbose);
	} else if ((capabilities & WDC_SN730B_CAP_VUC_LOG) == WDC_SN730B_CAP_VUC_LOG) {
		return wdc_do_sn730_get_and_tar(fd, f);
	} else {
		fprintf(stderr, "ERROR : WDC: unsupported device for this command\n");
		return -1;
	}
}

static int wdc_do_crash_dump(int fd, char *file, int type)
{
	int ret;
	__u32 crash_dump_length;
	__u32 opcode;
	__u32 cdw12;
	__u32 cdw10_size;
	__u32 cdw12_size;
	__u32 cdw12_clear;

	if (type == WDC_NVME_PFAIL_DUMP_TYPE) {
		/* set parms to get the PFAIL Crash Dump */
		opcode = WDC_NVME_PF_CRASH_DUMP_OPCODE;
		cdw10_size = WDC_NVME_PF_CRASH_DUMP_SIZE_NDT;
		cdw12_size = ((WDC_NVME_PF_CRASH_DUMP_SIZE_SUBCMD << WDC_NVME_SUBCMD_SHIFT) |
			WDC_NVME_PF_CRASH_DUMP_SIZE_CMD);

		cdw12 = (WDC_NVME_PF_CRASH_DUMP_SUBCMD << WDC_NVME_SUBCMD_SHIFT) |
			WDC_NVME_PF_CRASH_DUMP_CMD;

		cdw12_clear = ((WDC_NVME_CLEAR_PF_CRASH_DUMP_SUBCMD << WDC_NVME_SUBCMD_SHIFT) |
			WDC_NVME_CLEAR_CRASH_DUMP_CMD);

	} else {
		/* set parms to get the Crash Dump */
		opcode = WDC_NVME_CRASH_DUMP_OPCODE;
		cdw10_size = WDC_NVME_CRASH_DUMP_SIZE_NDT;
		cdw12_size = ((WDC_NVME_CRASH_DUMP_SIZE_SUBCMD << WDC_NVME_SUBCMD_SHIFT) |
			WDC_NVME_CRASH_DUMP_SIZE_CMD);

		cdw12 = (WDC_NVME_CRASH_DUMP_SUBCMD << WDC_NVME_SUBCMD_SHIFT) |
			WDC_NVME_CRASH_DUMP_CMD;

		cdw12_clear = ((WDC_NVME_CLEAR_CRASH_DUMP_SUBCMD << WDC_NVME_SUBCMD_SHIFT) |
			WDC_NVME_CLEAR_CRASH_DUMP_CMD);
	}

	ret = wdc_dump_length(fd,
		opcode,
		cdw10_size,
		cdw12_size,
		&crash_dump_length);

	if (ret == -1) {
		if (type == WDC_NVME_PFAIL_DUMP_TYPE)
		    fprintf(stderr, "INFO : WDC: Pfail dump get size failed\n");
		else
		    fprintf(stderr, "INFO : WDC: Crash dump get size failed\n");

		return -1;
	}

	if (crash_dump_length == 0) {
		if (type == WDC_NVME_PFAIL_DUMP_TYPE)
		    fprintf(stderr, "INFO : WDC: Pfail dump is empty\n");
		else
		    fprintf(stderr, "INFO : WDC: Crash dump is empty\n");
	} else {
		ret = wdc_do_dump(fd,
			opcode,
			crash_dump_length,
			cdw12,
			file,
			crash_dump_length);

		if (ret == 0)
			ret = wdc_do_clear_dump(fd, WDC_NVME_CLEAR_DUMP_OPCODE, cdw12_clear);
	}
	return ret;
}

static int wdc_crash_dump(int fd, char *file, int type)
{
	char f[PATH_MAX] = {0};
	const char *dump_type;

	if (file != NULL) {
		strncpy(f, file, PATH_MAX - 1);
	}

	if (type == WDC_NVME_PFAIL_DUMP_TYPE)
		dump_type = "_pfail_dump";
	else
		dump_type = "_crash_dump";

	if (wdc_get_serial_name(fd, f, PATH_MAX, dump_type) == -1) {
		fprintf(stderr, "ERROR : WDC : failed to generate file name\n");
		return -1;
	}
	return wdc_do_crash_dump(fd, f, type);
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
	int ret;
	__u64 capabilities = 0;
	struct config {
		char *file;
	};

	struct config cfg = {
		.file = NULL
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"output-file", 'o', "FILE", CFG_STRING, &cfg.file, required_argument, file},
		{ NULL, '\0', NULL, CFG_NONE, NULL, no_argument, desc},
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, NULL, 0);
	if (fd < 0)
		return fd;

	if (!wdc_check_device(fd))
		return -1;
	capabilities = wdc_get_drive_capabilities(fd);

	if ((capabilities & WDC_DRIVE_CAP_DRIVE_LOG) == 0) {
		fprintf(stderr, "ERROR : WDC: unsupported device for this command\n");
		ret = -1;
	} else {
		if (cfg.file != NULL) {
			strncpy(f, cfg.file, PATH_MAX - 1);
		}
		if (wdc_get_serial_name(fd, f, PATH_MAX, "drive_log") == -1) {
			fprintf(stderr, "ERROR : WDC : failed to generate file name\n");
			return -1;
		}
		ret = wdc_do_drive_log(fd, f);
	}
	return ret;
}

static int wdc_get_crash_dump(int argc, char **argv, struct command *command,
		struct plugin *plugin)
{
	const char *desc = "Get Crash Dump.";
	const char *file = "Output file pathname.";
	int fd;
	int ret;
	__u64 capabilities = 0;
	struct config {
		char *file;
	};

	struct config cfg = {
		.file = NULL,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"output-file", 'o', "FILE", CFG_STRING, &cfg.file, required_argument, file},
		{ NULL, '\0', NULL, CFG_NONE, NULL, no_argument, desc},
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, NULL, 0);
	if (fd < 0)
		return fd;

	if (!wdc_check_device(fd))
		return -1;

	capabilities = wdc_get_drive_capabilities(fd);

	if ((capabilities & WDC_DRIVE_CAP_CRASH_DUMP) == 0) {
		fprintf(stderr, "ERROR : WDC: unsupported device for this command\n");
		ret = -1;
	} else {
		ret = wdc_crash_dump(fd, cfg.file, WDC_NVME_CRASH_DUMP_TYPE);
		if (ret != 0) {
			fprintf(stderr, "ERROR : WDC : failed to read crash dump\n");
		}
	}
	return ret;
}

static int wdc_get_pfail_dump(int argc, char **argv, struct command *command,
		struct plugin *plugin)
{
	char *desc = "Get Pfail Crash Dump.";
	char *file = "Output file pathname.";
	int fd;
	int ret;
	__u64 capabilities = 0;
	struct config {
		char *file;
	};

	struct config cfg = {
		.file = NULL,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"output-file", 'o', "FILE", CFG_STRING, &cfg.file, required_argument, file},
		{ NULL, '\0', NULL, CFG_NONE, NULL, no_argument, desc},
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, NULL, 0);
	if (fd < 0)
		return fd;

	if (!wdc_check_device(fd))
		return -1;
	capabilities = wdc_get_drive_capabilities(fd);

	if ((capabilities & WDC_DRIVE_CAP_PFAIL_DUMP) == 0) {
		fprintf(stderr, "ERROR : WDC: unsupported device for this command\n");
		ret = -1;
	} else {
		ret = wdc_crash_dump(fd, cfg.file, WDC_NVME_PFAIL_DUMP_TYPE);
		if (ret != 0) {
			fprintf(stderr, "ERROR : WDC : failed to read pfail crash dump\n");
		}
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
	};

	err_str = "";
	memset(&admin_cmd, 0, sizeof (admin_cmd));
	admin_cmd.opcode = WDC_NVME_PURGE_CMD_OPCODE;

	fd = parse_and_open(argc, argv, desc, command_line_options, NULL, 0);
	if (fd < 0)
		return fd;

	if (!wdc_check_device(fd))
		return -1;
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

	if (!wdc_check_device(fd))
		return -1;
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
			le64_to_cpu(perf->hr_cmds));
	printf("  Host Read Blocks                               %20"PRIu64"\n",
			le64_to_cpu(perf->hr_blks));
	printf("  Average Read Size                              %20lf\n",
			safe_div_fp((le64_to_cpu(perf->hr_blks)), (le64_to_cpu(perf->hr_cmds))));
	printf("  Host Read Cache Hit Commands                   %20"PRIu64"\n",
			le64_to_cpu(perf->hr_ch_cmds));
	printf("  Host Read Cache Hit_Percentage                 %20"PRIu64"%%\n",
			(uint64_t) calc_percent(le64_to_cpu(perf->hr_ch_cmds), le64_to_cpu(perf->hr_cmds)));
	printf("  Host Read Cache Hit Blocks                     %20"PRIu64"\n",
			le64_to_cpu(perf->hr_ch_blks));
	printf("  Average Read Cache Hit Size                    %20f\n",
			safe_div_fp((le64_to_cpu(perf->hr_ch_blks)), (le64_to_cpu(perf->hr_ch_cmds))));
	printf("  Host Read Commands Stalled                     %20"PRIu64"\n",
			le64_to_cpu(perf->hr_st_cmds));
	printf("  Host Read Commands Stalled Percentage          %20"PRIu64"%%\n",
			(uint64_t)calc_percent((le64_to_cpu(perf->hr_st_cmds)), le64_to_cpu(perf->hr_cmds)));
	printf("  Host Write Commands                            %20"PRIu64"\n",
			le64_to_cpu(perf->hw_cmds));
	printf("  Host Write Blocks                              %20"PRIu64"\n",
			le64_to_cpu(perf->hw_blks));
	printf("  Average Write Size                             %20f\n",
			safe_div_fp((le64_to_cpu(perf->hw_blks)), (le64_to_cpu(perf->hw_cmds))));
	printf("  Host Write Odd Start Commands                  %20"PRIu64"\n",
			le64_to_cpu(perf->hw_os_cmds));
	printf("  Host Write Odd Start Commands Percentage       %20"PRIu64"%%\n",
			(uint64_t)calc_percent((le64_to_cpu(perf->hw_os_cmds)), (le64_to_cpu(perf->hw_cmds))));
	printf("  Host Write Odd End Commands                    %20"PRIu64"\n",
			le64_to_cpu(perf->hw_oe_cmds));
	printf("  Host Write Odd End Commands Percentage         %20"PRIu64"%%\n",
			(uint64_t)calc_percent((le64_to_cpu(perf->hw_oe_cmds)), (le64_to_cpu((perf->hw_cmds)))));
	printf("  Host Write Commands Stalled                    %20"PRIu64"\n",
		le64_to_cpu(perf->hw_st_cmds));
	printf("  Host Write Commands Stalled Percentage         %20"PRIu64"%%\n",
		(uint64_t)calc_percent((le64_to_cpu(perf->hw_st_cmds)), (le64_to_cpu(perf->hw_cmds))));
	printf("  NAND Read Commands                             %20"PRIu64"\n",
		le64_to_cpu(perf->nr_cmds));
	printf("  NAND Read Blocks Commands                      %20"PRIu64"\n",
		le64_to_cpu(perf->nr_blks));
	printf("  Average NAND Read Size                         %20f\n",
		safe_div_fp((le64_to_cpu(perf->nr_blks)), (le64_to_cpu((perf->nr_cmds)))));
	printf("  Nand Write Commands                            %20"PRIu64"\n",
			le64_to_cpu(perf->nw_cmds));
	printf("  NAND Write Blocks                              %20"PRIu64"\n",
			le64_to_cpu(perf->nw_blks));
	printf("  Average NAND Write Size                        %20f\n",
			safe_div_fp((le64_to_cpu(perf->nw_blks)), (le64_to_cpu(perf->nw_cmds))));
	printf("  NAND Read Before Write                         %20"PRIu64"\n",
			le64_to_cpu(perf->nrbw));
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
			le64_to_cpu(perf->hr_ch_cmds));
	json_object_add_value_int(root, "Host Read Cache Hit Percentage",
			(uint64_t) calc_percent(le64_to_cpu(perf->hr_ch_cmds), le64_to_cpu(perf->hr_cmds)));
	json_object_add_value_int(root, "Host Read Cache Hit Blocks",
			le64_to_cpu(perf->hr_ch_blks));
	json_object_add_value_int(root, "Average Read Cache Hit Size",
			safe_div_fp((le64_to_cpu(perf->hr_ch_blks)), (le64_to_cpu(perf->hr_ch_cmds))));
	json_object_add_value_int(root, "Host Read Commands Stalled",
			le64_to_cpu(perf->hr_st_cmds));
	json_object_add_value_int(root, "Host Read Commands Stalled Percentage",
			(uint64_t)calc_percent((le64_to_cpu(perf->hr_st_cmds)), le64_to_cpu(perf->hr_cmds)));
	json_object_add_value_int(root, "Host Write Commands",
			le64_to_cpu(perf->hw_cmds));
	json_object_add_value_int(root, "Host Write Blocks",
			le64_to_cpu(perf->hw_blks));
	json_object_add_value_int(root, "Average Write Size",
			safe_div_fp((le64_to_cpu(perf->hw_blks)), (le64_to_cpu(perf->hw_cmds))));
	json_object_add_value_int(root, "Host Write Odd Start Commands",
			le64_to_cpu(perf->hw_os_cmds));
	json_object_add_value_int(root, "Host Write Odd Start Commands Percentage",
			(uint64_t)calc_percent((le64_to_cpu(perf->hw_os_cmds)), (le64_to_cpu(perf->hw_cmds))));
	json_object_add_value_int(root, "Host Write Odd End Commands",
			le64_to_cpu(perf->hw_oe_cmds));
	json_object_add_value_int(root, "Host Write Odd End Commands Percentage",
			(uint64_t)calc_percent((le64_to_cpu(perf->hw_oe_cmds)), (le64_to_cpu((perf->hw_cmds)))));
	json_object_add_value_int(root, "Host Write Commands Stalled",
		le64_to_cpu(perf->hw_st_cmds));
	json_object_add_value_int(root, "Host Write Commands Stalled Percentage",
		(uint64_t)calc_percent((le64_to_cpu(perf->hw_st_cmds)), (le64_to_cpu(perf->hw_cmds))));
	json_object_add_value_int(root, "NAND Read Commands",
		le64_to_cpu(perf->nr_cmds));
	json_object_add_value_int(root, "NAND Read Blocks Commands",
		le64_to_cpu(perf->nr_blks));
	json_object_add_value_int(root, "Average NAND Read Size",
		safe_div_fp((le64_to_cpu(perf->nr_blks)), (le64_to_cpu((perf->nr_cmds)))));
	json_object_add_value_int(root, "Nand Write Commands",
			le64_to_cpu(perf->nw_cmds));
	json_object_add_value_int(root, "NAND Write Blocks",
			le64_to_cpu(perf->nw_blks));
	json_object_add_value_int(root, "Average NAND Write Size",
			safe_div_fp((le64_to_cpu(perf->nw_blks)), (le64_to_cpu(perf->nw_cmds))));
	json_object_add_value_int(root, "NAND Read Before Written",
			le64_to_cpu(perf->nrbw));
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
			le64_to_cpu(perf->nand_bytes_wr_hi), le64_to_cpu(perf->nand_bytes_wr_lo));
	printf("  NAND Bytes Read                                %20"PRIu64 "%20"PRIu64"\n",
			le64_to_cpu(perf->nand_bytes_rd_hi), le64_to_cpu(perf->nand_bytes_rd_lo));

	converted = le64_to_cpu(perf->nand_bad_block);
	printf("  NAND Bad Block Count (Normalized)              %20"PRIu64"\n",
			converted & 0xFFFF);
	printf("  NAND Bad Block Count (Raw)                     %20"PRIu64"\n",
			converted >> 16);

	printf("  Uncorrectable Read Count                       %20"PRIu64"\n",
			le64_to_cpu(perf->uncorr_read_count));
	printf("  Soft ECC Error Count                           %20"PRIu64"\n",
			le64_to_cpu(perf->ecc_error_count));
	printf("  SSD End to End Detected Correction Count       %20"PRIu32"\n",
			(uint32_t)le32_to_cpu(perf->ssd_detect_count));
	printf("  SSD End to End Corrected Correction Count      %20"PRIu32"\n",
			(uint32_t)le32_to_cpu(perf->ssd_correct_count));
	printf("  System Data Percent Used                       %20"PRIu32"%%\n",
			perf->data_percent_used);
	printf("  User Data Erase Counts Max                     %20"PRIu32"\n",
			(uint32_t)le32_to_cpu(perf->data_erase_max));
	printf("  User Data Erase Counts Min                     %20"PRIu32"\n",
			(uint32_t)le32_to_cpu(perf->data_erase_min));
	printf("  Refresh Count                                  %20"PRIu64"\n",
			le64_to_cpu(perf->refresh_count));

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

	printf("  Thermal Throttling Status                      %20"PRIu8"\n",
			perf->thermal_throttle_status);
	printf("  Thermal Throttling Count                       %20"PRIu8"\n",
			perf->thermal_throttle_count);
	printf("  PCIe Correctable Error Count                   %20"PRIu64"\n",
			le64_to_cpu(perf->pcie_corr_error));
	printf("  Incomplete Shutdown Count                      %20"PRIu32"\n",
			(uint32_t)le32_to_cpu(perf->incomplete_shutdown_count));
	printf("  Percent Free Blocks                            %20"PRIu32"%%\n",
			perf->percent_free_blocks);
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
			perf->data_percent_used);
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
			perf->thermal_throttle_status);
	json_object_add_value_int(root, "Thermal Throttling Count",
			perf->thermal_throttle_count);
	json_object_add_value_int(root, "PCIe Correctable Error", le64_to_cpu(perf->pcie_corr_error));
	json_object_add_value_int(root, "Incomplete Shutdown Counte", le32_to_cpu(perf->incomplete_shutdown_count));
	json_object_add_value_int(root, "Percent Free Blocks", perf->percent_free_blocks);
	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static void wdc_print_d0_log_normal(struct wdc_ssd_d0_smart_log *perf)
{
	printf("  D0 Smart Log Page Statistics :- \n");
	printf("  Lifetime Reallocated Erase Block Count	 %20"PRIu32"\n",
			(uint32_t)le32_to_cpu(perf->lifetime_realloc_erase_block_count));
	printf("  Lifetime Power on Hours			 %20"PRIu32"\n",
			(uint32_t)le32_to_cpu(perf->lifetime_power_on_hours));
	printf("  Lifetime UECC Count	                         %20"PRIu32"\n",
			(uint32_t)le32_to_cpu(perf->lifetime_uecc_count));
	printf("  Lifetime Write Amplification Factor	         %20"PRIu32"\n",
			(uint32_t)le32_to_cpu(perf->lifetime_wrt_amp_factor));
	printf("  Trailing Hour Write Amplification Factor  	 %20"PRIu32"\n",
			(uint32_t)le32_to_cpu(perf->trailing_hr_wrt_amp_factor));
	printf("  Reserve Erase Block Count	                 %20"PRIu32"\n",
			(uint32_t)le32_to_cpu(perf->reserve_erase_block_count));
	printf("  Lifetime Program Fail Count	     	         %20"PRIu32"\n",
			(uint32_t)le32_to_cpu(perf->lifetime_program_fail_count));
	printf("  Lifetime Block Erase Fail Count		 %20"PRIu32"\n",
			(uint32_t)le32_to_cpu(perf->lifetime_block_erase_fail_count));
	printf("  Lifetime Die Failure Count	                 %20"PRIu32"\n",
			(uint32_t)le32_to_cpu(perf->lifetime_die_failure_count));
	printf("  Lifetime Link Rate Downgrade Count	         %20"PRIu32"\n",
			(uint32_t)le32_to_cpu(perf->lifetime_link_rate_downgrade_count));
	printf("  Lifetime Clean Shutdown Count on Power Loss	 %20"PRIu32"\n",
			(uint32_t)le32_to_cpu(perf->lifetime_clean_shutdown_count));
	printf("  Lifetime Unclean Shutdowns on Power Loss	 %20"PRIu32"\n",
			(uint32_t)le32_to_cpu(perf->lifetime_unclean_shutdown_count));
	printf("  Current Temperature 	                         %20"PRIu32"\n",
			(uint32_t)le32_to_cpu(perf->current_temp));
	printf("  Max Recorded Temperature			 %20"PRIu32"\n",
			(uint32_t)le32_to_cpu(perf->max_recorded_temp));
	printf("  Lifetime Retired Block Count	                 %20"PRIu32"\n",
			(uint32_t)le32_to_cpu(perf->lifetime_retired_block_count));
	printf("  Lifetime Read Disturb Reallocation Events	 %20"PRIu32"\n",
			(uint32_t)le32_to_cpu(perf->lifetime_read_disturb_realloc_events));
	printf("  Lifetime NAND Writes	                         %20"PRIu64"\n",
			le64_to_cpu(perf->lifetime_nand_writes));
	printf("  Capacitor Health			 	 %20"PRIu32"%%\n",
			(uint32_t)le32_to_cpu(perf->capacitor_health));
	printf("  Lifetime User Writes	                         %20"PRIu64"\n",
			le64_to_cpu(perf->lifetime_user_writes));
	printf("  Lifetime User Reads	                         %20"PRIu64"\n",
			le64_to_cpu(perf->lifetime_user_reads));
	printf("  Lifetime Thermal Throttle Activations	         %20"PRIu32"\n",
			(uint32_t)le32_to_cpu(perf->lifetime_thermal_throttle_act));
	printf("  Percentage of P/E Cycles Remaining             %20"PRIu32"%%\n",
			(uint32_t)le32_to_cpu(perf->percentage_pe_cycles_remaining));
}

static void wdc_print_d0_log_json(struct wdc_ssd_d0_smart_log *perf)
{
	struct json_object *root;

	root = json_create_object();
	json_object_add_value_int(root, "Lifetime Reallocated Erase Block Count",
			le32_to_cpu(perf->lifetime_realloc_erase_block_count));
	json_object_add_value_int(root, "Lifetime Power on Hours",
			le32_to_cpu(perf->lifetime_power_on_hours));
	json_object_add_value_int(root, "Lifetime UECC Count",
			le32_to_cpu(perf->lifetime_uecc_count));
	json_object_add_value_int(root, "Lifetime Write Amplification Factor",
			le32_to_cpu(perf->lifetime_wrt_amp_factor));
	json_object_add_value_int(root, "Trailing Hour Write Amplification Factor",
			le32_to_cpu(perf->trailing_hr_wrt_amp_factor));
	json_object_add_value_int(root, "Reserve Erase Block Count",
			le32_to_cpu(perf->reserve_erase_block_count));
	json_object_add_value_int(root, "Lifetime Program Fail Count",
			le32_to_cpu(perf->lifetime_program_fail_count));
	json_object_add_value_int(root, "Lifetime Block Erase Fail Count",
			le32_to_cpu(perf->lifetime_block_erase_fail_count));
	json_object_add_value_int(root, "Lifetime Die Failure Count",
			le32_to_cpu(perf->lifetime_die_failure_count));
	json_object_add_value_int(root, "Lifetime Link Rate Downgrade Count",
			le32_to_cpu(perf->lifetime_link_rate_downgrade_count));
	json_object_add_value_int(root, "Lifetime Clean Shutdown Count on Power Loss",
			le32_to_cpu(perf->lifetime_clean_shutdown_count));
	json_object_add_value_int(root, "Lifetime Unclean Shutdowns on Power Loss",
			le32_to_cpu(perf->lifetime_unclean_shutdown_count));
	json_object_add_value_int(root, "Current Temperature",
			le32_to_cpu(perf->current_temp));
	json_object_add_value_int(root, "Max Recorded Temperature",
			le32_to_cpu(perf->max_recorded_temp));
	json_object_add_value_int(root, "Lifetime Retired Block Count",
			le32_to_cpu(perf->lifetime_retired_block_count));
	json_object_add_value_int(root, "Lifetime Read Disturb Reallocation Events",
			le32_to_cpu(perf->lifetime_read_disturb_realloc_events));
	json_object_add_value_int(root, "Lifetime NAND Writes",
			le64_to_cpu(perf->lifetime_nand_writes));
	json_object_add_value_int(root, "Capacitor Health",
			le32_to_cpu(perf->capacitor_health));
	json_object_add_value_int(root, "Lifetime User Writes",
			le64_to_cpu(perf->lifetime_user_writes));
	json_object_add_value_int(root, "Lifetime User Reads",
			le64_to_cpu(perf->lifetime_user_reads));
	json_object_add_value_int(root, "Lifetime Thermal Throttle Activations",
			le32_to_cpu(perf->lifetime_thermal_throttle_act));
	json_object_add_value_int(root, "Percentage of P/E Cycles Remaining",
			le32_to_cpu(perf->percentage_pe_cycles_remaining));

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

static int wdc_print_d0_log(struct wdc_ssd_d0_smart_log *perf, int fmt)
{
	if (!perf) {
		fprintf(stderr, "ERROR : WDC : Invalid buffer to read perf stats\n");
		return -1;
	}
	switch (fmt) {
	case NORMAL:
		wdc_print_d0_log_normal(perf);
		break;
	case JSON:
		wdc_print_d0_log_json(perf);
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

	if (!wdc_check_device(fd))
		return -1;
	fmt = validate_output_format(format);
	if (fmt < 0) {
		fprintf(stderr, "ERROR : WDC : invalid output format\n");
		return fmt;
	}

	/* verify the 0xCA log page is supported */
	if (wdc_nvme_check_supported_log_page(fd, WDC_NVME_GET_DEVICE_INFO_LOG_OPCODE) == false) {
		fprintf(stderr, "ERROR : WDC : 0xCA Log Page not supported\n");
		return -1;
	}

	if ((data = (__u8*) malloc(sizeof (__u8) * WDC_CA_LOG_BUF_LEN)) == NULL) {
		fprintf(stderr, "ERROR : WDC : malloc : %s\n", strerror(errno));
		return -1;
	}
	memset(data, 0, sizeof (__u8) * WDC_CA_LOG_BUF_LEN);

	ret = nvme_get_log(fd, 0xFFFFFFFF, WDC_NVME_GET_DEVICE_INFO_LOG_OPCODE,
			   false, WDC_CA_LOG_BUF_LEN, data);
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

	if (!wdc_check_device(fd))
		return -1;
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

	ret = nvme_get_log(fd, 0x01, WDC_NVME_ADD_LOG_OPCODE, false,
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
			skip_cnt = le16_to_cpu(sph->subpage_length) + 4;
		}
		if (ret) {
			fprintf(stderr, "ERROR : WDC : Unable to read data from buffer\n");
		}
	}
	free(data);
	return ret;
}

static int wdc_get_d0_log_page(int fd, char *format)
{
	int ret = 0;
	int fmt = -1;
	__u8 *data;
	struct wdc_ssd_d0_smart_log *perf;

	if (!wdc_check_device(fd))
		return -1;
	fmt = validate_output_format(format);
	if (fmt < 0) {
		fprintf(stderr, "ERROR : WDC : invalid output format\n");
		return fmt;
	}

	/* verify the 0xD0 log page is supported */
	if (wdc_nvme_check_supported_log_page(fd, WDC_NVME_GET_VU_SMART_LOG_OPCODE) == false) {
		fprintf(stderr, "ERROR : WDC : 0xD0 Log Page not supported\n");
		return -1;
	}

	if ((data = (__u8*) malloc(sizeof (__u8) * WDC_NVME_VU_SMART_LOG_LEN)) == NULL) {
		fprintf(stderr, "ERROR : WDC : malloc : %s\n", strerror(errno));
		return -1;
	}
	memset(data, 0, sizeof (__u8) * WDC_NVME_VU_SMART_LOG_LEN);

	ret = nvme_get_log(fd, 0xFFFFFFFF, WDC_NVME_GET_VU_SMART_LOG_OPCODE,
			   false, WDC_NVME_VU_SMART_LOG_LEN, data);
	if (strcmp(format, "json"))
		fprintf(stderr, "NVMe Status:%s(%x)\n", nvme_status_to_string(ret), ret);

	if (ret == 0) {
		/* parse the data */
		perf = (struct wdc_ssd_d0_smart_log *)(data);
		ret = wdc_print_d0_log(perf, fmt);
	} else {
		fprintf(stderr, "ERROR : WDC : Unable to read D0 Log Page data\n");
		ret = -1;
	}

	free(data);
	return ret;
}

static int wdc_vs_smart_add_log(int argc, char **argv, struct command *command,
		struct plugin *plugin)
{
	const char *desc = "Retrieve additional performance statistics.";
	const char *interval = "Interval to read the statistics from [1, 15].";
	int fd;
	int ret = 0;
	__u64 capabilities = 0;

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
		{ NULL, '\0', NULL, CFG_NONE, NULL, no_argument, desc },
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, NULL, 0);
	if (fd < 0)
		return fd;

	capabilities = wdc_get_drive_capabilities(fd);

	if ((capabilities & WDC_DRIVE_CAP_SMART_LOG_MASK) == 0) {
		fprintf(stderr, "ERROR : WDC: unsupported device for this command\n");
		ret = -1;
		goto out;
	}

	if ((capabilities & (WDC_DRIVE_CAP_CA_LOG_PAGE)) == (WDC_DRIVE_CAP_CA_LOG_PAGE)) {
		// Get the CA Log Page
		ret = wdc_get_ca_log_page(fd, cfg.output_format);
		if (ret)
			fprintf(stderr, "ERROR : WDC : Failure reading the CA Log Page, ret = %d\n", ret);
	}
	if ((capabilities & WDC_DRIVE_CAP_C1_LOG_PAGE) == WDC_DRIVE_CAP_C1_LOG_PAGE) {
		// Get the C1 Log Page
		ret = wdc_get_c1_log_page(fd, cfg.output_format, cfg.interval);
		if (ret)
			fprintf(stderr, "ERROR : WDC : Failure reading the C1 Log Page, ret = %d\n", ret);
	}
	if ((capabilities & WDC_DRIVE_CAP_D0_LOG_PAGE) == WDC_DRIVE_CAP_D0_LOG_PAGE) {
		// Get the D0 Log Page
		ret = wdc_get_d0_log_page(fd, cfg.output_format);
		if (ret)
			fprintf(stderr, "ERROR : WDC : Failure reading the D0 Log Page, ret = %d\n", ret);
	}
out:
	return ret;
}

static int wdc_clear_pcie_correctable_errors(int argc, char **argv, struct command *command,
		struct plugin *plugin)
{
	char *desc = "Clear PCIE Correctable Errors.";
	int fd;
	int ret;
	__u64 capabilities = 0;
	struct nvme_passthru_cmd admin_cmd;
	const struct argconfig_commandline_options command_line_options[] = {
		{ NULL, '\0', NULL, CFG_NONE, NULL, no_argument, desc },
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, NULL, 0);
	if (fd < 0)
		return fd;

	if (!wdc_check_device(fd)) {
		ret = -1;
		goto out;
	}

	capabilities = wdc_get_drive_capabilities(fd);
	if ((capabilities & WDC_DRIVE_CAP_CLEAR_PCIE) == 0) {
		fprintf(stderr, "ERROR : WDC: unsupported device for this command\n");
		ret = -1;
		goto out;
	}

	memset(&admin_cmd, 0, sizeof (admin_cmd));
	admin_cmd.opcode = WDC_NVME_CLEAR_PCIE_CORR_OPCODE;
	admin_cmd.cdw12 = ((WDC_NVME_CLEAR_PCIE_CORR_SUBCMD << WDC_NVME_SUBCMD_SHIFT) |
			WDC_NVME_CLEAR_PCIE_CORR_CMD);

	ret = nvme_submit_passthru(fd, NVME_IOCTL_ADMIN_CMD, &admin_cmd);
	fprintf(stderr, "NVMe Status:%s(%x)\n", nvme_status_to_string(ret), ret);
out:
	return ret;
}
static int wdc_drive_status(int argc, char **argv, struct command *command,
		struct plugin *plugin)
{
	char *desc = "Get Drive Status.";
	int fd;
	int ret = -1;
	__le32 system_eol_state;
	__le32 user_eol_state;
	__le32 format_corrupt_reason = cpu_to_le32(0xFFFFFFFF);
	__le32 eol_status;
	__le32 assert_status = cpu_to_le32(0xFFFFFFFF);
	__le32 thermal_status = cpu_to_le32(0xFFFFFFFF);
	__u64 capabilities = 0;

	const struct argconfig_commandline_options command_line_options[] = {
		{ NULL, '\0', NULL, CFG_NONE, NULL, no_argument, desc },
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, NULL, 0);
	if (fd < 0)
		return fd;

	capabilities = wdc_get_drive_capabilities(fd);
	if ((capabilities & WDC_DRIVE_CAP_DRIVE_STATUS) != WDC_DRIVE_CAP_DRIVE_STATUS) {
		fprintf(stderr, "ERROR : WDC: unsupported device for this command\n");
		ret = -1;
		goto out;
	}

	/* verify the 0xC2 Device Manageability log page is supported */
	if (wdc_nvme_check_supported_log_page(fd, WDC_NVME_GET_DEV_MGMNT_LOG_PAGE_OPCODE) == false) {
		fprintf(stderr, "ERROR : WDC : 0xC2 Log Page not supported\n");
		ret = -1;
		goto out;
	}

	/* Get the assert dump present status */
	if (!wdc_nvme_get_dev_status_log_data(fd, &assert_status,
			WDC_C2_ASSERT_DUMP_PRESENT_ID))
		fprintf(stderr, "ERROR : WDC : Get Assert Status Failed\n");

	/* Get the thermal throttling status */
	if (!wdc_nvme_get_dev_status_log_data(fd, &thermal_status,
			WDC_C2_THERMAL_THROTTLE_STATUS_ID))
		fprintf(stderr, "ERROR : WDC : Get Thermal Throttling Status Failed\n");

	/* Get EOL status */
	if (!wdc_nvme_get_dev_status_log_data(fd, &eol_status,
			WDC_C2_USER_EOL_STATUS_ID)) {
		fprintf(stderr, "ERROR : WDC : Get User EOL Status Failed\n");
		eol_status = cpu_to_le32(-1);
	}

	/* Get Customer EOL state */
	if (!wdc_nvme_get_dev_status_log_data(fd, &user_eol_state,
			WDC_C2_USER_EOL_STATE_ID))
		fprintf(stderr, "ERROR : WDC : Get User EOL State Failed\n");

	/* Get System EOL state*/
	if (!wdc_nvme_get_dev_status_log_data(fd, &system_eol_state,
			WDC_C2_SYSTEM_EOL_STATE_ID))
		fprintf(stderr, "ERROR : WDC : Get System EOL State Failed\n");

	/* Get format corrupt reason*/
	if (!wdc_nvme_get_dev_status_log_data(fd, &format_corrupt_reason,
			WDC_C2_FORMAT_CORRUPT_REASON_ID))
		fprintf(stderr, "ERROR : WDC : Get Format Corrupt Reason Failed\n");

	printf("  Drive Status :- \n");
	if (le32_to_cpu(eol_status) >= 0) {
		printf("  Percent Used:				%"PRIu32"%%\n",
				le32_to_cpu(eol_status));
	}
	else
		printf("  Percent Used:				Unknown\n");
	if (system_eol_state == WDC_EOL_STATUS_NORMAL && user_eol_state == WDC_EOL_STATUS_NORMAL)
		printf("  Drive Life Status:			Normal\n");
	else if (system_eol_state == WDC_EOL_STATUS_END_OF_LIFE || user_eol_state == WDC_EOL_STATUS_END_OF_LIFE)
		printf("  Drive Life Status:	  		End Of Life\n");
	else if (system_eol_state == WDC_EOL_STATUS_READ_ONLY || user_eol_state == WDC_EOL_STATUS_READ_ONLY)
		printf("  Drive Life Status:	  		Read Only\n");
	else
		printf("  Drive Life Status:			Unknown : 0x%08x/0x%08x\n",
				le32_to_cpu(user_eol_state), le32_to_cpu(system_eol_state));

	if (assert_status == WDC_ASSERT_DUMP_PRESENT)
		printf("  Assert Dump Status:			Present\n");
	else if (assert_status == WDC_ASSERT_DUMP_NOT_PRESENT)
		printf("  Assert Dump Status:			Not Present\n");
	else
		printf("  Assert Dump Status:			Unknown : 0x%08x\n", le32_to_cpu(assert_status));

	if (thermal_status == WDC_THERMAL_THROTTLING_OFF)
		printf("  Thermal Throttling Status:		Off\n");
	else if (thermal_status == WDC_THERMAL_THROTTLING_ON)
		printf("  Thermal Throttling Status:		On\n");
	else if (thermal_status == WDC_THERMAL_THROTTLING_UNAVAILABLE)
		printf("  Thermal Throttling Status:		Unavailable\n");
	else
		printf("  Thermal Throttling Status:		Unknown : 0x%08x\n", le32_to_cpu(thermal_status));

	if (format_corrupt_reason == WDC_FORMAT_NOT_CORRUPT)
		printf("  Format Corrupt Reason:		Format Not Corrupted\n");
	else if (format_corrupt_reason == WDC_FORMAT_CORRUPT_FW_ASSERT)
		printf("  Format Corrupt Reason:	        Format Corrupt due to FW Assert\n");
	else if (format_corrupt_reason == WDC_FORMAT_CORRUPT_UNKNOWN)
		printf("  Format Corrupt Reason:	        Format Corrupt for Unknown Reason\n");
	else
		printf("  Format Corrupt Reason:	        Unknown : 0x%08x\n", le32_to_cpu(format_corrupt_reason));

out:
	return ret;
}

static int wdc_clear_assert_dump(int argc, char **argv, struct command *command,
		struct plugin *plugin)
{
	char *desc = "Clear Assert Dump Present Status.";
	int fd;
	int ret = -1;
	__le32 assert_status = cpu_to_le32(0xFFFFFFFF);
	struct nvme_passthru_cmd admin_cmd;
	const struct argconfig_commandline_options command_line_options[] = {
		{ NULL, '\0', NULL, CFG_NONE, NULL, no_argument, desc },
	};
	__u64 capabilities = 0;

	fd = parse_and_open(argc, argv, desc, command_line_options, NULL, 0);
	if (fd < 0)
		return fd;

	capabilities = wdc_get_drive_capabilities(fd);
	if ((capabilities & WDC_DRIVE_CAP_CLEAR_ASSERT) != WDC_DRIVE_CAP_CLEAR_ASSERT) {
		fprintf(stderr, "ERROR : WDC: unsupported device for this command\n");
		ret = -1;
		goto out;
	}
	if (!wdc_nvme_get_dev_status_log_data(fd, &assert_status,
			WDC_C2_ASSERT_DUMP_PRESENT_ID)) {
		fprintf(stderr, "ERROR : WDC : Get Assert Status Failed\n");
		ret = -1;
		goto out;
	}

	/* Get the assert dump present status */
	if (assert_status == WDC_ASSERT_DUMP_PRESENT) {
		memset(&admin_cmd, 0, sizeof (admin_cmd));
		admin_cmd.opcode = WDC_NVME_CLEAR_ASSERT_DUMP_OPCODE;
		admin_cmd.cdw12 = ((WDC_NVME_CLEAR_ASSERT_DUMP_SUBCMD << WDC_NVME_SUBCMD_SHIFT) |
				WDC_NVME_CLEAR_ASSERT_DUMP_CMD);

		ret = nvme_submit_passthru(fd, NVME_IOCTL_ADMIN_CMD, &admin_cmd);
		fprintf(stderr, "NVMe Status:%s(%x)\n", nvme_status_to_string(ret), ret);
	} else
		fprintf(stderr, "INFO : WDC : No Assert Dump Present\n");

out:
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

static int wdc_de_VU_read_size(int fd, __u32 fileId, __u16 spiDestn, __u32* logSize)
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

static int wdc_de_VU_read_buffer(int fd, __u32 fileId, __u16 spiDestn, __u32 offsetInDwords, __u8* dataBuffer, __u32* bufferSize)
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

static int wdc_get_log_dir_max_entries(int fd, __u32* maxNumOfEntries)
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

static WDC_DRIVE_ESSENTIAL_TYPE wdc_get_essential_type(__u8 fileName[])
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

static int wdc_fetch_log_directory(int fd, PWDC_DE_VU_LOG_DIRECTORY directory)
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

static int wdc_fetch_log_file_from_device(int fd, __u32 fileId, __u16 spiDestn, __u64 fileSize, __u8* dataBuffer)
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
	if ((fileSize >= maximumTransferLength) || (fileSize > 0xFFFFFFFF))
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

static int wdc_de_get_dump_trace(int fd, char * filePath, __u16 binFileNameLen, char *binFileName)
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
				   false, dataBufferSize, dataBuffer);
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
						if (deEssentialsList.logEntry[listIdx].metaData.fileSize > 0xFFFFFFFF)
						{
							wdc_WriteToFile(fileName, dataBuffer, 0xFFFFFFFF);
							wdc_WriteToFile(fileName, dataBuffer + 0xFFFFFFFF, (__u32)(deEssentialsList.logEntry[listIdx].metaData.fileSize - 0xFFFFFFFF));
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
	};
	__u64 capabilities = 0;

	fd = parse_and_open(argc, argv, desc, command_line_options, NULL, 0);
	if (fd < 0)
		return fd;

	capabilities = wdc_get_drive_capabilities(fd);
	if ((capabilities & WDC_DRIVE_CAP_DRIVE_ESSENTIALS) != WDC_DRIVE_CAP_DRIVE_ESSENTIALS) {
		fprintf(stderr, "ERROR : WDC: unsupported device for this command\n");
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

static int wdc_do_drive_resize(int fd, uint64_t new_size)
{
	int ret;
	struct nvme_admin_cmd admin_cmd;

	memset(&admin_cmd, 0, sizeof (struct nvme_admin_cmd));
	admin_cmd.opcode = WDC_NVME_DRIVE_RESIZE_OPCODE;
	admin_cmd.cdw12 = ((WDC_NVME_DRIVE_RESIZE_SUBCMD << WDC_NVME_SUBCMD_SHIFT) |
			    WDC_NVME_DRIVE_RESIZE_CMD);
	admin_cmd.cdw13 = new_size;

	ret = nvme_submit_passthru(fd, NVME_IOCTL_ADMIN_CMD, &admin_cmd);
	return ret;
}

static int wdc_drive_resize(int argc, char **argv,
		struct command *command, struct plugin *plugin)
{
	const char *desc = "Send a Resize command.";
	const char *size = "The new size (in GB) to resize the drive to.";
	int fd;
	int ret;
	uint64_t capabilities = 0;

	struct config {
		uint64_t size;
	};

	struct config cfg = {
		.size = 0,
	};
	const struct argconfig_commandline_options command_line_options[] = {
		{"size", 's', "NUM", CFG_POSITIVE, &cfg.size, required_argument, size},
		{ NULL, '\0', NULL, CFG_NONE, NULL, no_argument, desc },
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, NULL, 0);
	if (fd < 0)
		return fd;

	wdc_check_device(fd);
	capabilities = wdc_get_drive_capabilities(fd);
	if ((capabilities & WDC_DRIVE_CAP_RESIZE) == WDC_DRIVE_CAP_RESIZE) {
		ret = wdc_do_drive_resize(fd, cfg.size);
	} else {
		fprintf(stderr, "ERROR : WDC: unsupported device for this command\n");
		ret = -1;
	}
	if (!ret)
		printf("New size: %lu GB\n", cfg.size);
	fprintf(stderr, "NVMe Status:%s(%x)\n", nvme_status_to_string(ret), ret);
	return ret;
}


static void wdc_print_nand_stats_normal(struct wdc_nand_stats *data)
{
	printf("  NAND Statistics :- \n");
	printf("  NAND Writes TLC (Bytes)		         %.0Lf\n",
			int128_to_double(data->nand_write_tlc));
	printf("  NAND Writes SLC (Bytes)		         %.0Lf\n",
			int128_to_double(data->nand_write_slc));
	printf("  NAND Program Failures			  	 %"PRIu32"\n",
			(uint32_t)le32_to_cpu(data->nand_prog_failure));
	printf("  NAND Erase Failures				 %"PRIu32"\n",
			(uint32_t)le32_to_cpu(data->nand_erase_failure));
	printf("  Bad Block Count			         %"PRIu32"\n",
			(uint32_t)le32_to_cpu(data->bad_block_count));
	printf("  NAND XOR/RAID Recovery Trigger Events		 %"PRIu64"\n",
			le64_to_cpu(data->nand_rec_trigger_event));
}

static void wdc_print_nand_stats_json(struct wdc_nand_stats *data)
{
	struct json_object *root;

	root = json_create_object();
	json_object_add_value_float(root, "NAND Writes TLC (Bytes)",
			int128_to_double(data->nand_write_tlc));
	json_object_add_value_float(root, "NAND Writes SLC (Bytes)",
			int128_to_double(data->nand_write_slc));
	json_object_add_value_uint(root, "NAND Program Failures",
			le32_to_cpu(data->nand_prog_failure));
	json_object_add_value_uint(root, "NAND Erase Failures",
			le32_to_cpu(data->nand_erase_failure));
	json_object_add_value_uint(root, "Bad Block Count",
			le32_to_cpu(data->bad_block_count));
	json_object_add_value_uint(root, "NAND XOR/RAID Recovery Trigger Events",
			le64_to_cpu(data->nand_rec_trigger_event));

	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static int wdc_do_vs_nand_stats(int fd, char *format)
{
	int ret;
	int fmt = -1;
	uint8_t *output = NULL;
	struct wdc_nand_stats *nand_stats;

	if ((output = (uint8_t*)calloc(WDC_NVME_NAND_STATS_SIZE, sizeof(uint8_t))) == NULL) {
		fprintf(stderr, "ERROR : WDC : calloc : %s\n", strerror(errno));
		ret = -1;
		goto out;
	}

	ret = nvme_get_log(fd, 0xFFFFFFFF, WDC_NVME_NAND_STATS_LOG_ID,
			   false, WDC_NVME_NAND_STATS_SIZE, (void*)output);
	if (ret) {
		fprintf(stderr, "ERROR : WDC : %s : Failed to retreive NAND stats\n", __func__);
		goto out;
	} else {
		fmt = validate_output_format(format);
		if (fmt < 0) {
			fprintf(stderr, "ERROR : WDC : invalid output format\n");
			ret = fmt;
			goto out;
		}

		/* parse the data */
		nand_stats = (struct wdc_nand_stats *)(output);
		switch (fmt) {
		case NORMAL:
			wdc_print_nand_stats_normal(nand_stats);
			break;
		case JSON:
			wdc_print_nand_stats_json(nand_stats);
			break;
		}
	}

out:
	free(output);
	return ret;
}

static int wdc_vs_nand_stats(int argc, char **argv, struct command *command,
		struct plugin *plugin)
{
	const char *desc = "Retrieve NAND statistics.";
	int fd;
	int ret = 0;
	__u64 capabilities = 0;

	struct config {
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"output-format", 'o', "FMT", CFG_STRING, &cfg.output_format, required_argument, "Output Format: normal|json" },
		{ NULL, '\0', NULL, CFG_NONE, NULL, no_argument, desc },
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, NULL, 0);
	if (fd < 0)
		return fd;

	capabilities = wdc_get_drive_capabilities(fd);

	if ((capabilities & WDC_DRIVE_CAP_NAND_STATS) == 0) {
		fprintf(stderr, "ERROR : WDC: unsupported device for this command\n");
		ret = -1;
	} else {
		ret = wdc_do_vs_nand_stats(fd, cfg.output_format);
		if (ret)
			fprintf(stderr, "ERROR : WDC : Failure reading NAND statistics, ret = %d\n", ret);
	}

	return ret;
}
