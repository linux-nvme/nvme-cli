/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (c) 2024 Western Digital Corporation or its affiliates.
 *
 * Authors: Jeff Lien <jeff.lien@wdc.com>,
 */

/*****************************************************************************
 * Telemetry Statistics ID's and Strings
 *****************************************************************************/
enum TELEMETRY_STATISTIC_ID {
	TELEMETRY_STAT_ID_OAC		= 0x1,  /* Outstanding Admin Commands */
	TELEMETRY_STAT_ID_HWB		= 0x2,  /* Host Write Bandwidth       */
	TELEMETRY_STAT_ID_GCWB		= 0x3,  /* Garbage Collection Write Bandwidth */
	TELEMETRY_STAT_ID_AN		= 0x4,  /* Active Namespaces  */
	TELEMETRY_STAT_ID_IWW		= 0x5,  /* Internal Write Workload  */
	TELEMETRY_STAT_ID_IRW		= 0x6,  /* Internal Read Workload  */
	TELEMETRY_STAT_ID_IWQD		= 0x7,  /* Internal Write Queue Depth  */
	TELEMETRY_STAT_ID_IRQD		= 0x8,  /* Internal Read Queue Depth  */
	TELEMETRY_STAT_ID_PTC		= 0x9,  /* Pending Trim LBA Count  */
	TELEMETRY_STAT_ID_HTRC		= 0xA,  /* Host Trim LBA Request Count  */
	TELEMETRY_STAT_ID_CNPS		= 0xB,  /* Current NVMe Power State  */
	TELEMETRY_STAT_ID_CDPS		= 0xC,  /* Current DSSD Power State  */
	TELEMETRY_STAT_ID_PFC		= 0xD,  /* Program Fail Count  */
	TELEMETRY_STAT_ID_EFC		= 0xE,  /* Erase Fail Count  */
	TELEMETRY_STAT_ID_RDW		= 0xF,  /* Read Disturb Write  */
	TELEMETRY_STAT_ID_RW		= 0x10, /* Retention Writes  */
	TELEMETRY_STAT_ID_WLW		= 0x11, /* Wear Leveling Writes  */
	TELEMETRY_STAT_ID_RRW		= 0x12, /* Read Recovery Writes  */
	TELEMETRY_STAT_ID_GCW		= 0x13, /* Garbage Collection Writes  */
	TELEMETRY_STAT_ID_SCC		= 0x14, /* SRAM Correctable Count  */
	TELEMETRY_STAT_ID_DCC		= 0x15, /* DRAM Uncorrectable Count  */
	TELEMETRY_STAT_ID_SUC		= 0x16, /* SRAM Correctable Count  */
	TELEMETRY_STAT_ID_DUC		= 0x17, /* DRAM Uncorrectable Count  */
	TELEMETRY_STAT_ID_DIEC		= 0x18, /* Data Integrity Error Count  */
	TELEMETRY_STAT_ID_RREC		= 0x19, /* Read Retry Error Count  */
	TELEMETRY_STAT_ID_PEC		= 0x1A, /* PERST Events Count  */
	TELEMETRY_STAT_ID_MAXDBB	= 0x1B, /* Max Die Bad Block  */
	TELEMETRY_STAT_ID_MAXCBB	= 0x1C, /* Max NAND Channel Bad Block  */
	TELEMETRY_STAT_ID_MINCBB	= 0x1D, /* Min NAND Channel Bad Block  */
};

static const char * const telemetry_stat_id_str[] = {
	[TELEMETRY_STAT_ID_OAC]		= "Outstanding Admin Commands",
	[TELEMETRY_STAT_ID_HWB]		= "Host Write Bandwidth",
	[TELEMETRY_STAT_ID_GCWB]	= "Garbage Collection Write Bandwidth",
	[TELEMETRY_STAT_ID_AN]		= "Active Namespaces",
	[TELEMETRY_STAT_ID_IWW]		= "Internal Write Workload",
	[TELEMETRY_STAT_ID_IRW]		= "Internal Read Workload",
	[TELEMETRY_STAT_ID_IWQD]	= "Internal Write Queue Depth",
	[TELEMETRY_STAT_ID_IRQD]	= "Internal Read Queue Depth",
	[TELEMETRY_STAT_ID_PTC]		= "Pending Trim LBA Count",
	[TELEMETRY_STAT_ID_HTRC]	= "Host Trim LBA Request Count",
	[TELEMETRY_STAT_ID_CNPS]	= "Current NVMe Power State",
	[TELEMETRY_STAT_ID_CDPS]	= "Current DSSD Power State",
	[TELEMETRY_STAT_ID_PFC]		= "Program Fail Count",
	[TELEMETRY_STAT_ID_EFC]		= "Erase Fail Count",
	[TELEMETRY_STAT_ID_RDW]		= "Read Disturb Write",
	[TELEMETRY_STAT_ID_RW]		= "Retention Writes",
	[TELEMETRY_STAT_ID_WLW]		= "Wear Leveling Writes",
	[TELEMETRY_STAT_ID_RRW]		= "Read Recovery Writes",
	[TELEMETRY_STAT_ID_GCW]		= "Garbage Collection Writes",
	[TELEMETRY_STAT_ID_SCC]		= "SRAM Correctable Count",
	[TELEMETRY_STAT_ID_DCC]		= "DRAM Correctable Count",
	[TELEMETRY_STAT_ID_SUC]		= "SRAM Uncorrectable Count",
	[TELEMETRY_STAT_ID_DUC]		= "DRAM Uncorrectable Count",
	[TELEMETRY_STAT_ID_DIEC]	= "Data Integrity Error Count",
	[TELEMETRY_STAT_ID_RREC]	= "Read Retry Error Count",
	[TELEMETRY_STAT_ID_PEC]		= "PERST Events Count",
	[TELEMETRY_STAT_ID_MAXDBB]	= "Max Die Bad Block",
	[TELEMETRY_STAT_ID_MAXCBB]	= "Max NAND Channel Bad Block",
	[TELEMETRY_STAT_ID_MINCBB]	= "Min NAND Channel Bad Block",
};

/*****************************************************************************
 * Telemetry FIFO Event Class ID's and Strings
 *****************************************************************************/
enum TELEMETRY_EVENT_CLASS_TYPE {
	TELEMETRY_TIMESTAMP_CLASS      = 0x1,
	TELEMETRY_PCIE_CLASS           = 0x2,
	TELEMETRY_NVME_CLASS           = 0x3,
	TELEMETRY_RESET_CLASS          = 0x4,
	TELEMETRY_BOOT_SEQ_CLASS       = 0x5,
	TELEMETRY_FW_ASSERT_CLASS      = 0x6,
	TELEMETRY_TEMPERATURE_CLASS    = 0x7,
	TELEMETRY_MEDIA_DBG_CLASS      = 0x8,
	TELEMETRY_MEDIA_WEAR_CLASS     = 0x9,
	TELEMETRY_STAT_SNAPSHOT_CLASS  = 0xA,
};

static const char * const telemetry_event_class_str[] = {
	[TELEMETRY_TIMESTAMP_CLASS]		= "Timestamp Class",
	[TELEMETRY_PCIE_CLASS]			= "PCIe Class",
	[TELEMETRY_NVME_CLASS]			= "NVMe Class",
	[TELEMETRY_RESET_CLASS]			= "Reset Class",
	[TELEMETRY_BOOT_SEQ_CLASS]		= "Boot Sequence Class",
	[TELEMETRY_FW_ASSERT_CLASS]		= "FW Assert Class",
	[TELEMETRY_TEMPERATURE_CLASS]	= "Temperature Class",
	[TELEMETRY_MEDIA_DBG_CLASS]		= "Media Debug Class",
	[TELEMETRY_MEDIA_WEAR_CLASS]	= "Media Wear Class",
	[TELEMETRY_STAT_SNAPSHOT_CLASS]	= "Statistic Snapshot Class",
};

/*****************************************************************************
 * Telemetry Timestamp Class (01h) Event ID's and Strings
 *****************************************************************************/
enum TELEMETRY_TIMESTAMP_EVENT_ID {
	TIMESTAMP_HOST_CMD_ISSUED      = 0x0000,
	TIMESTAMP_SNAPSHOT             = 0x0001,
	TIMESTAMP_POWER_ON_HOURS       = 0x0002,
};

static const char * const telemetry_timestamp_event_id_str[] = {
	[TIMESTAMP_HOST_CMD_ISSUED]		= "Timestamp Host Cmd Issued",
	[TIMESTAMP_SNAPSHOT]			= "Timestamp Snapshot",
	[TIMESTAMP_POWER_ON_HOURS]		= "Timestamp Power on Hours",
};

/*****************************************************************************
 * Telemetry PCIE Class (02h) Event ID's and Strings
 *****************************************************************************/
enum TELEMETRY_PCIE_EVENT_ID {
	PCIE_LINK_UP                   = 0x0000,
	PCIE_LINK_DOWN                 = 0x0001,
	PCIE_ERROR_DETECTED            = 0x0002,
	PCIE_PERST_ASSERTED            = 0x0003,
	PCIE_PERST_DEASSERTED          = 0x0004,
	PCIE_REFCLK_STABLE             = 0x0005,
	PCIE_VMAIN_STABLE              = 0x0006,
	PCIE_LINK_NEGOTIATED           = 0x0007,
};

static const char * const telemetry_pcie_event_id_str[] = {
	[PCIE_LINK_UP]				= "PCIe Link Up",
	[PCIE_LINK_DOWN]			= "PCIe Link Down",
	[PCIE_ERROR_DETECTED]		= "PCIe Error Detected",
	[PCIE_PERST_ASSERTED]		= "PCIe PERST Asserted",
	[PCIE_PERST_DEASSERTED]		= "PCIe PERST Deasserted",
	[PCIE_REFCLK_STABLE]		= "PCIe Refclk Stable",
	[PCIE_VMAIN_STABLE]			= "PCIe Vmain Stable",
	[PCIE_LINK_NEGOTIATED]		= "PCIe Link Negotiated",
};

enum TELEMETRY_PCIE_STATE_DATA {
	PCIE_STATE_UNCHANGED           = 0x00,
	PCIE_SPEED_CHANGED             = 0x01,
	PCIE_WIDTH_CHANGED             = 0x02,
};

static const char * const telemetry_pcie_state_data_str[] = {
	[PCIE_STATE_UNCHANGED]	= "PCIe State Unchained",
	[PCIE_SPEED_CHANGED]	= "PCIe Speed Changed",
	[PCIE_WIDTH_CHANGED]	= "PCIe Width Changed",
};

enum TELEMETRY_PCIE_SPEED_DATA {
	PCIE_LINK_GEN1			= 0x01,
	PCIE_LINK_GEN2			= 0x02,
	PCIE_LINK_GEN3			= 0x03,
	PCIE_LINK_GEN4			= 0x04,
	PCIE_LINK_GEN5			= 0x05,
	PCIE_LINK_GEN6			= 0x06,
	PCIE_LINK_GEN7			= 0x07,
};

static const char * const telemetry_pcie_speed_data_str[] = {
	[PCIE_LINK_GEN1]		= "PCIe Link Speed Gen1",
	[PCIE_LINK_GEN2]		= "PCIe Link Speed Gen2",
	[PCIE_LINK_GEN3]		= "PCIe Link Speed Gen3",
	[PCIE_LINK_GEN4]		= "PCIe Link Speed Gen4",
	[PCIE_LINK_GEN5]		= "PCIe Link Speed Gen5",
	[PCIE_LINK_GEN6]		= "PCIe Link Speed Gen6",
	[PCIE_LINK_GEN7]		= "PCIe Link Speed Gen7",
};

enum TELEMETRY_PCIE_WIDTH_DATA {
	PCIE_LINK_X1			= 0x01,
	PCIE_LINK_X2			= 0x02,
	PCIE_LINK_X4			= 0x03,
	PCIE_LINK_X8			= 0x04,
	PCIE_LINK_X16			= 0x05,
};

static const char * const telemetry_pcie_width_data_str[] = {
	[PCIE_LINK_X1]			= "PCIe Link Width x1",
	[PCIE_LINK_X2]			= "PCIe Link Width x2",
	[PCIE_LINK_X4]			= "PCIe Link Width x4",
	[PCIE_LINK_X8]			= "PCIe Link Width x8",
	[PCIE_LINK_X16]			= "PCIe Link Width x16",
};

/*****************************************************************************
 * Telemetry NVMe Class (03h) Event ID's and Strings
 *****************************************************************************/
enum TELEMETRY_NVME_EVENT_ID {
	CC_EN_0_TO_1					= 0x0000,
	CC_EN_1_TO_0					= 0x0001,
	CSTS_RDY_0_TO_1					= 0x0002,
	CSTS_RDY_1_TO_0					= 0x0003,
	NVME_EVENT_ID_RESERVED			= 0x0004,
	CREATE_IO_QUEUE_PROCESSED		= 0x0005,
	ADMIN_QUEUE_CMD_PROCESSED		= 0x0006,
	ADMIN_QUEUE_NONZERO_STATUS		= 0x0007,
	IO_QUEUE_NONZERO_STATUS			= 0x0008,
	CSTS_CFS_0_TO_1					= 0x0009,
	ADMIN_QUEUE_BASE_WRITTEN		= 0x000A,
	CC_REGISTER_CHANGED				= 0x000B,
	CSTS_REGISTER_CHANGED			= 0x000C,
	DELETE_IO_QUEUE_PROCESSED		= 0x000D,
};

static const char * const telemetry_nvme_event_id_str[] = {
	[CC_EN_0_TO_1]					= "CC.EN Transitions from 0 to 1",
	[CC_EN_1_TO_0]					= "CC.EN Transitions from 1 to 0",
	[CSTS_RDY_0_TO_1]				= "CSTS.RDY Transitions from 0 to 1",
	[CSTS_RDY_1_TO_0]				= "CSTS.RDY Transitions from 1 to 0",
	[NVME_EVENT_ID_RESERVED]		= "Reserved NVMe Event ID",
	[CREATE_IO_QUEUE_PROCESSED]		= "Create IO SQ or CQ Command Processed",
	[ADMIN_QUEUE_CMD_PROCESSED]		= "Other Admin Queue Command Processed",
	[ADMIN_QUEUE_NONZERO_STATUS]	= "Admin Command Returned Non-zero Status",
	[IO_QUEUE_NONZERO_STATUS]		= "IO Command Returned Non-zero Status",
	[CSTS_CFS_0_TO_1]				= "CSTS.CFS Transitions from 0 to 1",
	[ADMIN_QUEUE_BASE_WRITTEN]		= "Admin SQ or CQ Base Address Written",
	[CC_REGISTER_CHANGED]			= "CC Register Changed",
	[CSTS_REGISTER_CHANGED]			= "CTS Register Changed",
	[DELETE_IO_QUEUE_PROCESSED]		= "Delete IO SQ or CQ Command Processed",
};

/*****************************************************************************
 * Telemetry Reset Class (04h) Event ID's and Strings
 *****************************************************************************/
enum TELEMETRY_RESET_EVENT_ID {
	PCIE_CONVENTIONAL_HOT_RESET		= 0x0000,
	MAIN_POWER_CYCLE				= 0x0001,
	PERST							= 0x0002,
	PCIE_FUNCTION_LEVEL_RESET		= 0x0003,
	NVME_SUBSYSTEM_RESET			= 0x0004,
};

static const char * const telemetry_reset_event_id_str[] = {
	[PCIE_CONVENTIONAL_HOT_RESET]	= "PCIE Conventional Hot Reset",
	[MAIN_POWER_CYCLE]				= "Main Power_Cycle",
	[PERST]							= "PERST",
	[PCIE_FUNCTION_LEVEL_RESET]		= "PCIE Function Level Reset",
	[NVME_SUBSYSTEM_RESET]			= "NVMe Subsytem Reset",
};

/*****************************************************************************
 * Telemetry Boot Sequence Class (05h) Event ID's and Strings
 *****************************************************************************/
enum TELEMETRY_BOOT_SEQ_EVENT_ID {
	MAIN_FW_BOOT_COMPLETE			= 0x0000,
	FTL_LOAD_FROM_NVM_COMPLETE		= 0x0001,
	FTL_REBUILD_STARTED				= 0x0002,
	FTL_REBUILD_COMPLETE			= 0x0003,
};

static const char * const telemetry_boot_seq_event_id_str[] = {
	[MAIN_FW_BOOT_COMPLETE]			= "Main Firmware Boot Complete",
	[FTL_LOAD_FROM_NVM_COMPLETE]	= "FTL Load from NVM Complete",
	[FTL_REBUILD_STARTED]			= "FTL Rebuild Started",
	[FTL_REBUILD_COMPLETE]			= "FTL Rebuild Complete",
};

/*****************************************************************************
 * Telemetry Firmware Assert Class (06h) Event ID's and Strings
 *****************************************************************************/
enum TELEMETRY_FW_ASSERT_EVENT_ID {
	ASSERT_NVME_CODE				= 0x0000,
	ASSERT_MEDIA_CODE				= 0x0001,
	ASSERT_SECURITY_CODE			= 0x0002,
	ASSERT_BACKGROUND_CODE			= 0x0003,
	FTL_REBUILD_FAILED				= 0x0004,
	FTL_DATA_MISMATCH				= 0x0005,
	ASSERT_OTHER_CODE				= 0x0006,
};

static const char * const telemetry_fw_assert_event_id_str[] = {
	[ASSERT_NVME_CODE]				= "Assert in NVMe Processing Code",
	[ASSERT_MEDIA_CODE]				= "Assert in Media Code",
	[ASSERT_SECURITY_CODE]			= "Assert in Security Code",
	[ASSERT_BACKGROUND_CODE]		= "Assert in Background Services Code",
	[FTL_REBUILD_FAILED]			= "FTL Rebuild Failed",
	[FTL_DATA_MISMATCH]				= "FTL Data Mismatch",
	[ASSERT_OTHER_CODE]				= "FTL Other Code",
};

/*****************************************************************************
 * Telemetry Temperature Class (07h) Event ID's and Strings
 *****************************************************************************/
enum TELEMETRY_TEMPERATURE_EVENT_ID {
	COMPOSITE_TEMP_DECREASE			= 0x0000,
	COMPOSITE_TEMP_INCREASE_WCTEMP	= 0x0001,
	COMPOSITE_TEMP_INCREASE_CCTEMP	= 0x0002,
};

static const char * const telemetry_temperature_event_id_str[] = {
	[COMPOSITE_TEMP_DECREASE]			= "Composite Temp Decreases to (WCTEMP-2)",
	[COMPOSITE_TEMP_INCREASE_WCTEMP]	= "Composite Temp Increases to WCTEMP",
	[COMPOSITE_TEMP_INCREASE_CCTEMP]	= "Composite Temp Increases to CCTEMP",
};

/*****************************************************************************
 * Telemetry Media Debug Class (08h) Event ID's and Strings
 *****************************************************************************/
enum TELEMETRY_MEDIA_DEBUG_EVENT_ID {
	XOR_RECOVERY_INVOKED			= 0x0000,
	UNCORRECTABLE_MEDIA_ERROR		= 0x0001,
	BAD_BLOCK_PROGRAM_ERROR			= 0x0002,
	BAD_BLOCK_ERASE_ERROR			= 0x0003,
	BAD_BLOCK_READ_ERROR			= 0x0004,
	PLANE_FAILURE_EVENT				= 0x0005,
};

static const char * const telemetry_media_debug_event_id_str[] = {
	[XOR_RECOVERY_INVOKED]			= "XOR Recovery Invoked",
	[UNCORRECTABLE_MEDIA_ERROR]		= "Uncorrectable Media Error",
	[BAD_BLOCK_PROGRAM_ERROR]		= "Block Marked Bad Due to Program Error",
	[BAD_BLOCK_ERASE_ERROR]			= "Block Marked Bad Due to Erase Error",
	[BAD_BLOCK_READ_ERROR]			= "Block Marked Bad Due to Read Error",
	[PLANE_FAILURE_EVENT]			= "Plane Failure Event",
};

/*****************************************************************************
 * Telemetry Media Wear Class (09h) Event ID's and Strings
 *****************************************************************************/
enum TELEMETRY_MEDIA_WEAR_EVENT_ID {
	MEDIA_WEAR						= 0x0000,
};

static const char * const telemetry_media_wear_event_id_str[] = {
	[MEDIA_WEAR]					= "Media Wear",
};


/*****************************************************************************
 * Telemetry Data Structures
 *****************************************************************************/
#define TELEMETRY_HEADER_SIZE 512
#define TELEMETRY_DATA_SIZE 1536
#define TELEMETRY_BYTE_PER_BLOCK 512
#define TELEMETRY_TRANSFER_SIZE 1024
#define FILE_NAME_SIZE 2048

enum TELEMETRY_TYPE {
	TELEMETRY_TYPE_NONE       = 0,
	TELEMETRY_TYPE_HOST       = 7,
	TELEMETRY_TYPE_CONTROLLER = 8,
	TELEMETRY_TYPE_HOST_0     = 9,
	TELEMETRY_TYPE_HOST_1     = 10,
};

struct telemetry_initiated_log {
	__u8  LogIdentifier;
	__u8  Reserved1[4];
	__u8  IEEE[3];
	__le16 DataArea1LastBlock;
	__le16 DataArea2LastBlock;
	__le16 DataArea3LastBlock;
	__u8  Reserved2[2];
	__le32 DataArea4LastBlock;
	__u8  Reserved3[361];
	__u8  DataHostGenerationNumber;
	__u8  CtlrDataAvailable;
	__u8  DataCtlrGenerationNumber;
	__u8  ReasonIdentifier[128];
};

struct telemetry_stats_desc {
	__le16 id;
	__u8 info;
	__u8 ns_info;
	__le16 size;
	__le16 rsvd1;
	__u8 data[];
};

struct telemetry_event_desc {
	__u8 class;
	__le16 id;
	__u8 size;
	__u8 data[];
};

struct event_fifo {
	__le64	start;
	__le64	size;
};

struct telemetry_data_area_1 {
	__le16 major_version;
	__le16 minor_version;
	__u8   reserved1[4];
	__le64 timestamp;
	__u8   log_page_guid[16];
	__u8   no_of_tps_supp;
	__u8   tps;
	__u8   reserved2[6];
	__le64 sls;
	__u8   reserved3[8];
	__u8   fw_revision[8];
	__u8   reserved4[32];
	__le64 da1_stat_start;
	__le64 da1_stat_size;
	__le64 da2_stat_start;
	__le64 da2_stat_size;
	__u8   reserved5[32];
	__u8   event_fifo_da[16];
	struct event_fifo event_fifos[16];
	__u8   reserved6[80];
	__u8   smart_health_info[512];
	__u8   smart_health_info_extended[512];
};


/************************************************************
 * Telemetry Parsing Function Prototypes
 ************************************************************/
void print_vu_event_data(__u32 size, __u8 *data);
void print_stats_desc(struct telemetry_stats_desc *stat_desc);
void print_telemetry_fifo_event(__u8 class_type,
		__u16 id, __u8 size, __u8 *data);


/************************************************************
 * Telemetry ID to String Conversion Functions
 ************************************************************/
static inline const char *arg_str(const char * const *strings,
		size_t array_size, size_t idx)
{
	if (idx < array_size && strings[idx])
		return strings[idx];
	return "unrecognized";
}

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#define ARGSTR(s, i) arg_str(s, ARRAY_SIZE(s), i)

static inline const char *telemetry_stat_id_to_string(int stat_id)
{
	return ARGSTR(telemetry_stat_id_str, stat_id);
}
static inline const char *telemetry_event_class_to_string(int class)
{
	return ARGSTR(telemetry_event_class_str, class);
}
static inline const char *telemetry_ts_event_to_string(int event_id)
{
	return ARGSTR(telemetry_timestamp_event_id_str, event_id);
}
static inline const char *telemetry_pcie_event_id_to_string(int event_id)
{
	return ARGSTR(telemetry_pcie_event_id_str, event_id);
}
static inline const char *telemetry_pcie_state_data_to_string(int pcie_state)
{
	return ARGSTR(telemetry_pcie_state_data_str, pcie_state);
}
static inline const char *telemetry_pcie_speed_data_to_string(int pcie_speed)
{
	return ARGSTR(telemetry_pcie_speed_data_str, pcie_speed);
}
static inline const char *telemetry_pcie_width_data_to_string(int pcie_width)
{
	return ARGSTR(telemetry_pcie_width_data_str, pcie_width);
}
static inline const char *telemetry_nvme_event_id_to_string(int event_id)
{
	return ARGSTR(telemetry_nvme_event_id_str, event_id);
}
static inline const char *telemetry_reset_event_id_to_string(int event_id)
{
	return ARGSTR(telemetry_reset_event_id_str, event_id);
}
static inline const char *telemetry_boot_seq_event_id_to_string(int event_id)
{
	return ARGSTR(telemetry_boot_seq_event_id_str, event_id);
}
static inline const char *telemetry_fw_assert_event_id_to_string(int event_id)
{
	return ARGSTR(telemetry_fw_assert_event_id_str, event_id);
}
static inline const char *telemetry_temperature_event_id_to_string(int event_id)
{
	return ARGSTR(telemetry_temperature_event_id_str, event_id);
}
static inline const char *telemetry_media_debug_event_id_to_string(int event_id)
{
	return ARGSTR(telemetry_media_debug_event_id_str, event_id);
}
static inline const char *telemetry_media_wear_event_id_to_string(int event_id)
{
	return ARGSTR(telemetry_media_wear_event_id_str, event_id);
}
