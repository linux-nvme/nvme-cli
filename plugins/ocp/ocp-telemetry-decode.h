/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (c) 2024 Western Digital Corporation or its affiliates.
 *
 * Authors: Jeff Lien <jeff.lien@wdc.com>,
 */
#pragma once

#include <ccan/array_size/array_size.h>
#include <shared/compiler-attributes-util.h>

#include <libnvme.h>

#include "nvme-print.h"
#include "field-parser.h"

#include "ocp-nvme.h"

extern __u8 *ptelemetry_buffer;
extern __u8 *pstring_buffer;

#define OCP_TELEMETRY_DESCRIPTION_MAX 256

/*****************************************************************************
 * Telemetry SMBUS/I2C/I3C (0Ch) Event ID's and Event Data Strings
 *****************************************************************************/
enum TELEMETRY_SMBUS_EVENT_ID {
	SMBUS_TIMEOUT_ERRORS			= 0x0000,
	SMBUS_PEC_ERRORS			= 0x0001,
	SMBUS_ARBITRATION_LOSS			= 0x0002,
	SMBUS_NACK_ERROR			= 0x0003,
};

static const char * const telemetry_smbus_nack_event_data_str[] = {
	[0x0000]	= "Received invalid command or data",
	[0x0001]	= "Device is busy",
	[0x0002]	= "Requested data is not available",
};

/*****************************************************************************
 * Telemetry MCTP (0Dh) Event ID's, Event Data and Transport Protocol Strings
 *****************************************************************************/
enum TELEMETRY_MCTP_EVENT_ID {
	MCTP_DROPPED_PACKET			= 0x0000,
	MCTP_DROPPED_MESSAGE			= 0x0001,
	MCTP_DISCOVERY_ADDRESSING_ERRORS	= 0x0002,
	MCTP_ERROR_STATUS			= 0x0003,
};

static const char * const telemetry_mctp_dropped_packet_data_str[] = {
	[0x0000]	= "Unexpected middle or end packet",
	[0x0001]	= "Bad packet data integrity or other physical layer error: Framing errors",
	[0x0002]	= "Bad packet data integrity or other physical layer error: Byte alignment errors",
	[0x0003]	= "Bad packet data integrity or other physical layer error: Invalid packet size",
	[0x0004]	= "Unexpected or expired message tag",
	[0x0005]	= "Unknown destination EID",
	[0x0006]	= "Unsupported MCTP header version",
	[0x0007]	= "Unsupported transmission unit size",
};

static const char * const telemetry_mctp_dropped_message_data_str[] = {
	[0x0000]	= "Receipt of a new start packet",
	[0x0001]	= "Timeout waiting for a packet + threshold",
	[0x0002]	= "Out-of-sequence packet sequence number",
	[0x0003]	= "Incorrect transmission unit",
	[0x0004]	= "Bad message integrity check",
	[0x0005]	= "Invalid message type received",
};

static const char * const telemetry_mctp_discovery_data_str[] = {
	[0x0000]	= "Transport Binding specific bus enumeration errors",
	[0x0001]	= "Transport Binding specific bus address assignment errors",
};

static const char * const telemetry_mctp_error_status_data_str[] = {
	[0x0000]	= "Reserved",
	[0x0001]	= "ERROR",
	[0x0002]	= "ERROR_INVALID_DATA",
	[0x0003]	= "ERROR_INVALID_LENGTH",
	[0x0004]	= "ERROR_NOT_READY",
	[0x0005]	= "ERROR_UNSUPPORTED_CMD",
	[0x0006]	= "COMMAND_SPECIFIC",
};

static const char * const telemetry_mctp_transport_protocol_str[] = {
	[0x00]		= "PCIe VDM on device PCIe port 0",
	[0x01]		= "PCIe VDM on device PCIe port 1",
	[0x04]		= "I2C/SMBus",
	[0x05]		= "I3C",
};


/*****************************************************************************
 * Telemetry Data Structures
 *****************************************************************************/
enum TELEMETRY_TYPE {
	TELEMETRY_TYPE_HOST       = 7,
	TELEMETRY_TYPE_CONTROLLER = 8,
};

#define DATA_SIZE_12   12
#define DATA_SIZE_8    8
#define DATA_SIZE_4    4
#define MAX_BUFFER_32_KB              0x8000
#define OCP_TELEMETRY_DATA_BLOCK_SIZE 512
#define SIZE_OF_DWORD                 4
#define MAX_NUM_FIFOS                 16
#define DA1_OFFSET                    512
#define DEFAULT_ASCII_STRING_SIZE     16
#define SIZE_OF_VU_EVENT_ID           2

/* VU Virtual FIFO Identifier: 15:11 physical FIFO, 10:0 virtual FIFO */
#define VU_VIRTUAL_FIFO_PHY_NUM_SHIFT 11
#define VU_VIRTUAL_FIFO_NUM_MASK      0x07ff

/* MCTP Event Flags bit 7: the MCTP Transport Header field is valid */
#define MCTP_EVENT_FLAG_TRANSPORT_HEADER_VALID 0x80

#define DEFAULT_TELEMETRY_LOG "telemetry-log"
#define DEFAULT_STRING_BIN "string.bin"
#ifdef CONFIG_JSONC
#define DEFAULT_OUTPUT_FORMAT "json"
#else /* CONFIG_JSONC */
#define DEFAULT_OUTPUT_FORMAT "normal"
#endif /* CONFIG_JSONC */

/* C9 Telemetry String Log Format Log Page */
#define C9_TELEMETRY_STR_LOG_LEN                 432
#define C9_TELEMETRY_STR_LOG_SIST_OFST           431

#define STR_LOG_PAGE_HEADER "Log Page Header"
#define STR_REASON_IDENTIFIER "Reason Identifier"
#define STR_TELEMETRY_HOST_DATA_BLOCK_1 "Telemetry Host-Initiated Data Block 1"
#define STR_SMART_HEALTH_INFO "SMART / Health Information Log(LID-02h)"
#define STR_SMART_HEALTH_INTO_EXTENDED "SMART / Health Information Extended(LID-C0h)"
#define STR_DA_1_STATS "Data Area 1 Statistics"
#define STR_DA_2_STATS "Data Area 2 Statistics"
#define STR_DA_1_EVENT_FIFO_INFO "Data Area 1 Event FIFO info"
#define STR_DA_2_EVENT_FIFO_INFO "Data Area 2 Event FIFO info"
#define STR_STATISTICS_IDENTIFIER "Statistics Identifier"
#define STR_STATISTICS_IDENTIFIER_STR "Statistic Identifier String"
#define STR_STATISTICS_INFO_BEHAVIOUR_TYPE "Statistics Info Behavior Type"
#define STR_STATISTICS_INFO_CONTEXT_INDEX "Statistics Info Context Index"
#define STR_STATISTICS_INFO_HOST_HINT_TYPE "Statistics Info Host Hint Type"
#define STR_STATISTICS_INFO_RESERVED "Statistics Info Reserved"
#define STR_NAMESPACE_IDENTIFIER "Namespace Identifier"
#define STR_NAMESPACE_INFO_VALID "Namespace Information Valid"
#define STR_STATISTICS_DATA_SIZE "Statistic Data Size"
#define STR_NAMESPACE_IDENTIFIER_15_0 "Namespace Identifier[15:0]"
#define STR_STATISTICS_SPECIFIC_DATA "Statistic Specific Data"
#define STR_CONTEXT_DATA_SIZE "Context Data Size"
#define STR_CONTEXT_DATA_RESERVED "Context Data Reserved"
#define STR_CONTEXT_SCOPE "Context Scope"
#define STR_CONTEXT_SCOPE_FIELDS "Context Scope Fields"
#define STR_SCOPE_FIELD_STRING "Scope Field String"
#define STR_SCOPE_FIELD_OFFSET "Scope Field Offset"
#define STR_SCOPE_FIELD_SIZE "Scope Field Size"
#define STR_SCOPE_FIELD_VALUE "Scope Field Value"
#define STR_ENCAPSULATED_STATISTICS "Encapsulated Statistic Descriptors"
#define STR_CONTEXT_NAMESPACE_ID "Namespace ID"
#define STR_CONTEXT_CONTROLLER_ID "Controller ID"
#define STR_CONTEXT_QUEUE_ID "Queue ID"
#define STR_STATISTICS_WORST_DIE_PERCENT "Worst die % of bad blocks"
#define STR_STATISTICS_WORST_DIE_RAW "Worst die raw number of bad blocks"
#define STR_STATISTICS_WORST_NAND_CHANNEL_PERCENT "Worst NAND channel % of bad blocks"
#define STR_STATISTICS_WORST_NAND_CHANNEL_RAW "Worst NAND channel number of bad blocks"
#define STR_STATISTICS_BEST_NAND_CHANNEL_PERCENT "Best NAND channel % of bad blocks"
#define STR_STATISTICS_BEST_NAND_CHANNEL_RAW "Best NAND channel number of bad blocks"
#define STR_CLASS_SPECIFIC_DATA "Class Specific Data"
#define STR_DBG_EVENT_CLASS_TYPE "Debug Event Class type"
#define STR_EVENT_IDENTIFIER "Event Identifier"
#define STR_EVENT_STRING "Event String"
#define STR_EVENT_DATA_SIZE "Event Data Size"
#define STR_VU_EVENT_STRING "VU Event String"
#define STR_VU_EVENT_ID_STRING "VU Event Identifier"
#define STR_VU_DATA "VU Data"
#define STR_VU_VIRTUAL_FIFO_ID "VU Virtual FIFO Identifier"
#define STR_VU_VIRTUAL_FIFO_STRING "VU Virtual FIFO String"
#define STR_PHYSICAL_EVENT_FIFO_NUM "Physical Event FIFO Number"
#define STR_PHYSICAL_EVENT_FIFO_STRING "Physical Event FIFO String"
#define STR_VIRTUAL_FIFO_NUM "Virtual FIFO Number"
#define STR_SMBUS_DEBUG_EVENT_DATA "SMBUS Debug Event Data"
#define STR_SMBUS_DEBUG_EVENT_DATA_STRING "SMBUS Debug Event Data String"
#define STR_MCTP_DEBUG_EVENT_DATA "MCTP Debug Event Data"
#define STR_MCTP_DEBUG_EVENT_DATA_STRING "MCTP Debug Event Data String"
#define STR_MCTP_TRANSPORT_PROTOCOL "MCTP Transport Protocol Information"
#define STR_MCTP_TRANSPORT_PROTOCOL_STRING "MCTP Transport Protocol String"
#define STR_MCTP_TRANSPORT_HEADER_VALID "MCTP Transport Header Valid"
#define STR_MCTP_TRANSPORT_HEADER "MCTP Transport Header"
#define STR_LINE "==============================================================================\n"
#define STR_LINE2 "-----------------------------------------------------------------------------\n"

/**
 * enum ocp_telemetry_data_area - Telemetry Data Areas
 * @DATA_AREA_1:	Data Area 1
 * @DATA_AREA_2:	Data Area 2
 * @DATA_AREA_3:	Data Area 3
 * @DATA_AREA_4:	Data Area 4
 */
enum ocp_telemetry_data_area {
	DATA_AREA_1 = 0x01,
	DATA_AREA_2 = 0x02,
	DATA_AREA_3 = 0x03,
	DATA_AREA_4 = 0x04,
};

/**
 * enum ocp_telemetry_string_tables - OCP telemetry string tables
 * @STATISTICS_IDENTIFIER_STRING:	Statistic Identifier string
 * @EVENT_STRING:	Event String
 * @VU_EVENT_STRING:	VU Event String
 */
enum ocp_telemetry_string_tables {
	STATISTICS_IDENTIFIER_STRING = 0,
	EVENT_STRING,
	VU_EVENT_STRING
};

/**
 * enum ocp_telemetry_statistics_identifiers - OCP Statistics Identifiers
 */
enum ocp_telemetry_statistic_identifiers {
	STATISTICS_RESERVED_ID = 0x00,
	OUTSTANDING_ADMIN_CMDS_ID = 0x01,
	HOST_WRTIE_BANDWIDTH_ID = 0x02,
	GW_WRITE_BANDWITH_ID = 0x03,
	ACTIVE_NAMESPACES_ID = 0x04,
	INTERNAL_WRITE_WORKLOAD_ID = 0x05,
	INTERNAL_READ_WORKLOAD_ID = 0x06,
	INTERNAL_WRITE_QUEUE_DEPTH_ID = 0x07,
	INTERNAL_READ_QUEUE_DEPTH_ID = 0x08,
	PENDING_TRIM_LBA_COUNT_ID = 0x09,
	HOST_TRIM_LBA_REQUEST_COUNT_ID = 0x0A,
	CURRENT_NVME_POWER_STATE_ID = 0x0B,
	CURRENT_DSSD_POWER_STATE_ID = 0x0C,
	PROGRAM_FAIL_COUNT_ID = 0x0D,
	ERASE_FAIL_COUNT_ID = 0x0E,
	READ_DISTURB_WRITES_ID = 0x0F,

	RETENTION_WRITES_ID = 0x10,
	WEAR_LEVELING_WRITES_ID = 0x11,
	READ_RECOVERY_WRITES_ID = 0x12,
	GC_WRITES_ID = 0x13,
	SRAM_CORRECTABLE_COUNT_ID = 0x14,
	DRAM_CORRECTABLE_COUNT_ID = 0x15,
	SRAM_UNCORRECTABLE_COUNT_ID = 0x16,
	DRAM_UNCORRECTABLE_COUNT_ID = 0x17,
	DATA_INTEGRITY_ERROR_COUNT_ID = 0x18,
	READ_RETRY_ERROR_COUNT_ID = 0x19,
	PERST_EVENTS_COUNT_ID = 0x1A,
	MAX_DIE_BAD_BLOCK_ID = 0x1B,
	MAX_NAND_CHANNEL_BAD_BLOCK_ID = 0x1C,
	MIN_NAND_CHANNEL_BAD_BLOCK_ID = 0x1D,

	NAMESPACE_ID_CONTEXT_ID = 0x6D,
	CONTROLLER_ID_CONTEXT_ID = 0x6E,
	QUEUE_ID_CONTEXT_ID = 0x6F,

	//RESERVED = 7FFFh-70h,
	//VENDOR_UNIQUE_CLASS_TYPE = FFFFh-8000h,
};


/**
 * enum ocp_telemetry_debug_event_class_types - OCP Debug Event Class types
 * @RESERVED_CLASS_TYPE:	       Reserved class
 * @TIME_STAMP_CLASS_TYPE:	       Time stamp class
 * @PCIE_CLASS_TYPE:	           PCIe class
 * @NVME_CLASS_TYPE:	           NVME class
 * @RESET_CLASS_TYPE:	           Reset class
 * @BOOT_SEQUENCE_CLASS_TYPE:	   Boot Sequence class
 * @FIRMWARE_ASSERT_CLASS_TYPE:	   Firmware Assert class
 * @TEMPERATURE_CLASS_TYPE:	       Temperature class
 * @MEDIA_CLASS_TYPE:	           Media class
 * @MEDIA_WEAR_CLASS_TYPE:	       Media wear class
 * @STATISTIC_SNAPSHOT_CLASS_TYPE: Statistic snapshot class
 * @VIRTUAL_FIFO_EVENT_CLASS_TYPE: Virtual FIFO event class
 * @SMBUS_I2C_I3C_EVENT_CLASS_TYPE: SMBUS/I2C/I3C event class
 * @MCTP_EVENT_CLASS_TYPE:	       MCTP event class
 * @RESERVED:	                   Reserved class
 * @VENDOR_UNIQUE_CLASS_TYPE:	   Vendor Unique class
 */
enum ocp_telemetry_debug_event_class_types {
	RESERVED_CLASS_TYPE = 0x00,
	TIME_STAMP_CLASS_TYPE = 0x01,
	PCIE_CLASS_TYPE = 0x02,
	NVME_CLASS_TYPE = 0x03,
	RESET_CLASS_TYPE = 0x04,
	BOOT_SEQUENCE_CLASS_TYPE = 0x05,
	FIRMWARE_ASSERT_CLASS_TYPE = 0x06,
	TEMPERATURE_CLASS_TYPE = 0x07,
	MEDIA_CLASS_TYPE = 0x08,
	MEDIA_WEAR_CLASS_TYPE = 0x09,
	STATISTIC_SNAPSHOT_CLASS_TYPE = 0x0A,
	VIRTUAL_FIFO_EVENT_CLASS_TYPE = 0x0B,
	SMBUS_I2C_I3C_EVENT_CLASS_TYPE = 0x0C,
	MCTP_EVENT_CLASS_TYPE = 0x0D,
	//RESERVED = 7Fh-0Eh,
	//VENDOR_UNIQUE_CLASS_TYPE = FFh-80h,
};

/**
 * struct telemetry_str_log_format - Telemetry String Log Format
 * @log_page_version:          indicates the version of the mapping this log page uses
 *                             Shall be set to 01h.
 * @reserved1:                 Reserved.
 * @log_page_guid:             Shall be set to B13A83691A8F408B9EA495940057AA44h.
 * @sls:                       Shall be set to the number of DWORDS in the String Log.
 * @reserved2:                 reserved.
 * @sits:                      shall be set to the number of DWORDS in the Statistics
 *                             Identifier String Table
 * @ests:                      Shall be set to the number of DWORDS from byte 0 of this
 *                             log page to the start of the Event String Table
 * @estsz:                     shall be set to the number of DWORDS in the Event String Table
 * @vu_eve_sts:                Shall be set to the number of DWORDS from byte 0 of this
 *                             log page to the start of the VU Event String Table
 * @vu_eve_st_sz:              shall be set to the number of DWORDS in the VU Event String Table
 * @ascts:                     the number of DWORDS from byte 0 of this log page until the
 *                             ASCII Table Starts.
 * @asctsz:                    the number of DWORDS in the ASCII Table
 * @fifo1:                     FIFO 0 ASCII String
 * @fifo2:                     FIFO 1 ASCII String
 * @fifo3:                     FIFO 2 ASCII String
 * @fifo4:                     FIFO 3 ASCII String
 * @fif05:                     FIFO 4 ASCII String
 * @fifo6:                     FIFO 5 ASCII String
 * @fifo7:                     FIFO 6 ASCII String
 * @fifo8:                     FIFO 7 ASCII String
 * @fifo9:                     FIFO 8 ASCII String
 * @fifo10:                    FIFO 9 ASCII String
 * @fif011:                    FIFO 10 ASCII String
 * @fif012:                    FIFO 11 ASCII String
 * @fifo13:                    FIFO 12 ASCII String
 * @fif014:                    FIFO 13 ASCII String
 * @fif015:                    FIFO 14 ASCII String
 * @fif016:                    FIFO 15 ASCII String
 * @reserved3:                 reserved
 */
struct __packed telemetry_str_log_format {
	__u8    log_page_version;
	__u8    reserved1[15];
	__u8    log_page_guid[GUID_LEN];
	__le64  sls;
	__u8    reserved2[24];
	__le64  sits;
	__le64  sitsz;
	__le64  ests;
	__le64  estsz;
	__le64  vu_eve_sts;
	__le64  vu_eve_st_sz;
	__le64  ascts;
	__le64  asctsz;
	__u8    fifo1[16];
	__u8    fifo2[16];
	__u8    fifo3[16];
	__u8    fifo4[16];
	__u8    fifo5[16];
	__u8    fifo6[16];
	__u8    fifo7[16];
	__u8    fifo8[16];
	__u8    fifo9[16];
	__u8    fifo10[16];
	__u8    fifo11[16];
	__u8    fifo12[16];
	__u8    fifo13[16];
	__u8    fifo14[16];
	__u8    fifo15[16];
	__u8    fifo16[16];
	__u8    reserved3[48];
};

/*
 * struct statistics_id_str_table_entry - Statistics Identifier String Table Entry
 * @vs_si:                    Shall be set the Vendor Unique Statistic Identifier number.
 * @reserved1:                Reserved
 * @ascii_id_len:             Shall be set the number of ASCII Characters that are valid.
 * @ascii_id_ofst:            Shall be set to the offset from DWORD 0/Byte 0 of the Start
 *                            of the ASCII Table to the first character of the string for
 *                            this Statistic Identifier string..
 * @reserved2                 reserved
 */
struct __packed statistics_id_str_table_entry {
	__le16  vs_si;
	__u8    reserved1;
	__u8    ascii_id_len;
	__le64  ascii_id_ofst;
	__le32  reserved2;
};

/*
 * struct event_id_str_table_entry - Event Identifier String Table Entry
 * @deb_eve_class:            Shall be set the Debug Class.
 * @ei:                       Shall be set to the Event Identifier
 * @ascii_id_len:             Shall be set the number of ASCII Characters that are valid.
 * @ascii_id_ofst:            This is the offset from DWORD 0/ Byte 0 of the start of the
 *                            ASCII table to the ASCII data for this identifier
 * @reserved2                 reserved
 */
struct __packed event_id_str_table_entry {
	__u8      deb_eve_class;
	__le16    ei;
	__u8      ascii_id_len;
	__le64    ascii_id_ofst;
	__le32    reserved2;
};

/*
 * struct vu_event_id_str_table_entry - VU Event Identifier String Table Entry
 * @deb_eve_class:            Shall be set the Debug Class.
 * @vu_ei:                    Shall be set to the VU Event Identifier
 * @ascii_id_len:             Shall be set the number of ASCII Characters that are valid.
 * @ascii_id_ofst:            This is the offset from DWORD 0/ Byte 0 of the start of the
 *                            ASCII table to the ASCII data for this identifier
 * @reserved                  reserved
 */
struct __packed vu_event_id_str_table_entry {
	__u8      deb_eve_class;
	__le16    vu_ei;
	__u8      ascii_id_len;
	__le64    ascii_id_ofst;
	__le32    reserved;
};


struct __packed ocp_telemetry_parse_options {
	char *telemetry_log;
	char *string_log;
	char *output_file;
	char *output_format;
	int data_area;
	char *telemetry_type;
};

struct __packed nvme_ocp_telemetry_reason_id
{
	__u8 error_id[64];                // Bytes 63:00
	__u8 file_id[8];                  // Bytes 71:64
	__le16 line_number;               // Bytes 73:72
	__u8 valid_flags;                 // Bytes 74
	__u8 reserved[21];                // Bytes 95:75
	__u8 vu_reason_ext[32];           // Bytes 127:96
};

struct __packed nvme_ocp_telemetry_common_header
{
	__u8 log_id;                             // Byte 00
	__le32 reserved1;                        // Bytes 04:01
	__u8 ieee_oui_id[3];                     // Bytes 07:05
	__le16 da1_last_block;                   // Bytes 09:08
	__le16 da2_last_block;                   // Bytes 11:10
	__le16 da3_last_block;                   // Bytes 13:12
	__le16 reserved2;                        // Bytes 15:14
	__le32 da4_last_block;                   // Bytes 19:16
};

struct __packed nvme_ocp_telemetry_host_initiated_header
{
	struct nvme_ocp_telemetry_common_header commonHeader;    // Bytes 19:00
	__u8 reserved3[360];                                     // Bytes 379:20
	__u8 host_initiated_scope;                               // Byte 380
	__u8 host_initiated_gen_number;                          // Byte 381
	__u8 host_initiated_data_available;                      // Byte 382
	__u8 ctrl_initiated_gen_number;                          // Byte 383
	struct nvme_ocp_telemetry_reason_id reason_id;           // Bytes 511:384
};

struct __packed nvme_ocp_telemetry_controller_initiated_header
{
	struct nvme_ocp_telemetry_common_header commonHeader;   // Bytes 19:00
	__u8 reserved3[361];                                    // Bytes 380:20
	__u8 ctrl_initiated_scope;                              // Byte 381
	__u8 ctrl_initiated_data_available;                     // Byte 382
	__u8 ctrl_initiated_gen_number;                         // Byte 383
	struct nvme_ocp_telemetry_reason_id reason_id;          // Bytes 511:384
};

struct __packed nvme_ocp_telemetry_smart
{
	__u8 critical_warning;                                         // Byte 0
	__le16 composite_temperature;                                  // Bytes 2:1
	__u8 available_spare;                                          // Bytes 3
	__u8 available_spare_threshold;                                // Bytes 4
	__u8 percentage_used;                                          // Bytes 5
	__u8 reserved1[26];                                            // Bytes 31:6
	__u8 data_units_read[16];                                      // Bytes 47:32
	__u8 data_units_written[16];                                   // Bytes 63:48
	__u8 host_read_commands[16];                                   // Byte  79:64
	__u8 host_write_commands[16];                                  // Bytes 95:80
	__u8 controller_busy_time[16];                                 // Bytes 111:96
	__u8 power_cycles[16];                                         // Bytes 127:112
	__u8 power_on_hours[16];                                       // Bytes 143:128
	__u8 unsafe_shutdowns[16];                                     // Bytes 159:144
	__u8 media_and_data_integrity_errors[16];                      // Bytes 175:160
	__u8 number_of_error_information_log_entries[16];              // Bytes 191:176
	__le32 warning_composite_temperature_time;                     // Byte  195:192
	__le32 critical_composite_temperature_time;                    // Bytes 199:196
	__le16 temperature_sensor1;                                    // Bytes 201:200
	__le16 temperature_sensor2;                                    // Byte  203:202
	__le16 temperature_sensor3;                                    // Byte  205:204
	__le16 temperature_sensor4;                                    // Bytes 207:206
	__le16 temperature_sensor5;                                    // Bytes 209:208
	__le16 temperature_sensor6;                                    // Bytes 211:210
	__le16 temperature_sensor7;                                    // Bytes 213:212
	__le16 temperature_sensor8;                                    // Bytes 215:214
	__le32 thermal_management_temperature1_transition_count;       // Bytes 219:216
	__le32 thermal_management_temperature2_transition_count;       // Bytes 223:220
	__le32 total_time_for_thermal_management_temperature1;         // Bytes 227:224
	__le32 total_time_for_thermal_management_temperature2;         // Bytes 231:228
	__u8 reserved2[280];                                           // Bytes 511:232
};

struct __packed nvme_ocp_telemetry_smart_extended
{
	__u8 physical_media_units_written[16];                   // Bytes 15:0
	__u8 physical_media_units_read[16];                      // Bytes 31:16
	__u8 bad_user_nand_blocks_raw_count[6];                  // Bytes 37:32
	__le16 bad_user_nand_blocks_normalized_value;            // Bytes 39:38
	__u8 bad_system_nand_blocks_raw_count[6];                // Bytes 45:40
	__le16 bad_system_nand_blocks_normalized_value;          // Bytes 47:46
	__le64 xor_recovery_count;                               // Bytes 55:48
	__le64 uncorrectable_read_error_count;                   // Bytes 63:56
	__le64 soft_ecc_error_count;                             // Bytes 71:64
	__le32 end_to_end_correction_counts_detected_errors;     // Bytes 75:72
	__le32 end_to_end_correction_counts_corrected_errors;    // Bytes 79:76
	__u8 system_data_percent_used;                           // Byte  80
	__u8 refresh_counts[7];                                  // Bytes 87:81
	__le32 max_user_data_erase_count;                        // Bytes 91:88
	__le32 min_user_data_erase_count;                        // Bytes 95:92
	__u8 num_thermal_throttling_events;                      // Bytes 96
	__u8 current_throttling_status;                          // Bytes 97
	__u8  errata_version_field;                              // Byte 98
	__le16 point_version_field;                              // Byte 100:99
	__le16 minor_version_field;                              // Byte 102:101
	__u8  major_version_field;                               // Byte 103
	__le64 pcie_correctable_error_count;                     // Bytes 111:104
	__le32 incomplete_shutdowns;                             // Bytes 115:112
	__le32 reserved1;                                        // Bytes 119:116
	__u8 percent_free_blocks;                                // Byte  120
	__u8 reserved2[7];                                       // Bytes 127:121
	__le16 capacitor_health;                                 // Bytes 129:128
	__u8 nvme_base_errata_version;                           // Byte  130
	__u8 nvme_command_set_errata_version;                    // Byte  131
	__le32 reserved3;                                        // Bytes 135:132
	__le64 unaligned_io;                                     // Bytes 143:136
	__le64 security_version_number;                          // Bytes 151:144
	__le64 total_nuse;                                       // Bytes 159:152
	__u8 plp_start_count[16];                                // Bytes 175:160
	__u8 endurance_estimate[16];                             // Bytes 191:176
	__le64 pcie_link_retraining_count;                       // Bytes 199:192
	__le64 power_state_change_count;                         // Bytes 207:200
	__le64 lowest_permitted_firmware_revision;               // Bytes 215:208
	__u8 reserved4[278];                                     // Bytes 493:216
	__le16 log_page_version;                                 // Bytes 495:494
	__u8 log_page_guid[GUID_LEN];                            // Bytes 511:496
};

struct __packed nvme_ocp_event_fifo_data
{
	__le32 event_fifo_num;
	__u8 event_fifo_da;
	__le64 event_fifo_start;
	__le64 event_fifo_size;
};

struct __packed nvme_ocp_telemetry_offsets
{
	__le32 data_area;
	__le32 header_size;
	__le32 da1_start_offset;
	__le32 da1_size;
	__le32 da2_start_offset;
	__le32 da2_size;
	__le32 da3_start_offset;
	__le32 da3_size;
	__le32 da4_start_offset;
	__le32 da4_size;
};

struct __packed nvme_ocp_event_fifo_offsets
{
	__le64 event_fifo_start;
	__le64 event_fifo_size;
};

struct __packed nvme_ocp_header_in_da1
{
	__le16 major_version;                                                // Bytes 1:0
	__le16 minor_version;                                                // Bytes 3:2
	__le32 reserved1;                                                    // Bytes 7:4
	__le64 time_stamp;                                                   // Bytes 15:8
	__u8 log_page_guid[GUID_LEN];                                        // Bytes 31:16
	__u8 num_telemetry_profiles_supported;                               // Byte 32
	__u8 telemetry_profile_selected;                                     // Byte 33
	__u8 reserved2[6];                                                   // Bytes 39:34
	__le64 string_log_size;                                              // Bytes 47:40
	__le64 reserved3;                                                    // Bytes 55:48
	__le64 firmware_revision;                                            // Bytes 63:56
	__u8 reserved4[32];                                                  // Bytes 95:64
	__le64 da1_statistic_start;                                          // Bytes 103:96
	__le64 da1_statistic_size;                                           // Bytes 111:104
	__le64 da2_statistic_start;                                          // Bytes 119:112
	__le64 da2_statistic_size;                                           // Bytes 127:120
	__u8 reserved5[32];                                                  // Bytes 159:128
	__u8 event_fifo_da[16];                                              // Bytes 175:160
	struct nvme_ocp_event_fifo_offsets fifo_offsets[16];                 // Bytes 431:176
	__u8 reserved6[80];                                                  // Bytes 511:432
	struct nvme_ocp_telemetry_smart smart_health_info;                   // Bytes 1023:512
	struct nvme_ocp_telemetry_smart_extended smart_health_info_extended; // Bytes 1535:1024
};

struct __packed nvme_ocp_telemetry_statistic_descriptor
{
	__le16 statistic_id;                    // Bytes 1:0
	__u8 statistic_info_behaviour_type : 4; // Byte  2(3:0)
	__u8 statistic_info_host_hint_type : 2; // Byte  2(5:4)
	__u8 statistic_info_context_index : 1;  // Byte  2(6)
	__u8 statistic_info_reserved : 1;       // Byte  2(7)
	__u8 ns_info_nsid : 7;                  // Bytes 3(6:0)
	__u8 ns_info_ns_info_valid : 1;         // Bytes 3(7)
	__le16 statistic_data_size;             // Bytes 5:4
	__le16 ns_identifier_15_0;              // Bytes 7:6
};

/* Context data at the start of a Context Statistic Descriptor's data */
#define CONTEXT_DATA_DWORDS 2

struct __packed nvme_ocp_statistic_context_data
{
	__le16 context_data_size; // Bytes 1:0
	__le16 reserved;          // Bytes 3:2
	__u8 scope[4];            // Bytes 7:4
};

struct __packed nvme_ocp_telemetry_event_descriptor
{
	__u8 debug_event_class_type;    // Byte 0
	__le16 event_id;                // Bytes 2:1
	__u8 event_data_size;           // Byte 3
};

struct __packed nvme_ocp_time_stamp_dbg_evt_class_format
{
	__u8 time_stamp[DATA_SIZE_8];             // Bytes 11:4
};

struct __packed nvme_ocp_pcie_dbg_evt_class_format
{
	__u8 pCIeDebugEventData[DATA_SIZE_4];     // Bytes 7:4
};

struct __packed nvme_ocp_nvme_dbg_evt_class_format
{
	__u8 nvmeDebugEventData[DATA_SIZE_8];     // Bytes 11:4
};

struct __packed nvme_ocp_media_wear_dbg_evt_class_format
{
	__u8 currentMediaWear[DATA_SIZE_12];         // Bytes 15:4

};

struct __packed nvme_ocp_virtual_fifo_dbg_evt_class_format
{
	__le16 vu_virtual_fifo_identifier;        // Bytes 5:4
	__le16 reserved;                          // Bytes 7:6
};

struct __packed nvme_ocp_smbus_dbg_evt_class_format
{
	__le16 smbus_debug_event_data;            // Bytes 5:4
	__le16 reserved;                          // Bytes 7:6
};

struct __packed nvme_ocp_mctp_dbg_evt_class_format
{
	__le16 mctp_debug_event_data;             // Bytes 5:4
	__u8 transport_protocol;                  // Byte  6
	__u8 event_flags;                         // Byte  7
	__u8 transport_header[DATA_SIZE_4];       // Bytes 11:8
};

struct __packed nvme_ocp_common_dbg_evt_class_vu_data
{
	__le16 vu_event_identifier;         // Bytes 5:4
	__u8 data[];                        // Bytes N:6
};

struct __packed nvme_ocp_statistic_snapshot_evt_class_format
{
	__u8 debug_event_class_type;    // Byte  0
	__u8 reserved1[3];              // Bytes 3:1
	__le16 stat_id;                 // Bytes 5:4
	__u8 stat_info;                 // Byte  6
	__u8 namespace_info;            // Byte  7
	__le16 stat_data_size;          // Bytes 9:8
	__le16 nsid;                    // Bytes 11:10
};

struct __packed nvme_ocp_statistics_identifier_string_table
{
	__le16 vs_statistic_identifier;     //1:0
	__u8 reserved1;                     //2
	__u8 ascii_id_length;               //3
	__le64 ascii_id_offset;             //11:4
	__le32 reserved2;                   //15:12
};

struct __packed nvme_ocp_event_string_table
{
	__u8 debug_event_class;         //0
	__le16 event_identifier;        //2:1
	__u8 ascii_id_length;           //3
	__le64 ascii_id_offset;         //11:4
	__le32 reserved;                //15:12
};

struct __packed nvme_ocp_vu_event_string_table
{
	__u8 debug_event_class;        //0
	__le16 vu_event_identifier;    //2:1
	__u8 ascii_id_length;          //3
	__le64 ascii_id_offset;        //11:4
	__le32 reserved;               //15:12
};

struct __packed nvme_ocp_telemetry_string_header
{
	__u8 version;                   //0:0
	__u8 reserved1[15];             //15:1
	__u8 guid[GUID_LEN];            //32:16
	__le64 string_log_size;         //39:32
	__u8 reserved2[24];             //63:40
	__le64 sits;                    //71:64 Statistics Identifier String Table Start(SITS)
	__le64 sitsz;                   //79:72 Statistics Identifier String Table Size (SITSZ)
	__le64 ests;                    //87:80 Event String Table Start(ESTS)
	__le64 estsz;                   //95:88 Event String Table Size(ESTSZ)
	__le64 vu_ests;                 //103:96 VU Event String Table Start
	__le64 vu_estsz;                //111:104 VU Event String Table Size
	__le64 ascts;                   //119:112 ASCII Table start
	__le64 asctsz;                  //127:120 ASCII Table Size
	__u8 fifo_ascii_string[16][16]; //383:128
	__u8 reserved3[48];             //431:384
};

struct __packed statistic_entry {
	int identifier;
	char *description;
};

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

#define ARGSTR(s, i) arg_str(s, ARRAY_SIZE(s), i)

/* Event Data is defined for the NACK error Event ID only */
static inline const char *telemetry_smbus_event_data_to_string(int event_id, int data)
{
	if (event_id != SMBUS_NACK_ERROR)
		return "";
	return ARGSTR(telemetry_smbus_nack_event_data_str, data);
}

/* Each MCTP Event ID has its own Event Data values */
static inline const char *telemetry_mctp_event_data_to_string(int event_id, int data)
{
	switch (event_id) {
	case MCTP_DROPPED_PACKET:
		return ARGSTR(telemetry_mctp_dropped_packet_data_str, data);
	case MCTP_DROPPED_MESSAGE:
		return ARGSTR(telemetry_mctp_dropped_message_data_str, data);
	case MCTP_DISCOVERY_ADDRESSING_ERRORS:
		return ARGSTR(telemetry_mctp_discovery_data_str, data);
	case MCTP_ERROR_STATUS:
		return ARGSTR(telemetry_mctp_error_status_data_str, data);
	default:
		return "";
	}
}

static inline const char *telemetry_mctp_transport_protocol_to_string(int protocol)
{
	return ARGSTR(telemetry_mctp_transport_protocol_str, protocol);
}

/**
 * @brief parse the ocp telemetry host or controller log binary file
 *        into json or text
 *
 * @param options, input pointer for inputs like telemetry log bin file,
 *        string log bin file and output file etc.
 *
 * @return 0 success
 */
int parse_ocp_telemetry_log(struct ocp_telemetry_parse_options *options);

/**
 * @brief parse the ocp telemetry string log binary file to json or text
 *
 * @param event_fifo_num, input event FIFO number
 * @param debug_event_class, input debug event class id
 * @param string_table, input string table
 * @param description, input description string
 *
 * @return 0 success
 */
int parse_ocp_telemetry_string_log(int event_fifo_num, int identifier, int debug_event_class,
	enum ocp_telemetry_string_tables string_table, char *description);

/**
 * @brief gets the telemetry datas areas, offsets and sizes information
 *
 * @param ptelemetry_common_header, input telemetry common header pointer
 * @param ptelemetry_das_offset, input telemetry offsets pointer
 *
 * @return 0 success
 */
int get_telemetry_das_offset_and_size(
	struct nvme_ocp_telemetry_common_header *ptelemetry_common_header,
	struct nvme_ocp_telemetry_offsets *ptelemetry_das_offset);

/**
 * @brief parses statistics data to text or json formats
 *
 * @param root, input time json root object pointer
 * @param ptelemetry_das_offset, input telemetry offsets pointer
 * @param fp, input file pointer
 *
 * @return 0 success
 */
int parse_statistics(struct json_object *root, struct nvme_ocp_telemetry_offsets *pOffsets,
	FILE *fp);

/**
 * @brief parses a single statistic data to text or json formats
 *
 * @param pstatistic_entry, statistic entry pointer
 * @param pstats_array, stats array pointer
 * @param fp, input file pointer
 *
 * @return 0 success
 */
int parse_statistic(struct nvme_ocp_telemetry_statistic_descriptor *pstatistic_entry,
	struct json_object *pstats_array, FILE *fp);

/**
 * @brief parses event fifos data to text or json formats
 *
 * @param root, input time json root object pointer
 * @param poffsets, input telemetry offsets pointer
 * @param fp, input file pointer
 *
 * @return 0 success
 */
int parse_event_fifos(struct json_object *root, struct nvme_ocp_telemetry_offsets *poffsets,
	FILE *fp);

/**
 * @brief parses a single event fifo data to text or json formats
 *
 * @param fifo_num, input event fifo number
 * @param pfifo_start, event fifo start pointer
 * @param pevent_fifos_object, event fifos json object pointer
 * @param ptelemetry_das_offset, input telemetry offsets pointer
 * @param fifo_size, input event fifo size
 * @param fp, input file pointer
 *
 * @return 0 success
 */
int parse_event_fifo(unsigned int fifo_num, unsigned char *pfifo_start,
	struct json_object *pevent_fifos_object, unsigned char *pstring_buffer,
	struct nvme_ocp_telemetry_offsets *poffsets, __u64 fifo_size, FILE *fp);

/**
 * @brief parses event fifos data to text or json formats
 *
 * @return 0 success
 */
int print_ocp_telemetry_normal(struct ocp_telemetry_parse_options *options);

/**
 * @brief parses event fifos data to text or json formats
 *
 * @return 0 success
 */
int print_ocp_telemetry_json(struct ocp_telemetry_parse_options *options);

/**
 * @brief gets statistic id ascii string
 *
 * @param identifier, string id
 * @param description, string description
 *
 * @return 0 success
 */
int get_statistic_id_ascii_string(int identifier, char *description);

/**
 * @brief gets event id ascii string
 *
 * @param identifier, string id
 * @param debug_event_class, debug event class
 * @param description, string description
 *
 * @return 0 success
 */
int get_event_id_ascii_string(int identifier, int debug_event_class, char *description);

/**
 * @brief gets vu event id ascii string
 *
 * @param identifier, string id
 * @param debug_event_class, debug event class
 * @param description, string description
 *
 * @return 0 success
 */
int get_vu_event_id_ascii_string(int identifier, int debug_event_class, char *description);

/**
 * @brief parses a time-stamp event fifo data to text or json formats
 *
 * @param pevent_descriptor, input event descriptor data
 * @param pevent_descriptor_obj, event descriptor json object pointer
 * @param pevent_specific_data, input event specific data
 * @param pevent_fifos_object, event fifos json object pointer
 * @param fp, input file pointer
 *
 * @return 0 success
 */
int parse_time_stamp_event(
		struct nvme_ocp_telemetry_event_descriptor *pevent_descriptor,
		struct json_object *pevent_descriptor_obj,
		__u8 *pevent_specific_data,
		struct json_object *pevent_fifos_object,
		FILE *fp);

/**
 * @brief parses a pcie event fifo data to text or json formats
 *
 * @param pevent_descriptor, input event descriptor data
 * @param pevent_descriptor_obj, event descriptor json object pointer
 * @param pevent_specific_data, input event specific data
 * @param pevent_fifos_object, event fifos json object pointer
 * @param fp, input file pointer
 *
 * @return 0 success
 */
int parse_pcie_event(
		struct nvme_ocp_telemetry_event_descriptor *pevent_descriptor,
		struct json_object *pevent_descriptor_obj,
		__u8 *pevent_specific_data,
		struct json_object *pevent_fifos_object,
		FILE *fp);

/**
 * @brief parses a nvme event fifo data to text or json formats
 *
 * @param pevent_descriptor, input event descriptor data
 * @param pevent_descriptor_obj, event descriptor json object pointer
 * @param pevent_specific_data, input event specific data
 * @param pevent_fifos_object, event fifos json object pointer
 * @param fp, input file pointer
 *
 * @return 0 success
 */
int parse_nvme_event(
		struct nvme_ocp_telemetry_event_descriptor *pevent_descriptor,
		struct json_object *pevent_descriptor_obj,
		__u8 *pevent_specific_data,
		struct json_object *pevent_fifos_object,
		FILE *fp);

/**
 * @brief parses common event fifo data to text or json formats
 *
 * @param pevent_descriptor, input event descriptor data
 * @param pevent_descriptor_obj, event descriptor json object pointer
 * @param pevent_specific_data, input event specific data
 * @param pevent_fifos_object, event fifos json object pointer
 * @param fp, input file pointer
 *
 * @return
 */
void parse_common_event(struct nvme_ocp_telemetry_event_descriptor *pevent_descriptor,
			    struct json_object *pevent_descriptor_obj, __u8 *pevent_specific_data,
			    struct json_object *pevent_fifos_object, FILE *fp);

/**
 * @brief parses a media-wear event fifo data to text or json formats
 *
 * @param pevent_descriptor, input event descriptor data
 * @param pevent_descriptor_obj, event descriptor json object pointer
 * @param pevent_specific_data, input event specific data
 * @param pevent_fifos_object, event fifos json object pointer
 * @param fp, input file pointer
 *
 * @return 0 success
 */
int parse_media_wear_event(
		struct nvme_ocp_telemetry_event_descriptor *pevent_descriptor,
		struct json_object *pevent_descriptor_obj,
		__u8 *pevent_specific_data,
		struct json_object *pevent_fifos_object,
		FILE *fp);

/**
 * @brief parses a virtual FIFO event fifo data to text or json formats
 *
 * @param pevent_descriptor, input event descriptor data
 * @param pevent_descriptor_obj, event descriptor json object pointer
 * @param pevent_specific_data, input event specific data
 * @param pevent_fifos_object, event fifos json object pointer
 * @param fp, input file pointer
 *
 * @return 0 success
 */
int parse_virtual_fifo_event(
		struct nvme_ocp_telemetry_event_descriptor *pevent_descriptor,
		struct json_object *pevent_descriptor_obj,
		__u8 *pevent_specific_data,
		struct json_object *pevent_fifos_object,
		FILE *fp);

/**
 * @brief parses a SMBUS/I2C/I3C event fifo data to text or json formats
 *
 * @param pevent_descriptor, input event descriptor data
 * @param pevent_descriptor_obj, event descriptor json object pointer
 * @param pevent_specific_data, input event specific data
 * @param pevent_fifos_object, event fifos json object pointer
 * @param fp, input file pointer
 *
 * @return 0 success
 */
int parse_smbus_event(
		struct nvme_ocp_telemetry_event_descriptor *pevent_descriptor,
		struct json_object *pevent_descriptor_obj,
		__u8 *pevent_specific_data,
		struct json_object *pevent_fifos_object,
		FILE *fp);

/**
 * @brief parses a MCTP event fifo data to text or json formats
 *
 * @param pevent_descriptor, input event descriptor data
 * @param pevent_descriptor_obj, event descriptor json object pointer
 * @param pevent_specific_data, input event specific data
 * @param pevent_fifos_object, event fifos json object pointer
 * @param fp, input file pointer
 *
 * @return 0 success
 */
int parse_mctp_event(
		struct nvme_ocp_telemetry_event_descriptor *pevent_descriptor,
		struct json_object *pevent_descriptor_obj,
		__u8 *pevent_specific_data,
		struct json_object *pevent_fifos_object,
		FILE *fp);
