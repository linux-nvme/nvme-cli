// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) Micron, Inc 2024.
 *
 * @file: micron-ocp-telemetry.h
 * @brief: This module contains all the constructs needed for parsing
 *         (or) decoding ocp telemetry log files.
 * @author: Chaithanya Shoba <ashoba@micron.com>
 */

#include "nvme.h"
#include "nvme-print.h"
#include "micron-utils.h"
#include "common.h"

#define DATA_SIZE_12   12
#define DATA_SIZE_8    8
#define DATA_SIZE_4    4
#define NVME_HOST_TELEMETRY_LOG       0x07
#define NVME_CNTRL_TELEMETRY_LOG      0x08
#define MAX_BUFFER_32_KB              0x8000
#define OCP_TELEMETRY_DATA_BLOCK_SIZE 512
#define SIZE_OF_DWORD                 4
#define MAX_NUM_FIFOS                 16
#define DA1_OFFSET                    512
#define DEFAULT_ASCII_STRING_SIZE     16

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
#define STR_STATISTICS_INFO_RESERVED "Statistics Info Reserved"
#define STR_NAMESPACE_IDENTIFIER "Namespace Identifier"
#define STR_NAMESPACE_INFO_VALID "Namespace Information Valid"
#define STR_STATISTICS_DATA_SIZE "Statistic Data Size"
#define STR_RESERVED "Reserved"
#define STR_STATISTICS_SPECIFIC_DATA "Statistic Specific Data"
#define STR_CLASS_SPECIFIC_DATA "Class Specific Data"
#define STR_DBG_EVENT_CLASS_TYPE "Debug Event Class type"
#define STR_EVENT_IDENTIFIER "Event Identifier"
#define STR_EVENT_STRING "Event String"
#define STR_EVENT_DATA_SIZE "Event Data Size"
#define STR_VU_EVENT_STRING "VU Event String"
#define STR_VU_EVENT_ID_STRING "VU Event Identifier"
#define STR_VU_DATA "VU Data"
#define STR_LINE "==============================================================================\n"
#define STR_LINE2 "-----------------------------------------------------------------------------\n"

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
	__u8 log_page_guid[16];                                  // Bytes 511:496
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
	__u8 log_page_guid[16];                                              // Bytes 31:16
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
	__u8 statistic_info_reserved : 4;       // Byte  2(7:4)
	__u8 ns_info_nsid : 7;                  // Bytes 3(6:0)
	__u8 ns_info_ns_info_valid : 1;         // Bytes 3(7)
	__le16 statistic_data_size;             // Bytes 5:4
	__le16 reserved;                        // Bytes 7:6
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
	__le16 vu_event_identifier;               // Bytes 13:12
};

struct __packed nvme_ocp_pcie_dbg_evt_class_format
{
	__u8 pCIeDebugEventData[DATA_SIZE_4];     // Bytes 7:4
	__le16 vu_event_identifier;               // Bytes 9:8
};

struct __packed nvme_ocp_nvme_dbg_evt_class_format
{
	__u8 nvmeDebugEventData[DATA_SIZE_8];     // Bytes 11:4
	__le16 vu_event_identifier;               // Bytes 13:12
};

struct __packed nvme_ocp_common_dbg_evt_class_format
{
	__le16 vu_event_identifier;    // Bytes 5:4
};

struct __packed nvme_ocp_media_wear_dbg_evt_class_format
{
	__u8 currentMediaWear[DATA_SIZE_12];         // Bytes 15:4
	__le16 vu_event_identifier;                  // Bytes 17:16
};

struct __packed nvme_ocp_statistic_snapshot_evt_class_format
{
	struct nvme_ocp_telemetry_statistic_descriptor statisticDescriptorData; // Bytes 11:10
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
	__u8 guid[16];                  //32:16
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

struct __packed ocp_telemetry_parse_options {
	char *telemetry_log;
	char *string_log;
	char *output_file;
	char *output_fmt;
};

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
	//RESERVED = 7Fh-0Bh,
	//VENDOR_UNIQUE_CLASS_TYPE = FFh-80h,
};

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
int print_ocp_telemetry_normal(char *output_file);

/**
 * @brief parses event fifos data to text or json formats
 *
 * @return 0 success
 */
int print_ocp_telemetry_json(char *output_file);

/**
 * @brief gets statistic id ascii string
 *
 * @param identifier, string id
 * @param description, string description
 *
 * @return 0 success
 */
int get_static_id_ascii_string(int identifier, char *description);

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
 * @return
 */
void parse_time_stamp_event(struct nvme_ocp_telemetry_event_descriptor *pevent_descriptor,
			    struct json_object *pevent_descriptor_obj, __u8 *pevent_specific_data,
			    struct json_object *pevent_fifos_object, FILE *fp);

/**
 * @brief parses a pcie event fifo data to text or json formats
 *
 * @param pevent_descriptor, input event descriptor data
 * @param pevent_descriptor_obj, event descriptor json object pointer
 * @param pevent_specific_data, input event specific data
 * @param pevent_fifos_object, event fifos json object pointer
 * @param fp, input file pointer
 *
 * @return
 */
void parse_pcie_event(struct nvme_ocp_telemetry_event_descriptor *pevent_descriptor,
			    struct json_object *pevent_descriptor_obj, __u8 *pevent_specific_data,
			    struct json_object *pevent_fifos_object, FILE *fp);

/**
 * @brief parses a nvme event fifo data to text or json formats
 *
 * @param pevent_descriptor, input event descriptor data
 * @param pevent_descriptor_obj, event descriptor json object pointer
 * @param pevent_specific_data, input event specific data
 * @param pevent_fifos_object, event fifos json object pointer
 * @param fp, input file pointer
 *
 * @return
 */
void parse_nvme_event(struct nvme_ocp_telemetry_event_descriptor *pevent_descriptor,
			    struct json_object *pevent_descriptor_obj, __u8 *pevent_specific_data,
			    struct json_object *pevent_fifos_object, FILE *fp);

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
 * @return
 */
void parse_media_wear_event(struct nvme_ocp_telemetry_event_descriptor *pevent_descriptor,
			    struct json_object *pevent_descriptor_obj, __u8 *pevent_specific_data,
			    struct json_object *pevent_fifos_object, FILE *fp);
