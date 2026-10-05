// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (c) 2024 Western Digital Corporation or its affiliates.
 *
 * Authors: Jeff Lien <jeff.lien@wdc.com>,
 */
#include <libnvme.h>

#include <ccan/array_size/array_size.h>
#include <ccan/endian/endian.h>

#include "nvme-print.h"
#include "ocp-telemetry-decode.h"

struct statistic_entry statistic_identifiers_map[] = {
	{ 0x00, "Error, this entry does not exist." },
	{ 0x01, "Outstanding Admin Commands" },
	{ 0x02, "Host Write Bandwidth"},
	{ 0x03, "GC Write Bandwidth"},
	{ 0x04, "Active Namespaces"},
	{ 0x05, "Internal Write Workload"},
	{ 0x06, "Internal Read Workload"},
	{ 0x07, "Internal Write Queue Depth"},
	{ 0x08, "Internal Read Queue Depth"},
	{ 0x09, "Pending Trim LBA Count"},
	{ 0x0A, "Host Trim LBA Request Count"},
	{ 0x0B, "Current NVMe Power State"},
	{ 0x0C, "Current DSSD Power State"},
	{ 0x0D, "Program Fail Count"},
	{ 0x0E, "Erase Fail Count"},
	{ 0x0F, "Read Disturb Writes"},
	{ 0x10, "Retention Writes"},
	{ 0x11, "Wear Leveling Writes"},
	{ 0x12, "Read Recovery Writes"},
	{ 0x13, "GC Writes"},
	{ 0x14, "SRAM Correctable Count"},
	{ 0x15, "DRAM Correctable Count"},
	{ 0x16, "SRAM Uncorrectable Count"},
	{ 0x17, "DRAM Uncorrectable Count"},
	{ 0x18, "Data Integrity Error Count"},
	{ 0x19, "Read Retry Error Count"},
	{ 0x1A, "PERST Events Count"},
	{ 0x1B, "Max Die Bad Block"},
	{ 0x1C, "Max NAND Channel Bad Block"},
	{ 0x1D, "Minimum NAND Channel Bad Block"},
	{ 0x1E, "Physical Media Units Written"},
	{ 0x1F, "Physical Media Units Read"},
	{ 0x20, "Bad User NAND Blocks"},
	{ 0x21, "Bad System NAND Blocks"},
	{ 0x22, "XOR Recovery Count"},
	{ 0x23, "Uncorrectable Read Error Count"},
	{ 0x24, "Soft ECC Error Count"},
	{ 0x25, "End to End Correction Counts"},
	{ 0x26, "System Data % Used"},
	{ 0x27, "Refresh Counts"},
	{ 0x28, "User Data Erase Counts"},
	{ 0x29, "Thermal Throttling Status and Count"},
	{ 0x2A, "DSSD Specification Version"},
	{ 0x2B, "PCIe Correctable Error Count"},
	{ 0x2C, "Incomplete Shutdowns"},
	{ 0x2D, "% Free Blocks"},
	{ 0x2E, "Capacitor Health"},
	{ 0x2F, "NVM Express Base Errata Version"},
	{ 0x30, "NVM Command Set Errata Version"},
	{ 0x31, "NVM Express Management Interface Errata Version"},
	{ 0x32, "Unaligned I/O"},
	{ 0x33, "Security Version Number"},
	{ 0x34, "Total NUSE"},
	{ 0x35, "PLP Start Count"},
	{ 0x36, "Endurance Estimate"},
	{ 0x37, "PCIe Link Retraining Count"},
	{ 0x38, "Power State Change Count"},
	{ 0x39, "Lowest Permitted Firmware Revision"},
	{ 0x3A, "Log Page Version"},
	{ 0x3B, "Media Dies Offline"},
	{ 0x3C, "Max Temperature Recorded"},
	{ 0x3D, "NAND Avg. Erase Count"},
	{ 0x3E, "Command Timeouts"},
	{ 0x3F, "System Area Program Fail Count"},
	{ 0x40, "System Area Read Fail Count"},
	{ 0x41, "System Area Erase Fail Count"},
	{ 0x42, "Max Peak Power Capability"},
	{ 0x43, "Current Average Power"},
	{ 0x44, "Lifetime Power Consumed"},
	{ 0x45, "Error / Assert Count"},
	{ 0x46, "Device Busy Time"},
	{ 0x47, "Critical Warning"},
	{ 0x48, "Composite Temperature"},
	{ 0x49, "Available Spare"},
	{ 0x4A, "Available Spare Threshold"},
	{ 0x4B, "Percentage Used"},
	{ 0x4C, "Endurance Group Critical Warning Summary"},
	{ 0x4D, "Data Units Read"},
	{ 0x4E, "Data Units Written"},
	{ 0x4F, "Host Read Commands"},
	{ 0x50, "Host Write Commands"},
	{ 0x51, "Controller Busy Time"},
	{ 0x52, "Power Cycles"},
	{ 0x53, "Power On Hours"},
	{ 0x54, "Unsafe Shutdowns"},
	{ 0x55, "Media and Data Integrity Errors"},
	{ 0x56, "Number of Error Information Log Entries"},
	{ 0x57, "Warning Composite Temperature Time"},
	{ 0x58, "Critical Composite Temperature Time"},
	{ 0x59, "Temperature Sensor 1"},
	{ 0x5A, "Temperature Sensor 2"},
	{ 0x5B, "Temperature Sensor 3"},
	{ 0x5C, "Temperature Sensor 4"},
	{ 0x5D, "Temperature Sensor 5"},
	{ 0x5E, "Temperature Sensor 6"},
	{ 0x5F, "Temperature Sensor 7"},
	{ 0x60, "Temperature Sensor 8"},
	{ 0x61, "Thermal Management Temperature 1 Transition Count"},
	{ 0x62, "Thermal Management Temperature 2 Transition Count"},
	{ 0x63, "Total Time For Thermal Management Temperature 1"},
	{ 0x64, "Total Time For Thermal Management Temperature 2"},
	{ 0x65, "Endurance Estimate"},
	{ 0x66, "Data Units Read"},
	{ 0x67, "Data Units Written"},
	{ 0x68, "Media Units Written"},
	{ 0x69, "Number of Error Information Log Entries"},
	{ 0x6A, "Form Factor"},
	{ 0x6B, "Dies In Use Bad NAND Blocks"},
	{ 0x6C, "Proactive Bad Die Retirement"},
	{ 0x6D, "Namespace ID Context Statistic Descriptor"},
	{ 0x6E, "Controller ID Context Statistic Descriptor"},
	{ 0x6F, "Queue ID Context Statistic Descriptor"}
};

struct request_data host_log_page_header[] = {
	{ "LogIdentifier", 1 },
	{ "Reserved1", 4 },
	{ "IEEE OUI Identifier", 3 },
	{ "Telemetry Host-Initiated Data Area 1 Last Block", 2 },
	{ "Telemetry Host-Initiated Data Area 2 Last Block", 2 },
	{ "Telemetry Host-Initiated Data Area 3 Last Block", 2 },
	{ "Reserved2", 2 },
	{ "Telemetry Host-Initiated Data Area 4 Last Block", 4 },
	{ "Reserved3", 360 },
	{ "Telemetry Host-Initiated Scope", 1 },
	{ "Telemetry Host Initiated Generation Number", 1 },
	{ "Telemetry Host-Initiated Data Available", 1 },
	{ "Telemetry Controller-Initiated Data Generation Number", 1 }
};

struct request_data controller_log_page_header[] = {
	{ "LogIdentifier", 1 },
	{ "Reserved1", 4 },
	{ "IEEE OUI Identifier", 3 },
	{ "Telemetry Host-Initiated Data Area 1 Last Block", 2 },
	{ "Telemetry Host-Initiated Data Area 2 Last Block", 2 },
	{ "Telemetry Host-Initiated Data Area 3 Last Block", 2 },
	{ "Reserved2", 2 },
	{ "Telemetry Host-Initiated Data Area 4 Last Block", 4 },
	{ "Reserved3", 361 },
	{ "Telemetry Controller-Initiated Scope", 1 },
	{ "Telemetry Controller-Initiated Data Available", 1 },
	{ "Telemetry Controller-Initiated Data Generation Number", 1 }
};

struct request_data reason_identifier[] = {
	{ "Error ID", 64 },
	{ "File ID", 8 },
	{ "Line Number", 2 },
	{ "Valid Flags", 1 },
	{ "Reserved", 21 },
	{ "VU Reason Extension", 32 }
};

struct request_data ocp_header_in_da1[] = {
	{ "Major Version", 2 },
	{ "Minor Version", 2 },
	{ "Reserved1", 4 },
	{ "Timestamp", 8 },
	{ "Log page GUID", GUID_LEN },
	{ "Number Telemetry Profiles Supported", 1 },
	{ "Telemetry Profile Selected", 1 },
	{ "Reserved2", 6 },
	{ "Telemetry String Log Size", 8 },
	{ "Reserved3", 8 },
	{ "Firmware Revision", 8 },
	{ "Reserved4", 32 },
	{ "Data Area 1 Statistic Start", 8 },
	{ "Data Area 1 Statistic Size", 8 },
	{ "Data Area 2 Statistic Start", 8 },
	{ "Data Area 2 Statistic Size", 8 },
	{ "Reserved5", 32 },
	{ "Event FIFO 1 Data Area", 1 },
	{ "Event FIFO 2 Data Area", 1 },
	{ "Event FIFO 3 Data Area", 1 },
	{ "Event FIFO 4 Data Area", 1 },
	{ "Event FIFO 5 Data Area", 1 },
	{ "Event FIFO 6 Data Area", 1 },
	{ "Event FIFO 7 Data Area", 1 },
	{ "Event FIFO 8 Data Area", 1 },
	{ "Event FIFO 9 Data Area", 1 },
	{ "Event FIFO 10 Data Area", 1 },
	{ "Event FIFO 11 Data Area", 1 },
	{ "Event FIFO 12 Data Area", 1 },
	{ "Event FIFO 13 Data Area", 1 },
	{ "Event FIFO 14 Data Area", 1 },
	{ "Event FIFO 15 Data Area", 1 },
	{ "Event FIFO 16 Data Area", 1 },
	{ "Event FIFO 1 Start", 8 },
	{ "Event FIFO 1 Size", 8 },
	{ "Event FIFO 2 Start", 8 },
	{ "Event FIFO 2 Size", 8 },
	{ "Event FIFO 3 Start", 8 },
	{ "Event FIFO 3 Size", 8 },
	{ "Event FIFO 4 Start", 8 },
	{ "Event FIFO 4 Size", 8 },
	{ "Event FIFO 5 Start", 8 },
	{ "Event FIFO 5 Size", 8 },
	{ "Event FIFO 6 Start", 8 },
	{ "Event FIFO 6 Size", 8 },
	{ "Event FIFO 7 Start", 8 },
	{ "Event FIFO 7 Size", 8 },
	{ "Event FIFO 8 Start", 8 },
	{ "Event FIFO 8 Size", 8 },
	{ "Event FIFO 9 Start", 8 },
	{ "Event FIFO 9 Size", 8 },
	{ "Event FIFO 10 Start", 8 },
	{ "Event FIFO 10 Size", 8 },
	{ "Event FIFO 11 Start", 8 },
	{ "Event FIFO 11 Size", 8 },
	{ "Event FIFO 12 Start", 8 },
	{ "Event FIFO 12 Size", 8 },
	{ "Event FIFO 13 Start", 8 },
	{ "Event FIFO 13 Size", 8 },
	{ "Event FIFO 14 Start", 8 },
	{ "Event FIFO 14 Size", 8 },
	{ "Event FIFO 15 Start", 8 },
	{ "Event FIFO 15 Size", 8 },
	{ "Event FIFO 16 Start", 8 },
	{ "Event FIFO 16 Size", 8 },
	{ "Reserved6", 80 }
};

struct request_data smart[] = {
	{ "Critical Warning", 1 },
	{ "Composite Temperature", 2 },
	{ "Available Spare", 1 },
	{ "Available Spare Threshold", 1 },
	{ "Percentage Used", 1 },
	{ "Reserved1", 26 },
	{ "Data Units Read", 16 },
	{ "Data Units Written", 16 },
	{ "Host Read Commands", 16 },
	{ "Host Write Commands", 16 },
	{ "Controller Busy Time", 16 },
	{ "Power Cycles", 16 },
	{ "Power On Hours", 16 },
	{ "Unsafe Shutdowns", 16 },
	{ "Media and Data Integrity Errors", 16 },
	{ "Number of Error Information Log Entries", 16 },
	{ "Warning Composite Temperature Time", 4 },
	{ "Critical Composite Temperature Time", 4 },
	{ "Temperature Sensor 1", 2 },
	{ "Temperature Sensor 2", 2 },
	{ "Temperature Sensor 3", 2 },
	{ "Temperature Sensor 4", 2 },
	{ "Temperature Sensor 5", 2 },
	{ "Temperature Sensor 6", 2 },
	{ "Temperature Sensor 7", 2 },
	{ "Temperature Sensor 8", 2 },
	{ "Thermal Management Temperature 1 Transition Count", 4 },
	{ "Thermal Management Temperature 2 Transition Count", 4 },
	{ "Total Time for Thermal Management Temperature 1", 4 },
	{ "Total Time for Thermal Management Temperature 2", 4 },
	{ "Reserved2", 280 }
};

struct request_data smart_extended[] = {
	{ "Physical Media Units Written", 16 },
	{ "Physical Media Units Read", 16 },
	{ "Bad User NAND Blocks Raw Count", 6 },
	{ "Bad User NAND Blocks Normalized Value", 2 },
	{ "Bad System NAND Blocks Raw Count", 6 },
	{ "Bad System NAND Blocks Normalized Value", 2 },
	{ "XOR Recovery Count", 8 },
	{ "Uncorrectable Read Error Count", 8 },
	{ "Soft ECC Error Count", 8 },
	{ "End to End Correction Counts Detected Errors", 4 },
	{ "End to End Correction Counts Corrected Errors", 4 },
	{ "System Data Percent Used", 1 },
	{ "Refresh Counts", 7 },
	{ "Maximum User Data Erase Count", 4 },
	{ "Minimum User Data Erase Count", 4 },
	{ "Number of thermal throttling events", 1 },
	{ "Current Throttling Status", 1 },
	{ "Errata Version Field", 1 },
	{ "Point Version Field", 2 },
	{ "Minor Version Field", 2 },
	{ "Major Version Field", 1 },
	{ "PCIe Correctable Error Count", 8 },
	{ "Incomplete Shutdowns", 4 },
	{ "Reserved1", 4 },
	{ "Percent Free Blocks", 1 },
	{ "Reserved2", 7 },
	{ "Capacitor Health", 2 },
	{ "NVMe Base Errata Version", 1 },
	{ "NVMe Command Set Errata Version", 1 },
	{ "Reserved3", 4 },
	{ "Unaligned IO", 8 },
	{ "Security Version Number", 8 },
	{ "Total NUSE", 8 },
	{ "PLP Start Count", 16 },
	{ "Endurance Estimate", 16 },
	{ "PCIe Link Retraining Count", 8 },
	{ "Power State Change Count", 8 },
	{ "Lowest Permitted Firmware Revision", 8 },
	{ "Reserved4", 278 },
	{ "Log Page Version", 2 },
	{ "Log page GUID", GUID_LEN }
};

void json_add_formatted_u32_str(struct json_object *pobject, const char *msg, unsigned int pdata)
{
	char data_str[70] = { 0 };

	sprintf(data_str, "0x%x", pdata);
	json_object_add_value_string(pobject, msg, data_str);
}

void json_add_formatted_var_size_str(struct json_object *pobject, const char *msg, __u8 *pdata,
	unsigned int data_size)
{
	char *description_str = NULL;
	char temp_buffer[3] = { 0 };

	/* Allocate 2 chars for each value in the data + 2 bytes for the null terminator */
	description_str = (char *) calloc(1, data_size*2 + 2);
	if (!description_str) {
		nvme_show_error("Failed to allocate description buffer");
		return;
	}

	for (size_t i = 0; i < data_size; ++i) {
		sprintf(temp_buffer, "%02X", pdata[i]);
		strcat(description_str, temp_buffer);
	}

	json_object_add_value_string(pobject, msg, description_str);
	free(description_str);
}

int get_telemetry_das_offset_and_size(
	struct nvme_ocp_telemetry_common_header *ptelemetry_common_header,
	struct nvme_ocp_telemetry_offsets *ptelemetry_das_offset)
{
	if (NULL == ptelemetry_common_header || NULL == ptelemetry_das_offset) {
		nvme_show_error("Invalid input arguments.");
		return -1;
	}

	if (ptelemetry_common_header->log_id == NVME_LOG_LID_TELEMETRY_HOST)
		ptelemetry_das_offset->header_size =
		sizeof(struct nvme_ocp_telemetry_host_initiated_header);
	else if (ptelemetry_common_header->log_id == NVME_LOG_LID_TELEMETRY_CTRL)
		ptelemetry_das_offset->header_size =
		sizeof(struct nvme_ocp_telemetry_controller_initiated_header);
	else
		return -1;

	__u16 da1_last_block = le16_to_cpu(ptelemetry_common_header->da1_last_block);
	__u16 da2_last_block = le16_to_cpu(ptelemetry_common_header->da2_last_block);
	__u16 da3_last_block = le16_to_cpu(ptelemetry_common_header->da3_last_block);
	__u32 da4_last_block = le32_to_cpu(ptelemetry_common_header->da4_last_block);

	ptelemetry_das_offset->da1_start_offset = ptelemetry_das_offset->header_size;
	ptelemetry_das_offset->da1_size = da1_last_block * OCP_TELEMETRY_DATA_BLOCK_SIZE;

	ptelemetry_das_offset->da2_start_offset = ptelemetry_das_offset->da1_start_offset +
		ptelemetry_das_offset->da1_size;
	ptelemetry_das_offset->da2_size =
		(da2_last_block - da1_last_block) * OCP_TELEMETRY_DATA_BLOCK_SIZE;

	ptelemetry_das_offset->da3_start_offset = ptelemetry_das_offset->da2_start_offset +
		ptelemetry_das_offset->da2_size;
	ptelemetry_das_offset->da3_size =
		(da3_last_block - da2_last_block) * OCP_TELEMETRY_DATA_BLOCK_SIZE;

	ptelemetry_das_offset->da4_start_offset = ptelemetry_das_offset->da3_start_offset +
		ptelemetry_das_offset->da3_size;
	ptelemetry_das_offset->da4_size =
		(da4_last_block - da3_last_block) * OCP_TELEMETRY_DATA_BLOCK_SIZE;

	return 0;
}

/*
 * Device tables store ascii_id_length as the zero-based index of the last
 * character, so the byte count is length + 1. Keep the copy bounded to the
 * fixed caller buffers used throughout the telemetry parser.
 */
static size_t ocp_ascii_id_copy_len(__u8 ascii_id_length)
{
	size_t copy_len = (size_t)ascii_id_length + 1;

	if (copy_len >= OCP_TELEMETRY_DESCRIPTION_MAX)
		copy_len = OCP_TELEMETRY_DESCRIPTION_MAX - 1;

	return copy_len;
}

int get_statistic_id_ascii_string(int identifier, char *description)
{
	if (!pstring_buffer || !description)
		return -1;

	struct nvme_ocp_telemetry_string_header *pocp_ts_header =
		(struct nvme_ocp_telemetry_string_header *)pstring_buffer;

	//Calculating the sizes of the tables. Note: Data is present in the form of DWORDS,
	//So multiplying with sizeof(DWORD)
	unsigned long long sits_table_size = le64_to_cpu(pocp_ts_header->sitsz) * SIZE_OF_DWORD;

	//Calculating number of entries present in all 3 tables
	int sits_entries = (int)sits_table_size /
		sizeof(struct nvme_ocp_statistics_identifier_string_table);

	for (int sits_entry = 0; sits_entry < sits_entries; sits_entry++) {
		struct nvme_ocp_statistics_identifier_string_table
			*peach_statistic_entry =
			(struct nvme_ocp_statistics_identifier_string_table *)
			(pstring_buffer + (le64_to_cpu(pocp_ts_header->sits) * SIZE_OF_DWORD) +
			(sits_entry *
			sizeof(struct nvme_ocp_statistics_identifier_string_table)));

		if (identifier ==
		    (int)le16_to_cpu(peach_statistic_entry->vs_statistic_identifier)) {
			char *pdescription = (char *)(pstring_buffer +
				(le64_to_cpu(pocp_ts_header->ascts) * SIZE_OF_DWORD) +
				(le64_to_cpu(peach_statistic_entry->ascii_id_offset) *
				SIZE_OF_DWORD));
			size_t copy_len = ocp_ascii_id_copy_len(
				peach_statistic_entry->ascii_id_length);

			memcpy(description, pdescription, copy_len);
			description[copy_len] = '\0';

			return 0;
		}
	}

	// If ASCII string isn't found, see in our internal Map
	// for 2.5 Spec defined strings
	if (identifier <= 0x6F) {
		strcpy(description, statistic_identifiers_map[identifier].description);
		return 0;
	}

	return -1;
}

int get_event_id_ascii_string(int identifier, int debug_event_class, char *description)
{
	if (pstring_buffer == NULL)
		return -1;

	struct nvme_ocp_telemetry_string_header *pocp_ts_header =
		(struct nvme_ocp_telemetry_string_header *)pstring_buffer;

	//Calculating the sizes of the tables. Note: Data is present in the form of DWORDS,
	//So multiplying with sizeof(DWORD)
	unsigned long long ests_table_size = le64_to_cpu(pocp_ts_header->estsz) * SIZE_OF_DWORD;

	//Calculating number of entries present in all 3 tables
	int ests_entries = (int)ests_table_size / sizeof(struct nvme_ocp_event_string_table);

	for (int ests_entry = 0; ests_entry < ests_entries; ests_entry++) {
		struct nvme_ocp_event_string_table *peach_event_entry =
			(struct nvme_ocp_event_string_table *)
			(pstring_buffer + (le64_to_cpu(pocp_ts_header->ests) * SIZE_OF_DWORD) +
			(ests_entry * sizeof(struct nvme_ocp_event_string_table)));

		if (identifier == (int)le16_to_cpu(peach_event_entry->event_identifier) &&
			debug_event_class == (int)peach_event_entry->debug_event_class) {
			char *pdescription = (char *)(pstring_buffer +
				(le64_to_cpu(pocp_ts_header->ascts) * SIZE_OF_DWORD) +
				(le64_to_cpu(peach_event_entry->ascii_id_offset) * SIZE_OF_DWORD));
			size_t copy_len = ocp_ascii_id_copy_len(
				peach_event_entry->ascii_id_length);

			memcpy(description, pdescription, copy_len);
			description[copy_len] = '\0';
			return 0;
		}
	}

	return -1;
}

int get_vu_event_id_ascii_string(int identifier, int debug_event_class, char *description)
{
	if (pstring_buffer == NULL)
		return -1;

	struct nvme_ocp_telemetry_string_header *pocp_ts_header =
		(struct nvme_ocp_telemetry_string_header *)pstring_buffer;

	//Calculating the sizes of the tables. Note: Data is present in the form of DWORDS,
	//So multiplying with sizeof(DWORD)
	unsigned long long vuests_table_size =
		le64_to_cpu(pocp_ts_header->vu_estsz) * SIZE_OF_DWORD;

	//Calculating number of entries present in all 3 tables
	int vu_ests_entries = (int)vuests_table_size /
		sizeof(struct nvme_ocp_vu_event_string_table);

	for (int vu_ests_entry = 0; vu_ests_entry < vu_ests_entries; vu_ests_entry++) {
		struct nvme_ocp_vu_event_string_table *peach_vu_event_entry =
			(struct nvme_ocp_vu_event_string_table *)
			(pstring_buffer + (le64_to_cpu(pocp_ts_header->vu_ests) * SIZE_OF_DWORD) +
			(vu_ests_entry * sizeof(struct nvme_ocp_vu_event_string_table)));

		if (identifier == (int)le16_to_cpu(peach_vu_event_entry->vu_event_identifier) &&
			debug_event_class ==
				(int)peach_vu_event_entry->debug_event_class) {
			char *pdescription = (char *)(pstring_buffer +
				(le64_to_cpu(pocp_ts_header->ascts) * SIZE_OF_DWORD) +
				(le64_to_cpu(peach_vu_event_entry->ascii_id_offset) *
				SIZE_OF_DWORD));
			size_t copy_len = ocp_ascii_id_copy_len(
				peach_vu_event_entry->ascii_id_length);

			memcpy(description, pdescription, copy_len);
			description[copy_len] = '\0';
			return 0;
		}
	}

	return -1;
}

int parse_ocp_telemetry_string_log(int event_fifo_num, int identifier, int debug_event_class,
	enum ocp_telemetry_string_tables string_table, char *description)
{
	if (pstring_buffer == NULL)
		return -1;

	if (event_fifo_num != 0) {
		struct nvme_ocp_telemetry_string_header *pocp_ts_header =
			(struct nvme_ocp_telemetry_string_header *)pstring_buffer;

		if (*pocp_ts_header->fifo_ascii_string[event_fifo_num-1] != '\0')
			memcpy(description, pocp_ts_header->fifo_ascii_string[event_fifo_num-1],
			       16);
		else
			description[0] = '\0';

		return 0;
	}

	if (string_table == STATISTICS_IDENTIFIER_STRING)
		get_statistic_id_ascii_string(identifier, description);
	else if (string_table == EVENT_STRING && debug_event_class < 0x80)
		get_event_id_ascii_string(identifier, debug_event_class, description);
	else if (string_table == VU_EVENT_STRING || debug_event_class >= 0x80)
		get_vu_event_id_ascii_string(identifier, debug_event_class, description);

	return 0;
}

int parse_time_stamp_event(
		struct nvme_ocp_telemetry_event_descriptor *pevent_descriptor,
		struct json_object *pevent_descriptor_obj,
		__u8 *pevent_specific_data,
		struct json_object *pevent_fifos_object,
		FILE *fp)
{
	struct nvme_ocp_time_stamp_dbg_evt_class_format *ptime_stamp_event =
		(struct nvme_ocp_time_stamp_dbg_evt_class_format *) pevent_specific_data;
	struct nvme_ocp_common_dbg_evt_class_vu_data *ptime_stamp_event_vu_data = NULL;
	__u16 vu_event_id = 0;
	__u8 *pdata = NULL;
	char description_str[OCP_TELEMETRY_DESCRIPTION_MAX] = "";
	unsigned int vu_data_size = 0;
	bool vu_data_present = false;

	if ((pevent_descriptor->event_data_size * SIZE_OF_DWORD) >
		 sizeof(struct nvme_ocp_time_stamp_dbg_evt_class_format)) {
		vu_data_present = true;
		vu_data_size =
			((pevent_descriptor->event_data_size * SIZE_OF_DWORD) -
			 (sizeof(struct nvme_ocp_time_stamp_dbg_evt_class_format) +
			 SIZE_OF_VU_EVENT_ID));

		ptime_stamp_event_vu_data =
			(struct nvme_ocp_common_dbg_evt_class_vu_data *)((char *)ptime_stamp_event +
			sizeof(struct nvme_ocp_time_stamp_dbg_evt_class_format));
		vu_event_id = le16_to_cpu(ptime_stamp_event_vu_data->vu_event_identifier);
		pdata = (__u8 *)&(ptime_stamp_event_vu_data->data);

		parse_ocp_telemetry_string_log(0, vu_event_id,
			pevent_descriptor->debug_event_class_type,
			VU_EVENT_STRING, description_str);
	}  else if (pevent_descriptor->event_data_size < 2)
		return -1;

	if (pevent_fifos_object != NULL) {
		json_add_formatted_var_size_str(pevent_descriptor_obj, STR_CLASS_SPECIFIC_DATA,
						ptime_stamp_event->time_stamp, DATA_SIZE_8);
		if (vu_data_present) {
			json_add_formatted_u32_str(pevent_descriptor_obj, STR_VU_EVENT_ID_STRING,
						   vu_event_id);
			json_object_add_value_string(pevent_descriptor_obj, STR_VU_EVENT_STRING,
							 description_str);
			json_add_formatted_var_size_str(pevent_descriptor_obj, STR_VU_DATA, pdata,
							vu_data_size);
		}
	} else {
		if (fp) {
			print_formatted_var_size_str(STR_CLASS_SPECIFIC_DATA,
					     ptime_stamp_event->time_stamp, DATA_SIZE_8, fp);
			if (vu_data_present) {
				fprintf(fp, "%s: 0x%x\n", STR_VU_EVENT_ID_STRING, vu_event_id);
				fprintf(fp, "%s: %s\n", STR_VU_EVENT_STRING, description_str);
				print_formatted_var_size_str(STR_VU_DATA, pdata, vu_data_size, fp);
			}
		} else {
			print_formatted_var_size_str(STR_CLASS_SPECIFIC_DATA,
				ptime_stamp_event->time_stamp, DATA_SIZE_8, fp);
			if (vu_data_present) {
				printf("%s: 0x%x\n", STR_VU_EVENT_ID_STRING, vu_event_id);
				printf("%s: %s\n", STR_VU_EVENT_STRING, description_str);
				print_formatted_var_size_str(STR_VU_DATA, pdata, vu_data_size, fp);
			}
		}
	}

	return 0;
}

int parse_pcie_event(
		struct nvme_ocp_telemetry_event_descriptor *pevent_descriptor,
		struct json_object *pevent_descriptor_obj,
		__u8 *pevent_specific_data,
		struct json_object *pevent_fifos_object,
		FILE *fp)
{
	struct nvme_ocp_pcie_dbg_evt_class_format *ppcie_event =
				(struct nvme_ocp_pcie_dbg_evt_class_format *) pevent_specific_data;
	struct nvme_ocp_common_dbg_evt_class_vu_data *ppcie_event_vu_data = NULL;
	__u16 vu_event_id = 0;
	__u8 *pdata = NULL;
	char description_str[OCP_TELEMETRY_DESCRIPTION_MAX] = "";
	unsigned int vu_data_size = 0;
	bool vu_data_present = false;

	if ((pevent_descriptor->event_data_size * SIZE_OF_DWORD) >
		 sizeof(struct nvme_ocp_pcie_dbg_evt_class_format)) {
		vu_data_present = true;
		vu_data_size =
			((pevent_descriptor->event_data_size * SIZE_OF_DWORD) -
			(sizeof(struct nvme_ocp_pcie_dbg_evt_class_format) +
			SIZE_OF_VU_EVENT_ID));

		ppcie_event_vu_data =
			(struct nvme_ocp_common_dbg_evt_class_vu_data *)((char *)ppcie_event +
			sizeof(struct nvme_ocp_pcie_dbg_evt_class_format));
		vu_event_id = le16_to_cpu(ppcie_event_vu_data->vu_event_identifier);
		pdata = (__u8 *)&(ppcie_event_vu_data->data);

		parse_ocp_telemetry_string_log(0, vu_event_id,
			pevent_descriptor->debug_event_class_type,
			VU_EVENT_STRING, description_str);
	}  else if (pevent_descriptor->event_data_size < 1)
		return -1;

	if (pevent_fifos_object != NULL) {
		json_add_formatted_var_size_str(pevent_descriptor_obj, STR_CLASS_SPECIFIC_DATA,
						ppcie_event->pCIeDebugEventData, DATA_SIZE_4);
		if (vu_data_present) {
			json_add_formatted_u32_str(pevent_descriptor_obj, STR_VU_EVENT_ID_STRING,
					vu_event_id);
			json_object_add_value_string(pevent_descriptor_obj, STR_VU_EVENT_STRING,
					description_str);
			json_add_formatted_var_size_str(pevent_descriptor_obj, STR_VU_DATA, pdata,
					vu_data_size);
		}
	} else {
		if (fp) {
			print_formatted_var_size_str(STR_CLASS_SPECIFIC_DATA,
					     ppcie_event->pCIeDebugEventData, DATA_SIZE_4, fp);
			if (vu_data_present) {
				fprintf(fp, "%s: 0x%x\n", STR_VU_EVENT_ID_STRING, vu_event_id);
				fprintf(fp, "%s: %s\n", STR_VU_EVENT_STRING, description_str);
				print_formatted_var_size_str(STR_VU_DATA, pdata, vu_data_size, fp);
			}
		} else {
			print_formatted_var_size_str(STR_CLASS_SPECIFIC_DATA,
					     ppcie_event->pCIeDebugEventData, DATA_SIZE_4, fp);
			if (vu_data_present) {
				printf("%s: 0x%x\n", STR_VU_EVENT_ID_STRING, vu_event_id);
				printf("%s: %s\n", STR_VU_EVENT_STRING, description_str);
				print_formatted_var_size_str(STR_VU_DATA, pdata, vu_data_size, fp);
			}
		}
	}

	return 0;
}

int parse_nvme_event(
		struct nvme_ocp_telemetry_event_descriptor *pevent_descriptor,
		struct json_object *pevent_descriptor_obj,
		__u8 *pevent_specific_data,
		struct json_object *pevent_fifos_object,
		FILE *fp)
{
	struct nvme_ocp_nvme_dbg_evt_class_format *pnvme_event =
				(struct nvme_ocp_nvme_dbg_evt_class_format *) pevent_specific_data;
	struct nvme_ocp_common_dbg_evt_class_vu_data *pnvme_event_vu_data = NULL;
	__u16 vu_event_id = 0;
	__u8 *pdata = NULL;
	char description_str[OCP_TELEMETRY_DESCRIPTION_MAX] = "";
	unsigned int vu_data_size = 0;
	bool vu_data_present = false;

	if ((pevent_descriptor->event_data_size * SIZE_OF_DWORD) >
		 sizeof(struct nvme_ocp_nvme_dbg_evt_class_format)) {
		vu_data_present = true;
		vu_data_size =
			((pevent_descriptor->event_data_size * SIZE_OF_DWORD) -
			(sizeof(struct nvme_ocp_nvme_dbg_evt_class_format) +
			SIZE_OF_VU_EVENT_ID));
		pnvme_event_vu_data =
			(struct nvme_ocp_common_dbg_evt_class_vu_data *)((char *)pnvme_event +
			sizeof(struct nvme_ocp_nvme_dbg_evt_class_format));

		vu_event_id = le16_to_cpu(pnvme_event_vu_data->vu_event_identifier);
		pdata = (__u8 *)&(pnvme_event_vu_data->data);

		parse_ocp_telemetry_string_log(0, vu_event_id,
			pevent_descriptor->debug_event_class_type,
			VU_EVENT_STRING,
			description_str);
	} else if (pevent_descriptor->event_data_size < 2)
		return -1;

	if (pevent_fifos_object != NULL) {
		json_add_formatted_var_size_str(pevent_descriptor_obj, STR_CLASS_SPECIFIC_DATA,
			pnvme_event->nvmeDebugEventData, DATA_SIZE_8);
		if (vu_data_present) {
			json_add_formatted_u32_str(pevent_descriptor_obj, STR_VU_EVENT_ID_STRING,
						   vu_event_id);
			json_object_add_value_string(pevent_descriptor_obj, STR_VU_EVENT_STRING,
							 description_str);
			json_add_formatted_var_size_str(pevent_descriptor_obj, STR_VU_DATA, pdata,
							vu_data_size);
		}
	} else {
		if (fp) {
			print_formatted_var_size_str(STR_CLASS_SPECIFIC_DATA,
					     pnvme_event->nvmeDebugEventData, DATA_SIZE_8, fp);
			if (vu_data_present) {
				fprintf(fp, "%s: 0x%x\n", STR_VU_EVENT_ID_STRING, vu_event_id);
				fprintf(fp, "%s: %s\n", STR_VU_EVENT_STRING, description_str);
				print_formatted_var_size_str(STR_VU_DATA, pdata, vu_data_size, fp);
			}
		} else {
			print_formatted_var_size_str(STR_CLASS_SPECIFIC_DATA,
					      pnvme_event->nvmeDebugEventData, DATA_SIZE_8, fp);
			if (vu_data_present) {
				printf("%s: 0x%x\n", STR_VU_EVENT_ID_STRING, vu_event_id);
				printf("%s: %s\n", STR_VU_EVENT_STRING, description_str);
				print_formatted_var_size_str(STR_VU_DATA, pdata, vu_data_size, fp);
			}
		}
	}

	return 0;
}

void parse_common_event(struct nvme_ocp_telemetry_event_descriptor *pevent_descriptor,
			    struct json_object *pevent_descriptor_obj, __u8 *pevent_specific_data,
			    struct json_object *pevent_fifos_object, FILE *fp)
{
	if (pevent_specific_data) {
		struct nvme_ocp_common_dbg_evt_class_vu_data *pcommon_debug_event_vu_data =
			(struct nvme_ocp_common_dbg_evt_class_vu_data *) pevent_specific_data;

		__u16 vu_event_id = le16_to_cpu(pcommon_debug_event_vu_data->vu_event_identifier);
		char description_str[OCP_TELEMETRY_DESCRIPTION_MAX] = "";
		__u8 *pdata = (__u8 *)&(pcommon_debug_event_vu_data->data);

		unsigned int vu_data_size = ((pevent_descriptor->event_data_size *
			SIZE_OF_DWORD) - SIZE_OF_VU_EVENT_ID);

		parse_ocp_telemetry_string_log(0, vu_event_id,
			pevent_descriptor->debug_event_class_type,
			VU_EVENT_STRING, description_str);

		if (pevent_fifos_object != NULL) {
			json_add_formatted_u32_str(pevent_descriptor_obj, STR_VU_EVENT_ID_STRING,
						   vu_event_id);
			json_object_add_value_string(pevent_descriptor_obj, STR_VU_EVENT_STRING,
							 description_str);
			json_add_formatted_var_size_str(pevent_descriptor_obj, STR_VU_DATA, pdata,
							vu_data_size);
		} else {
			if (fp) {
				fprintf(fp, "%s: 0x%x\n", STR_VU_EVENT_ID_STRING, vu_event_id);
				fprintf(fp, "%s: %s\n", STR_VU_EVENT_STRING, description_str);
				print_formatted_var_size_str(STR_VU_DATA, pdata, vu_data_size, fp);
			} else {
				printf("%s: 0x%x\n", STR_VU_EVENT_ID_STRING, vu_event_id);
				printf("%s: %s\n", STR_VU_EVENT_STRING, description_str);
				print_formatted_var_size_str(STR_VU_DATA, pdata, vu_data_size, fp);
			}
		}
	}
}

int parse_media_wear_event(
		struct nvme_ocp_telemetry_event_descriptor *pevent_descriptor,
		struct json_object *pevent_descriptor_obj,
		__u8 *pevent_specific_data,
		struct json_object *pevent_fifos_object,
		FILE *fp)
{
	struct nvme_ocp_media_wear_dbg_evt_class_format *pmedia_wear_event =
			(struct nvme_ocp_media_wear_dbg_evt_class_format *) pevent_specific_data;
	struct nvme_ocp_common_dbg_evt_class_vu_data *pmedia_wear_event_vu_data = NULL;

	__u16 vu_event_id = 0;
	__u8 *pdata = NULL;
	char description_str[OCP_TELEMETRY_DESCRIPTION_MAX] = "";
	unsigned int vu_data_size = 0;
	bool vu_data_present = false;

	if ((pevent_descriptor->event_data_size * SIZE_OF_DWORD) >
		 sizeof(struct nvme_ocp_media_wear_dbg_evt_class_format)) {
		vu_data_present = true;
		vu_data_size =
			((pevent_descriptor->event_data_size * SIZE_OF_DWORD) -
			(sizeof(struct nvme_ocp_media_wear_dbg_evt_class_format) +
			SIZE_OF_VU_EVENT_ID));

		pmedia_wear_event_vu_data =
			(struct nvme_ocp_common_dbg_evt_class_vu_data *)((char *)pmedia_wear_event +
			sizeof(struct nvme_ocp_media_wear_dbg_evt_class_format));
		vu_event_id = le16_to_cpu(pmedia_wear_event_vu_data->vu_event_identifier);
		pdata = (__u8 *)&(pmedia_wear_event_vu_data->data);

		parse_ocp_telemetry_string_log(0, vu_event_id,
			pevent_descriptor->debug_event_class_type,
			VU_EVENT_STRING,
			description_str);
	}  else if (pevent_descriptor->event_data_size < 3)
		return -1;

	if (pevent_fifos_object != NULL) {
		json_add_formatted_var_size_str(pevent_descriptor_obj, STR_CLASS_SPECIFIC_DATA,
						pmedia_wear_event->currentMediaWear, DATA_SIZE_12);
		if (vu_data_present) {
			json_add_formatted_u32_str(pevent_descriptor_obj, STR_VU_EVENT_ID_STRING,
					vu_event_id);
			json_object_add_value_string(pevent_descriptor_obj, STR_VU_EVENT_STRING,
					description_str);
			json_add_formatted_var_size_str(pevent_descriptor_obj, STR_VU_DATA, pdata,
					vu_data_size);
		}
	} else {
		if (fp) {
			print_formatted_var_size_str(STR_CLASS_SPECIFIC_DATA,
				      pmedia_wear_event->currentMediaWear, DATA_SIZE_12, fp);
			if (vu_data_present) {
				fprintf(fp, "%s: 0x%x\n", STR_VU_EVENT_ID_STRING, vu_event_id);
				fprintf(fp, "%s: %s\n", STR_VU_EVENT_STRING, description_str);
				print_formatted_var_size_str(STR_VU_DATA, pdata, vu_data_size, fp);
			}
		} else {
			print_formatted_var_size_str(STR_CLASS_SPECIFIC_DATA,
				     pmedia_wear_event->currentMediaWear, DATA_SIZE_12, NULL);
			if (vu_data_present) {
				printf("%s: 0x%x\n", STR_VU_EVENT_ID_STRING, vu_event_id);
				printf("%s: %s\n", STR_VU_EVENT_STRING, description_str);
				print_formatted_var_size_str(STR_VU_DATA, pdata, vu_data_size, fp);
			}
		}
	}

	return 0;
}

/*
 * The Virtual FIFO Event class (0Bh) carries a single Dword of class specific
 * data and no VU data: a VU Virtual FIFO Identifier and a reserved half-word.
 * The identifier names a virtual FIFO in the String Log's VU event table, and
 * splits into the enclosing physical Event FIFO number and the virtual FIFO
 * number within that physical FIFO.
 */
int parse_virtual_fifo_event(
		struct nvme_ocp_telemetry_event_descriptor *pevent_descriptor,
		struct json_object *pevent_descriptor_obj,
		__u8 *pevent_specific_data,
		struct json_object *pevent_fifos_object,
		FILE *fp)
{
	struct nvme_ocp_virtual_fifo_dbg_evt_class_format *pvirtual_fifo_event =
		(struct nvme_ocp_virtual_fifo_dbg_evt_class_format *)
		pevent_specific_data;
	char description_str[OCP_TELEMETRY_DESCRIPTION_MAX] = "";
	char fifo_name_str[OCP_TELEMETRY_DESCRIPTION_MAX] = "";
	__u16 vu_virtual_fifo_id = 0;
	__u8 physical_fifo_num = 0;
	__u16 virtual_fifo_num = 0;

	if ((pevent_descriptor->event_data_size * SIZE_OF_DWORD) <
			sizeof(*pvirtual_fifo_event))
		return -1;

	vu_virtual_fifo_id =
		le16_to_cpu(pvirtual_fifo_event->vu_virtual_fifo_identifier);
	physical_fifo_num = vu_virtual_fifo_id >> VU_VIRTUAL_FIFO_PHY_NUM_SHIFT;
	virtual_fifo_num = vu_virtual_fifo_id & VU_VIRTUAL_FIFO_NUM_MASK;

	parse_ocp_telemetry_string_log(0, vu_virtual_fifo_id,
		pevent_descriptor->debug_event_class_type,
		VU_EVENT_STRING, description_str);

	/*
	 * A physical FIFO number of 0h is invalid and the field is wide enough
	 * to hold values past the 10h maximum, so range-check it before using
	 * it to index the string log's FIFO name array.
	 */
	if (physical_fifo_num >= 1 && physical_fifo_num <= MAX_NUM_FIFOS)
		parse_ocp_telemetry_string_log(physical_fifo_num, 0, 0,
			EVENT_STRING, fifo_name_str);

	if (pevent_fifos_object != NULL) {
		json_add_formatted_u32_str(pevent_descriptor_obj,
					   STR_VU_VIRTUAL_FIFO_ID,
					   vu_virtual_fifo_id);
		json_object_add_value_string(pevent_descriptor_obj,
					      STR_VU_VIRTUAL_FIFO_STRING,
					      description_str);
		json_add_formatted_u32_str(pevent_descriptor_obj,
					   STR_PHYSICAL_EVENT_FIFO_NUM,
					   physical_fifo_num);
		json_object_add_value_string(pevent_descriptor_obj,
					      STR_PHYSICAL_EVENT_FIFO_STRING,
					      fifo_name_str);
		json_add_formatted_u32_str(pevent_descriptor_obj,
					   STR_VIRTUAL_FIFO_NUM,
					   virtual_fifo_num);
	} else if (fp) {
		fprintf(fp, "%s: 0x%x\n", STR_VU_VIRTUAL_FIFO_ID,
			vu_virtual_fifo_id);
		fprintf(fp, "%s: %s\n", STR_VU_VIRTUAL_FIFO_STRING,
			description_str);
		fprintf(fp, "%s: 0x%x\n", STR_PHYSICAL_EVENT_FIFO_NUM,
			physical_fifo_num);
		fprintf(fp, "%s: %s\n", STR_PHYSICAL_EVENT_FIFO_STRING,
			fifo_name_str);
		fprintf(fp, "%s: 0x%x\n", STR_VIRTUAL_FIFO_NUM,
			virtual_fifo_num);
	} else {
		printf("%s: 0x%x\n", STR_VU_VIRTUAL_FIFO_ID,
		       vu_virtual_fifo_id);
		printf("%s: %s\n", STR_VU_VIRTUAL_FIFO_STRING,
		       description_str);
		printf("%s: 0x%x\n", STR_PHYSICAL_EVENT_FIFO_NUM,
		       physical_fifo_num);
		printf("%s: %s\n", STR_PHYSICAL_EVENT_FIFO_STRING,
		       fifo_name_str);
		printf("%s: 0x%x\n", STR_VIRTUAL_FIFO_NUM,
		       virtual_fifo_num);
	}

	return 0;
}

/*
 * A VU Event Identifier and VU Data follow a class's fixed record when its
 * Event Data Size reaches past it. @vu_data_size excludes the identifier.
 */
static void parse_class_vu_fields(
		struct nvme_ocp_telemetry_event_descriptor *pevent_descriptor,
		struct json_object *pevent_descriptor_obj,
		__u8 *pvu_fields, unsigned int vu_data_size,
		struct json_object *pevent_fifos_object,
		FILE *fp)
{
	struct nvme_ocp_common_dbg_evt_class_vu_data *pvu_data =
		(struct nvme_ocp_common_dbg_evt_class_vu_data *)pvu_fields;
	char description_str[OCP_TELEMETRY_DESCRIPTION_MAX] = "";
	__u16 vu_event_id = le16_to_cpu(pvu_data->vu_event_identifier);

	parse_ocp_telemetry_string_log(0, vu_event_id,
		pevent_descriptor->debug_event_class_type,
		VU_EVENT_STRING, description_str);

	if (pevent_fifos_object != NULL) {
		json_add_formatted_u32_str(pevent_descriptor_obj,
					   STR_VU_EVENT_ID_STRING, vu_event_id);
		json_object_add_value_string(pevent_descriptor_obj,
					      STR_VU_EVENT_STRING,
					      description_str);
		json_add_formatted_var_size_str(pevent_descriptor_obj,
						STR_VU_DATA, pvu_data->data,
						vu_data_size);
	} else if (fp) {
		fprintf(fp, "%s: 0x%x\n", STR_VU_EVENT_ID_STRING, vu_event_id);
		fprintf(fp, "%s: %s\n", STR_VU_EVENT_STRING, description_str);
		print_formatted_var_size_str(STR_VU_DATA, pvu_data->data,
					     vu_data_size, fp);
	} else {
		printf("%s: 0x%x\n", STR_VU_EVENT_ID_STRING, vu_event_id);
		printf("%s: %s\n", STR_VU_EVENT_STRING, description_str);
		print_formatted_var_size_str(STR_VU_DATA, pvu_data->data,
					     vu_data_size, NULL);
	}
}

/*
 * The SMBUS/I2C/I3C Debug Event class (0Ch) carries one Dword of class
 * specific data: the SMBUS Debug Event Data and a reserved half-word. The
 * Event Data values are defined only for the NACK error Event ID.
 */
int parse_smbus_event(
		struct nvme_ocp_telemetry_event_descriptor *pevent_descriptor,
		struct json_object *pevent_descriptor_obj,
		__u8 *pevent_specific_data,
		struct json_object *pevent_fifos_object,
		FILE *fp)
{
	struct nvme_ocp_smbus_dbg_evt_class_format *psmbus_event =
		(struct nvme_ocp_smbus_dbg_evt_class_format *)
		pevent_specific_data;
	unsigned int event_size =
		pevent_descriptor->event_data_size * SIZE_OF_DWORD;
	__u16 event_id = le16_to_cpu(pevent_descriptor->event_id);
	const char *event_data_str = NULL;
	__u16 event_data = 0;

	if (event_size < sizeof(*psmbus_event))
		return -1;

	event_data = le16_to_cpu(psmbus_event->smbus_debug_event_data);
	event_data_str = telemetry_smbus_event_data_to_string(event_id,
							      event_data);

	if (pevent_fifos_object != NULL) {
		json_add_formatted_u32_str(pevent_descriptor_obj,
					   STR_SMBUS_DEBUG_EVENT_DATA,
					   event_data);
		json_object_add_value_string(pevent_descriptor_obj,
					      STR_SMBUS_DEBUG_EVENT_DATA_STRING,
					      event_data_str);
	} else if (fp) {
		fprintf(fp, "%s: 0x%x\n", STR_SMBUS_DEBUG_EVENT_DATA,
			event_data);
		fprintf(fp, "%s: %s\n", STR_SMBUS_DEBUG_EVENT_DATA_STRING,
			event_data_str);
	} else {
		printf("%s: 0x%x\n", STR_SMBUS_DEBUG_EVENT_DATA, event_data);
		printf("%s: %s\n", STR_SMBUS_DEBUG_EVENT_DATA_STRING,
		       event_data_str);
	}

	if (event_size > sizeof(*psmbus_event))
		parse_class_vu_fields(pevent_descriptor, pevent_descriptor_obj,
			pevent_specific_data + sizeof(*psmbus_event),
			event_size - sizeof(*psmbus_event) - SIZE_OF_VU_EVENT_ID,
			pevent_fifos_object, fp);

	return 0;
}

/*
 * The MCTP Debug Event class (0Dh) carries two Dwords of class specific
 * data: the MCTP Debug Event Data, whose values depend on the Event ID, the
 * Transport Protocol Information, the Event Flags and the MCTP Transport
 * Header. The header holds captured packet bytes only when the Transport
 * Header Valid flag is set, so it is left out otherwise.
 */
int parse_mctp_event(
		struct nvme_ocp_telemetry_event_descriptor *pevent_descriptor,
		struct json_object *pevent_descriptor_obj,
		__u8 *pevent_specific_data,
		struct json_object *pevent_fifos_object,
		FILE *fp)
{
	struct nvme_ocp_mctp_dbg_evt_class_format *pmctp_event =
		(struct nvme_ocp_mctp_dbg_evt_class_format *)
		pevent_specific_data;
	unsigned int event_size =
		pevent_descriptor->event_data_size * SIZE_OF_DWORD;
	__u16 event_id = le16_to_cpu(pevent_descriptor->event_id);
	const char *event_data_str = NULL;
	const char *protocol_str = NULL;
	bool header_valid = false;
	__u16 event_data = 0;

	if (event_size < sizeof(*pmctp_event))
		return -1;

	event_data = le16_to_cpu(pmctp_event->mctp_debug_event_data);
	event_data_str = telemetry_mctp_event_data_to_string(event_id,
							     event_data);
	protocol_str = telemetry_mctp_transport_protocol_to_string(
		pmctp_event->transport_protocol);
	header_valid = pmctp_event->event_flags &
		MCTP_EVENT_FLAG_TRANSPORT_HEADER_VALID;

	if (pevent_fifos_object != NULL) {
		json_add_formatted_u32_str(pevent_descriptor_obj,
					   STR_MCTP_DEBUG_EVENT_DATA,
					   event_data);
		json_object_add_value_string(pevent_descriptor_obj,
					      STR_MCTP_DEBUG_EVENT_DATA_STRING,
					      event_data_str);
		json_add_formatted_u32_str(pevent_descriptor_obj,
					   STR_MCTP_TRANSPORT_PROTOCOL,
					   pmctp_event->transport_protocol);
		json_object_add_value_string(pevent_descriptor_obj,
					      STR_MCTP_TRANSPORT_PROTOCOL_STRING,
					      protocol_str);
		json_add_formatted_u32_str(pevent_descriptor_obj,
					   STR_MCTP_TRANSPORT_HEADER_VALID,
					   header_valid);
		if (header_valid)
			json_add_formatted_var_size_str(pevent_descriptor_obj,
				STR_MCTP_TRANSPORT_HEADER,
				pmctp_event->transport_header, DATA_SIZE_4);
	} else if (fp) {
		fprintf(fp, "%s: 0x%x\n", STR_MCTP_DEBUG_EVENT_DATA,
			event_data);
		fprintf(fp, "%s: %s\n", STR_MCTP_DEBUG_EVENT_DATA_STRING,
			event_data_str);
		fprintf(fp, "%s: 0x%x\n", STR_MCTP_TRANSPORT_PROTOCOL,
			pmctp_event->transport_protocol);
		fprintf(fp, "%s: %s\n", STR_MCTP_TRANSPORT_PROTOCOL_STRING,
			protocol_str);
		fprintf(fp, "%s: 0x%x\n", STR_MCTP_TRANSPORT_HEADER_VALID,
			header_valid);
		if (header_valid)
			print_formatted_var_size_str(STR_MCTP_TRANSPORT_HEADER,
				pmctp_event->transport_header, DATA_SIZE_4, fp);
	} else {
		printf("%s: 0x%x\n", STR_MCTP_DEBUG_EVENT_DATA, event_data);
		printf("%s: %s\n", STR_MCTP_DEBUG_EVENT_DATA_STRING,
		       event_data_str);
		printf("%s: 0x%x\n", STR_MCTP_TRANSPORT_PROTOCOL,
		       pmctp_event->transport_protocol);
		printf("%s: %s\n", STR_MCTP_TRANSPORT_PROTOCOL_STRING,
		       protocol_str);
		printf("%s: 0x%x\n", STR_MCTP_TRANSPORT_HEADER_VALID,
		       header_valid);
		if (header_valid)
			print_formatted_var_size_str(STR_MCTP_TRANSPORT_HEADER,
				pmctp_event->transport_header, DATA_SIZE_4, NULL);
	}

	if (event_size > sizeof(*pmctp_event))
		parse_class_vu_fields(pevent_descriptor, pevent_descriptor_obj,
			pevent_specific_data + sizeof(*pmctp_event),
			event_size - sizeof(*pmctp_event) - SIZE_OF_VU_EVENT_ID,
			pevent_fifos_object, fp);

	return 0;
}

int parse_event_fifo(unsigned int fifo_num, unsigned char *pfifo_start,
	struct json_object *pevent_fifos_object, unsigned char *pstring_buffer,
	struct nvme_ocp_telemetry_offsets *poffsets, __u64 fifo_size, FILE *fp)
{
	if (NULL == pfifo_start || NULL == poffsets) {
		nvme_show_error("Input buffer was NULL");
		return -1;
	}

	int status = 0, ret = 0;
	unsigned int event_fifo_number = fifo_num + 1;
	char *description = (char *)malloc((40 + 1) * sizeof(char));

	if (!description) {
		nvme_show_error("Failed to allocate description buffer");
		return -1;
	}

	memset(description, 0, 40 + 1);

	status =
		parse_ocp_telemetry_string_log(event_fifo_number, 0, 0, EVENT_STRING, description);

	if (status != 0) {
		nvme_show_error("Failed to get C9 String. status: %d", status);
		ret = -1;
		goto free_desc;
	}

	char event_fifo_name[100] = {0};

	snprintf(event_fifo_name, sizeof(event_fifo_name), "%s%d%s%s", "EVENT FIFO ",
		 event_fifo_number, " - ", description);

	struct json_object *pevent_fifo_array = NULL;

	if (pevent_fifos_object != NULL)
		pevent_fifo_array = json_create_array();
	else {
		char buffer[1024] = {0};

		sprintf(buffer, "%s%s\n%s", STR_LINE, event_fifo_name, STR_LINE);
		if (fp)
			fprintf(fp, "%s", buffer);
		else
			printf("%s", buffer);
	}

	int offset_to_move = 0;
	unsigned int event_des_size = sizeof(struct nvme_ocp_telemetry_event_descriptor);

	while ((fifo_size > 0) && (offset_to_move < fifo_size)) {
		struct nvme_ocp_telemetry_event_descriptor *pevent_descriptor =
			(struct nvme_ocp_telemetry_event_descriptor *)
			(pfifo_start + offset_to_move);

		/* check if at the end of the list */
		if (pevent_descriptor->debug_event_class_type == RESERVED_CLASS_TYPE)
			break;

		__u8 *pevent_specific_data = NULL;
		__u16 event_id = 0;
		char description_str[OCP_TELEMETRY_DESCRIPTION_MAX] = "";
		unsigned int data_size = 0;
		__u64 remaining = fifo_size - offset_to_move;
		bool is_snapshot = pevent_descriptor->debug_event_class_type ==
				STATISTIC_SNAPSHOT_CLASS_TYPE;
		struct nvme_ocp_statistic_snapshot_evt_class_format *psnapshot =
			(struct nvme_ocp_statistic_snapshot_evt_class_format *)
			pevent_descriptor;

		/*
		 * Bound the whole entry by what is left of the FIFO before its
		 * size field or any class specific data is read. A snapshot's
		 * Event ID and Event Data Size bytes are reserved, so its
		 * statistic's identifier and size are reported instead.
		 */
		event_des_size = is_snapshot ? sizeof(*psnapshot) :
			sizeof(struct nvme_ocp_telemetry_event_descriptor);
		if (remaining < event_des_size) {
			nvme_show_error(
				"Invalid entry at offset 0x%x of Event FIFO %u: "
				"class 0x%x needs a %u-byte header, %llu bytes left in FIFO",
				offset_to_move, event_fifo_number,
				pevent_descriptor->debug_event_class_type,
				event_des_size, (unsigned long long)remaining);
			ret = -1;
			goto free_desc;
		}

		/* Data sizes are in Dwords */
		if (is_snapshot)
			data_size = le16_to_cpu(psnapshot->stat_data_size) *
				SIZE_OF_DWORD;
		else
			data_size = pevent_descriptor->event_data_size *
				SIZE_OF_DWORD;
		if (remaining - event_des_size < data_size) {
			nvme_show_error(
				"Invalid entry at offset 0x%x of Event FIFO %u: "
				"class 0x%x, %s 0x%x declares %u data bytes, %llu left in FIFO",
				offset_to_move, event_fifo_number,
				pevent_descriptor->debug_event_class_type,
				is_snapshot ? "Statistic ID" : "Event ID",
				le16_to_cpu(is_snapshot ? psnapshot->stat_id :
					    pevent_descriptor->event_id),
				data_size,
				(unsigned long long)(remaining - event_des_size));
			ret = -1;
			goto free_desc;
		}

		if (!is_snapshot) {
			if (pevent_descriptor->event_data_size > 0)
				pevent_specific_data = (__u8 *)pevent_descriptor + event_des_size;

			event_id = le16_to_cpu(pevent_descriptor->event_id);

			parse_ocp_telemetry_string_log(0, event_id,
				pevent_descriptor->debug_event_class_type, EVENT_STRING,
				description_str);

			struct json_object *pevent_descriptor_obj =
				((pevent_fifos_object != NULL)?json_create_object():NULL);

			if (pevent_descriptor_obj != NULL) {
				json_add_formatted_u32_str(pevent_descriptor_obj,
					STR_DBG_EVENT_CLASS_TYPE,
					pevent_descriptor->debug_event_class_type);
				json_add_formatted_u32_str(pevent_descriptor_obj,
					STR_EVENT_IDENTIFIER, event_id);
				json_object_add_value_string(pevent_descriptor_obj,
					STR_EVENT_STRING, description_str);
				json_add_formatted_u32_str(pevent_descriptor_obj,
					STR_EVENT_DATA_SIZE, pevent_descriptor->event_data_size);

				if (pevent_descriptor->debug_event_class_type >= 0x80)
					json_add_formatted_var_size_str(pevent_descriptor_obj,
						STR_VU_DATA, pevent_specific_data, data_size);
			} else {
				if (fp) {
					fprintf(fp, "%s: 0x%x\n", STR_DBG_EVENT_CLASS_TYPE,
						pevent_descriptor->debug_event_class_type);
					fprintf(fp, "%s: 0x%x\n", STR_EVENT_IDENTIFIER,
						event_id);
					fprintf(fp, "%s: %s\n", STR_EVENT_STRING, description_str);
					fprintf(fp, "%s: 0x%x\n", STR_EVENT_DATA_SIZE,
						pevent_descriptor->event_data_size);
				} else {
					printf("%s: 0x%x\n", STR_DBG_EVENT_CLASS_TYPE,
					   pevent_descriptor->debug_event_class_type);
					printf("%s: 0x%x\n", STR_EVENT_IDENTIFIER,
					   event_id);
					printf("%s: %s\n", STR_EVENT_STRING, description_str);
					printf("%s: 0x%x\n", STR_EVENT_DATA_SIZE,
					   pevent_descriptor->event_data_size);
				}

				if (pevent_descriptor->debug_event_class_type >= 0x80)
					print_formatted_var_size_str(STR_VU_DATA,
						pevent_specific_data, data_size, fp);
			}

			switch (pevent_descriptor->debug_event_class_type) {
			case TIME_STAMP_CLASS_TYPE:
				ret = parse_time_stamp_event(pevent_descriptor,
					pevent_descriptor_obj,
					pevent_specific_data,
					pevent_fifos_object,
					fp);
				break;
			case PCIE_CLASS_TYPE:
				ret = parse_pcie_event(pevent_descriptor,
					pevent_descriptor_obj,
					pevent_specific_data,
					pevent_fifos_object,
					fp);
				break;
			case NVME_CLASS_TYPE:
				ret = parse_nvme_event(pevent_descriptor,
					pevent_descriptor_obj,
					pevent_specific_data,
					pevent_fifos_object,
					fp);
				break;
			case RESET_CLASS_TYPE:
			case BOOT_SEQUENCE_CLASS_TYPE:
			case FIRMWARE_ASSERT_CLASS_TYPE:
			case TEMPERATURE_CLASS_TYPE:
			case MEDIA_CLASS_TYPE:
				parse_common_event(pevent_descriptor,
					pevent_descriptor_obj,
					pevent_specific_data,
					pevent_fifos_object,
					fp);
				ret = 0;
				break;
			case MEDIA_WEAR_CLASS_TYPE:
				ret = parse_media_wear_event(pevent_descriptor,
					pevent_descriptor_obj,
					pevent_specific_data,
					pevent_fifos_object,
					fp);
				break;
			case VIRTUAL_FIFO_EVENT_CLASS_TYPE:
				ret = parse_virtual_fifo_event(
					pevent_descriptor,
					pevent_descriptor_obj,
					pevent_specific_data,
					pevent_fifos_object,
					fp);
				break;
			case SMBUS_I2C_I3C_EVENT_CLASS_TYPE:
				ret = parse_smbus_event(pevent_descriptor,
					pevent_descriptor_obj,
					pevent_specific_data,
					pevent_fifos_object,
					fp);
				break;
			case MCTP_EVENT_CLASS_TYPE:
				ret = parse_mctp_event(pevent_descriptor,
					pevent_descriptor_obj,
					pevent_specific_data,
					pevent_fifos_object,
					fp);
				break;
			case RESERVED_CLASS_TYPE:
				break;
			default:
				/*
				 * Keep the payload of a class with no decoder
				 * visible; vendor unique classes already print
				 * theirs as VU Data.
				 */
				if (pevent_descriptor->debug_event_class_type >= 0x80)
					break;
				if (pevent_descriptor_obj != NULL)
					json_add_formatted_var_size_str(
						pevent_descriptor_obj,
						STR_CLASS_SPECIFIC_DATA,
						pevent_specific_data, data_size);
				else
					print_formatted_var_size_str(
						STR_CLASS_SPECIFIC_DATA,
						pevent_specific_data, data_size,
						fp);
				break;
			}

			if (ret) {
				nvme_show_error(
					"ERROR : OCP : Invalid NVMe Event FIFO entry\n");
				nvme_show_error(
					"FIFO: %d, offset: 0x%x\n",
					event_fifo_number, offset_to_move);
				nvme_show_error(
					"Type: 0x%x, ID: 0x%x, Size: 0x%x\n",
					pevent_descriptor->debug_event_class_type,
					event_id,
					pevent_descriptor->event_data_size);
				goto free_desc;
			}

			if (pevent_descriptor_obj != NULL && pevent_fifo_array != NULL)
				json_array_add_value_object(pevent_fifo_array,
					pevent_descriptor_obj);
			else {
				if (fp)
					fprintf(fp, STR_LINE2);
				else
					printf(STR_LINE2);
			}
		} else {
			parse_ocp_telemetry_string_log(0, event_id,
				pevent_descriptor->debug_event_class_type, EVENT_STRING,
				description_str);

			struct json_object *pevent_descriptor_obj =
				((pevent_fifos_object != NULL) ? json_create_object() : NULL);

			if (pevent_descriptor_obj != NULL) {
				json_add_formatted_u32_str(pevent_descriptor_obj,
					STR_DBG_EVENT_CLASS_TYPE,
					pevent_descriptor->debug_event_class_type);
				json_object_add_value_string(pevent_descriptor_obj,
					STR_EVENT_STRING, description_str);
			} else {
				if (fp) {
					fprintf(fp, "%s: 0x%x\n", STR_DBG_EVENT_CLASS_TYPE,
						pevent_descriptor->debug_event_class_type);
					fprintf(fp, "%s: %s\n", STR_EVENT_STRING, description_str);
				} else {
					printf("%s: 0x%x\n", STR_DBG_EVENT_CLASS_TYPE,
					   pevent_descriptor->debug_event_class_type);
					printf("%s: %s\n", STR_EVENT_STRING, description_str);
				}
			}

			struct nvme_ocp_statistic_snapshot_evt_class_format
				*pStaticSnapshotEvent =
					(struct nvme_ocp_statistic_snapshot_evt_class_format *)
					pevent_descriptor;

			struct json_object *pstats_array =
				((pevent_fifos_object != NULL) ? json_create_array() : NULL);

			if (pStaticSnapshotEvent != NULL &&
				pStaticSnapshotEvent->stat_data_size > 0) {
				__u8 *pstatistic_entry;

				pstatistic_entry =
					(__u8 *)pStaticSnapshotEvent +
					sizeof(struct nvme_ocp_telemetry_event_descriptor);

				parse_statistic(
					(struct nvme_ocp_telemetry_statistic_descriptor *)
						pstatistic_entry,
					pstats_array,
					fp);
			}
		}
		offset_to_move += (data_size + event_des_size);
	}

	if (pevent_fifos_object != NULL && pevent_fifo_array != NULL)
		json_object_add_value_array(pevent_fifos_object, event_fifo_name,
			pevent_fifo_array);

free_desc:
	free(description);
	return ret;
}

/*
 * Data Area 1 always begins with the mandatory OCP DA1 header (which in
 * turn carries the DA1/DA2 statistics and event FIFO offsets/sizes). A
 * controller that has never captured a telemetry log for this type
 * reports Data Area 1 as empty (da1_size == 0); reading the DA1 header,
 * SMART blocks, statistics, or event FIFOs out of the telemetry buffer in
 * that case would run past the end of what was actually fetched/read.
 */
static bool telemetry_da1_header_present(
		struct nvme_ocp_telemetry_offsets *poffsets)
{
	return poffsets->da1_size >= sizeof(struct nvme_ocp_header_in_da1);
}

int parse_event_fifos(struct json_object *root, struct nvme_ocp_telemetry_offsets *poffsets,
	FILE *fp)
{
	if (poffsets == NULL) {
		nvme_show_error("Input buffer was NULL");
		return -1;
	}

	if (!telemetry_da1_header_present(poffsets))
		return 0;

	struct json_object *pevent_fifos_object = NULL;

	if (root != NULL)
		pevent_fifos_object = json_create_object();

	__u8 *pda1_header_offset = ptelemetry_buffer + poffsets->da1_start_offset;//512
	__u8 *pda2_offset = ptelemetry_buffer + poffsets->da2_start_offset;
	struct nvme_ocp_header_in_da1 *pda1_header = (struct nvme_ocp_header_in_da1 *)
		pda1_header_offset;
	struct nvme_ocp_event_fifo_data event_fifo[MAX_NUM_FIFOS];

	for (int fifo_num = 0; fifo_num < MAX_NUM_FIFOS; fifo_num++) {
		event_fifo[fifo_num].event_fifo_num = fifo_num;
		event_fifo[fifo_num].event_fifo_da = pda1_header->event_fifo_da[fifo_num];
		event_fifo[fifo_num].event_fifo_start =
			le64_to_cpu(pda1_header->fifo_offsets[fifo_num].event_fifo_start);
		event_fifo[fifo_num].event_fifo_size =
			le64_to_cpu(pda1_header->fifo_offsets[fifo_num].event_fifo_size);
	}

	//Parse all the FIFOs DA wise
	for (int fifo_no = 0; fifo_no < MAX_NUM_FIFOS; fifo_no++) {
		if (event_fifo[fifo_no].event_fifo_da == poffsets->data_area) {
			__u64 fifo_offset =
				(event_fifo[fifo_no].event_fifo_start  * SIZE_OF_DWORD);
			__u64 fifo_size =
				(event_fifo[fifo_no].event_fifo_size  * SIZE_OF_DWORD);
			__u64 da_size = (poffsets->data_area == 1) ?
				poffsets->da1_size : poffsets->da2_size;
			__u8 *pfifo_start = NULL;

			if (!fifo_size || fifo_offset + fifo_size > da_size) {
				nvme_show_error(
					"Invalid FIFO bounds for FIFO %d",
					fifo_no);
				return -1;
			}

			if (event_fifo[fifo_no].event_fifo_da == 1)
				pfifo_start = pda1_header_offset + fifo_offset;
			else if (event_fifo[fifo_no].event_fifo_da == 2)
				pfifo_start = pda2_offset + fifo_offset;
			else {
				nvme_show_error("Unsupported Data Area:[%d]", poffsets->data_area);
				return -1;
			}

			int status = parse_event_fifo(fifo_no, pfifo_start, pevent_fifos_object,
						      pstring_buffer, poffsets, fifo_size, fp);

			if (status != 0) {
				nvme_show_error("Failed to parse Event FIFO. status:%d", status);
				return -1;
			}
		}
	}

	if (pevent_fifos_object != NULL && root != NULL)
		json_object_add_value_array(root,
			poffsets->data_area == 1 ? STR_DA_1_EVENT_FIFO_INFO :
						   STR_DA_2_EVENT_FIFO_INFO,
			pevent_fifos_object);

	return 0;
}

#define STAT_NESTED_INDENT "    "

/* Where a statistic is printed: a JSON object, or text lines to fp */
struct stat_sink {
	struct json_object *obj;
	FILE *fp;
	const char *indent;
};

static FILE *stat_stream(struct stat_sink *s)
{
	return s->fp ? s->fp : stdout;
}

static void stat_add_hex(struct stat_sink *s, const char *key, __u32 value, int width)
{
	if (s->obj)
		json_add_formatted_u32_str(s->obj, key, value);
	else
		fprintf(stat_stream(s), "%s%s: 0x%0*x\n", s->indent, key, width, value);
}

static void stat_add_str(struct stat_sink *s, const char *key, const char *value)
{
	if (s->obj)
		json_object_add_value_string(s->obj, key, value);
	else
		fprintf(stat_stream(s), "%s%s: %s\n", s->indent, key, value);
}

static void stat_add_data(struct stat_sink *s, const char *key, __u8 *data, unsigned int size)
{
	if (s->obj) {
		json_add_formatted_var_size_str(s->obj, key, data, size);
	} else {
		fputs(s->indent, stat_stream(s));
		print_formatted_var_size_str(key, data, size, stat_stream(s));
	}
}

/* Returns the JSON array to add items to, NULL in text mode */
static struct json_object *stat_list_begin(struct stat_sink *s, const char *key)
{
	struct json_object *array = NULL;

	if (s->obj) {
		array = json_create_array();
		json_object_add_value_array(s->obj, key, array);
	} else {
		fprintf(stat_stream(s), "%s%s:\n", s->indent, key);
	}
	return array;
}

static void stat_item_begin(struct stat_sink *item, struct json_object *array, FILE *fp,
			    const char *indent)
{
	item->obj = array ? json_create_object() : NULL;
	item->fp = fp;
	item->indent = indent;
}

static void stat_item_end(struct stat_sink *item, struct json_object *array)
{
	if (array)
		json_array_add_value_object(array, item->obj);
	else
		fprintf(stat_stream(item), "%s%s", item->indent, STR_LINE2);
}

static __u32 get_le_field(const __u8 *p, unsigned int size)
{
	__u32 value = 0;

	while (size--)
		value = (value << 8) | p[size];
	return value;
}

/* Scope fields by offset into the context data (OCP 2.7 section 4.9.12) */
static const struct {
	__u16 stat_id;
	const char *name;
	__u8 offset;
	__u8 size;
} context_scope_fields[] = {
	{ NAMESPACE_ID_CONTEXT_ID,  STR_CONTEXT_NAMESPACE_ID,  4, 4 },
	{ CONTROLLER_ID_CONTEXT_ID, STR_CONTEXT_CONTROLLER_ID, 6, 2 },
	{ QUEUE_ID_CONTEXT_ID,      STR_CONTEXT_CONTROLLER_ID, 4, 2 },
	{ QUEUE_ID_CONTEXT_ID,      STR_CONTEXT_QUEUE_ID,      6, 2 },
};

static const struct {
	__u16 stat_id;
	const char *percent;
	const char *raw;
} bad_block_statistics[] = {
	{ MAX_DIE_BAD_BLOCK_ID, STR_STATISTICS_WORST_DIE_PERCENT,
	  STR_STATISTICS_WORST_DIE_RAW },
	{ MAX_NAND_CHANNEL_BAD_BLOCK_ID, STR_STATISTICS_WORST_NAND_CHANNEL_PERCENT,
	  STR_STATISTICS_WORST_NAND_CHANNEL_RAW },
	{ MIN_NAND_CHANNEL_BAD_BLOCK_ID, STR_STATISTICS_BEST_NAND_CHANNEL_PERCENT,
	  STR_STATISTICS_BEST_NAND_CHANNEL_RAW },
};

static bool is_context_scope_id(__u16 id)
{
	return id >= NAMESPACE_ID_CONTEXT_ID && id <= QUEUE_ID_CONTEXT_ID;
}

static bool is_context_statistic(struct nvme_ocp_telemetry_statistic_descriptor *d)
{
	return d->statistic_info_context_index ||
		is_context_scope_id(le16_to_cpu(d->statistic_id));
}

static void print_statistics(__u8 *pstats, unsigned int size, struct json_object *array,
			     FILE *fp, bool encapsulated, const char *where);

static void parse_context_statistic(__u16 id, __u8 *pdata, unsigned int data_size,
				    struct stat_sink *s)
{
	struct nvme_ocp_statistic_context_data *context =
		(struct nvme_ocp_statistic_context_data *)pdata;
	__u16 context_size = le16_to_cpu(context->context_data_size);
	char where[64];
	struct json_object *array;
	struct stat_sink item;
	size_t i;

	/*
	 * The encapsulated descriptors follow the context data whatever its
	 * declared size, so an invalid Context Data Size is only reported.
	 */
	if (!context_size || context_size > data_size / SIZE_OF_DWORD)
		nvme_show_error("Context Statistic 0x%x: "
				"Context Data Size 0x%x is outside 1 to 0x%x",
				id, context_size, data_size / SIZE_OF_DWORD);

	stat_add_hex(s, STR_CONTEXT_DATA_SIZE, context_size, 0);
	stat_add_hex(s, STR_CONTEXT_DATA_RESERVED, le16_to_cpu(context->reserved), 0);
	stat_add_data(s, STR_CONTEXT_SCOPE, context->scope, sizeof(context->scope));

	if (is_context_scope_id(id)) {
		array = stat_list_begin(s, STR_CONTEXT_SCOPE_FIELDS);
		for (i = 0; i < ARRAY_SIZE(context_scope_fields); i++) {
			__u8 offset = context_scope_fields[i].offset;
			__u8 size = context_scope_fields[i].size;

			if (context_scope_fields[i].stat_id != id)
				continue;
			stat_item_begin(&item, array, s->fp, STAT_NESTED_INDENT);
			stat_add_str(&item, STR_SCOPE_FIELD_STRING, context_scope_fields[i].name);
			stat_add_hex(&item, STR_SCOPE_FIELD_OFFSET, offset, 0);
			stat_add_hex(&item, STR_SCOPE_FIELD_SIZE, size, 0);
			stat_add_hex(&item, STR_SCOPE_FIELD_VALUE,
				     get_le_field(pdata + offset, size), 0);
			stat_item_end(&item, array);
		}
	}

	snprintf(where, sizeof(where),
		 "Encapsulated Statistic Descriptors of Context Statistic 0x%x", id);
	array = stat_list_begin(s, STR_ENCAPSULATED_STATISTICS);
	print_statistics(pdata + sizeof(*context), data_size - sizeof(*context), array, s->fp,
			 true, where);
}

static void print_statistic(struct nvme_ocp_telemetry_statistic_descriptor *pstatistic_entry,
			    struct json_object *pstats_array, FILE *fp, bool encapsulated)
{
	__u16 id = le16_to_cpu(pstatistic_entry->statistic_id);
	__u16 data_dwords = le16_to_cpu(pstatistic_entry->statistic_data_size);
	unsigned int data_size = data_dwords * SIZE_OF_DWORD;
	__u8 *pdata = (__u8 *)pstatistic_entry + sizeof(*pstatistic_entry);
	char description_str[OCP_TELEMETRY_DESCRIPTION_MAX] = "";
	bool context = is_context_statistic(pstatistic_entry);
	struct stat_sink s;
	size_t i;

	parse_ocp_telemetry_string_log(0, id, 0, STATISTICS_IDENTIFIER_STRING, description_str);

	stat_item_begin(&s, pstats_array, fp, encapsulated ? STAT_NESTED_INDENT : "");
	stat_add_hex(&s, STR_STATISTICS_IDENTIFIER, id, 0);
	stat_add_str(&s, STR_STATISTICS_IDENTIFIER_STR, description_str);
	stat_add_hex(&s, STR_STATISTICS_INFO_BEHAVIOUR_TYPE,
		     pstatistic_entry->statistic_info_behaviour_type, 0);
	stat_add_hex(&s, STR_STATISTICS_INFO_CONTEXT_INDEX,
		     pstatistic_entry->statistic_info_context_index, 0);
	stat_add_hex(&s, STR_STATISTICS_INFO_HOST_HINT_TYPE,
		     pstatistic_entry->statistic_info_host_hint_type, 0);
	stat_add_hex(&s, STR_STATISTICS_INFO_RESERVED,
		     pstatistic_entry->statistic_info_reserved, 0);
	stat_add_hex(&s, STR_NAMESPACE_IDENTIFIER, pstatistic_entry->ns_info_nsid, 0);
	stat_add_hex(&s, STR_NAMESPACE_INFO_VALID, pstatistic_entry->ns_info_ns_info_valid, 0);
	stat_add_hex(&s, STR_STATISTICS_DATA_SIZE, data_dwords, 0);
	stat_add_hex(&s, STR_NAMESPACE_IDENTIFIER_15_0,
		     le16_to_cpu(pstatistic_entry->ns_identifier_15_0), 0);

	/* Context Statistic Descriptors do not nest; the walk reports one that does */
	if (context && !encapsulated) {
		if (data_dwords >= CONTEXT_DATA_DWORDS) {
			parse_context_statistic(id, pdata, data_size, &s);
			goto out;
		}
		nvme_show_error("Context Statistic 0x%x: %u data bytes cannot hold "
				"its context data", id, data_size);
	}

	for (i = 0; !context && data_size >= 4 && i < ARRAY_SIZE(bad_block_statistics); i++) {
		if (bad_block_statistics[i].stat_id != id)
			continue;
		stat_add_hex(&s, bad_block_statistics[i].percent, pdata[0], 2);
		stat_add_hex(&s, bad_block_statistics[i].raw, get_le_field(pdata + 2, 2), 4);
		goto out;
	}

	stat_add_data(&s, STR_STATISTICS_SPECIFIC_DATA, pdata, data_size);
out:
	stat_item_end(&s, pstats_array);
}

/*
 * Prints the statistic descriptors in the @size bytes at @pstats, up to the
 * first reserved identifier or the first descriptor that does not fit.
 */
static void print_statistics(__u8 *pstats, unsigned int size, struct json_object *array,
			     FILE *fp, bool encapsulated, const char *where)
{
	struct nvme_ocp_telemetry_statistic_descriptor *pstatistic_entry;
	unsigned int offset = 0, left, data_size;
	__u16 id;

	/* Sizes are in Dwords, so the identifier always fits */
	while (offset < size) {
		pstatistic_entry = (struct nvme_ocp_telemetry_statistic_descriptor *)
			(pstats + offset);
		id = le16_to_cpu(pstatistic_entry->statistic_id);
		left = size - offset;

		if (id == STATISTICS_RESERVED_ID)
			break;
		if (left < sizeof(*pstatistic_entry)) {
			nvme_show_error("Invalid statistic at offset 0x%x of %s: "
					"descriptor needs %zu bytes, %u left",
					offset, where, sizeof(*pstatistic_entry), left);
			break;
		}
		data_size = le16_to_cpu(pstatistic_entry->statistic_data_size) * SIZE_OF_DWORD;
		if (left - sizeof(*pstatistic_entry) < data_size) {
			nvme_show_error("Invalid statistic at offset 0x%x of %s: "
					"Statistic ID 0x%x declares %u data bytes, %zu left",
					offset, where, id, data_size,
					left - sizeof(*pstatistic_entry));
			break;
		}
		if (encapsulated && is_context_statistic(pstatistic_entry))
			nvme_show_error("Invalid statistic at offset 0x%x of %s: "
					"Context Statistic Descriptor 0x%x does not nest",
					offset, where, id);

		print_statistic(pstatistic_entry, array, fp, encapsulated);

		/*
		 * A Context Statistic Descriptor's data size spans its context
		 * data and its encapsulated descriptors.
		 */
		offset += sizeof(*pstatistic_entry) + data_size;
	}
}

int parse_statistic(struct nvme_ocp_telemetry_statistic_descriptor *pstatistic_entry,
		    struct json_object *pstats_array, FILE *fp)
{
	if (pstatistic_entry == NULL) {
		nvme_show_error("Statistics Input buffer was NULL");
		return -1;
	}

	if (le16_to_cpu(pstatistic_entry->statistic_id) == STATISTICS_RESERVED_ID)
		/* End of statistics entries, return -1 to stop processing the buffer */
		return -1;

	print_statistic(pstatistic_entry, pstats_array, fp, false);
	return 0;
}

int parse_statistics(struct json_object *root, struct nvme_ocp_telemetry_offsets *poffsets,
		     FILE *fp)
{
	if (poffsets == NULL) {
		nvme_show_error("Input buffer was NULL");
		return -1;
	}

	if (!telemetry_da1_header_present(poffsets))
		return 0;

	__u8 *pda1_ocp_header_offset = ptelemetry_buffer + poffsets->header_size;//512
	struct nvme_ocp_header_in_da1 *pda1_header =
		(struct nvme_ocp_header_in_da1 *)pda1_ocp_header_offset;
	__u32 statistics_size = 0;
	__u32 stats_da_1_start_dw = 0, stats_da_1_size_dw = 0;
	__u32 stats_da_2_start_dw = 0, stats_da_2_size_dw = 0;
	__u8 *pstats_offset = NULL;
	char where[16];

	if (poffsets->data_area == 1) {
		__u32 stats_da_1_start = le64_to_cpu(pda1_header->da1_statistic_start);
		__u32 stats_da_1_size = le64_to_cpu(pda1_header->da1_statistic_size);

		//Data is present in the form of DWORDS, So multiplying with sizeof(DWORD)
		stats_da_1_start_dw = (stats_da_1_start * SIZE_OF_DWORD);
		stats_da_1_size_dw = (stats_da_1_size * SIZE_OF_DWORD);

		pstats_offset = pda1_ocp_header_offset + stats_da_1_start_dw;
		statistics_size = stats_da_1_size_dw;
	} else if (poffsets->data_area == 2) {
		__u32 stats_da_2_start = le64_to_cpu(pda1_header->da2_statistic_start);
		__u32 stats_da_2_size = le64_to_cpu(pda1_header->da2_statistic_size);

		stats_da_2_start_dw = (stats_da_2_start * SIZE_OF_DWORD);
		stats_da_2_size_dw = (stats_da_2_size * SIZE_OF_DWORD);

		pstats_offset = pda1_ocp_header_offset + poffsets->da1_size + stats_da_2_start_dw;
		statistics_size = stats_da_2_size_dw;
	} else {
		nvme_show_error("Unsupported Data Area:[%d]", poffsets->data_area);
		return -1;
	}

	struct json_object *pstats_array = ((root != NULL) ? json_create_array() : NULL);

	snprintf(where, sizeof(where), "Data Area %d", poffsets->data_area);
	print_statistics(pstats_offset, statistics_size, pstats_array, fp, false, where);

	if (root != NULL && pstats_array != NULL)
		json_object_add_value_array(root,
			poffsets->data_area == 1 ? STR_DA_1_STATS : STR_DA_2_STATS,
			pstats_array);

	return 0;
}

int print_ocp_telemetry_normal(struct ocp_telemetry_parse_options *options)
{
	int status = 0;
	char file_path[PATH_MAX];
	FILE *fp = stdout;

	if (ptelemetry_buffer == NULL) {
		nvme_show_error("No telemetry data to parse.");
		return -1;
	}

	if (options->output_file != NULL) {
		sprintf(file_path, "%s.%s", options->output_file, "txt");
		fp = fopen(file_path, "w");
		if (!fp) {
			nvme_show_error("Failed to open %s file.", file_path);
			return -1;
		}
	}

	fprintf(fp, STR_LINE);
	fprintf(fp, "%s\n", STR_LOG_PAGE_HEADER);
	fprintf(fp, STR_LINE);
	if (!strcmp(options->telemetry_type, "host"))
		generic_structure_parser(ptelemetry_buffer,
			host_log_page_header,
			ARRAY_SIZE(host_log_page_header), NULL, 0, fp);
	else if (!strcmp(options->telemetry_type, "controller"))
		generic_structure_parser(ptelemetry_buffer,
			controller_log_page_header,
			ARRAY_SIZE(controller_log_page_header), NULL, 0, fp);
	fprintf(fp, STR_LINE);
	fprintf(fp, "%s\n", STR_REASON_IDENTIFIER);
	fprintf(fp, STR_LINE);
	__u8 *preason_identifier_offset = ptelemetry_buffer +
		offsetof(struct nvme_ocp_telemetry_host_initiated_header,
			 reason_id);

	generic_structure_parser(preason_identifier_offset, reason_identifier,
		ARRAY_SIZE(reason_identifier), NULL, 0, fp);

	fprintf(fp, STR_LINE);
	fprintf(fp, "%s\n", STR_TELEMETRY_HOST_DATA_BLOCK_1);
	fprintf(fp, STR_LINE);

	//Set DA to 1 and get offsets
	struct nvme_ocp_telemetry_offsets offsets = { 0 };

	offsets.data_area = 1;// Default DA - DA1

	struct nvme_ocp_telemetry_common_header *ptelemetry_common_header =
		(struct nvme_ocp_telemetry_common_header *) ptelemetry_buffer;

	get_telemetry_das_offset_and_size(ptelemetry_common_header, &offsets);

	__u8 *pda1_header_offset = ptelemetry_buffer +
		offsets.da1_start_offset;//512

	if (telemetry_da1_header_present(&offsets)) {
		generic_structure_parser(
			pda1_header_offset, ocp_header_in_da1,
			ARRAY_SIZE(ocp_header_in_da1), NULL, 0, fp);

		fprintf(fp, STR_LINE);
		fprintf(fp, "%s\n", STR_SMART_HEALTH_INFO);
		fprintf(fp, STR_LINE);
		__u8 *pda1_smart_offset = pda1_header_offset +
			offsetof(struct nvme_ocp_header_in_da1,
				 smart_health_info);
		//512+512 =1024

		generic_structure_parser(pda1_smart_offset, smart,
			ARRAY_SIZE(smart), NULL, 0, fp);

		fprintf(fp, STR_LINE);
		fprintf(fp, "%s\n", STR_SMART_HEALTH_INTO_EXTENDED);
		fprintf(fp, STR_LINE);
		__u8 *pda1_smart_ext_offset = pda1_header_offset +
			offsetof(struct nvme_ocp_header_in_da1,
				 smart_health_info_extended);

		generic_structure_parser(
			pda1_smart_ext_offset, smart_extended,
			ARRAY_SIZE(smart_extended), NULL, 0, fp);
	}

	fprintf(fp, STR_LINE);
	fprintf(fp, "%s\n", STR_DA_1_STATS);
	fprintf(fp, STR_LINE);

	status = parse_statistics(NULL, &offsets, fp);
	if (status != 0) {
		nvme_show_error("status: %d", status);
		status = -1;
		goto out;
	}

	fprintf(fp, STR_LINE);
	fprintf(fp, "%s\n", STR_DA_1_EVENT_FIFO_INFO);
	fprintf(fp, STR_LINE);
	status = parse_event_fifos(NULL, &offsets, fp);
	if (status != 0) {
		status = -1;
		goto out;
	}

	//Set the DA to 2
	if (options->data_area >= DATA_AREA_2) {
		offsets.data_area = 2;
		fprintf(fp, STR_LINE);
		fprintf(fp, "%s\n", STR_DA_2_STATS);
		fprintf(fp, STR_LINE);
		status = parse_statistics(NULL, &offsets, fp);
		if (status != 0) {
			nvme_show_error("status: %d", status);
			status = -1;
			goto out;
		}

		fprintf(fp, STR_LINE);
		fprintf(fp, "%s\n", STR_DA_2_EVENT_FIFO_INFO);
		fprintf(fp, STR_LINE);
		status = parse_event_fifos(NULL, &offsets, fp);
		if (status != 0) {
			status = -1;
			goto out;
		}
	}

	fprintf(fp, STR_LINE);
out:
	if (fp != stdout)
		fclose(fp);

	return status;
}

#ifdef CONFIG_JSONC
int print_ocp_telemetry_json(struct ocp_telemetry_parse_options *options)
{
	int status = 0;
	char file_path[PATH_MAX];

	//create json objects
	struct json_object *root, *pheader, *preason_identifier, *da1_header, *smart_obj,
	*ext_smart_obj;

	root = json_create_object();

	//Add data to root json object

	//"Log Page Header"
	pheader = json_create_object();

	generic_structure_parser(ptelemetry_buffer, host_log_page_header,
			     ARRAY_SIZE(host_log_page_header), pheader, 0, NULL);
	json_object_add_value_object(root, STR_LOG_PAGE_HEADER, pheader);

	//"Reason Identifier"
	preason_identifier = json_create_object();

	__u8 *preason_identifier_offset = ptelemetry_buffer +
		offsetof(struct nvme_ocp_telemetry_host_initiated_header, reason_id);

	generic_structure_parser(preason_identifier_offset, reason_identifier,
			     ARRAY_SIZE(reason_identifier), preason_identifier, 0, NULL);
	json_object_add_value_object(pheader, STR_REASON_IDENTIFIER, preason_identifier);

	struct nvme_ocp_telemetry_offsets offsets = { 0 };

	//Set DA to 1 and get offsets
	offsets.data_area = 1;
	struct nvme_ocp_telemetry_common_header *ptelemetry_common_header =
		(struct nvme_ocp_telemetry_common_header *) ptelemetry_buffer;

	get_telemetry_das_offset_and_size(ptelemetry_common_header, &offsets);

	//"Telemetry Host-Initiated Data Block 1"
	__u8 *pda1_header_offset = ptelemetry_buffer + offsets.da1_start_offset;//512

	if (telemetry_da1_header_present(&offsets)) {
		da1_header = json_create_object();

		generic_structure_parser(
			pda1_header_offset, ocp_header_in_da1,
			ARRAY_SIZE(ocp_header_in_da1), da1_header, 0, NULL);
		json_object_add_value_object(root,
					      STR_TELEMETRY_HOST_DATA_BLOCK_1,
					      da1_header);

		//"SMART / Health Information Log(LID-02h)"
		__u8 *pda1_smart_offset = pda1_header_offset +
			offsetof(struct nvme_ocp_header_in_da1,
				 smart_health_info);
		smart_obj = json_create_object();

		generic_structure_parser(pda1_smart_offset, smart,
					  ARRAY_SIZE(smart), smart_obj, 0,
					  NULL);
		json_object_add_value_object(da1_header, STR_SMART_HEALTH_INFO,
					      smart_obj);

		//"SMART / Health Information Extended(LID-C0h)"
		__u8 *pda1_smart_ext_offset = pda1_header_offset +
			offsetof(struct nvme_ocp_header_in_da1,
				 smart_health_info_extended);
		ext_smart_obj = json_create_object();

		generic_structure_parser(
			pda1_smart_ext_offset, smart_extended,
			ARRAY_SIZE(smart_extended), ext_smart_obj, 0, NULL);
		json_object_add_value_object(da1_header,
					      STR_SMART_HEALTH_INTO_EXTENDED,
					      ext_smart_obj);
	}

	//Data Area 1 Statistics
	status = parse_statistics(root, &offsets, NULL);
	if (status != 0) {
		nvme_show_error("status: %d", status);
		status = -1;
		goto out;
	}

	//Data Area 1 Event FIFOs
	status = parse_event_fifos(root, &offsets, NULL);
	if (status != 0) {
		status = -1;
		goto out;
	}

	if (options->data_area >= DATA_AREA_2) {
		//Set the DA to 2
		offsets.data_area = 2;
		//Data Area 2 Statistics
		status = parse_statistics(root, &offsets, NULL);
		if (status != 0) {
			nvme_show_error("status: %d", status);
			status = -1;
			goto out;
		}

		//Data Area 2 Event FIFOs
		status = parse_event_fifos(root, &offsets, NULL);
		if (status != 0) {
			status = -1;
			goto out;
		}
	}

	if (options->output_file != NULL) {
		const char *json_string = json_object_to_json_string(root);
		sprintf(file_path, "%s.%s", options->output_file, "json");
		FILE *fp = fopen(file_path, "w");

		if (fp) {
			fputs(json_string, fp);
			fclose(fp);
		} else {
			nvme_show_error("Failed to open %s file.", file_path);
			status = -1;
		}
	} else {
		//Print root json object
		json_print_object(root, NULL);
		nvme_show_result("\n");
	}

out:
	json_free_object(root);

	return status;
}
#endif /* CONFIG_JSONC */
