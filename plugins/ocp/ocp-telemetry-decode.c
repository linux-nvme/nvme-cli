// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (c) 2024 Western Digital Corporation or its affiliates.
 *
 * Authors: Jeff Lien <jeff.lien@wdc.com>,
 */

#include "common.h"
#include "nvme.h"
#include "libnvme.h"
#include "plugin.h"
#include "linux/types.h"
#include "util/types.h"
#include "nvme-print.h"

#include "ocp-telemetry-decode.h"


void print_vu_event_data(__u32 size, __u8 *data)
{
	int j;
	__u16 vu_event_id = *(__u16 *)data;

	printf("  VU Event ID   : 0x%02x\n", le16_to_cpu(vu_event_id));
	printf("  VU Data       : 0x");
	for (j = 2; j < size; j++)
		printf("%x", data[j]);
	printf("\n\n");
}

void print_stats_desc(struct telemetry_stats_desc *stat_desc)
{
	int j;
	/* Get the statistics Identifier string name and data size  */
	__u16 stat_id = stat_desc->id;
	__u32 stat_data_sz = ((stat_desc->size) * 4);

	printf("Statistics Identifier         : 0x%x, %s\n",
			stat_id, telemetry_stat_id_to_string(stat_id));
	printf("Statistics info               : 0x%x\n", stat_desc->info);
	printf("NS info                       : 0x%x\n", stat_desc->ns_info);
	printf("Statistic Data Size           : 0x%x\n", le16_to_cpu(stat_data_sz));
	printf("Namespace ID[15:0]            : 0x%x\n", stat_desc->nsid);

	if (stat_data_sz > 0) {
		printf("%s  : 0x",
				telemetry_stat_id_to_string(stat_id));
		for (j = 0; j < stat_data_sz; j++)
			printf("%02x", stat_desc->data[j]);
		printf("\n");
	}
	printf("\n");
}

void print_telemetry_fifo_event(__u8 class_type,
		__u16 id, __u8 size_dw, __u8 *data)
{
	int j;
	const char *class_str = NULL;
	__u32 size = size_dw * 4;
	char time_str[40];
	uint64_t timestamp = 0;

	memset((void *)time_str, '\0', 40);

	if (class_type) {
		class_str = telemetry_event_class_to_string(class_type);
		printf("Event Class : %s\n", class_str);
		printf("  Size      : 0x%02x\n", size);
	}

	switch (class_type)	{
	case TELEMETRY_TIMESTAMP_CLASS:
		timestamp = (0x0000FFFFFFFFFFFF & le64_to_cpu(*(uint64_t *)data));

		memset((void *)time_str, 0, 9);
		sprintf((char *)time_str, "%04d:%02d:%02d", (int)(le64_to_cpu(timestamp)/3600),
				(int)((le64_to_cpu(timestamp%3600)/60)),
				(int)(le64_to_cpu(timestamp%60)));

		printf("  Event ID  : 0x%04x %s\n", id, telemetry_ts_event_to_string(id));
		printf("  Timestamp : %s\n", time_str);
		if (size > 8) {
			printf("  VU Data : 0x");
			for (j = 8; j < size; j++)
				printf("%02x", data[j]);
			printf("\n\n");
		}
		break;

	case TELEMETRY_PCIE_CLASS:
		printf("  Event ID : 0x%04x %s\n",
			id, telemetry_pcie_event_id_to_string(id));
		printf("  State    : 0x%02x %s\n",
			data[0], telemetry_pcie_state_data_to_string(data[0]));
		printf("  Speed    : 0x%02x %s\n",
			data[1], telemetry_pcie_speed_data_to_string(data[1]));
		printf("  Width    : 0x%02x %s\n",
			data[2], telemetry_pcie_width_data_to_string(data[2]));
		if (size > 4) {
			printf("  VU Data : ");
			for (j = 4; j < size; j++)
				printf("%x", data[j]);
			printf("\n\n");
		}
		break;

	case TELEMETRY_NVME_CLASS:
		printf("  Event ID          : 0x%04x %s\n",
			id, telemetry_nvme_event_id_to_string(id));
		if ((id == ADMIN_QUEUE_NONZERO_STATUS) ||
			(id == IO_QUEUE_NONZERO_STATUS)) {
			printf("  Cmd Op Code   : 0x%02x\n", data[0]);
			__u16 status;
			__u16 cmd_id;
			__u16 sq_id;

			memcpy(&status, &data[1], sizeof(status));
			memcpy(&cmd_id, &data[3], sizeof(cmd_id));
			memcpy(&sq_id, &data[5], sizeof(sq_id));

			printf("  Status Code   : 0x%04x\n", le16_to_cpu(status));
			printf("  Cmd ID        : 0x%04x\n", le16_to_cpu(cmd_id));
			printf("  SQ ID         : 0x%04x\n", le16_to_cpu(sq_id));
			printf("  LID,FID,Other Cmd Reserved         : 0x%02x\n", data[7]);
		} else if (id == CC_REGISTER_CHANGED) {
			__u32 cc_reg_data = *(__u32 *)data;

			printf("  CC Reg Data   : 0x%08x\n",
					le32_to_cpu(cc_reg_data));
		} else if (id == CSTS_REGISTER_CHANGED) {
			__u32 csts_reg_data = *(__u32 *)data;

			printf("  CSTS Reg Data : 0x%08x\n",
					le32_to_cpu(csts_reg_data));
		} else if (id == OOB_COMMAND) {
			printf("  Cmd Op Code   : 0x%02x\n", data[0]);
			__u16 status;
			memcpy(&status, &data[1], sizeof(status));

			printf("  Admin Cmd Status   : 0x%04x\n", le16_to_cpu(status));
			printf("  NVMe MI SC         : 0x%02x\n", data[3]);
			printf("  Byte1 Req Msg      : 0x%02x\n", data[4]);
			printf("  Byte2 Req Msg      : 0x%02x\n", data[5]);
		} else if (id == OOB_AER_EVENT_MSG_TRANS) {
			__u64 aem = *(__u64 *)data;

			printf("  AEM   : 0x%016"PRIx64"\n",
					le64_to_cpu(aem));
		}
		if (size > 8)
			print_vu_event_data((size-8), (__u8 *)&data[8]);
		break;

	case TELEMETRY_RESET_CLASS:
		printf("  Event ID          : 0x%04x %s\n",
			id, telemetry_reset_event_id_to_string(id));
		if (size)
			print_vu_event_data(size, data);
		break;

	case TELEMETRY_BOOT_SEQ_CLASS:
		printf("  Event ID          : 0x%04x %s\n",
			id, telemetry_boot_seq_event_id_to_string(id));
		if (size)
			print_vu_event_data(size, data);
		break;

	case TELEMETRY_FW_ASSERT_CLASS:
		printf("  Event ID          : 0x%04x %s\n",
			id, telemetry_fw_assert_event_id_to_string(id));
		if (size)
			print_vu_event_data(size, data);
		break;

	case TELEMETRY_TEMPERATURE_CLASS:
		printf("  Event ID          : 0x%04x %s\n",
			id, telemetry_temperature_event_id_to_string(id));
		if (size)
			print_vu_event_data(size, data);
		break;

	case TELEMETRY_MEDIA_DBG_CLASS:
		printf("  Event ID          : 0x%04x %s\n",
			id, telemetry_media_debug_event_id_to_string(id));
		if (size)
			print_vu_event_data(size, data);
		break;

	case TELEMETRY_MEDIA_WEAR_CLASS:
		printf("  Event ID          : 0x%04x %s\n",
			id, telemetry_media_wear_event_id_to_string(id));
		__u32 host_tb_written = *(__u32 *)&data[0];
		__u32 media_tb_written = *(__u32 *)&data[4];
		__u32 media_tb_erased = *(__u32 *)&data[8];

		printf("  Host TB Written   : 0x%04x\n",
			le16_to_cpu(host_tb_written));
		printf("  Media TB Written  : 0x%04x\n",
			le16_to_cpu(media_tb_written));
		printf("  Media TB Erased   : 0x%04x\n",
			le16_to_cpu(media_tb_erased));

		if (size > 12)
			print_vu_event_data((size-12), (__u8 *)&data[12]);
		break;

	case TELEMETRY_STAT_SNAPSHOT_CLASS:
		printf("  Statistic ID      : 0x%02x %s\n",
			id, telemetry_stat_id_to_string(id));
		print_stats_desc((struct telemetry_stats_desc *)data);
		break;

	case TELEMETRY_VIRTUAL_FIFO_EVENT_CLASS:
		printf("  Event ID : 0x%04x %s\n",
			id, telemetry_virtual_fifo_event_id_to_string(id));

		__u16 vu_event_id = *(__u16 *)data;

		printf("  VU Virtual FIFO Event ID   : 0x%02x\n", le16_to_cpu(vu_event_id));
		printf("\n");
		break;

	default:
		/*
		 * printf("Unknown Event Class Type\n");
		 * printf("Data : 0x");
		 * for (j = 0; j < size; j++)
		 *   printf("%x", data[j]);
		 * printf("\n\n");
		 */
		break;
	}
}

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
	{ 0x1D, "Minimum NAND Channel Bad Block"}
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

#ifdef CONFIG_JSONC
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

	for (size_t i = 0; i < data_size; ++i) {
		sprintf(temp_buffer, "%02X", pdata[i]);
		strcat(description_str, temp_buffer);
	}

	json_object_add_value_string(pobject, msg, description_str);
	free(description_str);
}
#endif /* CONFIG_JSONC */

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

	ptelemetry_das_offset->da1_start_offset = ptelemetry_das_offset->header_size;
	ptelemetry_das_offset->da1_size = ptelemetry_common_header->da1_last_block *
		OCP_TELEMETRY_DATA_BLOCK_SIZE;

	ptelemetry_das_offset->da2_start_offset = ptelemetry_das_offset->da1_start_offset +
		ptelemetry_das_offset->da1_size;
	ptelemetry_das_offset->da2_size =
		(ptelemetry_common_header->da2_last_block -
		ptelemetry_common_header->da1_last_block) * OCP_TELEMETRY_DATA_BLOCK_SIZE;

	ptelemetry_das_offset->da3_start_offset = ptelemetry_das_offset->da2_start_offset +
		ptelemetry_das_offset->da2_size;
	ptelemetry_das_offset->da3_size =
		(ptelemetry_common_header->da3_last_block -
		ptelemetry_common_header->da2_last_block) * OCP_TELEMETRY_DATA_BLOCK_SIZE;

	ptelemetry_das_offset->da4_start_offset = ptelemetry_das_offset->da3_start_offset +
		ptelemetry_das_offset->da3_size;
	ptelemetry_das_offset->da4_size =
		(ptelemetry_common_header->da4_last_block -
		ptelemetry_common_header->da3_last_block) * OCP_TELEMETRY_DATA_BLOCK_SIZE;

	return 0;
}

int get_statistic_id_ascii_string(int identifier, char *description)
{
	if (!pstring_buffer || !description)
		return -1;

	struct nvme_ocp_telemetry_string_header *pocp_ts_header =
		(struct nvme_ocp_telemetry_string_header *)pstring_buffer;

	//Calculating the sizes of the tables. Note: Data is present in the form of DWORDS,
	//So multiplying with sizeof(DWORD)
	unsigned long long sits_table_size = (pocp_ts_header->sitsz) * SIZE_OF_DWORD;

	//Calculating number of entries present in all 3 tables
	int sits_entries = (int)sits_table_size /
		sizeof(struct nvme_ocp_statistics_identifier_string_table);

	for (int sits_entry = 0; sits_entry < sits_entries; sits_entry++) {
		struct nvme_ocp_statistics_identifier_string_table
			*peach_statistic_entry =
			(struct nvme_ocp_statistics_identifier_string_table *)
			(pstring_buffer + (pocp_ts_header->sits * SIZE_OF_DWORD) +
			(sits_entry *
			sizeof(struct nvme_ocp_statistics_identifier_string_table)));

		if (identifier == (int)peach_statistic_entry->vs_statistic_identifier) {
			char *pdescription = (char *)(pstring_buffer +
				(pocp_ts_header->ascts * SIZE_OF_DWORD) +
				(peach_statistic_entry->ascii_id_offset *
				SIZE_OF_DWORD));

			memcpy(description, pdescription,
			       peach_statistic_entry->ascii_id_length + 1);

			return 0;
		}
	}

	// If ASCII string isn't found, see in our internal Map
	// for 2.5 Spec defined strings
	if (identifier <= 0x1D) {
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
	unsigned long long ests_table_size = (pocp_ts_header->estsz) * SIZE_OF_DWORD;

	//Calculating number of entries present in all 3 tables
	int ests_entries = (int)ests_table_size / sizeof(struct nvme_ocp_event_string_table);

	for (int ests_entry = 0; ests_entry < ests_entries; ests_entry++) {
		struct nvme_ocp_event_string_table *peach_event_entry =
			(struct nvme_ocp_event_string_table *)
			(pstring_buffer + (pocp_ts_header->ests * SIZE_OF_DWORD) +
			(ests_entry * sizeof(struct nvme_ocp_event_string_table)));

		if (identifier == (int)peach_event_entry->event_identifier &&
			debug_event_class == (int)peach_event_entry->debug_event_class) {
			char *pdescription = (char *)(pstring_buffer +
				(pocp_ts_header->ascts * SIZE_OF_DWORD) +
				(peach_event_entry->ascii_id_offset * SIZE_OF_DWORD));

			memcpy(description, pdescription,
			       peach_event_entry->ascii_id_length + 1);
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
	unsigned long long vuests_table_size = (pocp_ts_header->vu_estsz) * SIZE_OF_DWORD;

	//Calculating number of entries present in all 3 tables
	int vu_ests_entries = (int)vuests_table_size /
		sizeof(struct nvme_ocp_vu_event_string_table);

	for (int vu_ests_entry = 0; vu_ests_entry < vu_ests_entries; vu_ests_entry++) {
		struct nvme_ocp_vu_event_string_table *peach_vu_event_entry =
			(struct nvme_ocp_vu_event_string_table *)
			(pstring_buffer + (pocp_ts_header->vu_ests * SIZE_OF_DWORD) +
			(vu_ests_entry * sizeof(struct nvme_ocp_vu_event_string_table)));

		if (identifier == (int)peach_vu_event_entry->vu_event_identifier &&
			debug_event_class ==
				(int)peach_vu_event_entry->debug_event_class) {
			char *pdescription = (char *)(pstring_buffer +
				(pocp_ts_header->ascts * SIZE_OF_DWORD) +
				(peach_vu_event_entry->ascii_id_offset * SIZE_OF_DWORD));

			memcpy(description, pdescription,
			       peach_vu_event_entry->ascii_id_length + 1);
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
			description = "";

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

#ifdef CONFIG_JSONC
void parse_time_stamp_event(struct nvme_ocp_telemetry_event_descriptor *pevent_descriptor,
			    struct json_object *pevent_descriptor_obj, __u8 *pevent_specific_data,
			    struct json_object *pevent_fifos_object, FILE *fp)
{
	struct nvme_ocp_time_stamp_dbg_evt_class_format *ptime_stamp_event =
		(struct nvme_ocp_time_stamp_dbg_evt_class_format *) pevent_specific_data;
	struct nvme_ocp_common_dbg_evt_class_vu_data *ptime_stamp_event_vu_data = NULL;
	__u16 vu_event_id = 0;
	__u8 *pdata = NULL;
	char description_str[256] = "";
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
			(struct nvme_ocp_common_dbg_evt_class_vu_data *)((__u64)ptime_stamp_event +
			sizeof(struct nvme_ocp_time_stamp_dbg_evt_class_format));
		vu_event_id = le16_to_cpu(ptime_stamp_event_vu_data->vu_event_identifier);
		pdata = (__u8 *)&(ptime_stamp_event_vu_data->data);

		parse_ocp_telemetry_string_log(0, vu_event_id,
			pevent_descriptor->debug_event_class_type,
			VU_EVENT_STRING, description_str);
	}

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
}

void parse_pcie_event(struct nvme_ocp_telemetry_event_descriptor *pevent_descriptor,
			    struct json_object *pevent_descriptor_obj, __u8 *pevent_specific_data,
			    struct json_object *pevent_fifos_object, FILE *fp)
{
	struct nvme_ocp_pcie_dbg_evt_class_format *ppcie_event =
				(struct nvme_ocp_pcie_dbg_evt_class_format *) pevent_specific_data;
	struct nvme_ocp_common_dbg_evt_class_vu_data *ppcie_event_vu_data = NULL;
	__u16 vu_event_id = 0;
	__u8 *pdata = NULL;
	char description_str[256] = "";
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
			(struct nvme_ocp_common_dbg_evt_class_vu_data *)((__u64)ppcie_event +
			sizeof(struct nvme_ocp_pcie_dbg_evt_class_format));
		vu_event_id = le16_to_cpu(ppcie_event_vu_data->vu_event_identifier);
		pdata = (__u8 *)&(ppcie_event_vu_data->data);

		parse_ocp_telemetry_string_log(0, vu_event_id,
			pevent_descriptor->debug_event_class_type,
			VU_EVENT_STRING, description_str);
	}

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
}

void parse_nvme_event(struct nvme_ocp_telemetry_event_descriptor *pevent_descriptor,
			    struct json_object *pevent_descriptor_obj, __u8 *pevent_specific_data,
			    struct json_object *pevent_fifos_object, FILE *fp)
{
	struct nvme_ocp_nvme_dbg_evt_class_format *pnvme_event =
				(struct nvme_ocp_nvme_dbg_evt_class_format *) pevent_specific_data;
	struct nvme_ocp_common_dbg_evt_class_vu_data *pnvme_event_vu_data = NULL;
	__u16 vu_event_id = 0;
	__u8 *pdata = NULL;
	char description_str[256] = "";
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
			(struct nvme_ocp_common_dbg_evt_class_vu_data *)((__u64)pnvme_event +
			sizeof(struct nvme_ocp_nvme_dbg_evt_class_format));

		vu_event_id = le16_to_cpu(pnvme_event_vu_data->vu_event_identifier);
		pdata = (__u8 *)&(pnvme_event_vu_data->data);

		parse_ocp_telemetry_string_log(0, vu_event_id,
			pevent_descriptor->debug_event_class_type,
			VU_EVENT_STRING,
			description_str);
	}

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
}

void parse_common_event(struct nvme_ocp_telemetry_event_descriptor *pevent_descriptor,
			    struct json_object *pevent_descriptor_obj, __u8 *pevent_specific_data,
			    struct json_object *pevent_fifos_object, FILE *fp)
{
	if (pevent_specific_data) {
		struct nvme_ocp_common_dbg_evt_class_vu_data *pcommon_debug_event_vu_data =
			(struct nvme_ocp_common_dbg_evt_class_vu_data *) pevent_specific_data;

		__u16 vu_event_id = le16_to_cpu(pcommon_debug_event_vu_data->vu_event_identifier);
		char description_str[256] = "";
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

void parse_media_wear_event(struct nvme_ocp_telemetry_event_descriptor *pevent_descriptor,
			    struct json_object *pevent_descriptor_obj, __u8 *pevent_specific_data,
			    struct json_object *pevent_fifos_object, FILE *fp)
{
	struct nvme_ocp_media_wear_dbg_evt_class_format *pmedia_wear_event =
			(struct nvme_ocp_media_wear_dbg_evt_class_format *) pevent_specific_data;
	struct nvme_ocp_common_dbg_evt_class_vu_data *pmedia_wear_event_vu_data = NULL;

	__u16 vu_event_id = 0;
	__u8 *pdata = NULL;
	char description_str[256] = "";
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
			(struct nvme_ocp_common_dbg_evt_class_vu_data *)((__u64)pmedia_wear_event +
			sizeof(struct nvme_ocp_media_wear_dbg_evt_class_format));
		vu_event_id = le16_to_cpu(pmedia_wear_event_vu_data->vu_event_identifier);
		pdata = (__u8 *)&(pmedia_wear_event_vu_data->data);

		parse_ocp_telemetry_string_log(0, vu_event_id,
			pevent_descriptor->debug_event_class_type,
			VU_EVENT_STRING,
			description_str);
	}

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
}

int parse_event_fifo(unsigned int fifo_num, unsigned char *pfifo_start,
	struct json_object *pevent_fifos_object, unsigned char *pstring_buffer,
	struct nvme_ocp_telemetry_offsets *poffsets, __u64 fifo_size, FILE *fp)
{
	if (NULL == pfifo_start || NULL == poffsets) {
		nvme_show_error("Input buffer was NULL");
		return -1;
	}

	int status = 0;
	unsigned int event_fifo_number = fifo_num + 1;
	char *description = (char *)malloc((40 + 1) * sizeof(char));

	memset(description, 0, sizeof(40));

	status =
		parse_ocp_telemetry_string_log(event_fifo_number, 0, 0, EVENT_STRING, description);

	if (status != 0) {
		nvme_show_error("Failed to get C9 String. status: %d\n", status);
		return -1;
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
		char description_str[256] = "";
		unsigned int data_size = 0;

		if (pevent_descriptor != NULL &&
			pevent_descriptor->event_data_size >= 0 &&
			pevent_descriptor->debug_event_class_type !=
				STATISTIC_SNAPSHOT_CLASS_TYPE) {
			event_des_size = sizeof(struct nvme_ocp_telemetry_event_descriptor);
			/* Data is present in the form of DWORDS,
			 * So multiplying with sizeof(DWORD)
			 */
			data_size = pevent_descriptor->event_data_size *
							SIZE_OF_DWORD;

			if (pevent_descriptor != NULL && pevent_descriptor->event_data_size > 0)
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
				parse_time_stamp_event(pevent_descriptor,
					pevent_descriptor_obj,
					pevent_specific_data,
					pevent_fifos_object,
					fp);
				break;
			case PCIE_CLASS_TYPE:
				parse_pcie_event(pevent_descriptor,
					pevent_descriptor_obj,
					pevent_specific_data,
					pevent_fifos_object,
					fp);
				break;
			case NVME_CLASS_TYPE:
				parse_nvme_event(pevent_descriptor,
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
				break;
			case MEDIA_WEAR_CLASS_TYPE:
				parse_media_wear_event(pevent_descriptor,
					pevent_descriptor_obj,
					pevent_specific_data,
					pevent_fifos_object,
					fp);
				break;
			case RESERVED_CLASS_TYPE:
			default:
				break;
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
		} else if ((pevent_descriptor != NULL) &&
			(pevent_descriptor->debug_event_class_type ==
				STATISTIC_SNAPSHOT_CLASS_TYPE)) {
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

			event_des_size =
				sizeof(struct nvme_ocp_statistic_snapshot_evt_class_format);
			data_size =
				(le16_to_cpu((unsigned int)pStaticSnapshotEvent->stat_data_size) *
					SIZE_OF_DWORD);

			if (pStaticSnapshotEvent != NULL &&
				pStaticSnapshotEvent->stat_data_size > 0) {
				__u8 *pstatistic_entry =
					(__u8 *)pStaticSnapshotEvent +
					sizeof(struct nvme_ocp_telemetry_event_descriptor);

				parse_statistic(
					(struct nvme_ocp_telemetry_statistic_descriptor *)
						pstatistic_entry,
					pevent_descriptor_obj,
					fp);
			}
		} else {
			if (fp)
				fprintf(fp, "Unknown or null event class %p\n", pevent_descriptor);
			else
				printf("Unknown or null event class %p\n", pevent_descriptor);

			break;
		}

		offset_to_move += (data_size + event_des_size);
	}

	if (pevent_fifos_object != NULL && pevent_fifo_array != NULL)
		json_object_add_value_array(pevent_fifos_object, event_fifo_name,
			pevent_fifo_array);

	free(description);
	return 0;
}

int parse_event_fifos(struct json_object *root, struct nvme_ocp_telemetry_offsets *poffsets,
	FILE *fp)
{
	if (poffsets == NULL) {
		nvme_show_error("Input buffer was NULL");
		return -1;
	}

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
			pda1_header->fifo_offsets[fifo_num].event_fifo_start;
		event_fifo[fifo_num].event_fifo_size =
			pda1_header->fifo_offsets[fifo_num].event_fifo_size;
	}

	//Parse all the FIFOs DA wise
	for (int fifo_no = 0; fifo_no < MAX_NUM_FIFOS; fifo_no++) {
		if (event_fifo[fifo_no].event_fifo_da == poffsets->data_area) {
			__u64 fifo_offset =
				(event_fifo[fifo_no].event_fifo_start  * SIZE_OF_DWORD);
			__u64 fifo_size =
				(event_fifo[fifo_no].event_fifo_size  * SIZE_OF_DWORD);
			__u8 *pfifo_start = NULL;

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
				nvme_show_error("Failed to parse Event FIFO. status:%d\n", status);
				return -1;
			}
		}
	}

	if (pevent_fifos_object != NULL && root != NULL) {
		const char *data_area = (poffsets->data_area == 1 ? STR_DA_1_EVENT_FIFO_INFO :
					STR_DA_2_EVENT_FIFO_INFO);

		json_object_add_value_array(root, data_area, pevent_fifos_object);
	}

	return 0;
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

	unsigned int data_size = pstatistic_entry->statistic_data_size * SIZE_OF_DWORD;
	__u8 *pdata = (__u8 *)pstatistic_entry +
		sizeof(struct nvme_ocp_telemetry_statistic_descriptor);
	char description_str[256] = "";

	parse_ocp_telemetry_string_log(0, pstatistic_entry->statistic_id, 0,
		STATISTICS_IDENTIFIER_STRING, description_str);

	if (pstats_array != NULL) {
		struct json_object *pstatistics_object = json_create_object();

		json_add_formatted_u32_str(pstatistics_object, STR_STATISTICS_IDENTIFIER,
			pstatistic_entry->statistic_id);
		json_object_add_value_string(pstatistics_object, STR_STATISTICS_IDENTIFIER_STR,
			description_str);
		json_add_formatted_u32_str(pstatistics_object,
			STR_STATISTICS_INFO_BEHAVIOUR_TYPE,
			pstatistic_entry->statistic_info_behaviour_type);
		json_add_formatted_u32_str(pstatistics_object, STR_STATISTICS_INFO_RESERVED,
			pstatistic_entry->statistic_info_reserved);
		json_add_formatted_u32_str(pstatistics_object, STR_NAMESPACE_IDENTIFIER,
			pstatistic_entry->ns_info_nsid);
		json_add_formatted_u32_str(pstatistics_object, STR_NAMESPACE_INFO_VALID,
			pstatistic_entry->ns_info_ns_info_valid);
		json_add_formatted_u32_str(pstatistics_object, STR_STATISTICS_DATA_SIZE,
			pstatistic_entry->statistic_data_size);
		json_add_formatted_u32_str(pstatistics_object, STR_RESERVED,
			pstatistic_entry->reserved);
		if (pstatistic_entry->statistic_id == MAX_DIE_BAD_BLOCK_ID) {
			json_add_formatted_u32_str(pstatistics_object,
					STR_STATISTICS_WORST_DIE_PERCENT,
					pdata[0]);
			json_add_formatted_u32_str(pstatistics_object,
					STR_STATISTICS_WORST_DIE_RAW,
					*(__u16 *)&pdata[2]);
		} else if (pstatistic_entry->statistic_id == MAX_NAND_CHANNEL_BAD_BLOCK_ID) {
			json_add_formatted_u32_str(pstatistics_object,
					STR_STATISTICS_WORST_NAND_CHANNEL_PERCENT,
					pdata[0]);
			json_add_formatted_u32_str(pstatistics_object,
					STR_STATISTICS_WORST_NAND_CHANNEL_RAW,
					*(__u16 *)&pdata[2]);
		} else if (pstatistic_entry->statistic_id == MIN_NAND_CHANNEL_BAD_BLOCK_ID) {
			json_add_formatted_u32_str(pstatistics_object,
					STR_STATISTICS_BEST_NAND_CHANNEL_PERCENT,
					pdata[0]);
			json_add_formatted_u32_str(pstatistics_object,
					STR_STATISTICS_BEST_NAND_CHANNEL_RAW,
					*(__u16 *)&pdata[2]);
		} else {
			json_add_formatted_var_size_str(pstatistics_object,
					STR_STATISTICS_SPECIFIC_DATA,
					pdata,
					data_size);
		}

		if (pstatistics_object != NULL)
			json_array_add_value_object(pstats_array, pstatistics_object);
	} else {
		if (fp) {
			fprintf(fp, "%s: 0x%x\n", STR_STATISTICS_IDENTIFIER,
				pstatistic_entry->statistic_id);
			fprintf(fp, "%s: %s\n", STR_STATISTICS_IDENTIFIER_STR, description_str);
			fprintf(fp, "%s: 0x%x\n", STR_STATISTICS_INFO_BEHAVIOUR_TYPE,
				pstatistic_entry->statistic_info_behaviour_type);
			fprintf(fp, "%s: 0x%x\n", STR_STATISTICS_INFO_RESERVED,
				pstatistic_entry->statistic_info_reserved);
			fprintf(fp, "%s: 0x%x\n", STR_NAMESPACE_IDENTIFIER,
				pstatistic_entry->ns_info_nsid);
			fprintf(fp, "%s: 0x%x\n", STR_NAMESPACE_INFO_VALID,
				pstatistic_entry->ns_info_ns_info_valid);
			fprintf(fp, "%s: 0x%x\n", STR_STATISTICS_DATA_SIZE,
				pstatistic_entry->statistic_data_size);
			fprintf(fp, "%s: 0x%x\n", STR_RESERVED, pstatistic_entry->reserved);
			if (pstatistic_entry->statistic_id == MAX_DIE_BAD_BLOCK_ID) {
				fprintf(fp, "%s: 0x%02x\n", STR_STATISTICS_WORST_DIE_PERCENT,
						pdata[0]);
				fprintf(fp, "%s: 0x%04x\n", STR_STATISTICS_WORST_DIE_RAW,
						*(__u16 *)&pdata[2]);
			} else if (pstatistic_entry->statistic_id ==
					MAX_NAND_CHANNEL_BAD_BLOCK_ID) {
				fprintf(fp, "%s: 0x%02x\n",
						STR_STATISTICS_WORST_NAND_CHANNEL_PERCENT,
						pdata[0]);
				fprintf(fp, "%s: 0x%04x\n",
						STR_STATISTICS_WORST_NAND_CHANNEL_RAW,
						*(__u16 *)&pdata[2]);
			} else if (pstatistic_entry->statistic_id ==
					MIN_NAND_CHANNEL_BAD_BLOCK_ID) {
				fprintf(fp, "%s: 0x%02x\n",
						STR_STATISTICS_BEST_NAND_CHANNEL_PERCENT,
						pdata[0]);
				fprintf(fp, "%s: 0x%04x\n",
						STR_STATISTICS_BEST_NAND_CHANNEL_RAW,
						*(__u16 *)&pdata[2]);
			} else {
				print_formatted_var_size_str(STR_STATISTICS_SPECIFIC_DATA,
						pdata,
						data_size,
						fp);
			}
			fprintf(fp, STR_LINE2);
		} else {
			printf("%s: 0x%x\n", STR_STATISTICS_IDENTIFIER,
			       pstatistic_entry->statistic_id);
			printf("%s: %s\n", STR_STATISTICS_IDENTIFIER_STR, description_str);
			printf("%s: 0x%x\n", STR_STATISTICS_INFO_BEHAVIOUR_TYPE,
			       pstatistic_entry->statistic_info_behaviour_type);
			printf("%s: 0x%x\n", STR_STATISTICS_INFO_RESERVED,
			       pstatistic_entry->statistic_info_reserved);
			printf("%s: 0x%x\n", STR_NAMESPACE_IDENTIFIER,
			       pstatistic_entry->ns_info_nsid);
			printf("%s: 0x%x\n", STR_NAMESPACE_INFO_VALID,
			       pstatistic_entry->ns_info_ns_info_valid);
			printf("%s: 0x%x\n", STR_STATISTICS_DATA_SIZE,
			       pstatistic_entry->statistic_data_size);
			printf("%s: 0x%x\n", STR_RESERVED, pstatistic_entry->reserved);
			if (pstatistic_entry->statistic_id == MAX_DIE_BAD_BLOCK_ID) {
				printf("%s: 0x%02x\n", STR_STATISTICS_WORST_DIE_PERCENT,
						pdata[0]);
				printf("%s: 0x%04x\n", STR_STATISTICS_WORST_DIE_RAW,
						*(__u16 *)&pdata[2]);
			} else if (pstatistic_entry->statistic_id ==
					MAX_NAND_CHANNEL_BAD_BLOCK_ID) {
				printf("%s: 0x%02x\n",
						STR_STATISTICS_WORST_NAND_CHANNEL_PERCENT,
						pdata[0]);
				printf("%s: 0x%04x\n",
						STR_STATISTICS_WORST_NAND_CHANNEL_RAW,
						*(__u16 *)&pdata[2]);
			} else if (pstatistic_entry->statistic_id ==
					MIN_NAND_CHANNEL_BAD_BLOCK_ID) {
				printf("%s: 0x%02x\n",
						STR_STATISTICS_BEST_NAND_CHANNEL_PERCENT,
						pdata[0]);
				printf("%s: 0x%04x\n",
						STR_STATISTICS_BEST_NAND_CHANNEL_RAW,
						*(__u16 *)&pdata[2]);
			} else {
				print_formatted_var_size_str(STR_STATISTICS_SPECIFIC_DATA,
						pdata,
						data_size,
						fp);
			}
			printf(STR_LINE2);
		}
	}

	return 0;
}

int parse_statistics(struct json_object *root, struct nvme_ocp_telemetry_offsets *poffsets,
		     FILE *fp)
{
	if (poffsets == NULL) {
		nvme_show_error("Input buffer was NULL");
		return -1;
	}

	__u8 *pda1_ocp_header_offset = ptelemetry_buffer + poffsets->header_size;//512
	__u32 statistics_size = 0;
	__u32 stats_da_1_start_dw = 0, stats_da_1_size_dw = 0;
	__u32 stats_da_2_start_dw = 0, stats_da_2_size_dw = 0;
	__u8 *pstats_offset = NULL;
	int parse_rc = 0;

	if (poffsets->data_area == 1) {
		__u32 stats_da_1_start = *(__u32 *)(pda1_ocp_header_offset +
			offsetof(struct nvme_ocp_header_in_da1, da1_statistic_start));
		__u32 stats_da_1_size = *(__u32 *)(pda1_ocp_header_offset +
			offsetof(struct nvme_ocp_header_in_da1, da1_statistic_size));

		//Data is present in the form of DWORDS, So multiplying with sizeof(DWORD)
		stats_da_1_start_dw = (stats_da_1_start * SIZE_OF_DWORD);
		stats_da_1_size_dw = (stats_da_1_size * SIZE_OF_DWORD);

		pstats_offset = pda1_ocp_header_offset + stats_da_1_start_dw;
		statistics_size = stats_da_1_size_dw;
	} else if (poffsets->data_area == 2) {
		__u32 stats_da_2_start = *(__u32 *)(pda1_ocp_header_offset +
			offsetof(struct nvme_ocp_header_in_da1, da2_statistic_start));
		__u32 stats_da_2_size = *(__u32 *)(pda1_ocp_header_offset +
			offsetof(struct nvme_ocp_header_in_da1, da2_statistic_size));

		stats_da_2_start_dw = (stats_da_2_start * SIZE_OF_DWORD);
		stats_da_2_size_dw = (stats_da_2_size * SIZE_OF_DWORD);

		pstats_offset = pda1_ocp_header_offset + poffsets->da1_size + stats_da_2_start_dw;
		statistics_size = stats_da_2_size_dw;
	} else {
		nvme_show_error("Unsupported Data Area:[%d]", poffsets->data_area);
		return -1;
	}

	struct json_object *pstats_array = ((root != NULL) ? json_create_array() : NULL);

	__u32 stat_des_size = sizeof(struct nvme_ocp_telemetry_statistic_descriptor);//8
	__u32 offset_to_move = 0;

	while (((statistics_size > 0) && (offset_to_move < statistics_size))) {
		struct nvme_ocp_telemetry_statistic_descriptor *pstatistic_entry =
			(struct nvme_ocp_telemetry_statistic_descriptor *)
			(pstats_offset + offset_to_move);

		parse_rc = parse_statistic(pstatistic_entry, pstats_array, fp);
		if (parse_rc < 0)
			/* end of stats entries or null pointer, so break */
			break;

		offset_to_move += (pstatistic_entry->statistic_data_size * SIZE_OF_DWORD +
			stat_des_size);
	}

	if (root != NULL && pstats_array != NULL) {
		const char *pdata_area =
			(poffsets->data_area == 1 ? STR_DA_1_STATS : STR_DA_2_STATS);

		json_object_add_value_array(root, pdata_area, pstats_array);
	}

	return 0;
}

int print_ocp_telemetry_normal(struct ocp_telemetry_parse_options *options)
{
	int status = 0;

	if (options->output_file != NULL) {
		FILE *fp = fopen(options->output_file, "w");

		if (fp) {
			fprintf(fp, STR_LINE);
			fprintf(fp, "%s\n", STR_LOG_PAGE_HEADER);
			fprintf(fp, STR_LINE);
			if (!strcmp(options->telemetry_type, "host")) {
				if ((ptelemetry_buffer == NULL) ||
					(ARRAY_SIZE(host_log_page_header) == 0))
					printf("skip generic_structure_parser\n");
				else
					generic_structure_parser(ptelemetry_buffer,
						host_log_page_header,
						ARRAY_SIZE(host_log_page_header),
						NULL, 0, fp);
			}
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

			generic_structure_parser(pda1_header_offset, ocp_header_in_da1,
				 ARRAY_SIZE(ocp_header_in_da1), NULL, 0, fp);

			fprintf(fp, STR_LINE);
			fprintf(fp, "%s\n", STR_SMART_HEALTH_INFO);
			fprintf(fp, STR_LINE);
			__u8 *pda1_smart_offset = pda1_header_offset +
				offsetof(struct nvme_ocp_header_in_da1, smart_health_info);
			//512+512 =1024

			generic_structure_parser(pda1_smart_offset, smart, ARRAY_SIZE(smart),
				NULL, 0, fp);

			fprintf(fp, STR_LINE);
			fprintf(fp, "%s\n", STR_SMART_HEALTH_INTO_EXTENDED);
			fprintf(fp, STR_LINE);
			__u8 *pda1_smart_ext_offset = pda1_header_offset +
							offsetof(struct nvme_ocp_header_in_da1,
								 smart_health_info_extended);

			generic_structure_parser(pda1_smart_ext_offset, smart_extended,
					     ARRAY_SIZE(smart_extended), NULL, 0, fp);

			fprintf(fp, STR_LINE);
			fprintf(fp, "%s\n", STR_DA_1_STATS);
			fprintf(fp, STR_LINE);

			status = parse_statistics(NULL, &offsets, fp);
			if (status != 0) {
				nvme_show_error("status: %d\n", status);
				return -1;
			}

			fprintf(fp, STR_LINE);
			fprintf(fp, "%s\n", STR_DA_1_EVENT_FIFO_INFO);
			fprintf(fp, STR_LINE);
			status = parse_event_fifos(NULL, &offsets, fp);
			if (status != 0) {
				nvme_show_error("status: %d\n", status);
				return -1;
			}

			//Set the DA to 2
			if (options->data_area == 2) {
				offsets.data_area = 2;
				fprintf(fp, STR_LINE);
				fprintf(fp, "%s\n", STR_DA_2_STATS);
				fprintf(fp, STR_LINE);
				status = parse_statistics(NULL, &offsets, fp);

				if (status != 0) {
					nvme_show_error("status: %d\n", status);
					return -1;
				}

				fprintf(fp, STR_LINE);
				fprintf(fp, "%s\n", STR_DA_2_EVENT_FIFO_INFO);
				fprintf(fp, STR_LINE);
				status = parse_event_fifos(NULL, &offsets, fp);
				if (status != 0) {
					nvme_show_error("status: %d\n", status);
					return -1;
				}
			}

			fprintf(fp, STR_LINE);
			fclose(fp);
		} else {
			nvme_show_error("Failed to open %s file.\n", options->output_file);
			return -1;
		}
	} else {
		printf(STR_LINE);
		printf("%s\n", STR_LOG_PAGE_HEADER);
		printf(STR_LINE);
		if (!strcmp(options->telemetry_type, "host")) {
			if ((ptelemetry_buffer == NULL) ||
				(ARRAY_SIZE(host_log_page_header) == 0))
				printf("skip generic_structure_parser\n");
			else {
				generic_structure_parser(ptelemetry_buffer, host_log_page_header,
					ARRAY_SIZE(host_log_page_header), NULL, 0, NULL);
			}
		}
		else if (!strcmp(options->telemetry_type, "controller"))
			generic_structure_parser(ptelemetry_buffer, controller_log_page_header,
				     ARRAY_SIZE(controller_log_page_header), NULL, 0, NULL);

		printf(STR_LINE);
		printf("%s\n", STR_REASON_IDENTIFIER);
		printf(STR_LINE);
		__u8 *preason_identifier_offset = ptelemetry_buffer +
			offsetof(struct nvme_ocp_telemetry_host_initiated_header, reason_id);
		generic_structure_parser(preason_identifier_offset, reason_identifier,
			ARRAY_SIZE(reason_identifier), NULL, 0, NULL);

		printf(STR_LINE);
		printf("%s\n", STR_TELEMETRY_HOST_DATA_BLOCK_1);
		printf(STR_LINE);

		//Set DA to 1 and get offsets
		struct nvme_ocp_telemetry_offsets offsets = { 0 };

		offsets.data_area = 1;

		struct nvme_ocp_telemetry_common_header *ptelemetry_common_header =
			(struct nvme_ocp_telemetry_common_header *) ptelemetry_buffer;

		get_telemetry_das_offset_and_size(ptelemetry_common_header, &offsets);

		__u8 *pda1_header_offset = ptelemetry_buffer + offsets.da1_start_offset;//512

		generic_structure_parser(pda1_header_offset, ocp_header_in_da1,
			ARRAY_SIZE(ocp_header_in_da1), NULL, 0, NULL);

		printf(STR_LINE);
		printf("%s\n", STR_SMART_HEALTH_INFO);
		printf(STR_LINE);
		__u8 *pda1_smart_offset = pda1_header_offset +
			offsetof(struct nvme_ocp_header_in_da1, smart_health_info);

		generic_structure_parser(pda1_smart_offset, smart, ARRAY_SIZE(smart), NULL, 0,
			NULL);

		printf(STR_LINE);
		printf("%s\n", STR_SMART_HEALTH_INTO_EXTENDED);
		printf(STR_LINE);
		__u8 *pda1_smart_ext_offset = pda1_header_offset +
			offsetof(struct nvme_ocp_header_in_da1, smart_health_info_extended);

		generic_structure_parser(pda1_smart_ext_offset, smart_extended,
			ARRAY_SIZE(smart_extended), NULL, 0, NULL);

		printf(STR_LINE);
		printf("%s\n", STR_DA_1_STATS);
		printf(STR_LINE);
		status = parse_statistics(NULL, &offsets, NULL);
		if (status != 0) {
			nvme_show_error("status: %d\n", status);
			return -1;
		}

		printf(STR_LINE);
		printf("%s\n", STR_DA_1_EVENT_FIFO_INFO);
		printf(STR_LINE);
		status = parse_event_fifos(NULL, &offsets, NULL);
		if (status != 0) {
			nvme_show_error("status: %d\n", status);
			return -1;
		}

		//Set the DA to 2
		if (options->data_area == 2) {
			offsets.data_area = 2;
			printf(STR_LINE);
			printf("%s\n", STR_DA_2_STATS);
			printf(STR_LINE);
			status = parse_statistics(NULL, &offsets, NULL);
			if (status != 0) {
				nvme_show_error("status: %d\n", status);
				return -1;
			}

			printf(STR_LINE);
			printf("%s\n", STR_DA_2_EVENT_FIFO_INFO);
			printf(STR_LINE);
			status = parse_event_fifos(NULL, &offsets, NULL);
			if (status != 0) {
				nvme_show_error("status: %d\n", status);
				return -1;
			}
		}

		printf(STR_LINE);
	}

	return status;
}

int print_ocp_telemetry_json(struct ocp_telemetry_parse_options *options)
{
	int status = 0;

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

	da1_header = json_create_object();

	generic_structure_parser(pda1_header_offset, ocp_header_in_da1,
				 ARRAY_SIZE(ocp_header_in_da1), da1_header, 0, NULL);
	json_object_add_value_object(root, STR_TELEMETRY_HOST_DATA_BLOCK_1, da1_header);

	//"SMART / Health Information Log(LID-02h)"
	__u8 *pda1_smart_offset = pda1_header_offset + offsetof(struct nvme_ocp_header_in_da1,
								smart_health_info);
	smart_obj = json_create_object();

	generic_structure_parser(pda1_smart_offset, smart, ARRAY_SIZE(smart), smart_obj, 0, NULL);
	json_object_add_value_object(da1_header, STR_SMART_HEALTH_INFO, smart_obj);

	//"SMART / Health Information Extended(LID-C0h)"
	__u8 *pda1_smart_ext_offset = pda1_header_offset + offsetof(struct nvme_ocp_header_in_da1,
								    smart_health_info_extended);
	ext_smart_obj = json_create_object();

	generic_structure_parser(pda1_smart_ext_offset, smart_extended, ARRAY_SIZE(smart_extended),
			     ext_smart_obj, 0, NULL);
	json_object_add_value_object(da1_header, STR_SMART_HEALTH_INTO_EXTENDED, ext_smart_obj);

	//Data Area 1 Statistics
	status = parse_statistics(root, &offsets, NULL);
	if (status != 0) {
		nvme_show_error("status: %d\n", status);
		return -1;
	}

	//Data Area 1 Event FIFOs
	status = parse_event_fifos(root, &offsets, NULL);
	if (status != 0) {
		nvme_show_error("status: %d\n", status, NULL);
		return -1;
	}

	if (options->data_area == 2) {
		//Set the DA to 2
		offsets.data_area = 2;
		//Data Area 2 Statistics
		status = parse_statistics(root, &offsets, NULL);
		if (status != 0) {
			nvme_show_error("status: %d\n", status);
			return -1;
		}

		//Data Area 2 Event FIFOs
		status = parse_event_fifos(root, &offsets, NULL);
		if (status != 0) {
			nvme_show_error("status: %d\n", status);
			return -1;
		}
	}

	if (options->output_file != NULL) {
		const char *json_string = json_object_to_json_string(root);
		FILE *fp = fopen(options->output_file, "w");

		if (fp) {
			fputs(json_string, fp);
			fclose(fp);
		} else {
			nvme_show_error("Failed to open %s file.\n", options->output_file);
			return -1;
		}
	} else {
		//Print root json object
		json_print_object(root, NULL);
		nvme_show_result("\n");
		json_free_object(root);
	}

	return status;
}
#endif /* CONFIG_JSONC */
