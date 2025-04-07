/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (c) Micron, Inc 2024.
 * 
 * @file: micron-ocp-telemetry.c
 * @brief: This module contains all the constructs needed for parsing (or) decoding ocp telemetry log files.
 * @author: Chaithanya Shoba <ashoba@micron.com>
 */

#include "micron-ocp-telemetry.h"

//global buffers
static unsigned char *ptelemetry_buffer;
static unsigned char *pstring_buffer;

#define NVME_HOST_TELEMETRY_LOG       0x07
#define NVME_CNTRL_TELEMETRY_LOG      0x08
#define MAX_BUFFER_32_KB              0x8000
#define OCP_TELEMETRY_DATA_BLOCK_SIZE 512
#define SIZE_OF_DWORD                 4
#define MAX_NUM_FIFOS                 16
#define DA1_OFFSET                    512

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

#define JSON_ADD_FORMATTED_UINT32_STR(pobject, msg, pdata) {\
    char data_str[70] = { 0 };\
    sprintf(data_str, "0x%x", pdata);\
    json_object_add_value_string(pobject, msg, data_str);\
}

#define JSON_ADD_STR(pobject, msg, description_str) {\
    json_object_add_value_string(pobject, msg, description_str);\
}

#define JSON_ADD_FORMATTED_VAR_SIZE_STR(pobject, msg, pdata, data_size) {\
    char description_str[256] = "";\
    char temp_buffer[3] = { 0 };\
    for (size_t i = 0; i < data_size; ++i)\
    {\
        sprintf(temp_buffer, "%02X", pdata[i]);\
        strcat(description_str, temp_buffer);\
    }\
    JSON_ADD_STR(pobject, msg, description_str);\
}

statistic_entry_t statistic_identifiers_map[] = {
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
	//7FFFh:001Eh:Reserved,Statistic Identifier’s between 001Eh and 7FFFh are reserved for future expansion.
	//FFFFh:8000h:Vendor Unique:Statistic Identifier’s between 8000h and FFFFh are vendor unique.  
};

micron_vs_logpage_t host_log_page_header[] = {
	{ "LogIdentifier",1 },                                         //00 Log Identifier
	{ "Reserved1", 4 },                                            //04:01  Reserved
	{ "IEEE OUI Identifier", 3 },                                  //07:05  IEEE OUI Identifier
	{ "Telemetry Host-Initiated Data Area 1 Last Block", 2 },      //09:08  Data Area 1 Last Block
	{ "Telemetry Host-Initiated Data Area 2 Last Block", 2 },      //11:10  Data Area 2 Last Block
	{ "Telemetry Host-Initiated Data Area 3 Last Block", 2 },      //13:12  Data Area 3 Last Block
	{ "Reserved2", 2 },                                            //15:14  Reserved
	{ "Telemetry Host-Initiated Data Area 4 Last Block", 4 },      //19:16  Data Area 4 Last Block
	{ "Reserved3", 360 },                                          //379:20  Reserved
	{ "Telemetry Host-Initiated Scope", 1 },                       //380 Telemetry Host-Initiated Scope
	{ "Telemetry Host Initiated Generation Number", 1 },           //381 Telemetry Host Initiated Generation Number
	{ "Telemetry Host-Initiated Data Available", 1 },              //382 Telemetry Host-Initiated Data Available
	{ "Telemetry Controller-Initiated Data Generation Number", 1 } //383     Telemetry Controller Initiated Generation Number
																   //511:384 Reason string
};

micron_vs_logpage_t controller_log_page_header[] = {
	{ "LogIdentifier",1 },                                        //00 Log Identifier
	{ "Reserved1", 4 },                                           //04:01  Reserved
	{ "IEEE OUI Identifier", 3 },                                 //07:05  IEEE OUI Identifier
	{ "Telemetry Host-Initiated Data Area 1 Last Block", 2 },     //09:08  Data Area 1 Last Block
	{ "Telemetry Host-Initiated Data Area 2 Last Block", 2 },     //11:10  Data Area 2 Last Block
	{ "Telemetry Host-Initiated Data Area 3 Last Block", 2 },     //13:12  Data Area 3 Last Block
	{ "Reserved2", 2 },                                           //15:14  Reserved
	{ "Telemetry Host-Initiated Data Area 4 Last Block", 4 },     //19:16  Data Area 4 Last Block
	{ "Reserved3", 361 },                                         //380:20  Reserved
	{ "Telemetry Controller-Initiated Scope", 1 },                //381 Telemetry Controller-Initiated Scope
	{ "Telemetry Controller-Initiated Data Available", 1 },       //382 Telemetry Controller-Initiated Data Available
	{ "Telemetry Controller-Initiated Data Generation Number", 1 }//383     Telemetry Controller Initiated Generation Number
																  //511:384 Reason string
};

micron_vs_logpage_t reason_identifier[] = {
	{ "Error ID", 64 },           //63:00 Error ID
	{ "File ID", 8 },             //71:64 File ID
	{ "Line Number", 2 },         //73:72 Line Number
	{ "Valid Flags", 1 },         //74 Valid Flags
	{ "Reserved", 21 },           //95:75 Reserved
	{ "VU Reason Extension", 32 } //127:96 VU Reason Extension
};

micron_vs_logpage_t ocp_header_in_da1[] = {
	{ "Major Version",2 },
	{ "Minor Version", 2 },
	{ "Reserved1", 4 },
	{ "Timestamp", 8 },
	{ "Log page GUID", 16 },
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

micron_vs_logpage_t smart[] = {
	{ "Critical Warning",1 },
	{ "Composite Temperature", 2 },
	{ "Available Spare", 1 },
	{ "Available Spare Threshold",1 },
	{ "Percentage Used", 1 },
	{ "Reserved1", 26 },
	{ "Data Units Read",16 },
	{ "Data Units Written", 16 },
	{ "Host Read Commands",16 },
	{ "Host Write Commands", 16 },
	{ "Controller Busy Time", 16 },
	{ "Power Cycles",16 },
	{ "Power On Hours", 16 },
	{ "Unsafe Shutdowns", 16 },
	{ "Media and Data Integrity Errors",16 },
	{ "Number of Error Information Log Entries", 16 },
	{ "Warning Composite Temperature Time",4 },
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
	{ "Total Time for Thermal Management Temperature 1",4 },
	{ "Total Time for Thermal Management Temperature 2", 4 },
	{ "Reserved2", 280 }
};

micron_vs_logpage_t smart_extended[] = {
	{ "Physical Media Units Written",16 },
	{ "Physical Media Units Read", 16 },
	{ "Bad User NAND Blocks Raw Count", 6 },
	{ "Bad User NAND Blocks Normalized Value", 2 },
	{ "Bad System NAND Blocks Raw Count",6 },
	{ "Bad System NAND Blocks Normalized Value",2 },
	{ "XOR Recovery Count", 8 },
	{ "Uncorrectable Read Error Count", 8 },
	{ "Soft ECC Error Count",8 },
	{ "End to End Correction Counts Detected Errors", 4 },
	{ "End to End Correction Counts Corrected Errors", 4 },
	{ "System Data Percent Used", 1 },
	{ "Refresh Counts",7 },
	{ "Maximum User Data Erase Count", 4 },
	{ "Minimum User Data Erase Count", 4 },
	{ "Number of thermal throttling events", 1 },
	{ "Current Throttling Status", 1 },
	{ "Errata Version Field",1 },
	{ "Point Version Field",2 },
	{ "Minor Version Field",2 },
	{ "Major Version Field",1 },
	{ "PCIe Correctable Error Count", 8 },
	{ "Incomplete Shutdowns", 4 },
	{ "Reserved1",4 },
	{ "Percent Free Blocks", 1 },
	{ "Reserved2", 7 },
	{ "Capacitor Health",2 },
	{ "NVMe Base Errata Version", 1 },
	{ "NVMe Command Set Errata Version", 1 },
	{ "Reserved3",4 },
	{ "Unaligned IO", 8 },
	{ "Security Version Number", 8 },
	{ "Total NUSE",8 },
	{ "PLP Start Count", 16 },
	{ "Endurance Estimate", 16 },
	{ "PCIe Link Retraining Count",8 },
	{ "Power State Change Count", 8 },
	{ "Lowest Permitted Firmware Revision", 8 },
	{ "Reserved4",278 },
	{ "Log Page Version", 2 },
	{ "Log page GUID", 16 }
};

int get_telemetry_das_offset_and_size(pnvme_ocp_telemetry_common_header ptelemetry_common_header, pnvme_ocp_telemetry_offsets ptelemetry_das_offset)
{
	if (NULL == ptelemetry_common_header || NULL == ptelemetry_das_offset)
	{
		nvme_show_error("Invalid input arguments.");
		return -1;
	}

	if (ptelemetry_common_header->log_id == NVME_HOST_TELEMETRY_LOG)
	{
		ptelemetry_das_offset->header_size = sizeof(nvme_ocp_telemetry_host_initiated_header_t);
	}
	else if (ptelemetry_common_header->log_id == NVME_CNTRL_TELEMETRY_LOG)
	{
		ptelemetry_das_offset->header_size = sizeof(nvme_ocp_telemetry_controller_initiated_header_t);
	}
	else
	{
		return -1;
	}

	ptelemetry_das_offset->da1_start_offset = ptelemetry_das_offset->header_size;
	ptelemetry_das_offset->da1_size = ptelemetry_common_header->da1_last_block * OCP_TELEMETRY_DATA_BLOCK_SIZE;

	ptelemetry_das_offset->da2_start_offset = ptelemetry_das_offset->da1_start_offset + ptelemetry_das_offset->da1_size;
	ptelemetry_das_offset->da2_size = (ptelemetry_common_header->da2_last_block - ptelemetry_common_header->da1_last_block) * OCP_TELEMETRY_DATA_BLOCK_SIZE;

	ptelemetry_das_offset->da3_start_offset = ptelemetry_das_offset->da2_start_offset + ptelemetry_das_offset->da2_size;
	ptelemetry_das_offset->da3_size = (ptelemetry_common_header->da3_last_block - ptelemetry_common_header->da2_last_block) * OCP_TELEMETRY_DATA_BLOCK_SIZE;

	ptelemetry_das_offset->da4_start_offset = ptelemetry_das_offset->da3_start_offset + ptelemetry_das_offset->da3_size;
	ptelemetry_das_offset->da4_size = (ptelemetry_common_header->da4_last_block - ptelemetry_common_header->da3_last_block) * OCP_TELEMETRY_DATA_BLOCK_SIZE;

	return 0;
}

int parse_ocp_telemetry_string_log(int event_fifo_num, int identifier, int debug_event_class, ocp_telemetry_string_tables_t string_table, char *description)
{
	if (pstring_buffer == NULL)
	{
		return -1;
	}

	pnvme_ocp_telemetry_string_header pocp_ts_header = (pnvme_ocp_telemetry_string_header)pstring_buffer;

	if (event_fifo_num != 0)
	{
		__u8 fifo_ascii_string[17] = { '\0' };
		switch (event_fifo_num)
		{
		case 1:
		{
			memcpy(fifo_ascii_string,pocp_ts_header->fifo1_ascii_string, 16);
		}
		break;
		case 2:
		{
			memcpy(fifo_ascii_string, pocp_ts_header->fifo2_ascii_string, 16);
		}
		break;
		case 3:
		{
			memcpy(fifo_ascii_string, pocp_ts_header->fifo3_ascii_string, 16);
		}
		break;
		case 4:
		{
			memcpy(fifo_ascii_string, pocp_ts_header->fifo4_ascii_string, 16);
		}
		break;
		case 5:
		{
			memcpy(fifo_ascii_string, pocp_ts_header->fifo5_ascii_string, 16);
		}
		break;
		case 6:
		{
			memcpy(fifo_ascii_string, pocp_ts_header->fifo6_ascii_string, 16);
		}
		break;
		case 7:
		{
			memcpy(fifo_ascii_string, pocp_ts_header->fifo7_ascii_string, 16);
		}
		break;
		case 8:
		{
			memcpy(fifo_ascii_string, pocp_ts_header->fifo8_ascii_string, 16);
		}
		break;
		case 9:
		{
			memcpy(fifo_ascii_string, pocp_ts_header->fifo9_ascii_string, 16);
		}
		break;
		case 10:
		{
			memcpy(fifo_ascii_string, pocp_ts_header->fifo10_ascii_string, 16);
		}
		break;
		case 11:
		{
			memcpy(fifo_ascii_string, pocp_ts_header->fifo11_ascii_string, 16);
		}
		break;
		case 12:
		{
			memcpy(fifo_ascii_string, pocp_ts_header->fifo12_ascii_string, 16);
		}
		break;
		case 13:
		{
			memcpy(fifo_ascii_string, pocp_ts_header->fifo13_ascii_string, 16);
		}
		break;
		case 14:
		{
			memcpy(fifo_ascii_string, pocp_ts_header->fifo14_ascii_string, 16);
		}
		break;
		case 15:
		{
			memcpy(fifo_ascii_string, pocp_ts_header->fifo15_ascii_string, 16);
		}
		break;
		case 16:
		{
			memcpy(fifo_ascii_string, pocp_ts_header->fifo16_ascii_string, 16);
		}
		break;
		default:
		{
			description = "";
			return 0;
		}
		break;
		}

		if (fifo_ascii_string[0] != '\0')
		{
			memcpy(description, fifo_ascii_string, 16);
		}

		return 0;
	}	

	//Calculating the sizes of the tables. Note: Data is present in the form of DWORDS, So multiplying with sizeof(DWORD)
	unsigned long long sits_table_size = (pocp_ts_header->sitsz) * SIZE_OF_DWORD;
	unsigned long long ests_table_size = (pocp_ts_header->estsz) * SIZE_OF_DWORD;
	unsigned long long vuests_table_size = (pocp_ts_header->vu_estsz) * SIZE_OF_DWORD;

	//Calculating number of entries present in all 3 tables
	int sits_entries = (int)sits_table_size / sizeof(nvme_ocp_statistics_identifier_string_table_t);
	int ests_entries = (int)ests_table_size / sizeof(nvme_ocp_event_string_table_t);
	int vu_ests_entries = (int)vuests_table_size / sizeof(nvme_ocp_vu_event_string_table_t);

	if (string_table == STATISTICS_IDENTIFIER_STRING)
	{
		for (int sits_entry = 0; sits_entry < sits_entries; sits_entry++)
		{
			pnvme_ocp_statistics_identifier_string_table peach_statistic_entry = NULL;
			peach_statistic_entry = (pnvme_ocp_statistics_identifier_string_table)(pstring_buffer + (pocp_ts_header->sits * SIZE_OF_DWORD) + (sits_entry * sizeof(nvme_ocp_statistics_identifier_string_table_t)));
			if (identifier == (int)peach_statistic_entry->vs_statistic_identifier)
			{
			    char *pdescription = (char *)(pstring_buffer + (pocp_ts_header->ascts * SIZE_OF_DWORD) + (peach_statistic_entry->ascii_id_offset * SIZE_OF_DWORD));
				memcpy(description, pdescription, peach_statistic_entry->ascii_id_length + 1);

				//If ASCII string isn't found, see in our internal Map for 2.5 Spec defined strings (id < 0x1D).
				if ((description == NULL) && (identifier < 0x1D))
				{
					memcpy(description, statistic_identifiers_map[identifier].description, peach_statistic_entry->ascii_id_length + 1);
				}
				return 0;
			}
		}
	}
	else if (string_table == EVENT_STRING)
	{
		for (int ests_entry = 0; ests_entry < ests_entries; ests_entry++)
		{
			pnvme_ocp_event_string_table peach_event_entry = NULL;
			peach_event_entry = (pnvme_ocp_event_string_table)(pstring_buffer + (pocp_ts_header->ests * SIZE_OF_DWORD) + (ests_entry * sizeof(nvme_ocp_event_string_table_t)));
			if (identifier == (int)peach_event_entry->event_identifier && debug_event_class == (int)peach_event_entry->debug_event_class)
			{
				char *pdescription = (char *)(pstring_buffer + (pocp_ts_header->ascts * SIZE_OF_DWORD) + (peach_event_entry->ascii_id_offset * SIZE_OF_DWORD));
				memcpy(description, pdescription, peach_event_entry->ascii_id_length + 1);
				return 0;
			}
		}
	}
	else if (string_table == VU_EVENT_STRING)
	{
		for (int vu_ests_entry = 0; vu_ests_entry < vu_ests_entries; vu_ests_entry++)
		{
			pnvme_ocp_vu_event_string_table peach_vu_event_entry = NULL;
			peach_vu_event_entry = (pnvme_ocp_vu_event_string_table)(pstring_buffer + (pocp_ts_header->vu_ests * SIZE_OF_DWORD) + (vu_ests_entry * sizeof(nvme_ocp_vu_event_string_table_t)));
			if (identifier == (int)peach_vu_event_entry->vu_event_identifier && debug_event_class == (int)peach_vu_event_entry->debug_event_class)
			{
				char *pdescription = (char *)(pstring_buffer + (pocp_ts_header->ascts * SIZE_OF_DWORD) + (peach_vu_event_entry->ascii_id_offset * SIZE_OF_DWORD));
				memcpy(description, pdescription, peach_vu_event_entry->ascii_id_length + 1);
				return 0;
			}
		}
	}

	return 0;
}

int parse_event_fifo(unsigned int fifo_num, unsigned char *pfifo_start, struct json_object *pevent_fifos_object, unsigned char *pstring_buffer, pnvme_ocp_telemetry_offsets poffsets, __u64 fifo_size, FILE *fp)
{
    if (NULL == pfifo_start || NULL == poffsets)
	{
		nvme_show_error("Input buffer was NULL");
		return -1;
	}

    int status = 0;
	unsigned int event_fifo_number = fifo_num + 1;
	char* description = (char*)malloc((40 + 1) * sizeof(char));
	memset(description, 0 ,sizeof(40));
	status = parse_ocp_telemetry_string_log(event_fifo_number, 0, 0, EVENT_STRING, description);

	if (status != 0)
	{
		nvme_show_error("Failed to get C9 String. status: %d\n", status);
		return -1;
	}

    char event_fifo_name[100] = {0};
    snprintf(event_fifo_name, sizeof(event_fifo_name), "%s%d%s%s", "EVENT FIFO ", event_fifo_number, " - ", description);

	struct json_object *pevent_fifo_array = NULL;

	if(pevent_fifos_object != NULL)
	{
		pevent_fifo_array = json_create_array();
	}
	else
	{
		if(fp)
		{
            fprintf(fp, "=====================================================================================\n");
	        fprintf(fp, "%s\n", event_fifo_name);
	        fprintf(fp, "=====================================================================================\n");
		}
		else
		{
            printf("=====================================================================================\n");
	        printf("%s\n", event_fifo_name);
	        printf("=====================================================================================\n");
		}
	}	
   
	int offset_to_move = 0;
	int event_des_size = sizeof(nvme_ocp_telemetry_event_descriptor_t);
	while ((fifo_size > 0) &&(offset_to_move < fifo_size))
	{
        struct json_object *pevent_descriptor_obj = ((pevent_fifos_object != NULL)?json_create_object():NULL);

		pnvme_ocp_telemetry_event_descriptor pevent_descriptor = (pnvme_ocp_telemetry_event_descriptor)(pfifo_start + offset_to_move);	

		if (pevent_descriptor->event_data_size >= 0)
		{
			//Data is present in the form of DWORDS, So multiplying with sizeof(DWORD)
		    unsigned int data_size = pevent_descriptor->event_data_size * SIZE_OF_DWORD;
			__u8 *pevent_specific_data = (__u8*)pevent_descriptor + event_des_size;

		    char description_str[256] = "";
            parse_ocp_telemetry_string_log(0, pevent_descriptor->event_id, pevent_descriptor->debug_event_class_type, EVENT_STRING, description_str);

            if(pevent_fifos_object != NULL)
		    {
                JSON_ADD_FORMATTED_UINT32_STR(pevent_descriptor_obj, STR_DBG_EVENT_CLASS_TYPE, pevent_descriptor->debug_event_class_type);
		        JSON_ADD_FORMATTED_UINT32_STR(pevent_descriptor_obj, STR_EVENT_IDENTIFIER, pevent_descriptor->event_id);
		        JSON_ADD_STR(pevent_descriptor_obj, STR_EVENT_STRING, description_str);
		        JSON_ADD_FORMATTED_UINT32_STR(pevent_descriptor_obj, STR_EVENT_DATA_SIZE, pevent_descriptor->event_data_size);
			
		        if (pevent_descriptor->debug_event_class_type >= 0x80)
		        {
			        JSON_ADD_FORMATTED_VAR_SIZE_STR(pevent_descriptor_obj, STR_VU_DATA, pevent_specific_data, data_size);
		        }	
		    }	
            else
		    {
				if(fp)
		        {
                    fprintf(fp,"%s: 0x%x\n", STR_DBG_EVENT_CLASS_TYPE, pevent_descriptor->debug_event_class_type);
		            fprintf(fp,"%s: 0x%x\n", STR_EVENT_IDENTIFIER, pevent_descriptor->event_id);
		            fprintf(fp,"%s: %s\n",   STR_EVENT_STRING,     description_str);
		            fprintf(fp,"%s: 0x%x\n", STR_EVENT_DATA_SIZE,  pevent_descriptor->event_data_size);		            
		        }
		        else
		        {
                    printf("%s: 0x%x\n", STR_DBG_EVENT_CLASS_TYPE, pevent_descriptor->debug_event_class_type);
		            printf("%s: 0x%x\n", STR_EVENT_IDENTIFIER, pevent_descriptor->event_id);
		            printf("%s: %s\n",   STR_EVENT_STRING,     description_str);
		            printf("%s: 0x%x\n", STR_EVENT_DATA_SIZE,  pevent_descriptor->event_data_size);
		        }

				if (pevent_descriptor->debug_event_class_type >= 0x80)
		        {
					print_formatted_var_size_str(STR_VU_DATA, pevent_specific_data, data_size, fp);
		        }
	        }

			switch (pevent_descriptor->debug_event_class_type)
			{
			    case RESERVED_CLASS_TYPE:
			    {
			    }
			    break;
				case TIME_STAMP_CLASS_TYPE:
				{
					pnvme_ocp_time_stamp_dbg_evt_class_format ptime_stamp_event = (pnvme_ocp_time_stamp_dbg_evt_class_format)pevent_specific_data;				
					int vu_event_id = (int)ptime_stamp_event->vu_event_identifier;
					unsigned int data_size = ((pevent_descriptor->event_data_size * SIZE_OF_DWORD) - sizeof(nvme_ocp_time_stamp_dbg_evt_class_format_t));
					__u8 *pdata = (__u8*)ptime_stamp_event + sizeof(nvme_ocp_time_stamp_dbg_evt_class_format_t);

					char description_str[256] = "";
                    parse_ocp_telemetry_string_log(0, ptime_stamp_event->vu_event_identifier, pevent_descriptor->debug_event_class_type, VU_EVENT_STRING, description_str);

					if(pevent_fifos_object != NULL)
		            {
						JSON_ADD_FORMATTED_VAR_SIZE_STR(pevent_descriptor_obj, STR_CLASS_SPECIFIC_DATA, ptime_stamp_event->time_stamp, DATA_SIZE_8);
					    JSON_ADD_FORMATTED_UINT32_STR(pevent_descriptor_obj, STR_VU_EVENT_ID_STRING, vu_event_id);					
						JSON_ADD_STR(pevent_descriptor_obj, STR_VU_EVENT_STRING, description_str);
					    JSON_ADD_FORMATTED_VAR_SIZE_STR(pevent_descriptor_obj, STR_VU_DATA, pdata, data_size);
					}
					else
					{
						if(fp)
		                {
							print_formatted_var_size_str(STR_CLASS_SPECIFIC_DATA, ptime_stamp_event->time_stamp, DATA_SIZE_8, fp);
		                    fprintf(fp, "%s: 0x%x\n", STR_VU_EVENT_ID_STRING, vu_event_id);
		                    fprintf(fp, "%s: %s\n", STR_VU_EVENT_STRING, description_str);
						    print_formatted_var_size_str(STR_VU_DATA, pdata, data_size, fp);
						}
						else
						{
							print_formatted_var_size_str(STR_CLASS_SPECIFIC_DATA, ptime_stamp_event->time_stamp, DATA_SIZE_8, fp);
		                    printf("%s: 0x%x\n", STR_VU_EVENT_ID_STRING, vu_event_id);
		                    printf("%s: %s\n", STR_VU_EVENT_STRING, description_str);
						    print_formatted_var_size_str(STR_VU_DATA, pdata, data_size, fp);
						}
					}				
				}
				break;
				case PCIE_CLASS_TYPE:
				{
					pnvme_ocp_pcie_dbg_evt_class_format ppcie_event = (pnvme_ocp_pcie_dbg_evt_class_format)pevent_specific_data;
					int vu_event_id = (int)ppcie_event->vu_event_identifier;
					unsigned int data_size = ((pevent_descriptor->event_data_size * SIZE_OF_DWORD) - sizeof(nvme_ocp_pcie_dbg_evt_class_format_t));
					__u8 *pdata = (__u8*)ppcie_event + sizeof(nvme_ocp_pcie_dbg_evt_class_format_t);

					char description_str[256] = "";
                    parse_ocp_telemetry_string_log(0, ppcie_event->vu_event_identifier, pevent_descriptor->debug_event_class_type, VU_EVENT_STRING, description_str);

					if(pevent_fifos_object != NULL)
		            {
						JSON_ADD_FORMATTED_VAR_SIZE_STR(pevent_descriptor_obj, STR_CLASS_SPECIFIC_DATA, ppcie_event->pCIeDebugEventData, DATA_SIZE_4);
					    JSON_ADD_FORMATTED_UINT32_STR(pevent_descriptor_obj, STR_VU_EVENT_ID_STRING, vu_event_id);
					    JSON_ADD_STR(pevent_descriptor_obj, STR_VU_EVENT_STRING, description_str);
					    JSON_ADD_FORMATTED_VAR_SIZE_STR(pevent_descriptor_obj, STR_VU_DATA, pdata, data_size);
					}
					else
					{
						if(fp)
						{
							print_formatted_var_size_str(STR_CLASS_SPECIFIC_DATA, ppcie_event->pCIeDebugEventData, DATA_SIZE_4, fp);
		                    fprintf(fp, "%s: 0x%x\n", STR_VU_EVENT_ID_STRING, vu_event_id);
		                    fprintf(fp, "%s: %s\n", STR_VU_EVENT_STRING, description_str);
						    print_formatted_var_size_str(STR_VU_DATA, pdata, data_size, fp);
						}
						else
						{
							print_formatted_var_size_str(STR_CLASS_SPECIFIC_DATA, ppcie_event->pCIeDebugEventData, DATA_SIZE_4, fp);
		                    printf("%s: 0x%x\n", STR_VU_EVENT_ID_STRING, vu_event_id);
		                    printf("%s: %s\n", STR_VU_EVENT_STRING, description_str);
						    print_formatted_var_size_str(STR_VU_DATA, pdata, data_size, fp);
						}
					}
				}
				break;
				case NVME_CLASS_TYPE:
				{
					pnvme_ocp_nvme_dbg_evt_class_format pnvme_event = (pnvme_ocp_nvme_dbg_evt_class_format)pevent_specific_data;
					int vu_event_id = (int)pnvme_event->vu_event_identifier;
					unsigned int data_size = ((pevent_descriptor->event_data_size * SIZE_OF_DWORD) - sizeof(nvme_ocp_nvme_dbg_evt_class_format_t));
					__u8 *pdata = (__u8*)pnvme_event + sizeof(nvme_ocp_nvme_dbg_evt_class_format_t);

					char description_str[256] = "";
                    parse_ocp_telemetry_string_log(0, pnvme_event->vu_event_identifier, pevent_descriptor->debug_event_class_type, VU_EVENT_STRING, description_str);

					if(pevent_fifos_object != NULL)
		            {
						JSON_ADD_FORMATTED_VAR_SIZE_STR(pevent_descriptor_obj, STR_CLASS_SPECIFIC_DATA, pnvme_event->nvmeDebugEventData, DATA_SIZE_8);
					    JSON_ADD_FORMATTED_UINT32_STR(pevent_descriptor_obj, STR_VU_EVENT_ID_STRING, vu_event_id);
					    JSON_ADD_STR(pevent_descriptor_obj, STR_VU_EVENT_STRING, description_str);
					    JSON_ADD_FORMATTED_VAR_SIZE_STR(pevent_descriptor_obj, STR_VU_DATA, pdata, data_size);
					}
					else
					{
						if(fp)
						{
							print_formatted_var_size_str(STR_CLASS_SPECIFIC_DATA, pnvme_event->nvmeDebugEventData, DATA_SIZE_8, fp);
		                    fprintf(fp, "%s: 0x%x\n", STR_VU_EVENT_ID_STRING, vu_event_id);
		                    fprintf(fp, "%s: %s\n", STR_VU_EVENT_STRING, description_str);
						    print_formatted_var_size_str(STR_VU_DATA, pdata, data_size, fp);
						}
						else
						{
                            print_formatted_var_size_str(STR_CLASS_SPECIFIC_DATA, pnvme_event->nvmeDebugEventData, DATA_SIZE_8, fp);
		                    printf("%s: 0x%x\n", STR_VU_EVENT_ID_STRING, vu_event_id);
		                    printf("%s: %s\n", STR_VU_EVENT_STRING, description_str);
						    print_formatted_var_size_str(STR_VU_DATA, pdata, data_size, fp);
						}
					}
				}
				break;
				case RESET_CLASS_TYPE:
				case BOOT_SEQUENCE_CLASS_TYPE:
				case FIRMWARE_ASSERT_CLASS_TYPE:
				case TEMPERATURE_CLASS_TYPE:
				case MEDIA_CLASS_TYPE:
				{
					pnvme_ocp_common_dbg_evt_class_format pcommon_debug_event = (pnvme_ocp_common_dbg_evt_class_format)pevent_specific_data;					
					int vu_event_id = (int)pcommon_debug_event->vu_event_identifier;
					unsigned int data_size = ((pevent_descriptor->event_data_size * SIZE_OF_DWORD) - sizeof(nvme_ocp_common_dbg_evt_class_format_t));
					__u8 *pdata = (__u8*)pcommon_debug_event + sizeof(nvme_ocp_common_dbg_evt_class_format_t);

					char description_str[256] = "";
                    parse_ocp_telemetry_string_log(0, pcommon_debug_event->vu_event_identifier, pevent_descriptor->debug_event_class_type, VU_EVENT_STRING, description_str);

					if(pevent_fifos_object != NULL)
		            {
					    JSON_ADD_FORMATTED_UINT32_STR(pevent_descriptor_obj, STR_VU_EVENT_ID_STRING, vu_event_id);
						JSON_ADD_STR(pevent_descriptor_obj, STR_VU_EVENT_STRING, description_str);
					    JSON_ADD_FORMATTED_VAR_SIZE_STR(pevent_descriptor_obj, STR_VU_DATA, pdata, data_size);
					}
					else
					{						
						if(fp)			
						{
                            fprintf(fp, "%s: 0x%x\n", STR_VU_EVENT_ID_STRING, vu_event_id);
		                    fprintf(fp,"%s: %s\n", STR_VU_EVENT_STRING, description_str);
						    print_formatted_var_size_str(STR_VU_DATA, pdata, data_size, fp);
						}
						else
						{
                            printf("%s: 0x%x\n", STR_VU_EVENT_ID_STRING, vu_event_id);
		                    printf("%s: %s\n", STR_VU_EVENT_STRING, description_str);
						    print_formatted_var_size_str(STR_VU_DATA, pdata, data_size, fp);
						}
					}
				}
				break;
				case MEDIA_WEAR_CLASS_TYPE:
				{
					pnvme_ocp_media_wear_dbg_evt_class_format pmedia_wear_event = (pnvme_ocp_media_wear_dbg_evt_class_format)pevent_specific_data;				
					int vu_event_id = (int)pmedia_wear_event->vu_event_identifier;
					unsigned int data_size = ((pevent_descriptor->event_data_size * SIZE_OF_DWORD) - sizeof(nvme_ocp_media_wear_dbg_evt_class_format_t));
					__u8 *pdata = (__u8*)pmedia_wear_event + sizeof(nvme_ocp_media_wear_dbg_evt_class_format_t);

					char description_str[256] = "";
                    parse_ocp_telemetry_string_log(0, pmedia_wear_event->vu_event_identifier, pevent_descriptor->debug_event_class_type, VU_EVENT_STRING, description_str);

					if(pevent_fifos_object != NULL)
		            {
					    JSON_ADD_FORMATTED_VAR_SIZE_STR(pevent_descriptor_obj, STR_CLASS_SPECIFIC_DATA, pmedia_wear_event->currentMediaWear, DATA_SIZE_12);
					    JSON_ADD_FORMATTED_UINT32_STR(pevent_descriptor_obj, STR_VU_EVENT_ID_STRING, vu_event_id);
					    JSON_ADD_STR(pevent_descriptor_obj, STR_VU_EVENT_STRING, description_str);
					    JSON_ADD_FORMATTED_VAR_SIZE_STR(pevent_descriptor_obj, STR_VU_DATA, pdata, data_size);
					}
					else
					{
						if(fp)
						{
							print_formatted_var_size_str(STR_CLASS_SPECIFIC_DATA, pmedia_wear_event->currentMediaWear, DATA_SIZE_12, fp);
		                    fprintf(fp, "%s: 0x%x\n", STR_VU_EVENT_ID_STRING, vu_event_id);
		                    fprintf(fp, "%s: %s\n", STR_VU_EVENT_STRING, description_str);
							print_formatted_var_size_str(STR_VU_DATA, pdata, data_size, fp);
						}
						else
						{
                            print_formatted_var_size_str(STR_CLASS_SPECIFIC_DATA, pmedia_wear_event->currentMediaWear, DATA_SIZE_12, NULL);
		                    printf("%s: 0x%x\n", STR_VU_EVENT_ID_STRING, vu_event_id);
		                    printf("%s: %s\n", STR_VU_EVENT_STRING, description_str);
						    print_formatted_var_size_str(STR_VU_DATA, pdata, data_size, fp);
						}

					}
				}
				break;
				case STATISTIC_SNAPSHOT_CLASS_TYPE:
				{
					pnvme_ocp_statistic_snapshot_evt_class_format pStaticSnapshotEvent = (pnvme_ocp_statistic_snapshot_evt_class_format)pevent_specific_data;
					pnvme_ocp_telemetry_statistic_descriptor pstatistic_entry = (pnvme_ocp_telemetry_statistic_descriptor)(&pStaticSnapshotEvent->statisticDescriptorData);
					parse_statistic(pstatistic_entry, pevent_descriptor_obj, fp);
				}
				break;
			    default:
				{
					//Reserved 7Fh-0Bh and Vendor Unique FFh-80h Classes will fall here, Nothing to Parse
				}
				break;
			}

			if (pevent_descriptor_obj != NULL && pevent_fifo_array != NULL)
			{
				json_array_add_value_object(pevent_fifo_array, pevent_descriptor_obj);
			}
			else
			{
				if(fp)
				{
                    fprintf(fp,"-----------------------------------------------------------------------------\n");
				}
				else
				{
                    printf("-----------------------------------------------------------------------------\n");
				}
			}
		}
		else
		{
			break;
		}
		offset_to_move += (pevent_descriptor->event_data_size * SIZE_OF_DWORD + event_des_size);
	}


	if (pevent_fifos_object != NULL && pevent_fifo_array != NULL)
	{
		json_object_add_value_array(pevent_fifos_object, event_fifo_name, pevent_fifo_array);
	}	

	free(description);
    return 0;
}

int parse_event_fifos(struct json_object *root, pnvme_ocp_telemetry_offsets poffsets, FILE *fp)
{
    if (NULL == poffsets)
	{
		nvme_show_error("Input buffer was NULL");
		return -1;
	}

	struct json_object* pevent_fifos_object = NULL;
	if(NULL != root)
	{
        pevent_fifos_object = json_create_object();
	}

    __u8 *pda1_header_offset = ptelemetry_buffer + poffsets->da1_start_offset;//512
	__u8 *pda2_offset = ptelemetry_buffer + poffsets->da2_start_offset;
	pnvme_ocp_header_in_da1 pda1_header = (pnvme_ocp_header_in_da1)pda1_header_offset;

    nvme_ocp_event_fifo_data_t event_fifo[MAX_NUM_FIFOS];
	for (int fifo_num = 0; fifo_num < MAX_NUM_FIFOS; fifo_num++)
	{
		switch (fifo_num)
		{
		case 0:
		    {
			    event_fifo[fifo_num].event_fifo_num = fifo_num;
			    event_fifo[fifo_num].event_fifo_da = pda1_header->event_fifo_1_da;
			    event_fifo[fifo_num].event_fifo_start = pda1_header->event_fifo_1_start;
			    event_fifo[fifo_num].event_fifo_size = pda1_header->event_fifo_1_size;
		    }
			break;
		case 1:
			{
				event_fifo[fifo_num].event_fifo_num = fifo_num;
				event_fifo[fifo_num].event_fifo_da = pda1_header->event_fifo_2_da;
				event_fifo[fifo_num].event_fifo_start = pda1_header->event_fifo_2_start;
				event_fifo[fifo_num].event_fifo_size = pda1_header->event_fifo_2_size;
			}
			break;
		case 2:
		    {
			    event_fifo[fifo_num].event_fifo_num = fifo_num;
				event_fifo[fifo_num].event_fifo_da = pda1_header->event_fifo_3_da;
				event_fifo[fifo_num].event_fifo_start = pda1_header->event_fifo_3_start;
				event_fifo[fifo_num].event_fifo_size = pda1_header->event_fifo_3_size;
		    }
			break;
		case 3:
		    {
			    event_fifo[fifo_num].event_fifo_num = fifo_num;
				event_fifo[fifo_num].event_fifo_da = pda1_header->event_fifo_4_da;
				event_fifo[fifo_num].event_fifo_start = pda1_header->event_fifo_4_start;
				event_fifo[fifo_num].event_fifo_size = pda1_header->event_fifo_4_size;
		    }
			break;
		case 4:
		    {
			    event_fifo[fifo_num].event_fifo_num = fifo_num;
			    event_fifo[fifo_num].event_fifo_da = pda1_header->event_fifo_5_da;
				event_fifo[fifo_num].event_fifo_start = pda1_header->event_fifo_5_start;
				event_fifo[fifo_num].event_fifo_size = pda1_header->event_fifo_5_size;
		    }
			break;
		case 5:
		    {
			    event_fifo[fifo_num].event_fifo_num = fifo_num;
			    event_fifo[fifo_num].event_fifo_da = pda1_header->event_fifo_6_da;
				event_fifo[fifo_num].event_fifo_start = pda1_header->event_fifo_6_start;
				event_fifo[fifo_num].event_fifo_size = pda1_header->event_fifo_6_size;
		    }
			break;
		case 6:
		    {
			    event_fifo[fifo_num].event_fifo_num = fifo_num;
			    event_fifo[fifo_num].event_fifo_da = pda1_header->event_fifo_7_da;
				event_fifo[fifo_num].event_fifo_start = pda1_header->event_fifo_7_start;
				event_fifo[fifo_num].event_fifo_size = pda1_header->event_fifo_7_size;
		    }
			break;
		case 7:
		    {
			    event_fifo[fifo_num].event_fifo_num = fifo_num;
			    event_fifo[fifo_num].event_fifo_da = pda1_header->event_fifo_8_da;
				event_fifo[fifo_num].event_fifo_start = pda1_header->event_fifo_8_start;
				event_fifo[fifo_num].event_fifo_size = pda1_header->event_fifo_8_size;
		    }
			break;
		case 8:
		    {
			    event_fifo[fifo_num].event_fifo_num = fifo_num;
			    event_fifo[fifo_num].event_fifo_da = pda1_header->event_fifo_9_da;
				event_fifo[fifo_num].event_fifo_start = pda1_header->event_fifo_9_start;
				event_fifo[fifo_num].event_fifo_size = pda1_header->event_fifo_9_size;
		    }
			break;
		case 9:
		    {
			    event_fifo[fifo_num].event_fifo_num = fifo_num;
			    event_fifo[fifo_num].event_fifo_da = pda1_header->event_fifo_10_da;
				event_fifo[fifo_num].event_fifo_start = pda1_header->event_fifo_10_start;
				event_fifo[fifo_num].event_fifo_size = pda1_header->event_fifo_10_size;
		    }
			break;
		case 10:
		    {
			    event_fifo[fifo_num].event_fifo_num = fifo_num;
			    event_fifo[fifo_num].event_fifo_da = pda1_header->event_fifo_11_da;
				event_fifo[fifo_num].event_fifo_start = pda1_header->event_fifo_11_start;
				event_fifo[fifo_num].event_fifo_size = pda1_header->event_fifo_11_size;
		    }
			break;
		case 11:
		    {
			    event_fifo[fifo_num].event_fifo_num = fifo_num;
			    event_fifo[fifo_num].event_fifo_da = pda1_header->event_fifo_12_da;
				event_fifo[fifo_num].event_fifo_start = pda1_header->event_fifo_12_start;
				event_fifo[fifo_num].event_fifo_size = pda1_header->event_fifo_12_size;
		    }
			break;
		case 12:
		    {
			    event_fifo[fifo_num].event_fifo_num = fifo_num;
			    event_fifo[fifo_num].event_fifo_da = pda1_header->event_fifo_13_da;
				event_fifo[fifo_num].event_fifo_start = pda1_header->event_fifo_13_start;
				event_fifo[fifo_num].event_fifo_size = pda1_header->event_fifo_13_size;
		    }
			break;
		case 13:
		    {
			    event_fifo[fifo_num].event_fifo_num = fifo_num;
			    event_fifo[fifo_num].event_fifo_da = pda1_header->event_fifo_14_da;
				event_fifo[fifo_num].event_fifo_start = pda1_header->event_fifo_14_start;
				event_fifo[fifo_num].event_fifo_size = pda1_header->event_fifo_14_size;
		    }
			break;
		case 14:
		    {
			    event_fifo[fifo_num].event_fifo_num = fifo_num;
			    event_fifo[fifo_num].event_fifo_da = pda1_header->event_fifo_15_da;
				event_fifo[fifo_num].event_fifo_start = pda1_header->event_fifo_15_start;
				event_fifo[fifo_num].event_fifo_size = pda1_header->event_fifo_15_size;
		    }
			break;
		case 15:
		    {
			    event_fifo[fifo_num].event_fifo_num = fifo_num;
			    event_fifo[fifo_num].event_fifo_da = pda1_header->event_fifo_16_da;
				event_fifo[fifo_num].event_fifo_start = pda1_header->event_fifo_16_start;
				event_fifo[fifo_num].event_fifo_size = pda1_header->event_fifo_16_size;
		    }
			break;
		default:
			break;
		}
	}

	//Parse all the FIFOs DA wise
	for (int fifo_no = 0; fifo_no < MAX_NUM_FIFOS; fifo_no++)
	{
		if (event_fifo[fifo_no].event_fifo_da == poffsets->data_area)
		{
			__u64 fifo_offset = (event_fifo[fifo_no].event_fifo_start  * SIZE_OF_DWORD);
			__u64 fifo_size = (event_fifo[fifo_no].event_fifo_size  * SIZE_OF_DWORD);
			__u8 *pfifo_start = NULL;

			if (event_fifo[fifo_no].event_fifo_da == 1)
			{
				__u64 offset_in_da_1 = fifo_offset - poffsets->header_size;

				if (offset_in_da_1 > poffsets->da1_size)
				{
					nvme_show_error("Event FIFO %d start is outside of data area 1.\n", fifo_no);
				}
				if ((offset_in_da_1 + fifo_size - 1) > poffsets->da1_size)
				{
					nvme_show_error("Event FIFO %d size is outside of data area 1.\n", fifo_no);
				}
				pfifo_start = pda1_header_offset + fifo_offset;
			}
			else if (event_fifo[fifo_no].event_fifo_da == 2)
			{
				__u64 offset_in_da_2 = fifo_offset;

				if (offset_in_da_2 > poffsets->da2_size)
				{
					nvme_show_error("Event FIFO %d start is outside of data area 2.\n", fifo_no);
				}
				if ((offset_in_da_2 + fifo_size - 1) > poffsets->da2_size)
				{
					nvme_show_error("Event FIFO %d size is outside of data area 2.\n", fifo_no);
				}
				pfifo_start = pda2_offset + fifo_offset;
			}
			else
			{
				nvme_show_error("Unsupported Data Area:[%d]", poffsets->data_area);
				return -1;
			}		    

			int status = parse_event_fifo(fifo_no, pfifo_start, pevent_fifos_object, pstring_buffer, poffsets, fifo_size, fp);
			if (status != 0)
			{
				nvme_show_error("Failed to parse Event FIFO. status: %d\n", status);
				return -1;
			}
		}
	}

    if(pevent_fifos_object != NULL && root != NULL)
	{
        const char* data_area = (poffsets->data_area == 1 ? STR_DA_1_EVENT_FIFO_INFO : STR_DA_2_EVENT_FIFO_INFO);
        json_object_add_value_array(root, data_area, pevent_fifos_object);
	}
	
    return 0;
}

int parse_statistic(pnvme_ocp_telemetry_statistic_descriptor pstatistic_entry, struct json_object *pstats_array, FILE *fp)
{
    if (NULL == pstatistic_entry)
	{
		nvme_show_error("Input buffer was NULL");
		return -1;
	}

    unsigned int data_size = pstatistic_entry->statistic_data_size * SIZE_OF_DWORD;
    __u8 *pdata = (__u8*)pstatistic_entry + sizeof(nvme_ocp_telemetry_statistic_descriptor_t);

	char description_str[256] = "";
    parse_ocp_telemetry_string_log(0, pstatistic_entry->statistic_id, 0, STATISTICS_IDENTIFIER_STRING, description_str);

    if (NULL != pstats_array)
	{
	    struct json_object* pstatistics_object = json_create_object();

        JSON_ADD_FORMATTED_UINT32_STR(pstatistics_object, STR_STATISTICS_IDENTIFIER, pstatistic_entry->statistic_id);
		JSON_ADD_STR(pstatistics_object, STR_STATISTICS_IDENTIFIER_STR, description_str);
	    JSON_ADD_FORMATTED_UINT32_STR(pstatistics_object, STR_STATISTICS_INFO_BEHAVIOUR_TYPE, pstatistic_entry->statistic_info_behaviour_type);
	    JSON_ADD_FORMATTED_UINT32_STR(pstatistics_object, STR_STATISTICS_INFO_RESERVED, pstatistic_entry->statistic_info_reserved);
	    JSON_ADD_FORMATTED_UINT32_STR(pstatistics_object, STR_NAMESPACE_IDENTIFIER, pstatistic_entry->ns_info_nsid);
	    JSON_ADD_FORMATTED_UINT32_STR(pstatistics_object, STR_NAMESPACE_INFO_VALID, pstatistic_entry->ns_info_ns_info_valid);
	    JSON_ADD_FORMATTED_UINT32_STR(pstatistics_object, STR_STATISTICS_DATA_SIZE, pstatistic_entry->statistic_data_size);
	    JSON_ADD_FORMATTED_UINT32_STR(pstatistics_object, STR_RESERVED, pstatistic_entry->reserved);
	    JSON_ADD_FORMATTED_VAR_SIZE_STR(pstatistics_object, STR_STATISTICS_SPECIFIC_DATA, pdata, data_size);

		if(pstatistics_object != NULL)
		{
            json_array_add_value_object(pstats_array, pstatistics_object);
		}		
	}
	else
	{
	    if(fp)
		{
            fprintf(fp, "%s: 0x%x\n", STR_STATISTICS_IDENTIFIER, pstatistic_entry->statistic_id);
		    fprintf(fp, "%s: %s\n",   STR_STATISTICS_IDENTIFIER_STR, description_str);
		    fprintf(fp, "%s: 0x%x\n", STR_STATISTICS_INFO_BEHAVIOUR_TYPE, pstatistic_entry->statistic_info_behaviour_type);
		    fprintf(fp, "%s: 0x%x\n", STR_STATISTICS_INFO_RESERVED,  pstatistic_entry->statistic_info_reserved);
		    fprintf(fp, "%s: 0x%x\n", STR_NAMESPACE_IDENTIFIER, pstatistic_entry->ns_info_nsid);
		    fprintf(fp, "%s: 0x%x\n", STR_NAMESPACE_INFO_VALID, pstatistic_entry->ns_info_ns_info_valid);
		    fprintf(fp, "%s: 0x%x\n", STR_STATISTICS_DATA_SIZE,  pstatistic_entry->statistic_data_size);
		    fprintf(fp, "%s: 0x%x\n", STR_RESERVED, pstatistic_entry->reserved);
		    print_formatted_var_size_str(STR_STATISTICS_SPECIFIC_DATA, pdata, data_size, fp);
		    fprintf(fp, "--------------------------------------------------------------------------------------\n");
		}
		else
		{
            printf("%s: 0x%x\n", STR_STATISTICS_IDENTIFIER, pstatistic_entry->statistic_id);
		    printf("%s: %s\n",   STR_STATISTICS_IDENTIFIER_STR, description_str);
		    printf("%s: 0x%x\n", STR_STATISTICS_INFO_BEHAVIOUR_TYPE, pstatistic_entry->statistic_info_behaviour_type);
		    printf("%s: 0x%x\n", STR_STATISTICS_INFO_RESERVED,  pstatistic_entry->statistic_info_reserved);
		    printf("%s: 0x%x\n", STR_NAMESPACE_IDENTIFIER, pstatistic_entry->ns_info_nsid);
		    printf("%s: 0x%x\n", STR_NAMESPACE_INFO_VALID, pstatistic_entry->ns_info_ns_info_valid);
		    printf("%s: 0x%x\n", STR_STATISTICS_DATA_SIZE,  pstatistic_entry->statistic_data_size);
		    printf("%s: 0x%x\n", STR_RESERVED, pstatistic_entry->reserved);
		    print_formatted_var_size_str(STR_STATISTICS_SPECIFIC_DATA, pdata, data_size, fp);
		    printf("--------------------------------------------------------------------------------------\n");
		}
	}

    return 0;
}

int parse_statistics(struct json_object *root, pnvme_ocp_telemetry_offsets poffsets, FILE *fp)
{
    if (NULL == poffsets)
	{
		nvme_show_error("Input buffer was NULL");
		return -1;
	}

    __u8 *pda1_ocp_header_offset = ptelemetry_buffer + poffsets->header_size;//512
	__u32 statistics_size = 0;
	__u32 stats_da_1_start_dw = 0, stats_da_1_size_dw = 0;
	__u32 stats_da_2_start_dw = 0, stats_da_2_size_dw = 0;
	__u8 *pstats_offset = NULL;

	if (poffsets->data_area == 1)
	{
		__u32 stats_da_1_start = *(__u32 *)(pda1_ocp_header_offset + offsetof(nvme_ocp_header_in_da1_t, da1_statistic_start));
		__u32 stats_da_1_size = *(__u32 *)(pda1_ocp_header_offset + offsetof(nvme_ocp_header_in_da1_t, da1_statistic_size));

		//Data is present in the form of DWORDS, So multiplying with sizeof(DWORD)
		stats_da_1_start_dw = (stats_da_1_start * SIZE_OF_DWORD);
		stats_da_1_size_dw = (stats_da_1_size * SIZE_OF_DWORD);

		pstats_offset = pda1_ocp_header_offset + stats_da_1_start_dw;
		statistics_size = stats_da_1_size_dw;
	}
	else if (poffsets->data_area == 2)
	{
		__u32 stats_da_2_start = *(__u32 *)(pda1_ocp_header_offset + offsetof(nvme_ocp_header_in_da1_t, da2_statistic_start));
		__u32 stats_da_2_size = *(__u32 *)(pda1_ocp_header_offset + offsetof(nvme_ocp_header_in_da1_t, da2_statistic_size));

		stats_da_2_start_dw = (stats_da_2_start * SIZE_OF_DWORD);
		stats_da_2_size_dw = (stats_da_2_size * SIZE_OF_DWORD);

		pstats_offset = pda1_ocp_header_offset + poffsets->da1_size + stats_da_2_start_dw;
		statistics_size = stats_da_2_size_dw;
	}
	else
	{
		nvme_show_error("Unsupported Data Area:[%d]", poffsets->data_area);
		return -1;
	}

    struct json_object *pstats_array = ((NULL != root)? json_create_array() : NULL);
	
	__u32 stat_des_size = sizeof(nvme_ocp_telemetry_statistic_descriptor_t);//8
	__u32 offset_to_move = 0;

	while (((statistics_size > 0) && (offset_to_move < statistics_size)))
	{
		pnvme_ocp_telemetry_statistic_descriptor pstatistic_entry = (pnvme_ocp_telemetry_statistic_descriptor)(pstats_offset + offset_to_move);
		parse_statistic(pstatistic_entry, pstats_array, fp);
		offset_to_move += (pstatistic_entry->statistic_data_size * SIZE_OF_DWORD + stat_des_size);
	}

    if (NULL != root && NULL != pstats_array)
	{
		const char *pdata_area = (poffsets->data_area == 1 ? STR_DA_1_STATS : STR_DA_2_STATS );
        json_object_add_value_array(root, pdata_area, pstats_array);
	}    

    return 0;
}

int print_ocp_telemetry_normal(char *output_file)
{
	int status = 0;
	if(output_file != NULL)
	{
		FILE *fp = fopen(output_file, "w");
		if (fp) 
		{
		    fprintf(fp, "=====================================================================================\n");
	        fprintf(fp, "%s\n", STR_LOG_PAGE_HEADER);
	        fprintf(fp, "=====================================================================================\n");
	        print_micron_vs_logs(ptelemetry_buffer, host_log_page_header, ARRAY_SIZE(host_log_page_header), NULL, 0, fp);

            fprintf(fp, "=====================================================================================\n");
	        fprintf(fp, "%s\n", STR_REASON_IDENTIFIER);
	        fprintf(fp, "=====================================================================================\n");
			__u8 *preason_identifier_offset = ptelemetry_buffer + offsetof(nvme_ocp_telemetry_host_initiated_header_t, reason_id);
	        print_micron_vs_logs(preason_identifier_offset, reason_identifier, ARRAY_SIZE(reason_identifier), NULL, 0, fp);

            fprintf(fp, "=====================================================================================\n");
	        fprintf(fp, "%s\n", STR_TELEMETRY_HOST_DATA_BLOCK_1);
	        fprintf(fp, "=====================================================================================\n");	
	
	        //Set DA to 1 and get offsets
	        nvme_ocp_telemetry_offsets_t offsets = { 0 };
            offsets.data_area = 1;
            pnvme_ocp_telemetry_common_header ptelemetry_common_header = (pnvme_ocp_telemetry_common_header) ptelemetry_buffer;
            get_telemetry_das_offset_and_size(ptelemetry_common_header, &offsets);

            __u8 *pda1_header_offset = ptelemetry_buffer + offsets.da1_start_offset;//512
            print_micron_vs_logs(pda1_header_offset, ocp_header_in_da1, ARRAY_SIZE(ocp_header_in_da1), NULL, 0, fp);

	        fprintf(fp, "=====================================================================================\n");
	        fprintf(fp, "%s\n", STR_SMART_HEALTH_INFO);
	        fprintf(fp, "=====================================================================================\n");	
            __u8 *pda1_smart_offset = pda1_header_offset + offsetof(nvme_ocp_header_in_da1_t, smart_health_info);//512+512 =1024
            print_micron_vs_logs(pda1_smart_offset, smart, ARRAY_SIZE(smart), NULL, 0, fp);

	        fprintf(fp, "=====================================================================================\n");
	        fprintf(fp, "%s\n", STR_SMART_HEALTH_INTO_EXTENDED);
	        fprintf(fp, "=====================================================================================\n");	
            __u8 *pda1_smart_ext_offset = pda1_header_offset + offsetof(nvme_ocp_header_in_da1_t, smart_health_info_extended);//512+1024 =1536
            print_micron_vs_logs(pda1_smart_ext_offset, smart_extended, ARRAY_SIZE(smart_extended), NULL, 0, fp);

	        fprintf(fp, "=====================================================================================\n");
	        fprintf(fp, "%s\n", STR_DA_1_STATS);
	        fprintf(fp, "=====================================================================================\n");

			status = parse_statistics(NULL, &offsets, fp);
	        if (status != 0)
	        {
    	        nvme_show_error("status: %d\n", status);
	            return -1;
	        }

	        fprintf(fp, "=====================================================================================\n");
	        fprintf(fp, "%s\n", STR_DA_1_EVENT_FIFO_INFO);
	        fprintf(fp, "=====================================================================================\n");
	        status = parse_event_fifos(NULL, &offsets, fp);
	        if (status != 0)
	        {
    	        nvme_show_error("status: %d\n", status);
	            return -1;
	        }

            //Set the DA to 2
	        offsets.data_area = 2;

	        fprintf(fp, "=====================================================================================\n");
	        fprintf(fp, "%s\n", STR_DA_2_STATS);
	        fprintf(fp, "=====================================================================================\n");
	        status = parse_statistics(NULL, &offsets, fp);
	        if (status != 0)
	        {
	            nvme_show_error("status: %d\n", status);
	            return -1;
	        }

	        fprintf(fp, "=====================================================================================\n");
	        fprintf(fp, "%s\n", STR_DA_2_EVENT_FIFO_INFO);
	        fprintf(fp, "=====================================================================================\n");
	        status = parse_event_fifos(NULL, &offsets, fp);
	        if (status != 0)
	        {
	            nvme_show_error("status: %d\n", status);
	            return -1;
	        }

	        fprintf(fp, "=====================================================================================\n");

		    fclose(fp);
	    } else	{
		    nvme_show_error("Failed to open %s file.\n", output_file);
			return -1;
	    }
	}
	else
	{
	    printf("=====================================================================================\n");
	    printf("%s\n", STR_LOG_PAGE_HEADER);
	    printf("=====================================================================================\n");
	    print_micron_vs_logs(ptelemetry_buffer, host_log_page_header, ARRAY_SIZE(host_log_page_header), NULL, 0, NULL);

	    printf("=====================================================================================\n");
	    printf("%s\n", STR_REASON_IDENTIFIER);
	    printf("=====================================================================================\n");
		__u8 *preason_identifier_offset = ptelemetry_buffer + offsetof(nvme_ocp_telemetry_host_initiated_header_t, reason_id);
	    print_micron_vs_logs(preason_identifier_offset, reason_identifier, ARRAY_SIZE(reason_identifier), NULL, 0, NULL);

        printf("=====================================================================================\n");
	    printf("%s\n", STR_TELEMETRY_HOST_DATA_BLOCK_1);
	    printf("=====================================================================================\n");	
	
	    //Set DA to 1 and get offsets
	    nvme_ocp_telemetry_offsets_t offsets = { 0 };
        offsets.data_area = 1;
        pnvme_ocp_telemetry_common_header ptelemetry_common_header = (pnvme_ocp_telemetry_common_header) ptelemetry_buffer;
        get_telemetry_das_offset_and_size(ptelemetry_common_header, &offsets);

        __u8 *pda1_header_offset = ptelemetry_buffer + offsets.da1_start_offset;//512
        print_micron_vs_logs(pda1_header_offset, ocp_header_in_da1, ARRAY_SIZE(ocp_header_in_da1), NULL, 0, NULL);

	    printf("=====================================================================================\n");
	    printf("%s\n", STR_SMART_HEALTH_INFO);
	    printf("=====================================================================================\n");	
        __u8 *pda1_smart_offset = pda1_header_offset + offsetof(nvme_ocp_header_in_da1_t, smart_health_info);//512+512 =1024
        print_micron_vs_logs(pda1_smart_offset, smart, ARRAY_SIZE(smart), NULL, 0, NULL);

	    printf("=====================================================================================\n");
	    printf("%s\n", STR_SMART_HEALTH_INTO_EXTENDED);
	    printf("=====================================================================================\n");	
        __u8 *pda1_smart_ext_offset = pda1_header_offset + offsetof(nvme_ocp_header_in_da1_t, smart_health_info_extended);//512+1024 =1536
        print_micron_vs_logs(pda1_smart_ext_offset, smart_extended, ARRAY_SIZE(smart_extended), NULL, 0, NULL);

	    printf("=====================================================================================\n");
	    printf("%s\n", STR_DA_1_STATS);
	    printf("=====================================================================================\n");	
	    status = parse_statistics(NULL, &offsets, NULL);
	    if (status != 0)
	    {
    	    nvme_show_error("status: %d\n", status);
	        return -1;
	    }

	    printf("=====================================================================================\n");
	    printf("%s\n", STR_DA_1_EVENT_FIFO_INFO);
	    printf("=====================================================================================\n");
	    status = parse_event_fifos(NULL, &offsets, NULL);
	    if (status != 0)
	    {
    	    nvme_show_error("status: %d\n", status);
	        return -1;
	    }

        //Set the DA to 2
	    offsets.data_area = 2;

	    printf("=====================================================================================\n");
	    printf("%s\n", STR_DA_2_STATS);
	    printf("=====================================================================================\n");
	    status = parse_statistics(NULL, &offsets, NULL);
	    if (status != 0)
	    {
	        nvme_show_error("status: %d\n", status);
	        return -1;
	    }

	    printf("=====================================================================================\n");
	    printf("%s\n", STR_DA_2_EVENT_FIFO_INFO);
	    printf("=====================================================================================\n");
	    status = parse_event_fifos(NULL, &offsets, NULL);
	    if (status != 0)
	    {
	        nvme_show_error("status: %d\n", status);
	        return -1;
	    }

	    printf("=====================================================================================\n");
	}
	
	return status;
}

int print_ocp_telemetry_json(char *output_file)
{
	int status = 0;

    //create json objects
    struct json_object *root, *pheader, *preason_identifier, *da1_header, *smart_obj, *ext_smart_obj;
	root = json_create_object();

    //Add data to root json object

    //"Log Page Header"
    pheader = json_create_object();        
    print_micron_vs_logs(ptelemetry_buffer, host_log_page_header, ARRAY_SIZE(host_log_page_header), pheader, 0, NULL);
    json_object_add_value_object(root, STR_LOG_PAGE_HEADER, pheader);

    //"Reason Identifier"
    preason_identifier = json_create_object();
	__u8 *preason_identifier_offset = ptelemetry_buffer + offsetof(nvme_ocp_telemetry_host_initiated_header_t, reason_id);
    print_micron_vs_logs(preason_identifier_offset, reason_identifier, ARRAY_SIZE(reason_identifier), preason_identifier, 0, NULL);
    json_object_add_value_object(pheader, STR_REASON_IDENTIFIER, preason_identifier);

    nvme_ocp_telemetry_offsets_t offsets = { 0 };

    //Set DA to 1 and get offsets
    offsets.data_area = 1;
    pnvme_ocp_telemetry_common_header ptelemetry_common_header = (pnvme_ocp_telemetry_common_header) ptelemetry_buffer;
    get_telemetry_das_offset_and_size(ptelemetry_common_header, &offsets);

    //"Telemetry Host-Initiated Data Block 1"
    __u8 *pda1_header_offset = ptelemetry_buffer + offsets.da1_start_offset;//512
    da1_header = json_create_object();        
    print_micron_vs_logs(pda1_header_offset, ocp_header_in_da1, ARRAY_SIZE(ocp_header_in_da1), da1_header, 0, NULL);
    json_object_add_value_object(root, STR_TELEMETRY_HOST_DATA_BLOCK_1, da1_header);

    //"SMART / Health Information Log(LID-02h)"
    __u8 *pda1_smart_offset = pda1_header_offset + offsetof(nvme_ocp_header_in_da1_t, smart_health_info);//512+512 =1024
    smart_obj = json_create_object();        
    print_micron_vs_logs(pda1_smart_offset, smart, ARRAY_SIZE(smart), smart_obj, 0, NULL);
    json_object_add_value_object(da1_header, STR_SMART_HEALTH_INFO, smart_obj);

    //"SMART / Health Information Extended(LID-C0h)"
    __u8 *pda1_smart_ext_offset = pda1_header_offset + offsetof(nvme_ocp_header_in_da1_t, smart_health_info_extended);//512+1024 =1536
    ext_smart_obj = json_create_object();
    print_micron_vs_logs(pda1_smart_ext_offset, smart_extended, ARRAY_SIZE(smart_extended), ext_smart_obj, 0, NULL);
    json_object_add_value_object(da1_header, STR_SMART_HEALTH_INTO_EXTENDED, ext_smart_obj);

    //Data Area 1 Statistics
	status = parse_statistics(root, &offsets, NULL);
	if (status != 0)
	{
	    nvme_show_error("status: %d\n", status);
	    return -1;
	}

	//Data Area 1 Event FIFOs
	status = parse_event_fifos(root, &offsets, NULL);
	if (status != 0)
	{
	    nvme_show_error("status: %d\n", status, NULL);
	    return -1;
	}

    //Set the DA to 2
	offsets.data_area = 2;

	//Data Area 2 Statistics
	status = parse_statistics(root, &offsets, NULL);
	if (status != 0)
	{
	    nvme_show_error("status: %d\n", status);
	    return -1;
	}

	//Data Area 2 Event FIFOs
	status = parse_event_fifos(root, &offsets, NULL);
	if (status != 0)
	{
	    nvme_show_error("status: %d\n", status);
	    return -1;
	}

    if(output_file != NULL)
	{
		const char *json_string = json_object_to_json_string(root);
		FILE *fp = fopen(output_file, "w");
		if (fp) 
		{
		    fputs(json_string, fp);
		    fclose(fp);
	    } else	{
		    nvme_show_error("Failed to open %s file.\n", output_file);
			return -1;
	    }
	}
	else
	{
        //Print root json object
        json_print_object(root, NULL);
	    nvme_show_result("\n");
        json_free_object(root);
	}

	return status;
}

int parse_ocp_telemetry_log(pocp_telemetry_parse_options options)
{
    int status = 0;
    // Read the data from the telemetry binary file
    long telemetry_buffer_size = 0;
	ptelemetry_buffer = read_binary_file(NULL, options->telemetry_log, &telemetry_buffer_size, 1);
	if (ptelemetry_buffer == NULL)
	{
        nvme_show_error("Failed to read telemetry bin file.\n");
        return -1;
    }

    // Read the data from the string binary file
    long string_buffer_size = 0;
	pstring_buffer = read_binary_file(NULL, options->string_log, &string_buffer_size, 1);
	if (pstring_buffer == NULL)
	{
        nvme_show_error("Failed to read string log bin file.\n");
        return -1;
	}

    unsigned char log_id = ptelemetry_buffer[0];
	if ((log_id != NVME_HOST_TELEMETRY_LOG) && (log_id != NVME_CNTRL_TELEMETRY_LOG))
	{
        nvme_show_error("Invalid LogPageId [0x%02X]\n", log_id);
		return -1;
	}

    enum nvme_print_flags fmt;
    status = validate_output_format(options->output_fmt, &fmt);
	if (status < 0) {
		nvme_show_error("Invalid output format\n");
		return status;
	}

    switch (fmt) {
		case NORMAL:
			print_ocp_telemetry_normal(options->output_file);
			break;
		case JSON:
			print_ocp_telemetry_json(options->output_file);
			break;
		default:
			break;
	}

    return 0;
}