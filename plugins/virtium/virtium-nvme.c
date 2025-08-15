// SPDX-License-Identifier: GPL-2.0-or-later
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stddef.h>
#include <inttypes.h>
#include <stdbool.h>
#include <time.h>
#include <locale.h>

#include "common.h"
#include "nvme.h"
#include "libnvme.h"
#include "plugin.h"
#include "util/types.h"

#define CREATE_CMD
#include "virtium-nvme.h"

#define MIN2(a, b) (((a) < (b)) ? (a) : (b))

#define HOUR_IN_SECONDS     3600

#define MAX_HEADER_BUFF     (20 * 1024)
#define MAX_LOG_BUFF        4096
#define DEFAULT_TEST_NAME   "Put the name of your test here"

static char vt_default_log_file_name[256];

struct vtview_log_header {
	char				path[256];
	char				test_name[256];
	time_t				time_stamp;
	struct nvme_id_ctrl		raw_ctrl;
	struct nvme_firmware_slot	raw_fw;
};

struct vtview_smart_log_entry {
	char			path[256];
	time_t			time_stamp;
	struct nvme_id_ns	raw_ns;
	struct nvme_id_ctrl	raw_ctrl;
	struct nvme_smart_log	raw_smart;
};

struct vtview_save_log_settings {
	double		run_time_hrs;
	double		log_record_frequency_hrs;
	const char	*output_file;
	const char	*test_name;
};

static void vt_initialize_header_buffer(struct vtview_log_header *pbuff)
{
	memset(pbuff->path, 0, sizeof(pbuff->path));
	memset(pbuff->test_name, 0, sizeof(pbuff->test_name));
}

static void vt_convert_data_buffer_to_hex_string(const unsigned char *bufPtr,
		const unsigned int size, const bool isReverted, char *output)
{
	unsigned int i, pos;
	const char hextable[16] = {
		'0', '1', '2', '3',
		'4', '5', '6', '7',
		'8', '9', 'A', 'B',
		'C', 'D', 'E', 'F',
	};

	memset(output, 0, (size * 2) + 1);

	for (i = 0; i < size; i++) {
		if (isReverted)
			pos = size - 1 - i;
		else
			pos = i;
		output[2 * i] = hextable[(bufPtr[pos] & 0xF0) >> 4];
		output[2 * i + 1] = hextable[(bufPtr[pos] & 0x0F)];
	}
}

/*
 * Generate log file name.
 * Log file name will be generated automatically if user leave log file option blank.
 * Log file name will be generated as vtView-Smart-log-date-time.txt
 */
static void vt_generate_vtview_log_file_name(char *fname)
{
	time_t     current;
	struct tm  tstamp;
	char       temp[256];

	time(&current);

	tstamp = *localtime(&current);
	snprintf(temp, sizeof(temp), "./vtView-Smart-log-");
	strcat(fname, temp);
	strftime(temp, sizeof(temp), "%Y-%m-%d", &tstamp);
	strcat(fname, temp);
	snprintf(temp, sizeof(temp), ".txt");
	strcat(fname, temp);
}

static void vt_convert_smart_data_to_human_readable_format(struct vtview_smart_log_entry *smart, char *text)
{
	char tempbuff[1024] = "";
	int i;
	int temperature = ((smart->raw_smart.temperature[1] << 8) | smart->raw_smart.temperature[0]) - 273;
	double capacity;
	char *curlocale;
	char *templocale;
	__u8 lba_index;

	nvme_id_ns_flbas_to_lbaf_inuse(smart->raw_ns.flbas, &lba_index);

	curlocale = setlocale(LC_ALL, NULL);
	templocale = strdup(curlocale);

	if (!templocale)
		printf("Cannot malloc buffer\n");

	setlocale(LC_ALL, "C");

	unsigned long long lba = 1ULL << smart->raw_ns.lbaf[lba_index].ds;

	capacity = le64_to_cpu(smart->raw_ns.nsze) * lba;

	snprintf(tempbuff, sizeof(tempbuff), "log;%s;%llu;%s;%s;%-.*s;", smart->raw_ctrl.sn,
		 (unsigned long long)smart->time_stamp, smart->path,
		 smart->raw_ctrl.mn, (int)sizeof(smart->raw_ctrl.fr),
		 smart->raw_ctrl.fr);
	strcpy(text, tempbuff);
	snprintf(tempbuff, sizeof(tempbuff), "Capacity;%lf;", capacity / 1000000000);
	strcat(text, tempbuff);
	snprintf(tempbuff, sizeof(tempbuff), "Critical_Warning;%u;", smart->raw_smart.critical_warning);
	strcat(text, tempbuff);
	snprintf(tempbuff, sizeof(tempbuff), "Temperature;%u;", temperature);
	strcat(text, tempbuff);
	snprintf(tempbuff, sizeof(tempbuff), "Available_Spare;%u;", smart->raw_smart.avail_spare);
	strcat(text, tempbuff);
	snprintf(tempbuff, sizeof(tempbuff), "Available_Spare_Threshold;%u;", smart->raw_smart.spare_thresh);
	strcat(text, tempbuff);
	snprintf(tempbuff, sizeof(tempbuff), "Percentage_Used;%u;", smart->raw_smart.percent_used);
	strcat(text, tempbuff);
	snprintf(tempbuff, sizeof(tempbuff), "Data_Units_Read;%s;", uint128_t_to_string(le128_to_cpu(smart->raw_smart.data_units_read)));
	strcat(text, tempbuff);
	snprintf(tempbuff, sizeof(tempbuff), "Data_Units_Written;%s;", uint128_t_to_string(le128_to_cpu(smart->raw_smart.data_units_written)));
	strcat(text, tempbuff);
	snprintf(tempbuff, sizeof(tempbuff), "Host_Read_Commands;%s;", uint128_t_to_string(le128_to_cpu(smart->raw_smart.host_reads)));
	strcat(text, tempbuff);
	snprintf(tempbuff, sizeof(tempbuff), "Host_Write_Commands;%s;", uint128_t_to_string(le128_to_cpu(smart->raw_smart.host_writes)));
	strcat(text, tempbuff);
	snprintf(tempbuff, sizeof(tempbuff), "Controller_Busy_Time;%s;", uint128_t_to_string(le128_to_cpu(smart->raw_smart.ctrl_busy_time)));
	strcat(text, tempbuff);
	snprintf(tempbuff, sizeof(tempbuff), "Power_Cycles;%s;", uint128_t_to_string(le128_to_cpu(smart->raw_smart.power_cycles)));
	strcat(text, tempbuff);
	snprintf(tempbuff, sizeof(tempbuff), "Power_On_Hours;%s;", uint128_t_to_string(le128_to_cpu(smart->raw_smart.power_on_hours)));
	strcat(text, tempbuff);
	snprintf(tempbuff, sizeof(tempbuff), "Unsafe_Shutdowns;%s;", uint128_t_to_string(le128_to_cpu(smart->raw_smart.unsafe_shutdowns)));
	strcat(text, tempbuff);
	snprintf(tempbuff, sizeof(tempbuff), "Media_Errors;%s;", uint128_t_to_string(le128_to_cpu(smart->raw_smart.media_errors)));
	strcat(text, tempbuff);
	snprintf(tempbuff, sizeof(tempbuff), "Num_Err_Log_Entries;%s;", uint128_t_to_string(le128_to_cpu(smart->raw_smart.num_err_log_entries)));
	strcat(text, tempbuff);
	snprintf(tempbuff, sizeof(tempbuff), "Warning_Temperature_Time;%u;", le32_to_cpu(smart->raw_smart.warning_temp_time));
	strcat(text, tempbuff);
	snprintf(tempbuff, sizeof(tempbuff), "Critical_Composite_Temperature_Time;%u;", le32_to_cpu(smart->raw_smart.critical_comp_time));
	strcat(text, tempbuff);

	for (i = 0; i < 8; i++) {
		__s32 temp = le16_to_cpu(smart->raw_smart.temp_sensor[i]);

		if (!temp) {
			snprintf(tempbuff, sizeof(tempbuff), "Temperature_Sensor_%d;NC;", i);
			strcat(text, tempbuff);
			continue;
		}
		snprintf(tempbuff, sizeof(tempbuff), "Temperature_Sensor_%d;%d;", i, temp - 273);
		strcat(text, tempbuff);
	}

	snprintf(tempbuff, sizeof(tempbuff), "Thermal_Management_T1_Trans_Count;%u;", le32_to_cpu(smart->raw_smart.thm_temp1_trans_count));
	strcat(text, tempbuff);
	snprintf(tempbuff, sizeof(tempbuff), "Thermal_Management_T2_Trans_Count;%u;", le32_to_cpu(smart->raw_smart.thm_temp2_trans_count));
	strcat(text, tempbuff);
	snprintf(tempbuff, sizeof(tempbuff), "Thermal_Management_T1_Total_Time;%u;", le32_to_cpu(smart->raw_smart.thm_temp1_total_time));
	strcat(text, tempbuff);
	snprintf(tempbuff, sizeof(tempbuff), "Thermal_Management_T2_Total_Time;%u;", le32_to_cpu(smart->raw_smart.thm_temp2_total_time));
	strcat(text, tempbuff);

	snprintf(tempbuff, sizeof(tempbuff), "NandWrites;%d;\n", 0);
	strcat(text, tempbuff);

	setlocale(LC_ALL, templocale);
	free(templocale);
}

static void vt_header_to_string(const struct vtview_log_header *header, char *text)
{
	char timebuff[50] = "";
	char tempbuff[MAX_HEADER_BUFF] = "";
	char identext[16384] = "";
	char fwtext[2048] = "";

	strftime(timebuff, 50, "%Y-%m-%d %H:%M:%S", localtime(&(header->time_stamp)));
	snprintf(tempbuff, MAX_HEADER_BUFF, "header;{\"session\":{\"testName\":\"%s\",\"dateTime\":\"%s\"},",
		header->test_name, timebuff);
	strcpy(text, tempbuff);

	vt_convert_data_buffer_to_hex_string((unsigned char *)&(header->raw_ctrl), sizeof(header->raw_ctrl), false, identext);
	vt_convert_data_buffer_to_hex_string((unsigned char *)&(header->raw_fw), sizeof(header->raw_fw), false, fwtext);
	snprintf(tempbuff, MAX_HEADER_BUFF,
		"\"devices\":[{\"model\":\"%s\",\"port\":\"%s\",\"SN\":\"%s\",\"type\":\"NVMe\",\"identify\":\"%s\",\"firmwareSlot\":\"%s\"}]}\n",
		header->raw_ctrl.mn, header->path, header->raw_ctrl.sn, identext, fwtext);
	strcat(text, tempbuff);
}

static int vt_append_text_file(const char *text, const char *filename)
{
	FILE *f;

	f = fopen(filename, "a");
	if (!f) {
		printf("Cannot open %s\n", filename);
		return -1;
	}

	fprintf(f, "%s", text);
	fclose(f);
	return 0;
}

static int vt_append_log(struct vtview_smart_log_entry *smart, const char *filename)
{
	char sm_log_text[MAX_LOG_BUFF] = "";

	vt_convert_smart_data_to_human_readable_format(smart, sm_log_text);
	return vt_append_text_file(sm_log_text, filename);
}

static int vt_append_header(const struct vtview_log_header *header, const char *filename)
{
	char header_text[MAX_HEADER_BUFF] = "";

	vt_header_to_string(header, header_text);
	return vt_append_text_file(header_text, filename);
}

static void vt_process_string(char *str, const size_t size)
{
	size_t i;

	if (!size)
		return;

	i = size - 1;
	while (i && (' ' == str[i])) {
		str[i] = 0;
		i--;
	}
}

static int vt_add_entry_to_log(struct nvme_transport_handle *hdl,
			       const char *path,
			       const struct vtview_save_log_settings *cfg)
{
	struct vtview_smart_log_entry smart;
	const char *filename;
	int ret = 0;
	unsigned int nsid = 0;

	memset(smart.path, 0, sizeof(smart.path));
	strncpy(smart.path, path, sizeof(smart.path) - 1);
	if (!cfg->output_file)
		filename = vt_default_log_file_name;
	else
		filename = cfg->output_file;

	smart.time_stamp = time(NULL);
	ret = nvme_get_nsid(hdl, &nsid);

	if (ret < 0) {
		printf("Cannot read namespace-id\n");
		return -1;
	}

	ret = nvme_identify_ns(hdl, nsid, &smart.raw_ns);
	if (ret) {
		printf("Cannot read namespace identify\n");
		return -1;
	}

	ret = nvme_identify_ctrl(hdl, &smart.raw_ctrl);
	if (ret) {
		printf("Cannot read device identify controller\n");
		return -1;
	}

	ret = nvme_get_log_smart(hdl, NVME_NSID_ALL, &smart.raw_smart);
	if (ret) {
		printf("Cannot read device SMART log\n");
		return -1;
	}

	vt_process_string(smart.raw_ctrl.sn, sizeof(smart.raw_ctrl.sn));
	vt_process_string(smart.raw_ctrl.mn, sizeof(smart.raw_ctrl.mn));

	ret = vt_append_log(&smart, filename);
	return ret;
}

static int
vt_update_vtview_log_header(struct nvme_transport_handle *hdl, const char *path,
			    const struct vtview_save_log_settings *cfg)
{
	struct vtview_log_header header;
	const char *filename;
	int ret = 0;

	vt_initialize_header_buffer(&header);
	if (strlen(path) > sizeof(header.path)) {
		printf("filename too long\n");
		errno = EINVAL;
		return -1;
	}
	strcpy(header.path, path);

	if (!cfg->test_name) {
		strcpy(header.test_name, DEFAULT_TEST_NAME);
	} else {
		if (strlen(cfg->test_name) > sizeof(header.test_name)) {
			printf("test name too long\n");
			errno = EINVAL;
			return -1;
		}
		strcpy(header.test_name, cfg->test_name);
	}

	if (!cfg->output_file)
		filename = vt_default_log_file_name;
	else
		filename = cfg->output_file;

	printf("Log file: %s\n", filename);
	header.time_stamp = time(NULL);

	ret = nvme_identify_ctrl(hdl, &header.raw_ctrl);
	if (ret) {
		printf("Cannot read identify device\n");
		return -1;
	}

	ret = nvme_get_log_fw_slot(hdl, false, &header.raw_fw);
	if (ret) {
		printf("Cannot read device firmware log\n");
		return -1;
	}

	vt_process_string(header.raw_ctrl.sn, sizeof(header.raw_ctrl.sn));
	vt_process_string(header.raw_ctrl.mn, sizeof(header.raw_ctrl.mn));

	ret = vt_append_header(&header, filename);
	return ret;
}

static void vt_build_identify_lv2(unsigned int data, unsigned int start,
				  unsigned int count, const char **table,
				  bool isEnd)
{
	unsigned int i, end, pos, sh = 1;
	unsigned int temp;

	end = start + count;

	for (i = start; i < end; i++) {
		temp = ((data & (sh << i)) >> i);
		pos = i * 2;
		printf("        \"bit %u\":\"%ub  %s\"\n", i, temp, table[pos]);
		printf("                     %s", table[pos + 1]);

		if ((end - 1) != i || !isEnd)
			printf(",\n");
		else
			printf("\n");
	}

	if (isEnd)
		printf("    },\n");
}

static void vt_build_power_state_descriptor(const struct nvme_id_ctrl *ctrl)
{
	unsigned int i;
	unsigned char *buf;

	printf("{\n");
	printf("\"Power State Descriptors\":{\n");
	printf("    \"NOPS\":\"Non-Operational State,\"\n");
	printf("    \"MPS\":\"Max Power Scale (0: in 0.01 Watts; 1: in 0.0001 Watts),\"\n");
	printf("    \"ENLAT\":\"Entry Latency in microseconds,\"\n");
	printf("    \"RWL\":\"Relative Write Latency,\"\n");
	printf("    \"RRL\":\"Relative Read Latency,\"\n");
	printf("    \"IPS\":\"Idle Power Scale (00b: Not reported; 01b: 0.0001 W; 10b: 0.01 W; 11b: Reserved),\"\n");
	printf("    \"APS\":\"Active Power Scale (00b: Not reported; 01b: 0.0001 W; 10b: 0.01 W; 11b: Reserved),\"\n");
	printf("    \"ACTP\":\"Active Power,\"\n");
	printf("    \"MP\":\"Maximum Power,\"\n");
	printf("    \"EXLAT\":\"Exit Latency in microsecond,\"\n");
	printf("    \"RWT\":\"Relative Write Throughput,\"\n");
	printf("    \"RRT\":\"Relative Read Throughput,\"\n");
	printf("    \"IDLP\":\"Idle Power,\"\n");
	printf("    \"APW\":\"Active Power Workload,\"\n");
	printf("    \"Ofs\":\"BYTE Offset,\"\n");

	printf("    \"Power State Descriptors\":\"\n");

	printf("%6s%10s%5s%4s%6s%10s%10s%10s%4s%4s%4s%4s%10s%4s%6s%10s%4s%5s%6s\n", "Entry", "0fs 00-03", "NOPS", "MPS", "MP", "ENLAT", "EXLAT", "0fs 12-15",
			"RWL", "RWT", "RRL", "RRT", "0fs 16-19", "IPS", "IDLP", "0fs 20-23", "APS", "APW", "ACTP");


	printf("%6s%10s%5s%4s%6s%10s%10s%10s%4s%4s%4s%4s%10s%4s%6s%10s%4s%5s%6s\n", "=====", "=========", "====", "===", "=====", "=========", "=========",
			"=========", "===", "===", "===", "===", "=========", "===", "=====", "=========", "===", "====", "=====");

	for (i = 0; i < 32; i++) {
		char s[100];
		unsigned int temp;

		printf("%6d", i);
		buf = (unsigned char *) (&ctrl->psd[i]);
		vt_convert_data_buffer_to_hex_string(&buf[0], 4, true, s);
		printf("%9sh", s);

		temp = ctrl->psd[i].flags;
		printf("%4ub", ((unsigned char)temp & 0x02));
		printf("%3ub", ((unsigned char)temp & 0x01));
		vt_convert_data_buffer_to_hex_string(&buf[0], 2, true, s);
		printf("%5sh", s);

		vt_convert_data_buffer_to_hex_string(&buf[4], 4, true, s);
		printf("%9sh", s);
		vt_convert_data_buffer_to_hex_string(&buf[8], 4, true, s);
		printf("%9sh", s);
		vt_convert_data_buffer_to_hex_string(&buf[12], 4, true, s);
		printf("%9sh", s);
		vt_convert_data_buffer_to_hex_string(&buf[15], 1, true, s);
		printf("%3sh", s);
		vt_convert_data_buffer_to_hex_string(&buf[14], 1, true, s);
		printf("%3sh", s);
		vt_convert_data_buffer_to_hex_string(&buf[13], 1, true, s);
		printf("%3sh", s);
		vt_convert_data_buffer_to_hex_string(&buf[12], 1, true, s);
		printf("%3sh", s);
		vt_convert_data_buffer_to_hex_string(&buf[16], 4, true, s);
		printf("%9sh", s);

		temp = ctrl->psd[i].ips;
		snprintf(s, sizeof(s), "%u%u", (((unsigned char)temp >> 6) & 0x01), (((unsigned char)temp >> 7) & 0x01));
		printf("%3sb", s);

		vt_convert_data_buffer_to_hex_string(&buf[16], 2, true, s);
		printf("%5sh", s);
		vt_convert_data_buffer_to_hex_string(&buf[20], 4, true, s);
		printf("%9sh", s);

		temp = ctrl->psd[i].apws;
		snprintf(s, sizeof(s), "%u%u", (((unsigned char)temp >> 6) & 0x01), (((unsigned char)temp >> 7) & 0x01));
		printf("%3sb", s);
		snprintf(s, sizeof(s), "%u%u%u", (((unsigned char)temp) & 0x01), (((unsigned char)temp >> 1) & 0x01), (((unsigned char)temp >> 2) & 0x01));
		printf("%4sb", s);

		vt_convert_data_buffer_to_hex_string(&buf[20], 2, true, s);
		printf("%5sh", s);
		printf("\n");
	}

	printf("    \"}\n}\n");

}

static void vt_dump_hex_data(const unsigned char *pbuff, size_t pbuffsize)
{
	char textbuf[33];
	unsigned long i, j;

	textbuf[32] = '\0';
	printf("[%08X] ", 0);
	for (i = 0; i < pbuffsize; i++) {
		printf("%02X ", pbuff[i]);

		if (pbuff[i] >= ' ' && pbuff[i] <= '~')
			textbuf[i % 32] = pbuff[i];
		else
			textbuf[i % 32] = '.';

		if (!(((i + 1) % 8)) || ((i + 1) == pbuffsize)) {
			printf(" ");
			if (!((i + 1) % 32)) {
				printf(" %s\n", textbuf);
				if ((i + 1) != pbuffsize)
					printf("[%08lX] ", (i + 1));
			} else if (i + 1 == pbuffsize) {
				textbuf[(i + 1) % 32] = '\0';
				if (!((i + 1) % 8))
					printf(" ");

				for (j = ((i + 1) % 32); j < 32; j++) {
					printf("   ");
					if (!((j + 1) % 8))
						printf(" ");
				}

				printf("%s\n", textbuf);
			}
		}
	}
}

static void vt_parse_detail_identify(const struct nvme_id_ctrl *ctrl)
{
	unsigned char *buf;
	unsigned int temp, pos;
	char s[1024] = "";

	const char *CMICtable[6] = {"0 = the NVM subsystem contains only a single NVM subsystem port",
				    "1 = the NVM subsystem may contain more than one subsystem ports",
				    "0 = the NVM subsystem contains only a single controller",
				    "1 = the NVM subsystem may contain two or more controllers (see section 1.4.1)",
				    "0 = the controller is associated with a PCI Function or a Fabrics connection",
				    "1 = the controller is associated with an SR-IOV Virtual Function"};

	const char *OAEStable[20] = {"Reserved",
				     "Reserved",
				     "Reserved",
				     "Reserved",
				     "Reserved",
				     "Reserved",
				     "Reserved",
				     "Reserved",
				     "Reserved",
				     "Reserved",
				     "Reserved",
				     "Reserved",
				     "Reserved",
				     "Reserved",
				     "Reserved",
				     "Reserved",
				     "0 = does not support sending the Namespace Attribute Notices event nor the associated Changed Namespace List log page",
				     "1 = supports sending the Namespace Attribute Notices  & the associated Changed Namespace List log page",
				     "0 = does not support sending Firmware Activation Notices event",
				     "1 = supports sending Firmware Activation Notices"};

	const char *CTRATTtable[4] = {"0 = does not support a 128-bit Host Identifier",
				      "1 = supports a 128-bit Host Identifier",
				      "0 = does not support Non-Operational Power State Permissive Mode",
				      "1 = supports Non-Operational Power State Permissive Mode"};

	const char *OACStable[18] = {"0 = does not support the Security Send and Security Receive commands",
				     "1 = supports the Security Send and Security Receive commands",
				     "0 = does not support the Format NVM command",
				     "1 = supports the Format NVM command",
				     "0 = does not support the Firmware Commit and Firmware Image Download commands",
				     "1 = supports the Firmware Commit and Firmware Image Download commands",
				     "0 = does not support the Namespace Management capability",
				     "1 = supports the Namespace Management capability",
				     "0 = does not support the Device Self-test command",
				     "1 = supports the Device Self-test command",
				     "0 = does not support Directives",
				     "1 = supports Directive Send & Directive Receive commands",
				     "0 = does not support the NVMe-MI Send and NVMe-MI Receive commands",
				     "1 = supports the NVMe-MI Send and NVMe-MI Receive commands",
				     "0 = does not support the Virtualization Management command",
				     "1 = supports the Virtualization Management command",
				     "0 = does not support the Doorbell Buffer Config command",
				     "1 = supports the Doorbell Buffer Config command"};

	const char *FRMWtable[10] = {"0 = the 1st firmware slot (slot 1) is read/write",
				     "1 = the 1st firmware slot (slot 1) is read only",
				     "Reserved",
				     "Reserved",
				     "Reserved",
				     "Reserved",
				     "Reserved",
				     "Reserved",
				     "0 = requires a reset for firmware to be activated",
				     "1 = supports firmware activation without a reset"};

	const char *LPAtable[8] = {"0 = does not support the SMART / Health information log page on a per namespace basis",
				   "1 = supports the SMART / Health information log page on a per namespace basis",
				   "0 = does not support the Commands Supported & Effects log page",
				   "1 = supports the Commands Supported Effects log page",
				   "0 = does not support extended data for Get Log Page",
				   "1 = supports extended data for Get Log Page (including extended Number of Dwords and Log Page Offset fields)",
				   "0 = does not support the Telemetry Host-Initiated and Telemetry Controller-Initiated log pages and Telemetry Log Notices events",
				   "1 = supports the Telemetry Host-Initiated and Telemetry Controller-Initiated log pages and sending Telemetry Log Notices"};

	const char *AVSCCtable[2] = {"0 = the format of all Admin Vendor Specific Commands are vendor specific",
				     "1 = all Admin Vendor Specific Commands use the format defined in NVM Express specification"};

	const char *APSTAtable[2] = {"0 = does not support autonomous power state transitions",
				     "1 = supports autonomous power state transitions"};

	const char *DSTOtable[2] =  {"0 = the NVM subsystem supports one device self-test operation per controller at a time",
				     "1 = the NVM subsystem supports only one device self-test operation in progress at a time"};

	const char *HCTMAtable[2] = {"0 = does not support host controlled thermal management",
				     "1 = supports host controlled thermal management. Supports Set Features & Get Features commands with the Feature Identifier field set to 10h"};

	const char *SANICAPtable[6] =  {"0 = does not support the Crypto Erase sanitize operation",
					"1 = supports the Crypto Erase sanitize operation",
					"0 = does not support the Block Erase sanitize operation",
					"1 = supports the Block Erase sanitize operation",
					"0 = does not support the Overwrite sanitize operation",
					"1 = supports the Overwrite sanitize operation"};

	const char *ONCStable[14] =  {"0 = does not support the Compare command",
				      "1 = supports the Compare command",
				      "0 = does not support the Write Uncorrectable command",
				      "1 = supports the Write Uncorrectable command",
				      "0 = does not support the Dataset Management command",
				      "1 = supports the Dataset Management command",
				      "0 = does not support the Write Zeroes command",
				      "1 = supports the Write Zeroes command",
				      "0 = does not support the Save field set to a non-zero value in the Set Features and the Get Features commands",
				      "1 = supports the Save field set to a non-zero value in the Set Features and the Get Features commands",
				      "0 = does not support reservations",
				      "1 = supports reservations",
				      "0 = does not support the Timestamp feature (refer to section 5.21.1.14)",
				      "1 = supports the Timestamp feature"};

	const char *FUSEStable[2] = {"0 =  does not support the Compare and Write fused operation",
				     "1 =  supports the Compare and Write fused operation"};

	const char *FNAtable[6] = {"0 = supports format on a per namespace basis",
				   "1 = all namespaces shall be configured with the same attributes and a format (excluding secure erase) of any namespace results in a format of all namespaces in an NVM subsystem",
				   "0 = any secure erase performed as part of a format results in a secure erase of a particular namespace specified",
				   "1 = any secure erase performed as part of a format operation results in a secure erase of all namespaces in the NVM subsystem",
				   "0 = cryptographic erase is not supported",
				   "1 = cryptographic erase is supported as part of the secure erase functionality"};

	const char *VWCtable[2] = {"0 = a volatile write cache is not present",
				   "1 = a volatile write cache is present"};

	const char *ICSVSCCtable[2] = {"0 = the format of all NVM Vendor Specific Commands are vendor specific",
				       "1 = all NVM Vendor Specific Commands use the format defined in NVM Express specification"};

	const char *SGLSSubtable[4] =  {"00b = SGLs are not supported",
					"01b = SGLs are supported. There is no alignment nor granularity requirement for Data Blocks",
					"10b = SGLs are supported. There is a Dword alignment and granularity requirement for Data Blocks",
					"11b = Reserved"};

	const char *SGLStable[42] =  {"Used",
				      "Used",
				      "Used",
				      "Used",
				      "0 = does not support the Keyed SGL Data Block descriptor",
				      "1 = supports the Keyed SGL Data Block descriptor",
				      "Reserved",
				      "Reserved",
				      "Reserved",
				      "Reserved",
				      "Reserved",
				      "Reserved",
				      "Reserved",
				      "Reserved",
				      "Reserved",
				      "Reserved",
				      "Reserved",
				      "Reserved",
				      "Reserved",
				      "Reserved",
				      "Reserved",
				      "Reserved",
				      "Reserved",
				      "Reserved",
				      "Reserved",
				      "Reserved",
				      "Reserved",
				      "Reserved",
				      "Reserved",
				      "Reserved",
				      "Reserved",
				      "Reserved",
				      "0 = the SGL Bit Bucket descriptor is not supported",
				      "1 = the SGL Bit Bucket descriptor is supported",
				      "0 = use of a byte aligned contiguous physical buffer of metadata is not supported",
				      "1 = use of a byte aligned contiguous physical buffer of metadata is supported",
				      "0 = the SGL length shall be equal to the amount of data to be transferred",
				      "1 = supports commands that contain a data or metadata SGL of a length larger than the amount of data to be transferred",
				      "0 = use of Metadata Pointer (MPTR) that contains an address of an SGL segment containing exactly one SGL Descriptor that is Qword aligned is not supported",
				      "1 = use of Metadata Pointer (MPTR) that contains an address of an SGL segment containing exactly one SGL Descriptor that is Qword aligned is supported",
				      "0 = the Address field specifying an offset is not supported",
				      "1 = supports the Address field in SGL Data Block, SGL Segment, and SGL Last Segment descriptor types specifying an offset"};

	buf = (unsigned char *)(ctrl);

	printf("{\n");
	vt_convert_data_buffer_to_hex_string(buf, 2, true, s);
	printf("    \"PCI Vendor ID\":\"%sh\",\n", s);
	vt_convert_data_buffer_to_hex_string(&buf[2], 2, true, s);
	printf("    \"PCI Subsystem Vendor ID\":\"%sh\",\n",  s);
	printf("    \"Serial Number\":\"%s\",\n", ctrl->sn);
	printf("    \"Model Number\":\"%s\",\n", ctrl->mn);
	printf("    \"Firmware Revision\":\"%-.*s\",\n", (int)sizeof(ctrl->fr), ctrl->fr);
	vt_convert_data_buffer_to_hex_string(&buf[72], 1, true, s);
	printf("    \"Recommended Arbitration Burst\":\"%sh\",\n", s);
	vt_convert_data_buffer_to_hex_string(&buf[73], 3, true, s);
	printf("    \"IEEE OUI Identifier\":\"%sh\",\n", s);

	temp = ctrl->cmic;
	printf("    \"Controller Multi-Path I/O and Namespace Sharing Capabilities\":{\n");
	vt_convert_data_buffer_to_hex_string(&buf[76], 1, true, s);
	printf("        \"Value\":\"%sh\",\n", s);
	vt_build_identify_lv2(temp, 0, 3, CMICtable, true);

	vt_convert_data_buffer_to_hex_string(&buf[77], 1, true, s);
	printf("    \"Maximum Data Transfer Size\":\"%sh\",\n", s);
	vt_convert_data_buffer_to_hex_string(&buf[78], 2, true, s);
	printf("    \"Controller ID\":\"%sh\",\n", s);
	vt_convert_data_buffer_to_hex_string(&buf[80], 4, true, s);
	printf("    \"Version\":\"%sh\",\n", s);
	vt_convert_data_buffer_to_hex_string(&buf[84], 4, true, s);
	printf("    \"RTD3 Resume Latency\":\"%sh\",\n", s);
	vt_convert_data_buffer_to_hex_string(&buf[88], 4, true, s);
	printf("    \"RTD3 Entry Latency\":\"%sh\",\n", s);

	temp = le32_to_cpu(ctrl->oaes);
	printf("    \"Optional Asynchronous Events Supported\":{\n");
	vt_convert_data_buffer_to_hex_string(&buf[92], 4, true, s);
	printf("        \"Value\":\"%sh\",\n", s);
	vt_build_identify_lv2(temp, 8, 2, OAEStable, true);

	temp = le32_to_cpu(ctrl->ctratt);
	printf("    \"Controller Attributes\":{\n");
	vt_convert_data_buffer_to_hex_string(&buf[96], 4, true, s);
	printf("        \"Value\":\"%sh\",\n", s);
	vt_build_identify_lv2(temp, 0, 2, CTRATTtable, true);

	vt_convert_data_buffer_to_hex_string(&buf[122], 16, true, s);
	printf("    \"FRU Globally Unique Identifier\":\"%sh\",\n", s);
	vt_convert_data_buffer_to_hex_string(&buf[240], 16, true, s);
	printf("    \"NVMe Management Interface Specification\":\"%sh\",\n", s);

	temp = le16_to_cpu(ctrl->oacs);
	printf("    \"Optional Admin Command Support\":{\n");
	vt_convert_data_buffer_to_hex_string(&buf[256], 2, true, s);
	printf("        \"Value\":\"%sh\",\n", s);
	vt_build_identify_lv2(temp, 0, 9, OACStable, true);

	vt_convert_data_buffer_to_hex_string(&buf[258], 1, true, s);
	printf("    \"Abort Command Limit\":\"%sh\",\n", s);
	vt_convert_data_buffer_to_hex_string(&buf[259], 1, true, s);
	printf("    \"Asynchronous Event Request Limit\":\"%sh\",\n", s);

	temp = ctrl->frmw;
	printf("    \"Firmware Updates\":{\n");
	vt_convert_data_buffer_to_hex_string(&buf[260], 1, true, s);
	printf("        \"Value\":\"%sh\",\n", s);
	vt_build_identify_lv2(temp, 0, 1, FRMWtable, false);
	vt_convert_data_buffer_to_hex_string(&buf[260], 1, true, s);
	printf("        \"Firmware Slot\":\"%uh\",\n", ((ctrl->frmw >> 1) & 0x07));
	vt_build_identify_lv2(temp, 4, 1, FRMWtable, true);

	temp = ctrl->lpa;
	printf("    \"Log Page Attributes\":{\n");
	vt_convert_data_buffer_to_hex_string(&buf[261], 1, true, s);
	printf("        \"Value\":\"%sh\",\n", s);
	vt_build_identify_lv2(temp, 0, 4, LPAtable, true);

	vt_convert_data_buffer_to_hex_string(&buf[262], 1, true, s);
	printf("    \"Error Log Page Entries\":\"%sh\",\n", s);
	vt_convert_data_buffer_to_hex_string(&buf[263], 1, true, s);
	printf("    \"Number of Power States Support\":\"%sh\",\n", s);

	temp = ctrl->avscc;
	printf("    \"Admin Vendor Specific Command Configuration\":{\n");
	vt_convert_data_buffer_to_hex_string(&buf[264], 1, true, s);
	printf("        \"Value\":\"%sh\",\n", s);
	vt_build_identify_lv2(temp, 0, 1, AVSCCtable, true);

	temp = ctrl->apsta;
	printf("    \"Autonomous Power State Transition Attributes\":{\n");
	vt_convert_data_buffer_to_hex_string(&buf[265], 1, true, s);
	printf("        \"Value\":\"%sh\",\n", s);
	vt_build_identify_lv2(temp, 0, 1, APSTAtable, true);

	vt_convert_data_buffer_to_hex_string(&buf[266], 2, true, s);
	printf("    \"Warning Composite Temperature Threshold\":\"%sh\",\n", s);
	vt_convert_data_buffer_to_hex_string(&buf[268], 2, true, s);
	printf("    \"Critical Composite Temperature Threshold\":\"%sh\",\n", s);
	vt_convert_data_buffer_to_hex_string(&buf[270], 2, true, s);
	printf("    \"Maximum Time for Firmware Activation\":\"%sh\",\n", s);
	vt_convert_data_buffer_to_hex_string(&buf[272], 4, true, s);
	printf("    \"Host Memory Buffer Preferred Size\":\"%sh\",\n", s);
	vt_convert_data_buffer_to_hex_string(&buf[276], 4, true, s);
	printf("    \"Host Memory Buffer Minimum Size\":\"%sh\",\n", s);
	vt_convert_data_buffer_to_hex_string(&buf[280], 16, true, s);
	printf("    \"Total NVM Capacity\":\"%sh\",\n", s);
	vt_convert_data_buffer_to_hex_string(&buf[296], 16, true, s);
	printf("    \"Unallocated NVM Capacity\":\"%sh\",\n", s);

	temp = le32_to_cpu(ctrl->rpmbs);
	printf("    \"Replay Protected Memory Block Support\":{\n");
	vt_convert_data_buffer_to_hex_string(&buf[312], 4, true, s);
	printf("        \"Value\":\"%sh\",\n", s);
	printf("        \"Number of RPMB Units\":\"%u\",\n", (temp & 0x00000003));
	snprintf(s, sizeof(s), ((temp >> 3) & 0x00000007) ? "Reserved" : "HMAC SHA-256");
	printf("        \"Authentication Method\":\"%u: %s\",\n", ((temp >> 3) & 0x00000007), s);
	printf("        \"Total Size\":\"%u\",\n", ((temp >> 16) & 0x000000FF));
	printf("        \"Access Size\":\"%u\",\n", ((temp >> 24) & 0x000000FF));
	printf("    },\n");

	vt_convert_data_buffer_to_hex_string(&buf[316], 2, true, s);
	printf("    \"Extended Device Self-test Time\":\"%sh\",\n", s);

	temp = ctrl->dsto;
	printf("    \"Device Self-test Options\":{\n");
	vt_convert_data_buffer_to_hex_string(&buf[318], 1, true, s);
	printf("        \"Value\":\"%sh\",\n", s);
	vt_build_identify_lv2(temp, 0, 1, DSTOtable, true);

	vt_convert_data_buffer_to_hex_string(&buf[319], 1, true, s);
	printf("    \"Firmware Update Granularity\":\"%sh\",\n", s);
	vt_convert_data_buffer_to_hex_string(&buf[320], 1, true, s);
	printf("    \"Keep Alive Support\":\"%sh\",\n", s);

	temp = le16_to_cpu(ctrl->hctma);
	printf("    \"Host Controlled Thermal Management Attributes\":{\n");
	vt_convert_data_buffer_to_hex_string(&buf[322], 2, true, s);
	printf("        \"Value\":\"%sh\",\n", s);
	vt_build_identify_lv2(temp, 0, 1, HCTMAtable, true);

	vt_convert_data_buffer_to_hex_string(&buf[324], 2, true, s);
	printf("    \"Minimum Thermal Management Temperature\":\"%sh\",\n", s);
	vt_convert_data_buffer_to_hex_string(&buf[326], 2, true, s);
	printf("    \"Maximum Thermal Management Temperature\":\"%sh\",\n", s);

	temp = le16_to_cpu(ctrl->sanicap);
	printf("    \"Sanitize Capabilities\":{\n");
	vt_convert_data_buffer_to_hex_string(&buf[328], 2, true, s);
	printf("        \"Value\":\"%sh\",\n", s);
	vt_build_identify_lv2(temp, 0, 3, SANICAPtable, true);

	temp = ctrl->sqes;
	printf("    \"Submission Queue Entry Size\":{\n");
	vt_convert_data_buffer_to_hex_string(&buf[512], 1, true, s);
	printf("        \"Value\":\"%sh\",\n", s);
	printf("        \"Maximum Size\":\"%u\",\n", (temp & 0x0000000F));
	printf("        \"Required Size\":\"%u\",\n", ((temp >> 4) & 0x0000000F));
	printf("    }\n");

	temp = ctrl->cqes;
	printf("    \"Completion Queue Entry Size\":{\n");
	vt_convert_data_buffer_to_hex_string(&buf[513], 1, true, s);
	printf("        \"Value\":\"%sh\",\n", s);
	printf("        \"Maximum Size\":\"%u\",\n", (temp & 0x0000000F));
	printf("        \"Required Size\":\"%u\",\n", ((temp >> 4) & 0x0000000F));
	printf("    }\n");

	vt_convert_data_buffer_to_hex_string(&buf[514], 2, true, s);
	printf("    \"Maximum Outstanding Commands\":\"%sh\",\n", s);
	vt_convert_data_buffer_to_hex_string(&buf[516], 4, true, s);
	printf("    \"Number of Namespaces\":\"%sh\",\n", s);

	temp = le16_to_cpu(ctrl->oncs);
	printf("    \"Optional NVM Command Support\":{\n");
	vt_convert_data_buffer_to_hex_string(&buf[520], 2, true, s);
	printf("        \"Value\":\"%sh\",\n", s);
	vt_build_identify_lv2(temp, 0, 7, ONCStable, true);

	temp = le16_to_cpu(ctrl->fuses);
	printf("    \"Fused Operation Support\":{\n");
	vt_convert_data_buffer_to_hex_string(&buf[522], 2, true, s);
	printf("        \"Value\":\"%sh\",\n", s);
	vt_build_identify_lv2(temp, 0, 1, FUSEStable, true);

	temp = ctrl->fna;
	printf("    \"Format NVM Attributes\":{\n");
	vt_convert_data_buffer_to_hex_string(&buf[524], 1, true, s);
	printf("        \"Value\":\"%sh\",\n", s);
	vt_build_identify_lv2(temp, 0, 3, FNAtable, true);

	temp = ctrl->vwc;
	printf("    \"Volatile Write Cache\":{\n");
	vt_convert_data_buffer_to_hex_string(&buf[525], 1, true, s);
	printf("        \"Value\":\"%sh\",\n", s);
	vt_build_identify_lv2(temp, 0, 1, VWCtable, true);

	vt_convert_data_buffer_to_hex_string(&buf[526], 2, true, s);
	printf("    \"Atomic Write Unit Normal\":\"%sh\",\n", s);
	vt_convert_data_buffer_to_hex_string(&buf[528], 2, true, s);
	printf("    \"Atomic Write Unit Power Fail\":\"%sh\",\n", s);

	temp = ctrl->icsvscc;
	printf("    \"NVM Vendor Specific Command Configuration\":{\n");
	vt_convert_data_buffer_to_hex_string(&buf[530], 1, true, s);
	printf("        \"Value\":\"%sh\",\n", s);
	vt_build_identify_lv2(temp, 0, 1, ICSVSCCtable, true);

	vt_convert_data_buffer_to_hex_string(&buf[532], 2, true, s);
	printf("    \"Atomic Compare 0 Write Unit\":\"%sh\",\n", s);

	temp = le32_to_cpu(ctrl->sgls);
	printf("    \"SGL Support\":{\n");
	vt_convert_data_buffer_to_hex_string(&buf[536], 4, true, s);
	printf("        \"Value\":\"%sh\",\n", s);
	pos = (temp & 0x00000003);
	printf("        \"bit 1:0\":\"%s\",\n", SGLSSubtable[pos]);
	vt_build_identify_lv2(temp, 2, 1, SGLStable, false);
	vt_build_identify_lv2(temp, 16, 5, SGLStable, true);

	vt_convert_data_buffer_to_hex_string(&buf[768], 256, false, s);
	printf("    \"NVM Subsystem NVMe Qualified Name\":\"%s\",\n", s);
	printf("}\n\n");

	vt_build_power_state_descriptor(ctrl);


	printf("\n{\n");
	printf("\"Vendor Specific\":\"\n");
	vt_dump_hex_data(&buf[3072], 1024);
	printf("\"}\n");
}

static int vt_save_smart_to_vtview_log(int argc, char **argv,
				       struct command *command,
				       struct plugin *plugin)
{
	int ret, err = 0;
	long total_time = 0;
	long freq_time = 0;
	long cur_time = 0;
	long remain_time = 0;
	long start_time = 0;
	long end_time = 0;
	char path[256] = "";
	char *desc = "Save SMART data into log file with format that is easy to analyze (comma delimited). Maximum log file will be 4K.\n\n"
		"Typical usages:\n\n"
		"Temperature characterization:\n"
		"\tvirtium save-smart-to-vtview-log /dev/yourDevice --run-time=100 --record-frequency=0.25 --test-name=burn-in-at-(-40)\n\n"
		"Endurance testing :\n"
		"\tvirtium save-smart-to-vtview-log /dev/yourDevice --run-time=100 --record-frequency=1 --test-name=Endurance-test-JEDEG-219-workload\n\n"
		"Just logging :\n"
		"\tvirtium save-smart-to-vtview-log /dev/yourDevice";

	const char *run_time = "(optional) Number of hours to log data (default = 20 hours)";
	const char *freq = "(optional) How often you want to log SMART data (0.25 = 15' , 0.5 = 30' , 1 = 1 hour, 2 = 2 hours, etc.). Default = 10 hours.";
	const char *output_file = "(optional) Name of the log file (give it a name that easy for you to remember what the test is). You can leave it blank too, we will take care it for you.";
	const char *test_name = "(optional) Name of the test you are doing. We use this as part of the name of the log file.";
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;

	struct vtview_save_log_settings cfg = {
		.run_time_hrs = 20,
		.log_record_frequency_hrs = 10,
		.output_file = NULL,
		.test_name = NULL,
	};

	OPT_ARGS(opts) = {
		OPT_DOUBLE("run-time",  'r', &cfg.run_time_hrs,             run_time),
		OPT_DOUBLE("freq",      'f', &cfg.log_record_frequency_hrs, freq),
		OPT_FILE("output-file", 'o', &cfg.output_file,              output_file),
		OPT_STRING("test-name", 'n', "NAME", &cfg.test_name,        test_name),
		OPT_END()
	};

	vt_generate_vtview_log_file_name(vt_default_log_file_name);

	if (argc >= 2) {
		if (strlen(argv[1]) > sizeof(path) - 1) {
			printf("Filename too long\n");
			return -1;
		}
		strcpy(path, argv[1]);
	}

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err) {
		printf("Error parse and open (err = %d)\n", err);
		return err;
	}

	printf("Running...\n");
	printf("Collecting data for device %s\n", path);
	printf("Running for %lf hour(s)\n", cfg.run_time_hrs);
	printf("Logging SMART data for every %lf hour(s)\n", cfg.log_record_frequency_hrs);

	ret = vt_update_vtview_log_header(hdl, path, &cfg);
	if (ret)
		return ret;

	total_time = cfg.run_time_hrs * (float)HOUR_IN_SECONDS;
	freq_time = cfg.log_record_frequency_hrs * (float)HOUR_IN_SECONDS;

	if (!freq_time)
		freq_time = 1;

	start_time = time(NULL);
	end_time = start_time + total_time;

	fflush(stdout);

	while (1) {
		cur_time = time(NULL);
		if (cur_time >= end_time)
			break;

		ret = vt_add_entry_to_log(hdl, path, &cfg);
		if (ret) {
			printf("Cannot update driver log\n");
			break;
		}

		remain_time = end_time - cur_time;
		freq_time = MIN2(freq_time, remain_time);
		sleep(freq_time);
		fflush(stdout);
	}

	return err;
}

static int vt_show_identify(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	char *desc = "Parse identify data to json format\n\n"
		"Typical usages:\n\n"
		"virtium show-identify /dev/yourDevice\n";
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	struct nvme_id_ctrl ctrl;
	int ret, err = 0;

	OPT_ARGS(opts) = {
		OPT_END()
	};

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err) {
		printf("Error parse and open (err = %d)\n", err);
		return err;
	}

	ret = nvme_identify_ctrl(hdl, &ctrl);
	if (ret) {
		printf("Cannot read identify device\n");
		return -1;
	}

	vt_process_string(ctrl.sn, sizeof(ctrl.sn));
	vt_process_string(ctrl.mn, sizeof(ctrl.mn));
	vt_parse_detail_identify(&ctrl);

	return err;
}
