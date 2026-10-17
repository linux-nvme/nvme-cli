// SPDX-License-Identifier: GPL-2.0-or-later
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <locale.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include <libnvme.h>

#include <ccan/endian/endian.h>
#include <shared/compiler-attributes-util.h>
#include <shared/hex-util.h>
#include <shared/string-util.h>
#include <shared/uint128-util.h>

#include "cleanup.h"
#include "global-ctx.h"
#include "nvme-cmds.h"
#include "nvme-print.h"
#include "plugin.h"

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

/*
 * Generate log file name.
 * Log file name will be generated automatically if user leave log file option blank.
 * Log file name will be generated as vtView-Smart-log-date-time.txt
 */
static void vt_generate_vtview_log_file_name(char *fname, size_t size)
{
	time_t current = time(NULL);
	struct tm tstamp = *localtime(&current);
	char date[32];

	strftime(date, sizeof(date), "%Y-%m-%d", &tstamp);
	snprintf(fname, size, "./vtView-Smart-log-%s.txt", date);
}

/* A 128 bit counter of the SMART log as "name;value;" */
static void vt_append_u128(char *text, size_t size, size_t *len,
			   const char *name, __u8 *value)
{
	shr_snprintf_append(text, size, len, "%s;%s;", name,
			    uint128_t_to_string(le128_to_cpu(value)));
}

static void vt_convert_smart_data_to_human_readable_format(
		struct vtview_smart_log_entry *smart, char *text, size_t size)
{
	struct nvme_smart_log *log = &smart->raw_smart;
	struct nvme_id_ctrl *ctrl = &smart->raw_ctrl;
	int i;
	int temperature = ((log->temperature[1] << 8) |
			   log->temperature[0]) - 273;
	double capacity;
	char *curlocale;
	char *templocale;
	size_t len = 0;
	__u8 lba_index;

	nvme_id_ns_flbas_to_lbaf_inuse(smart->raw_ns.flbas, &lba_index);

	curlocale = setlocale(LC_ALL, NULL);
	templocale = strdup(curlocale);

	if (!templocale)
		nvme_show_error("Cannot malloc buffer");

	setlocale(LC_ALL, "C");

	unsigned long long lba = 1ULL << smart->raw_ns.lbaf[lba_index].ds;

	capacity = le64_to_cpu(smart->raw_ns.nsze) * lba;

	text[0] = '\0';
	shr_snprintf_append(text, size, &len, "log;%-.*s;%llu;%s;%-.*s;%-.*s;",
			    (int)sizeof(ctrl->sn), ctrl->sn,
			    (unsigned long long)smart->time_stamp, smart->path,
			    (int)sizeof(ctrl->mn), ctrl->mn,
			    (int)sizeof(ctrl->fr), ctrl->fr);
	shr_snprintf_append(text, size, &len, "Capacity;%lf;",
			    capacity / 1000000000);
	shr_snprintf_append(text, size, &len, "Critical_Warning;%u;",
			    log->critical_warning);
	shr_snprintf_append(text, size, &len, "Temperature;%u;", temperature);
	shr_snprintf_append(text, size, &len, "Available_Spare;%u;",
			    log->avail_spare);
	shr_snprintf_append(text, size, &len, "Available_Spare_Threshold;%u;",
			    log->spare_thresh);
	shr_snprintf_append(text, size, &len, "Percentage_Used;%u;",
			    log->percent_used);
	vt_append_u128(text, size, &len, "Data_Units_Read",
		       log->data_units_read);
	vt_append_u128(text, size, &len, "Data_Units_Written",
		       log->data_units_written);
	vt_append_u128(text, size, &len, "Host_Read_Commands", log->host_reads);
	vt_append_u128(text, size, &len, "Host_Write_Commands",
		       log->host_writes);
	vt_append_u128(text, size, &len, "Controller_Busy_Time",
		       log->ctrl_busy_time);
	vt_append_u128(text, size, &len, "Power_Cycles", log->power_cycles);
	vt_append_u128(text, size, &len, "Power_On_Hours", log->power_on_hours);
	vt_append_u128(text, size, &len, "Unsafe_Shutdowns",
		       log->unsafe_shutdowns);
	vt_append_u128(text, size, &len, "Media_Errors", log->media_errors);
	vt_append_u128(text, size, &len, "Num_Err_Log_Entries",
		       log->num_err_log_entries);
	shr_snprintf_append(text, size, &len, "Warning_Temperature_Time;%u;",
			    le32_to_cpu(log->warning_temp_time));
	shr_snprintf_append(text, size, &len,
			    "Critical_Composite_Temperature_Time;%u;",
			    le32_to_cpu(log->critical_comp_time));

	for (i = 0; i < 8; i++) {
		__s32 temp = le16_to_cpu(log->temp_sensor[i]);

		if (!temp) {
			shr_snprintf_append(text, size, &len,
					    "Temperature_Sensor_%d;NC;", i);
			continue;
		}
		shr_snprintf_append(text, size, &len,
				    "Temperature_Sensor_%d;%d;", i,
				    temp - 273);
	}

	shr_snprintf_append(text, size, &len,
			    "Thermal_Management_T1_Trans_Count;%u;",
			    le32_to_cpu(log->thm_temp1_trans_count));
	shr_snprintf_append(text, size, &len,
			    "Thermal_Management_T2_Trans_Count;%u;",
			    le32_to_cpu(log->thm_temp2_trans_count));
	shr_snprintf_append(text, size, &len,
			    "Thermal_Management_T1_Total_Time;%u;",
			    le32_to_cpu(log->thm_temp1_total_time));
	shr_snprintf_append(text, size, &len,
			    "Thermal_Management_T2_Total_Time;%u;",
			    le32_to_cpu(log->thm_temp2_total_time));

	shr_snprintf_append(text, size, &len, "NandWrites;%d;\n", 0);

	setlocale(LC_ALL, templocale);
	free(templocale);
}

static void vt_header_to_string(const struct vtview_log_header *header,
			       char *text, size_t size)
{
	const struct nvme_id_ctrl *ctrl = &header->raw_ctrl;
	char timebuff[50] = "";
	char identext[16384] = "";
	char fwtext[2048] = "";
	size_t len = 0;

	strftime(timebuff, sizeof(timebuff), "%Y-%m-%d %H:%M:%S",
		 localtime(&(header->time_stamp)));
	text[0] = '\0';
	shr_snprintf_append(text, size, &len,
		"header;{\"session\":{\"testName\":\"%s\",\"dateTime\":\"%s\"},",
		header->test_name, timebuff);

	shr_bin_to_hex(identext, sizeof(identext), ctrl, sizeof(*ctrl),
		       SHR_HEX_UPPER);
	shr_bin_to_hex(fwtext, sizeof(fwtext), &header->raw_fw,
		       sizeof(header->raw_fw), SHR_HEX_UPPER);
	shr_snprintf_append(text, size, &len,
		"\"devices\":[{\"model\":\"%-.*s\",\"port\":\"%s\",\"SN\":\"%-.*s\",\"type\":\"NVMe\",\"identify\":\"%s\",\"firmwareSlot\":\"%s\"}]}\n",
		(int)sizeof(ctrl->mn), ctrl->mn, header->path,
		(int)sizeof(ctrl->sn), ctrl->sn, identext, fwtext);
}

static int vt_append_text_file(const char *text, const char *filename)
{
	FILE *f;

	f = fopen(filename, "a");
	if (!f) {
		nvme_show_error("Cannot open %s", filename);
		return -1;
	}

	fprintf(f, "%s", text);
	fclose(f);
	return 0;
}

static int vt_append_log(struct vtview_smart_log_entry *smart, const char *filename)
{
	char sm_log_text[MAX_LOG_BUFF] = "";

	vt_convert_smart_data_to_human_readable_format(smart, sm_log_text,
						       sizeof(sm_log_text));
	return vt_append_text_file(sm_log_text, filename);
}

static int vt_append_header(const struct vtview_log_header *header, const char *filename)
{
	char header_text[MAX_HEADER_BUFF] = "";

	vt_header_to_string(header, header_text, sizeof(header_text));
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

static int vt_add_entry_to_log(struct libnvme_transport_handle *hdl,
			       const char *path,
			       const struct vtview_save_log_settings *cfg)
{
	struct vtview_smart_log_entry smart;
	struct libnvme_passthru_cmd cmd;
	const char *filename;
	int ret = 0;
	unsigned int nsid = 0;

	snprintf(smart.path, sizeof(smart.path), "%s", path);
	if (!cfg->output_file)
		filename = vt_default_log_file_name;
	else
		filename = cfg->output_file;

	smart.time_stamp = time(NULL);
	ret = libnvme_get_nsid(hdl, &nsid);

	if (ret < 0) {
		nvme_show_error("Cannot read namespace-id");
		return -1;
	}

	nvme_init_identify_ns(&cmd, nsid, &smart.raw_ns);
	ret = libnvme_exec_admin_passthru(hdl, &cmd);
	if (ret) {
		nvme_show_error("Cannot read namespace identify");
		return -1;
	}

	nvme_init_identify_ctrl(&cmd, &smart.raw_ctrl);
	ret = libnvme_exec_admin_passthru(hdl, &cmd);
	if (ret) {
		nvme_show_error("Cannot read device identify controller");
		return -1;
	}

	ret = nvme_get_log_smart(hdl, NVME_NSID_ALL, &smart.raw_smart);
	if (ret) {
		nvme_show_error("Cannot read device SMART log");
		return -1;
	}

	vt_process_string(smart.raw_ctrl.sn, sizeof(smart.raw_ctrl.sn));
	vt_process_string(smart.raw_ctrl.mn, sizeof(smart.raw_ctrl.mn));

	ret = vt_append_log(&smart, filename);
	return ret;
}

static int
vt_update_vtview_log_header(struct libnvme_transport_handle *hdl, const char *path,
			    const struct vtview_save_log_settings *cfg)
{
	struct vtview_log_header header;
	struct libnvme_passthru_cmd cmd;
	const char *filename;
	int ret = 0;

	vt_initialize_header_buffer(&header);
	if (strlen(path) >= sizeof(header.path)) {
		nvme_show_error("filename too long");
		errno = EINVAL;
		return -1;
	}
	shr_strscpy(header.path, path, sizeof(header.path));

	if (!cfg->test_name) {
		shr_strscpy(header.test_name, DEFAULT_TEST_NAME,
			    sizeof(header.test_name));
	} else {
		if (strlen(cfg->test_name) >= sizeof(header.test_name)) {
			nvme_show_error("test name too long");
			errno = EINVAL;
			return -1;
		}
		shr_strscpy(header.test_name, cfg->test_name,
			    sizeof(header.test_name));
	}

	if (!cfg->output_file)
		filename = vt_default_log_file_name;
	else
		filename = cfg->output_file;

	nvme_show_verbose_info("Log file: %s", filename);
	header.time_stamp = time(NULL);

	nvme_init_identify_ctrl(&cmd, &header.raw_ctrl);
	ret = libnvme_exec_admin_passthru(hdl, &cmd);
	if (ret) {
		nvme_show_error("Cannot read identify device");
		return -1;
	}

	nvme_init_get_log(&cmd, NVME_NSID_ALL, NVME_LOG_LID_FW_SLOT,
		NVME_CSI_NVM, &header.raw_fw, sizeof(header.raw_fw));

	ret = libnvme_get_log(hdl, &cmd, false, sizeof(header.raw_fw));
	if (ret) {
		nvme_show_error("Cannot read device firmware log");
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
		shr_bin_to_hex(s, sizeof(s), &buf[0], 4,
			       SHR_HEX_UPPER | SHR_HEX_REVERSE);
		printf("%9sh", s);

		temp = ctrl->psd[i].flags;
		printf("%4ub", ((unsigned char)temp & 0x02));
		printf("%3ub", ((unsigned char)temp & 0x01));
		shr_bin_to_hex(s, sizeof(s), &buf[0], 2,
			       SHR_HEX_UPPER | SHR_HEX_REVERSE);
		printf("%5sh", s);

		shr_bin_to_hex(s, sizeof(s), &buf[4], 4,
			       SHR_HEX_UPPER | SHR_HEX_REVERSE);
		printf("%9sh", s);
		shr_bin_to_hex(s, sizeof(s), &buf[8], 4,
			       SHR_HEX_UPPER | SHR_HEX_REVERSE);
		printf("%9sh", s);
		shr_bin_to_hex(s, sizeof(s), &buf[12], 4,
			       SHR_HEX_UPPER | SHR_HEX_REVERSE);
		printf("%9sh", s);
		shr_bin_to_hex(s, sizeof(s), &buf[15], 1,
			       SHR_HEX_UPPER | SHR_HEX_REVERSE);
		printf("%3sh", s);
		shr_bin_to_hex(s, sizeof(s), &buf[14], 1,
			       SHR_HEX_UPPER | SHR_HEX_REVERSE);
		printf("%3sh", s);
		shr_bin_to_hex(s, sizeof(s), &buf[13], 1,
			       SHR_HEX_UPPER | SHR_HEX_REVERSE);
		printf("%3sh", s);
		shr_bin_to_hex(s, sizeof(s), &buf[12], 1,
			       SHR_HEX_UPPER | SHR_HEX_REVERSE);
		printf("%3sh", s);
		shr_bin_to_hex(s, sizeof(s), &buf[16], 4,
			       SHR_HEX_UPPER | SHR_HEX_REVERSE);
		printf("%9sh", s);

		temp = ctrl->psd[i].ips;
		snprintf(s, sizeof(s), "%u%u", (((unsigned char)temp >> 6) & 0x01), (((unsigned char)temp >> 7) & 0x01));
		printf("%3sb", s);

		shr_bin_to_hex(s, sizeof(s), &buf[16], 2,
			       SHR_HEX_UPPER | SHR_HEX_REVERSE);
		printf("%5sh", s);
		shr_bin_to_hex(s, sizeof(s), &buf[20], 4,
			       SHR_HEX_UPPER | SHR_HEX_REVERSE);
		printf("%9sh", s);

		temp = ctrl->psd[i].apws;
		snprintf(s, sizeof(s), "%u%u", (((unsigned char)temp >> 6) & 0x01), (((unsigned char)temp >> 7) & 0x01));
		printf("%3sb", s);
		snprintf(s, sizeof(s), "%u%u%u", (((unsigned char)temp) & 0x01), (((unsigned char)temp >> 1) & 0x01), (((unsigned char)temp >> 2) & 0x01));
		printf("%4sb", s);

		shr_bin_to_hex(s, sizeof(s), &buf[20], 2,
			       SHR_HEX_UPPER | SHR_HEX_REVERSE);
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
	shr_bin_to_hex(s, sizeof(s), buf, 2, SHR_HEX_UPPER | SHR_HEX_REVERSE);
	printf("    \"PCI Vendor ID\":\"%sh\",\n", s);
	shr_bin_to_hex(s, sizeof(s), &buf[2], 2,
		       SHR_HEX_UPPER | SHR_HEX_REVERSE);
	printf("    \"PCI Subsystem Vendor ID\":\"%sh\",\n",  s);
	printf("    \"Serial Number\":\"%s\",\n", ctrl->sn);
	printf("    \"Model Number\":\"%s\",\n", ctrl->mn);
	printf("    \"Firmware Revision\":\"%-.*s\",\n", (int)sizeof(ctrl->fr), ctrl->fr);
	shr_bin_to_hex(s, sizeof(s), &buf[72], 1,
		       SHR_HEX_UPPER | SHR_HEX_REVERSE);
	printf("    \"Recommended Arbitration Burst\":\"%sh\",\n", s);
	shr_bin_to_hex(s, sizeof(s), &buf[73], 3,
		       SHR_HEX_UPPER | SHR_HEX_REVERSE);
	printf("    \"IEEE OUI Identifier\":\"%sh\",\n", s);

	temp = ctrl->cmic;
	printf("    \"Controller Multi-Path I/O and Namespace Sharing Capabilities\":{\n");
	shr_bin_to_hex(s, sizeof(s), &buf[76], 1,
		       SHR_HEX_UPPER | SHR_HEX_REVERSE);
	printf("        \"Value\":\"%sh\",\n", s);
	vt_build_identify_lv2(temp, 0, 3, CMICtable, true);

	shr_bin_to_hex(s, sizeof(s), &buf[77], 1,
		       SHR_HEX_UPPER | SHR_HEX_REVERSE);
	printf("    \"Maximum Data Transfer Size\":\"%sh\",\n", s);
	shr_bin_to_hex(s, sizeof(s), &buf[78], 2,
		       SHR_HEX_UPPER | SHR_HEX_REVERSE);
	printf("    \"Controller ID\":\"%sh\",\n", s);
	shr_bin_to_hex(s, sizeof(s), &buf[80], 4,
		       SHR_HEX_UPPER | SHR_HEX_REVERSE);
	printf("    \"Version\":\"%sh\",\n", s);
	shr_bin_to_hex(s, sizeof(s), &buf[84], 4,
		       SHR_HEX_UPPER | SHR_HEX_REVERSE);
	printf("    \"RTD3 Resume Latency\":\"%sh\",\n", s);
	shr_bin_to_hex(s, sizeof(s), &buf[88], 4,
		       SHR_HEX_UPPER | SHR_HEX_REVERSE);
	printf("    \"RTD3 Entry Latency\":\"%sh\",\n", s);

	temp = le32_to_cpu(ctrl->oaes);
	printf("    \"Optional Asynchronous Events Supported\":{\n");
	shr_bin_to_hex(s, sizeof(s), &buf[92], 4,
		       SHR_HEX_UPPER | SHR_HEX_REVERSE);
	printf("        \"Value\":\"%sh\",\n", s);
	vt_build_identify_lv2(temp, 8, 2, OAEStable, true);

	temp = le32_to_cpu(ctrl->ctratt);
	printf("    \"Controller Attributes\":{\n");
	shr_bin_to_hex(s, sizeof(s), &buf[96], 4,
		       SHR_HEX_UPPER | SHR_HEX_REVERSE);
	printf("        \"Value\":\"%sh\",\n", s);
	vt_build_identify_lv2(temp, 0, 2, CTRATTtable, true);

	shr_bin_to_hex(s, sizeof(s), &buf[122], 16,
		       SHR_HEX_UPPER | SHR_HEX_REVERSE);
	printf("    \"FRU Globally Unique Identifier\":\"%sh\",\n", s);
	shr_bin_to_hex(s, sizeof(s), &buf[240], 16,
		       SHR_HEX_UPPER | SHR_HEX_REVERSE);
	printf("    \"NVMe Management Interface Specification\":\"%sh\",\n", s);

	temp = le16_to_cpu(ctrl->oacs);
	printf("    \"Optional Admin Command Support\":{\n");
	shr_bin_to_hex(s, sizeof(s), &buf[256], 2,
		       SHR_HEX_UPPER | SHR_HEX_REVERSE);
	printf("        \"Value\":\"%sh\",\n", s);
	vt_build_identify_lv2(temp, 0, 9, OACStable, true);

	shr_bin_to_hex(s, sizeof(s), &buf[258], 1,
		       SHR_HEX_UPPER | SHR_HEX_REVERSE);
	printf("    \"Abort Command Limit\":\"%sh\",\n", s);
	shr_bin_to_hex(s, sizeof(s), &buf[259], 1,
		       SHR_HEX_UPPER | SHR_HEX_REVERSE);
	printf("    \"Asynchronous Event Request Limit\":\"%sh\",\n", s);

	temp = ctrl->frmw;
	printf("    \"Firmware Updates\":{\n");
	shr_bin_to_hex(s, sizeof(s), &buf[260], 1,
		       SHR_HEX_UPPER | SHR_HEX_REVERSE);
	printf("        \"Value\":\"%sh\",\n", s);
	vt_build_identify_lv2(temp, 0, 1, FRMWtable, false);
	shr_bin_to_hex(s, sizeof(s), &buf[260], 1,
		       SHR_HEX_UPPER | SHR_HEX_REVERSE);
	printf("        \"Firmware Slot\":\"%uh\",\n", ((ctrl->frmw >> 1) & 0x07));
	vt_build_identify_lv2(temp, 4, 1, FRMWtable, true);

	temp = ctrl->lpa;
	printf("    \"Log Page Attributes\":{\n");
	shr_bin_to_hex(s, sizeof(s), &buf[261], 1,
		       SHR_HEX_UPPER | SHR_HEX_REVERSE);
	printf("        \"Value\":\"%sh\",\n", s);
	vt_build_identify_lv2(temp, 0, 4, LPAtable, true);

	shr_bin_to_hex(s, sizeof(s), &buf[262], 1,
		       SHR_HEX_UPPER | SHR_HEX_REVERSE);
	printf("    \"Error Log Page Entries\":\"%sh\",\n", s);
	shr_bin_to_hex(s, sizeof(s), &buf[263], 1,
		       SHR_HEX_UPPER | SHR_HEX_REVERSE);
	printf("    \"Number of Power States Support\":\"%sh\",\n", s);

	temp = ctrl->avscc;
	printf("    \"Admin Vendor Specific Command Configuration\":{\n");
	shr_bin_to_hex(s, sizeof(s), &buf[264], 1,
		       SHR_HEX_UPPER | SHR_HEX_REVERSE);
	printf("        \"Value\":\"%sh\",\n", s);
	vt_build_identify_lv2(temp, 0, 1, AVSCCtable, true);

	temp = ctrl->apsta;
	printf("    \"Autonomous Power State Transition Attributes\":{\n");
	shr_bin_to_hex(s, sizeof(s), &buf[265], 1,
		       SHR_HEX_UPPER | SHR_HEX_REVERSE);
	printf("        \"Value\":\"%sh\",\n", s);
	vt_build_identify_lv2(temp, 0, 1, APSTAtable, true);

	shr_bin_to_hex(s, sizeof(s), &buf[266], 2,
		       SHR_HEX_UPPER | SHR_HEX_REVERSE);
	printf("    \"Warning Composite Temperature Threshold\":\"%sh\",\n", s);
	shr_bin_to_hex(s, sizeof(s), &buf[268], 2,
		       SHR_HEX_UPPER | SHR_HEX_REVERSE);
	printf("    \"Critical Composite Temperature Threshold\":\"%sh\",\n", s);
	shr_bin_to_hex(s, sizeof(s), &buf[270], 2,
		       SHR_HEX_UPPER | SHR_HEX_REVERSE);
	printf("    \"Maximum Time for Firmware Activation\":\"%sh\",\n", s);
	shr_bin_to_hex(s, sizeof(s), &buf[272], 4,
		       SHR_HEX_UPPER | SHR_HEX_REVERSE);
	printf("    \"Host Memory Buffer Preferred Size\":\"%sh\",\n", s);
	shr_bin_to_hex(s, sizeof(s), &buf[276], 4,
		       SHR_HEX_UPPER | SHR_HEX_REVERSE);
	printf("    \"Host Memory Buffer Minimum Size\":\"%sh\",\n", s);
	shr_bin_to_hex(s, sizeof(s), &buf[280], 16,
		       SHR_HEX_UPPER | SHR_HEX_REVERSE);
	printf("    \"Total NVM Capacity\":\"%sh\",\n", s);
	shr_bin_to_hex(s, sizeof(s), &buf[296], 16,
		       SHR_HEX_UPPER | SHR_HEX_REVERSE);
	printf("    \"Unallocated NVM Capacity\":\"%sh\",\n", s);

	temp = le32_to_cpu(ctrl->rpmbs);
	printf("    \"Replay Protected Memory Block Support\":{\n");
	shr_bin_to_hex(s, sizeof(s), &buf[312], 4,
		       SHR_HEX_UPPER | SHR_HEX_REVERSE);
	printf("        \"Value\":\"%sh\",\n", s);
	printf("        \"Number of RPMB Units\":\"%u\",\n", (temp & 0x00000003));
	snprintf(s, sizeof(s), ((temp >> 3) & 0x00000007) ? "Reserved" : "HMAC SHA-256");
	printf("        \"Authentication Method\":\"%u: %s\",\n", ((temp >> 3) & 0x00000007), s);
	printf("        \"Total Size\":\"%u\",\n", ((temp >> 16) & 0x000000FF));
	printf("        \"Access Size\":\"%u\",\n", ((temp >> 24) & 0x000000FF));
	printf("    },\n");

	shr_bin_to_hex(s, sizeof(s), &buf[316], 2,
		       SHR_HEX_UPPER | SHR_HEX_REVERSE);
	printf("    \"Extended Device Self-test Time\":\"%sh\",\n", s);

	temp = ctrl->dsto;
	printf("    \"Device Self-test Options\":{\n");
	shr_bin_to_hex(s, sizeof(s), &buf[318], 1,
		       SHR_HEX_UPPER | SHR_HEX_REVERSE);
	printf("        \"Value\":\"%sh\",\n", s);
	vt_build_identify_lv2(temp, 0, 1, DSTOtable, true);

	shr_bin_to_hex(s, sizeof(s), &buf[319], 1,
		       SHR_HEX_UPPER | SHR_HEX_REVERSE);
	printf("    \"Firmware Update Granularity\":\"%sh\",\n", s);
	shr_bin_to_hex(s, sizeof(s), &buf[320], 1,
		       SHR_HEX_UPPER | SHR_HEX_REVERSE);
	printf("    \"Keep Alive Support\":\"%sh\",\n", s);

	temp = le16_to_cpu(ctrl->hctma);
	printf("    \"Host Controlled Thermal Management Attributes\":{\n");
	shr_bin_to_hex(s, sizeof(s), &buf[322], 2,
		       SHR_HEX_UPPER | SHR_HEX_REVERSE);
	printf("        \"Value\":\"%sh\",\n", s);
	vt_build_identify_lv2(temp, 0, 1, HCTMAtable, true);

	shr_bin_to_hex(s, sizeof(s), &buf[324], 2,
		       SHR_HEX_UPPER | SHR_HEX_REVERSE);
	printf("    \"Minimum Thermal Management Temperature\":\"%sh\",\n", s);
	shr_bin_to_hex(s, sizeof(s), &buf[326], 2,
		       SHR_HEX_UPPER | SHR_HEX_REVERSE);
	printf("    \"Maximum Thermal Management Temperature\":\"%sh\",\n", s);

	temp = le16_to_cpu(ctrl->sanicap);
	printf("    \"Sanitize Capabilities\":{\n");
	shr_bin_to_hex(s, sizeof(s), &buf[328], 2,
		       SHR_HEX_UPPER | SHR_HEX_REVERSE);
	printf("        \"Value\":\"%sh\",\n", s);
	vt_build_identify_lv2(temp, 0, 3, SANICAPtable, true);

	temp = ctrl->sqes;
	printf("    \"Submission Queue Entry Size\":{\n");
	shr_bin_to_hex(s, sizeof(s), &buf[512], 1,
		       SHR_HEX_UPPER | SHR_HEX_REVERSE);
	printf("        \"Value\":\"%sh\",\n", s);
	printf("        \"Maximum Size\":\"%u\",\n", (temp & 0x0000000F));
	printf("        \"Required Size\":\"%u\",\n", ((temp >> 4) & 0x0000000F));
	printf("    }\n");

	temp = ctrl->cqes;
	printf("    \"Completion Queue Entry Size\":{\n");
	shr_bin_to_hex(s, sizeof(s), &buf[513], 1,
		       SHR_HEX_UPPER | SHR_HEX_REVERSE);
	printf("        \"Value\":\"%sh\",\n", s);
	printf("        \"Maximum Size\":\"%u\",\n", (temp & 0x0000000F));
	printf("        \"Required Size\":\"%u\",\n", ((temp >> 4) & 0x0000000F));
	printf("    }\n");

	shr_bin_to_hex(s, sizeof(s), &buf[514], 2,
		       SHR_HEX_UPPER | SHR_HEX_REVERSE);
	printf("    \"Maximum Outstanding Commands\":\"%sh\",\n", s);
	shr_bin_to_hex(s, sizeof(s), &buf[516], 4,
		       SHR_HEX_UPPER | SHR_HEX_REVERSE);
	printf("    \"Number of Namespaces\":\"%sh\",\n", s);

	temp = le16_to_cpu(ctrl->oncs);
	printf("    \"Optional NVM Command Support\":{\n");
	shr_bin_to_hex(s, sizeof(s), &buf[520], 2,
		       SHR_HEX_UPPER | SHR_HEX_REVERSE);
	printf("        \"Value\":\"%sh\",\n", s);
	vt_build_identify_lv2(temp, 0, 7, ONCStable, true);

	temp = le16_to_cpu(ctrl->fuses);
	printf("    \"Fused Operation Support\":{\n");
	shr_bin_to_hex(s, sizeof(s), &buf[522], 2,
		       SHR_HEX_UPPER | SHR_HEX_REVERSE);
	printf("        \"Value\":\"%sh\",\n", s);
	vt_build_identify_lv2(temp, 0, 1, FUSEStable, true);

	temp = ctrl->fna;
	printf("    \"Format NVM Attributes\":{\n");
	shr_bin_to_hex(s, sizeof(s), &buf[524], 1,
		       SHR_HEX_UPPER | SHR_HEX_REVERSE);
	printf("        \"Value\":\"%sh\",\n", s);
	vt_build_identify_lv2(temp, 0, 3, FNAtable, true);

	temp = ctrl->vwc;
	printf("    \"Volatile Write Cache\":{\n");
	shr_bin_to_hex(s, sizeof(s), &buf[525], 1,
		       SHR_HEX_UPPER | SHR_HEX_REVERSE);
	printf("        \"Value\":\"%sh\",\n", s);
	vt_build_identify_lv2(temp, 0, 1, VWCtable, true);

	shr_bin_to_hex(s, sizeof(s), &buf[526], 2,
		       SHR_HEX_UPPER | SHR_HEX_REVERSE);
	printf("    \"Atomic Write Unit Normal\":\"%sh\",\n", s);
	shr_bin_to_hex(s, sizeof(s), &buf[528], 2,
		       SHR_HEX_UPPER | SHR_HEX_REVERSE);
	printf("    \"Atomic Write Unit Power Fail\":\"%sh\",\n", s);

	temp = ctrl->icsvscc;
	printf("    \"NVM Vendor Specific Command Configuration\":{\n");
	shr_bin_to_hex(s, sizeof(s), &buf[530], 1,
		       SHR_HEX_UPPER | SHR_HEX_REVERSE);
	printf("        \"Value\":\"%sh\",\n", s);
	vt_build_identify_lv2(temp, 0, 1, ICSVSCCtable, true);

	shr_bin_to_hex(s, sizeof(s), &buf[532], 2,
		       SHR_HEX_UPPER | SHR_HEX_REVERSE);
	printf("    \"Atomic Compare 0 Write Unit\":\"%sh\",\n", s);

	temp = le32_to_cpu(ctrl->sgls);
	printf("    \"SGL Support\":{\n");
	shr_bin_to_hex(s, sizeof(s), &buf[536], 4,
		       SHR_HEX_UPPER | SHR_HEX_REVERSE);
	printf("        \"Value\":\"%sh\",\n", s);
	pos = (temp & 0x00000003);
	printf("        \"bit 1:0\":\"%s\",\n", SGLSSubtable[pos]);
	vt_build_identify_lv2(temp, 2, 1, SGLStable, false);
	vt_build_identify_lv2(temp, 16, 5, SGLStable, true);

	shr_bin_to_hex(s, sizeof(s), &buf[768], 256, SHR_HEX_UPPER);
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
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;

	struct vtview_save_log_settings cfg = {
		.run_time_hrs = 20,
		.log_record_frequency_hrs = 10,
		.output_file = NULL,
		.test_name = NULL,
	};

	OPT_ARGS(opts) = {
		OPT_DOUBLE("run-time",  'r', &cfg.run_time_hrs, run_time),
		OPT_DOUBLE("freq", 'f', &cfg.log_record_frequency_hrs, freq),
		OPT_FILE("output-file", 'O', &cfg.output_file,  output_file),
		OPT_STRING("test-name", 'n', "NAME", &cfg.test_name, test_name),
		OPT_END()
	};

	vt_generate_vtview_log_file_name(vt_default_log_file_name,
					 sizeof(vt_default_log_file_name));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	nvme_show_verbose_info("Running...");
	nvme_show_verbose_info("Collecting data for device %s",
			       nvme_args.device);
	nvme_show_verbose_info("Running for %lf hour(s)", cfg.run_time_hrs);
	nvme_show_verbose_info("Logging SMART data for every %lf hour(s)", cfg.log_record_frequency_hrs);

	ret = vt_update_vtview_log_header(hdl, nvme_args.device, &cfg);
	if (ret)
		return ret;

	total_time = cfg.run_time_hrs * HOUR_IN_SECONDS;
	freq_time = cfg.log_record_frequency_hrs * HOUR_IN_SECONDS;

	if (!freq_time)
		freq_time = 1;

	start_time = time(NULL);
	end_time = start_time + total_time;

	fflush(stdout);

	while (1) {
		cur_time = time(NULL);
		if (cur_time >= end_time)
			break;

		ret = vt_add_entry_to_log(hdl, nvme_args.device, &cfg);
		if (ret) {
			nvme_show_error("Cannot update driver log");
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
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	struct nvme_id_ctrl ctrl;
	struct libnvme_passthru_cmd cmd;
	int ret, err = 0;

	OPT_ARGS(opts) = {
		OPT_END()
	};

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	nvme_init_identify_ctrl(&cmd, &ctrl);
	ret = libnvme_exec_admin_passthru(hdl, &cmd);
	if (ret) {
		nvme_show_error("Cannot read identify device");
		return -1;
	}

	vt_process_string(ctrl.sn, sizeof(ctrl.sn));
	vt_process_string(ctrl.mn, sizeof(ctrl.mn));
	vt_parse_detail_identify(&ctrl);

	return err;
}

static struct command vt_save_smart_to_vtview_log_cmd = {
	.name = "save-smart-to-vtview-log",
	.help = "Periodically save smart attributes into a log file.\n"
		"                             The data in this log file can be "
		"analyzed using excel or using Virtium’s vtView.\n"
		"                             Visit vtView.virtium.com to see full "
		"potential uses of the data",
	.fn = vt_save_smart_to_vtview_log,
};

static struct command vt_show_identify_cmd = {
	.name = "show-identify",
	.help = "Shows detail features and current settings",
	.fn = vt_show_identify,
};

static struct command *commands[] = {
	&vt_save_smart_to_vtview_log_cmd,
	&vt_show_identify_cmd,
	NULL,
};

static struct plugin plugin = {
	.name = "virtium",
	.desc = "Virtium vendor specific extensions",
	.version = NVME_VERSION,
};

static void __shr_constructor register_plugin(void)
{
	plugin_add_group(&plugin, NULL, commands);
	register_extension(&plugin);
}
