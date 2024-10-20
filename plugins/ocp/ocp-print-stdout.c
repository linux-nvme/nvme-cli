// SPDX-License-Identifier: GPL-2.0-or-later
#include "util/types.h"
#include "common.h"
#include "nvme-print.h"
#include "ocp-print.h"
#include "ocp-hardware-component-log.h"
#include "ocp-fw-activation-history.h"
#include "ocp-smart-extended-log.h"
#include "ocp-telemetry-decode.h"
#include "ocp-nvme.h"

static void print_hwcomp_desc(struct hwcomp_desc_entry *e, bool list, int num)
{
	printf("  Component %d: %s\n", num, hwcomp_id_to_string(le32_to_cpu(e->desc->id)));

	if (list)
		return;

	printf("    Date/Lot Size: 0x%"PRIx64"\n", (uint64_t)e->date_lot_size);
	printf("    Additional Information Size: 0x%"PRIx64"\n", (uint64_t)e->add_info_size);
	printf("    Identifier: 0x%08x\n", le32_to_cpu(e->desc->id));
	printf("    Manufacture: 0x%016"PRIx64"\n", le64_to_cpu(e->desc->mfg));
	printf("    Revision: 0x%016"PRIx64"\n", le64_to_cpu(e->desc->rev));
	printf("    Manufacture Code: 0x%016"PRIx64"\n", le64_to_cpu(e->desc->mfg_code));
	print_array("    Date/Lot Code", e->date_lot_code, e->date_lot_size);
	print_array("    Additional Information", e->add_info, e->add_info_size);
}

static void stdout_hwcomp_log(struct hwcomp_log *log, __u32 id, bool list)
{
	size_t date_lot_code_offset = sizeof(struct hwcomp_desc);
	int num = 1;
	struct hwcomp_desc_entry e = { log->desc };

	long double log_size = uint128_t_to_double(le128_to_cpu(log->size)) * sizeof(__le32);

	printf("Log Identifier: 0x%02xh\n", LID_HWCOMP);
	printf("Log Page Version: 0x%x\n", le16_to_cpu(log->ver));
	print_array("Reserved2", log->rsvd2, ARRAY_SIZE(log->rsvd2));
	print_array("Log page GUID", log->guid, ARRAY_SIZE(log->guid));
	printf("Hardware Component Log Size: 0x%"PRIx64"\n", (uint64_t)log_size);
	print_array("Reserved48", log->rsvd48, ARRAY_SIZE(log->rsvd48));
	printf("Component Descriptions\n");
	while (log_size > 0) {
		e.date_lot_size = le64_to_cpu(e.desc->date_lot_size) * sizeof(__le32);
		e.date_lot_code = e.date_lot_size ? (__u8 *)e.desc + date_lot_code_offset : NULL;
		e.add_info_size = le64_to_cpu(e.desc->add_info_size) * sizeof(__le32);
		e.add_info = e.add_info_size ? e.date_lot_code ? e.date_lot_code + e.date_lot_size :
		    (__u8 *)e.desc + date_lot_code_offset : NULL;
		if (!id || id == le32_to_cpu(e.desc->id))
			print_hwcomp_desc(&e, list, num++);
		e.desc_size = date_lot_code_offset + e.date_lot_size + e.add_info_size;
		e.desc = (struct hwcomp_desc *)((__u8 *)e.desc + e.desc_size);
		log_size -= e.desc_size;
	}
}

static void stdout_fw_activation_history(const struct fw_activation_history *fw_history)
{
	printf("Firmware History Log:\n");

	printf("  %-26s%d\n", "log identifier:", fw_history->log_id);
	printf("  %-26s%d\n", "valid entries:", le32_to_cpu(fw_history->valid_entries));

	printf("  entries:\n");

	for (int index = 0; index < fw_history->valid_entries; index++) {
		const struct fw_activation_history_entry *entry = &fw_history->entries[index];

		printf("    entry[%d]:\n", le32_to_cpu(index));
		printf("      %-22s%d\n", "version number:", entry->ver_num);
		printf("      %-22s%d\n", "entry length:", entry->entry_length);
		printf("      %-22s%d\n", "activation count:",
		       le16_to_cpu(entry->activation_count));
		printf("      %-22s%"PRIu64"\n", "timestamp:",
				(0x0000FFFFFFFFFFFF & le64_to_cpu(entry->timestamp)));
		printf("      %-22s%"PRIu64"\n", "power cycle count:",
		       le64_to_cpu(entry->power_cycle_count));
		printf("      %-22s%.*s\n", "previous firmware:", (int)sizeof(entry->previous_fw),
		       entry->previous_fw);
		printf("      %-22s%.*s\n", "new firmware:", (int)sizeof(entry->new_fw),
		       entry->new_fw);
		printf("      %-22s%d\n", "slot number:", entry->slot_number);
		printf("      %-22s%d\n", "commit action type:", entry->commit_action);
		printf("      %-22s%d\n", "result:",  le16_to_cpu(entry->result));
	}

	printf("  %-26s%d\n", "log page version:",
	       le16_to_cpu(fw_history->log_page_version));

	printf("  %-26s0x%"PRIx64"%"PRIx64"\n", "log page guid:",
	       le64_to_cpu(fw_history->log_page_guid[1]),
	       le64_to_cpu(fw_history->log_page_guid[0]));

	printf("\n");
}

static void stdout_smart_extended_log(void *data)
{
	uint16_t smart_log_ver = 0;
	__u8 *log_data = data;

	printf("SMART Cloud Attributes :-\n");

	printf("  Physical media units written -		%"PRIu64" %"PRIu64"\n",
	       (uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_PMUW + 8] & 0xFFFFFFFFFFFFFFFF),
	       (uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_PMUW] & 0xFFFFFFFFFFFFFFFF));
	printf("  Physical media units read    -		%"PRIu64" %"PRIu64"\n",
	       (uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_PMUR + 8] & 0xFFFFFFFFFFFFFFFF),
	       (uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_PMUR] & 0xFFFFFFFFFFFFFFFF));
	printf("  Bad user nand blocks - Raw			%"PRIu64"\n",
	       (uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_BUNBR] & 0x0000FFFFFFFFFFFF));
	printf("  Bad user nand blocks - Normalized		%d\n",
	       (uint16_t)le16_to_cpu(*(uint16_t *)&log_data[SCAO_BUNBN]));
	printf("  Bad system nand blocks - Raw			%"PRIu64"\n",
	       (uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_BSNBR] & 0x0000FFFFFFFFFFFF));
	printf("  Bad system nand blocks - Normalized		%d\n",
	       (uint16_t)le16_to_cpu(*(uint16_t *)&log_data[SCAO_BSNBN]));
	printf("  XOR recovery count				%"PRIu64"\n",
	       (uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_XRC]));
	printf("  Uncorrectable read error count		%"PRIu64"\n",
	       (uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_UREC]));
	printf("  Soft ecc error count				%"PRIu64"\n",
	       (uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_SEEC]));
	printf("  End to end detected errors			%"PRIu32"\n",
	       (uint32_t)le32_to_cpu(*(uint32_t *)&log_data[SCAO_EEDC]));
	printf("  End to end corrected errors			%"PRIu32"\n",
	       (uint32_t)le32_to_cpu(*(uint32_t *)&log_data[SCAO_EECE]));
	printf("  System data percent used			%d\n",
	       (__u8)log_data[SCAO_SDPU]);
	printf("  Refresh counts				%"PRIu64"\n",
	       (uint64_t)(le64_to_cpu(*(uint64_t *)&log_data[SCAO_RFSC]) & 0x00FFFFFFFFFFFFFF));
	printf("  Max User data erase counts			%"PRIu32"\n",
	       (uint32_t)le32_to_cpu(*(uint32_t *)&log_data[SCAO_MXUDEC]));
	printf("  Min User data erase counts			%"PRIu32"\n",
	       (uint32_t)le32_to_cpu(*(uint32_t *)&log_data[SCAO_MNUDEC]));
	printf("  Number of Thermal throttling events		%d\n",
	       (__u8)log_data[SCAO_NTTE]);
	printf("  Current throttling status			0x%x\n",
	       (__u8)log_data[SCAO_CTS]);
	printf("  PCIe correctable error count			%"PRIu64"\n",
	       (uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_PCEC]));
	printf("  Incomplete shutdowns				%"PRIu32"\n",
	       (uint32_t)le32_to_cpu(*(uint32_t *)&log_data[SCAO_ICS]));
	printf("  Percent free blocks				%d\n",
	       (__u8)log_data[SCAO_PFB]);
	printf("  Capacitor health				%"PRIu16"\n",
	       (uint16_t)le16_to_cpu(*(uint16_t *)&log_data[SCAO_CPH]));
	printf("  NVMe base errata version			%c\n",
	       (uint16_t)le16_to_cpu(*(uint16_t *)&log_data[SCAO_CPH]));
	printf("  NVMe command set errata version		%c\n",
	       (uint16_t)le16_to_cpu(*(uint16_t *)&log_data[SCAO_CPH]));
	printf("  Unaligned I/O					%"PRIu64"\n",
	       (uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_UIO]));
	printf("  Security Version Number			%"PRIu64"\n",
	       (uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_SVN]));
	printf("  NUSE - Namespace utilization			%"PRIu64"\n",
	       (uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_NUSE]));
	printf("  PLP start count				%s\n",
	       uint128_t_to_string(le128_to_cpu(&log_data[SCAO_PSC])));
	printf("  Endurance estimate				%s\n",
	       uint128_t_to_string(le128_to_cpu(&log_data[SCAO_EEST])));
	smart_log_ver = (uint16_t)le16_to_cpu(*(uint16_t *)&log_data[SCAO_LPV]);
	printf("  Log page version				%"PRIu16"\n", smart_log_ver);
	printf("  Log page GUID					0x");
	printf("%"PRIx64"%"PRIx64"\n", (uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_LPG + 8]),
	       (uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_LPG]));
	switch (smart_log_ver) {
	case 0 ... 1:
		break;
	default:
	case 4:
		printf("  NVMe Command Set Errata Version               %d\n",
		       (__u8)log_data[SCAO_NCSEV]);
		printf("  Lowest Permitted Firmware Revision            %"PRIu64"\n",
		       le64_to_cpu(*(uint64_t *)&log_data[SCAO_PSCC]));
		fallthrough;
	case 2 ... 3:
		printf("  Errata Version Field                          %d\n",
		       (__u8)log_data[SCAO_EVF]);
		printf("  Point Version Field                           %"PRIu16"\n",
		       le16_to_cpu(*(uint16_t *)&log_data[SCAO_PVF]));
		printf("  Minor Version Field                           %"PRIu16"\n",
		       le16_to_cpu(*(uint16_t *)&log_data[SCAO_MIVF]));
		printf("  Major Version Field                           %d\n",
		       (__u8)log_data[SCAO_MAVF]);
		printf("  NVMe Base Errata Version                      %d\n",
		       (__u8)log_data[SCAO_NBEV]);
		printf("  PCIe Link Retraining Count                    %"PRIu64"\n",
		       (uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_PLRC]));
		printf("  Power State Change Count                      %"PRIu64"\n",
		       le64_to_cpu(*(uint64_t *)&log_data[SCAO_PSCC]));
	}
	printf("\n");
}

static void stdout_telemetry_log(struct ocp_telemetry_parse_options *options)
{
#ifdef CONFIG_JSONC
	print_ocp_telemetry_normal(options);
#endif /* CONFIG_JSONC */
}

static int stdout_c3_log(struct nvme_dev *dev, struct ssd_latency_monitor_log *log_data)
{
	char ts_buf[128];
	int i, j;

	printf("-Latency Monitor/C3 Log Page Data-\n");
	printf("  Controller   :  %s\n", dev->name);
	printf("  Feature Status                     0x%x\n",
	       log_data->feature_status);
	printf("  Active Bucket Timer                %d min\n",
	       C3_ACTIVE_BUCKET_TIMER_INCREMENT *
	       le16_to_cpu(log_data->active_bucket_timer));
	printf("  Active Bucket Timer Threshold      %d min\n",
	       C3_ACTIVE_BUCKET_TIMER_INCREMENT *
	       le16_to_cpu(log_data->active_bucket_timer_threshold));
	printf("  Active Threshold A                 %d ms\n",
	       C3_ACTIVE_THRESHOLD_INCREMENT *
	       le16_to_cpu(log_data->active_threshold_a+1));
	printf("  Active Threshold B                 %d ms\n",
	       C3_ACTIVE_THRESHOLD_INCREMENT *
	       le16_to_cpu(log_data->active_threshold_b+1));
	printf("  Active Threshold C                 %d ms\n",
	       C3_ACTIVE_THRESHOLD_INCREMENT *
	       le16_to_cpu(log_data->active_threshold_c+1));
	printf("  Active Threshold D                 %d ms\n",
	       C3_ACTIVE_THRESHOLD_INCREMENT *
	       le16_to_cpu(log_data->active_threshold_d+1));
	printf("  Active Latency Configuration       0x%x\n",
	       le16_to_cpu(log_data->active_latency_config));
	printf("  Active Latency Minimum Window      %d ms\n",
	       C3_MINIMUM_WINDOW_INCREMENT *
	       le16_to_cpu(log_data->active_latency_min_window));
	printf("  Active Latency Stamp Units         %d\n",
	       le16_to_cpu(log_data->active_latency_stamp_units));
	printf("  Static Latency Stamp Units         %d\n",
	       le16_to_cpu(log_data->static_latency_stamp_units));
	printf("  Debug Log Trigger Enable           %d\n",
	       le16_to_cpu(log_data->debug_log_trigger_enable));
	printf("  Debug Log Measured Latency         %d\n",
	       le16_to_cpu(log_data->debug_log_measured_latency));
	if (le64_to_cpu(log_data->debug_log_latency_stamp) == -1) {
		printf("  Debug Log Latency Time Stamp       N/A\n");
	} else {
		convert_ts(le64_to_cpu(log_data->debug_log_latency_stamp), ts_buf);
		printf("  Debug Log Latency Time Stamp       %s\n", ts_buf);
	}
	printf("  Debug Log Pointer                  %d\n",
	       le16_to_cpu(log_data->debug_log_ptr));
	printf("  Debug Counter Trigger Source       %d\n",
	       le16_to_cpu(log_data->debug_log_counter_trigger));
	printf("  Debug Log Stamp Units              %d\n",
	       le16_to_cpu(log_data->debug_log_stamp_units));
	printf("  Log Page Version                   %d\n",
	       le16_to_cpu(log_data->log_page_version));

	char guid[(C3_GUID_LENGTH * 2) + 1];
	char *ptr = &guid[0];

	for (i = C3_GUID_LENGTH - 1; i >= 0; i--)
		ptr += sprintf(ptr, "%02X", log_data->log_page_guid[i]);

	printf("  Log Page GUID                      %s\n", guid);
	printf("\n");

	printf("%64s%92s%119s\n", "Read", "Write", "Deallocate/Trim");
	for (i = 0; i < C3_BUCKET_NUM; i++) {
		printf("  Active Bucket Counter: Bucket %d    %27d     %27d     %27d\n",
		       i,
		       le32_to_cpu(log_data->active_bucket_counter[i][READ]),
		       le32_to_cpu(log_data->active_bucket_counter[i][WRITE]),
		       le32_to_cpu(log_data->active_bucket_counter[i][TRIM]));
	}

	for (i = 0; i < C3_BUCKET_NUM; i++) {
		printf("  Active Latency Time Stamp: Bucket %d    ", i);
		for (j = 2; j >= 0; j--) {
			if (le64_to_cpu(log_data->active_latency_timestamp[3-i][j]) == -1) {
				printf("                    N/A         ");
			} else {
				convert_ts(le64_to_cpu(log_data->active_latency_timestamp[3-i][j]),
					   ts_buf);
				printf("%s     ", ts_buf);
			}
		}
		printf("\n");
	}

	for (i = 0; i < C3_BUCKET_NUM; i++) {
		printf("  Active Measured Latency: Bucket %d  %27d ms  %27d ms  %27d ms\n",
		       i,
		       le16_to_cpu(log_data->active_measured_latency[3-i][READ-1]),
		       le16_to_cpu(log_data->active_measured_latency[3-i][WRITE-1]),
		       le16_to_cpu(log_data->active_measured_latency[3-i][TRIM-1]));
	}

	printf("\n");
	for (i = 0; i < C3_BUCKET_NUM; i++) {
		printf("  Static Bucket Counter: Bucket %d    %27d     %27d     %27d\n",
		       i,
		       le32_to_cpu(log_data->static_bucket_counter[i][READ]),
		       le32_to_cpu(log_data->static_bucket_counter[i][WRITE]),
		       le32_to_cpu(log_data->static_bucket_counter[i][TRIM]));
	}

	for (i = 0; i < C3_BUCKET_NUM; i++) {
		printf("  Static Latency Time Stamp: Bucket %d    ", i);
		for (j = 2; j >= 0; j--) {
			if (le64_to_cpu(log_data->static_latency_timestamp[3-i][j]) == -1) {
				printf("                    N/A         ");
			} else {
				convert_ts(le64_to_cpu(log_data->static_latency_timestamp[3-i][j]),
					   ts_buf);
				printf("%s     ", ts_buf);
			}
		}
		printf("\n");
	}

	for (i = 0; i < C3_BUCKET_NUM; i++) {
		printf("  Static Measured Latency: Bucket %d  %27d ms  %27d ms  %27d ms\n",
		       i,
		       le16_to_cpu(log_data->static_measured_latency[3-i][READ-1]),
		       le16_to_cpu(log_data->static_measured_latency[3-i][WRITE-1]),
		       le16_to_cpu(log_data->static_measured_latency[3-i][TRIM-1]));
	}

	return 0;
}

static int stdout_c5_log(struct nvme_dev *dev, struct unsupported_requirement_log *log_data)
{
	int j;

	printf("Unsupported Requirement-C5 Log Page Data-\n");

	printf("  Number Unsupported Req IDs		: 0x%x\n",
	       le16_to_cpu(log_data->unsupported_count));

	for (j = 0; j < le16_to_cpu(log_data->unsupported_count); j++)
		printf("  Unsupported Requirement List %d	: %s\n", j,
		       log_data->unsupported_req_list[j]);

	printf("  Log Page Version			: 0x%x\n",
	       le16_to_cpu(log_data->log_page_version));
	printf("  Log page GUID				: 0x");
	for (j = C5_GUID_LENGTH - 1; j >= 0; j--)
		printf("%02x", log_data->log_page_guid[j]);
	printf("\n");

	return 0;
}

static void stdout_c1_log(struct ocp_error_recovery_log_page *log_data)
{
	int i;

	printf("  Error Recovery/C1 Log Page Data\n");
	printf("  Panic Reset Wait Time             : 0x%x\n",
	       le16_to_cpu(log_data->panic_reset_wait_time));
	printf("  Panic Reset Action                : 0x%x\n", log_data->panic_reset_action);
	printf("  Device Recovery Action 1          : 0x%x\n", log_data->device_recover_action_1);
	printf("  Panic ID                          : 0x%x\n", le32_to_cpu(log_data->panic_id));
	printf("  Device Capabilities               : 0x%x\n",
	       le32_to_cpu(log_data->device_capabilities));
	printf("  Vendor Specific Recovery Opcode   : 0x%x\n",
	       log_data->vendor_specific_recovery_opcode);
	printf("  Vendor Specific Command CDW12     : 0x%x\n",
	       le32_to_cpu(log_data->vendor_specific_command_cdw12));
	printf("  Vendor Specific Command CDW13     : 0x%x\n",
	       le32_to_cpu(log_data->vendor_specific_command_cdw13));
	printf("  Vendor Specific Command Timeout   : 0x%x\n",
	       log_data->vendor_specific_command_timeout);
	printf("  Device Recovery Action 2          : 0x%x\n",
	       log_data->device_recover_action_2);
	printf("  Device Recovery Action 2 Timeout  : 0x%x\n",
	       log_data->device_recover_action_2_timeout);
	printf("  Panic Count                       : 0x%x\n", log_data->panic_count);
	printf("  Previous Panic IDs:");
	for (i = 0; i < C1_PREV_PANIC_IDS_LENGTH; i++)
		printf("%s Panic ID N-%d : 0x%"PRIx64"\n", i ? "                     " : "", i + 1,
		       le64_to_cpu(log_data->prev_panic_id[i]));
	printf("  Log Page Version                  : 0x%x\n",
	       le16_to_cpu(log_data->log_page_version));
	printf("  Log page GUID                     : 0x");
	for (i = C1_GUID_LENGTH - 1; i >= 0; i--)
		printf("%02x", log_data->log_page_guid[i]);
	printf("\n");
}

static struct ocp_print_ops stdout_print_ops = {
	.hwcomp_log = stdout_hwcomp_log,
	.fw_act_history = stdout_fw_activation_history,
	.smart_extended_log = stdout_smart_extended_log,
	.telemetry_log = stdout_telemetry_log,
	.c3_log = (void *)stdout_c3_log,
	.c5_log = (void *)stdout_c5_log,
	.c1_log = stdout_c1_log,
};

struct ocp_print_ops *ocp_get_stdout_print_ops(nvme_print_flags_t flags)
{
	stdout_print_ops.flags = flags;
	return &stdout_print_ops;
}
