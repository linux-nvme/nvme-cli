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
	long double log_bytes = uint128_t_to_double(le128_to_cpu(log->size));
	struct hwcomp_desc_entry e = { log->desc };

	if (log->ver == 1)
		log_bytes *= sizeof(__le32);

	printf("Log Identifier: 0x%02xh\n", OCP_LID_HWCOMP);
	printf("Log Page Version: 0x%x\n", le16_to_cpu(log->ver));
	print_array("Reserved2", log->rsvd2, ARRAY_SIZE(log->rsvd2));
	print_array("Log page GUID", log->guid, ARRAY_SIZE(log->guid));
	printf("Hardware Component Log Size: 0x%"PRIx64"\n", (uint64_t)log_bytes);
	print_array("Reserved48", log->rsvd48, ARRAY_SIZE(log->rsvd48));
	printf("Component Descriptions\n");
	log_bytes -= offsetof(struct hwcomp_log, desc);
	while (log_bytes > 0) {
		e.date_lot_size = le64_to_cpu(e.desc->date_lot_size) * sizeof(__le32);
		e.date_lot_code = e.date_lot_size ? (__u8 *)e.desc + date_lot_code_offset : NULL;
		e.add_info_size = le64_to_cpu(e.desc->add_info_size) * sizeof(__le32);
		e.add_info = e.add_info_size ? e.date_lot_code ? e.date_lot_code + e.date_lot_size :
		    (__u8 *)e.desc + date_lot_code_offset : NULL;
		if (!id || id == le32_to_cpu(e.desc->id))
			print_hwcomp_desc(&e, list, num++);
		e.desc_size = date_lot_code_offset + e.date_lot_size + e.add_info_size;
		e.desc = (struct hwcomp_desc *)((__u8 *)e.desc + e.desc_size);
		log_bytes -= e.desc_size;
	}
}

static void stdout_fw_activation_history(const struct fw_activation_history *fw_history)
{
	printf("Firmware History Log:\n");

	printf("  %-26s%d\n", "log identifier:", fw_history->log_id);
	printf("  %-26s%d\n", "valid entries:", le32_to_cpu(fw_history->valid_entries));

	printf("  entries:\n");

	for (int index = 0; index < le32_to_cpu(fw_history->valid_entries); index++) {
		const struct fw_activation_history_entry *entry = &fw_history->entries[index];

		printf("    entry[%d]:\n", index);
		printf("      %-22s%d\n", "version number:", entry->ver_num);
		printf("      %-22s%d\n", "entry length:", entry->entry_length);
		printf("      %-22s%d\n", "activation count:",
		       le16_to_cpu(entry->activation_count));
		printf("      %-22s%"PRIu64"\n", "timestamp:", int48_to_long(entry->ts.timestamp));
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

static void stdout_smart_extended_log(struct ocp_smart_extended_log *log, unsigned int version)
{
	uint16_t smart_log_ver = 0;
	uint16_t dssd_version = 0;
	int i = 0;

	printf("SMART Cloud Attributes :-\n");

	printf("  Physical media units written -		%"PRIu64" %"PRIu64"\n",
		le64_to_cpu(*(uint64_t *)&log->physical_media_units_written[8]),
		le64_to_cpu(*(uint64_t *)&log->physical_media_units_written));
	printf("  Physical media units read    -		%"PRIu64" %"PRIu64"\n",
		le64_to_cpu(*(uint64_t *)&log->physical_media_units_read[8]),
		le64_to_cpu(*(uint64_t *)&log->physical_media_units_read));
	printf("  Bad user nand blocks - Raw			%"PRIu64"\n",
		int48_to_long(log->bad_user_nand_blocks_raw));
	printf("  Bad user nand blocks - Normalized		%d\n",
		le16_to_cpu(log->bad_user_nand_blocks_normalized));
	printf("  Bad system nand blocks - Raw			%"PRIu64"\n",
		int48_to_long(log->bad_system_nand_blocks_raw));
	printf("  Bad system nand blocks - Normalized		%d\n",
		le16_to_cpu(log->bad_system_nand_blocks_normalized));
	printf("  XOR recovery count				%"PRIu64"\n",
		le64_to_cpu(log->xor_recovery_count));
	printf("  Uncorrectable read error count		%"PRIu64"\n",
		le64_to_cpu(log->uncorrectable_read_err_count));
	printf("  Soft ecc error count				%"PRIu64"\n",
		le64_to_cpu(log->soft_ecc_err_count));
	printf("  End to end detected errors			%"PRIu32"\n",
		le32_to_cpu(log->end_to_end_detected_err));
	printf("  End to end corrected errors			%"PRIu32"\n",
		le32_to_cpu(log->end_to_end_corrected_err));
	printf("  System data percent used			%d\n",
		log->system_data_used_percent);
	printf("  Refresh counts				%"PRIu64"\n",
		int56_to_long(log->refresh_counts));
	printf("  Max User data erase counts			%"PRIu32"\n",
		le32_to_cpu(log->user_data_erase_count_max));
	printf("  Min User data erase counts			%"PRIu32"\n",
		le32_to_cpu(log->user_data_erase_count_min));
	printf("  Number of Thermal throttling events		%d\n",
		log->thermal_throttling_event_count);
	printf("  Current throttling status			0x%x\n",
		log->thermal_throttling_current_status);
	printf("  PCIe correctable error count			%"PRIu64"\n",
		le64_to_cpu(log->pcie_correctable_err_count));
	printf("  Incomplete shutdowns				%"PRIu32"\n",
		le32_to_cpu(log->incomplete_shoutdowns));
	printf("  Percent free blocks				%d\n",
		log->percent_free_blocks);
	printf("  Capacitor health				%"PRIu16"\n",
		le16_to_cpu(log->capacitor_health));
	printf("  Unaligned I/O					%"PRIu64"\n",
		le64_to_cpu(log->unaligned_io));
	printf("  Security Version Number			%"PRIu64"\n",
		le64_to_cpu(log->security_version));
	printf("  NUSE - Namespace utilization			%"PRIu64"\n",
		le64_to_cpu(log->total_nuse));
	printf("  PLP start count				%s\n",
		uint128_t_to_string(le128_to_cpu(log->plp_start_count)));
	printf("  Endurance estimate				%s\n",
		uint128_t_to_string(le128_to_cpu(log->endurance_estimate)));
	smart_log_ver = le16_to_cpu(log->log_page_version);
	printf("  Log page version				%"PRIu16"\n", smart_log_ver);
	printf("  Log page GUID					0x");
	printf("%"PRIx64"%"PRIx64"\n", le64_to_cpu(*(uint64_t *)&log->log_page_guid[8]),
		le64_to_cpu(*(uint64_t *)&log->log_page_guid));
	switch (smart_log_ver) {
	case 0 ... 1:
		break;
	default:
	case 4:
		printf("  NVMe Command Set Errata Version               %d\n",
			log->nvme_cmdset_errata_version);
		printf("  Lowest Permitted Firmware Revision            %"PRIu64"\n",
			le64_to_cpu(log->lowest_permitted_fw_rev));
		printf("  NVMe Over Pcie Errata Version			%d\n",
			log->nvme_over_pcie_errate_version);
		printf("  NVMe Mi Errata Version			%d\n",
			log->nvme_mi_errata_version);
		printf("  Total media dies				%"PRIu16"\n",
			le16_to_cpu(log->total_media_dies));
		printf("  Total die failure tolerance			%"PRIu16"\n",
			le16_to_cpu(log->total_die_failure_tolerance));
		printf("  Media dies offline				%"PRIu16"\n",
			le16_to_cpu(log->media_dies_offline));
		printf("  Max temperature recorded			%d\n",
			log->max_temperature_recorded);
		printf("  Nand avg erase count				%"PRIu64"\n",
			le64_to_cpu(log->nand_avg_erase_count));
		printf("  Command timeouts				%"PRIu32"\n",
			le32_to_cpu(log->command_timeouts));
		printf("  Sys area program fail count raw		%"PRIu32"\n",
			le32_to_cpu(log->sys_area_program_fail_count_raw));
		printf("  Sys area program fail count noralized		%d\n",
			le32_to_cpu(log->sys_area_program_fail_count_normalized));
		printf("  Sys area uncorrectable read count raw		%"PRIu32"\n",
			le32_to_cpu(log->sys_area_uncorr_read_count_raw));
		printf("  Sys area uncorrectable read count noralized	%d\n",
			le32_to_cpu(log->sys_area_uncorr_read_count_normalized));
		printf("  Sys area erase fail count raw			%"PRIu32"\n",
			le32_to_cpu(log->sys_area_erase_fail_count_raw));
		printf("  Sys area erase fail count noralized		%d\n",
			le32_to_cpu(log->sys_area_erase_fail_count_normalized));
		printf("  Max peak power capability			%"PRIu16"\n",
			le16_to_cpu(log->max_peak_power_capability));
		printf("  Current max avg power				%"PRIu16"\n",
			le16_to_cpu(log->current_max_avg_power));
		printf("  Lifetime power consumed			%"PRIu64"\n",
			int48_to_long(log->lifetime_power_consumed));
		printf("  Dssd firmware revision			");
		for (i = 0; i < sizeof(log->dssd_firmware_revision); i++)
			printf("%c", log->dssd_firmware_revision[i]);
		printf("\n");
		printf("  Dssd firmware build UUID			%s\n",
			util_uuid_to_string(log->dssd_firmware_build_uuid));
		printf("  Dssd firmware build label			");
		for (i = 0; i < sizeof(log->dssd_firmware_build_label); i++)
			printf("%c", log->dssd_firmware_build_label[i]);
		printf("\n");
		fallthrough;
	case 2 ... 3:
		printf("  Errata Version Field                          %d\n",
			log->dssd_errata_version);
		memcpy(&dssd_version, log->dssd_point_version, sizeof(dssd_version));
		printf("  Point Version Field                           %"PRIu16"\n",
			le16_to_cpu(dssd_version));
		memcpy(&dssd_version, log->dssd_minor_version, sizeof(dssd_version));
		printf("  Minor Version Field                           %"PRIu16"\n",
			le16_to_cpu(dssd_version));
		printf("  Major Version Field                           %d\n",
			log->dssd_major_version);
		printf("  NVMe Base Errata Version                      %d\n",
			log->nvme_base_errata_version);
		printf("  PCIe Link Retraining Count                    %"PRIu64"\n",
			le64_to_cpu(log->pcie_link_retaining_count));
		printf("  Power State Change Count                      %"PRIu64"\n",
			le64_to_cpu(log->power_state_change_count));
	}
	printf("\n");
}

static void stdout_telemetry_log(struct ocp_telemetry_parse_options *options)
{
#ifdef CONFIG_JSONC
	print_ocp_telemetry_normal(options);
#endif /* CONFIG_JSONC */
}

static void stdout_c3_log(struct nvme_transport_handle *hdl, struct ssd_latency_monitor_log *log_data)
{
	char ts_buf[128];
	int i, j;
	__u16 log_page_version = le16_to_cpu(log_data->log_page_version);

	printf("-Latency Monitor/C3 Log Page Data-\n");
	printf("  Controller   :  %s\n",
	       nvme_transport_handle_get_name(hdl));
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

	if (log_page_version >= 0x4) {
		printf("    Debug Telemetry Log Size         0x");
		for (i = ARRAY_SIZE(log_data->latency_monitor_debug_log_size) - 1;
			i > 0 && (log_data->latency_monitor_debug_log_size[i] == 0); i--)
			;
		while (i >= 0)
			printf("%02x", log_data->latency_monitor_debug_log_size[i--]);
		printf("\n");
	}

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
	printf("  Log Page Version                   %d\n", log_page_version);

	char guid[(GUID_LEN * 2) + 1];
	char *ptr = &guid[0];

	for (i = GUID_LEN - 1; i >= 0; i--)
		ptr += sprintf(ptr, "%02X", log_data->log_page_guid[i]);

	printf("  Log Page GUID                      %s\n", guid);
	printf("\n");

	printf("%64s     %27s     %27s\n", "Read", "Write", "Deallocate/Trim");
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
}

static void stdout_c5_log(struct nvme_transport_handle *hdl, struct unsupported_requirement_log *log_data)
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
	for (j = GUID_LEN - 1; j >= 0; j--)
		printf("%02x", log_data->log_page_guid[j]);
	printf("\n");
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
	for (i = GUID_LEN - 1; i >= 0; i--)
		printf("%02x", log_data->log_page_guid[i]);
	printf("\n");
}

static void stdout_c4_log(struct ocp_device_capabilities_log_page *log_data)
{
	int i;

	printf("  Device Capability/C4 Log Page Data\n");
	printf("  PCI Express Ports						: 0x%x\n",
	       le16_to_cpu(log_data->pcie_exp_port));
	printf("  OOB Management Support				: 0x%x\n",
	       le16_to_cpu(log_data->oob_management_support));
	printf("  Write Zeroes Command Support			: 0x%x\n",
	       le16_to_cpu(log_data->wz_cmd_support));
	printf("  Sanitize Command Support				: 0x%x\n",
	       le16_to_cpu(log_data->sanitize_cmd_support));
	printf("  Dataset Management Command Support	: 0x%x\n",
	       le16_to_cpu(log_data->dsm_cmd_support));
	printf("  Write Uncorrectable Command Support	: 0x%x\n",
	       le16_to_cpu(log_data->wu_cmd_support));
	printf("  Fused Operation Support				: 0x%x\n",
	       le16_to_cpu(log_data->fused_operation_support));
	printf("  Minimum Valid DSSD Power State		: 0x%x\n",
	       le16_to_cpu(log_data->min_valid_dssd_pwr_state));
	printf("  DSSD Power State Descriptors					: 0x");
	for (i = 0; i <= 127; i++)
		printf("%x", log_data->dssd_pwr_state_desc[i]);
	printf("\n");
	printf("  Log Page Version						: 0x%x\n",
	       le16_to_cpu(log_data->log_page_version));
	printf("  Log page GUID							: 0x");
	for (i = GUID_LEN - 1; i >= 0; i--)
		printf("%02x", log_data->log_page_guid[i]);
	printf("\n");
}

static void stdout_c9_log(struct telemetry_str_log_format *log_data, __u8 *log_data_buf,
			  int total_log_page_size)
{
	//calculating the index value for array
	__le64 stat_id_index = (log_data->sitsz * 4) / 16;
	__le64 eve_id_index = (log_data->estsz * 4) / 16;
	__le64 vu_eve_index = (log_data->vu_eve_st_sz * 4) / 16;
	__le64 ascii_table_index = (log_data->asctsz * 4);
	//Calculating the offset for dynamic fields.
	__le64 stat_id_str_table_ofst = log_data->sits * 4;
	__le64 event_str_table_ofst = log_data->ests * 4;
	__le64 vu_event_str_table_ofst = log_data->vu_eve_sts * 4;
	__le64 ascii_table_ofst = log_data->ascts * 4;
	struct statistics_id_str_table_entry stat_id_str_table_arr[stat_id_index];
	struct event_id_str_table_entry event_id_str_table_arr[eve_id_index];
	struct vu_event_id_str_table_entry vu_event_id_str_table_arr[vu_eve_index];
	int j;

	printf("  Log Page Version                                : 0x%x\n",
	       log_data->log_page_version);

	printf("  Reserved                                        : ");
	for (j = 0; j < 15; j++)
		printf("%d", log_data->reserved1[j]);
	printf("\n");

	printf("  Log page GUID                                   : 0x");
	for (j = GUID_LEN - 1; j >= 0; j--)
		printf("%02x", log_data->log_page_guid[j]);
	printf("\n");

	printf("  Telemetry String Log Size                       : 0x%"PRIx64"\n",
	       le64_to_cpu(log_data->sls));

	printf("  Reserved                                        : ");
	for (j = 0; j < 24; j++)
		printf("%d", log_data->reserved2[j]);
	printf("\n");

	printf("  Statistics Identifier String Table Start        : 0x%"PRIx64"\n",
	       le64_to_cpu(log_data->sits));
	printf("  Statistics Identifier String Table Size         : 0x%"PRIx64"\n",
	       le64_to_cpu(log_data->sitsz));
	printf("  Event String Table Start                        : 0x%"PRIx64"\n",
	       le64_to_cpu(log_data->ests));
	printf("  Event String Table Size                         : 0x%"PRIx64"\n",
	       le64_to_cpu(log_data->estsz));
	printf("  VU Event String Table Start                     : 0x%"PRIx64"\n",
	       le64_to_cpu(log_data->vu_eve_sts));
	printf("  VU Event String Table Size                      : 0x%"PRIx64"\n",
	       le64_to_cpu(log_data->vu_eve_st_sz));
	printf("  ASCII Table Start                               : 0x%"PRIx64"\n",
	       le64_to_cpu(log_data->ascts));
	printf("  ASCII Table Size                                : 0x%"PRIx64"\n",
	       le64_to_cpu(log_data->asctsz));

	printf("  FIFO 1 ASCII String\n");
	printf("   index    value    ascii_val\n");
	for (j = 0; j < 16; j++)
		printf("  %d       %d        %c\n", j, log_data->fifo1[j],
		       log_data->fifo1[j]);

	printf("  FIFO 2 ASCII String\n");
	printf("   index    value    ascii_val\n");
	for (j = 0; j < 16; j++)
		printf("  %d       %d        %c\n", j, log_data->fifo2[j],
		       log_data->fifo2[j]);

	printf("  FIFO 3 ASCII String\n");
	printf("   index    value    ascii_val\n");
	for (j = 0; j < 16; j++)
		printf("  %d       %d        %c\n", j, log_data->fifo3[j],
		       log_data->fifo3[j]);

	printf("  FIFO 4 ASCII String\n");
	printf("   index    value    ascii_val\n");
	for (j = 0; j < 16; j++)
		printf("  %d       %d        %c\n", j, log_data->fifo4[j], log_data->fifo4[j]);

	printf("  FIFO 5 ASCII String\n");
	printf("   index    value    ascii_val\n");
	for (j = 0; j < 16; j++)
		printf("  %d       %d        %c\n", j, log_data->fifo5[j], log_data->fifo5[j]);

	printf("  FIFO 6 ASCII String\n");
	printf("   index    value    ascii_val\n");
	for (j = 0; j < 16; j++)
		printf("  %d       %d        %c\n", j, log_data->fifo6[j], log_data->fifo6[j]);

	printf("  FIFO 7 ASCII String\n");
	printf("   index    value    ascii_val\n");
	for (j = 0; j < 16; j++)
		printf("  %d       %d        %c\n", j, log_data->fifo7[j], log_data->fifo7[j]);

	printf("  FIFO 8 ASCII String\n");
	printf("   index    value    ascii_val\n");
	for (j = 0; j < 16; j++)
		printf("  %d       %d        %c\n", j, log_data->fifo8[j], log_data->fifo8[j]);

	printf("  FIFO 9 ASCII String\n");
	printf("   index    value    ascii_val\n");
	for (j = 0; j < 16; j++)
		printf("  %d       %d        %c\n", j, log_data->fifo9[j], log_data->fifo9[j]);

	printf("  FIFO 10 ASCII String\n");
	printf("   index    value    ascii_val\n");
	for (j = 0; j < 16; j++)
		printf("  %d       %d        %c\n", j, log_data->fifo10[j], log_data->fifo10[j]);

	printf("  FIFO 11 ASCII String\n");
	printf("   index    value    ascii_val\n");
	for (j = 0; j < 16; j++)
		printf("  %d       %d        %c\n", j, log_data->fifo11[j], log_data->fifo11[j]);

	printf("  FIFO 12 ASCII String\n");
	printf("   index    value    ascii_val\n");
	for (j = 0; j < 16; j++)
		printf("  %d       %d        %c\n", j, log_data->fifo12[j], log_data->fifo12[j]);

	printf("  FIFO 13 ASCII String\n");
	printf("   index    value    ascii_val\n");
	for (j = 0; j < 16; j++)
		printf("  %d       %d        %c\n", j, log_data->fifo13[j], log_data->fifo13[j]);

	printf("  FIFO 14 ASCII String\n");
	printf("   index    value    ascii_val\n");
	for (j = 0; j < 16; j++)
		printf("  %d       %d        %c\n", j, log_data->fifo14[j], log_data->fifo14[j]);

	printf("  FIFO 15 ASCII String\n");
	printf("   index    value    ascii_val\n");
	for (j = 0; j < 16; j++)
		printf("  %d       %d        %c\n", j, log_data->fifo15[j], log_data->fifo16[j]);

	printf("  FIFO 16 ASCII String\n");
	printf("   index    value    ascii_val\n");
	for (j = 0; j < 16; j++)
		printf("  %d       %d        %c\n", j, log_data->fifo16[j], log_data->fifo16[j]);

	printf("  Reserved                                        : ");
	for (j = 0; j < 48; j++)
		printf("%d", log_data->reserved3[j]);
	printf("\n");

	if (log_data->sitsz != 0) {
		memcpy(stat_id_str_table_arr, (__u8 *)log_data_buf + stat_id_str_table_ofst,
		       (log_data->sitsz * 4));
		printf("  Statistics Identifier String Table\n");
		for (j = 0; j < stat_id_index; j++) {
			printf("   Vendor Specific Statistic Identifier : 0x%x\n",
			       le16_to_cpu(stat_id_str_table_arr[j].vs_si));
			printf("   Reserved                             : 0x%x\n",
			       stat_id_str_table_arr[j].reserved1);
			printf("   ASCII ID Length                      : 0x%x\n",
			       stat_id_str_table_arr[j].ascii_id_len);
			printf("   ASCII ID offset                      : 0x%"PRIx64"\n",
			       le64_to_cpu(stat_id_str_table_arr[j].ascii_id_ofst));
			printf("   Reserved                             : 0x%x\n",
			       stat_id_str_table_arr[j].reserved2);
		}
	}

	if (log_data->estsz != 0) {
		memcpy(event_id_str_table_arr, (__u8 *)log_data_buf + event_str_table_ofst,
		       (log_data->estsz * 4));
		printf("  Event Identifier String Table Entry\n");
		for (j = 0; j < eve_id_index; j++) {
			printf("   Debug Event Class        : 0x%x\n",
			       event_id_str_table_arr[j].deb_eve_class);
			printf("   Event Identifier         : 0x%x\n",
			       le16_to_cpu(event_id_str_table_arr[j].ei));
			printf("   ASCII ID Length          : 0x%x\n",
			       event_id_str_table_arr[j].ascii_id_len);
			printf("   ASCII ID offset          : 0x%"PRIx64"\n",
			       le64_to_cpu(event_id_str_table_arr[j].ascii_id_ofst));
			printf("   Reserved                 : 0x%x\n",
			       event_id_str_table_arr[j].reserved2);

		}
	}

	if (log_data->vu_eve_st_sz != 0) {
		memcpy(vu_event_id_str_table_arr, (__u8 *)log_data_buf + vu_event_str_table_ofst,
		       (log_data->vu_eve_st_sz * 4));
		printf("  VU Event Identifier String Table Entry\n");
		for (j = 0; j < vu_eve_index; j++) {
			printf("   Debug Event Class        : 0x%x\n",
			       vu_event_id_str_table_arr[j].deb_eve_class);
			printf("   VU Event Identifier      : 0x%x\n",
			       le16_to_cpu(vu_event_id_str_table_arr[j].vu_ei));
			printf("   ASCII ID Length          : 0x%x\n",
			       vu_event_id_str_table_arr[j].ascii_id_len);
			printf("   ASCII ID offset          : 0x%"PRIx64"\n",
			       le64_to_cpu(vu_event_id_str_table_arr[j].ascii_id_ofst));
			printf("   Reserved                 : 0x%x\n",
			       vu_event_id_str_table_arr[j].reserved);
		}
	}

	if (log_data->asctsz != 0) {
		printf("  ASCII Table\n");
		printf("   Byte    Data_Byte    ASCII_Character\n");
		for (j = 0; j < ascii_table_index; j++)
			printf("    %"PRIu64"        %d             %c\n",
			       le64_to_cpu(ascii_table_ofst + j),
			       log_data_buf[ascii_table_ofst + j],
			       (char)log_data_buf[ascii_table_ofst + j]);
	}
}

static void stdout_c7_log(struct nvme_transport_handle *hdl, struct tcg_configuration_log *log_data)
{
	int j;
	__u16 log_page_version = le16_to_cpu(log_data->log_page_version);

	printf("TCG Configuration C7 Log Page Data-\n");

	printf("  State                                                    : 0x%x\n",
		log_data->state);
	printf("  Reserved1                                              : ");
	for (j = 0; j < 3; j++)
		printf("%d", log_data->rsvd1[j]);
	printf("\n");
	printf("  Locking SP Activation Count                              : 0x%x\n",
	       log_data->locking_sp_act_count);
	printf("  Tper Revert Count                                        : 0x%x\n",
	       log_data->type_rev_count);
	printf("  Locking SP Revert Count                                  : 0x%x\n",
	       log_data->locking_sp_rev_count);
	printf("  Number of Locking Objects                                : 0x%x\n",
	       log_data->no_of_locking_obj);
	printf("  Number of Single User Mode Locking Objects               : 0x%x\n",
	       log_data->no_of_single_um_locking_obj);
	printf("  Number of Range Provisioned Locking Objects              : 0x%x\n",
	       log_data->no_of_range_prov_locking_obj);
	printf("  Number of Namespace Provisioned Locking Objects          : 0x%x\n",
	       log_data->no_of_ns_prov_locking_obj);
	printf("  Number of Read Locked Locking Objects                    : 0x%x\n",
	       log_data->no_of_read_lock_locking_obj);
	printf("  Number of Write Locked Locking Objects                   : 0x%x\n",
	       log_data->no_of_write_lock_locking_obj);
	printf("  Number of Read Unlocked Locking Objects                  : 0x%x\n",
	       log_data->no_of_read_unlock_locking_obj);
	printf("  Number of Write Unlocked Locking Objects                 : 0x%x\n",
	       log_data->no_of_write_unlock_locking_obj);
	printf("  Reserved2                                              : %x\n",
		log_data->rsvd15);
	printf("  SID Authentication Try Count                             : 0x%x\n",
	       le32_to_cpu(log_data->sid_auth_try_count));
	printf("  SID Authentication Try Limit                             : 0x%x\n",
	       le32_to_cpu(log_data->sid_auth_try_limit));
	printf("  Programmatic TCG Reset Count                             : 0x%x\n",
	       le32_to_cpu(log_data->pro_tcg_rc));
	printf("  Programmatic Reset Lock Count                            : 0x%x\n",
	       le32_to_cpu(log_data->pro_rlc));
	printf("  TCG Error Count                                          : 0x%x\n",
	       le32_to_cpu(log_data->tcg_ec));

	if (log_page_version == 1) {
		printf("  Reserved3                                                : %d%d",
			*(__u8 *)&log_data->no_of_ns_prov_locking_obj_ext,
			*((__u8 *)&log_data->no_of_ns_prov_locking_obj_ext + 1));
	} else {
		printf("  Number of Namespace Provisioned Locking Objects Extended : 0x%x\n",
			le16_to_cpu(log_data->no_of_ns_prov_locking_obj_ext));
		printf("  Reserved3                                                : ");
	}
	for (j = 0; j < 456; j++)
		printf("%d", log_data->rsvd38[j]);
	printf("\n");

	printf("  Log Page Version                                         : 0x%x\n",
	       log_page_version);
	printf("  Log page GUID                                            : 0x");
	for (j = GUID_LEN - 1; j >= 0; j--)
		printf("%02x", log_data->log_page_guid[j]);
	printf("\n");
}

static struct ocp_print_ops stdout_print_ops = {
	.hwcomp_log = stdout_hwcomp_log,
	.fw_act_history = stdout_fw_activation_history,
	.smart_extended_log = stdout_smart_extended_log,
	.telemetry_log = stdout_telemetry_log,
	.c3_log = stdout_c3_log,
	.c5_log = stdout_c5_log,
	.c1_log = stdout_c1_log,
	.c4_log = stdout_c4_log,
	.c9_log = stdout_c9_log,
	.c7_log = stdout_c7_log,
};

struct ocp_print_ops *ocp_get_stdout_print_ops(nvme_print_flags_t flags)
{
	stdout_print_ops.flags = flags;
	return &stdout_print_ops;
}
