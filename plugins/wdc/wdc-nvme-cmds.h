/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2025 Western Digital Corporation or its affiliates.
 *
 *   Author: Jeff Lien <jeff.lien@wdc.com>,
 */

int run_wdc_cloud_ssd_plugin_version(int argc, char **argv,
		struct command *command,
		struct plugin *plugin);

int run_wdc_vs_internal_fw_log(int argc, char **argv,
		struct command *command,
		struct plugin *plugin);

int run_wdc_vs_nand_stats(int argc, char **argv,
		struct command *command,
		struct plugin *plugin);

int run_wdc_vs_smart_add_log(int argc, char **argv,
		struct command *command,
		struct plugin *plugin);

int run_wdc_clear_pcie_correctable_errors(int argc, char **argv,
		struct command *command,
		struct plugin *plugin);

int run_wdc_drive_status(int argc, char **argv,
		struct command *command,
		struct plugin *plugin);

int run_wdc_clear_assert_dump(int argc, char **argv,
		struct command *command,
		struct plugin *plugin);

int run_wdc_drive_resize(int argc, char **argv,
		struct command *command,
		struct plugin *plugin);

int run_wdc_vs_fw_activate_history(int argc, char **argv,
		struct command *command,
		struct plugin *plugin);

int run_wdc_clear_fw_activate_history(int argc, char **argv,
		struct command *command,
		struct plugin *plugin);

int run_wdc_vs_telemetry_controller_option(int argc, char **argv,
		struct command *command,
		struct plugin *plugin);

int run_wdc_reason_identifier(int argc, char **argv,
		struct command *command,
		struct plugin *plugin);

int run_wdc_log_page_directory(int argc, char **argv,
		struct command *command,
		struct plugin *plugin);

int run_wdc_namespace_resize(int argc, char **argv,
		struct command *command,
		struct plugin *plugin);

int run_wdc_vs_drive_info(int argc, char **argv,
		struct command *command,
		struct plugin *plugin);

int run_wdc_cloud_ssd_plugin_version(int argc, char **argv,
		struct command *command,
		struct plugin *plugin);

int run_wdc_vs_pcie_stats(int argc, char **argv,
		struct command *command,
		struct plugin *plugin);

int run_wdc_get_latency_monitor_log(int argc, char **argv,
		struct command *command,
		struct plugin *plugin);

int run_wdc_get_error_recovery_log(int argc, char **argv,
		struct command *command,
		struct plugin *plugin);

int run_wdc_get_dev_capabilities_log(int argc, char **argv,
		struct command *command,
		struct plugin *plugin);

int run_wdc_get_unsupported_reqs_log(int argc, char **argv,
		struct command *command,
		struct plugin *plugin);

int run_wdc_cloud_boot_SSD_version(int argc, char **argv,
		struct command *command,
		struct plugin *plugin);

int run_wdc_vs_cloud_log(int argc, char **argv,
		struct command *command,
		struct plugin *plugin);

int run_wdc_vs_hw_rev_log(int argc, char **argv,
		struct command *command,
		struct plugin *plugin);

int run_wdc_vs_device_waf(int argc, char **argv,
		struct command *command,
		struct plugin *plugin);

int run_wdc_set_latency_monitor_feature(int argc, char **argv,
		struct command *cmd,
		struct plugin *plugin);

int run_wdc_vs_temperature_stats(int argc, char **argv,
		struct command *command,
		struct plugin *plugin);

int run_wdc_cu_smart_log(int argc, char **argv,
		struct command *command,
		struct plugin *plugin);

bool run_wdc_nvme_check_supported_log_page(nvme_root_t r,
		struct nvme_dev *dev,
		__u8 log_id);

__u32 run_wdc_get_fw_cust_id(nvme_root_t r,
		struct nvme_dev *dev);

__u64 run_wdc_get_drive_capabilities(nvme_root_t r, struct nvme_dev *dev);
