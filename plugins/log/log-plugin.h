/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file is part of nvme-cli.
 *
 * Copyright (c) 2014-2015, Intel Corporation.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Keith Busch <kbusch@kernel.org>
 *          Daniel Wagner <dwagner@suse.com>
 */

#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/log/log-plugin

#if !defined(LOG_PLUGIN) || defined(CMD_HEADER_MULTI_READ)
#define LOG_PLUGIN

#include "cmd.h"

PLUGIN(NAME("log", "Retrieve and show NVMe log pages", NVME_VERSION),
	COMMAND_LIST(
		ENTRY("smart", "Retrieve SMART Log, show it", get_smart_log)
		ENTRY("ana", "Retrieve ANA Log, show it", get_ana_log)
		ENTRY("telemetry", "Retrieve FW Telemetry log write to file", get_telemetry_log)
		ENTRY("fw", "Retrieve FW Log, show it", get_fw_log)
		ENTRY("endurance", "Retrieve Endurance Group Log, show it", get_endurance_log)
		ENTRY("effects", "Retrieve Command Effects Log, show it", get_effects_log)
		ENTRY("error", "Retrieve Error Log, show it", get_error_log)
		ENTRY("changed-ns-list", "Retrieve Changed Attached Namespace List, show it",
		      get_changed_attach_ns_list_log)
		ENTRY("changed-alloc-ns-list", "Retrieve Changed Allocated Namespace List, show it",
		      get_changed_alloc_ns_list_log)
		ENTRY("predictable-lat", "Retrieve Predictable Latency per Nvmset Log, show it",
		      get_pred_lat_per_nvmset_log)
		ENTRY("pred-lat-event-agg", "Retrieve Predictable Latency Event Aggregate Log, show it",
		      get_pred_lat_event_agg_log)
		ENTRY("persistent-event", "Retrieve Persistent Event Log, show it", get_persistent_event_log)
		ENTRY("endurance-event-agg", "Retrieve Endurance Group Event Aggregate Log, show it",
		      get_endurance_event_agg_log)
		ENTRY("lba-status", "Retrieve LBA Status Information Log, show it", get_lba_status_log)
		ENTRY("resv-notif", "Retrieve Reservation Notification Log, show it", get_resv_notif_log)
		ENTRY("boot-part", "Retrieve Boot Partition Log, show it", get_boot_part_log)
		ENTRY("phy-rx-eom", "Retrieve Physical Interface Receiver Eye Opening Measurement, show it",
		      get_phy_rx_eom_log)
		ENTRY("self-test", "Retrieve the SELF-TEST Log, show it", self_test_log)
		ENTRY("fid-support-effects", "Retrieve FID Support and Effects log and show it",
		      get_fid_support_effects_log)
		ENTRY("mi-cmd-support-effects", "Retrieve MI Command Support and Effects log and show it",
		      get_mi_cmd_support_effects_log)
		ENTRY("media-unit-stat", "Retrieve the configuration and wear of media units, show it",
		      get_media_unit_stat_log)
		ENTRY("supported-cap-config", "Retrieve the list of Supported Capacity Configuration Descriptors",
		      get_supp_cap_config_log)
		ENTRY("mgmt-addr-list", "Retrieve Management Address List Log, show it", get_mgmt_addr_list_log)
		ENTRY("rotational-media-info", "Retrieve Rotational Media Information Log, show it",
		      get_rotational_media_info_log)
		ENTRY("dispersed-ns-participating-nss",
		      "Retrieve Dispersed Namespace Participating NVM Subsystems Log, show it",
		      get_dispersed_ns_participating_nss_log)
		ENTRY("reachability-groups", "Retrieve Reachability Groups Log, show it",
		      get_reachability_groups_log)
		ENTRY("reachability-associations", "Retrieve Reachability Associations Log, show it",
		      get_reachability_associations_log)
		ENTRY("host-discovery", "Retrieve Host Discovery Log, show it", get_host_discovery_log)
		ENTRY("ave-discovery", "Retrieve AVE Discovery Log, show it", get_ave_discovery_log)
		ENTRY("pull-model-ddc-req", "Retrieve Pull Model DDC Request Log, show it",
		      get_pull_model_ddc_req_log)
		ENTRY("power-measurement", "Retrieve Power Measurement Log, show it", get_power_measurement_log)
		ENTRY("sanitize", "Retrieve sanitize log, show it", sanitize_log)
	)
);

#endif

#include "define_cmd.h"
