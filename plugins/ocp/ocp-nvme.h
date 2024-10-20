/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (c) 2022 Meta Platforms, Inc.
 *
 * Authors: Arthur Shau <arthurshau@fb.com>,
 *          Wei Zhang <wzhang@fb.com>,
 *          Venkat Ramesh <venkatraghavan@fb.com>
 */
#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/ocp/ocp-nvme

#if !defined(OCP_NVME) || defined(CMD_HEADER_MULTI_READ)
#define OCP_NVME

#define OCP_PLUGIN_VERSION   "2.9.2"
#include "cmd.h"

PLUGIN(NAME("ocp", "OCP cloud SSD extensions", OCP_PLUGIN_VERSION),
	COMMAND_LIST(
		ENTRY("smart-add-log", "Retrieve extended SMART Information", smart_add_log)
		ENTRY("latency-monitor-log", "Get Latency Monitor Log Page", ocp_latency_monitor_log)
		ENTRY("set-latency-monitor-feature", "Set Latency Monitor feature", ocp_set_latency_monitor_feature)
		ENTRY("internal-log", "Retrieve and save internal device telemetry log", ocp_telemetry_log)
		ENTRY("clear-fw-activate-history", "Clear firmware update history log", clear_fw_update_history)
		ENTRY("eol-plp-failure-mode", "Define EOL or PLP circuitry failure mode.", eol_plp_failure_mode)
		ENTRY("clear-pcie-correctable-errors", "Clear PCIe correctable error counters", clear_pcie_correctable_error_counters)
		ENTRY("fw-activate-history", "Get firmware activation history log", fw_activation_history_log)
		ENTRY("unsupported-reqs-log", "Get Unsupported Requirements Log Page", ocp_unsupported_requirements_log)
		ENTRY("error-recovery-log", "Retrieve Error Recovery Log Page", ocp_error_recovery_log)
		ENTRY("device-capability-log", "Get Device capabilities Requirements Log Page", ocp_device_capabilities_log)
		ENTRY("set-dssd-power-state-feature", "Set DSSD Power State feature", set_dssd_power_state_feature)
		ENTRY("get-dssd-power-state-feature", "Get DSSD Power State feature", get_dssd_power_state_feature)
		ENTRY("set-plp-health-check-interval", "Set PLP Health Check Interval", set_plp_health_check_interval)
		ENTRY("get-plp-health-check-interval", "Get PLP Health Check Interval", get_plp_health_check_interval)
		ENTRY("telemetry-string-log", "Retrieve Telemetry string Log Page", ocp_telemetry_str_log_format)
		ENTRY("set-telemetry-profile", "Set Telemetry Profile Feature", ocp_set_telemetry_profile_feature)
		ENTRY("set-dssd-async-event-config", "Set DSSD Async Event Config", set_dssd_async_event_config)
		ENTRY("get-dssd-async-event-config", "Get DSSD Async Event Config", get_dssd_async_event_config)
		ENTRY("tcg-configuration-log", "Retrieve TCG Configuration Log Page", ocp_tcg_configuration_log)
		ENTRY("get-error-injection", "Return set of error injection", get_error_injection)
		ENTRY("set-error-injection", "Inject error conditions", set_error_injection)
		ENTRY("get-enable-ieee1667-silo", "return set of enable IEEE1667 silo",
		      get_enable_ieee1667_silo)
		ENTRY("hardware-component-log", "retrieve hardware component log", hwcomp_log)
	)
);

#endif

#include "define_cmd.h"

#ifndef OCP_NVME_H
#define OCP_NVME_H
struct __packed ssd_latency_monitor_log {
	__u8	feature_status;			/* 0x00 */
	__u8	rsvd1;				/* 0x01 */
	__le16	active_bucket_timer;		/* 0x02 */
	__le16	active_bucket_timer_threshold;	/* 0x04 */
	__u8	active_threshold_a;		/* 0x06 */
	__u8	active_threshold_b;		/* 0x07 */
	__u8	active_threshold_c;		/* 0x08 */
	__u8	active_threshold_d;		/* 0x09 */
	__le16	active_latency_config;		/* 0x0A */
	__u8	active_latency_min_window;	/* 0x0C */
	__u8	rsvd2[0x13];			/* 0x0D */

	__le32	active_bucket_counter[4][4];	/* 0x20 - 0x5F */
	__le64	active_latency_timestamp[4][3];	/* 0x60 - 0xBF */
	__le16	active_measured_latency[4][3];	/* 0xC0 - 0xD7 */
	__le16	active_latency_stamp_units;	/* 0xD8 */
	__u8	rsvd3[0x16];			/* 0xDA */

	__le32	static_bucket_counter[4][4];	/* 0x0F0 - 0x12F */
	__le64	static_latency_timestamp[4][3];	/* 0x130 - 0x18F */
	__le16	static_measured_latency[4][3];	/* 0x190 - 0x1A7 */
	__le16	static_latency_stamp_units;	/* 0x1A8 */
	__u8	rsvd4[0x16];			/* 0x1AA */

	__le16	debug_log_trigger_enable;	/* 0x1C0 */
	__le16	debug_log_measured_latency;	/* 0x1C2 */
	__le64	debug_log_latency_stamp;	/* 0x1C4 */
	__le16	debug_log_ptr;			/* 0x1CC */
	__le16	debug_log_counter_trigger;	/* 0x1CE */
	__u8	debug_log_stamp_units;		/* 0x1D0 */
	__u8	rsvd5[0x1D];			/* 0x1D1 */

	__le16	log_page_version;		/* 0x1EE */
	__u8	log_page_guid[0x10];		/* 0x1F0 */
};

#define C3_GUID_LENGTH				16

#define C3_ACTIVE_BUCKET_TIMER_INCREMENT	5
#define C3_ACTIVE_THRESHOLD_INCREMENT		5
#define C3_MINIMUM_WINDOW_INCREMENT		100
#define C3_BUCKET_NUM				4

#define READ		3
#define WRITE		2
#define TRIM		1

#define C5_GUID_LENGTH                     16
#define C5_NUM_UNSUPPORTED_REQ_ENTRIES     253

/*
 * struct unsupported_requirement_log - unsupported requirement list
 * @unsupported_count:        Number of Unsupported Requirement IDs
 * @rsvd1:                    Reserved
 * @unsupported_req_list:     Unsupported Requirements lists up to 253.
 * @rsvd2:                    Reserved
 * @log_page_version:         indicates the version of the mapping this log page uses.
 *                            Shall be set to 0001h
 * @log_page_guid:            Shall be set to C7BB98B7D0324863BB2C23990E9C722Fh.
 */
struct __packed unsupported_requirement_log {
	__le16  unsupported_count;
	__u8    rsvd1[14];
	__u8    unsupported_req_list[C5_NUM_UNSUPPORTED_REQ_ENTRIES][16];
	__u8    rsvd2[14];
	__le16  log_page_version;
	__u8    log_page_guid[C5_GUID_LENGTH];
};
#endif /* OCP_NVME_H */
