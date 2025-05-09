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

#define OCP_PLUGIN_VERSION   "2.12.0"
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
		ENTRY("set-enable-ieee1667-silo", "enable IEEE1667 silo", set_enable_ieee1667_silo)
		ENTRY("hardware-component-log", "retrieve hardware component log", hwcomp_log)
		ENTRY("get-latency-monitor", "Get Latency Monitor Feature",
		      ocp_get_latency_monitor_feature)
		ENTRY("get-clear-pcie-correctable-errors", "Clear PCIe correctable error counters",
		      get_clear_pcie_correctable_error_counters)
		ENTRY("get-telemetry-profile", "Get Telemetry Profile Feature",
		      ocp_get_telemetry_profile_feature)
	)
);

#endif

#include "define_cmd.h"

#ifndef OCP_NVME_H
#define OCP_NVME_H
#include "common.h"

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
	__u8	rsvd4[0x0A];			/* 0x1AA */

	__u8	latency_monitor_debug_log_size[0x0C]; /* 0x1B4 */
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

#define GUID_LEN 16

#define C3_ACTIVE_BUCKET_TIMER_INCREMENT	5
#define C3_ACTIVE_THRESHOLD_INCREMENT		5
#define C3_MINIMUM_WINDOW_INCREMENT		100
#define C3_BUCKET_NUM				4

#define READ		3
#define WRITE		2
#define TRIM		1

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
	__u8    log_page_guid[GUID_LEN];
};

#define C1_PREV_PANIC_IDS_LENGTH            4

/**
 * struct ocp_error_recovery_log_page -	Error Recovery Log Page
 * @panic_reset_wait_time:		Panic Reset Wait Time
 * @panic_reset_action:			Panic Reset Action
 * @device_recover_action_1:		Device Recovery Action 1
 * @panic_id:				Panic ID
 * @device_capabilities:		Device Capabilities
 * @vendor_specific_recovery_opcode:	Vendor Specific Recovery Opcode
 * @reserved:				Reserved
 * @vendor_specific_command_cdw12:	Vendor Specific Command CDW12
 * @vendor_specific_command_cdw13:	Vendor Specific Command CDW13
 * @vendor_specific_command_timeout:	Vendor Specific Command Timeout
 * @device_recover_action_2:		Device Recovery Action 2
 * @device_recover_action_2_timeout:	Device Recovery Action 2 Timeout
 * @panic_count:			Panic Count
 * @prev_panic_id:			Previous Panic IDs
 * @reserved2:				Reserved
 * @log_page_version:			Log Page Version
 * @log_page_guid:			Log Page GUID
 */
struct __packed ocp_error_recovery_log_page {
	__le16  panic_reset_wait_time;                   /* 2 bytes      - 0x00 - 0x01 */
	__u8    panic_reset_action;                      /* 1 byte       - 0x02 */
	__u8    device_recover_action_1;                 /* 1 byte       - 0x03 */
	__le64  panic_id;                                /* 8 bytes      - 0x04 - 0x0B */
	__le32  device_capabilities;                     /* 4 bytes      - 0x0C - 0x0F */
	__u8    vendor_specific_recovery_opcode;         /* 1 byte       - 0x10 */
	__u8    reserved[0x3];                           /* 3 bytes      - 0x11 - 0x13 */
	__le32  vendor_specific_command_cdw12;           /* 4 bytes      - 0x14 - 0x17 */
	__le32  vendor_specific_command_cdw13;           /* 4 bytes      - 0x18 - 0x1B */
	__u8    vendor_specific_command_timeout;         /* 1 byte       - 0x1C */
	__u8    device_recover_action_2;                 /* 1 byte       - 0x1D */
	__u8    device_recover_action_2_timeout;         /* 1 byte       - 0x1E */
	__u8    panic_count;                             /* 1 byte       - 0x1F */
	__le64  prev_panic_id[C1_PREV_PANIC_IDS_LENGTH]; /* 32 bytes     - 0x20 - 0x3F */
	__u8    reserved2[0x1ae];                        /* 430 bytes    - 0x40 - 0x1ED */
	__le16  log_page_version;                        /* 2 bytes      - 0x1EE - 0x1EF */
	__u8    log_page_guid[GUID_LEN];                 /* 16 bytes     - 0x1F0 - 0x1FF */
};

/**
 * struct ocp_device_capabilities_log_page -	Device Capability Log page
 * @pcie_exp_port:						PCI Express Ports
 * @oob_management_support:				OOB Management Support
 * @wz_cmd_support:						Write Zeroes Command Support
 * @sanitize_cmd_support:				Sanitize Command Support
 * @dsm_cmd_support:					Dataset Management Command Support
 * @wu_cmd_support:						Write Uncorrectable Command Support
 * @fused_operation_support:			Fused Operation Support
 * @min_valid_dssd_pwr_state:			Minimum Valid DSSD Power State
 * @dssd_pwr_state_desc:				DSSD Power State Descriptors
 * @vendor_specific_command_timeout:	Vendor Specific Command Timeout
 * @reserved:							Reserved
 * @log_page_version:					Log Page Version
 * @log_page_guid:						Log Page GUID
 */
struct __packed ocp_device_capabilities_log_page {
	__le16  pcie_exp_port;
	__le16  oob_management_support;
	__le16  wz_cmd_support;
	__le16  sanitize_cmd_support;
	__le16  dsm_cmd_support;
	__le16  wu_cmd_support;
	__le16  fused_operation_support;
	__le16  min_valid_dssd_pwr_state;
	__u8    dssd_pwr_state_desc[128];
	__u8    reserved[3934];
	__le16  log_page_version;
	__u8    log_page_guid[GUID_LEN];
};

/*
 * struct tcg_configuration_log - TCG Configuration Log Page Structure
 * @state:                            state
 * @rsvd1:                            Reserved
 * @locking_sp_act_count:             Locking SP Activation Count
 * @type_rev_count:                   Tper Revert Count
 * @locking_sp_rev_count:             Locking SP Revert Count.
 * @no_of_locking_obj:                Number of Locking Objects
 * @no_of_single_um_locking_obj:      Number of Single User Mode Locking Objects
 * @no_of_range_prov_locking_obj:     Number of Range Provisioned Locking Objects
 * @no_of_ns_prov_locking_obj:        Number of Namespace Provisioned Locking Objects
 * @no_of_read_lock_locking_obj:      Number of Read Locked Locking Objects
 * @no_of_write_lock_locking_obj:     Number of Write Locked Locking Objects
 * @no_of_read_unlock_locking_obj:    Number of Read Unlocked Locking Objects
 * @no_of_read_unlock_locking_obj:    Number of Write Unlocked Locking Objects
 * @rsvd15:                           Reserved
 * @sid_auth_try_count:               SID Authentication Try Count
 * @sid_auth_try_limit:               SID Authentication Try Limit
 * @pro_tcg_rc:                       Programmatic TCG Reset Count
 * @pro_rlc:                          Programmatic Reset Lock Count
 * @tcg_ec:                           TCG Error Count
 * @no_of_ns_prov_locking_obj_ext:    Number of Namespace Provisioned Locking Objects Extended
 * @rsvd38:                           Reserved
 * @log_page_version:                 Log Page Version
 */
struct __packed tcg_configuration_log {
	__u8    state;
	__u8    rsvd1[3];
	__u8    locking_sp_act_count;
	__u8    type_rev_count;
	__u8    locking_sp_rev_count;
	__u8    no_of_locking_obj;
	__u8    no_of_single_um_locking_obj;
	__u8    no_of_range_prov_locking_obj;
	__u8    no_of_ns_prov_locking_obj;
	__u8    no_of_read_lock_locking_obj;
	__u8    no_of_write_lock_locking_obj;
	__u8    no_of_read_unlock_locking_obj;
	__u8    no_of_write_unlock_locking_obj;
	__u8    rsvd15;
	__le32  sid_auth_try_count;
	__le32  sid_auth_try_limit;
	__le32  pro_tcg_rc;
	__le32  pro_rlc;
	__le32  tcg_ec;
	__le16  no_of_ns_prov_locking_obj_ext;
	__u8    rsvd38[456];
	__le16  log_page_version;
	__u8    log_page_guid[GUID_LEN];

};

enum ocp_dssd_log_id {
	OCP_LID_SMART = 0xc0, /* SMART / Helth Information Extended */
	OCP_LID_EREC, /* Error Recovery */
	OCP_LID_FAHL_OBSOLETE, /* Firmware Activation History (Obsolete) */
	OCP_LID_LMLOG, /* Latency Monitor */
	OCP_LID_DCLP, /* Device Capabilities */
	OCP_LID_URLP, /* Unsupported Requirements */
	OCP_LID_HWCOMP, /* Hardware Component */
	OCP_LID_TCGL, /* TCG Configuration */
	OCP_LID_RESERVED, /* Reserved for future use */
	OCP_LID_TELSLG, /* Telemetry String */
	OCP_LID_LMLOG_DEBUG, /* Latency Monitor Debug Telemetry */
};

enum ocp_dssd_feature_id {
	OCP_FID_ERRI = 0xc0, /* Error Injection */
	OCP_FID_CFUH, /* Clear Firmware Update History (Obsolete) */
	OCP_FID_ROWTM, /* EOL/PLP Failure Mode */
	OCP_FID_CPCIE, /* Clear PCIe Correctable Error Counters */
	OCP_FID_1667, /* Enable IEEE1667 Silo */
	OCP_FID_LM, /* Latency Monitor */
	OCP_FID_PLPI, /* PLP Health Check Interval */
	OCP_FID_DSSDPS, /* DSSD Power State */
	OCP_FID_TEL_CFG, /* Telemetry Profile */
	OCP_FID_DAEC, /* DSSD Asynchronous Event Configuration */
};
#endif /* OCP_NVME_H */
