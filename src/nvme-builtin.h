/* SPDX-License-Identifier: GPL-2.0-or-later */
#undef CMD_INC_FILE
#define CMD_INC_FILE nvme-builtin

#if !defined(NVME_BUILTIN) || defined(CMD_HEADER_MULTI_READ)
#define NVME_BUILTIN

#include "cmd.h"

COMMAND_LIST(
	ENTRY("list", "List all NVMe devices and namespaces on machine", list)
	ENTRY("list-subsys", "List nvme subsystems", list_subsys)
#ifdef CONFIG_DEPRECATED_CMDS
	ENTRY_DEPRECATED("id-ctrl", "Send NVMe Identify Controller (deprecated, use 'nvme id ctrl')", id_ctrl)
	ENTRY_DEPRECATED("id-ns", "Send NVMe Identify Namespace, display structure (deprecated, use 'nvme id ns')", id_ns)
	ENTRY_DEPRECATED("id-ns-granularity", "Send NVMe Identify Namespace Granularity List, display structure (deprecated, use 'nvme id ns-granularity')", id_ns_granularity)
	ENTRY_DEPRECATED("id-ns-lba-format", "Send NVMe Identify Namespace for the specified LBA Format index, display structure (deprecated, use 'nvme id ns-lba-format')", id_ns_lba_format)
	ENTRY_DEPRECATED("list-ns", "Send NVMe Identify List, display structure (deprecated, use 'nvme id ns-list')", list_ns)
	ENTRY_DEPRECATED("list-ctrl", "Send NVMe Identify Controller List, display structure (deprecated, use 'nvme id ctrl-list')", list_ctrl)
	ENTRY_DEPRECATED("nvm-id-ctrl", "Send NVMe Identify Controller NVM Command Set, display structure (deprecated, use 'nvme id nvm-ctrl')", nvm_id_ctrl)
	ENTRY_DEPRECATED("nvm-id-ns", "Send NVMe Identify Namespace NVM Command Set, display structure (deprecated, use 'nvme id nvm-ns')", nvm_id_ns)
	ENTRY_DEPRECATED("nvm-id-ns-lba-format", "Send NVMe Identify Namespace NVM Command Set for the specified LBA Format index, display structure (deprecated, use 'nvme id nvm-ns-lba-format')", nvm_id_ns_lba_format)
	ENTRY_DEPRECATED("primary-ctrl-caps", "Send NVMe Identify Primary Controller Capabilities (deprecated, use 'nvme id primary-ctrl-caps')", primary_ctrl_caps)
	ENTRY_DEPRECATED("list-secondary", "List Secondary Controllers associated with a Primary Controller (deprecated, use 'nvme id secondary-ctrl-list')", list_secondary_ctrl)
	ENTRY_DEPRECATED("cmdset-ind-id-ns", "I/O Command Set Independent Identify Namespace (deprecated, use 'nvme id ns-ind')", cmd_set_independent_id_ns)
	ENTRY_DEPRECATED("ns-descs", "Send NVMe Namespace Descriptor List, display structure (deprecated, use 'nvme id ns-descs')", ns_descs)
	ENTRY_DEPRECATED("id-nvmset", "Send NVMe Identify NVM Set List, display structure (deprecated, use 'nvme id nvmset')", id_nvmset)
	ENTRY_DEPRECATED("id-uuid", "Send NVMe Identify UUID List, display structure (deprecated, use 'nvme id uuid')", id_uuid)
	ENTRY_DEPRECATED("id-iocs", "Send NVMe Identify I/O Command Set, display structure (deprecated, use 'nvme id iocs')", id_iocs)
	ENTRY_DEPRECATED("id-domain", "Send NVMe Identify Domain List, display structure (deprecated, use 'nvme id domain')", id_domain)
	ENTRY_DEPRECATED("list-endgrp", "Send NVMe Identify Endurance Group List, display structure (deprecated, use 'nvme id endgrp-list')", id_endurance_grp_list)
	ENTRY_DEPRECATED("create-ns", "Creates a namespace with the provided parameters (deprecated, use 'nvme ns create')", create_ns)
	ENTRY_DEPRECATED("delete-ns", "Deletes a namespace from the controller (deprecated, use 'nvme ns delete')", delete_ns)
	ENTRY_DEPRECATED("attach-ns", "Attaches a namespace to requested controller(s) (deprecated, use 'nvme ns attach')", attach_ns)
	ENTRY_DEPRECATED("detach-ns", "Detaches a namespace from requested controller(s) (deprecated, use 'nvme ns detach')", detach_ns)
	ENTRY_DEPRECATED("get-ns-id", "Retrieve the namespace ID of opened block device (deprecated, use 'nvme ns get-id')", get_ns_id)
#endif /* CONFIG_DEPRECATED_CMDS */
	ENTRY("get-log", "Generic NVMe get log, returns log in raw format", get_log)
#ifdef CONFIG_DEPRECATED_CMDS
	ENTRY_DEPRECATED("telemetry-log", "Retrieve FW Telemetry log write to file (deprecated, use 'nvme log telemetry')", get_telemetry_log)
	ENTRY_DEPRECATED("fw-log", "Retrieve FW Log, show it (deprecated, use 'nvme log fw')", get_fw_log)
	ENTRY_DEPRECATED("changed-ns-list-log", "Retrieve Changed Attached Namespace List, show it (deprecated, use 'nvme log changed-ns-list')", get_changed_attach_ns_list_log)
	ENTRY_DEPRECATED("smart-log", "Retrieve SMART Log, show it (deprecated, use 'nvme log smart')", get_smart_log)
	ENTRY_DEPRECATED("ana-log", "Retrieve ANA Log, show it (deprecated, use 'nvme log ana')", get_ana_log)
	ENTRY_DEPRECATED("error-log", "Retrieve Error Log, show it (deprecated, use 'nvme log error')", get_error_log)
	ENTRY_DEPRECATED("effects-log", "Retrieve Command Effects Log, show it (deprecated, use 'nvme log effects')", get_effects_log)
	ENTRY_DEPRECATED("endurance-log", "Retrieve Endurance Group Log, show it (deprecated, use 'nvme log endurance')", get_endurance_log)
	ENTRY_DEPRECATED("predictable-lat-log", "Retrieve Predictable Latency per Nvmset Log, show it (deprecated, use 'nvme log predictable-lat')", get_pred_lat_per_nvmset_log)
	ENTRY_DEPRECATED("pred-lat-event-agg-log", "Retrieve Predictable Latency Event Aggregate Log, show it (deprecated, use 'nvme log pred-lat-event-agg')", get_pred_lat_event_agg_log)
	ENTRY_DEPRECATED("persistent-event-log", "Retrieve Persistent Event Log, show it (deprecated, use 'nvme log persistent-event')", get_persistent_event_log)
	ENTRY_DEPRECATED("endurance-event-agg-log", "Retrieve Endurance Group Event Aggregate Log, show it (deprecated, use 'nvme log endurance-event-agg')", get_endurance_event_agg_log)
	ENTRY_DEPRECATED("lba-status-log", "Retrieve LBA Status Information Log, show it (deprecated, use 'nvme log lba-status')", get_lba_status_log)
	ENTRY_DEPRECATED("resv-notif-log", "Retrieve Reservation Notification Log, show it (deprecated, use 'nvme log resv-notif')", get_resv_notif_log)
	ENTRY_DEPRECATED("boot-part-log", "Retrieve Boot Partition Log, show it (deprecated, use 'nvme log boot-part')", get_boot_part_log)
	ENTRY_DEPRECATED("phy-rx-eom-log", "Retrieve Physical Interface Receiver Eye Opening Measurement, show it (deprecated, use 'nvme log phy-rx-eom')", get_phy_rx_eom_log)
#endif /* CONFIG_DEPRECATED_CMDS */
	ENTRY("get-feature", "Get feature and show the resulting value", get_feature)
	ENTRY("device-self-test", "Perform the necessary tests to observe the performance", device_self_test)
#ifdef CONFIG_DEPRECATED_CMDS
	ENTRY_DEPRECATED("self-test-log", "Retrieve the SELF-TEST Log, show it (deprecated, use 'nvme log self-test')", self_test_log)
#endif /* CONFIG_DEPRECATED_CMDS */
	ENTRY("supported-log-pages", "Retrieve the Supported Log pages details, show it", get_supported_log_pages)
#ifdef CONFIG_DEPRECATED_CMDS
	ENTRY_DEPRECATED("fid-support-effects-log", "Retrieve FID Support and Effects log and show it (deprecated, use 'nvme log fid-support-effects')", get_fid_support_effects_log)
	ENTRY_DEPRECATED("mi-cmd-support-effects-log", "Retrieve MI Command Support and Effects log and show it (deprecated, use 'nvme log mi-cmd-support-effects')", get_mi_cmd_support_effects_log)
	ENTRY_DEPRECATED("media-unit-stat-log", "Retrieve the configuration and wear of media units, show it (deprecated, use 'nvme log media-unit-stat')", get_media_unit_stat_log)
	ENTRY_DEPRECATED("supported-cap-config-log", "Retrieve the list of Supported Capacity Configuration Descriptors (deprecated, use 'nvme log supported-cap-config')", get_supp_cap_config_log)
	ENTRY_DEPRECATED("mgmt-addr-list-log", "Retrieve Management Address List Log, show it (deprecated, use 'nvme log mgmt-addr-list')", get_mgmt_addr_list_log)
	ENTRY_DEPRECATED("rotational-media-info-log", "Retrieve Rotational Media Information Log, show it (deprecated, use 'nvme log rotational-media-info')", get_rotational_media_info_log)
	ENTRY_DEPRECATED("changed-alloc-ns-list-log", "Retrieve Changed Allocated Namespace List, show it (deprecated, use 'nvme log changed-alloc-ns-list')", get_changed_alloc_ns_list_log)
	ENTRY_DEPRECATED("dispersed-ns-participating-nss-log", "Retrieve Dispersed Namespace Participating NVM Subsystems Log, show it (deprecated, use 'nvme log dispersed-ns-participating-nss')", get_dispersed_ns_participating_nss_log)
	ENTRY_DEPRECATED("reachability-groups-log", "Retrieve Reachability Groups Log, show it (deprecated, use 'nvme log reachability-groups')", get_reachability_groups_log)
	ENTRY_DEPRECATED("reachability-associations-log", "Retrieve Reachability Associations Log, show it (deprecated, use 'nvme log reachability-associations')", get_reachability_associations_log)
	ENTRY_DEPRECATED("host-discovery-log", "Retrieve Host Discovery Log, show it (deprecated, use 'nvme log host-discovery')", get_host_discovery_log)
	ENTRY_DEPRECATED("ave-discovery-log", "Retrieve AVE Discovery Log, show it (deprecated, use 'nvme log ave-discovery')", get_ave_discovery_log)
	ENTRY_DEPRECATED("pull-model-ddc-req-log", "Retrieve Pull Model DDC Request Log, show it (deprecated, use 'nvme log pull-model-ddc-req')", get_pull_model_ddc_req_log)
	ENTRY_DEPRECATED("power-measurement-log", "Retrieve Power Measurement Log, show it (deprecated, use 'nvme log power-measurement')", get_power_measurement_log)
#endif /* CONFIG_DEPRECATED_CMDS */
	ENTRY("set-feature", "Set a feature and show the resulting value", set_feature)
	ENTRY("set-property", "Set a property and show the resulting value", set_property)
	ENTRY("get-property", "Get a property and show the resulting value", get_property)
	ENTRY("format", "Format namespace with new block format", format_cmd)
	ENTRY("fw-commit", "Verify and commit firmware to a specific slot (fw-activate in old version < 1.2)", fw_commit, "fw-activate")
	ENTRY("fw-download", "Download new firmware", fw_download)
	ENTRY("admin-passthru", "Submit an arbitrary admin command, return results", admin_passthru)
	ENTRY("io-passthru", "Submit an arbitrary IO command, return results", io_passthru)
	ENTRY("security-send", "Submit a Security Send command, return results", sec_send)
	ENTRY("security-recv", "Submit a Security Receive command, return results", sec_recv)
	ENTRY("get-lba-status", "Submit a Get LBA Status command, return results", get_lba_status)
	ENTRY("capacity-mgmt", "Submit Capacity Management Command, return results", capacity_mgmt)
#ifdef CONFIG_DEPRECATED_CMDS
	ENTRY_DEPRECATED("resv-acquire", "Submit a Reservation Acquire, return results (deprecated, use 'nvme resv acquire')", resv_acquire)
	ENTRY_DEPRECATED("resv-register", "Submit a Reservation Register, return results (deprecated, use 'nvme resv register')", resv_register)
	ENTRY_DEPRECATED("resv-release", "Submit a Reservation Release, return results (deprecated, use 'nvme resv release')", resv_release)
	ENTRY_DEPRECATED("resv-report", "Submit a Reservation Report, return results (deprecated, use 'nvme resv report')", resv_report)
#endif /* CONFIG_DEPRECATED_CMDS */
	ENTRY("dsm", "Submit a Data Set Management command, return results", dsm)
	ENTRY("copy", "Submit a Simple Copy command, return results", copy_cmd)
	ENTRY("flush", "Submit a Flush command, return results", flush_cmd)
	ENTRY("compare", "Submit a Compare command, return results", compare)
	ENTRY("read", "Submit a read command, return results", read_cmd)
	ENTRY("write", "Submit a write command, return results", write_cmd)
	ENTRY("write-zeroes", "Submit a write zeroes command, return results", write_zeroes)
	ENTRY("write-uncor", "Submit a write uncorrectable command, return results", write_uncor)
	ENTRY("verify", "Submit a verify command, return results", verify_cmd)
	ENTRY("sanitize", "Submit a sanitize command", sanitize_cmd)
#ifdef CONFIG_DEPRECATED_CMDS
	ENTRY_DEPRECATED("sanitize-log", "Retrieve sanitize log, show it (deprecated, use 'nvme log sanitize')", sanitize_log)
#endif /* CONFIG_DEPRECATED_CMDS */
	ENTRY("sanitize-ns", "Submit a sanitize namespace command",
	      sanitize_ns_cmd)
	ENTRY("reset", "Resets the controller", reset)
	ENTRY("subsystem-reset", "Resets the subsystem", subsystem_reset)
	ENTRY("ns-rescan", "Rescans the NVME namespaces", ns_rescan)
	ENTRY("show-regs", "Shows the controller registers or properties. Requires character device", show_registers)
	ENTRY("set-reg", "Set a register and show the resulting value", set_register)
	ENTRY("get-reg", "Get a register and show the resulting value", get_register)
#ifdef CONFIG_TOP
	ENTRY("top", "nvme top", top)
#endif /* CONFIG_TOP */
#ifdef CONFIG_FABRICS
	ENTRY("discover", "Discover NVMeoF subsystems", discover_cmd)
	ENTRY("connect-all", "Discover and Connect to NVMeoF subsystems", connect_all_cmd)
	ENTRY("connect", "Connect to NVMeoF subsystem", connect_cmd)
	ENTRY("disconnect", "Disconnect from NVMeoF subsystem", disconnect_cmd)
	ENTRY("disconnect-all", "Disconnect from all connected NVMeoF subsystems", disconnect_all_cmd)
	ENTRY("dim", "Send Discovery Information Management command to a Discovery Controller", dim_cmd)
	ENTRY("gen-hostnqn", "Generate NVMeoF host NQN", gen_hostnqn_cmd)
	ENTRY("show-hostnqn", "Show NVMeoF host NQN", show_hostnqn_cmd)
#ifdef CONFIG_DEPRECATED_CMDS
	ENTRY_DEPRECATED("gen-dhchap-key", "Generate NVMeoF DH-HMAC-CHAP host secret (deprecated, use 'nvme keys gen-kxchap-secret')", gen_dhchap_key)
	ENTRY_DEPRECATED("check-dhchap-key", "Validate NVMeoF DH-HMAC-CHAP host secret (deprecated, use 'nvme keys check-kxchap-secret')", check_dhchap_key)
	ENTRY_DEPRECATED("gen-tls-key", "Generate NVMeoF TLS PSK (deprecated, use 'nvme keys gen-tls')", gen_tls_key)
	ENTRY_DEPRECATED("check-tls-key", "Validate NVMeoF TLS PSK (deprecated, use 'nvme keys check-tls')", check_tls_key)
	ENTRY_DEPRECATED("tls-key", "Manage NVMeoF TLS PSKs (deprecated, use 'nvme keys import/export/revoke')", tls_key)
#endif /* CONFIG_DEPRECATED_CMDS */
#endif /* CONFIG_FABRICS */
#ifdef CONFIG_DEPRECATED_CMDS
	ENTRY_DEPRECATED("dir-receive", "Submit a Directive Receive command, return results (deprecated, use 'nvme dir receive')", dir_receive)
	ENTRY_DEPRECATED("dir-send", "Submit a Directive Send command, return results (deprecated, use 'nvme dir send')", dir_send)
#endif /* CONFIG_DEPRECATED_CMDS */
	ENTRY("virt-mgmt", "Manage Flexible Resources between Primary and Secondary Controller", virtual_mgmt)
	ENTRY("rpmb", "Replay Protection Memory Block commands", rpmb_cmd)
	ENTRY("lockdown", "Submit a Lockdown command,return result", lockdown_cmd)
	ENTRY("show-topology", "Show the topology", show_topology_cmd)
	ENTRY("io-mgmt-recv", "I/O Management Receive", io_mgmt_recv)
	ENTRY("io-mgmt-send", "I/O Management Send", io_mgmt_send)
#ifdef CONFIG_DEPRECATED_CMDS
	ENTRY_DEPRECATED("nvme-mi-recv", "Submit a NVMe-MI Receive command, return results (deprecated, use 'nvme nvme-mi recv')", nmi_recv)
	ENTRY_DEPRECATED("nvme-mi-send", "Submit a NVMe-MI Send command, return results (deprecated, use 'nvme nvme-mi send')", nmi_send)
#endif /* CONFIG_DEPRECATED_CMDS */
);

#endif

#include "define_cmd.h"
