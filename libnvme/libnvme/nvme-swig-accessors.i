/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * This file is part of libnvme.
 *
 * Copyright (c) 2026, Dell Technologies Inc. or its subsidiaries.
 * Authors: Martin Belanger <Martin.Belanger@dell.com>
 *
 *   ____                           _           _    ____          _
 *  / ___| ___ _ __   ___ _ __ __ _| |_ ___  __| |  / ___|___   __| | ___
 * | |  _ / _ \ '_ \ / _ \ '__/ _` | __/ _ \/ _` | | |   / _ \ / _` |/ _ \
 * | |_| |  __/ | | |  __/ | | (_| | ||  __/ (_| | | |__| (_) | (_| |  __/
 *  \____|\___|_| |_|\___|_|  \__,_|\__\___|\__,_|  \____\___/ \__,_|\___|
 *
 * Auto-generated SWIG accessor #define bridges.
 *
 * To update run: meson compile -C [BUILD-DIR] update-accessors
 * Or:            make update-accessors
 */

%{
	/* struct libnvme_fabrics_config */
	#define libnvme_fabrics_config_queue_size_get            libnvme_fabrics_config_get_queue_size
	#define libnvme_fabrics_config_nr_io_queues_get          libnvme_fabrics_config_get_nr_io_queues
	#define libnvme_fabrics_config_reconnect_delay_get       libnvme_fabrics_config_get_reconnect_delay
	#define libnvme_fabrics_config_ctrl_loss_tmo_get         libnvme_fabrics_config_get_ctrl_loss_tmo
	#define libnvme_fabrics_config_fast_io_fail_tmo_get      libnvme_fabrics_config_get_fast_io_fail_tmo
	#define libnvme_fabrics_config_keep_alive_tmo_get        libnvme_fabrics_config_get_keep_alive_tmo
	#define libnvme_fabrics_config_nr_write_queues_get       libnvme_fabrics_config_get_nr_write_queues
	#define libnvme_fabrics_config_nr_poll_queues_get        libnvme_fabrics_config_get_nr_poll_queues
	#define libnvme_fabrics_config_tos_get                   libnvme_fabrics_config_get_tos
	#define libnvme_fabrics_config_keyring_id_get            libnvme_fabrics_config_get_keyring_id
	#define libnvme_fabrics_config_tls_key_id_get            libnvme_fabrics_config_get_tls_key_id
	#define libnvme_fabrics_config_tls_configured_key_id_get libnvme_fabrics_config_get_tls_configured_key_id
	#define libnvme_fabrics_config_duplicate_connect_get     libnvme_fabrics_config_get_duplicate_connect
	#define libnvme_fabrics_config_disable_sqflow_get        libnvme_fabrics_config_get_disable_sqflow
	#define libnvme_fabrics_config_hdr_digest_get            libnvme_fabrics_config_get_hdr_digest
	#define libnvme_fabrics_config_data_digest_get           libnvme_fabrics_config_get_data_digest
	#define libnvme_fabrics_config_tls_get                   libnvme_fabrics_config_get_tls
	#define libnvme_fabrics_config_concat_get                libnvme_fabrics_config_get_concat
	#define libnvme_fabrics_config_queue_size_set            libnvme_fabrics_config_set_queue_size
	#define libnvme_fabrics_config_nr_io_queues_set          libnvme_fabrics_config_set_nr_io_queues
	#define libnvme_fabrics_config_reconnect_delay_set       libnvme_fabrics_config_set_reconnect_delay
	#define libnvme_fabrics_config_ctrl_loss_tmo_set         libnvme_fabrics_config_set_ctrl_loss_tmo
	#define libnvme_fabrics_config_fast_io_fail_tmo_set      libnvme_fabrics_config_set_fast_io_fail_tmo
	#define libnvme_fabrics_config_keep_alive_tmo_set        libnvme_fabrics_config_set_keep_alive_tmo
	#define libnvme_fabrics_config_nr_write_queues_set       libnvme_fabrics_config_set_nr_write_queues
	#define libnvme_fabrics_config_nr_poll_queues_set        libnvme_fabrics_config_set_nr_poll_queues
	#define libnvme_fabrics_config_tos_set                   libnvme_fabrics_config_set_tos
	#define libnvme_fabrics_config_keyring_id_set            libnvme_fabrics_config_set_keyring_id
	#define libnvme_fabrics_config_tls_key_id_set            libnvme_fabrics_config_set_tls_key_id
	#define libnvme_fabrics_config_tls_configured_key_id_set libnvme_fabrics_config_set_tls_configured_key_id
	#define libnvme_fabrics_config_duplicate_connect_set     libnvme_fabrics_config_set_duplicate_connect
	#define libnvme_fabrics_config_disable_sqflow_set        libnvme_fabrics_config_set_disable_sqflow
	#define libnvme_fabrics_config_hdr_digest_set            libnvme_fabrics_config_set_hdr_digest
	#define libnvme_fabrics_config_data_digest_set           libnvme_fabrics_config_set_data_digest
	#define libnvme_fabrics_config_tls_set                   libnvme_fabrics_config_set_tls
	#define libnvme_fabrics_config_concat_set                libnvme_fabrics_config_set_concat

	/* struct libnvme_path */
	#define libnvme_path_name_get       libnvme_path_get_name
	#define libnvme_path_sysfs_dir_get  libnvme_path_get_sysfs_dir
	#define libnvme_path_ana_state_get  libnvme_path_get_ana_state
	#define libnvme_path_numa_nodes_get libnvme_path_get_numa_nodes
	#define libnvme_path_grpid_get      libnvme_path_get_grpid
	#define libnvme_path_name_set       libnvme_path_set_name
	#define libnvme_path_sysfs_dir_set  libnvme_path_set_sysfs_dir
	#define libnvme_path_ana_state_set  libnvme_path_set_ana_state
	#define libnvme_path_numa_nodes_set libnvme_path_set_numa_nodes
	#define libnvme_path_grpid_set      libnvme_path_set_grpid

	/* struct libnvme_ns */
	#define libnvme_ns_nsid_get      libnvme_ns_get_nsid
	#define libnvme_ns_name_get      libnvme_ns_get_name
	#define libnvme_ns_sysfs_dir_get libnvme_ns_get_sysfs_dir
	#define libnvme_ns_lba_shift_get libnvme_ns_get_lba_shift
	#define libnvme_ns_lba_size_get  libnvme_ns_get_lba_size
	#define libnvme_ns_meta_size_get libnvme_ns_get_meta_size
	#define libnvme_ns_lba_count_get libnvme_ns_get_lba_count
	#define libnvme_ns_lba_util_get  libnvme_ns_get_lba_util
	#define libnvme_ns_nsid_set      libnvme_ns_set_nsid
	#define libnvme_ns_name_set      libnvme_ns_set_name
	#define libnvme_ns_sysfs_dir_set libnvme_ns_set_sysfs_dir
	#define libnvme_ns_lba_shift_set libnvme_ns_set_lba_shift
	#define libnvme_ns_lba_size_set  libnvme_ns_set_lba_size
	#define libnvme_ns_meta_size_set libnvme_ns_set_meta_size
	#define libnvme_ns_lba_count_set libnvme_ns_set_lba_count
	#define libnvme_ns_lba_util_set  libnvme_ns_set_lba_util

	/* struct libnvme_ctrl */
	#define libnvme_ctrl_name_get                  libnvme_ctrl_get_name
	#define libnvme_ctrl_sysfs_dir_get             libnvme_ctrl_get_sysfs_dir
	#define libnvme_ctrl_firmware_get              libnvme_ctrl_get_firmware
	#define libnvme_ctrl_model_get                 libnvme_ctrl_get_model
	#define libnvme_ctrl_numa_node_get             libnvme_ctrl_get_numa_node
	#define libnvme_ctrl_queue_count_get           libnvme_ctrl_get_queue_count
	#define libnvme_ctrl_serial_get                libnvme_ctrl_get_serial
	#define libnvme_ctrl_sqsize_get                libnvme_ctrl_get_sqsize
	#define libnvme_ctrl_transport_get             libnvme_ctrl_get_transport
	#define libnvme_ctrl_subsysnqn_get             libnvme_ctrl_get_subsysnqn
	#define libnvme_ctrl_traddr_get                libnvme_ctrl_get_traddr
	#define libnvme_ctrl_trsvcid_get               libnvme_ctrl_get_trsvcid
	#define libnvme_ctrl_dhchap_host_key_get       libnvme_ctrl_get_dhchap_host_key
	#define libnvme_ctrl_dhchap_ctrl_key_get       libnvme_ctrl_get_dhchap_ctrl_key
	#define libnvme_ctrl_keyring_get               libnvme_ctrl_get_keyring
	#define libnvme_ctrl_tls_key_identity_get      libnvme_ctrl_get_tls_key_identity
	#define libnvme_ctrl_tls_key_get               libnvme_ctrl_get_tls_key
	#define libnvme_ctrl_cntrltype_get             libnvme_ctrl_get_cntrltype
	#define libnvme_ctrl_cntlid_get                libnvme_ctrl_get_cntlid
	#define libnvme_ctrl_dctype_get                libnvme_ctrl_get_dctype
	#define libnvme_ctrl_phy_slot_get              libnvme_ctrl_get_phy_slot
	#define libnvme_ctrl_host_traddr_get           libnvme_ctrl_get_host_traddr
	#define libnvme_ctrl_host_iface_get            libnvme_ctrl_get_host_iface
	#define libnvme_ctrl_discovery_ctrl_get        libnvme_ctrl_get_discovery_ctrl
	#define libnvme_ctrl_unique_discovery_ctrl_get libnvme_ctrl_get_unique_discovery_ctrl
	#define libnvme_ctrl_discovered_get            libnvme_ctrl_get_discovered
	#define libnvme_ctrl_persistent_get            libnvme_ctrl_get_persistent
	#define libnvme_ctrl_dhchap_host_key_set       libnvme_ctrl_set_dhchap_host_key
	#define libnvme_ctrl_dhchap_ctrl_key_set       libnvme_ctrl_set_dhchap_ctrl_key
	#define libnvme_ctrl_keyring_set               libnvme_ctrl_set_keyring
	#define libnvme_ctrl_tls_key_identity_set      libnvme_ctrl_set_tls_key_identity
	#define libnvme_ctrl_tls_key_set               libnvme_ctrl_set_tls_key
	#define libnvme_ctrl_discovery_ctrl_set        libnvme_ctrl_set_discovery_ctrl
	#define libnvme_ctrl_unique_discovery_ctrl_set libnvme_ctrl_set_unique_discovery_ctrl
	#define libnvme_ctrl_discovered_set            libnvme_ctrl_set_discovered
	#define libnvme_ctrl_persistent_set            libnvme_ctrl_set_persistent

	/* struct libnvme_subsystem */
	#define libnvme_subsystem_name_get        libnvme_subsystem_get_name
	#define libnvme_subsystem_sysfs_dir_get   libnvme_subsystem_get_sysfs_dir
	#define libnvme_subsystem_subsysnqn_get   libnvme_subsystem_get_subsysnqn
	#define libnvme_subsystem_model_get       libnvme_subsystem_get_model
	#define libnvme_subsystem_serial_get      libnvme_subsystem_get_serial
	#define libnvme_subsystem_firmware_get    libnvme_subsystem_get_firmware
	#define libnvme_subsystem_subsystype_get  libnvme_subsystem_get_subsystype
	#define libnvme_subsystem_application_get libnvme_subsystem_get_application
	#define libnvme_subsystem_iopolicy_get    libnvme_subsystem_get_iopolicy
	#define libnvme_subsystem_application_set libnvme_subsystem_set_application
	#define libnvme_subsystem_iopolicy_set    libnvme_subsystem_set_iopolicy

	/* struct libnvme_host */
	#define libnvme_host_hostnqn_get           libnvme_host_get_hostnqn
	#define libnvme_host_hostid_get            libnvme_host_get_hostid
	#define libnvme_host_dhchap_host_key_get   libnvme_host_get_dhchap_host_key
	#define libnvme_host_hostsymname_get       libnvme_host_get_hostsymname
	#define libnvme_host_pdc_enabled_valid_get libnvme_host_get_pdc_enabled_valid
	#define libnvme_host_dhchap_host_key_set   libnvme_host_set_dhchap_host_key
	#define libnvme_host_hostsymname_set       libnvme_host_set_hostsymname
	#define libnvme_host_pdc_enabled_valid_set libnvme_host_set_pdc_enabled_valid

	/* struct libnvme_fabric_options */
	#define libnvme_fabric_options_cntlid_get             libnvme_fabric_options_get_cntlid
	#define libnvme_fabric_options_concat_get             libnvme_fabric_options_get_concat
	#define libnvme_fabric_options_ctrl_loss_tmo_get      libnvme_fabric_options_get_ctrl_loss_tmo
	#define libnvme_fabric_options_data_digest_get        libnvme_fabric_options_get_data_digest
	#define libnvme_fabric_options_dhchap_ctrl_secret_get libnvme_fabric_options_get_dhchap_ctrl_secret
	#define libnvme_fabric_options_dhchap_secret_get      libnvme_fabric_options_get_dhchap_secret
	#define libnvme_fabric_options_disable_sqflow_get     libnvme_fabric_options_get_disable_sqflow
	#define libnvme_fabric_options_discovery_get          libnvme_fabric_options_get_discovery
	#define libnvme_fabric_options_duplicate_connect_get  libnvme_fabric_options_get_duplicate_connect
	#define libnvme_fabric_options_fast_io_fail_tmo_get   libnvme_fabric_options_get_fast_io_fail_tmo
	#define libnvme_fabric_options_hdr_digest_get         libnvme_fabric_options_get_hdr_digest
	#define libnvme_fabric_options_host_iface_get         libnvme_fabric_options_get_host_iface
	#define libnvme_fabric_options_host_traddr_get        libnvme_fabric_options_get_host_traddr
	#define libnvme_fabric_options_hostid_get             libnvme_fabric_options_get_hostid
	#define libnvme_fabric_options_hostnqn_get            libnvme_fabric_options_get_hostnqn
	#define libnvme_fabric_options_instance_get           libnvme_fabric_options_get_instance
	#define libnvme_fabric_options_keep_alive_tmo_get     libnvme_fabric_options_get_keep_alive_tmo
	#define libnvme_fabric_options_keyring_get            libnvme_fabric_options_get_keyring
	#define libnvme_fabric_options_nqn_get                libnvme_fabric_options_get_nqn
	#define libnvme_fabric_options_nr_io_queues_get       libnvme_fabric_options_get_nr_io_queues
	#define libnvme_fabric_options_nr_poll_queues_get     libnvme_fabric_options_get_nr_poll_queues
	#define libnvme_fabric_options_nr_write_queues_get    libnvme_fabric_options_get_nr_write_queues
	#define libnvme_fabric_options_queue_size_get         libnvme_fabric_options_get_queue_size
	#define libnvme_fabric_options_reconnect_delay_get    libnvme_fabric_options_get_reconnect_delay
	#define libnvme_fabric_options_tls_get                libnvme_fabric_options_get_tls
	#define libnvme_fabric_options_tls_key_get            libnvme_fabric_options_get_tls_key
	#define libnvme_fabric_options_tos_get                libnvme_fabric_options_get_tos
	#define libnvme_fabric_options_traddr_get             libnvme_fabric_options_get_traddr
	#define libnvme_fabric_options_transport_get          libnvme_fabric_options_get_transport
	#define libnvme_fabric_options_trsvcid_get            libnvme_fabric_options_get_trsvcid
	#define libnvme_fabric_options_cntlid_set             libnvme_fabric_options_set_cntlid
	#define libnvme_fabric_options_concat_set             libnvme_fabric_options_set_concat
	#define libnvme_fabric_options_ctrl_loss_tmo_set      libnvme_fabric_options_set_ctrl_loss_tmo
	#define libnvme_fabric_options_data_digest_set        libnvme_fabric_options_set_data_digest
	#define libnvme_fabric_options_dhchap_ctrl_secret_set libnvme_fabric_options_set_dhchap_ctrl_secret
	#define libnvme_fabric_options_dhchap_secret_set      libnvme_fabric_options_set_dhchap_secret
	#define libnvme_fabric_options_disable_sqflow_set     libnvme_fabric_options_set_disable_sqflow
	#define libnvme_fabric_options_discovery_set          libnvme_fabric_options_set_discovery
	#define libnvme_fabric_options_duplicate_connect_set  libnvme_fabric_options_set_duplicate_connect
	#define libnvme_fabric_options_fast_io_fail_tmo_set   libnvme_fabric_options_set_fast_io_fail_tmo
	#define libnvme_fabric_options_hdr_digest_set         libnvme_fabric_options_set_hdr_digest
	#define libnvme_fabric_options_host_iface_set         libnvme_fabric_options_set_host_iface
	#define libnvme_fabric_options_host_traddr_set        libnvme_fabric_options_set_host_traddr
	#define libnvme_fabric_options_hostid_set             libnvme_fabric_options_set_hostid
	#define libnvme_fabric_options_hostnqn_set            libnvme_fabric_options_set_hostnqn
	#define libnvme_fabric_options_instance_set           libnvme_fabric_options_set_instance
	#define libnvme_fabric_options_keep_alive_tmo_set     libnvme_fabric_options_set_keep_alive_tmo
	#define libnvme_fabric_options_keyring_set            libnvme_fabric_options_set_keyring
	#define libnvme_fabric_options_nqn_set                libnvme_fabric_options_set_nqn
	#define libnvme_fabric_options_nr_io_queues_set       libnvme_fabric_options_set_nr_io_queues
	#define libnvme_fabric_options_nr_poll_queues_set     libnvme_fabric_options_set_nr_poll_queues
	#define libnvme_fabric_options_nr_write_queues_set    libnvme_fabric_options_set_nr_write_queues
	#define libnvme_fabric_options_queue_size_set         libnvme_fabric_options_set_queue_size
	#define libnvme_fabric_options_reconnect_delay_set    libnvme_fabric_options_set_reconnect_delay
	#define libnvme_fabric_options_tls_set                libnvme_fabric_options_set_tls
	#define libnvme_fabric_options_tls_key_set            libnvme_fabric_options_set_tls_key
	#define libnvme_fabric_options_tos_set                libnvme_fabric_options_set_tos
	#define libnvme_fabric_options_traddr_set             libnvme_fabric_options_set_traddr
	#define libnvme_fabric_options_transport_set          libnvme_fabric_options_set_transport
	#define libnvme_fabric_options_trsvcid_set            libnvme_fabric_options_set_trsvcid

	/* struct libnvmf_discovery_args */
	#define libnvmf_discovery_args_max_retries_get libnvmf_discovery_args_get_max_retries
	#define libnvmf_discovery_args_lsp_get         libnvmf_discovery_args_get_lsp
	#define libnvmf_discovery_args_max_retries_set libnvmf_discovery_args_set_max_retries
	#define libnvmf_discovery_args_lsp_set         libnvmf_discovery_args_set_lsp

	/* struct libnvmf_uri */
	#define libnvmf_uri_scheme_get        libnvmf_uri_get_scheme
	#define libnvmf_uri_protocol_get      libnvmf_uri_get_protocol
	#define libnvmf_uri_userinfo_get      libnvmf_uri_get_userinfo
	#define libnvmf_uri_host_get          libnvmf_uri_get_host
	#define libnvmf_uri_port_get          libnvmf_uri_get_port
	#define libnvmf_uri_path_segments_get libnvmf_uri_get_path_segments
	#define libnvmf_uri_query_get         libnvmf_uri_get_query
	#define libnvmf_uri_fragment_get      libnvmf_uri_get_fragment
	#define libnvmf_uri_scheme_set        libnvmf_uri_set_scheme
	#define libnvmf_uri_protocol_set      libnvmf_uri_set_protocol
	#define libnvmf_uri_userinfo_set      libnvmf_uri_set_userinfo
	#define libnvmf_uri_host_set          libnvmf_uri_set_host
	#define libnvmf_uri_port_set          libnvmf_uri_set_port
	#define libnvmf_uri_path_segments_set libnvmf_uri_set_path_segments
	#define libnvmf_uri_query_set         libnvmf_uri_set_query
	#define libnvmf_uri_fragment_set      libnvmf_uri_set_fragment

%}
