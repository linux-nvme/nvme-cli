# SPDX-License-Identifier: LGPL-2.1-or-later

/*
 * This file is part of libnvme.
 *
 * Copyright (c) 2025, Dell Technologies Inc. or its subsidiaries.
 * Authors: Martin Belanger <Martin.Belanger@dell.com>
 *
 * This symbol list is maintained by hand, not auto-generated. When
 * you run the update below, it does not rewrite this file -- it
 * prints which symbols should be added or removed. Add or remove
 * those symbols yourself, in the correct ABI version section.
 *
 * To check: meson compile -C [BUILD-DIR] update-accessors
 * Or:       make update-accessors
 */

LIBNVME_ATTR_ACCESSORS_3 {
	global:
		libnvme_ctrl_get_numa_node;
		libnvme_ctrl_get_queue_count;
		libnvme_ctrl_get_sqsize;
		libnvme_ctrl_get_command_error_count;
		libnvme_ctrl_get_reset_count;
		libnvme_ctrl_get_reconnect_count;
		libnvme_ctrl_get_firmware;
		libnvme_ctrl_set_firmware;
		libnvme_ctrl_get_model;
		libnvme_ctrl_set_model;
		libnvme_ctrl_get_serial;
		libnvme_ctrl_set_serial;
		libnvme_ctrl_get_cntrltype;
		libnvme_ctrl_set_cntrltype;
		libnvme_ctrl_get_cntlid;
		libnvme_ctrl_set_cntlid;
		libnvme_ctrl_get_dctype;
		libnvme_ctrl_set_dctype;
		libnvme_ctrl_get_phy_slot;
		libnvme_ctrl_get_kxchap_host_key;
		libnvme_ctrl_set_kxchap_host_key;
		libnvme_ctrl_get_kxchap_ctrl_key;
		libnvme_ctrl_set_kxchap_ctrl_key;
		libnvme_ctrl_get_keyring;
		libnvme_ctrl_set_keyring;
		libnvme_path_get_ana_state;
		libnvme_path_get_numa_nodes;
		libnvme_path_get_grpid;
		libnvme_path_get_queue_depth;
		libnvme_path_get_multipath_failover_count;
		libnvme_path_get_command_retry_count;
		libnvme_path_get_command_error_count;
		libnvme_ns_get_lba_size;
		libnvme_ns_get_lba_shift;
		libnvme_ns_get_lba_count;
		libnvme_ns_get_lba_util;
		libnvme_ns_get_meta_size;
		libnvme_ns_get_csi;
		libnvme_ns_get_eui64;
		libnvme_ns_get_nguid;
		libnvme_ns_get_uuid;
		libnvme_ns_get_command_retry_count;
		libnvme_ns_get_command_error_count;
		libnvme_ns_get_io_requeue_no_usable_path_count;
		libnvme_ns_get_io_fail_no_available_path_count;
		libnvme_subsystem_get_model;
		libnvme_subsystem_set_model;
		libnvme_subsystem_get_serial;
		libnvme_subsystem_set_serial;
		libnvme_subsystem_get_firmware;
		libnvme_subsystem_set_firmware;
		libnvme_subsystem_get_iopolicy;
};
