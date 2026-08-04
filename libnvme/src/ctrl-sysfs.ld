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

LIBNVME_CTRL_SYSFS_3 {
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
		libnvme_ctrl_get_dhchap_host_key;
		libnvme_ctrl_set_dhchap_host_key;
		libnvme_ctrl_get_dhchap_ctrl_key;
		libnvme_ctrl_set_dhchap_ctrl_key;
		libnvme_ctrl_get_keyring;
		libnvme_ctrl_set_keyring;
};
