# SPDX-License-Identifier: LGPL-2.1-or-later

/*
 * This file is part of libnvme.
 *
 * Copyright (c) 2026, Dell Technologies Inc. or its subsidiaries.
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

LIBNVME_SUBSYS_SYSFS_3 {
	global:
		libnvme_subsystem_get_model;
		libnvme_subsystem_set_model;
		libnvme_subsystem_get_serial;
		libnvme_subsystem_set_serial;
		libnvme_subsystem_get_firmware;
		libnvme_subsystem_set_firmware;
		libnvme_subsystem_get_iopolicy;
};
