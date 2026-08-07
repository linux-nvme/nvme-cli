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

LIBNVME_PATH_ATTRS_3 {
	global:
		libnvme_path_get_ana_state;
		libnvme_path_get_numa_nodes;
		libnvme_path_get_grpid;
		libnvme_path_get_queue_depth;
		libnvme_path_get_multipath_failover_count;
		libnvme_path_get_command_retry_count;
		libnvme_path_get_command_error_count;
};
