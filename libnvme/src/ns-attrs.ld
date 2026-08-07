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

LIBNVME_NS_ATTRS_3 {
	global:
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
};
