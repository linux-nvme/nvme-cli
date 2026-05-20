// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * Copyright (c) 2025 Micron Technology, Inc.
 *
 * Authors: Broc Going <bgoing@micron.com>
 */

 #include <libnvme.h>

#include "micron-utils.h"
#include "util/cleanup.h"

char *micron_get_ctrl_name(struct libnvme_transport_handle *hdl)
{
	const char *name = libnvme_transport_handle_get_name(hdl);
	char *ctrl_name = NULL;

	if (libnvme_transport_handle_is_ctrl(hdl)) {
		ctrl_name = strdup(name);
	} else {
		const char *p = strlen(name) > 4 ? strchr(name + 4, 'n') : NULL;

		ctrl_name = p ? strndup(name, p - name) : strdup(name);
	}

	return ctrl_name;
}

char *micron_get_ns_name(struct libnvme_transport_handle *hdl)
{
	const char *name = libnvme_transport_handle_get_name(hdl);
	char *ns_name = NULL;

	if (libnvme_transport_handle_is_ns(hdl)) {
		ns_name = strdup(name);
	} else {
		if (asprintf(&ns_name, "%sn1", name) < 0)
			return NULL;
	}

	return ns_name;
}

char *micron_get_ctrl_sysfs_dir(
	struct libnvme_global_ctx *ctx,
	struct libnvme_transport_handle *hdl)
{
	libnvme_ctrl_t c = NULL;
	__cleanup_free char *ctrl_name = NULL;
	char *sysfs_dir = NULL;

	ctrl_name = micron_get_ctrl_name(hdl);
	if (ctrl_name && libnvme_scan_ctrl(ctx, ctrl_name, &c) == 0) {
		sysfs_dir = strdup(libnvme_ctrl_get_sysfs_dir(c));
		libnvme_free_ctrl(c);
	}

	return sysfs_dir;
}
