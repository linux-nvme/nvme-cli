// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2026 Micron Technology, Inc.
 *
 * Authors: Broc Going <bgoing@micron.com>
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libnvme.h>

#include "nvme-pci-ids.h"
#include "nvme-print.h"
#include "util/cleanup.h"

int nvme_get_pci_ids(struct libnvme_global_ctx *ctx,
		struct libnvme_transport_handle *hdl,
		__u32 *vid, __u32 *did,
		__u32 *subsys_vid, __u32 *subsys_did,
		__u32 *class_code)
{
	int ret;
	const char *name;

	__cleanup_free char *ctrl_name = NULL;
	__cleanup_free char *sysfs_dir = NULL;

	name = libnvme_transport_handle_get_name(hdl);
	if (libnvme_transport_handle_is_ctrl(hdl)) {
		ctrl_name = strdup(name);
	} else {
		/* Strip the 'nY' namespace suffix: "nvme0n1" -> "nvme0" */
		const char *p = strlen(name) > 4 ? strchr(name + 4, 'n') : NULL;

		ctrl_name = p ? strndup(name, p - name) : strdup(name);
	}

	if (!ctrl_name)
		return -ENOMEM;

	ret = __nvme_get_sysfs_dir(ctx, ctrl_name, &sysfs_dir);
	if (ret != 0)
		return ret;

	return __nvme_get_pci_ids(sysfs_dir, vid, did, subsys_vid, subsys_did,
		class_code);
}
