// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * Copyright (c) 2025 Micron Technology, Inc.
 *
 * Authors: Broc Going <bgoing@micron.com>
 */

#include <errno.h>
#include <stdio.h>
#include <windows.h>

#include <libnvme.h>

#include "micron-utils.h"
#include "util/cleanup.h"

int micron_get_pci_ids(struct libnvme_global_ctx *ctx,
			struct libnvme_transport_handle *hdl,
			unsigned short *vid, unsigned short *did)
{
	const char *p;
	unsigned int val;

	/* Windows sysfs dir for controller contains VID and DID */
	__cleanup_free char *ctrl_sysfs_dir = micron_get_ctrl_sysfs_dir(ctx, hdl);

	*vid = 0;
	*did = 0;

	if (!ctrl_sysfs_dir)
		return -EINVAL;

	p = strstr(ctrl_sysfs_dir, "ven_");
	if (p && sscanf(p, "ven_%x", &val) == 1)
		*vid = (unsigned short)val;
	else
		return -EINVAL;

	p = strstr(ctrl_sysfs_dir, "dev_");
	if (p && sscanf(p, "dev_%x", &val) == 1)
		*did = (unsigned short)val;
	else
		return -EINVAL;

	return 0;
}

int micron_get_pcie_aer_errors(struct libnvme_transport_handle *hdl,
	__u32 *correctable_errors, __u32 *uncorrectable_errors)
{
	*correctable_errors = 0;
	*uncorrectable_errors = 0;
	printf("register reads not supported on the current platform\n");
	return -ENOTSUP;
}

int micron_clear_pcie_aer_correctable_errors(
	struct libnvme_transport_handle *hdl)
{
	printf("register writes not supported on the current platform\n");
	return -ENOTSUP;
}
