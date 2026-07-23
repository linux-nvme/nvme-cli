// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2026 Micron Technology, Inc.
 *
 * Authors: Broc Going <bgoing@micron.com>
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <libnvme.h>
#include <nvme/types.h>

#include "nvme-print.h"

int __nvme_get_sysfs_dir(struct libnvme_global_ctx *ctx,
		const char *ctrl_name, char **sysfs_dir)
{
	libnvme_ctrl_t c = NULL;
	const char *path;
	int ret;

	ret = libnvme_scan_ctrl(ctx, ctrl_name, &c);
	if (ret != 0) {
		nvme_show_error("Unable to find device path for %s", ctrl_name);
		return ret;
	}

	path = libnvme_ctrl_get_sysfs_dir(c);
	if (!path) {
		nvme_show_error("No device path found for %s", ctrl_name);
		libnvme_free_ctrl(c);
		return -ENOENT;
	}

	*sysfs_dir = strdup(path);
	libnvme_free_ctrl(c);
	return *sysfs_dir ? 0 : -ENOMEM;
}

int __nvme_get_pci_ids(const char *sysfs_dir,
		__u32 *vid, __u32 *did,
		__u32 *subsys_vid, __u32 *subsys_did,
		__u32 *class_code)
{
	const char *p;
	unsigned int val;
	int ret = 0;

	/*
	 * On Windows, sysfs_dir is the SetupDI device interface path, e.g.:
	 *   \\?\pci#ven_1344&dev_5196&subsys_51961344&rev_02#...
	 * VID, DID, and subsystem IDs are embedded as tokens in the path.
	 * Class code is not available from the path string.
	 */

	if (vid) {
		p = strstr(sysfs_dir, "ven_");
		if (p && sscanf(p, "ven_%x", &val) == 1)
			*vid = val;
		else
			ret = -ENOENT;
	}

	if (did) {
		p = strstr(sysfs_dir, "dev_");
		if (p && sscanf(p, "dev_%x", &val) == 1)
			*did = val;
		else
			ret = -ENOENT;
	}

	/*
	 * subsys_DDDDVVVV:
	 * high 16 bits = subsystem DID, low 16 bits = subsystem VID
	 */
	if (subsys_vid || subsys_did) {
		p = strstr(sysfs_dir, "subsys_");
		if (p && sscanf(p, "subsys_%8x", &val) == 1) {
			if (subsys_did)
				*subsys_did = val >> 16;
			if (subsys_vid)
				*subsys_vid = val & 0xFFFF;
		} else {
			ret = -ENOENT;
		}
	}

	/*
	 * nvme-cli on Windows only opens NVMe devices, so the PCI class code
	 * is always 0x010802 (Mass Storage / NVM Express).
	 */
	if (class_code)
		*class_code = 0x010802;

	return ret;
}
