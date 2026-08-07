// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

#include <errno.h>

#include <nvme/types.h>

#include "nvme-pci-ids.h"

int __nvme_get_sysfs_dir(struct libnvme_global_ctx *ctx,
		const char *ctrl_name, char **sysfs_dir)
{
	return -ENOTSUP;
}

int __nvme_get_pci_ids(const char *sysfs_dir,
		__u32 *vid, __u32 *did,
		__u32 *subsys_vid, __u32 *subsys_did,
		__u32 *class_code)
{
	return -ENOTSUP;
}
