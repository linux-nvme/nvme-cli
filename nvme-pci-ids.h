/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2026 Micron Technology, Inc.
 *
 * Authors: Broc Going <bgoing@micron.com>
 */
#pragma once

#include <nvme/lib-types.h>

/**
 * nvme_get_pci_ids() - Read PCI IDs for a controller
 * @ctx:	Global context
 * @hdl:	Transport handle
 * @vid:	Output vendor ID (may be NULL)
 * @did:	Output device ID (may be NULL)
 * @subsys_vid:	Output subsystem vendor ID (may be NULL)
 * @subsys_did:	Output subsystem device ID (may be NULL)
 * @class_code:	Output PCI class code (may be NULL)
 *
 * Gets the PCI IDs for the controller associated with @hdl.
 * Any output pointer that is NULL is silently skipped.
 * If any error occurs when reading an ID, the value of that ID
 * is left unchanged.
 *
 * Return: 0 on success, negative errno on failure.
 */
int nvme_get_pci_ids(struct libnvme_global_ctx *ctx,
		struct libnvme_transport_handle *hdl,
		__u32 *vid, __u32 *did,
		__u32 *subsys_vid, __u32 *subsys_did,
		__u32 *class_code);


int __nvme_get_pci_ids(const char *sysfs_dir,
		__u32 *vid, __u32 *did,
		__u32 *subsys_vid, __u32 *subsys_did,
		__u32 *class_code);

int __nvme_get_sysfs_dir(struct libnvme_global_ctx *ctx,
		const char *ctrl_name, char **sysfs_dir);
