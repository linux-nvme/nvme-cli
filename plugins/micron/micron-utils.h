/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (c) 2025 Micron Technology, Inc.
 *
 * Authors: Broc Going <bgoing@micron.com>
 */
#pragma once

#include <nvme/lib-types.h>

/**
 * micron_get_ctrl_name() - Get the controller name from the device
 * transport handle
 * @hdl:	Transport handle
 *
 * Returns the controller name for the handle (e.g., "nvme0").
 * For namespace handles, the namespace indicator is stripped from the
 * name to derive the controller name.
 *
 * Return: Allocated string containing the controller name on success,
 * or NULL on failure. The caller is responsible for freeing the returned
 * string.
 */
char *micron_get_ctrl_name(struct libnvme_transport_handle *hdl);

/**
 * micron_get_ns_name() - Get the namespace name from a transport handle
 * @hdl:	Transport handle
 *
 * Returns the namespace name for the handle. For controller handles,
 * "n1" is appended to derive a default namespace name.
 *
 * Return: Allocated string containing the namespace name on success,
 * or NULL on failure. The caller is responsible for freeing the returned
 * string.
 */
char *micron_get_ns_name(struct libnvme_transport_handle *hdl);

/**
 * micron_get_ctrl_sysfs_dir() - Get the sysfs directory path for a controller
 * @ctx:	struct libnvme_global_ctx object
 * @hdl:	Transport handle
 *
 * Looks up the sysfs directory for the controller associated with @hdl
 * by scanning the NVMe subsystem.
 *
 * Return: Allocated string containing the sysfs directory path on
 * success, or NULL on failure. The caller is responsible for freeing
 * the returned string.
 */
char *micron_get_ctrl_sysfs_dir(struct libnvme_global_ctx *ctx,
				struct libnvme_transport_handle *hdl);

/**
 * micron_get_pci_ids() - Read PCI vendor and device IDs for a controller
 * @ctx:	struct libnvme_global_ctx object
 * @hdl:	Transport handle
 * @vid:	Output PCI vendor ID
 * @did:	Output PCI device ID
 *
 * Gets the PCI vendor and device IDs for the controller associated with @hdl.
 *
 * Return: 0 on success, negative errno on failure.
 */
int micron_get_pci_ids(struct libnvme_global_ctx *ctx,
			struct libnvme_transport_handle *hdl,
			unsigned short *vid, unsigned short *did);
