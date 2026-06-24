/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 Micron Technology, Inc.
 *
 * Authors: Brandon Capener <bcapener@micron.com>
 */
#pragma once

#if defined(_WIN32)

#include "nvme-types.h"

struct ctrl_map_entry;

/**
 * libnvme_ctrl_map_get_ctrl_names() - Get all controller names, sorted
 * @count: Optional output for the number of names returned (may be NULL)
 *
 * Collects the controller names from the map and returns them in ascending
 * numeric order (e.g. "nvme2" before "nvme10").  The returned array is
 * NULL-terminated; the caller frees the array but not the name strings,
 * which remain owned by the controller map and are valid until the next
 * libnvme_ctrl_map_clear().
 *
 * Return: NULL-terminated array of controller names, or NULL on allocation
 * failure or when the map is empty
 */
const char **libnvme_ctrl_map_get_ctrl_names(size_t *count);

/**
 * libnvme_ctrl_map_init() - Initialize the controller map
 * @ctx: libnvme global context used for transient Identify commands
 *
 * Enumerates all NVMe controllers via SetupDI and populates the
 * global controller map.  Safe to call multiple times; returns
 * immediately if the map is already populated.
 *
 * Return: 0 on success, negative errno on failure
 */
int libnvme_ctrl_map_init(struct libnvme_global_ctx *ctx);

/**
 * libnvme_ctrl_map_clear() - Free all controller map entries
 *
 * Releases all memory associated with the global controller map
 * and resets the count to zero.
 */
void libnvme_ctrl_map_clear(void);

/**
 * libnvme_ctrl_map_lookup() - Resolve controller name to map entry
 * @ctx: libnvme global context used to initialize the map if needed
 * @ctrl_name: Controller name in nvmeX format
 *
 * Return: controller map entry on Windows, or NULL if unavailable
 */
struct ctrl_map_entry *
libnvme_ctrl_map_lookup(struct libnvme_global_ctx *ctx, const char *ctrl_name);

/**
 * libnvme_ctrl_map_lookup_by_physdrive() - Resolve PhysicalDrive path to
 * controller entry
 * @ctx: libnvme global context used to initialize the map if needed
 * @drive_path: Device path in \\.\PhysicalDriveX format
 *
 * Scans all NVMe controllers and returns the controller map entry whose
 * child disk set contains the given PhysicalDrive number.
 *
 * Return: controller map entry on match, or NULL if not found
 */
const struct ctrl_map_entry *
libnvme_ctrl_map_lookup_by_physdrive(struct libnvme_global_ctx *ctx,
		const char *drive_path);

/**
 * libnvme_ctrl_map_entry_set_id_ctrl() - Set id_ctrl for a entry
 * @entry: controller map entry
 * @id: Pointer to the new identify controller data
 *
 * Return: 0 on success, -EINVAL for bad args
 */
int libnvme_ctrl_map_entry_set_id_ctrl(struct ctrl_map_entry *entry,
		const struct nvme_id_ctrl *id);

/**
 * libnvme_ctrl_map_entry_get_ctrl_name() - Get UTF-8 controller name for
 * entry
 * @entry: controller map entry
 *
 * Return: UTF-8 controller name string, or NULL if unavailable
 */
const char *libnvme_ctrl_map_entry_get_ctrl_name(
		const struct ctrl_map_entry *entry);

/**
 * libnvme_ctrl_map_entry_get_ctrl_path() - Get UTF-8 device path for entry
 * @entry: controller map entry
 * @ctrl_path: Output UTF-8 path string, allocated on success
 *
 * Return: 0 on success, or a negative error code
 */
int libnvme_ctrl_map_entry_get_ctrl_path(const struct ctrl_map_entry *entry,
		char **ctrl_path);

/**
 * libnvme_ctrl_map_entry_get_pci_address() - Get PCI BDF address for a
 * controller
 * @entry: controller map entry
 * @address: Output BDF string in "DDDD:BB:DD.F" format, allocated on success
 *
 * Queries the Windows CM API for the PCI bus, device, and function numbers
 * and formats them into a Linux-compatible BDF address string.
 *
 * Return: 0 on success, or a negative error code
 */
int libnvme_ctrl_map_entry_get_pci_address(const struct ctrl_map_entry *entry,
		char **address);

/**
 * libnvme_ctrl_map_entry_scan_device_numbers() - Get device numbers for a
 * controller
 * @entry: controller map entry
 * @device_numbers: Output array of device numbers,
 * allocated on success (caller frees)
 * @count: Output number of entries in @device_numbers
 *
 * Walks the child devnodes of the controller and enumerates their
 * GUID_DEVINTERFACE_DISK interfaces to collect PhysicalDrive device numbers.
 *
 * Return: 0 on success, or a negative error code
 */
int libnvme_ctrl_map_entry_scan_device_numbers(
		const struct ctrl_map_entry *entry, DWORD **device_numbers,
		int *count);

/**
 * libnvme_ctrl_map_entry_map_nsid_to_drive_path() - Map namespace ID to
 * PhysicalDrive path
 * @entry: controller map entry for the controller
 * @nsid: NVMe namespace ID (1-based)
 * @drive_path: Output path string in \\.\PhysicalDriveX format (caller frees)
 *
 * Scans the disks belonging to the given controller and returns the
 * device path whose SCSI LUN corresponds to @nsid.
 *
 * Return: 0 on success, -ENODEV if no matching namespace, or a negative error
 * code
 */
int libnvme_ctrl_map_entry_map_nsid_to_drive_path(
		const struct ctrl_map_entry *entry, __u32 nsid,
		char **drive_path);

/**
 * libnvme_ctrl_map_entry_get_subsys_name() - Get UTF-8 subsystem name for
 * entry
 * @entry: controller map entry
 *
 * Return: UTF-8 subsystem name string, or NULL if unavailable
 */
char *libnvme_ctrl_map_entry_get_subsys_name(
		const struct ctrl_map_entry *entry);

/**
 * libnvme_ctrl_map_entry_get_subnqn() - Get UTF-8 subsystem NQN for
 * entry
 * @entry: controller map entry
 *
 * Return: UTF-8 subsystem NQN string, or NULL if unavailable
 */
char *libnvme_ctrl_map_entry_get_subnqn(const struct ctrl_map_entry *entry);

/**
 * libnvme_ctrl_map_entry_get_serial() - Get UTF-8 serial number for entry
 * @entry: controller map entry
 *
 * Return: UTF-8 serial number string, or NULL if unavailable
 */
char *libnvme_ctrl_map_entry_get_serial(const struct ctrl_map_entry *entry);

/**
 * libnvme_ctrl_map_entry_get_model() - Get UTF-8 model number for entry
 * @entry: controller map entry
 *
 * Return: UTF-8 model number string, or NULL if unavailable
 */
char *libnvme_ctrl_map_entry_get_model(const struct ctrl_map_entry *entry);

/**
 * libnvme_ctrl_map_entry_get_firmware() - Get UTF-8 firmware revision for
 * entry
 * @entry: controller map entry
 *
 * Return: UTF-8 firmware revision string, or NULL if unavailable
 */
char *libnvme_ctrl_map_entry_get_firmware(const struct ctrl_map_entry *entry);

#endif /* defined(_WIN32) */
