/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 Micron Technology, Inc.
 *
 * Authors: Brandon Capener <bcapener@micron.com>
 */
#pragma once

#if defined(_WIN32)

#include <winsock2.h>
#include <windows.h>
#include "nvme-types.h"

struct storageport_map_entry;

/**
 * libnvme_storageport_map_get_count() - Get number of StoragePort map entries
 *
 * Return: Number of entries in the global storageport map
 */
size_t libnvme_storageport_map_get_count(void);

/**
 * libnvme_storageport_map_get_name() - Get StoragePort name by index
 * @index: Zero-based index into the storageport map
 *
 * Return: StoragePort name string (e.g. "nvme0"), or NULL if index
 * is out of range
 */
const char *libnvme_storageport_map_get_name(size_t index);

/**
 * libnvme_storageport_map_init() - Initialize the StoragePort map
 *
 * Enumerates all NVMe controllers via SetupDI and populates the
 * global storageport map.  Safe to call multiple times; returns
 * immediately if the map is already populated.
 *
 * Return: 0 on success, negative errno on failure
 */
int libnvme_storageport_map_init(void);

/**
 * libnvme_storageport_map_clear() - Free all StoragePort map entries
 *
 * Releases all memory associated with the global storageport map
 * and resets the count to zero.
 */
void libnvme_storageport_map_clear(void);

/**
 * libnvme_storageport_map_lookup() - Resolve StoragePort name to map entry
 * @ctrl_name: Controller name in nvmeX format
 *
 * Return: StoragePort map entry on Windows, or NULL if unavailable
 */
struct storageport_map_entry *
libnvme_storageport_map_lookup(const char *ctrl_name);

/**
 * libnvme_storageport_map_lookup_by_physdrive() - Resolve PhysicalDrive path to
 * StoragePort entry
 * @drive_path: Device path in \\.\PhysicalDriveX format
 *
 * Scans all NVMe controllers and returns the StoragePort map entry whose
 * child disk set contains the given PhysicalDrive number.
 *
 * Return: StoragePort map entry on match, or NULL if not found
 */
const struct storageport_map_entry *
libnvme_storageport_map_lookup_by_physdrive(const char *drive_path);

/**
 * libnvme_storageport_entry_set_id_ctrl() - Set id_ctrl for a entry
 * @sp_entry: StoragePort map entry
 * @id: Pointer to the new identify controller data
 *
 * Return: 0 on success, -EINVAL for bad args
 */
int libnvme_storageport_entry_set_id_ctrl(
	struct storageport_map_entry *sp_entry,
	const struct nvme_id_ctrl *id);

/**
 * libnvme_storageport_entry_get_ctrl_name() - Get UTF-8 controller name for
 * entry
 * @entry: StoragePort map entry
 *
 * Return: UTF-8 controller name string, or NULL if unavailable
 */
const char *libnvme_storageport_entry_get_ctrl_name(
	const struct storageport_map_entry *entry);

/**
 * libnvme_storageport_entry_get_ctrl_path() - Get UTF-8 device path for entry
 * @entry: StoragePort map entry
 * @ctrl_path: Output UTF-8 path string, allocated on success
 *
 * Return: 0 on success, or a negative error code
 */
int libnvme_storageport_entry_get_ctrl_path(
	const struct storageport_map_entry *entry,
	char **ctrl_path);

/**
 * libnvme_storageport_entry_get_pci_address() - Get PCI BDF address for a
 * StoragePort
 * @entry: StoragePort map entry
 * @address: Output BDF string in "DDDD:BB:DD.F" format, allocated on success
 *
 * Queries the Windows CM API for the PCI bus, device, and function numbers
 * and formats them into a Linux-compatible BDF address string.
 *
 * Return: 0 on success, or a negative error code
 */
int libnvme_storageport_entry_get_pci_address(
	const struct storageport_map_entry *entry,
	char **address);

/**
 * libnvme_storageport_entry_scan_device_numbers() - Get device numbers for a
 * StoragePort
 * @entry: StoragePort map entry
 * @device_numbers: Output array of device numbers,
 * allocated on success (caller frees)
 * @count: Output number of entries in @device_numbers
 *
 * Walks the child devnodes of the StoragePort and enumerates their
 * GUID_DEVINTERFACE_DISK interfaces to collect PhysicalDrive device numbers.
 *
 * Return: 0 on success, or a negative error code
 */
int libnvme_storageport_entry_scan_device_numbers(
	const struct storageport_map_entry *entry,
	DWORD **device_numbers,
	int *count);

/**
 * libnvme_storageport_entry_map_nsid_to_drive_path() - Map namespace ID to
 * PhysicalDrive path
 * @entry: StoragePort map entry for the controller
 * @nsid: NVMe namespace ID (1-based)
 * @drive_path: Output path string in \\.\PhysicalDriveX format (caller frees)
 *
 * Scans the disks belonging to the given StoragePort and returns the
 * device path whose SCSI LUN corresponds to @nsid.
 *
 * Return: 0 on success, -ENODEV if no matching namespace, or a negative error
 * code
 */
int libnvme_storageport_entry_map_nsid_to_drive_path(
	const struct storageport_map_entry *entry,
	__u32 nsid,
	char **drive_path);

/**
 * libnvme_storageport_entry_get_subsys_name() - Get UTF-8 subsystem name for
 * entry
 * @entry: StoragePort map entry
 *
 * Return: UTF-8 subsystem name string, or NULL if unavailable
 */
char *libnvme_storageport_entry_get_subsys_name(
	const struct storageport_map_entry *entry);

/**
 * libnvme_storageport_entry_get_subnqn() - Get UTF-8 subsystem NQN for
 * entry
 * @entry: StoragePort map entry
 *
 * Return: UTF-8 subsystem NQN string, or NULL if unavailable
 */
char *libnvme_storageport_entry_get_subnqn(
	const struct storageport_map_entry *entry);

/**
 * libnvme_storageport_entry_get_serial() - Get UTF-8 serial number for entry
 * @entry: StoragePort map entry
 *
 * Return: UTF-8 serial number string, or NULL if unavailable
 */
char *libnvme_storageport_entry_get_serial(
	const struct storageport_map_entry *entry);

/**
 * libnvme_storageport_entry_get_model() - Get UTF-8 model number for entry
 * @entry: StoragePort map entry
 *
 * Return: UTF-8 model number string, or NULL if unavailable
 */
char *libnvme_storageport_entry_get_model(
	const struct storageport_map_entry *entry);

/**
 * libnvme_storageport_entry_get_firmware() - Get UTF-8 firmware revision for
 * entry
 * @entry: StoragePort map entry
 *
 * Return: UTF-8 firmware revision string, or NULL if unavailable
 */
char *libnvme_storageport_entry_get_firmware(
	const struct storageport_map_entry *entry);

#endif /* defined(_WIN32) */
