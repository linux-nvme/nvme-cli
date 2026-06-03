/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */
#pragma once

/**
 * DOC: registry.h
 *
 * NVMe controller ownership registry.
 *
 * The registry records which orchestrator owns each connected NVMe-oF
 * controller.  It is stored under /run/nvme/registry/ as one directory per
 * live controller (e.g. nvme3/), containing one plain text file per attribute
 * (e.g. nvme3/owner).  Registry support is only available when fabrics support
 * is enabled (-Dfabrics=enabled).
 *
 * The registry is a cooperative coordination mechanism.  All participants are
 * assumed to be cooperative; there is no OS-level enforcement.  Its primary
 * purpose is to prevent accidental disconnection of controllers managed by one
 * orchestrator by another.
 */

/**
 * libnvmf_registry_retrieve() - Read an attribute from a controller's registry entry
 * @device:	Kernel device name (e.g. "nvme3")
 * @attr:	Attribute name to retrieve (e.g. "owner")
 * @value:	On success, set to a newly allocated string with the attribute
 *		value.  The caller must free this string.
 *
 * Return: 0 on success, -ENOENT if the controller is not registered or the
 * attribute is not present, -ENOMEM on allocation failure, negative errno
 * from underlying system calls otherwise.
 */
int libnvmf_registry_retrieve(const char *device, const char *attr,
			       char **value);

/**
 * libnvmf_registry_update() - Update an attribute in a controller's registry entry
 * @device:	Kernel device name (e.g. "nvme3")
 * @attr:	Attribute name to update (e.g. "owner")
 * @value:	New attribute value, or NULL to remove the attribute file
 *
 * Writes the attribute value to the controller's registry entry using an
 * atomic tmp-file rename.  Creates the entry directory if it does not exist.
 * If @value is NULL, the attribute file is removed instead.
 *
 * Return: 0 on success, negative errno from underlying system calls otherwise.
 */
int libnvmf_registry_update(const char *device, const char *attr,
			     const char *value);

/**
 * libnvmf_registry_delete() - Remove a controller's registry entry
 * @device:	Kernel device name (e.g. "nvme3")
 *
 * Removes the registry directory and all attribute files for @device.  Called
 * by the owning orchestrator on intentional disconnect.  The udev REMOVE rule
 * handles the common case of kernel-driven removal directly via rm -rf and
 * does not call this function.
 *
 * Return: 0 on success, -ENOENT if no entry exists, negative errno from
 * underlying system calls otherwise.
 */
int libnvmf_registry_delete(const char *device);

/**
 * libnvmf_registry_device_for_each() - Iterate over live controller registry entries
 * @cback:	Callback invoked for each live entry
 * @user_data:	User data passed to @cback
 *
 * Scans the registry directory and invokes @cback for each entry whose
 * corresponding /dev/nvmeN device node exists.  Stale entries left behind
 * after a controller is removed are silently skipped.  The existence check is
 * advisory: a device may be removed between the check and callback invocation;
 * callers should handle ENOENT gracefully.
 *
 * Return: 0 on success, negative errno if the registry directory cannot be
 * opened.  Returns 0 when the directory does not exist (nothing registered).
 */
int libnvmf_registry_device_for_each(
		void (*cback)(const char *device, void *user_data),
		void *user_data);

/**
 * libnvmf_registry_attr_for_each() - Iterate over attributes in a controller's registry entry
 * @device:	Kernel device name (e.g. "nvme3")
 * @cback:	Callback invoked for each attribute
 * @user_data:	User data passed to @cback
 *
 * Opens the registry directory for @device and invokes @cback for each
 * attribute file found.  Attribute files that disappear during iteration
 * (e.g. because the device is removed concurrently) are silently skipped.
 *
 * Return: 0 on success, -ENOENT if the device directory does not exist at the
 * time of the initial open, negative errno otherwise.
 */
int libnvmf_registry_attr_for_each(
		const char *device,
		void (*cback)(const char *attr, const char *value, void *user_data),
		void *user_data);
