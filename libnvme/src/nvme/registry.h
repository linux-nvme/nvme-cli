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
 * controller.  It is stored under /run/nvme/registry/ as one JSON file per
 * live controller (e.g. nvme3.json).  Registry support is only available when
 * fabrics support is enabled (-Dfabrics=enabled).
 *
 * The registry is a cooperative coordination mechanism.  All participants are
 * assumed to be cooperative; there is no OS-level enforcement.  Its primary
 * purpose is to prevent accidental disconnection of controllers managed by one
 * orchestrator by another.
 */

/**
 * libnvmf_registry_retrieve() - Read a field from a controller's registry entry
 * @device:	Kernel device name (e.g. "nvme3")
 * @key:	Field name to retrieve (e.g. "owner")
 * @value:	On success, set to a newly allocated string with the field value.
 *		The caller must free this string.
 *
 * Return: 0 on success, -ENOENT if the controller is not registered, the
 * requested key is absent, or the entry cannot be parsed (parse failures are
 * not distinguished from missing entries), -ENOMEM on allocation failure.
 */
int libnvmf_registry_retrieve(const char *device, const char *key,
			       char **value);

/**
 * libnvmf_registry_update() - Update a field in a controller's registry entry
 * @device:	Kernel device name (e.g. "nvme3")
 * @key:	Field name to update (e.g. "owner")
 * @value:	New field value (e.g. "stas")
 *
 * Writes the key/value pair to the controller's registry entry using an atomic
 * tmp-file rename.  Creates the entry if it does not exist.  Used by
 * orchestrators to claim or steal ownership of an existing connection.
 *
 * Return: 0 on success, -ENOMEM on allocation failure, -EIO if the entry
 * cannot be serialized to JSON, negative errno from underlying system calls
 * otherwise.
 */
int libnvmf_registry_update(const char *device, const char *key,
			     const char *value);

/**
 * libnvmf_registry_delete() - Remove a controller's registry entry
 * @device:	Kernel device name (e.g. "nvme3")
 *
 * Removes the registry entry for @device.  Called by the owning orchestrator
 * on intentional disconnect.  The udev REMOVE rule handles the common case of
 * kernel-driven removal directly via rm -f and does not call this function.
 *
 * Return: 0 on success, -ENOENT if no entry exists, -ENOMEM on allocation
 * failure, negative errno from underlying system calls otherwise.
 */
int libnvmf_registry_delete(const char *device);

/**
 * libnvmf_registry_for_each() - Iterate over live controller registry entries
 * @cback:	Callback invoked for each live entry
 * @user_data:	User data passed to @cback
 *
 * Scans the registry directory and invokes @cback for each entry whose
 * corresponding /dev/nvmeN device node exists.  Stale entries left behind
 * after a controller is removed are silently skipped.
 *
 * Return: 0 on success, negative errno if the registry directory cannot be
 * opened.  Returns 0 when the directory does not exist (nothing registered).
 */
int libnvmf_registry_for_each(
		void (*cback)(const char *device, const char *owner,
			      void *user_data),
		void *user_data);
