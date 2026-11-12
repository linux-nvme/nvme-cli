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
 *
 * Nothing removes the entry of a controller the kernel removed.  A connect
 * that gets the device name replaces the entry, and until then the functions
 * that read the registry treat an entry without a controller in sysfs as
 * absent.
 */

struct libnvme_global_ctx;

/**
 * libnvmf_registry_retrieve() - Read an attribute from a controller's registry entry
 * @ctx:	libnvme global context; must not be NULL
 * @device:	Kernel device name (e.g. "nvme3")
 * @attr:	Attribute name to retrieve (e.g. "owner")
 * @value:	On success, set to a newly allocated string with the attribute
 *		value.  The caller must free this string.
 *
 * Return: 0 on success, -ENOENT if the controller does not exist, is not
 * registered or the attribute is not present, -ENOMEM on allocation
 * failure, negative errno from underlying system calls otherwise.
 */
int libnvmf_registry_retrieve(struct libnvme_global_ctx *ctx,
			      const char *device, const char *attr,
			      char **value);

/**
 * libnvmf_registry_attr_equal() - Compare a registry attribute to a value
 * @ctx:	libnvme global context; must not be NULL
 * @device:	Kernel device name (e.g. "nvme3")
 * @attr:	Attribute name to compare (e.g. "owner")
 * @value:	Value to compare against; NULL means "attribute absent"
 *
 * Return: 0 if @attr equals @value (a missing attribute equals a NULL
 * @value), >0 if it differs, negative errno on a read error.
 */
int libnvmf_registry_attr_equal(struct libnvme_global_ctx *ctx,
				const char *device, const char *attr,
				const char *value);

/**
 * libnvmf_registry_update() - Update an attribute in a controller's registry entry
 * @ctx:	libnvme global context; must not be NULL
 * @device:	Kernel device name (e.g. "nvme3")
 * @attr:	Attribute name to update (e.g. "owner")
 * @value:	New attribute value, or NULL to remove the attribute file
 *
 * Writes the attribute value to the controller's registry entry using an
 * atomic tmp-file rename.  If the entry does not exist, it is created
 * atomically the same way as on connect.  If @value is NULL, the attribute
 * file is removed instead; a missing entry is left alone in this case.
 *
 * Return: 0 on success, negative errno from underlying system calls otherwise.
 */
int libnvmf_registry_update(struct libnvme_global_ctx *ctx,
			    const char *device, const char *attr,
			    const char *value);

/**
 * libnvmf_registry_delete() - Remove a controller's registry entry
 * @ctx:	libnvme global context; must not be NULL
 * @device:	Kernel device name (e.g. "nvme3")
 *
 * Removes the registry directory and all attribute files for @device.
 *
 * Return: 0 on success, -ENOENT if no entry exists, negative errno from
 * underlying system calls otherwise.
 */
int libnvmf_registry_delete(struct libnvme_global_ctx *ctx, const char *device);

/**
 * libnvmf_registry_device_for_each() - Iterate over live controller registry entries
 * @ctx:	libnvme global context; must not be NULL
 * @callback:	Callback invoked for each live entry
 * @user_data:	User data passed to @callback
 *
 * Scans the registry directory and invokes @callback for each entry whose
 * controller exists in sysfs.  Entries left behind by a removed controller
 * are skipped.  The existence check is
 * advisory: a device may be removed between the check and callback invocation;
 * callers should handle ENOENT gracefully.
 *
 * Return: 0 on success, negative errno if the registry directory cannot be
 * opened.  Returns 0 when the directory does not exist (nothing registered).
 */
int libnvmf_registry_device_for_each(
		struct libnvme_global_ctx *ctx,
		int (*callback)(const char *device, void *user_data),
		void *user_data);

/**
 * libnvmf_registry_attr_for_each() - Iterate over attributes in a controller's registry entry
 * @ctx:	libnvme global context; must not be NULL
 * @device:	Kernel device name (e.g. "nvme3")
 * @callback:	Callback invoked for each attribute
 * @user_data:	User data passed to @callback
 *
 * Opens the registry directory for @device and invokes @callback for each
 * attribute file found.  Attribute files that disappear during iteration
 * (e.g. because the device is removed concurrently) are silently skipped.
 *
 * Return: 0 on success, -ENOENT if the controller or its registry entry does
 * not exist at the time of the initial open, negative errno otherwise.
 */
int libnvmf_registry_attr_for_each(
		struct libnvme_global_ctx *ctx,
		const char *device,
		void (*callback)(const char *attr, const char *value,
				 void *user_data),
		void *user_data);
