/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE LLC
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */
#pragma once

#include <stdbool.h>

#include "tid.h"

/*
 * sysfs access by path. The attributes are read as plain files, not through
 * sd_device, which refuses a syspath outside /sys: a test points the root
 * at a directory tree that imitates sysfs, as nvme-cli's test-sysfs-dir
 * does.
 */

/*
 * Read sysfs under @dir instead of the real one: "/sys/class/nvme" becomes
 * "@dir/sys/class/nvme". NULL restores the real sysfs. Returns 0 or
 * -ENOMEM.
 */
int sysfs_set_root(const char *dir);

/* The directory set by sysfs_set_root(), or NULL for the real sysfs. */
const char *sysfs_root(void);

/*
 * The path of @path ("/sys/...") under the sysfs root. Returns an
 * allocated string or NULL. Caller must free.
 */
char *sysfs_path(const char *path);

/*
 * The path of controller @devname, "/sys/class/nvme/@devname" under the
 * sysfs root. Returns an allocated string or NULL. Caller must free.
 */
char *sysfs_nvme_path(const char *devname);

/*
 * The value of attribute @attr of controller @devname, without its
 * trailing newline. Returns an allocated string, or NULL if the attribute
 * cannot be read. Caller must free.
 */
char *sysfs_nvme_attr(const char *devname, const char *attr);

/*
 * Build a TID from controller @devname's sysfs attributes (transport,
 * address, subsysnqn, ...). If @is_dc is non-NULL, *is_dc is set true when
 * the controller's cntrltype is "discovery". Returns an allocated TID, or
 * NULL if the mandatory attributes are missing.
 */
struct libnvmf_tid *tid_from_sysfs(const char *devname, bool *is_dc);
