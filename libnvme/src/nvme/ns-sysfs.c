// SPDX-License-Identifier: LGPL-2.1-or-later

/*
 * This file is part of libnvme.
 *
 * Copyright (c) 2025, Dell Technologies Inc. or its subsidiaries.
 * Authors: Martin Belanger <Martin.Belanger@dell.com>
 *
 *   ____                           _           _    ____          _
 *  / ___| ___ _ __   ___ _ __ __ _| |_ ___  __| |  / ___|___   __| | ___
 * | |  _ / _ \ '_ \ / _ \ '__/ _` | __/ _ \/ _` | | |   / _ \ / _` |/ _ \
 * | |_| |  __/ | | |  __/ | | (_| | ||  __/ (_| | | |__| (_) | (_| |  __/
 *  \____|\___|_| |_|\___|_|  \__,_|\__\___|\__,_|  \____\___/ \__,_|\___|
 *
 * Auto-generated struct member accessors (setter/getter)
 *
 * To update run: meson compile -C [BUILD-DIR] update-accessors
 * Or:            make update-accessors
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <compiler-attributes.h>

#include "private.h"
#include "private-tree.h"
#include "ns-sysfs.h"

struct libnvme_ns_sysfs {
	int *lba_size;
	int *lba_shift;
	uint64_t *lba_count;
	uint64_t *lba_util;
	int *meta_size;
	enum nvme_csi *csi;
	uint8_t *eui64;
	uint8_t *nguid;
	unsigned char *uuid;
	long command_retry_count;
	long command_error_count;
	long io_requeue_no_usable_path_count;
	long io_fail_no_available_path_count;
};

struct libnvme_ns_sysfs *libnvme_ns_sysfs_alloc(void)
{
	return calloc(1, sizeof(struct libnvme_ns_sysfs));
}

void libnvme_ns_sysfs_reset(
		struct libnvme_ns_sysfs *sysfs)
{
	if (!sysfs)
		return;

}

void libnvme_ns_sysfs_free(
		struct libnvme_ns_sysfs *sysfs)
{
	if (!sysfs)
		return;

	SYSFS_FREE(sysfs->lba_size);
	SYSFS_FREE(sysfs->lba_shift);
	SYSFS_FREE(sysfs->lba_count);
	SYSFS_FREE(sysfs->lba_util);
	SYSFS_FREE(sysfs->meta_size);
	SYSFS_FREE(sysfs->csi);
	SYSFS_FREE(sysfs->eui64);
	SYSFS_FREE(sysfs->nguid);
	SYSFS_FREE(sysfs->uuid);
	free(sysfs);
}

__shr_public int libnvme_ns_get_command_retry_count(
		const struct libnvme_ns *p,
		long *val,
		long dflt)
{
	struct libnvme_ns *c = (struct libnvme_ns *)p;
	__cleanup_free char *str = NULL;

	*val = dflt;

	str = libnvme_get_ns_attr(c, "diag/command_retry_count");
	if (!str)
		return -ENOENT;

	if (sscanf(str, "%ld", &c->sysfs->command_retry_count) != 1)
		return -EINVAL;

	*val = c->sysfs->command_retry_count;
	return 0;
}

__shr_public int libnvme_ns_get_command_error_count(
		const struct libnvme_ns *p,
		long *val,
		long dflt)
{
	struct libnvme_ns *c = (struct libnvme_ns *)p;
	__cleanup_free char *str = NULL;

	*val = dflt;

	str = libnvme_get_ns_attr(c, "diag/command_error_count");
	if (!str)
		return -ENOENT;

	if (sscanf(str, "%ld", &c->sysfs->command_error_count) != 1)
		return -EINVAL;

	*val = c->sysfs->command_error_count;
	return 0;
}

__shr_public int libnvme_ns_get_io_requeue_no_usable_path_count(
		const struct libnvme_ns *p,
		long *val,
		long dflt)
{
	struct libnvme_ns *c = (struct libnvme_ns *)p;
	__cleanup_free char *str = NULL;

	*val = dflt;

	str = libnvme_get_ns_attr(c, "diag/io_requeue_no_usable_path_count");
	if (!str)
		return -ENOENT;

	if (sscanf(str, "%ld", &c->sysfs->io_requeue_no_usable_path_count) != 1)
		return -EINVAL;

	*val = c->sysfs->io_requeue_no_usable_path_count;
	return 0;
}

__shr_public int libnvme_ns_get_io_fail_no_available_path_count(
		const struct libnvme_ns *p,
		long *val,
		long dflt)
{
	struct libnvme_ns *c = (struct libnvme_ns *)p;
	__cleanup_free char *str = NULL;

	*val = dflt;

	str = libnvme_get_ns_attr(c, "diag/io_fail_no_available_path_count");
	if (!str)
		return -ENOENT;

	if (sscanf(str, "%ld", &c->sysfs->io_fail_no_available_path_count) != 1)
		return -EINVAL;

	*val = c->sysfs->io_fail_no_available_path_count;
	return 0;
}

