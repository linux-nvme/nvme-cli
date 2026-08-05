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
#include "path-sysfs.h"

struct libnvme_path_sysfs {
	char *ana_state;
	char *numa_nodes;
	int *grpid;
	volatile int queue_depth;
	volatile long multipath_failover_count;
	volatile long command_retry_count;
	volatile long command_error_count;
};

struct libnvme_path_sysfs *libnvme_path_sysfs_alloc(void)
{
	return calloc(1, sizeof(struct libnvme_path_sysfs));
}

void libnvme_path_sysfs_reset(
		struct libnvme_path_sysfs *sysfs)
{
	if (!sysfs)
		return;

}

void libnvme_path_sysfs_free(
		struct libnvme_path_sysfs *sysfs)
{
	if (!sysfs)
		return;

	SYSFS_FREE(sysfs->ana_state);
	SYSFS_FREE(sysfs->numa_nodes);
	SYSFS_FREE(sysfs->grpid);
	free(sysfs);
}

