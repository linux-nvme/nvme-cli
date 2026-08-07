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

#include "../private.h"
#include "../private-tree.h"
#include "path-attrs.h"

struct libnvme_path_attrs {
	char *ana_state;
	char *numa_nodes;
	int *grpid;
	int queue_depth;
	long multipath_failover_count;
	long command_retry_count;
	long command_error_count;
};

struct libnvme_path_attrs *libnvme_path_attrs_alloc(void)
{
	return calloc(1, sizeof(struct libnvme_path_attrs));
}

void libnvme_path_attrs_reset(
		struct libnvme_path_attrs *attrs)
{
	if (!attrs)
		return;

}

void libnvme_path_attrs_free(
		struct libnvme_path_attrs *attrs)
{
	if (!attrs)
		return;

	ATTR_FREE(attrs->ana_state);
	ATTR_FREE(attrs->numa_nodes);
	ATTR_FREE(attrs->grpid);
	free(attrs);
}

