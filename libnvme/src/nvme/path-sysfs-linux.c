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

__shr_public int libnvme_path_get_ana_state(
		const struct libnvme_path *p,
		const char **val,
		const char *dflt)
{
	struct libnvme_path *c = (struct libnvme_path *)p;
	__cleanup_free char *str = NULL;

	*val = dflt;

	str = libnvme_get_path_attr(c, "ana_state");
	if (!str)
		return -ENOENT;

	if (!c->sysfs->ana_state || strcmp(str, c->sysfs->ana_state)) {
		free(c->sysfs->ana_state);
		c->sysfs->ana_state = strdup(str);
		if (!c->sysfs->ana_state)
			return -ENOMEM;
	}

	*val = c->sysfs->ana_state;
	return 0;
}

__shr_public int libnvme_path_get_numa_nodes(
		const struct libnvme_path *p,
		const char **val,
		const char *dflt)
{
	struct libnvme_path *c = (struct libnvme_path *)p;

	*val = dflt;

	if (__shr_unlikely(!SYSFS_IS_LOADED(c->sysfs->numa_nodes))) {
		c->sysfs->numa_nodes = libnvme_get_path_attr(c, "numa_nodes");
		if (!c->sysfs->numa_nodes)
			c->sysfs->numa_nodes = NO_SYSFS_ATTR;
	}

	if (SYSFS_IS_ABSENT(c->sysfs->numa_nodes))
		return -ENOENT;

	*val = c->sysfs->numa_nodes;
	return 0;
}

__shr_public int libnvme_path_get_grpid(
		const struct libnvme_path *p,
		int *val,
		int dflt)
{
	struct libnvme_path *c = (struct libnvme_path *)p;

	*val = dflt;

	if (__shr_unlikely(!SYSFS_IS_LOADED(c->sysfs->grpid))) {
		__cleanup_free char *str = NULL;

		str = libnvme_get_path_attr(c, "ana_grpid");
		if (!str)
			c->sysfs->grpid = (int *)NO_SYSFS_ATTR;
		else {
			c->sysfs->grpid = malloc(sizeof(int));
			if (!c->sysfs->grpid)
				return -ENOMEM;
			if (sscanf(str, "%d", c->sysfs->grpid) != 1) {
				free(c->sysfs->grpid);
				c->sysfs->grpid = NULL;
				return -EINVAL;
			}
		}
	}

	if (SYSFS_IS_ABSENT(c->sysfs->grpid))
		return -ENOENT;

	*val = *c->sysfs->grpid;
	return 0;
}

__shr_public int libnvme_path_get_queue_depth(
		const struct libnvme_path *p,
		int *val,
		int dflt)
{
	struct libnvme_path *c = (struct libnvme_path *)p;
	__cleanup_free char *str = NULL;

	*val = dflt;

	str = libnvme_get_path_attr(c, "queue_depth");
	if (!str)
		return -ENOENT;

	if (sscanf(str, "%d", &c->sysfs->queue_depth) != 1)
		return -EINVAL;

	*val = c->sysfs->queue_depth;
	return 0;
}

__shr_public int libnvme_path_get_multipath_failover_count(
		const struct libnvme_path *p,
		long *val,
		long dflt)
{
	struct libnvme_path *c = (struct libnvme_path *)p;
	__cleanup_free char *str = NULL;

	*val = dflt;

	str = libnvme_get_path_attr(c, "diag/multipath_failover_count");
	if (!str)
		return -ENOENT;

	if (sscanf(str, "%ld", &c->sysfs->multipath_failover_count) != 1)
		return -EINVAL;

	*val = c->sysfs->multipath_failover_count;
	return 0;
}

__shr_public int libnvme_path_get_command_retry_count(
		const struct libnvme_path *p,
		long *val,
		long dflt)
{
	struct libnvme_path *c = (struct libnvme_path *)p;
	__cleanup_free char *str = NULL;

	*val = dflt;

	str = libnvme_get_path_attr(c, "diag/command_retry_count");
	if (!str)
		return -ENOENT;

	if (sscanf(str, "%ld", &c->sysfs->command_retry_count) != 1)
		return -EINVAL;

	*val = c->sysfs->command_retry_count;
	return 0;
}

__shr_public int libnvme_path_get_command_error_count(
		const struct libnvme_path *p,
		long *val,
		long dflt)
{
	struct libnvme_path *c = (struct libnvme_path *)p;
	__cleanup_free char *str = NULL;

	*val = dflt;

	str = libnvme_get_path_attr(c, "diag/command_error_count");
	if (!str)
		return -ENOENT;

	if (sscanf(str, "%ld", &c->sysfs->command_error_count) != 1)
		return -EINVAL;

	*val = c->sysfs->command_error_count;
	return 0;
}

