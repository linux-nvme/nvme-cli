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
		__shr_unused const struct libnvme_path *p,
		const char **val,
		const char *dflt)
{
	*val = dflt;

	return -ENOENT;
}

__shr_public int libnvme_path_get_numa_nodes(
		__shr_unused const struct libnvme_path *p,
		const char **val,
		const char *dflt)
{
	*val = dflt;

	return -ENOENT;
}

__shr_public int libnvme_path_get_grpid(
		__shr_unused const struct libnvme_path *p,
		int *val,
		int dflt)
{
	*val = dflt;

	return -ENOENT;
}

__shr_public int libnvme_path_get_queue_depth(
		__shr_unused const struct libnvme_path *p,
		int *val,
		int dflt)
{
	*val = dflt;

	return -ENOENT;
}

__shr_public int libnvme_path_get_multipath_failover_count(
		__shr_unused const struct libnvme_path *p,
		long *val,
		long dflt)
{
	*val = dflt;

	return -ENOENT;
}

__shr_public int libnvme_path_get_command_retry_count(
		__shr_unused const struct libnvme_path *p,
		long *val,
		long dflt)
{
	*val = dflt;

	return -ENOENT;
}

__shr_public int libnvme_path_get_command_error_count(
		__shr_unused const struct libnvme_path *p,
		long *val,
		long dflt)
{
	*val = dflt;

	return -ENOENT;
}

