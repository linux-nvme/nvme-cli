// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 Micron Technology, Inc.
 *
 * Authors: Brandon Capener <bcapener@micron.com>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libnvme.h>

#include "private.h"
#include "private-ctrl-map.h"
#include "compiler-attributes.h"

__libnvme_public int libnvme_scan_subsystems(
	__libnvme_unused struct dirent ***subsys)
{
	return 0;
}

__libnvme_public int libnvme_scan_subsystem_namespaces(
	__libnvme_unused libnvme_subsystem_t s,
	__libnvme_unused struct dirent ***ns)
{
	return 0;
}

__libnvme_public int libnvme_scan_ctrls(struct dirent ***ctrls)
{
	struct dirent **entries;
	size_t i, count;
	int ret;

	if (!ctrls)
		return -EINVAL;

	*ctrls = NULL;

	libnvme_ctrl_map_clear();
	ret = libnvme_ctrl_map_init();
	if (ret)
		return ret;

	count = libnvme_ctrl_map_get_count();
	if (!count)
		return 0;

	entries = calloc(count, sizeof(*entries));
	if (!entries)
		goto enomem;

	for (i = 0; i < count; i++) {
		entries[i] = calloc(1, sizeof(*entries[i]));
		if (!entries[i])
			goto enomem;
		snprintf(entries[i]->d_name,
			 sizeof(entries[i]->d_name), "%s",
			 libnvme_ctrl_map_get_name(i));
	}

	*ctrls = entries;
	return (int)count;

enomem:
	libnvme_ctrl_map_clear();
	if (entries) {
		while (i > 0)
			free(entries[--i]);
		free(entries);
	}
	return -ENOMEM;
}

__libnvme_public int libnvme_scan_ctrl_namespace_paths(
	__libnvme_unused libnvme_ctrl_t c,
	__libnvme_unused struct dirent ***paths)
{
	return 0;
}

__libnvme_public int libnvme_scan_ctrl_namespaces(libnvme_ctrl_t c,
						  struct dirent ***ns)
{
	struct dirent **entries = NULL;
	const struct ctrl_map_entry *ctrl_entry;
	DWORD *device_numbers = NULL;
	int dev_count = 0;
	int ret;
	int i;

	if (!c || !ns)
		return -EINVAL;

	*ns = NULL;

	ctrl_entry = libnvme_ctrl_map_lookup(c->name);
	if (!ctrl_entry)
		return 0;

	ret = libnvme_ctrl_map_entry_scan_device_numbers(ctrl_entry,
							 &device_numbers,
							 &dev_count);
	if (ret)
		return ret;

	if (!dev_count)
		return 0;

	entries = calloc(dev_count, sizeof(*entries));
	if (!entries) {
		free(device_numbers);
		return -ENOMEM;
	}

	for (i = 0; i < dev_count; i++) {
		entries[i] = calloc(1, sizeof(*entries[i]));
		if (!entries[i])
			goto enomem;

		snprintf(entries[i]->d_name,
			 sizeof(entries[i]->d_name),
			 "\\\\.\\PhysicalDrive%lu",
			 device_numbers[i]);
	}

	free(device_numbers);
	*ns = entries;
	return dev_count;

enomem:
	while (i > 0)
		free(entries[--i]);
	free(entries);
	free(device_numbers);
	return -ENOMEM;
}

__libnvme_public int libnvme_scan_ns_head_paths(
	__libnvme_unused libnvme_ns_head_t head,
	__libnvme_unused struct dirent ***paths)
{
	return 0;
}
