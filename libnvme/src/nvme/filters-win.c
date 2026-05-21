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
#include "private-storageport.h"
#include "compiler-attributes.h"

__libnvme_public int libnvme_scan_subsystems(struct dirent ***subsys)
{
	(void)subsys;
	return 0;
}

__libnvme_public int libnvme_scan_subsystem_namespaces(libnvme_subsystem_t s,
		struct dirent ***ns)
{
	(void)s;
	(void)ns;
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

	libnvme_storageport_map_clear();
	ret = libnvme_storageport_map_init();
	if (ret)
		return ret;

	count = libnvme_storageport_map_get_count();
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
			 libnvme_storageport_map_get_name(i));
	}

	*ctrls = entries;
	return (int)count;

enomem:
	libnvme_storageport_map_clear();
	if (entries) {
		while (i > 0)
			free(entries[--i]);
		free(entries);
	}
	return -ENOMEM;
}

__libnvme_public int libnvme_scan_ctrl_namespace_paths(libnvme_ctrl_t c,
		struct dirent ***paths)
{
	(void)c;
	(void)paths;
	return 0;
}

__libnvme_public int libnvme_scan_ctrl_namespaces(libnvme_ctrl_t c, struct dirent ***ns)
{
	struct dirent **entries = NULL;
	const struct storageport_map_entry *sp_entry;
	DWORD *device_numbers = NULL;
	int dev_count = 0;
	int ret;
	int i;

	if (!c || !ns)
		return -EINVAL;

	*ns = NULL;

	sp_entry = libnvme_storageport_lookup_entry(c->name);
	if (!sp_entry)
		return 0;

	ret = libnvme_storageport_scan_device_numbers(sp_entry,
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

__libnvme_public int libnvme_scan_ns_head_paths(libnvme_ns_head_t head,
		struct dirent ***paths)
{
	(void)head;
	(void)paths;
	return 0;
}
