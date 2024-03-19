// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 * 	    Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 */
#include <stdio.h>
#include <string.h>
#include <dirent.h>

#include "filters.h"
#include "private.h"

int nvme_namespace_filter(const struct dirent *d)
{
	int i, n;

	if (d->d_name[0] == '.')
		return 0;

	if (strstr(d->d_name, "nvme"))
		if (sscanf(d->d_name, "nvme%dn%d", &i, &n) == 2)
			return 1;

	return 0;
}

int nvme_paths_filter(const struct dirent *d)
{
	int i, c, n;

	if (d->d_name[0] == '.')
		return 0;

	if (strstr(d->d_name, "nvme"))
		if (sscanf(d->d_name, "nvme%dc%dn%d", &i, &c, &n) == 3)
			return 1;

	return 0;
}

int nvme_ctrls_filter(const struct dirent *d)
{
	int i, c, n;

	if (d->d_name[0] == '.')
		return 0;

	if (strstr(d->d_name, "nvme")) {
		if (sscanf(d->d_name, "nvme%dc%dn%d", &i, &c, &n) == 3)
			return 0;
		if (sscanf(d->d_name, "nvme%dn%d", &i, &n) == 2)
			return 0;
		if (sscanf(d->d_name, "nvme%d", &i) == 1)
			return 1;
	}

	return 0;
}

int nvme_subsys_filter(const struct dirent *d)
{
	int i;

	if (d->d_name[0] == '.')
		return 0;

	if (strstr(d->d_name, "nvme-subsys"))
		if (sscanf(d->d_name, "nvme-subsys%d", &i) == 1)
			return 1;

	return 0;
}

int nvme_scan_subsystems(struct dirent ***subsys)
{
	const char *dir = nvme_subsys_sysfs_dir();

	return scandir(dir, subsys, nvme_subsys_filter, alphasort);
}

int nvme_scan_subsystem_namespaces(nvme_subsystem_t s, struct dirent ***ns)
{
	return scandir(nvme_subsystem_get_sysfs_dir(s), ns,
		       nvme_namespace_filter, alphasort);
}

int nvme_scan_ctrls(struct dirent ***ctrls)
{
	const char *dir = nvme_ctrl_sysfs_dir();

	return scandir(dir, ctrls, nvme_ctrls_filter, alphasort);
}

int nvme_scan_ctrl_namespace_paths(nvme_ctrl_t c, struct dirent ***paths)
{
	return scandir(nvme_ctrl_get_sysfs_dir(c), paths,
		       nvme_paths_filter, alphasort);
}

int nvme_scan_ctrl_namespaces(nvme_ctrl_t c, struct dirent ***ns)
{
	return scandir(nvme_ctrl_get_sysfs_dir(c), ns,
		       nvme_namespace_filter, alphasort);
}
