// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 * 	    Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <libgen.h>

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

#include "filters.h"
#include "types.h"
#include "util.h"

const char *nvme_ctrl_sysfs_dir = "/sys/class/nvme";
const char *nvme_ns_sysfs_dir = "/sys/block";
const char *nvme_subsys_sysfs_dir = "/sys/class/nvme-subsystem";

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
	return scandir(nvme_subsys_sysfs_dir, subsys, nvme_subsys_filter,
		       alphasort);
}

int nvme_scan_subsystem_ctrls(nvme_subsystem_t s, struct dirent ***ctrls)
{
	return scandir(nvme_subsystem_get_sysfs_dir(s), ctrls,
		       nvme_ctrls_filter, alphasort);
}

int nvme_scan_subsystem_namespaces(nvme_subsystem_t s, struct dirent ***namespaces)
{
	return scandir(nvme_subsystem_get_sysfs_dir(s), namespaces,
		       nvme_namespace_filter, alphasort);
}

int nvme_scan_ctrl_namespace_paths(nvme_ctrl_t c, struct dirent ***namespaces)
{
	return scandir(nvme_ctrl_get_sysfs_dir(c), namespaces,
		       nvme_paths_filter, alphasort);
}

int nvme_scan_ctrl_namespaces(nvme_ctrl_t c, struct dirent ***namespaces)
{
	return scandir(nvme_ctrl_get_sysfs_dir(c), namespaces,
		       nvme_namespace_filter, alphasort);
}
