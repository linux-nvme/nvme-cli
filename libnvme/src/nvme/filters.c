// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 * 	    Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 */
#include <dirent.h>
#include <stdio.h>
#include <string.h>

#include <libnvme.h>

#include "private.h"

LIBNVME_PUBLIC int nvme_filter_namespace(const struct dirent *d)
{
	int i, n;

	if (d->d_name[0] == '.')
		return 0;

	if (strstr(d->d_name, "nvme"))
		if (sscanf(d->d_name, "nvme%dn%d", &i, &n) == 2)
			return 1;

	return 0;
}

LIBNVME_PUBLIC int nvme_filter_paths(const struct dirent *d)
{
	int i, c, n;

	if (d->d_name[0] == '.')
		return 0;

	if (strstr(d->d_name, "nvme"))
		if (sscanf(d->d_name, "nvme%dc%dn%d", &i, &c, &n) == 3)
			return 1;

	return 0;
}

LIBNVME_PUBLIC int nvme_filter_ctrls(const struct dirent *d)
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

LIBNVME_PUBLIC int nvme_filter_subsys(const struct dirent *d)
{
	int i;

	if (d->d_name[0] == '.')
		return 0;

	if (strstr(d->d_name, "nvme-subsys"))
		if (sscanf(d->d_name, "nvme-subsys%d", &i) == 1)
			return 1;

	return 0;
}

LIBNVME_PUBLIC int nvme_scan_subsystems(struct dirent ***subsys)
{
	const char *dir = nvme_subsys_sysfs_dir();
	int ret;

	ret = scandir(dir, subsys, nvme_filter_subsys, alphasort);
	if (ret < 0)
		return -errno;

	return ret;
}

LIBNVME_PUBLIC int nvme_scan_subsystem_namespaces(
		nvme_subsystem_t s,
		struct dirent ***ns)
{
	int ret;

	ret = scandir(nvme_subsystem_get_sysfs_dir(s), ns,
		       nvme_filter_namespace, alphasort);
	if (ret < 0)
		return -errno;

	return ret;
}

LIBNVME_PUBLIC int nvme_scan_ctrls(struct dirent ***ctrls)
{
	const char *dir = nvme_ctrl_sysfs_dir();
	int ret;

	ret = scandir(dir, ctrls, nvme_filter_ctrls, alphasort);
	if (ret < 0)
		return -errno;

	return ret;
}

LIBNVME_PUBLIC int nvme_scan_ctrl_namespace_paths(
		nvme_ctrl_t c,
		struct dirent ***paths)
{
	int ret;

	ret = scandir(nvme_ctrl_get_sysfs_dir(c), paths,
		       nvme_filter_paths, alphasort);
	if (ret < 0)
		return -errno;

	return ret;
}

LIBNVME_PUBLIC int nvme_scan_ctrl_namespaces(nvme_ctrl_t c, struct dirent ***ns)
{
	int ret;

	ret = scandir(nvme_ctrl_get_sysfs_dir(c), ns,
		       nvme_filter_namespace, alphasort);
	if (ret < 0)
		return -errno;

	return ret;
}

int nvme_scan_ns_head_paths(nvme_ns_head_t head, struct dirent ***paths)
{
	int ret;

	ret = scandir(nvme_ns_head_get_sysfs_dir(head), paths,
		       nvme_filter_paths, alphasort);
	if (ret < 0)
		return -errno;

	return ret;
}
