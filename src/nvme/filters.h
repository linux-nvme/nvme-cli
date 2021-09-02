// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 */

#ifndef _LIBNVME_FILTERS_H
#define _LIBNVME_FILTERS_H

#include <dirent.h>
#include "tree.h"

/**
 * nvme_namespace_filter() -
 * @d:
 *
 * Return: 
 */
int nvme_namespace_filter(const struct dirent *d);

/**
 * nvme_paths_filter() -
 * @d:
 *
 * Return: 
 */
int nvme_paths_filter(const struct dirent *d);

/**
 * nvme_ctrls_filter() -
 * @d:
 *
 * Return: 
 */
int nvme_ctrls_filter(const struct dirent *d);

/**
 * nvme_subsys_filter() -
 * @d:
 *
 * Return: 
 */
int nvme_subsys_filter(const struct dirent *d);

/**
 * nvme_scan_subsystems() -
 * @subsys:
 *
 * Return: 
 */
int nvme_scan_subsystems(struct dirent ***subsys);

/**
 * nvme_scan_subsystem_ctrls() -
 * @s:
 * @ctrls:
 *
 * Return: 
 */
int nvme_scan_subsystem_ctrls(nvme_subsystem_t s, struct dirent ***ctrls);

/**
 * nvme_scan_subsystem_namespaces() -
 * @s:
 * @namespaces:
 *
 * Return: 
 */
int nvme_scan_subsystem_namespaces(nvme_subsystem_t s, struct dirent ***namespaces);

/**
 * nvme_scan_ctrl_namespace_paths() -
 * @c:
 * @namespaces:
 *
 * Return: 
 */
int nvme_scan_ctrl_namespace_paths(nvme_ctrl_t c, struct dirent ***namespaces);

/**
 * nvme_scan_ctrl_namespaces() -
 * @c:
 * @namespaces:
 *
 * Return: 
 */
int nvme_scan_ctrl_namespaces(nvme_ctrl_t c, struct dirent ***namespaces);

#endif /* _LIBNVME_FILTERS_H */
