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
 * DOC: filters.h
 *
 * libnvme directory filter
 */

/**
 * nvme_namespace_filter() - Filter for namespaces
 * @d: dirent to check
 *
 * Return: 1 if @d matches, 0 otherwise
 */
int nvme_namespace_filter(const struct dirent *d);

/**
 * nvme_paths_filter() - Filter for paths
 * @d: dirent to check
 *
 * Return: 1 if @d matches, 0 otherwise
 */
int nvme_paths_filter(const struct dirent *d);

/**
 * nvme_ctrls_filter() - Filter for controllers
 * @d: dirent to check
 *
 * Return: 1 if @d matches, 0 otherwise
 */
int nvme_ctrls_filter(const struct dirent *d);

/**
 * nvme_subsys_filter() - Filter for subsystems
 * @d: dirent to check
 *
 * Return: 1 if @d matches, 0 otherwise
 */
int nvme_subsys_filter(const struct dirent *d);

/**
 * nvme_scan_subsystems() - Scan for subsystems
 * @subsys: Pointer to array of dirents
 *
 * Return: number of entries in @subsys
 */
int nvme_scan_subsystems(struct dirent ***subsys);

/**
 * nvme_scan_subsystem_namespaces() - Scan for namespaces in a subsystem
 * @s: Subsystem to scan
 * @ns: Pointer to array of dirents
 *
 * Return: number of entries in @ns
 */
int nvme_scan_subsystem_namespaces(nvme_subsystem_t s, struct dirent ***ns);

/**
 * nvme_scan_ctrls() - Scan for controllers
 * @ctrls: Pointer to array of dirents
 *
 * Return: number of entries in @ctrls
 */
int nvme_scan_ctrls(struct dirent ***ctrls);

/**
 * nvme_scan_ctrl_namespace_paths() - Scan for namespace paths in a controller
 * @c: Controller to scan
 * @paths: Pointer to array of dirents
 *
 * Return: number of entries in @paths
 */
int nvme_scan_ctrl_namespace_paths(nvme_ctrl_t c, struct dirent ***paths);

/**
 * nvme_scan_ctrl_namespaces() - Scan for namespaces in a controller
 * @c: Controller to scan
 * @ns: Pointer to array of dirents
 *
 * Return: number of entries in @ns
 */
int nvme_scan_ctrl_namespaces(nvme_ctrl_t c, struct dirent ***ns);

#endif /* _LIBNVME_FILTERS_H */
