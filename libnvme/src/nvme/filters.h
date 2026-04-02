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

#include <nvme/tree.h>

/**
 * DOC: filters.h
 *
 * libnvme directory filter
 */

/**
 * libnvme_filter_namespace() - Filter for namespaces
 * @d: dirent to check
 *
 * Return: 1 if @d matches, 0 otherwise
 */
int libnvme_filter_namespace(const struct dirent *d);

/**
 * libnvme_filter_paths() - Filter for paths
 * @d: dirent to check
 *
 * Return: 1 if @d matches, 0 otherwise
 */
int libnvme_filter_paths(const struct dirent *d);

/**
 * libnvme_filter_ctrls() - Filter for controllers
 * @d: dirent to check
 *
 * Return: 1 if @d matches, 0 otherwise
 */
int libnvme_filter_ctrls(const struct dirent *d);

/**
 * libnvme_filter_subsys() - Filter for subsystems
 * @d: dirent to check
 *
 * Return: 1 if @d matches, 0 otherwise
 */
int libnvme_filter_subsys(const struct dirent *d);

/**
 * libnvme_scan_subsystems() - Scan for subsystems
 * @subsys: Pointer to array of dirents
 *
 * Return: number of entries in @subsys or a negative error code
 */
int libnvme_scan_subsystems(struct dirent ***subsys);

/**
 * libnvme_scan_subsystem_namespaces() - Scan for namespaces in a subsystem
 * @s: Subsystem to scan
 * @ns: Pointer to array of dirents
 *
 * Return: number of entries in @ns or a negative error code
 */
int libnvme_scan_subsystem_namespaces(libnvme_subsystem_t s,
		struct dirent ***ns);

/**
 * libnvme_scan_ctrls() - Scan for controllers
 * @ctrls: Pointer to array of dirents
 *
 * Return: number of entries in @ctrls or a negative error code
 */
int libnvme_scan_ctrls(struct dirent ***ctrls);

/**
 * libnvme_scan_ctrl_namespace_paths() - Scan for namespace paths in
 * a controller
 * @c: Controller to scan
 * @paths: Pointer to array of dirents
 *
 * Return: number of entries in @paths or a negative error code
 */
int libnvme_scan_ctrl_namespace_paths(libnvme_ctrl_t c, struct dirent ***paths);

/**
 * libnvme_scan_ctrl_namespaces() - Scan for namespaces in a controller
 * @c: Controller to scan
 * @ns: Pointer to array of dirents
 *
 * Return: number of entries in @ns or a negative error code
 */
int libnvme_scan_ctrl_namespaces(libnvme_ctrl_t c, struct dirent ***ns);

/**
 * libnvme_scan_ns_head_paths() - Scan for namespace paths
 * @head: Namespace head node to scan
 * @paths : Pointer to array of dirents
 *
 * Return: number of entries in @ents or a negative error code
 */
int libnvme_scan_ns_head_paths(libnvme_ns_head_t head, struct dirent ***paths);

#endif /* _LIBNVME_FILTERS_H */
