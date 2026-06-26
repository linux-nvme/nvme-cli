// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 *	    Daniel Wagner <dwagner@suse.de>
 */
#pragma once

#include <dirent.h>

#include <nvme/tree.h>

/**
 * DOC: scan.h
 */

/**
 * libnvme_scan_subsystems() - Scan for subsystems
 * @ctx: &struct libnvme_global_ctx object
 * @subsys: Pointer to array of dirents
 *
 * Return: number of entries in @subsys or a negative error code
 */
int libnvme_scan_subsystems(struct libnvme_global_ctx *ctx,
		struct dirent ***subsys);

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
 * @ctx: &struct libnvme_global_ctx object
 * @ctrls: Pointer to array of dirents
 *
 * Return: number of entries in @ctrls or a negative error code
 */
int libnvme_scan_ctrls(struct libnvme_global_ctx *ctx,
		struct dirent ***ctrls);

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
