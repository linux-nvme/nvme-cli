/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of libnvme.
 * Copyright (c) 2026, Micron Technology, Inc.
 *
 * Authors: Brandon Capener <bcapener@micron.com>
 */
#pragma once

#include <nvme/tree.h>

int libnvme_ctrl_alloc(struct libnvme_global_ctx *ctx, libnvme_subsystem_t s,
		const char *path, const char *name, libnvme_ctrl_t *cp);

int libnvme_ctrl_scan_namespaces(struct libnvme_global_ctx *ctx,
		struct libnvme_ctrl *c);

int libnvme_ctrl_scan_paths(struct libnvme_global_ctx *ctx,
			struct libnvme_ctrl *c);

int libnvme_reconfigure_ctrl(struct libnvme_global_ctx *ctx,
		libnvme_ctrl_t c, const char *path, const char *name);

/**
 * libnvme_get_ctrl_transport - Get transport type and address for a controller
 * @path:		Path to the controller
 * @name:		Name of the controller
 * @transport:		Pointer to store the transport type
 * @traddr:		Pointer to store the transport address
 * @addr:		Pointer to store the address
 *
 * Return: 0 on success or negative error code otherwise
 */
int libnvme_get_ctrl_transport(const char *path, const char *name,
		char **transport, char **traddr, char **addr);

int libnvme_ns_init(const char *path, struct libnvme_ns *ns);

int libnvme_ns_open(struct libnvme_global_ctx *ctx, const char *sys_path,
		    const char *name, libnvme_ns_t *ns);

int __libnvme_scan_namespace(struct libnvme_global_ctx *ctx,
		const char *sysfs_dir, const char *name, libnvme_ns_t *ns);
