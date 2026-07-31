/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of libnvme.
 * Copyright (c) 2026, Micron Technology, Inc.
 *
 * Authors: Brandon Capener <bcapener@micron.com>
 */
#pragma once

#include "cleanup.h"
#include <nvme/tree.h>

#define FREE_CTRL_ATTR(a) \
	do { free(a); (a) = NULL; } while (0)

/* Placeholder identity for a controller with none of its own (e.g.
 * PCIe) -- fixed, not resolved/generated, so it's deterministic.
 */
#define NVME_DEFAULT_HOSTNQN \
	"nqn.2014-08.org.nvmexpress:uuid:00000000-0000-0000-0000-000000000000"
#define NVME_DEFAULT_HOSTID "00000000-0000-0000-0000-000000000000"

char *libnvme_hostid_from_hostnqn(const char *hostnqn);
/**
 * libnvme_parse_src_addr - Extract the source address from an address string
 * @ctx:		libnvme global context
 * @address:		Address string to parse (may be NULL)
 * @src_addr:		Buffer to store the extracted source address
 * @src_addr_len:	Size of @src_addr
 *
 * Return: @src_addr on success, or NULL if @address has no src_addr field
 *	   or @src_addr is too small.
 */
char *libnvme_parse_src_addr(struct libnvme_global_ctx *ctx,
		const char *address, char *src_addr, size_t src_addr_len);

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
 * @ctx:		libnvme global context
 * @path:		Path to the controller
 * @name:		Name of the controller
 * @transport:		Pointer to store the transport type
 * @traddr:		Pointer to store the transport address
 * @addr:		Pointer to store the address
 * @trsvcid:		Pointer to store the transport service ID (optional)
 * @host_traddr:	Pointer to store the host transport address (optional)
 * @host_iface:		Pointer to store the host interface (optional)
 *
 * Return: 0 on success or negative error code otherwise
 */
int libnvme_get_ctrl_transport(struct libnvme_global_ctx *ctx,
		const char *path, const char *name,
		char **transport, char **traddr, char **addr, char **trsvcid,
		char **host_traddr, char **host_iface);

int libnvme_init_subsystem(libnvme_subsystem_t s, const char *name);

int libnvme_ns_init(const char *path, struct libnvme_ns *ns);

int libnvme_ns_open(struct libnvme_global_ctx *ctx, const char *sys_path,
		    const char *name, libnvme_ns_t *ns);

int __libnvme_scan_namespace(struct libnvme_global_ctx *ctx,
		const char *sysfs_dir, const char *name, libnvme_ns_t *ns);
