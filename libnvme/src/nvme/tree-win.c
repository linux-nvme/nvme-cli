// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 Micron Technology, Inc.
 *
 * Authors: Brandon Capener <bcapener@micron.com>
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/stat.h>
#include <sys/types.h>

#include <libnvme.h>

#include "cleanup.h"
#include "private.h"
#include "private-tree.h"
#include "compiler-attributes.h"


int libnvme_reconfigure_ctrl(struct libnvme_global_ctx *ctx,
		libnvme_ctrl_t c, const char *path, const char *name)
{
	return -ENOTSUP;
}

__libnvme_public int libnvme_get_host(struct libnvme_global_ctx *ctx,
	const char *hostnqn, const char *hostid, libnvme_host_t *host)
{
	return -ENOTSUP;
}

__libnvme_public const char *libnvme_ctrl_get_state(libnvme_ctrl_t c)
{
	return NULL;
}

__libnvme_public int libnvme_init_ctrl(__libnvme_unused libnvme_host_t h,
				       __libnvme_unused libnvme_ctrl_t c,
				       __libnvme_unused int instance)
{
	return -ENOTSUP;
}

int libnvme_get_ctrl_transport(__libnvme_unused const char *path,
			       const char *name, char **transport,
			       char **traddr, char **addr, char **trsvcid,
			       char **host_traddr, char **host_iface)
{
	return -ENOTSUP;
}


__libnvme_public int libnvme_scan_ctrl(struct libnvme_global_ctx *ctx,
				       const char *name, libnvme_ctrl_t *cp)
{
	return -ENOTSUP;
}

__libnvme_public char *libnvme_get_subsys_attr(
	__libnvme_unused libnvme_subsystem_t s,
	__libnvme_unused const char *attr)
{
	return NULL;
}

__libnvme_public char *libnvme_get_path_attr(
	__libnvme_unused libnvme_path_t p,
	__libnvme_unused const char *attr)
{
	return NULL;
}

__libnvme_public char *libnvme_get_attr(
	__libnvme_unused const char *dir,
	__libnvme_unused const char *attr)
{
	return NULL;
}

__libnvme_public char *libnvme_get_ctrl_attr(
	__libnvme_unused libnvme_ctrl_t c,
	__libnvme_unused const char *attr)
{
	return NULL;
}

__libnvme_public char *libnvme_get_ns_attr(
	__libnvme_unused libnvme_ns_t n,
	__libnvme_unused const char *attr)
{
	return NULL;
}

const char *libnvme_subsys_sysfs_dir(void)
{
	return NULL;
}

const char *libnvme_ns_sysfs_dir(void)
{
	return NULL;
}

int libnvme_ns_init(const char *path, struct libnvme_ns *ns)
{
	return -ENOTSUP;
}

int libnvme_ns_open(struct libnvme_global_ctx *ctx,
		    __libnvme_unused const char *sys_path,
		    const char *name, libnvme_ns_t *ns)
{
	return -ENOTSUP;
}

int __libnvme_scan_namespace(struct libnvme_global_ctx *ctx,
			     __libnvme_unused const char *sysfs_dir,
			     const char *name, libnvme_ns_t *ns)
{
	return -ENOTSUP;
}

int libnvme_init_subsystem(libnvme_subsystem_t s, const char *name)
{
	s->subsystype = strdup("nvm");
	if (!s->subsystype)
		return -ENOMEM;

	s->name = strdup(name);
	if (!s->name) {
		free(s->subsystype);
		return -ENOMEM;
	}

	return 0;
}
