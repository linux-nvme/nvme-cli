// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <ccan/endian/endian.h>
#include <ccan/list/list.h>

#include <compiler-attributes.h>

#include <libnvme.h>

#include "cleanup.h"
#include "private-tree.h"
#include "private.h"
#include "util.h"

int libnvme_reconfigure_ctrl(__shr_unused struct libnvme_global_ctx *ctx,
		libnvme_ctrl_t c, const char *path, const char *name)
{
	/*
	 * It's necessary to release any resources first because a ctrl
	 * can be reused.
	 */
	libnvme_ctrl_release_transport_handle(c);
	FREE_CTRL_ATTR(c->name);
	FREE_CTRL_ATTR(c->sysfs_dir);
	libnvme_ctrl_sysfs_reset(c->sysfs);

	c->hdl = NULL;
	c->name = shr_xstrdup(name);
	c->sysfs_dir = shr_xstrdup(path);
	if (!c->name || !c->sysfs_dir) {
		FREE_CTRL_ATTR(c->name);
		FREE_CTRL_ATTR(c->sysfs_dir);
		return -ENOMEM;
	}

	if (!libnvme_ctrl_get_transport_handle(c))
		return -ENODEV;

	return 0;
}

__shr_public const char *libnvme_ctrl_get_state(libnvme_ctrl_t c)
{
	char *state = c->state;

	c->state = strdup("");
	free(state);
	return c->state;
}

__shr_public int libnvme_init_ctrl(__shr_unused libnvme_host_t h,
		__shr_unused libnvme_ctrl_t c,
		__shr_unused int instance)
{
	return -ENOTSUP;
}

int libnvme_get_ctrl_transport(__shr_unused struct libnvme_global_ctx *ctx,
		__shr_unused const char *path,
		__shr_unused const char *name, char **transport,
		char **traddr, char **addr, char **trsvcid,
		char **host_traddr, char **host_iface)
{
	*transport = NULL;
	*traddr = NULL;
	*addr = NULL;
	*trsvcid = NULL;
	*host_traddr = NULL;
	*host_iface = NULL;

	return -ENODEV;
}

__shr_public int libnvme_scan_ctrl(
		__shr_unused struct libnvme_global_ctx *ctx,
		__shr_unused const char *name,
		__shr_unused libnvme_ctrl_t *cp)
{
	return -ENODEV;
}

__shr_public char *libnvme_get_subsys_attr(
		__shr_unused libnvme_subsystem_t s,
		__shr_unused const char *attr)
{
	return NULL;
}

__shr_public char *libnvme_get_path_attr(
		__shr_unused libnvme_path_t p,
		__shr_unused const char *attr)
{
	return NULL;
}

__shr_public char *libnvme_get_attr(
		__shr_unused const char *dir,
		__shr_unused const char *attr)
{
	return NULL;
}

__shr_public char *libnvme_get_ctrl_attr(
		__shr_unused libnvme_ctrl_t c,
		__shr_unused const char *attr)
{
	return NULL;
}

__shr_public char *libnvme_get_ns_attr(
		__shr_unused libnvme_ns_t n,
		__shr_unused const char *attr)
{
	return NULL;
}

const char *libnvme_subsys_sysfs_dir(
		__shr_unused struct libnvme_global_ctx *ctx)
{
	return NULL;
}

const char *libnvme_ns_sysfs_dir(
		__shr_unused struct libnvme_global_ctx *ctx)
{
	return NULL;
}

int libnvme_ns_init(__shr_unused const char *path, struct libnvme_ns *ns)
{
	__cleanup_libnvme_free struct nvme_id_ns *id = NULL;
	uint8_t flbas;
	int ret;

	id = libnvme_alloc(sizeof(*id));
	if (!id)
		return -ENOMEM;

	ret = libnvme_ns_identify(ns, id);
	if (ret)
		return ret;

	nvme_id_ns_flbas_to_lbaf_inuse(id->flbas, &flbas);
	ns->lba_size = 1 << id->lbaf[flbas].ds;
	ns->lba_count = le64_to_cpu(id->nsze);
	ns->lba_util = le64_to_cpu(id->nuse);
	ns->meta_size = le16_to_cpu(id->lbaf[flbas].ms);

	return 0;
}

int libnvme_ns_open(struct libnvme_global_ctx *ctx,
		__shr_unused const char *sys_path,
		const char *name, libnvme_ns_t *ns)
{
	struct libnvme_transport_handle *hdl;
	struct libnvme_ns_head *head;
	struct libnvme_ns *n;
	int ret;

	n = calloc(1, sizeof(*n));
	if (!n)
		return -ENOMEM;

	head = calloc(1, sizeof(*head));
	if (!head) {
		free(n);
		return -ENOMEM;
	}

	head->n = n;
	list_head_init(&head->paths);

	n->ctx = ctx;
	n->head = head;
	n->hdl = NULL;
	n->name = strdup(name);
	n->generic_name = strdup(name);
	if (!n->name || !n->generic_name) {
		ret = -ENOMEM;
		goto free_ns;
	}

	/* Open the device to query the namespace ID */
	ret = libnvme_open(ctx, name, &hdl);
	if (ret)
		goto free_ns;

	ret = libnvme_get_nsid(hdl, &n->nsid);
	libnvme_close(hdl);
	if (ret)
		goto free_ns;

	ret = libnvme_ns_init(name, n);
	if (ret)
		goto free_ns;

	list_node_init(&n->entry);

	libnvme_ns_release_transport_handle(n);

	*ns = n;
	return 0;

free_ns:
	free(n->generic_name);
	free(n->name);
	free(head);
	free(n);
	return ret;
}

int __libnvme_scan_namespace(struct libnvme_global_ctx *ctx,
		__shr_unused const char *sysfs_dir,
		const char *name, libnvme_ns_t *ns)
{
	struct libnvme_ns *n = NULL;
	int ret;

	ret = libnvme_ns_open(ctx, NULL, name, &n);
	if (ret)
		return ret;

	n->sysfs_dir = strdup(name);
	if (!n->sysfs_dir) {
		libnvme_free_ns(n);
		return -ENOMEM;
	}

	*ns = n;
	return 0;
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
