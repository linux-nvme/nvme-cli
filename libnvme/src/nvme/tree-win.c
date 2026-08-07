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

#include <ccan/endian/endian.h>
#include <ccan/list/list.h>

#include <compiler-attributes.h>

#include <libnvme.h>

#include "cleanup.h"
#include "private.h"
#include "private-ctrl-map.h"
#include "private-tree.h"
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
	libnvme_ctrl_attrs_reset(c->attrs);

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

int libnvme_get_ctrl_transport(struct libnvme_global_ctx *ctx,
		__shr_unused const char *path,
		const char *name, char **transport,
		char **traddr, char **addr, char **trsvcid,
		char **host_traddr, char **host_iface)
{
	const struct ctrl_map_entry *ctrl_entry;
	int ret;

	*transport = NULL;
	*traddr = NULL;
	*addr = NULL;
	*trsvcid = NULL;
	*host_traddr = NULL;
	*host_iface = NULL;

	ctrl_entry = libnvme_ctrl_map_lookup(ctx, name);
	if (!ctrl_entry)
		return -ENODEV;

	*transport = strdup("pcie");
	if (!*transport)
		return -ENOMEM;

	ret = libnvme_ctrl_map_entry_get_pci_address(ctrl_entry, addr);
	if (ret || !*addr) {
		ret = -ENXIO;
		goto free_transport;
	}

	*traddr = strdup(*addr);
	if (!*traddr) {
		ret = -ENOMEM;
		goto free_transport;
	}
	return 0;
free_transport:
	free(*transport);
	*transport = NULL;
	free(*addr);
	*addr = NULL;
	return ret;
}

static libnvme_subsystem_t libnvme_get_subsystem_windows(libnvme_host_t h,
		const struct ctrl_map_entry *ctrl_entry)
{
	libnvme_subsystem_t s;
	char *subsysnqn;
	char *subsysname;
	int ret;

	subsysnqn = libnvme_ctrl_map_entry_get_subnqn(ctrl_entry);
	if (!subsysnqn)
		return NULL;

	subsysname = libnvme_ctrl_map_entry_get_subsys_name(ctrl_entry);
	if (!subsysname) {
		free(subsysnqn);
		return NULL;
	}

	ret = libnvme_get_subsystem(h->ctx, h, subsysname, subsysnqn, &s);
	free(subsysnqn);
	free(subsysname);
	if (ret)
		return NULL;

	/*
	 * Populate subsystem info from first controller. Windows has no
	 * sysfs to lazily read these from, so push them in from the ctrl
	 * map instead -- but only the first time this subsystem is seen,
	 * matching the sysfs-backed getters' own "cache once" semantics.
	 */
	{
		const char *cur;

		if (libnvme_subsystem_get_serial(s, &cur, NULL)) {
			__cleanup_free char *serial =
				libnvme_ctrl_map_entry_get_serial(ctrl_entry);
			libnvme_subsystem_set_serial(s, serial);
		}
		if (libnvme_subsystem_get_model(s, &cur, NULL)) {
			__cleanup_free char *model =
				libnvme_ctrl_map_entry_get_model(ctrl_entry);
			libnvme_subsystem_set_model(s, model);
		}
		if (libnvme_subsystem_get_firmware(s, &cur, NULL)) {
			__cleanup_free char *firmware =
				libnvme_ctrl_map_entry_get_firmware(ctrl_entry);
			libnvme_subsystem_set_firmware(s, firmware);
		}
	}

	return s;
}

__shr_public int libnvme_scan_ctrl(struct libnvme_global_ctx *ctx,
		const char *name, libnvme_ctrl_t *cp)
{
	__cleanup_free char *path = NULL;
	const struct ctrl_map_entry *ctrl_entry;
	libnvme_host_t h;
	libnvme_subsystem_t s;
	libnvme_ctrl_t c;
	int ret;

	libnvme_msg(ctx, LIBNVME_LOG_DEBUG, "scan controller %s\n", name);
	ctrl_entry = libnvme_ctrl_map_lookup(ctx, name);
	if (!ctrl_entry)
		return -ENODEV;
	ret = libnvme_ctrl_map_entry_get_ctrl_path(ctrl_entry, &path);
	if (ret)
		return ret;

	ret = libnvme_get_host(ctx, NULL, NULL, &h);
	if (ret)
		return ret;

	s = libnvme_get_subsystem_windows(h, ctrl_entry);
	if (!s)
		return -ENOMEM;

	ret = libnvme_ctrl_alloc(ctx, s, path, name, &c);
	if (ret)
		return ret;

	ret = libnvme_ctrl_scan_paths(ctx, c);
	if (ret) {
		libnvme_free_ctrl(c);
		return ret;
	}

	ret = libnvme_ctrl_scan_namespaces(ctx, c);
	if (ret) {
		libnvme_free_ctrl(c);
		return ret;
	}

	*cp = c;
	return 0;
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
	ns->attrs = libnvme_ns_attrs_alloc();
	if (!ns->attrs)
		return -ENOMEM;

	return 0;
}

int libnvme_ns_open(struct libnvme_global_ctx *ctx,
		__shr_unused const char *sys_path,
		const char *name, libnvme_ns_t *ns)
{
	const struct ctrl_map_entry *ctrl_entry;
	struct libnvme_transport_handle *hdl;
	struct libnvme_ns_head *head;
	struct libnvme_ns *n;
	HANDLE h;
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

	/* Open the device to query the namespace ID */
	h = CreateFileA(name, 0,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			NULL, OPEN_EXISTING, 0, NULL);
	if (h == INVALID_HANDLE_VALUE) {
		ret = -EIO;
		goto free_ns;
	}

	hdl = __libnvme_create_transport_handle(ctx);
	if (!hdl) {
		CloseHandle(h);
		ret = -ENOMEM;
		goto free_ns;
	}

	hdl->fd = h;
	hdl->type = LIBNVME_TRANSPORT_HANDLE_TYPE_DIRECT;

	ret = libnvme_get_nsid(hdl, &n->nsid);
	libnvme_close(hdl);
	if (ret)
		goto free_ns;

	ctrl_entry = libnvme_ctrl_map_lookup_by_physdrive(ctx, name);
	if (!ctrl_entry) {
		ret = -ENODEV;
		goto free_ns;
	}
	ret = asprintf(&n->name, "%sn%d",
		       libnvme_ctrl_map_entry_get_ctrl_name(ctrl_entry),
		       n->nsid);
	if (ret < 0) {
		ret = -ENOMEM;
		goto free_ns;
	}

	n->generic_name = strdup(name);
	if (!n->generic_name) {
		ret = -ENOMEM;
		goto free_ns;
	}

	ret = libnvme_ns_init(NULL, n);
	if (ret)
		goto free_ns;

	list_node_init(&n->entry);

	libnvme_ns_release_transport_handle(n);

	*ns = n;
	return 0;

free_ns:
	free(n->name);
	free(n->generic_name);
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

	n->sysfs_dir = strdup(name); /* \\\\.\\PhysicalDriveX */
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
