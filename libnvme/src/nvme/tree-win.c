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

#include <libnvme.h>

#include "cleanup.h"
#include "private.h"
#include "private-storageport.h"
#include "private-tree.h"
#include "util.h"
#include "compiler-attributes.h"


#define FREE_CTRL_ATTR(a) \
	do { free(a); (a) = NULL; } while (0)
int libnvme_reconfigure_ctrl(struct libnvme_global_ctx *ctx,
		libnvme_ctrl_t c, const char *path, const char *name)
{
	struct nvme_id_ctrl id_ctrl;
	struct storageport_map_entry *sp_entry;
	int ret;

	/*
	 * It's necessary to release any resources first because a ctrl
	 * can be reused.
	 */
	libnvme_ctrl_release_transport_handle(c);
	FREE_CTRL_ATTR(c->name);
	FREE_CTRL_ATTR(c->sysfs_dir);
	FREE_CTRL_ATTR(c->firmware);
	FREE_CTRL_ATTR(c->model);
	FREE_CTRL_ATTR(c->state);
	FREE_CTRL_ATTR(c->numa_node);
	FREE_CTRL_ATTR(c->queue_count);
	FREE_CTRL_ATTR(c->serial);
	FREE_CTRL_ATTR(c->sqsize);
	FREE_CTRL_ATTR(c->cntrltype);
	FREE_CTRL_ATTR(c->cntlid);
	FREE_CTRL_ATTR(c->dctype);
	FREE_CTRL_ATTR(c->phy_slot);

	c->hdl = NULL;
	c->name = xstrdup(name);
	c->sysfs_dir = xstrdup(path);

	if (!libnvme_ctrl_get_transport_handle(c))
		return -ENODEV;

	ret = libnvme_ctrl_identify(c, &id_ctrl);
	if (ret != 0) {
		libnvme_msg(ctx, LIBNVME_LOG_ERR,
			"Failed to identify ctrl %s, error %d\n",
			c->name, ret);
		return -ENODEV;
	}

	sp_entry = libnvme_storageport_map_lookup(c->name);
	if (!sp_entry) {
		libnvme_msg(ctx, LIBNVME_LOG_ERR,
			"Failed to find storageport map entry for ctrl %s\n",
			c->name);
		return -ENODEV;
	}

	ret = libnvme_storageport_entry_set_id_ctrl(sp_entry, &id_ctrl);
	if (ret != 0) {
		libnvme_msg(ctx, LIBNVME_LOG_ERR,
			"Failed to update storageport map for ctrl %s, error %d\n",
			c->name, ret);
		return -ENODEV;
	}

	c->firmware = libnvme_storageport_entry_get_firmware(sp_entry);
	if (!c->firmware)
		return -ENOMEM;

	c->model = libnvme_storageport_entry_get_model(sp_entry);
	if (!c->model)
		return -ENOMEM;

	c->serial = libnvme_storageport_entry_get_serial(sp_entry);
	if (!c->serial)
		return -ENOMEM;

	if (asprintf(&c->cntrltype, "%u", id_ctrl.cntrltype) < 0)
		return -errno;

	if (asprintf(&c->cntlid, "%u", le16_to_cpu(id_ctrl.cntlid)) < 0)
		return -errno;

	if (asprintf(&c->dctype, "%u", id_ctrl.dctype) < 0)
		return -errno;

	return 0;
}

__libnvme_public int libnvme_get_host(struct libnvme_global_ctx *ctx,
	const char *hostnqn, const char *hostid, libnvme_host_t *host)
{
	__cleanup_free char *hnqn = NULL;
	__cleanup_free char *hid = NULL;
	struct libnvme_host *h;

	/* Use provided values or generate defaults */
	if (hostnqn)
		hnqn = strdup(hostnqn);
	else
		hnqn = strdup("nqn.2014-08.org.nvmexpress:uuid:00000000-0000-0000-0000-000000000000");

	if (!hnqn)
		return -ENOMEM;

	if (hostid)
		hid = strdup(hostid);
	else
		hid = strdup("00000000-0000-0000-0000-000000000000");

	if (!hid)
		return -ENOMEM;

	h = libnvme_lookup_host(ctx, hnqn, hid);
	if (!h)
		return -ENOMEM;

	libnvme_host_set_hostsymname(h, NULL);

	*host = h;
	return 0;
}

__libnvme_public const char *libnvme_ctrl_get_state(libnvme_ctrl_t c)
{
	char *state = c->state;

	c->state = strdup("");
	free(state);
	return c->state;
}

__libnvme_public int libnvme_init_ctrl(libnvme_host_t h, libnvme_ctrl_t c, int instance)
{
	(void)h;
	(void)c;
	(void)instance;
	return -ENOTSUP;
}

int libnvme_get_ctrl_transport(const char *path, const char *name,
		char **transport, char **traddr, char **addr)
{
	const struct storageport_map_entry *sp_entry;
	int ret;

	*transport = strdup("pcie");
	if (!*transport)
		return -ENOMEM;

	sp_entry = libnvme_storageport_map_lookup(name);

	ret = libnvme_storageport_entry_get_pci_address(sp_entry, addr);
	if (ret || !*addr) {
		free(*transport);
		*transport = NULL;
		return -ENXIO;
	}

	*traddr = *addr;
	return 0;
}

static libnvme_subsystem_t libnvme_lookup_subsystem_windows(libnvme_host_t h,
		const struct storageport_map_entry *sp_entry)
{
	libnvme_subsystem_t s;
	char *subsysnqn;
	char *subsysname;

	subsysnqn = libnvme_storageport_entry_get_subnqn(sp_entry);
	if (!subsysnqn)
		return NULL;

	subsysname = libnvme_storageport_entry_get_subsys_name(sp_entry);
	if (!subsysname) {
		free(subsysnqn);
		return NULL;
	}

	s = libnvme_lookup_subsystem(h, subsysname, subsysnqn);
	free(subsysnqn);
	free(subsysname);
	if (!s)
		return NULL;

	/* Populate subsystem info from first controller */
	if (!s->serial)
		s->serial = libnvme_storageport_entry_get_serial(sp_entry);
	if (!s->model)
		s->model = libnvme_storageport_entry_get_model(sp_entry);
	if (!s->firmware)
		s->firmware = libnvme_storageport_entry_get_firmware(sp_entry);

	return s;
}

__libnvme_public int libnvme_scan_ctrl(struct libnvme_global_ctx *ctx, const char *name,
			       libnvme_ctrl_t *cp)
{
	__cleanup_free char *subsysnqn = NULL, *subsysname = NULL;
	__cleanup_free char *hostnqn = NULL, *hostid = NULL;
	__cleanup_free char *path = NULL;
	const struct storageport_map_entry *sp_entry;
	libnvme_host_t h;
	libnvme_subsystem_t s;
	libnvme_ctrl_t c;
	int ret;

	libnvme_msg(ctx, LIBNVME_LOG_DEBUG, "scan controller %s\n", name);
	sp_entry = libnvme_storageport_map_lookup(name);
	if (!sp_entry)
		return -ENODEV;
	ret = libnvme_storageport_entry_get_ctrl_path(sp_entry, &path);
	if (ret)
		return ret;

	ret = libnvme_get_host(ctx, hostnqn, hostid, &h);
	if (ret)
		return ret;

	s = libnvme_lookup_subsystem_windows(h, sp_entry);
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

__libnvme_public char *libnvme_get_subsys_attr(libnvme_subsystem_t s, const char *attr)
{
	(void)s;
	(void)attr;
	return NULL;
}

__libnvme_public char *libnvme_get_path_attr(libnvme_path_t p, const char *attr)
{
	(void)p;
	(void)attr;
	return NULL;
}

__libnvme_public char *libnvme_get_attr(const char *dir, const char *attr)
{
	(void)dir;
	(void)attr;
	return NULL;
}

__libnvme_public char *libnvme_get_ctrl_attr(libnvme_ctrl_t c, const char *attr)
{
	(void)c;
	(void)attr;
	return NULL;
}

__libnvme_public char *libnvme_get_ns_attr(libnvme_ns_t n, const char *attr)
{
	(void)n;
	(void)attr;
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

int libnvme_ns_open(struct libnvme_global_ctx *ctx, const char *sys_path,
		const char *name, libnvme_ns_t *ns)
{
	const struct storageport_map_entry *sp_entry;
	struct libnvme_transport_handle *hdl;
	struct libnvme_ns_head *head;
	struct libnvme_ns *n;
	HANDLE h;
	int ret;
	(void)sys_path;

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

	sp_entry = libnvme_storageport_map_lookup_by_physdrive(name);
	if (!sp_entry) {
		ret = -ENODEV;
		goto free_ns;
	}
	ret = asprintf(&n->name, "%sn%d",
		       libnvme_storageport_entry_get_ctrl_name(sp_entry),
		       n->nsid);
	if (ret < 0) {
		ret = -ENOMEM;
		goto free_ns;
	}
	n->generic_name = strdup(name);

	ret = libnvme_ns_init(NULL, n);
	if (ret)
		goto free_ns;

	list_node_init(&n->entry);

	libnvme_ns_release_transport_handle(n);

	*ns = n;
	return 0;

free_ns:
	free(n->name);
	free(head);
	free(n);
	return ret;
}

int __libnvme_scan_namespace(struct libnvme_global_ctx *ctx,
		const char *sysfs_dir, const char *name, libnvme_ns_t *ns)
{
	struct libnvme_ns *n = NULL;
	int ret;
	(void)sysfs_dir;

	ret = libnvme_ns_open(ctx, NULL, name, &n);
	if (ret)
		return ret;

	n->sysfs_dir = strdup(name); /* \\\\.\\PhysicalDriveX */

	*ns = n;
	return 0;
}
