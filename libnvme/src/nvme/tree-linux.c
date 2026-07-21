// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 * 	    Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 */
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include <sys/stat.h>
#include <sys/types.h>

#include <ccan/endian/endian.h>
#include <ccan/list/list.h>

#include <libnvme.h>

#include "cleanup-linux.h"
#include "cleanup.h"
#include "compiler-attributes.h"
#include "private-fabrics.h"
#include "private-tree.h"
#include "private.h"
#include "util.h"

#define PATH_UUID_IBM			"/proc/device-tree/ibm,partition-uuid"
#define PATH_SYSFS_BLOCK		"/sys/block"
#define PATH_SYSFS_SLOTS		"/sys/bus/pci/slots"
#define PATH_SYSFS_NVME_SUBSYSTEM	"/sys/class/nvme-subsystem"
#define PATH_SYSFS_NVME			"/sys/class/nvme"
#define PATH_DMI_ENTRIES		"/sys/firmware/dmi/entries"

static const char *make_sysfs_dir(struct libnvme_global_ctx *ctx,
		const char *path)
{
	char *str;

	if (!ctx || !ctx->test_sysfs_dir)
		return path;

	if (asprintf(&str, "%s%s", ctx->test_sysfs_dir, path) < 0)
		return NULL;

	return str;
}

const char *libnvme_subsys_sysfs_dir(struct libnvme_global_ctx *ctx)
{
	static const char *str;

	if (str)
		return str;

	return str = make_sysfs_dir(ctx, PATH_SYSFS_NVME_SUBSYSTEM);
}

const char *libnvme_ctrl_sysfs_dir(struct libnvme_global_ctx *ctx)
{
	static const char *str;

	if (str)
		return str;

	return str = make_sysfs_dir(ctx, PATH_SYSFS_NVME);
}

const char *libnvme_ns_sysfs_dir(struct libnvme_global_ctx *ctx)
{
	static const char *str;

	if (str)
		return str;

	return str = make_sysfs_dir(ctx, PATH_SYSFS_BLOCK);
}

const char *libnvme_slots_sysfs_dir(struct libnvme_global_ctx *ctx)
{
	static const char *str;

	if (str)
		return str;

	return str = make_sysfs_dir(ctx, PATH_SYSFS_SLOTS);
}

const char *libnvme_uuid_ibm_filename(void)
{
	static const char *str;

	if (str)
		return str;

	return str = make_sysfs_dir(NULL, PATH_UUID_IBM);
}

const char *libnvme_dmi_entries_dir(void)
{
	static const char *str;

	if (str)
		return str;

	return str = make_sysfs_dir(NULL, PATH_DMI_ENTRIES);
}

static int __nvme_set_attr(const char *path, const char *value)
{
	__cleanup_fd int fd = -1;

	fd = open(path, O_WRONLY);
	if (fd < 0) {
#if 0
		libnvme_msg(LIBNVME_LOG_DEBUG, "Failed to open %s: %s\n", path,
			 strerror(errno));
#endif
		return -errno;
	}
	return write(fd, value, strlen(value));
}

int libnvme_set_attr(const char *dir, const char *attr, const char *value)
{
	__cleanup_free char *path = NULL;
	int ret;

	ret = asprintf(&path, "%s/%s", dir, attr);
	if (ret < 0)
		return -ENOMEM;

	return __nvme_set_attr(path, value);
}

static char *__nvme_get_attr(const char *path)
{
	char value[4096] = { 0 };
	int ret, fd;
	int saved_errno;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return NULL;

	ret = read(fd, value, sizeof(value) - 1);
	saved_errno = errno;
	close(fd);
	if (ret < 0) {
		errno = saved_errno;
		return NULL;
	}
	errno = 0;
	if (!strlen(value))
		return NULL;

	if (value[strlen(value) - 1] == '\n')
		value[strlen(value) - 1] = '\0';
	while (strlen(value) > 0 && value[strlen(value) - 1] == ' ')
		value[strlen(value) - 1] = '\0';

	return strlen(value) ? strdup(value) : NULL;
}

__libnvme_public char *libnvme_get_attr(const char *dir, const char *attr)
{
	__cleanup_free char *path = NULL;
	int ret;

	ret = asprintf(&path, "%s/%s", dir, attr);
	if (ret < 0)
		return NULL;

	return __nvme_get_attr(path);
}

__libnvme_public char *libnvme_get_subsys_attr(
		libnvme_subsystem_t s, const char *attr)
{
	return libnvme_get_attr(libnvme_subsystem_get_sysfs_dir(s), attr);
}

__libnvme_public char *libnvme_get_ctrl_attr(libnvme_ctrl_t c, const char *attr)
{
	return libnvme_get_attr(libnvme_ctrl_get_sysfs_dir(c), attr);
}

__libnvme_public char *libnvme_get_ns_attr(libnvme_ns_t n, const char *attr)
{
	return libnvme_get_attr(libnvme_ns_get_sysfs_dir(n), attr);
}

__libnvme_public char *libnvme_get_path_attr(libnvme_path_t p, const char *attr)
{
	return libnvme_get_attr(libnvme_path_get_sysfs_dir(p), attr);
}

__libnvme_public const char *libnvme_ctrl_get_state(libnvme_ctrl_t c)
{
	char *state = c->state;

	c->state = libnvme_get_ctrl_attr(c, "state");
	free(state);
	return c->state;
}

static int libnvme_ctrl_lookup_subsystem_name(struct libnvme_global_ctx *ctx,
		const char *ctrl_name, char **name)
{
	const char *subsys_dir = libnvme_subsys_sysfs_dir(ctx);
	__cleanup_dirents struct dirents subsys = {};
	int i;

	subsys.num = libnvme_scan_subsystems(ctx, &subsys.ents);
	if (subsys.num < 0)
		return subsys.num;

	for (i = 0; i < subsys.num; i++) {
		struct stat st;
		__cleanup_free char *path = NULL;

		if (asprintf(&path, "%s/%s/%s", subsys_dir,
			     subsys.ents[i]->d_name, ctrl_name) < 0)
			return -ENOMEM;
		libnvme_msg(ctx, LIBNVME_LOG_DEBUG, "lookup subsystem %s\n", path);
		if (stat(path, &st) < 0) {
			continue;
		}

		*name = strdup(subsys.ents[i]->d_name);
		if (!*name)
			return -ENOMEM;

		return 0;
	}
	return -ENOENT;
}

static int libnvme_ctrl_lookup_phy_slot(struct libnvme_global_ctx *ctx,
		libnvme_ctrl_t c)
{
	const char *slots_sysfs_dir = libnvme_slots_sysfs_dir(ctx);
	__cleanup_free char *target_addr = NULL;
	__cleanup_dir DIR *slots_dir = NULL;
	struct dirent *entry;
	char *slot;
	int ret;

	if (!c->address)
		return -EINVAL;

	slots_dir = opendir(slots_sysfs_dir);
	if (!slots_dir) {
		libnvme_msg(ctx, LIBNVME_LOG_WARN, "failed to open slots dir %s\n",
		slots_sysfs_dir);
		return -errno;
	}

	target_addr = strndup(c->address, 10);
	while ((entry = readdir(slots_dir))) {
		if (entry->d_type == DT_DIR &&
		    strncmp(entry->d_name, ".", 1) != 0 &&
		    strncmp(entry->d_name, "..", 2) != 0) {
			__cleanup_free char *path = NULL;
			__cleanup_free char *addr = NULL;

			ret = asprintf(&path, "%s/%s",
				       slots_sysfs_dir, entry->d_name);
			if (ret < 0)
				return -ENOMEM;
			addr = libnvme_get_attr(path, "address");

			/* some directories don't have an address entry */
			if (!addr)
				continue;
			if (strcmp(addr, target_addr))
				continue;

			slot = strdup(entry->d_name);
			if (!slot)
				return -ENOMEM;

			c->phy_slot = slot;
			return 0;
		}
	}
	return -ENOENT;
}

int libnvme_reconfigure_ctrl(struct libnvme_global_ctx *ctx,
		libnvme_ctrl_t c, const char *path, const char *name)
{
	DIR *d;

	/*
	 * It's necesssary to release any resources first because a ctrl
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

	d = opendir(path);
	if (!d) {
		libnvme_msg(ctx, LIBNVME_LOG_ERR,
			"Failed to open ctrl dir %s, error %d\n", path, errno);
		return -ENODEV;
	}
	closedir(d);

	c->hdl = NULL;
	c->name = xstrdup(name);
	c->sysfs_dir = xstrdup(path);
	c->firmware = libnvme_get_ctrl_attr(c, "firmware_rev");
	c->model = libnvme_get_ctrl_attr(c, "model");
	c->state = libnvme_get_ctrl_attr(c, "state");
	c->numa_node = libnvme_get_ctrl_attr(c, "numa_node");
	c->queue_count = libnvme_get_ctrl_attr(c, "queue_count");
	c->serial = libnvme_get_ctrl_attr(c, "serial");
	c->sqsize = libnvme_get_ctrl_attr(c, "sqsize");
	c->cntrltype = libnvme_get_ctrl_attr(c, "cntrltype");
	c->cntlid = libnvme_get_ctrl_attr(c, "cntlid");
	c->dctype = libnvme_get_ctrl_attr(c, "dctype");
	libnvme_ctrl_lookup_phy_slot(ctx, c);
	libnvmf_read_sysfs_fabrics_attrs(ctx, c);

	return 0;
}

__libnvme_public int libnvme_init_ctrl(
		libnvme_host_t h, libnvme_ctrl_t c, int instance)
{
	__cleanup_free char *subsys_name = NULL, *name = NULL, *path = NULL;
	libnvme_subsystem_t s;
	int ret;

	ret = asprintf(&name, "nvme%d", instance);
	if (ret < 0)
		return -ENOMEM;

	ret = asprintf(&path, "%s/%s", libnvme_ctrl_sysfs_dir(h->ctx), name);
	if (ret < 0)
		return -ENOMEM;

	ret = libnvme_reconfigure_ctrl(h->ctx, c, path, name);
	if (ret < 0)
		return ret;

	c->address = libnvme_get_attr(path, "address");
	if (!c->address && strcmp(c->transport, "loop"))
		return -ENVME_CONNECT_INVAL_TR;

	ret = libnvme_ctrl_lookup_subsystem_name(h->ctx, name, &subsys_name);
	if (ret) {
		libnvme_msg(h->ctx, LIBNVME_LOG_ERR,
			 "Failed to lookup subsystem name for %s\n",
			 c->name);
		return ENVME_CONNECT_LOOKUP_SUBSYS_NAME;
	}

	s = libnvme_lookup_subsystem(h, subsys_name, c->subsysnqn);
	if (!s)
		return -ENVME_CONNECT_LOOKUP_SUBSYS;

	if (s->subsystype && !strcmp(s->subsystype, "discovery"))
		c->discovery_ctrl = true;

	c->s = s;
	list_add_tail(&s->ctrls, &c->entry);

	return ret;
}

__libnvme_public int libnvme_scan_ctrl(
		struct libnvme_global_ctx *ctx, const char *name,
		libnvme_ctrl_t *cp)
{
	__cleanup_free char *subsysnqn = NULL, *subsysname = NULL;
	__cleanup_free char *hostnqn = NULL, *hostid = NULL;
	__cleanup_free char *path = NULL;
	char *host_key;
	libnvme_host_t h;
	libnvme_subsystem_t s;
	libnvme_ctrl_t c;
	int ret;

	libnvme_msg(ctx, LIBNVME_LOG_DEBUG, "scan controller %s\n", name);
	ret = asprintf(&path, "%s/%s", libnvme_ctrl_sysfs_dir(ctx), name);
	if (ret < 0)
		return -ENOMEM;

	hostnqn = libnvme_get_attr(path, "hostnqn");
	hostid = libnvme_get_attr(path, "hostid");
	if (!hostnqn)
		hostnqn = xstrdup(ctx->hostnqn);
	if (!hostid)
		hostid = xstrdup(ctx->hostid);
	ret = libnvme_get_host(ctx, hostnqn, hostid, &h);
	if (ret)
		return ret;

	host_key = libnvme_get_attr(path, "dhchap_secret");
	if (host_key && strcmp(host_key, "none")) {
		free(h->dhchap_host_key);
		h->dhchap_host_key = host_key;
		host_key = NULL;
	}
	free(host_key);

	subsysnqn = libnvme_get_attr(path, "subsysnqn");
	if (!subsysnqn)
		return -ENXIO;

	ret = libnvme_ctrl_lookup_subsystem_name(ctx, name, &subsysname);
	if (ret) {
		libnvme_msg(ctx, LIBNVME_LOG_DEBUG,
			 "failed to lookup subsystem for controller %s\n",
			 name);
		return ret;
	}

	s = libnvme_lookup_subsystem(h, subsysname, subsysnqn);
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

static int libnvme_strtou64(const char *str, void *res)
{
	char *endptr;
	__u64 v;

	errno = 0;
	v = strtoull(str, &endptr, 0);

	if (errno != 0)
		return -errno;

	if (endptr == str) {
		/* no digits found */
		return -EINVAL;
	}

	*(__u64 *)res = v;
	return 0;
}

static int libnvme_strtou32(const char *str, void *res)
{
	char *endptr;
	__u32 v;

	errno = 0;
	v = strtol(str, &endptr, 0);

	if (errno != 0)
		return -errno;

	if (endptr == str) {
		/* no digits found */
		return -EINVAL;
	}

	*(__u32 *)res = v;
	return 0;
}

static int libnvme_strtoi(const char *str, void *res)
{
	char *endptr;
	int v;

	errno = 0;
	v = strtol(str, &endptr, 0);

	if (errno != 0)
		return -errno;

	if (endptr == str) {
		/* no digits found */
		return -EINVAL;
	}

	*(int *)res = v;
	return 0;
}

static int libnvme_strtoeuid(const char *str, void *res)
{
	memcpy(res, str, 8);
	return 0;
}

static int libnvme_strtouuid(const char *str, void *res)
{
	unsigned char uuid[NVME_UUID_LEN];

	if (libnvme_uuid_from_string(str, uuid))
		return -EINVAL;

	memcpy(res, uuid, NVME_UUID_LEN);
	return 0;
}

struct sysfs_attr_table {
	void *var;
	int (*parse)(const char *str, void *res);
	bool mandatory;
	const char *name;
};

#define GETSHIFT(x) (__builtin_ffsll(x) - 1)
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

static int parse_attrs(const char *path, struct sysfs_attr_table *tbl, int size)
{
	char *str;
	int ret, i;

	for (i = 0; i < size; i++) {
		struct sysfs_attr_table *e = &tbl[i];

		str = libnvme_get_attr(path, e->name);
		if (!str) {
			if (!e->mandatory)
				continue;
			return -ENOENT;
		}
		ret = e->parse(str, e->var);
		free(str);
		if (ret)
			return ret;
	}

	return 0;
}

int libnvme_ns_init(const char *path, struct libnvme_ns *ns)
{
	__cleanup_free char *attr = NULL;
	struct stat sb;
	uint64_t size;
	int ret;

	struct sysfs_attr_table base[] = {
		{ &ns->nsid,      libnvme_strtou32,  true, "nsid" },
		{ &size,          libnvme_strtou64,  true, "size" },
		{ &ns->lba_size,  libnvme_strtou32,  true, "queue/logical_block_size" },
		{ ns->eui64,      libnvme_strtoeuid, false, "eui" },
		{ ns->nguid,      libnvme_strtouuid, false, "nguid" },
		{ ns->uuid,       libnvme_strtouuid, false, "uuid" }
	};

	ret = parse_attrs(path, base, ARRAY_SIZE(base));
	if (ret)
		return ret;

	ns->lba_shift = GETSHIFT(ns->lba_size);
	/*
	 * size is in 512 bytes units and lba_count is in lba_size which are not
	 * necessarily the same.
	 */
	ns->lba_count = size >> (ns->lba_shift -  SECTOR_SHIFT);

	if (asprintf(&attr, "%s/csi", path) < 0)
		return -ENOMEM;

	ret = stat(attr, &sb);
	if (ret == 0) {
		/* only available on kernels >= 6.8 */
		struct sysfs_attr_table ext[] = {
			{ &ns->csi,       libnvme_strtoi,	true, "csi" },
			{ &ns->lba_util,  libnvme_strtou64,	true, "nuse" },
			{ &ns->meta_size, libnvme_strtoi,	true, "metadata_bytes"},

		};

		ret = parse_attrs(path, ext, ARRAY_SIZE(ext));
		if (ret)
			return ret;
	} else {
		__cleanup_libnvme_free struct nvme_id_ns *id = NULL;
		uint8_t flbas;

		id = libnvme_alloc(sizeof(*id));
		if (!id)
			return -ENOMEM;

		ret = libnvme_ns_identify(ns, id);
		if (ret)
			return ret;

		nvme_id_ns_flbas_to_lbaf_inuse(id->flbas, &flbas);
		ns->lba_count = le64_to_cpu(id->nsze);
		ns->lba_util = le64_to_cpu(id->nuse);
		ns->meta_size = le16_to_cpu(id->lbaf[flbas].ms);
	}

	return 0;
}

static void libnvme_ns_set_generic_name(struct libnvme_ns *n, const char *name)
{
	char generic_name[PATH_MAX];
	int instance, head_instance;
	int ret;

	ret = sscanf(name, "nvme%dn%d", &instance, &head_instance);
	if (ret != 2)
		return;

	sprintf(generic_name, "ng%dn%d", instance, head_instance);
	n->generic_name = strdup(generic_name);
}

int libnvme_ns_open(struct libnvme_global_ctx *ctx, const char *sys_path,
		const char *name, libnvme_ns_t *ns)
{
	int ret;
	struct libnvme_ns *n;
	struct libnvme_ns_head *head;
	struct stat arg;
	__cleanup_free char *path = NULL;

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
	ret = asprintf(&path, "%s/%s", sys_path, "multipath");
	if (ret < 0) {
		ret = -ENOMEM;
		goto free_ns_head;
	}

	/*
	 * The sysfs-dir "multipath" is available only when nvme multipath
	 * is configured and we're running kernel version >= 6.14.
	 */
	ret = stat(path, &arg);
	if (ret == 0) {
		head->sysfs_dir = path;
		path = NULL;
	} else
		head->sysfs_dir = NULL;

	n->ctx = ctx;
	n->head = head;
	n->hdl = NULL;
	n->name = strdup(name);

	libnvme_ns_set_generic_name(n, name);

	ret = libnvme_ns_init(sys_path, n);
	if (ret)
		goto free_ns;

	list_node_init(&n->entry);

	libnvme_ns_release_transport_handle(n);

	*ns = n;
	return 0;

free_ns:
	free(n->generic_name);
	free(n->name);
free_ns_head:
	free(head);
	free(n);
	return ret;
}

static inline bool libnvme_ns_is_generic(const char *name)
{
	int instance, head_instance;

	if (sscanf(name, "ng%dn%d", &instance, &head_instance) != 2)
		return false;
	return true;
}

static char *libnvme_ns_generic_to_blkdev(const char *generic)
{

	int instance, head_instance;
	char blkdev[PATH_MAX];

	if (!libnvme_ns_is_generic(generic))
		return strdup(generic);

	sscanf(generic, "ng%dn%d", &instance, &head_instance);
	sprintf(blkdev, "nvme%dn%d", instance, head_instance);

	return strdup(blkdev);
}

int __libnvme_scan_namespace(struct libnvme_global_ctx *ctx,
		const char *sysfs_dir, const char *name, libnvme_ns_t *ns)
{
	__cleanup_free char *blkdev = NULL;
	__cleanup_free char *path = NULL;
	struct libnvme_ns *n = NULL;
	int ret;

	blkdev = libnvme_ns_generic_to_blkdev(name);
	if (!blkdev)
		return -ENOMEM;

	ret = asprintf(&path, "%s/%s", sysfs_dir, blkdev);
	if (ret < 0)
		return -ENOMEM;

	ret = libnvme_ns_open(ctx, path, blkdev, &n);
	if (ret)
		return ret;

	n->sysfs_dir = path;
	path = NULL;

	*ns = n;
	return 0;
}

int libnvme_get_ctrl_transport(__libnvme_unused struct libnvme_global_ctx *ctx,
		const char *path, const char *name,
		char **transport, char **traddr, char **addr, char **trsvcid,
		char **host_traddr, char **host_iface)
{
	char *a = NULL, *e = NULL;

	*transport = libnvme_get_attr(path, "transport");
	if (!*transport)
		return -ENXIO;

	/* Parse 'address' string into components */
	*addr = libnvme_get_attr(path, "address");
	if (!*addr) {
		__cleanup_free char *rpath = NULL;
		char *p = NULL, *_a = NULL;

		/* loop transport might not have an address */
		if (!strcmp(*transport, "loop"))
			goto skip_address;

		/* Older kernels don't support pcie transport addresses */
		if (strcmp(*transport, "pcie") &&
		    strcmp(*transport, "apple-nvme"))
			return -ENXIO;
		/* Figure out the PCI address from the attribute path */
		rpath = realpath(path, NULL);
		if (!rpath)
			return -ENOMEM;
		a = strtok_r(rpath, "/", &e);
		while (a && strlen(a)) {
			if (_a)
				p = _a;
			_a = a;
			if (!strncmp(a, "nvme", 4))
				break;
			a = strtok_r(NULL, "/", &e);
		}
		if (p)
			*addr = strdup(p);
	} else if (!strcmp(*transport, "pcie") ||
		   !strcmp(*transport, "apple-nvme")) {
		/* The 'address' string is the transport address */
		*traddr = strdup(*addr);
		if (!*traddr)
			return -ENOMEM;
	} else {
		__cleanup_free char *address = strdup(*addr);
		if (!address)
			return -ENOMEM;

		a = strtok_r(address, ",", &e);
		while (a && strlen(a)) {
			if (!strncmp(a, "traddr=", 7))
				*traddr = strdup(a + 7);
			else if (!strncmp(a, "trsvcid=", 8))
				*trsvcid = strdup(a + 8);
			else if (!strncmp(a, "host_traddr=", 12))
				*host_traddr = strdup(a + 12);
			else if (!strncmp(a, "host_iface=", 11))
				*host_iface = strdup(a + 11);
			a = strtok_r(NULL, ",", &e);
		}
	}
skip_address:
	return 0;
}

int libnvme_init_subsystem(libnvme_subsystem_t s, const char *name)
{
	char *path;

	if (asprintf(&path, "%s/%s",
			libnvme_subsys_sysfs_dir(s->h->ctx), name) < 0)
		return -ENOMEM;

	s->model = libnvme_get_attr(path, "model");
	if (!s->model)
		s->model = strdup("undefined");
	s->serial = libnvme_get_attr(path, "serial");
	s->firmware = libnvme_get_attr(path, "firmware_rev");
	s->subsystype = libnvme_get_attr(path, "subsystype");
	if (!s->subsystype) {
		if (!strcmp(s->subsysnqn, NVME_DISC_SUBSYS_NAME))
			s->subsystype = strdup("discovery");
		else
			s->subsystype = strdup("nvm");
	}
	s->name = strdup(name);
	s->sysfs_dir = (char *)path;
	s->iopolicy = libnvme_get_attr(path, "iopolicy");

	return 0;
}
