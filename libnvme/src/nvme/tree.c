// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 * 	    Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 */
#include <dirent.h>
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

#ifdef CONFIG_FABRICS
#include <ifaddrs.h>
#include <netdb.h>

#include <arpa/inet.h>
#endif

#include <ccan/endian/endian.h>
#include <ccan/list/list.h>

#include <libnvme.h>

#include "cleanup.h"
#include "cleanup-linux.h"
#include "private.h"
#include "private-fabrics.h"
#include "util.h"
#include "compiler-attributes.h"

/**
 * struct candidate_args - Used to look for a controller matching these parameters
 * @transport:		Transport type: loop, fc, rdma, tcp
 * @traddr:		Transport address (destination address)
 * @trsvcid:		Transport service ID
 * @subsysnqn:		Subsystem NQN
 * @host_traddr:	Host transport address (source address)
 * @host_iface:		Host interface for connection (tcp only)
 * @iface_list:		Interface list (tcp only)
 * @addreq:		Address comparison function (for traddr, host-traddr)
 * @well_known_nqn:	Set to "true" when @subsysnqn is the well-known NQN
 */
struct candidate_args {
	const char *transport;
	const char *traddr;
	const char *trsvcid;
	const char *subsysnqn;
	const char *host_traddr;
	const char *host_iface;
	const struct ifaddrs *iface_list;
	bool (*addreq)(const char *, const char *);
	bool well_known_nqn;
};
typedef bool (*ctrl_match_t)(struct libnvme_ctrl *c,
		struct candidate_args *candidate);

static void __libnvme_free_ctrl(libnvme_ctrl_t c);
static int libnvme_subsystem_scan_namespace(struct libnvme_global_ctx *ctx,
		struct libnvme_subsystem *s, char *name);
static int libnvme_init_subsystem(libnvme_subsystem_t s, const char *name);
static int libnvme_scan_subsystem(struct libnvme_global_ctx *ctx,
	 	const char *name);
static int libnvme_ctrl_scan_namespace(struct libnvme_global_ctx *ctx,
		struct libnvme_ctrl *c, char *name);
static int libnvme_ctrl_scan_path(struct libnvme_global_ctx *ctx,
		struct libnvme_ctrl *c, char *name);

/**
 * Compare two C strings and handle NULL pointers gracefully.
 * Return true if both pointers are equal (including both set to NULL).
 * Return false if one and only one of the two pointers is NULL.
 * Perform string comparisong only if both pointers are not NULL and
 * return true if both strings are the same, false otherwise.
 */
static bool streq0(const char *s1, const char *s2)
{
	if (s1 == s2)
		return true;
	if (!s1 || !s2)
		return false;
	return !strcmp(s1, s2);
}

/**
 * Same as streq0() but ignore the case of the characters.
 */
static bool streqcase0(const char *s1, const char *s2)
{
	if (s1 == s2)
		return true;
	if (!s1 || !s2)
		return false;
	return !strcasecmp(s1, s2);
}

struct dirents {
	struct dirent **ents;
	int num;
};

static void cleanup_dirents(struct dirents *ents)
{
	while (ents->num > 0)
		free(ents->ents[--ents->num]);
	free(ents->ents);
}

#define __cleanup_dirents __cleanup(cleanup_dirents)

static char *nvme_hostid_from_hostnqn(const char *hostnqn)
{
	const char *uuid;

	uuid = strstr(hostnqn, "uuid:");
	if (!uuid)
		return NULL;

	return strdup(uuid + strlen("uuid:"));
}

__libnvme_public int libnvme_host_get_ids(struct libnvme_global_ctx *ctx,
		      const char *hostnqn_arg, const char *hostid_arg,
		      char **hostnqn, char **hostid)
{
	__cleanup_free char *nqn = NULL;
	__cleanup_free char *hid = NULL;
	__cleanup_free char *hnqn = NULL;
	libnvme_host_t h;

	/* command line argumments */
	if (hostid_arg)
		hid = strdup(hostid_arg);
	if (hostnqn_arg)
		hnqn = strdup(hostnqn_arg);

	/* JSON config: assume the first entry is the default host */
	h = libnvme_first_host(ctx);
	if (h) {
		if (!hid)
			hid = xstrdup(libnvme_host_get_hostid(h));
		if (!hnqn)
			hnqn = xstrdup(libnvme_host_get_hostnqn(h));
	}

	/* /etc/nvme/hostid and/or /etc/nvme/hostnqn */
	if (!hid)
		hid = libnvme_read_hostid();
	if (!hnqn)
		hnqn = libnvme_read_hostnqn();

	/* incomplete configuration, thus derive hostid from hostnqn */
	if (!hid && hnqn)
		hid = nvme_hostid_from_hostnqn(hnqn);

	/*
	 * fallback to use either DMI information or device-tree. If all
	 * fails generate one
	 */
	if (!hid) {
		hid = libnvme_generate_hostid();
		if (!hid)
			return -ENOMEM;

		libnvme_msg(ctx, LIBNVME_LOG_DEBUG,
			 "warning: using auto generated hostid and hostnqn\n");
	}

	/* incomplete configuration, thus derive hostnqn from hostid */
	if (!hnqn) {
		hnqn = libnvme_generate_hostnqn_from_hostid(hid);
		if (!hnqn)
			return -ENOMEM;
	}

	/* sanity checks */
	nqn = nvme_hostid_from_hostnqn(hnqn);
	if (nqn && strcmp(nqn, hid)) {
		libnvme_msg(ctx, LIBNVME_LOG_DEBUG,
			 "warning: use hostid '%s' which does not match uuid in hostnqn '%s'\n",
			 hid, hnqn);
	}

	*hostid = hid;
	*hostnqn = hnqn;
	hid = NULL;
	hnqn = NULL;

	return 0;
}

__libnvme_public int libnvme_get_host(
		struct libnvme_global_ctx *ctx, const char *hostnqn,
		const char *hostid, libnvme_host_t *host)
{
	__cleanup_free char *hnqn = NULL;
	__cleanup_free char *hid = NULL;
	struct libnvme_host *h;
	int err;

	err = libnvme_host_get_ids(ctx, hostnqn, hostid, &hnqn, &hid);
	if (err)
		return err;

	h = libnvme_lookup_host(ctx, hnqn, hid);
	if (!h)
		return -ENOMEM;

	libnvme_host_set_hostsymname(h, NULL);

	*host = h;
	return 0;
}

static void libnvme_filter_subsystem(struct libnvme_global_ctx *ctx,
		libnvme_subsystem_t s, libnvme_scan_filter_t f, void *f_args)
{
	if (f(s, NULL, NULL, f_args))
		return;

	libnvme_msg(ctx, LIBNVME_LOG_DEBUG, "filter out subsystem %s\n",
		 libnvme_subsystem_get_name(s));
	libnvme_free_subsystem(s);
}

static void libnvme_filter_ns(struct libnvme_global_ctx *ctx, libnvme_ns_t n,
		libnvme_scan_filter_t f, void *f_args)
{
	if (f(NULL, NULL, n, f_args))
		return;

	libnvme_msg(ctx, LIBNVME_LOG_DEBUG, "filter out namespace %s\n",
		 libnvme_ns_get_name(n));
	libnvme_free_ns(n);
}

static void libnvme_filter_ctrl(struct libnvme_global_ctx *ctx,
		libnvme_ctrl_t c, libnvme_scan_filter_t f, void *f_args)
{
	if (f(NULL, c, NULL, f_args))
		return;

	libnvme_msg(ctx, LIBNVME_LOG_DEBUG, "filter out controller %s\n",
		 libnvme_ctrl_get_name(c));
	libnvme_free_ctrl(c);
}

static void libnvme_filter_tree(struct libnvme_global_ctx *ctx,
		libnvme_scan_filter_t f, void *f_args)
{
	libnvme_host_t h, _h;
	libnvme_subsystem_t s, _s;
	libnvme_ns_t n, _n;
	libnvme_path_t p, _p;
	libnvme_ctrl_t c, _c;

	if (!f)
		return;

	libnvme_for_each_host_safe(ctx, h, _h) {
		libnvme_for_each_subsystem_safe(h, s, _s) {
			libnvme_subsystem_for_each_ctrl_safe(s, c, _c)
				libnvme_filter_ctrl(ctx, c, f, f_args);

			libnvme_subsystem_for_each_ns_safe(s, n, _n) {
				libnvme_namespace_for_each_path_safe(n, p, _p) {
					libnvme_filter_ctrl(ctx, libnvme_path_get_ctrl(p),
							 f, f_args);
				}
				libnvme_filter_ns(ctx, n, f, f_args);
			}

			libnvme_filter_subsystem(ctx, s, f, f_args);
		}
	}
}

__libnvme_public int libnvme_scan_topology(struct libnvme_global_ctx *ctx,
		libnvme_scan_filter_t f, void *f_args)
{
	__cleanup_dirents struct dirents subsys = {}, ctrls = {};
	int i, ret;

	if (!ctx)
		return 0;

	ctrls.num = libnvme_scan_ctrls(&ctrls.ents);
	if (ctrls.num < 0) {
		libnvme_msg(ctx, LIBNVME_LOG_DEBUG, "failed to scan ctrls: %s\n",
			 libnvme_strerror(-ctrls.num));
		return ctrls.num;
	}

	for (i = 0; i < ctrls.num; i++) {
		libnvme_ctrl_t c;

		ret = libnvme_scan_ctrl(ctx, ctrls.ents[i]->d_name, &c);
		if (ret < 0) {
			libnvme_msg(ctx, LIBNVME_LOG_DEBUG,
				"failed to scan ctrl %s: %s\n",
				ctrls.ents[i]->d_name, libnvme_strerror(-ret));
			continue;
		}
	}

	subsys.num = libnvme_scan_subsystems(&subsys.ents);
	if (subsys.num < 0) {
		libnvme_msg(ctx, LIBNVME_LOG_DEBUG, "failed to scan subsystems: %s\n",
			libnvme_strerror(-subsys.num));
		return subsys.num;
	}

	for (i = 0; i < subsys.num; i++) {
		ret = libnvme_scan_subsystem(ctx, subsys.ents[i]->d_name);
		if (ret < 0) {
			libnvme_msg(ctx, LIBNVME_LOG_DEBUG,
				"failed to scan subsystem %s: %s\n",
				subsys.ents[i]->d_name,
				libnvme_strerror(-ret));
		}
	}

	/*
	 * Filter the tree after it has been fully populated and
	 * updated
	 */
	libnvme_filter_tree(ctx, f, f_args);

	return 0;
}

__libnvme_public int libnvme_read_config(struct libnvme_global_ctx *ctx,
		const char *config_file)
{
	int err;

	if (!ctx || !config_file)
		return -ENODEV;

	ctx->config_file = strdup(config_file);
	if (!ctx->config_file)
		return -ENOMEM;

	err = json_read_config(ctx, config_file);
	/*
	 * The json configuration file is optional,
	 * so ignore errors when opening the file.
	 */
	if (err < 0 && err != -EPROTO)
		return 0;

	return err;
}

__libnvme_public int libnvme_dump_config(struct libnvme_global_ctx *ctx, int fd)
{
	return json_update_config(ctx, fd);
}

__libnvme_public int libnvme_dump_tree(struct libnvme_global_ctx *ctx)
{
	return json_dump_tree(ctx);
}

__libnvme_public const char *libnvme_get_application(
		struct libnvme_global_ctx *ctx)
{
	return ctx->application;
}

__libnvme_public void libnvme_set_application(struct libnvme_global_ctx *ctx,
		const char *a)
{
	free(ctx->application);
	ctx->application = NULL;

	if (a)
		ctx->application = strdup(a);
}

__libnvme_public void libnvme_skip_namespaces(struct libnvme_global_ctx *ctx)
{
	ctx->create_only = true;
}

__libnvme_public libnvme_host_t libnvme_first_host(
		struct libnvme_global_ctx *ctx)
{
	return list_top(&ctx->hosts, struct libnvme_host, entry);
}

__libnvme_public libnvme_host_t libnvme_next_host(
		struct libnvme_global_ctx *ctx, libnvme_host_t h)
{
	return h ? list_next(&ctx->hosts, h, entry) : NULL;
}

__libnvme_public struct libnvme_global_ctx *libnvme_host_get_global_ctx(
		libnvme_host_t h)
{
	return h->ctx;
}

__libnvme_public void libnvme_host_set_pdc_enabled(
		libnvme_host_t h, bool enabled)
{
	h->pdc_enabled_valid = true;
	h->pdc_enabled = enabled;
}

__libnvme_public bool libnvme_host_is_pdc_enabled(
		libnvme_host_t h, bool fallback)
{
	if (h->pdc_enabled_valid)
		return h->pdc_enabled;
	return fallback;
}

__libnvme_public libnvme_subsystem_t libnvme_first_subsystem(libnvme_host_t h)
{
	return list_top(&h->subsystems, struct libnvme_subsystem, entry);
}

__libnvme_public libnvme_subsystem_t libnvme_next_subsystem(libnvme_host_t h,
		libnvme_subsystem_t s)
{
	return s ? list_next(&h->subsystems, s, entry) : NULL;
}

__libnvme_public void libnvme_refresh_topology(struct libnvme_global_ctx *ctx)
{
	struct libnvme_host *h, *_h;

	libnvme_for_each_host_safe(ctx, h, _h)
		__libnvme_free_host(h);
	libnvme_scan_topology(ctx, NULL, NULL);
}

void nvme_root_release_fds(struct libnvme_global_ctx *ctx)
{
	struct libnvme_host *h, *_h;

	libnvme_for_each_host_safe(ctx, h, _h)
		libnvme_host_release_fds(h);
}

__libnvme_public libnvme_ctrl_t libnvme_subsystem_first_ctrl(
		libnvme_subsystem_t s)
{
	return list_top(&s->ctrls, struct libnvme_ctrl, entry);
}

__libnvme_public libnvme_ctrl_t libnvme_subsystem_next_ctrl(
		libnvme_subsystem_t s, libnvme_ctrl_t c)
{
	return c ? list_next(&s->ctrls, c, entry) : NULL;
}

__libnvme_public libnvme_host_t libnvme_subsystem_get_host(
		libnvme_subsystem_t s)
{
	return s->h;
}

__libnvme_public char *libnvme_subsystem_get_iopolicy(libnvme_subsystem_t s)
{
	__cleanup_free char *iopolicy = NULL;

	iopolicy = libnvme_get_subsys_attr(s, "iopolicy");
	if (iopolicy) {
		if (!s->iopolicy || strcmp(iopolicy, s->iopolicy)) {
			free(s->iopolicy);
			s->iopolicy = strdup(iopolicy);
		}
	}

	return s->iopolicy;
}

__libnvme_public libnvme_ns_t libnvme_subsystem_first_ns(libnvme_subsystem_t s)
{
	return list_top(&s->namespaces, struct libnvme_ns, entry);
}

__libnvme_public libnvme_ns_t libnvme_subsystem_next_ns(libnvme_subsystem_t s,
		libnvme_ns_t n)
{
	return n ? list_next(&s->namespaces, n, entry) : NULL;
}

__libnvme_public libnvme_path_t libnvme_namespace_first_path(libnvme_ns_t ns)
{
	return list_top(&ns->head->paths, struct libnvme_path, nentry);
}

__libnvme_public libnvme_path_t libnvme_namespace_next_path(libnvme_ns_t ns,
		libnvme_path_t p)
{
	return p ? list_next(&ns->head->paths, p, nentry) : NULL;
}

static void __nvme_free_ns(struct libnvme_ns *n)
{
	struct libnvme_path *p, *_p;

	list_del_init(&n->entry);
	libnvme_ns_release_transport_handle(n);
	free(n->generic_name);
	free(n->name);
	free(n->sysfs_dir);
	libnvme_namespace_for_each_path_safe(n, p, _p) {
		list_del_init(&p->nentry);
		p->n = NULL;
	}
	list_head_init(&n->head->paths);
	free(n->head->sysfs_dir);
	free(n->head);
	free(n);
}

/* Stub for SWIG */
__libnvme_public void libnvme_free_ns(struct libnvme_ns *n)
{
	if (!n)
		return;

	__nvme_free_ns(n);
}

static void __nvme_free_subsystem(struct libnvme_subsystem *s)
{
	struct libnvme_ctrl *c, *_c;
	struct libnvme_ns *n, *_n;

	list_del_init(&s->entry);
	libnvme_subsystem_for_each_ctrl_safe(s, c, _c)
		__libnvme_free_ctrl(c);

	libnvme_subsystem_for_each_ns_safe(s, n, _n)
		__nvme_free_ns(n);

	free(s->name);
	free(s->sysfs_dir);
	free(s->subsysnqn);
	free(s->model);
	free(s->serial);
	free(s->firmware);
	free(s->subsystype);
	free(s->application);
	free(s->iopolicy);
	free(s);
}

__libnvme_public void libnvme_subsystem_release_fds(struct libnvme_subsystem *s)
{
	struct libnvme_ctrl *c, *_c;
	struct libnvme_ns *n, *_n;

	libnvme_subsystem_for_each_ctrl_safe(s, c, _c)
		libnvme_ctrl_release_transport_handle(c);

	libnvme_subsystem_for_each_ns_safe(s, n, _n)
		libnvme_ns_release_transport_handle(n);
}

/*
 * Stub for SWIG
 */
__libnvme_public void libnvme_free_subsystem(libnvme_subsystem_t s)
{
	if (!s)
		return;

	__nvme_free_subsystem(s);
}

struct libnvme_subsystem *nvme_alloc_subsystem(struct libnvme_host *h,
		const char *name, const char *subsysnqn)
{
	struct libnvme_subsystem *s;

	s = calloc(1, sizeof(*s));
	if (!s)
		return NULL;

	s->h = h;
	s->subsysnqn = strdup(subsysnqn);
	if (name)
		libnvme_init_subsystem(s, name);
	list_head_init(&s->ctrls);
	list_head_init(&s->namespaces);
	list_node_init(&s->entry);
	list_add_tail(&h->subsystems, &s->entry);
	return s;
}

struct libnvme_subsystem *libnvme_lookup_subsystem(struct libnvme_host *h,
		const char *name, const char *subsysnqn)
{
	struct libnvme_subsystem *s;

	libnvme_for_each_subsystem(h, s) {
		if (subsysnqn && s->subsysnqn &&
		    strcmp(s->subsysnqn, subsysnqn))
			continue;
		if (name && s->name &&
		    strcmp(s->name, name))
			continue;
		if (h->ctx->application) {
			if (!s->application)
				continue;
			if (strcmp(h->ctx->application, s->application))
				continue;
		}
		return s;
	}
	return nvme_alloc_subsystem(h, name, subsysnqn);
}

__libnvme_public int libnvme_get_subsystem(struct libnvme_global_ctx *ctx,
		struct libnvme_host *h, const char *name,
		const char *subsysnqn, struct libnvme_subsystem **subsys)
{
	struct libnvme_subsystem *s;

	s = libnvme_lookup_subsystem(h, name, subsysnqn);
	if (!s)
		return -ENOMEM;

	*subsys = s;

	return 0;
}

void __libnvme_free_host(struct libnvme_host *h)
{
	struct libnvme_subsystem *s, *_s;

	list_del_init(&h->entry);
	libnvme_for_each_subsystem_safe(h, s, _s)
		__nvme_free_subsystem(s);
	free(h->hostnqn);
	free(h->hostid);
	free(h->dhchap_host_key);
	libnvme_host_set_hostsymname(h, NULL);
	free(h);
}

__libnvme_public void libnvme_host_release_fds(struct libnvme_host *h)
{
	struct libnvme_subsystem *s, *_s;

	libnvme_for_each_subsystem_safe(h, s, _s)
		libnvme_subsystem_release_fds(s);
}

/* Stub for SWIG */
__libnvme_public void libnvme_free_host(struct libnvme_host *h)
{
	if (!h)
		return;

	__libnvme_free_host(h);
}

static int libnvme_create_host(struct libnvme_global_ctx *ctx,
		const char *hostnqn, const char *hostid,
		struct libnvme_host **host)
{
	struct libnvme_host *h;

	h = calloc(1, sizeof(*h));
	if (!h)
		return -ENOMEM;

	h->hostnqn = strdup(hostnqn);
	if (!hostid)
		hostid = nvme_hostid_from_hostnqn(hostnqn);
	if (hostid)
		h->hostid = strdup(hostid);
	list_head_init(&h->subsystems);
	list_node_init(&h->entry);
	h->ctx = ctx;

	list_add_tail(&ctx->hosts, &h->entry);

	*host = h;

	return 0;
}

struct libnvme_host *libnvme_lookup_host(struct libnvme_global_ctx *ctx,
		const char *hostnqn, const char *hostid)
{
	struct libnvme_host *h;

	if (!hostnqn)
		return NULL;

	libnvme_for_each_host(ctx, h) {
		if (strcmp(h->hostnqn, hostnqn))
			continue;
		if (hostid && (!h->hostid ||
		    strcmp(h->hostid, hostid)))
			continue;
		return h;
	}

	if (libnvme_create_host(ctx, hostnqn, hostid, &h))
		return NULL;

	return h;
}

static int nvme_subsystem_scan_namespaces(struct libnvme_global_ctx *ctx,
		libnvme_subsystem_t s)
{
	__cleanup_dirents struct dirents namespaces = {};
	int i, ret;

	if (ctx->create_only) {
		libnvme_msg(ctx, LIBNVME_LOG_DEBUG,
			 "skipping namespace scan for subsys %s\n",
			 s->subsysnqn);
		return 0;
	}
	namespaces.num = libnvme_scan_subsystem_namespaces(s, &namespaces.ents);
	if (namespaces.num < 0) {
		libnvme_msg(ctx, LIBNVME_LOG_DEBUG,
			"failed to scan namespaces for subsys %s: %s\n",
			s->subsysnqn, libnvme_strerror(-namespaces.num));
		return namespaces.num;
	}

	for (i = 0; i < namespaces.num; i++) {
		ret = libnvme_subsystem_scan_namespace(ctx, s,
				namespaces.ents[i]->d_name);
		if (ret < 0)
			libnvme_msg(ctx, LIBNVME_LOG_DEBUG,
				"failed to scan namespace %s: %s\n",
				namespaces.ents[i]->d_name,
				libnvme_strerror(-ret));
	}

	return 0;
}

static int libnvme_init_subsystem(libnvme_subsystem_t s, const char *name)
{
	char *path;

	if (asprintf(&path, "%s/%s", libnvme_subsys_sysfs_dir(), name) < 0)
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
	if (s->h->ctx->application)
		s->application = strdup(s->h->ctx->application);
	s->iopolicy = libnvme_get_attr(path, "iopolicy");

	return 0;
}

static int libnvme_scan_subsystem(struct libnvme_global_ctx *ctx,
		const char *name)
{
	struct libnvme_subsystem *s = NULL, *_s;
	__cleanup_free char *path = NULL, *subsysnqn = NULL;
	libnvme_host_t h = NULL;
	int ret;

	libnvme_msg(ctx, LIBNVME_LOG_DEBUG, "scan subsystem %s\n", name);
	ret = asprintf(&path, "%s/%s", libnvme_subsys_sysfs_dir(), name);
	if (ret < 0)
		return -ENOMEM;

	subsysnqn = libnvme_get_attr(path, "subsysnqn");
	if (!subsysnqn)
		return -ENODEV;
	libnvme_for_each_host(ctx, h) {
		libnvme_for_each_subsystem(h, _s) {
			/*
			 * We are always called after libnvme_scan_ctrl(),
			 * so any subsystem we're interested at _must_
			 * have a name.
			 */
			if (!_s->name)
				continue;
			if (strcmp(_s->name, name))
				continue;
			if (nvme_subsystem_scan_namespaces(ctx, _s))
				return -EINVAL;
			s = _s;
		}
	}
	if (!s) {
		/*
		 * Subsystem with non-matching controller. odd.
		 * Create a subsystem with the default host
		 * and hope for the best.
		 */
		libnvme_msg(ctx, LIBNVME_LOG_DEBUG,
			"creating detached subsystem '%s'\n", name);
		ret = libnvme_get_host(ctx, NULL, NULL, &h);
		if (ret)
			return ret;
		s = nvme_alloc_subsystem(h, name, subsysnqn);
		if (!s)
			return -ENOMEM;
		if (nvme_subsystem_scan_namespaces(ctx, s))
			return -EINVAL;
	} else if (strcmp(s->subsysnqn, subsysnqn)) {
		libnvme_msg(ctx, LIBNVME_LOG_DEBUG, "NQN mismatch for subsystem '%s'\n",
			 name);
		return -EINVAL;
	}

	return 0;
}

__libnvme_public libnvme_ctrl_t libnvme_path_get_ctrl(libnvme_path_t p)
{
	return p->c;
}

__libnvme_public libnvme_ns_t libnvme_path_get_ns(libnvme_path_t p)
{
	return p->n;
}

__libnvme_public int libnvme_path_get_queue_depth(libnvme_path_t p)
{
	__cleanup_free char *queue_depth = NULL;

	queue_depth = libnvme_get_path_attr(p, "queue_depth");
	if (queue_depth) {
		sscanf(queue_depth, "%d", &p->queue_depth);
	}

	return p->queue_depth;
}

__libnvme_public char *libnvme_path_get_ana_state(libnvme_path_t p)
{
	__cleanup_free char *ana_state = NULL;

	ana_state = libnvme_get_path_attr(p, "ana_state");
	if (ana_state) {
		if (!p->ana_state || strcmp(ana_state, p->ana_state)) {
			free(p->ana_state);
			p->ana_state = strdup(ana_state);
		}
	}

	return p->ana_state;
}

__libnvme_public char *libnvme_path_get_numa_nodes(libnvme_path_t p)
{
	__cleanup_free char *numa_nodes = NULL;

	numa_nodes = libnvme_get_path_attr(p, "numa_nodes");
	if (numa_nodes) {
		if (!p->numa_nodes || strcmp(numa_nodes, p->numa_nodes)) {
			free(p->numa_nodes);
			p->numa_nodes = strdup(numa_nodes);
		}
	}

	return p->numa_nodes;
}

__libnvme_public long libnvme_path_get_multipath_failover_count(
		libnvme_path_t p)
{
	__cleanup_free char *failover_count = NULL;

	failover_count = libnvme_get_path_attr(p, "multipath_failover_count");
	if (failover_count)
		sscanf(failover_count, "%ld", &p->multipath_failover_count);

	return p->multipath_failover_count;
}

__libnvme_public long libnvme_path_get_command_retry_count(libnvme_path_t p)
{
	__cleanup_free char *retry_count = NULL;

	retry_count = libnvme_get_path_attr(p, "command_retry_count");
	if (retry_count)
		sscanf(retry_count, "%ld", &p->command_retry_count);

	return p->command_retry_count;
}

__libnvme_public long libnvme_path_get_command_error_count(libnvme_path_t p)
{
	__cleanup_free char *error_count = NULL;

	error_count = libnvme_get_path_attr(p, "command_error_count");
	if (error_count)
		sscanf(error_count, "%ld", &p->command_error_count);

	return p->command_error_count;
}

static libnvme_stat_t libnvme_path_get_stat(libnvme_path_t p, unsigned int idx)
{
	if (idx > 1)
		return NULL;

	return &p->stat[idx];
}

__libnvme_public void libnvme_path_reset_stat(libnvme_path_t p)
{
	libnvme_stat_t stat = &p->stat[0];

	memset(stat, 0, 2 * sizeof(struct libnvme_stat));
}

static libnvme_stat_t libnvme_ns_get_stat(libnvme_ns_t n, unsigned int idx)
{
	if (idx > 1)
		return NULL;

	return &n->stat[idx];
}

__libnvme_public void libnvme_ns_reset_stat(libnvme_ns_t n)
{
	libnvme_stat_t stat = &n->stat[0];

	memset(stat, 0, 2 * sizeof(struct libnvme_stat));
}

static int libnvme_update_stat(const char *sysfs_stat_path, libnvme_stat_t stat)
{
	int n;
	struct timespec ts;
	unsigned long rd_ios, rd_merges, wr_ios, wr_merges;
	unsigned long dc_ios, dc_merges, fl_ios;
	unsigned long long rd_sectors, wr_sectors, dc_sectors;
	unsigned int rd_ticks, wr_ticks, dc_ticks, fl_ticks;
	unsigned int io_ticks, tot_ticks, inflights;

	memset(stat, 0, sizeof(struct libnvme_stat));

	n = sscanf(sysfs_stat_path,
		"%lu %lu %llu %u %lu %lu %llu %u %u %u %u %lu %lu %llu %u %lu %u",
		&rd_ios, &rd_merges, &rd_sectors, &rd_ticks,
		&wr_ios, &wr_merges, &wr_sectors, &wr_ticks,
		&inflights, &io_ticks, &tot_ticks,
		&dc_ios, &dc_merges, &dc_sectors, &dc_ticks,
		&fl_ios, &fl_ticks);

	if (n < 17)
		return -EINVAL;

	/* update read stat */
	stat->group[READ].ios = rd_ios;
	stat->group[READ].merges = rd_merges;
	stat->group[READ].sectors = rd_sectors;
	stat->group[READ].ticks = rd_ticks;

	/* update write stat */
	stat->group[WRITE].ios = wr_ios;
	stat->group[WRITE].merges = wr_merges;
	stat->group[WRITE].sectors = wr_sectors;
	stat->group[WRITE].ticks = wr_ticks;

	/* update inflight counters and ticks */
	stat->inflights = inflights;
	stat->io_ticks = io_ticks;
	stat->tot_ticks = tot_ticks;

	/* update discard stat */
	stat->group[DISCARD].ios = dc_ios;
	stat->group[DISCARD].merges = dc_merges;
	stat->group[DISCARD].sectors = dc_sectors;
	stat->group[DISCARD].ticks = dc_ticks;

	/* update flush stat */
	stat->group[FLUSH].ios = fl_ios;
	stat->group[FLUSH].ticks = fl_ticks;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	stat->ts_ms = ts.tv_sec * 1000 + (double)ts.tv_nsec / 1e6;

	return 0;
}

__libnvme_public int libnvme_path_update_stat(libnvme_path_t p, bool diffstat)
{
	__cleanup_free char *sysfs_stat_path = NULL;
	libnvme_stat_t stat;

	p->diffstat = diffstat;
	p->curr_idx ^= 1;
	stat = libnvme_path_get_stat(p, p->curr_idx);
	if (!stat)
		return -EINVAL;

	sysfs_stat_path = libnvme_get_path_attr(p, "stat");
	if (!sysfs_stat_path)
		return -EINVAL;

	return libnvme_update_stat(sysfs_stat_path, stat);
}

__libnvme_public int libnvme_ns_update_stat(libnvme_ns_t n, bool diffstat)
{
	__cleanup_free char *sysfs_stat_path = NULL;
	libnvme_stat_t stat;

	n->diffstat = diffstat;
	n->curr_idx ^= 1;
	stat = libnvme_ns_get_stat(n, n->curr_idx);
	if (!stat)
		return -EINVAL;

	sysfs_stat_path = libnvme_get_ns_attr(n, "stat");
	if (!sysfs_stat_path)
		return -EINVAL;

	return libnvme_update_stat(sysfs_stat_path, stat);
}

static int libnvme_stat_get_inflights(libnvme_stat_t stat)
{
	return stat->inflights;
}

__libnvme_public unsigned int libnvme_path_get_inflights(libnvme_path_t p)
{
	libnvme_stat_t curr;

	curr = libnvme_path_get_stat(p, p->curr_idx);
	if (!curr)
		return 0;

	return libnvme_stat_get_inflights(curr);
}

__libnvme_public unsigned int libnvme_ns_get_inflights(libnvme_ns_t n)
{
	libnvme_stat_t curr;

	curr = libnvme_ns_get_stat(n, n->curr_idx);
	if (!curr)
		return 0;

	return libnvme_stat_get_inflights(curr);
}

static int libnvme_stat_get_io_ticks(libnvme_stat_t curr, libnvme_stat_t prev,
		bool diffstat)
{
	unsigned int delta = 0;

	if (!diffstat)
		return curr->io_ticks;

	if (curr->io_ticks > prev->io_ticks)
		delta = curr->io_ticks - prev->io_ticks;

	return delta;
}

__libnvme_public unsigned int libnvme_path_get_io_ticks(libnvme_path_t p)
{
	libnvme_stat_t curr, prev;

	curr = libnvme_path_get_stat(p, p->curr_idx);
	prev = libnvme_path_get_stat(p, !p->curr_idx);

	if (!curr || !prev)
		return 0;

	return libnvme_stat_get_io_ticks(curr, prev, p->diffstat);
}

__libnvme_public unsigned int libnvme_ns_get_io_ticks(libnvme_ns_t n)
{
	libnvme_stat_t curr, prev;

	curr = libnvme_ns_get_stat(n, n->curr_idx);
	prev = libnvme_ns_get_stat(n, !n->curr_idx);

	if (!curr || !prev)
		return 0;

	return libnvme_stat_get_io_ticks(curr, prev, n->diffstat);
}

static unsigned int libnvme_stat_get_ticks(libnvme_stat_t curr,
		libnvme_stat_t prev, enum libnvme_stat_group grp, bool diffstat)
{
	unsigned int delta = 0;

	if (!diffstat)
		return curr->group[grp].ticks;

	if (curr->group[grp].ticks > prev->group[grp].ticks)
		delta = curr->group[grp].ticks - prev->group[grp].ticks;

	return delta;
}

static unsigned int __libnvme_path_get_ticks(libnvme_path_t p,
		enum libnvme_stat_group grp)
{
	libnvme_stat_t curr, prev;

	curr = libnvme_path_get_stat(p, p->curr_idx);
	prev = libnvme_path_get_stat(p, !p->curr_idx);

	if (!curr || !prev)
		return 0;

	return libnvme_stat_get_ticks(curr, prev, grp, p->diffstat);
}

__libnvme_public unsigned int libnvme_path_get_read_ticks(libnvme_path_t p)
{
	return __libnvme_path_get_ticks(p, READ);
}

__libnvme_public unsigned int libnvme_path_get_write_ticks(libnvme_path_t p)
{
	return __libnvme_path_get_ticks(p, WRITE);
}

static unsigned int __libnvme_ns_get_ticks(libnvme_ns_t n,
		enum libnvme_stat_group grp)
{
	libnvme_stat_t curr, prev;

	curr = libnvme_ns_get_stat(n, n->curr_idx);
	prev = libnvme_ns_get_stat(n, !n->curr_idx);

	if (!curr || !prev)
		return 0;

	return libnvme_stat_get_ticks(curr, prev, grp, n->diffstat);
}

__libnvme_public unsigned int libnvme_ns_get_read_ticks(libnvme_ns_t n)
{
	return __libnvme_ns_get_ticks(n, READ);
}

__libnvme_public unsigned int libnvme_ns_get_write_ticks(libnvme_ns_t n)
{
	return __libnvme_ns_get_ticks(n, WRITE);
}

static double libnvme_stat_get_interval(libnvme_stat_t curr,
		libnvme_stat_t prev)
{
	double delta = 0.0;

	if (prev->ts_ms && curr->ts_ms > prev->ts_ms)
		delta = curr->ts_ms - prev->ts_ms;

	return delta;
}

__libnvme_public double libnvme_path_get_stat_interval(libnvme_path_t p)
{
	libnvme_stat_t curr, prev;

	curr = libnvme_path_get_stat(p, p->curr_idx);
	prev = libnvme_path_get_stat(p, !p->curr_idx);

	if (!curr || !prev)
		return 0;

	return libnvme_stat_get_interval(curr, prev);
}

__libnvme_public double libnvme_ns_get_stat_interval(libnvme_ns_t n)
{
	libnvme_stat_t curr, prev;

	curr = libnvme_ns_get_stat(n, n->curr_idx);
	prev = libnvme_ns_get_stat(n, !n->curr_idx);

	if (!curr || !prev)
		return 0;

	return libnvme_stat_get_interval(curr, prev);
}

static unsigned long libnvme_stat_get_ios(libnvme_stat_t curr,
		libnvme_stat_t prev, enum libnvme_stat_group grp, bool diffstat)
{
	unsigned long ios = 0;

	if (!diffstat)
		return curr->group[grp].ios;

	if (curr->group[grp].ios > prev->group[grp].ios)
		ios = curr->group[grp].ios - prev->group[grp].ios;

	return ios;
}

static unsigned long __libnvme_path_get_ios(libnvme_path_t p,
		enum libnvme_stat_group grp)
{
	libnvme_stat_t curr, prev;

	curr = libnvme_path_get_stat(p, p->curr_idx);
	prev = libnvme_path_get_stat(p, !p->curr_idx);

	if (!curr || !prev)
		return 0;

	return libnvme_stat_get_ios(curr, prev, grp, p->diffstat);
}

__libnvme_public unsigned long libnvme_path_get_read_ios(libnvme_path_t p)
{
	return __libnvme_path_get_ios(p, READ);
}

__libnvme_public unsigned long libnvme_path_get_write_ios(libnvme_path_t p)
{
	return __libnvme_path_get_ios(p, WRITE);
}

static unsigned long __libnvme_ns_get_ios(libnvme_ns_t n,
		enum libnvme_stat_group grp)
{
	libnvme_stat_t curr, prev;

	curr = libnvme_ns_get_stat(n, n->curr_idx);
	prev = libnvme_ns_get_stat(n, !n->curr_idx);

	if (!curr || !prev)
		return 0;

	return libnvme_stat_get_ios(curr, prev, grp, n->diffstat);
}

__libnvme_public unsigned long libnvme_ns_get_read_ios(libnvme_ns_t n)
{
	return __libnvme_ns_get_ios(n, READ);
}

__libnvme_public unsigned long libnvme_ns_get_write_ios(libnvme_ns_t n)
{
	return __libnvme_ns_get_ios(n, WRITE);
}

static unsigned long long libnvme_stat_get_sectors(libnvme_stat_t curr,
		libnvme_stat_t prev, enum libnvme_stat_group grp, bool diffstat)
{
	unsigned long long sec = 0;

	if (!diffstat)
		return curr->group[grp].sectors;

	if (curr->group[grp].sectors > prev->group[grp].sectors)
		sec = curr->group[grp].sectors - prev->group[grp].sectors;

	return sec;
}

static unsigned long long __libnvme_path_get_sectors(libnvme_path_t p,
		enum libnvme_stat_group grp)
{
	libnvme_stat_t curr, prev;

	curr = libnvme_path_get_stat(p, p->curr_idx);
	prev = libnvme_path_get_stat(p, !p->curr_idx);

	if (!curr || !prev)
		return 0;

	return libnvme_stat_get_sectors(curr, prev, grp, p->diffstat);
}

__libnvme_public unsigned long long libnvme_path_get_read_sectors(
		libnvme_path_t p)
{
	return __libnvme_path_get_sectors(p, READ);
}

__libnvme_public unsigned long long libnvme_path_get_write_sectors(
		libnvme_path_t p)
{
	return __libnvme_path_get_sectors(p, WRITE);
}

static unsigned long long __libnvme_ns_get_sectors(libnvme_ns_t n,
		enum libnvme_stat_group grp)
{
	libnvme_stat_t curr, prev;

	curr = libnvme_ns_get_stat(n, n->curr_idx);
	prev = libnvme_ns_get_stat(n, !n->curr_idx);

	if (!curr || !prev)
		return 0;

	return libnvme_stat_get_sectors(curr, prev, grp, n->diffstat);
}

__libnvme_public unsigned long long libnvme_ns_get_read_sectors(libnvme_ns_t n)
{
	return __libnvme_ns_get_sectors(n, READ);
}

__libnvme_public unsigned long long libnvme_ns_get_write_sectors(libnvme_ns_t n)
{
	return __libnvme_ns_get_sectors(n, WRITE);
}

void nvme_free_path(struct libnvme_path *p)
{
	if (!p)
		return;

	list_del_init(&p->entry);
	list_del_init(&p->nentry);
	free(p->name);
	free(p->sysfs_dir);
	free(p->ana_state);
	free(p->numa_nodes);
	free(p);
}

static int libnvme_ctrl_scan_path(struct libnvme_global_ctx *ctx,
		struct libnvme_ctrl *c, char *name)
{
	struct libnvme_path *p;
	__cleanup_free char *path = NULL, *grpid = NULL, *queue_depth = NULL;
	int ret;

	libnvme_msg(ctx, LIBNVME_LOG_DEBUG, "scan controller %s path %s\n",
		 c->name, name);
	if (!c->s)
		return -ENXIO;

	ret = asprintf(&path, "%s/%s", c->sysfs_dir, name);
	if (ret < 0)
		return -ENOMEM;

	p = calloc(1, sizeof(*p));
	if (!p)
		return -ENOMEM;

	p->c = c;
	p->name = strdup(name);
	p->sysfs_dir = path;
	path = NULL;
	p->ana_state = libnvme_get_path_attr(p, "ana_state");
	if (!p->ana_state)
		p->ana_state = strdup("optimized");

	p->numa_nodes = libnvme_get_path_attr(p, "numa_nodes");
	if (!p->numa_nodes)
		p->numa_nodes = strdup("-1");

	grpid = libnvme_get_path_attr(p, "ana_grpid");
	if (grpid) {
		sscanf(grpid, "%d", &p->grpid);
	}

	queue_depth = libnvme_get_path_attr(p, "queue_depth");
	if (queue_depth) {
		sscanf(queue_depth, "%d", &p->queue_depth);
	}

	list_node_init(&p->nentry);
	list_node_init(&p->entry);
	list_add_tail(&c->paths, &p->entry);
	return 0;
}

__libnvme_public struct libnvme_transport_handle *libnvme_ctrl_get_transport_handle(
		libnvme_ctrl_t c)
{
	if (!c->hdl) {
		int err;

		err = libnvme_open(c->ctx, c->name, &c->hdl);
		if (err)
			libnvme_msg(c->ctx, LIBNVME_LOG_ERR,
				 "Failed to open ctrl %s, errno %d\n",
				 c->name, err);
	}
	return c->hdl;
}

__libnvme_public void libnvme_ctrl_release_transport_handle(libnvme_ctrl_t c)
{
	if (!c->hdl)
		return;

	libnvme_close(c->hdl);
	c->hdl = NULL;
}

__libnvme_public libnvme_subsystem_t libnvme_ctrl_get_subsystem(
		libnvme_ctrl_t c)
{
	return c->s;
}


__libnvme_public char *libnvme_ctrl_get_src_addr(
		libnvme_ctrl_t c, char *src_addr, size_t src_addr_len)
{
	size_t l;
	char *p;

	if (!c->address)
		return NULL;

	p = strstr(c->address, "src_addr=");
	if (!p)
		return NULL;

	p += strlen("src_addr=");
	l = strcspn(p, ",%"); /* % to eliminate IPv6 scope (if present) */
	if (l >= src_addr_len) {
		libnvme_msg(c->ctx, LIBNVME_LOG_ERR,
			"Buffer for src_addr is too small (%zu must be > %zu)\n",
			src_addr_len, l);
		return NULL;
	}

	strncpy(src_addr, p, l);
	src_addr[l] = '\0';
	return src_addr;
}

__libnvme_public const char *libnvme_ctrl_get_state(libnvme_ctrl_t c)
{
	char *state = c->state;

	c->state = libnvme_get_ctrl_attr(c, "state");
	free(state);
	return c->state;
}

__libnvme_public long libnvme_ctrl_get_command_error_count(libnvme_ctrl_t c)
{
	__cleanup_free char *error_count = NULL;

	error_count = libnvme_get_ctrl_attr(c, "command_error_count");
	if (error_count)
		sscanf(error_count, "%ld", &c->command_error_count);

	return c->command_error_count;
}

__libnvme_public long libnvme_ctrl_get_reset_count(libnvme_ctrl_t c)
{
	__cleanup_free char *reset_count = NULL;

	reset_count = libnvme_get_ctrl_attr(c, "reset_count");
	if (reset_count)
		sscanf(reset_count, "%ld", &c->reset_count);

	return c->reset_count;
}

__libnvme_public long libnvme_ctrl_get_reconnect_count(libnvme_ctrl_t c)
{
	__cleanup_free char *reconnect_count = NULL;

	reconnect_count = libnvme_get_ctrl_attr(c, "reconnect_count");
	if (reconnect_count)
		sscanf(reconnect_count, "%ld", &c->reconnect_count);

	return c->reconnect_count;
}

__libnvme_public int libnvme_ctrl_identify(
		libnvme_ctrl_t c, struct nvme_id_ctrl *id)
{
	struct libnvme_transport_handle *hdl =
		libnvme_ctrl_get_transport_handle(c);
	struct libnvme_passthru_cmd cmd;

	nvme_init_identify_ctrl(&cmd, id);
	return libnvme_exec_admin_passthru(hdl, &cmd);
}

__libnvme_public libnvme_ns_t libnvme_ctrl_first_ns(libnvme_ctrl_t c)
{
	return list_top(&c->namespaces, struct libnvme_ns, entry);
}

__libnvme_public libnvme_ns_t libnvme_ctrl_next_ns(
		libnvme_ctrl_t c, libnvme_ns_t n)
{
	return n ? list_next(&c->namespaces, n, entry) : NULL;
}

__libnvme_public libnvme_path_t libnvme_ctrl_first_path(libnvme_ctrl_t c)
{
	return list_top(&c->paths, struct libnvme_path, entry);
}

__libnvme_public libnvme_path_t libnvme_ctrl_next_path(libnvme_ctrl_t c,
		libnvme_path_t p)
{
	return p ? list_next(&c->paths, p, entry) : NULL;
}

#define FREE_CTRL_ATTR(a) \
	do { free(a); (a) = NULL; } while (0)
void nvme_deconfigure_ctrl(libnvme_ctrl_t c)
{
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
	FREE_CTRL_ATTR(c->dhchap_host_key);
	FREE_CTRL_ATTR(c->dhchap_ctrl_key);
	FREE_CTRL_ATTR(c->keyring);
	FREE_CTRL_ATTR(c->tls_key_identity);
	FREE_CTRL_ATTR(c->tls_key);
	FREE_CTRL_ATTR(c->address);
	FREE_CTRL_ATTR(c->dctype);
	FREE_CTRL_ATTR(c->cntrltype);
	FREE_CTRL_ATTR(c->cntlid);
	FREE_CTRL_ATTR(c->phy_slot);
}

__libnvme_public void libnvme_unlink_ctrl(libnvme_ctrl_t c)
{
	list_del_init(&c->entry);
	c->s = NULL;
}

static void __libnvme_free_ctrl(libnvme_ctrl_t c)
{
	struct libnvme_path *p, *_p;
	struct libnvme_ns *n, *_n;

	libnvme_unlink_ctrl(c);

	libnvme_ctrl_for_each_path_safe(c, p, _p)
		nvme_free_path(p);

	libnvme_ctrl_for_each_ns_safe(c, n, _n)
		__nvme_free_ns(n);

	nvme_deconfigure_ctrl(c);

	FREE_CTRL_ATTR(c->transport);
	FREE_CTRL_ATTR(c->subsysnqn);
	FREE_CTRL_ATTR(c->traddr);
	FREE_CTRL_ATTR(c->host_traddr);
	FREE_CTRL_ATTR(c->host_iface);
	FREE_CTRL_ATTR(c->trsvcid);
	free(c);
}

__libnvme_public void libnvme_free_ctrl(libnvme_ctrl_t c)
{
	if (!c)
		return;

	__libnvme_free_ctrl(c);
}

int _libnvme_create_ctrl(struct libnvme_global_ctx *ctx,
		struct libnvmf_context *fctx, libnvme_ctrl_t *cp)
{
	struct libnvme_ctrl *c;

	if (!fctx->transport) {
		libnvme_msg(ctx, LIBNVME_LOG_ERR, "No transport specified\n");
		return -EINVAL;
	}
	if (strncmp(fctx->transport, "loop", 4) &&
	    strncmp(fctx->transport, "pcie", 4) &&
	    strncmp(fctx->transport, "apple-nvme", 10) && !fctx->traddr) {
		libnvme_msg(ctx, LIBNVME_LOG_ERR, "No transport address for '%s'\n",
			 fctx->transport);
	       return -EINVAL;
	}
	if (!fctx->subsysnqn) {
		libnvme_msg(ctx, LIBNVME_LOG_ERR, "No subsystem NQN specified\n");
		return -EINVAL;
	}
	c = calloc(1, sizeof(*c));
	if (!c)
		return -ENOMEM;

	c->ctx = ctx;
	c->hdl = NULL;
	c->cfg = fctx->cfg;
	list_head_init(&c->namespaces);
	list_head_init(&c->paths);
	list_node_init(&c->entry);
	c->transport = strdup(fctx->transport);
	c->subsysnqn = strdup(fctx->subsysnqn);
	if (fctx->traddr)
		c->traddr = strdup(fctx->traddr);
	if (fctx->host_traddr) {
		if (traddr_is_hostname(ctx, fctx->transport, fctx->host_traddr))
			hostname2traddr(ctx, fctx->host_traddr,
					&c->host_traddr);
		if (!c->host_traddr)
			c->host_traddr = strdup(fctx->host_traddr);
	}
	if (fctx->host_iface)
		c->host_iface = strdup(fctx->host_iface);
	if (fctx->trsvcid)
		c->trsvcid = strdup(fctx->trsvcid);

	*cp = c;
	return 0;
}

#ifdef CONFIG_FABRICS
/**
 * _tcp_ctrl_match_host_traddr_no_src_addr() - Match host_traddr w/o src_addr
 * @c:	An existing controller instance
 * @candidate:	Candidate ctrl we're trying to match with @c.
 *
 * On kernels prior to 6.1 (i.e. src_addr is not available), try to match
 * a candidate controller's host_traddr to that of an existing controller.
 *
 * This function takes an optimistic approach. In doubt, it will declare a
 * match and return true.
 *
 * Return: true if @c->host_traddr matches @candidate->host_traddr. false otherwise.
 */
static bool _tcp_ctrl_match_host_traddr_no_src_addr(struct libnvme_ctrl *c,
		struct candidate_args *candidate)
{
	if (c->host_traddr)
		return candidate->addreq(candidate->host_traddr,
			c->host_traddr);

	/* If c->cfg.host_traddr is NULL, then the controller (c)
	 * uses the interface's primary address as the source
	 * address. If c->cfg.host_iface is defined we can
	 * determine the primary address associated with that
	 * interface and compare that to the candidate->host_traddr.
	 */
	if (c->host_iface)
		return libnvme_iface_primary_addr_matches(candidate->iface_list,
			c->host_iface, candidate->host_traddr);

	/* If both c->cfg.host_traddr and c->cfg.host_iface are
	 * NULL, we don't have enough information to make a
	 * 100% positive match. Regardless, let's be optimistic
	 * and assume that we have a match.
	 */
	libnvme_msg(c->ctx, LIBNVME_LOG_DEBUG,
		"Not enough data, but assume %s matches candidate's host_traddr: %s\n",
		libnvme_ctrl_get_name(c), candidate->host_traddr);

	return true;
}

/**
 * _tcp_ctrl_match_host_iface_no_src_addr() - Match host_iface w/o src_addr
 * @c:	An existing controller instance
 * @candidate:	Candidate ctrl we're trying to match with @c.
 *
 * On kernels prior to 6.1 (i.e. src_addr is not available), try to match
 * a candidate controller's host_iface to that of an existing controller.
 *
 * This function takes an optimistic approach. In doubt, it will declare a
 * match and return true.
 *
 * Return: true if @c->host_iface matches @candidate->host_iface. false otherwise.
 */
static bool _tcp_ctrl_match_host_iface_no_src_addr(struct libnvme_ctrl *c,
		struct candidate_args *candidate)
{
	if (c->host_iface)
		return streq0(candidate->host_iface, c->host_iface);

	/* If c->cfg.host_traddr is not NULL we can infer the controller's (c)
	 * interface from it and compare it to the candidate->host_iface.
	 */
	if (c->host_traddr) {
		const char *c_host_iface;

		c_host_iface =
			libnvme_iface_matching_addr(candidate->iface_list,
				c->host_traddr);
		return streq0(candidate->host_iface, c_host_iface);
	}

	/* If both c->cfg.host_traddr and c->cfg.host_iface are
	 * NULL, we don't have enough information to make a
	 * 100% positive match. Regardless, let's be optimistic
	 * and assume that we have a match.
	 */
	libnvme_msg(c->ctx, LIBNVME_LOG_DEBUG,
		"Not enough data, but assume %s matches candidate's host_iface: %s\n",
		libnvme_ctrl_get_name(c), candidate->host_iface);

	return true;
}

/**
 * _tcp_opt_params_match_no_src_addr() - Match optional
 * host_traddr/host_iface w/o src_addr
 * @c:	An existing controller instance
 * @candidate:	Candidate ctrl we're trying to match with @c.
 *
 * Before kernel 6.1, the src_addr was not reported by the kernel which makes
 * it hard to match a candidate's host_traddr and host_iface to an existing
 * controller if that controller was created without specifying the
 * host_traddr and/or host_iface. This function tries its best in the absense
 * of a src_addr to match @c to @candidate. This may not be 100% accurate.
 * Only the src_addr can provide 100% accuracy.
 *
 * This function takes an optimistic approach. In doubt, it will declare a
 * match and return true.
 *
 * Return: true if @c matches @candidate. false otherwise.
 */
static bool _tcp_opt_params_match_no_src_addr(struct libnvme_ctrl *c,
		struct candidate_args *candidate)
{
	/* Check host_traddr only if candidate is interested */
	if (candidate->host_traddr) {
		if (!_tcp_ctrl_match_host_traddr_no_src_addr(c, candidate))
			return false;
	}

	/* Check host_iface only if candidate is interested */
	if (candidate->host_iface) {
		if (!_tcp_ctrl_match_host_iface_no_src_addr(c, candidate))
			return false;
	}

	return true;
}

/**
 * _tcp_opt_params_match() - Match optional host_traddr/host_iface
 * @c:	An existing controller instance
 * @candidate:	Candidate ctrl we're trying to match with @c.
 *
 * The host_traddr and host_iface are optional for TCP. When they are not
 * specified, the kernel looks up the destination IP address (traddr) in the
 * routing table to determine the best interface for the connection. The
 * kernel then retrieves the primary IP address assigned to that interface
 * and uses that as the connection’s source address.
 *
 * An interface’s primary address is the default source address used for
 * all connections made on that interface unless host-traddr is used to
 * override the default. Kernel-selected interfaces and/or source addresses
 * are hidden from user-space applications unless the kernel makes that
 * information available through the "src_addr" attribute in the
 * sysfs (kernel 6.1 or later).
 *
 * Sometimes, an application may force the interface by specifying the
 * "host-iface" or may force a different source address (instead of the
 * primary address) by providing the "host-traddr".
 *
 * If the candidate specifies the host_traddr and/or host_iface but they
 * do not match the existing controller's host_traddr and/or host_iface
 * (they could be NULL), we may still be able to find a match by taking
 * the existing controller's src_addr into consideration since that
 * parameter identifies the actual source address of the connection and
 * therefore can be used to infer the interface of the connection. However,
 * the src_addr can only be read from the nvme device's sysfs "address"
 * attribute starting with kernel 6.1 (or kernels that backported the
 * src_addr patch).
 *
 * For legacy kernels that do not provide the src_addr we must use a
 * different algorithm to match the host_traddr and host_iface, but
 * it's not 100% accurate.
 *
 * Return: true if @c matches @candidate. false otherwise.
 */
static bool _tcp_opt_params_match(struct libnvme_ctrl *c,
		struct candidate_args *candidate)
{
	char *src_addr, buffer[INET6_ADDRSTRLEN];

	/* Check if src_addr is available (kernel 6.1 or later) */
	src_addr = libnvme_ctrl_get_src_addr(c, buffer, sizeof(buffer));
	if (!src_addr)
		return _tcp_opt_params_match_no_src_addr(c, candidate);

	/* Check host_traddr only if candidate is interested */
	if (candidate->host_traddr &&
	    !candidate->addreq(candidate->host_traddr, src_addr))
		return false;

	/* Check host_iface only if candidate is interested */
	if (candidate->host_iface &&
	    !streq0(candidate->host_iface,
		    libnvme_iface_matching_addr(candidate->iface_list, src_addr)))
		return false;

	return true;
}

/**
 * _tcp_match_ctrl() - Check if controller matches candidate (TCP only)
 * @c:	An existing controller instance
 * @candidate:	Candidate ctrl we're trying to match with @c.
 *
 * We want to determine if an existing controller can be re-used
 * for the candidate controller we're trying to instantiate.
 *
 * For TCP, we do not have a match if the candidate's transport, traddr,
 * trsvcid are not identical to those of the the existing controller.
 * These 3 parameters are mandatory for a match.
 *
 * The host_traddr and host_iface are optional. When the candidate does
 * not specify them (both NULL), we can ignore them. Otherwise, we must
 * employ advanced investigation techniques to determine if there's a match.
 *
 * Return: true if a match is found, false otherwise.
 */
static bool _tcp_match_ctrl(struct libnvme_ctrl *c,
		struct candidate_args *candidate)
{
	if (!streq0(c->transport, candidate->transport))
		return false;

	if (!streq0(c->trsvcid, candidate->trsvcid))
		return false;

	if (!candidate->addreq(c->traddr, candidate->traddr))
		return false;

	if (candidate->well_known_nqn && !libnvme_ctrl_get_discovery_ctrl(c))
		return false;

	if (candidate->subsysnqn && !streq0(c->subsysnqn, candidate->subsysnqn))
		return false;

	/* Check host_traddr / host_iface only if candidate is interested */
	if ((candidate->host_iface || candidate->host_traddr) &&
	    !_tcp_opt_params_match(c, candidate))
		return false;

	return true;
}
#endif

/**
 * _match_ctrl() - Check if controller matches candidate (non TCP transport)
 * @c:	An existing controller instance
 * @candidate:	Candidate ctrl we're trying to match with @c.
 *
 * We want to determine if an existing controller can be re-used
 * for the candidate controller we're trying to instantiate. This function
 * is used for all transports except TCP.
 *
 * Return: true if a match is found, false otherwise.
 */
static bool _match_ctrl(struct libnvme_ctrl *c,
		struct candidate_args *candidate)
{
	if (!streq0(c->transport, candidate->transport))
		return false;

	if (candidate->traddr && c->traddr &&
	    !candidate->addreq(c->traddr, candidate->traddr))
		return false;

	if (candidate->host_traddr && c->host_traddr &&
	    !candidate->addreq(c->host_traddr, candidate->host_traddr))
		return false;

	if (candidate->host_iface && c->host_iface &&
	    !streq0(c->host_iface, candidate->host_iface))
		return false;

	if (candidate->trsvcid && c->trsvcid &&
	    !streq0(c->trsvcid, candidate->trsvcid))
		return false;

	if (candidate->well_known_nqn && !libnvme_ctrl_get_discovery_ctrl(c))
		return false;

	if (candidate->subsysnqn && !streq0(c->subsysnqn, candidate->subsysnqn))
		return false;

	return true;
}

/**
 * _candidate_init() - Init candidate and get the matching function
 *
 * @candidate:		Candidate struct to initialize
 * @transport:		Transport name
 * @traddr:		Transport address
 * @trsvcid:		Transport service identifier
 * @subsysnqn:		Subsystem NQN
 * @host_traddr:	Host transport address
 * @host_iface:		Host interface name
 * @host_iface:		Host interface name
 *
 * The function _candidate_free() must be called to release resources once
 * the candidate object is not longer required.
 *
 * Return: The matching function to use when comparing an existing
 * controller to the candidate controller.
 */
static ctrl_match_t _candidate_init(struct libnvme_global_ctx *ctx,
		struct candidate_args *candidate, struct libnvmf_context *fctx)
{
	memset(candidate, 0, sizeof(*candidate));

	candidate->traddr = fctx->traddr;
	candidate->trsvcid = fctx->trsvcid;
	candidate->transport = fctx->transport;
	candidate->subsysnqn = fctx->subsysnqn;
	candidate->host_iface = streqcase0(fctx->host_iface, "none") ?
		NULL : fctx->host_iface;
	candidate->host_traddr = streqcase0(fctx->host_traddr, "none") ?
		NULL : fctx->host_traddr;

	if (streq0(fctx->subsysnqn, NVME_DISC_SUBSYS_NAME)) {
		/* Since TP8013, the NQN of discovery controllers can be the
		 * well-known NQN (i.e. nqn.2014-08.org.nvmexpress.discovery) or
		 * a unique NQN. A DC created using the well-known NQN may later
		 * display a unique NQN when looked up in the sysfs. Therefore,
		 * ignore (i.e. set to NULL) the well-known NQN when looking for
		 * a match.
		 */
		candidate->subsysnqn = NULL;
		candidate->well_known_nqn = true;
	}

#ifdef CONFIG_FABRICS
	if (streq0(fctx->transport, "tcp")) {
		candidate->iface_list = libnvmf_getifaddrs(ctx); /* TCP only */
		candidate->addreq = libnvme_ipaddrs_eq;
		return _tcp_match_ctrl;
	}

	if (streq0(fctx->transport, "rdma")) {
		candidate->addreq = libnvme_ipaddrs_eq;
		return _match_ctrl;
	}
#endif

	/* All other transport types */
	candidate->addreq = streqcase0;
	return _match_ctrl;
}

static libnvme_ctrl_t __nvme_ctrl_find(libnvme_subsystem_t s,
		struct libnvmf_context *fctx, libnvme_ctrl_t p)
{
	struct candidate_args candidate = {};
	struct libnvme_ctrl *c, *matching_c = NULL;
	ctrl_match_t ctrl_match;

	/* Init candidate and get the matching function to use */
	ctrl_match = _candidate_init(s->h->ctx, &candidate, fctx);

	c = p ? libnvme_subsystem_next_ctrl(s, p) : libnvme_subsystem_first_ctrl(s);
	for (; c != NULL; c = libnvme_subsystem_next_ctrl(s, c)) {
		if (ctrl_match(c, &candidate)) {
			matching_c = c;
			break;
		}
	}

	return matching_c;
}

bool _libnvme_ctrl_match_config(struct libnvme_ctrl *c,
		struct libnvmf_context *fctx)
{
	struct candidate_args candidate = {};
	ctrl_match_t ctrl_match;

	/* Init candidate and get the matching function to use */
	ctrl_match = _candidate_init(c->ctx, &candidate, fctx);

	return ctrl_match(c, &candidate);
}

__libnvme_public bool libnvme_ctrl_match_config(struct libnvme_ctrl *c,
		const char *transport, const char *traddr, const char *trsvcid,
		const char *subsysnqn, const char *host_traddr,
		const char *host_iface)
{
	struct libnvmf_context fctx = {
		.transport = transport,
		.traddr = traddr,
		.host_traddr = host_traddr,
		.host_iface = host_iface,
		.trsvcid = trsvcid,
		.subsysnqn = subsysnqn,
	};

	return _libnvme_ctrl_match_config(c, &fctx);
}

libnvme_ctrl_t libnvme_ctrl_find(libnvme_subsystem_t s,
		struct libnvmf_context *fctx)
{
	return __nvme_ctrl_find(s, fctx, NULL/*p*/);
}

libnvme_ctrl_t libnvme_lookup_ctrl(libnvme_subsystem_t s,
			     struct libnvmf_context *fctx,
			     libnvme_ctrl_t p)
{
	struct libnvme_global_ctx *ctx;
	struct libnvme_ctrl *c;
	const char *subsysnqn = fctx->subsysnqn;
	int ret;

	if (!s || !fctx->transport)
		return NULL;

	/* Clear out subsysnqn; might be different for discovery subsystems */
	fctx->subsysnqn = NULL;
	c = __nvme_ctrl_find(s, fctx, p);
	if (c) {
		fctx->subsysnqn = subsysnqn;
		return c;
	}

	ctx = s->h ? s->h->ctx : NULL;
	/* Set the NQN to the subsystem the controller should be created in */
	fctx->subsysnqn = s->subsysnqn;
	libnvmf_default_config(&fctx->cfg);
	ret = _libnvme_create_ctrl(ctx, fctx, &c);
	/* And restore NQN to avoid issues with repetitive calls */
	fctx->subsysnqn = subsysnqn;
	if (ret)
		return NULL;

	c->s = s;
	list_add_tail(&s->ctrls, &c->entry);

	return c;
}

static int libnvme_ctrl_scan_paths(struct libnvme_global_ctx *ctx,
			struct libnvme_ctrl *c)
{
	__cleanup_dirents struct dirents paths = {};
	int err, i;

	if (ctx->create_only) {
		libnvme_msg(ctx, LIBNVME_LOG_DEBUG,
			 "skipping path scan for ctrl %s\n", c->name);
		return 0;
	}
	paths.num = libnvme_scan_ctrl_namespace_paths(c, &paths.ents);
	if (paths.num < 0)
		return paths.num;

	for (i = 0; i < paths.num; i++) {
		err = libnvme_ctrl_scan_path(ctx, c, paths.ents[i]->d_name);
		if (err)
			return err;
	}

	return 0;
}

static int libnvme_ctrl_scan_namespaces(struct libnvme_global_ctx *ctx,
		struct libnvme_ctrl *c)
{
	__cleanup_dirents struct dirents namespaces = {};
	int err, i;

	if (ctx->create_only) {
		libnvme_msg(ctx, LIBNVME_LOG_DEBUG,
			"skipping namespace scan for ctrl %s\n", c->name);
		return 0;
	}
	namespaces.num = libnvme_scan_ctrl_namespaces(c, &namespaces.ents);
	for (i = 0; i < namespaces.num; i++) {
		err = libnvme_ctrl_scan_namespace(ctx, c,
			namespaces.ents[i]->d_name);
		if (err)
			return err;
	}

	return 0;
}

static int libnvme_ctrl_lookup_subsystem_name(struct libnvme_global_ctx *ctx,
		const char *ctrl_name, char **name)
{
	const char *subsys_dir = libnvme_subsys_sysfs_dir();
	__cleanup_dirents struct dirents subsys = {};
	int i;

	subsys.num = libnvme_scan_subsystems(&subsys.ents);
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
	const char *slots_sysfs_dir = libnvme_slots_sysfs_dir();
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

static void libnvme_read_sysfs_dhchap(struct libnvme_global_ctx *ctx,
		libnvme_ctrl_t c)
{
	char *host_key, *ctrl_key;

	host_key = libnvme_get_ctrl_attr(c, "dhchap_secret");
	if (host_key && !strcmp(host_key, "none")) {
		free(host_key);
		host_key = NULL;
	}
	if (host_key) {
		libnvme_ctrl_set_dhchap_host_key(c, NULL);
		c->dhchap_host_key = host_key;
	}

	ctrl_key = libnvme_get_ctrl_attr(c, "dhchap_ctrl_secret");
	if (ctrl_key && !strcmp(ctrl_key, "none")) {
		free(ctrl_key);
		ctrl_key = NULL;
	}
	if (ctrl_key) {
		libnvme_ctrl_set_dhchap_ctrl_key(c, NULL);
		c->dhchap_ctrl_key = ctrl_key;
	}
}

static void libnvme_read_sysfs_tls(struct libnvme_global_ctx *ctx,
		libnvme_ctrl_t c)
{
	char *endptr;
	long key_id;
	char *key, *keyring;

	key = libnvme_get_ctrl_attr(c, "tls_key");
	if (!key) {
		/* tls_key is only present if --tls or --concat has been used */
		return;
	}

	keyring = libnvme_get_ctrl_attr(c, "tls_keyring");
	libnvme_ctrl_set_keyring(c, keyring);
	free(keyring);

	/* the sysfs entry is not prefixing the id but it's in hex */
	key_id = strtol(key, &endptr, 16);
	if (endptr != key)
		c->cfg.tls_key_id = key_id;

	free(key);

	key = libnvme_get_ctrl_attr(c, "tls_configured_key");
	if (!key)
		return;

	/* the sysfs entry is not prefixing the id but it's in hex */
	key_id = strtol(key, &endptr, 16);
	if (endptr != key)
		c->cfg.tls_configured_key_id = key_id;

	free(key);
}

static void libnvme_read_sysfs_tls_mode(struct libnvme_global_ctx *ctx,
		libnvme_ctrl_t c)
{
	__cleanup_free char *mode = NULL;

	mode = libnvme_get_ctrl_attr(c, "tls_mode");
	if (!mode)
		return;

	if (!strcmp(mode, "tls"))
		c->cfg.tls = true;
	else if (!strcmp(mode, "concat"))
		c->cfg.concat = true;
}

static int libnvme_reconfigure_ctrl(struct libnvme_global_ctx *ctx,
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
	libnvme_read_sysfs_dhchap(ctx, c);
	libnvme_read_sysfs_tls(ctx, c);
	libnvme_read_sysfs_tls_mode(ctx, c);

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

	ret = asprintf(&path, "%s/%s", libnvme_ctrl_sysfs_dir(), name);
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

int libnvme_ctrl_alloc(struct libnvme_global_ctx *ctx, libnvme_subsystem_t s,
		const char *path, const char *name, libnvme_ctrl_t *cp)
{
	__cleanup_free char *addr = NULL, *address = NULL, *transport = NULL;
	char *host_traddr = NULL, *host_iface = NULL;
	char *traddr = NULL, *trsvcid = NULL;
	char *a = NULL, *e = NULL;
	libnvme_ctrl_t c, p;
	int ret;

	transport = libnvme_get_attr(path, "transport");
	if (!transport)
		return -ENXIO;

	/* Parse 'address' string into components */
	addr = libnvme_get_attr(path, "address");
	if (!addr) {
		__cleanup_free char *rpath = NULL;
		char *p = NULL, *_a = NULL;

		/* loop transport might not have an address */
		if (!strcmp(transport, "loop"))
			goto skip_address;

		/* Older kernel don't support pcie transport addresses */
		if (strcmp(transport, "pcie") &&
		    strcmp(transport, "apple-nvme"))
			return -ENXIO;
		/* Figure out the PCI address from the attribute path */
		rpath = realpath(path, NULL);
		if (!rpath)
			return -ENOMEM;
		a = strtok_r(rpath, "/", &e);
		while(a && strlen(a)) {
		    if (_a)
			p = _a;
		    _a = a;
		    if (!strncmp(a, "nvme", 4))
			break;
		    a = strtok_r(NULL, "/", &e);
		}
		if (p)
			addr = strdup(p);
	} else if (!strcmp(transport, "pcie") ||
		   !strcmp(transport, "apple-nvme")) {
		/* The 'address' string is the transport address */
		traddr = addr;
	} else {
		address = strdup(addr);
		a = strtok_r(address, ",", &e);
		while (a && strlen(a)) {
			if (!strncmp(a, "traddr=", 7))
				traddr = a + 7;
			else if (!strncmp(a, "trsvcid=", 8))
				trsvcid = a + 8;
			else if (!strncmp(a, "host_traddr=", 12))
				host_traddr = a + 12;
			else if (!strncmp(a, "host_iface=", 11))
				host_iface = a + 11;
			a = strtok_r(NULL, ",", &e);
		}
	}
skip_address:
	p = NULL;
	do {
		struct libnvmf_context fctx = {
			.transport = transport,
			.traddr = traddr,
			.host_traddr = host_traddr,
			.host_iface = host_iface,
			.trsvcid = trsvcid,
		};
		c = libnvme_lookup_ctrl(s, &fctx, p);
		if (c) {
			if (!c->name)
				break;
			if (!strcmp(c->name, name)) {
				libnvme_msg(ctx, LIBNVME_LOG_DEBUG,
					"found existing ctrl %s\n", c->name);
				break;
			}
			libnvme_msg(ctx, LIBNVME_LOG_DEBUG,
				"skipping ctrl %s\n", c->name);
			p = c;
		}
	} while (c);
	if (!c)
		c = p;
	if (!c && !p) {
		libnvme_msg(ctx, LIBNVME_LOG_ERR, "failed to lookup ctrl\n");
		return -ENODEV;
	}
	FREE_CTRL_ATTR(c->address);
	c->address = xstrdup(addr);
	if (s->subsystype && !strcmp(s->subsystype, "discovery"))
		c->discovery_ctrl = true;
	ret = libnvme_reconfigure_ctrl(ctx, c, path, name);
	if (ret)
		return ret;

	*cp = c;
	return 0;
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
	ret = asprintf(&path, "%s/%s", libnvme_ctrl_sysfs_dir(), name);
	if (ret < 0)
		return -ENOMEM;

	hostnqn = libnvme_get_attr(path, "hostnqn");
	hostid = libnvme_get_attr(path, "hostid");
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

__libnvme_public void libnvme_rescan_ctrl(struct libnvme_ctrl *c)
{
	struct libnvme_global_ctx *ctx = c->s && c->s->h ? c->s->h->ctx : NULL;
	if (!c->s)
		return;
	libnvme_ctrl_scan_namespaces(ctx, c);
	libnvme_ctrl_scan_paths(ctx, c);
	nvme_subsystem_scan_namespaces(ctx, c->s);
}

static int libnvme_bytes_to_lba(libnvme_ns_t n, off_t offset, size_t count,
		__u64 *lba, __u16 *nlb)
{
	int bs;

	bs = libnvme_ns_get_lba_size(n);
	if (!count || offset & (bs - 1) || count & (bs - 1))
		return -EINVAL;

	*lba = offset >> n->lba_shift;
	*nlb = (count >> n->lba_shift) - 1;

	return 0;
}

int libnvme_ns_get_transport_handle(libnvme_ns_t n,
		struct libnvme_transport_handle **hdl)
{
	int err;

	if (n->hdl)
		goto valid;

	err = libnvme_open(n->ctx, n->name, &n->hdl);
	if (err) {
		libnvme_msg(n->ctx, LIBNVME_LOG_ERR, "Failed to open ns %s, error %d\n",
			n->name, err);
		return err;
	}

valid:
	*hdl = n->hdl;
	return 0;
}

void libnvme_ns_release_transport_handle(libnvme_ns_t n)
{
	if (!n->hdl)
		return;

	libnvme_close(n->hdl);
	n->hdl = NULL;
}

__libnvme_public libnvme_subsystem_t libnvme_ns_get_subsystem(libnvme_ns_t n)
{
	return n->s;
}

__libnvme_public libnvme_ctrl_t libnvme_ns_get_ctrl(libnvme_ns_t n)
{
	return n->c;
}

const char *libnvme_ns_head_get_sysfs_dir(libnvme_ns_head_t head)
{
	return head->sysfs_dir;
}

__libnvme_public const char *libnvme_ns_get_model(libnvme_ns_t n)
{
	return n->c ? n->c->model : n->s->model;
}

__libnvme_public const char *libnvme_ns_get_serial(libnvme_ns_t n)
{
	return n->c ? n->c->serial : n->s->serial;
}

__libnvme_public const char *libnvme_ns_get_firmware(libnvme_ns_t n)
{
	return n->c ? n->c->firmware : n->s->firmware;
}

__libnvme_public void libnvme_ns_copy_uuid(libnvme_ns_t n,
		unsigned char out[NVME_UUID_LEN])
{
	memcpy(out, n->uuid, NVME_UUID_LEN);
}

__libnvme_public long libnvme_ns_get_command_retry_count(libnvme_ns_t n)
{
	__cleanup_free char *retry_count = NULL;

	retry_count = libnvme_get_ns_attr(n, "command_retry_count");
	if (retry_count)
		sscanf(retry_count, "%ld", &n->command_retry_count);

	return n->command_retry_count;
}

__libnvme_public long libnvme_ns_get_command_error_count(libnvme_ns_t n)
{
	__cleanup_free char *error_count = NULL;

	error_count = libnvme_get_ns_attr(n, "command_error_count");
	if (error_count)
		sscanf(error_count, "%ld", &n->command_error_count);

	return n->command_error_count;
}

__libnvme_public long libnvme_ns_get_requeue_no_usable_path_count(
		libnvme_ns_t n)
{
	__cleanup_free char *requeue_count = NULL;

	requeue_count = libnvme_get_ns_attr(n, "requeue_no_usable_path_count");
	if (requeue_count)
		sscanf(requeue_count, "%ld", &n->requeue_no_usable_path_count);

	return n->requeue_no_usable_path_count;
}

__libnvme_public long libnvme_ns_get_fail_no_available_path_count(
		libnvme_ns_t n)
{
	__cleanup_free char *fail_count = NULL;

	fail_count = libnvme_get_ns_attr(n, "fail_no_available_path_count");
	if (fail_count)
		sscanf(fail_count, "%ld", &n->fail_no_available_path_count);

	return n->fail_no_available_path_count;
}

__libnvme_public int libnvme_ns_identify(libnvme_ns_t n, struct nvme_id_ns *ns)
{
	struct libnvme_transport_handle *hdl;
	struct libnvme_passthru_cmd cmd;
	int err;

	err = libnvme_ns_get_transport_handle(n, &hdl);
	if (err)
		return err;

	nvme_init_identify_ns(&cmd, libnvme_ns_get_nsid(n), ns);
	return libnvme_exec_admin_passthru(hdl, &cmd);
}

int libnvme_ns_identify_descs(libnvme_ns_t n, struct nvme_ns_id_desc *descs)
{
	struct libnvme_transport_handle *hdl;
	struct libnvme_passthru_cmd cmd;
	int err;

	err = libnvme_ns_get_transport_handle(n, &hdl);
	if (err)
		return err;

	nvme_init_identify_ns_descs_list(&cmd, libnvme_ns_get_nsid(n), descs);
	return libnvme_exec_admin_passthru(hdl, &cmd);
}

__libnvme_public int libnvme_ns_verify(
		libnvme_ns_t n, off_t offset, size_t count)
{
	struct libnvme_transport_handle *hdl;
	struct libnvme_passthru_cmd cmd;
	__u64 slba;
	__u16 nlb;
	int err;

	err = libnvme_ns_get_transport_handle(n, &hdl);
	if (err)
		return err;

	if (libnvme_bytes_to_lba(n, offset, count, &slba, &nlb))
		return -1;

	nvme_init_verify(&cmd, libnvme_ns_get_nsid(n), slba, nlb,
		0, 0, NULL, 0, NULL, 0);

	return libnvme_submit_io_passthru(hdl, &cmd);
}

__libnvme_public int libnvme_ns_write_uncorrectable(
		libnvme_ns_t n, off_t offset, size_t count)
{
	struct libnvme_transport_handle *hdl;
	struct libnvme_passthru_cmd cmd;
	__u64 slba;
	__u16 nlb;
	int err;

	err = libnvme_ns_get_transport_handle(n, &hdl);
	if (err)
		return err;

	if (libnvme_bytes_to_lba(n, offset, count, &slba, &nlb))
		return -1;

	nvme_init_write_uncorrectable(&cmd, libnvme_ns_get_nsid(n), slba, nlb,
		0, 0);

	return libnvme_submit_io_passthru(hdl, &cmd);
}

__libnvme_public int libnvme_ns_write_zeros(
		libnvme_ns_t n, off_t offset, size_t count)
{
	struct libnvme_transport_handle *hdl;
	struct libnvme_passthru_cmd cmd;
	__u64 slba;
	__u16 nlb;
	int err;

	err = libnvme_ns_get_transport_handle(n, &hdl);
	if (err)
		return err;

	if (libnvme_bytes_to_lba(n, offset, count, &slba, &nlb))
		return -1;

	nvme_init_write_zeros(&cmd, libnvme_ns_get_nsid(n),
		slba, nlb, 0, 0, 0, 0);

	return libnvme_submit_io_passthru(hdl, &cmd);
}

__libnvme_public int libnvme_ns_write(libnvme_ns_t n, void *buf, off_t offset,
		size_t count)
{
	struct libnvme_transport_handle *hdl;
	struct libnvme_passthru_cmd cmd;
	__u64 slba;
	__u16 nlb;
	int err;

	err = libnvme_ns_get_transport_handle(n, &hdl);
	if (err)
		return err;

	if (libnvme_bytes_to_lba(n, offset, count, &slba, &nlb))
		return -1;

	nvme_init_write(&cmd, libnvme_ns_get_nsid(n), slba, nlb,
		0, 0, 0, 0, buf, count, NULL, 0);

	return libnvme_submit_io_passthru(hdl, &cmd);
}

__libnvme_public int libnvme_ns_read(libnvme_ns_t n, void *buf, off_t offset,
		size_t count)
{
	struct libnvme_transport_handle *hdl;
	struct libnvme_passthru_cmd cmd;
	__u64 slba;
	__u16 nlb;
	int err;

	err = libnvme_ns_get_transport_handle(n, &hdl);
	if (err)
		return err;

	if (libnvme_bytes_to_lba(n, offset, count, &slba, &nlb))
		return -1;

	nvme_init_read(&cmd, libnvme_ns_get_nsid(n), slba, nlb,
		0, 0, 0, buf, count, NULL, 0);

	return libnvme_submit_io_passthru(hdl, &cmd);
}

__libnvme_public int libnvme_ns_compare(libnvme_ns_t n, void *buf, off_t offset,
		size_t count)
{
	struct libnvme_transport_handle *hdl;
	struct libnvme_passthru_cmd cmd;
	__u64 slba;
	__u16 nlb;
	int err;

	err = libnvme_ns_get_transport_handle(n, &hdl);
	if (err)
		return err;

	if (libnvme_bytes_to_lba(n, offset, count, &slba, &nlb))
		return -1;

	nvme_init_compare(&cmd, libnvme_ns_get_nsid(n), slba, nlb,
		0, 0, buf, count, NULL, 0);

	return libnvme_submit_io_passthru(hdl, &cmd);
}

__libnvme_public int libnvme_ns_flush(libnvme_ns_t n)
{
	struct libnvme_transport_handle *hdl;
	struct libnvme_passthru_cmd cmd;
	int err;

	err = libnvme_ns_get_transport_handle(n, &hdl);
	if (err)
		return err;

	nvme_init_flush(&cmd, libnvme_ns_get_nsid(n));
	return libnvme_submit_io_passthru(hdl, &cmd);
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
	memcpy(res, str, NVME_UUID_LEN);
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

static int libnvme_ns_init(const char *path, struct libnvme_ns *ns)
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
		__cleanup_free struct nvme_id_ns *id = NULL;
		uint8_t flbas;

		id = __libnvme_alloc(sizeof(*ns));
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

static int libnvme_ns_open(struct libnvme_global_ctx *ctx, const char *sys_path,
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

static int __libnvme_scan_namespace(struct libnvme_global_ctx *ctx,
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

__libnvme_public int libnvme_scan_namespace(struct libnvme_global_ctx *ctx,
		const char *name, libnvme_ns_t *ns)
{
	return __libnvme_scan_namespace(ctx, libnvme_ns_sysfs_dir(), name, ns);
}


static void libnvme_ns_head_scan_path(libnvme_subsystem_t s,
		libnvme_ns_t n, char *name)
{
	libnvme_ctrl_t c;
	libnvme_path_t p;

	libnvme_subsystem_for_each_ctrl(s, c) {
		libnvme_ctrl_for_each_path(c, p) {
			if (!strcmp(libnvme_path_get_name(p), name)) {
				list_add_tail(&n->head->paths, &p->nentry);
				p->n = n;
				return;
			}
		}
	}
}

static void libnvme_subsystem_set_ns_path(libnvme_subsystem_t s, libnvme_ns_t n)
{
	struct libnvme_ns_head *head = n->head;

	if (libnvme_ns_head_get_sysfs_dir(head)) {
		struct dirents paths = {};
		int i;

		/*
		 * When multipath is configured on kernel version >= 6.15,
		 * we use multipath sysfs link to get each path of a namespace.
		 */
		paths.num = libnvme_scan_ns_head_paths(head, &paths.ents);

		for (i = 0; i < paths.num; i++)
			libnvme_ns_head_scan_path(s, n, paths.ents[i]->d_name);
	} else {
		libnvme_ctrl_t c;
		libnvme_path_t p;
		int ns_ctrl, ns_nsid, ret;

		/*
		 * If multipath is not configured or we're running on kernel
		 * version < 6.15, fallback to the old way.
		 */
		ret = sscanf(libnvme_ns_get_name(n), "nvme%dn%d",
				&ns_ctrl, &ns_nsid);
		if (ret != 2)
			return;

		libnvme_subsystem_for_each_ctrl(s, c) {
			libnvme_ctrl_for_each_path(c, p) {
				int p_subsys, p_ctrl, p_nsid;

				ret = sscanf(libnvme_path_get_name(p),
					     "nvme%dc%dn%d",
					     &p_subsys, &p_ctrl, &p_nsid);
				if (ret != 3)
					continue;
				if (ns_ctrl == p_subsys && ns_nsid == p_nsid) {
					list_add_tail(&head->paths, &p->nentry);
					p->n = n;
				}
			}
		}
	}
}

static int libnvme_ctrl_scan_namespace(struct libnvme_global_ctx *ctx,
		struct libnvme_ctrl *c, char *name)
{
	struct libnvme_ns *n, *_n, *__n;
	int ret;

	libnvme_msg(ctx, LIBNVME_LOG_DEBUG, "scan controller %s namespace %s\n",
		 c->name, name);
	if (!c->s) {
		libnvme_msg(ctx, LIBNVME_LOG_DEBUG, "no subsystem for %s\n", name);
		return -EINVAL;
	}
	ret = __libnvme_scan_namespace(ctx, c->sysfs_dir, name, &n);
	if (ret) {
		libnvme_msg(ctx, LIBNVME_LOG_DEBUG, "failed to scan namespace %s\n", name);
		return ret;
	}
	libnvme_ctrl_for_each_ns_safe(c, _n, __n) {
		if (strcmp(n->name, _n->name))
			continue;
		__nvme_free_ns(_n);
	}
	n->s = c->s;
	n->c = c;
	list_add_tail(&c->namespaces, &n->entry);
	libnvme_subsystem_set_ns_path(c->s, n);

	return 0;
}

static int libnvme_subsystem_scan_namespace(struct libnvme_global_ctx *ctx,
		libnvme_subsystem_t s, char *name)
{
	struct libnvme_ns *n, *_n, *__n;
	int ret;

	libnvme_msg(ctx, LIBNVME_LOG_DEBUG, "scan subsystem %s namespace %s\n",
		 s->name, name);
	ret = __libnvme_scan_namespace(ctx, s->sysfs_dir, name, &n);
	if (ret) {
		libnvme_msg(ctx, LIBNVME_LOG_DEBUG, "failed to scan namespace %s\n", name);
		return ret;
	}
	libnvme_subsystem_for_each_ns_safe(s, _n, __n) {
		if (strcmp(n->name, _n->name))
			continue;
		__nvme_free_ns(_n);
	}
	n->s = s;
	list_add_tail(&s->namespaces, &n->entry);
	libnvme_subsystem_set_ns_path(s, n);
	return 0;
}

__libnvme_public struct libnvme_ns *libnvme_subsystem_lookup_namespace(
		struct libnvme_subsystem *s, __u32 nsid)
{
	struct libnvme_ns *n;

	libnvme_subsystem_for_each_ns(s, n) {
		if (libnvme_ns_get_nsid(n) == nsid)
			return n;
	}
	return NULL;
}
