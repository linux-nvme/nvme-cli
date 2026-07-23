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

#include "cleanup.h"
#include "cleanup-linux.h"
#include "private.h"
#include "private-tree.h"
#include "util.h"
#include "compiler-attributes.h"

static void __libnvme_free_ctrl(libnvme_ctrl_t c);
static int libnvme_subsystem_scan_namespace(struct libnvme_global_ctx *ctx,
		struct libnvme_subsystem *s, char *name);
static int libnvme_scan_subsystem(struct libnvme_global_ctx *ctx,
	 	const char *name);
static int libnvme_ctrl_scan_namespace(struct libnvme_global_ctx *ctx,
		struct libnvme_ctrl *c, char *name);
static int libnvme_ctrl_scan_path(struct libnvme_global_ctx *ctx,
		struct libnvme_ctrl *c, char *name);

char *libnvme_hostid_from_hostnqn(const char *hostnqn)
{
	const char *uuid;

	uuid = strstr(hostnqn, "uuid:");
	if (!uuid)
		return NULL;

	return strdup(uuid + strlen("uuid:"));
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

	ctrls.num = libnvme_scan_ctrls(ctx, &ctrls.ents);
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

	subsys.num = libnvme_scan_subsystems(ctx, &subsys.ents);
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

__libnvme_public int libnvme_refresh_topology(struct libnvme_global_ctx *ctx)
{
	struct libnvme_host *h, *_h;

	libnvme_for_each_host_safe(ctx, h, _h)
		__libnvme_free_host(h);
	return libnvme_scan_topology(ctx, NULL, NULL);
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
	s->subsysnqn = xstrdup(subsysnqn);
	if (!s->subsysnqn) {
		free(s);
		return NULL;
	}

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
	if (hostid)
		h->hostid = strdup(hostid);
	else
		h->hostid = libnvme_hostid_from_hostnqn(hostnqn);
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

__libnvme_public int libnvme_get_host(
		struct libnvme_global_ctx *ctx, const char *hostnqn,
		const char *hostid, libnvme_host_t *host)
{
	struct libnvme_host *h;

	/*
	 * No sysfs identity (e.g. PCIe) and no ctx default: use a fixed
	 * placeholder rather than resolving/generating one -- that's a
	 * policy call for the caller, not us.
	 */
	if (!hostnqn)
		hostnqn = NVME_DEFAULT_HOSTNQN;
	if (!hostid)
		hostid = NVME_DEFAULT_HOSTID;

	h = libnvme_lookup_host(ctx, hostnqn, hostid);
	if (!h)
		return -ENOMEM;

	libnvme_host_set_hostsymname(h, NULL);

	*host = h;
	return 0;
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

static int libnvme_scan_subsystem(struct libnvme_global_ctx *ctx,
		const char *name)
{
	struct libnvme_subsystem *s = NULL, *_s;
	__cleanup_free char *path = NULL, *subsysnqn = NULL;
	libnvme_host_t h = NULL;
	int ret;

	libnvme_msg(ctx, LIBNVME_LOG_DEBUG, "scan subsystem %s\n", name);
	ret = asprintf(&path, "%s/%s", libnvme_subsys_sysfs_dir(ctx), name);
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
		ret = libnvme_get_host(ctx, ctx->hostnqn, ctx->hostid, &h);
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

	failover_count = libnvme_get_path_attr(p,
				"diag/multipath_failover_count");
	if (failover_count)
		sscanf(failover_count, "%ld", &p->multipath_failover_count);

	return p->multipath_failover_count;
}

__libnvme_public long libnvme_path_get_command_retry_count(libnvme_path_t p)
{
	__cleanup_free char *retry_count = NULL;

	retry_count = libnvme_get_path_attr(p, "diag/command_retry_count");
	if (retry_count)
		sscanf(retry_count, "%ld", &p->command_retry_count);

	return p->command_retry_count;
}

__libnvme_public long libnvme_path_get_command_error_count(libnvme_path_t p)
{
	__cleanup_free char *error_count = NULL;

	error_count = libnvme_get_path_attr(p, "diag/command_error_count");
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

__libnvme_public long libnvme_ctrl_get_command_error_count(libnvme_ctrl_t c)
{
	__cleanup_free char *error_count = NULL;

	error_count = libnvme_get_ctrl_attr(c, "diag/command_error_count");
	if (error_count)
		sscanf(error_count, "%ld", &c->command_error_count);

	return c->command_error_count;
}

__libnvme_public long libnvme_ctrl_get_reset_count(libnvme_ctrl_t c)
{
	__cleanup_free char *reset_count = NULL;

	reset_count = libnvme_get_ctrl_attr(c, "diag/reset_count");
	if (reset_count)
		sscanf(reset_count, "%ld", &c->reset_count);

	return c->reset_count;
}

__libnvme_public long libnvme_ctrl_get_reconnect_count(libnvme_ctrl_t c)
{
	__cleanup_free char *reconnect_count = NULL;

	reconnect_count = libnvme_get_ctrl_attr(c, "diag/reconnect_count");
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

int libnvme_create_ctrl(struct libnvme_global_ctx *ctx,
		const struct libnvme_ctrl_params *params, libnvme_ctrl_t *cp)
{
	struct libnvme_ctrl *c;

	if (!params->transport) {
		libnvme_msg(ctx, LIBNVME_LOG_ERR, "No transport specified\n");
		return -EINVAL;
	}
	if (strncmp(params->transport, "loop", 4) &&
	    strncmp(params->transport, "pcie", 4) &&
	    strncmp(params->transport, "apple-nvme", 10) && !params->traddr) {
		libnvme_msg(ctx, LIBNVME_LOG_ERR,
			"No transport address for '%s'\n", params->transport);
		return -EINVAL;
	}
	if (!params->subsysnqn) {
		libnvme_msg(ctx, LIBNVME_LOG_ERR, "No subsystem NQN specified\n");
		return -EINVAL;
	}
	c = calloc(1, sizeof(*c));
	if (!c)
		return -ENOMEM;

	c->ctx = ctx;
	c->hdl = NULL;
	libnvme_fabrics_config_copy(&c->cfg, &params->cfg);
	list_head_init(&c->namespaces);
	list_head_init(&c->paths);
	list_node_init(&c->entry);
	c->transport = strdup(params->transport);
	c->subsysnqn = strdup(params->subsysnqn);
	if (params->traddr)
		c->traddr = strdup(params->traddr);
	if (params->host_traddr)
		c->host_traddr = strdup(params->host_traddr);
	if (params->host_iface)
		c->host_iface = strdup(params->host_iface);
	if (params->trsvcid)
		c->trsvcid = strdup(params->trsvcid);

	*cp = c;
	return 0;
}

libnvme_ctrl_t libnvme_lookup_ctrl(libnvme_subsystem_t s,
			     const struct libnvme_ctrl_params *in,
			     libnvme_ctrl_t p)
{
	struct libnvme_global_ctx *ctx;
	struct libnvme_ctrl_params search;
	struct libnvme_ctrl *c;
	int ret;

	if (!s || !in->transport)
		return NULL;

	/*
	 * Clear subsysnqn for the initial search; discovery subsystems
	 * may report a different NQN than the one used to connect.
	 */
	search = *in;
	libnvme_fabrics_config_copy(&search.cfg, &in->cfg);
	search.subsysnqn = NULL;
	c = libnvme_ctrl_find(s, &search, p);
	if (c)
		return c;

	ctx = s->h ? s->h->ctx : NULL;
	search.subsysnqn = s->subsysnqn;
	libnvmf_default_config(&search.cfg);
	ret = libnvme_create_ctrl(ctx, &search, &c);
	if (ret)
		return NULL;

	c->s = s;
	list_add_tail(&s->ctrls, &c->entry);

	return c;
}

int libnvme_ctrl_scan_paths(struct libnvme_global_ctx *ctx,
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

int libnvme_ctrl_scan_namespaces(struct libnvme_global_ctx *ctx,
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

/*
 * Fabrics = any transport that is not a known local one (pcie/apple-nvme).
 * Testing by exclusion means a newly added transport defaults to fabrics.
 */
__libnvme_public bool libnvme_transport_is_fabric(const char *transport)
{
	return transport &&
	       strcmp(transport, "pcie") &&
	       strcmp(transport, "apple-nvme");
}

__libnvme_public bool libnvme_ctrl_is_transport_fabric(libnvme_ctrl_t c)
{
	return c && libnvme_transport_is_fabric(c->transport);
}

int libnvme_ctrl_alloc(struct libnvme_global_ctx *ctx, libnvme_subsystem_t s,
		const char *path, const char *name, libnvme_ctrl_t *cp)
{
	__cleanup_free char *addr = NULL, *transport = NULL;
	__cleanup_free char *host_traddr = NULL, *host_iface = NULL;
	__cleanup_free char *traddr = NULL, *trsvcid = NULL;
	libnvme_ctrl_t c, p;
	int ret;

	ret = libnvme_get_ctrl_transport(ctx, path, name, &transport, &traddr,
					 &addr, &trsvcid, &host_traddr,
					 &host_iface);
	if (ret)
		return ret;

	p = NULL;
	do {
		struct libnvme_ctrl_params params = {
			.transport = transport,
			.traddr = traddr,
			.host_traddr = host_traddr,
			.host_iface = host_iface,
			.trsvcid = trsvcid,
		};
		c = libnvme_lookup_ctrl(s, &params, p);
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

__libnvme_public void libnvme_rescan_ctrl(struct libnvme_ctrl *c)
{
	struct libnvme_global_ctx *ctx = c->s && c->s->h ? c->s->h->ctx : NULL;
	if (!ctx)
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

	retry_count = libnvme_get_ns_attr(n, "diag/command_retry_count");
	if (retry_count)
		sscanf(retry_count, "%ld", &n->command_retry_count);

	return n->command_retry_count;
}

__libnvme_public long libnvme_ns_get_command_error_count(libnvme_ns_t n)
{
	__cleanup_free char *error_count = NULL;

	error_count = libnvme_get_ns_attr(n, "diag/command_error_count");
	if (error_count)
		sscanf(error_count, "%ld", &n->command_error_count);

	return n->command_error_count;
}

__libnvme_public long libnvme_ns_get_io_requeue_no_usable_path_count(
		libnvme_ns_t n)
{
	__cleanup_free char *requeue_count = NULL;

	requeue_count = libnvme_get_ns_attr(n,
			"diag/io_requeue_no_usable_path_count");
	if (requeue_count)
		sscanf(requeue_count, "%ld",
			&n->io_requeue_no_usable_path_count);

	return n->io_requeue_no_usable_path_count;
}

__libnvme_public long libnvme_ns_get_io_fail_no_available_path_count(
		libnvme_ns_t n)
{
	__cleanup_free char *fail_count = NULL;

	fail_count = libnvme_get_ns_attr(n,
			"diag/io_fail_no_available_path_count");
	if (fail_count)
		sscanf(fail_count, "%ld", &n->io_fail_no_available_path_count);

	return n->io_fail_no_available_path_count;
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

	return libnvme_exec_io_passthru(hdl, &cmd);
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

	return libnvme_exec_io_passthru(hdl, &cmd);
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

	return libnvme_exec_io_passthru(hdl, &cmd);
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

	return libnvme_exec_io_passthru(hdl, &cmd);
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

	return libnvme_exec_io_passthru(hdl, &cmd);
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

	return libnvme_exec_io_passthru(hdl, &cmd);
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
	return libnvme_exec_io_passthru(hdl, &cmd);
}

__libnvme_public int libnvme_scan_namespace(struct libnvme_global_ctx *ctx,
		const char *name, libnvme_ns_t *ns)
{
	return __libnvme_scan_namespace(ctx,
		libnvme_ns_sysfs_dir(ctx), name, ns);
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
		__cleanup_dirents struct dirents paths = {};
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
