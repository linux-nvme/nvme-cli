// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026, Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <Martin.Belanger@dell.com>
 */

/*
 * The cascade resolver: turn the raw models of the main file and its
 * drop-ins into the flat connection list (libnvme/design/CONFIG.md).  The
 * precedence, most-specific last in merge order:
 *
 *   [Global] (top-level, overlaid by the file's own)
 *   < per-type defaults (top-level, overlaid by the file's own)
 *   < [Host]
 *   < endpoint section
 *   < controller= line overrides
 *
 * Identity is per file: a drop-in's [Host] must name its hostnqn (a persona
 * without a name would silently conflate with the default persona); the
 * relational Tier 1 rules reject a hostid shared by two personas and one
 * hostnqn appearing with two hostids.
 */

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <nvme/nvme-types-fabrics.h>

#include "cleanup.h"
#include "config-ini.h"
#include "lib.h"
#include "private-fabrics.h"

#define resolve_err(ctx, src, fmt, ...)					\
	libnvme_msg(ctx, LIBNVME_LOG_ERR, "%s: " fmt "\n", src,	\
		    ##__VA_ARGS__)

/* One file's merged cascade levels: everything below the endpoint rung. */
struct scope {
	struct libnvmf_params *dc_base;  /* global + DC defaults + [Host] */
	struct libnvmf_params *ioc_base; /* global + IOC defaults + [Host] */
};

static void scope_reset(struct scope *s)
{
	libnvmf_params_free(s->dc_base);
	libnvmf_params_free(s->ioc_base);
	s->dc_base = NULL;
	s->ioc_base = NULL;
}

static int merge_maybe(struct libnvmf_params *dst,
		       const struct libnvmf_params *src)
{
	return src ? libnvmf_params_merge(dst, src) : 0;
}

/*
 * base(kind) = top [Global] + file [Global] + top defaults(kind) +
 * file defaults(kind) + file [Host] params.  When @f is the top-level file
 * itself the overlays coincide, so the file terms are skipped.
 */
static struct libnvmf_params *build_base(const struct libnvmf_conf_file *top,
					 const struct libnvmf_conf_file *f,
					 bool dc)
{
	struct libnvmf_params *base = libnvmf_params_new();

	if (!base)
		return NULL;

	if (merge_maybe(base, top->global) ||
	    (f != top && merge_maybe(base, f->global)) ||
	    merge_maybe(base, dc ? top->dc_defaults : top->ioc_defaults) ||
	    (f != top && merge_maybe(base, dc ? f->dc_defaults :
						f->ioc_defaults)) ||
	    merge_maybe(base, f->host_params)) {
		libnvmf_params_free(base);
		return NULL;
	}

	return base;
}

static int build_scope(struct scope *s, const struct libnvmf_conf_file *top,
		       const struct libnvmf_conf_file *f)
{
	s->dc_base = build_base(top, f, true);
	s->ioc_base = build_base(top, f, false);
	if (!s->dc_base || !s->ioc_base) {
		scope_reset(s);
		return -ENOMEM;
	}

	return 0;
}

static void free_conns(struct libnvmf_conf_conn *c)
{
	struct libnvmf_conf_conn *next;

	for (; c; c = next) {
		next = c->next;
		free(c->transport);
		free(c->traddr);
		free(c->trsvcid);
		free(c->host_traddr);
		free(c->host_iface);
		free(c->subsysnqn);
		free(c->hostnqn);
		free(c->hostid);
		libnvmf_params_free(c->params);
		libnvmf_params_free(c->dlp_dc_params);
		libnvmf_params_free(c->dlp_ioc_params);
		free(c->hostsymname);
		free(c->source);
		free(c);
	}
}

void libnvmf_conf_free(struct libnvmf_conf *conf)
{
	if (!conf)
		return;
	free_conns(conf->conns);
	libnvmf_params_free(conf->top_dc_params);
	libnvmf_params_free(conf->top_ioc_params);
	free(conf);
}

/* A persona field is "real" when set to an actual value (not unset/reset). */
static bool real_value(const char *s)
{
	return s && *s;
}

static int resolve_path(struct libnvme_global_ctx *ctx,
			const struct libnvmf_conf_file *f,
			const struct scope *scope,
			const struct libnvmf_conf_endpoint *ep,
			const struct libnvmf_conf_path *path,
			struct libnvmf_conf_conn ***tail)
{
	struct libnvmf_conf_conn *conn;
	const char *hostnqn = real_value(f->hostnqn) ? f->hostnqn : NULL;
	const char *hostid = real_value(f->hostid) ? f->hostid : NULL;
	const char *nqn = ep->nqn ? ep->nqn : NVME_DISC_SUBSYS_NAME;

	conn = calloc(1, sizeof(*conn));
	if (!conn)
		return -ENOMEM;

	conn->is_dc = ep->is_dc;
	conn->source = xstrdup(f->path);
	conn->line = path->line;

	conn->transport = xstrdup(path->transport);
	conn->traddr = xstrdup(path->traddr);
	conn->trsvcid = xstrdup(path->trsvcid);
	conn->host_traddr = xstrdup(path->host_traddr);
	conn->host_iface = xstrdup(path->host_iface);
	conn->subsysnqn = xstrdup(nqn);
	conn->hostnqn = xstrdup(hostnqn);
	conn->hostid = xstrdup(hostid);
	if (!conn->source || !conn->transport || !conn->traddr ||
	    !conn->subsysnqn ||
	    (path->trsvcid && !conn->trsvcid) ||
	    (path->host_traddr && !conn->host_traddr) ||
	    (path->host_iface && !conn->host_iface) ||
	    (hostnqn && !conn->hostnqn) ||
	    (hostid && !conn->hostid))
		goto fail;
	if (real_value(f->hostsymname)) {
		conn->hostsymname = xstrdup(f->hostsymname);
		if (!conn->hostsymname)
			goto fail;
	}

	conn->params = libnvmf_params_dup(ep->is_dc ? scope->dc_base :
						      scope->ioc_base);
	if (!conn->params ||
	    libnvmf_params_merge(conn->params, ep->params) ||
	    libnvmf_params_merge(conn->params, path->overrides))
		goto fail;

	if (ep->is_dc) {
		conn->dlp_dc_params = libnvmf_params_dup(scope->dc_base);
		conn->dlp_ioc_params = libnvmf_params_dup(scope->ioc_base);
		if (!conn->dlp_dc_params || !conn->dlp_ioc_params)
			goto fail;
	}

	**tail = conn;
	*tail = &conn->next;

	return 0;

fail:
	free_conns(conn);
	return -ENOMEM;
}

static int resolve_file(struct libnvme_global_ctx *ctx,
			const struct libnvmf_conf_file *top,
			const struct libnvmf_conf_file *f,
			struct libnvmf_conf_conn ***tail)
{
	const struct libnvmf_conf_endpoint *ep;
	const struct libnvmf_conf_path *path;
	struct scope scope = { 0 };
	int ret;

	ret = build_scope(&scope, top, f);
	if (ret)
		return ret;

	for (ep = f->endpoints; ep; ep = ep->next) {
		for (path = ep->paths; path; path = path->next) {
			ret = resolve_path(ctx, f, &scope, ep, path, tail);
			if (ret)
				goto out;
		}
	}

out:
	scope_reset(&scope);
	return ret;
}

/*
 * The relational identity rules (CONFIG.md Tier 1).  @files is the top-level
 * file followed by the drop-ins; index 0 is the top.
 */
static int check_personas(struct libnvme_global_ctx *ctx,
			  struct libnvmf_conf_file **files, size_t nfiles)
{
	size_t i, j;

	for (i = 0; i < nfiles; i++) {
		struct libnvmf_conf_file *f = files[i];

		if (!f->has_host)
			continue;

		/* A drop-in persona must be named. */
		if (i > 0 && !real_value(f->hostnqn)) {
			resolve_err(ctx, f->path,
				    "[Host] without a hostnqn in a drop-in");
			return -EINVAL;
		}

		for (j = 0; j < i; j++) {
			struct libnvmf_conf_file *o = files[j];

			if (!o->has_host)
				continue;
			/*
			 * One persona, one file: the spec permits several
			 * HostIDs under one HostNQN, but the Linux kernel
			 * does not currently support that, so a hostnqn
			 * reused across files is rejected outright, whether
			 * or not the hostid also matches.
			 */
			if (real_value(f->hostnqn) && real_value(o->hostnqn) &&
			    !strcmp(f->hostnqn, o->hostnqn)) {
				resolve_err(ctx, f->path,
					    "hostnqn %s already used by the persona in %s",
					    f->hostnqn, o->path);
				return -EINVAL;
			}
			if (real_value(f->hostid) && real_value(o->hostid) &&
			    !strcmp(f->hostid, o->hostid) &&
			    real_value(f->hostnqn) && real_value(o->hostnqn) &&
			    strcmp(f->hostnqn, o->hostnqn)) {
				resolve_err(ctx, f->path,
					    "hostid %s already used by persona %s (%s); same hostid means same host",
					    f->hostid, o->hostnqn, o->path);
				return -EINVAL;
			}
		}
	}

	return 0;
}

static int dropin_filter(const struct dirent *d)
{
	const char *dot = strrchr(d->d_name, '.');

	return dot && dot != d->d_name && !strcmp(dot, ".conf");
}

struct libnvmf_conf *libnvmf_conf_load(struct libnvme_global_ctx *ctx,
		const char *path, int *err)
{
	struct libnvmf_conf_file **files = NULL;
	struct libnvmf_conf *conf = NULL;
	struct libnvmf_conf_conn **tail;
	struct dirent **entries = NULL;
	__cleanup_free char *dirname = NULL;
	size_t nfiles = 0, i;
	int ret, n = 0;

	if (err)
		*err = -EINVAL;
	if (!ctx || !path)
		return NULL;

	if (asprintf(&dirname, "%s.d", path) < 0) {
		dirname = NULL;
		ret = -ENOMEM;
		goto out;
	}

	n = scandir(dirname, &entries, dropin_filter, alphasort);
	if (n < 0) {
		if (errno != ENOENT) {
			ret = -errno;
			goto out;
		}
		n = 0; /* no drop-in directory: nothing more to read */
	}

	files = calloc(n + 1, sizeof(*files));
	if (!files) {
		ret = -ENOMEM;
		goto out;
	}

	/*
	 * Slot 0 is the main file.  When it does not exist it contributes
	 * nothing, represented by an empty raw model.
	 */
	ret = libnvmf_conf_file_parse(ctx, path, &files[0]);
	if (ret) {
		if (ret != -ENOENT)
			goto out;
		files[0] = calloc(1, sizeof(*files[0]));
		if (files[0])
			files[0]->path = xstrdup(path);
		if (!files[0] || !files[0]->path) {
			libnvmf_conf_file_free(files[0]);
			ret = -ENOMEM;
			goto out;
		}
	}
	nfiles = 1;

	for (i = 0; i < (size_t)n; i++) {
		__cleanup_free char *sub = NULL;

		if (asprintf(&sub, "%s/%s", dirname, entries[i]->d_name) < 0) {
			sub = NULL;
			ret = -ENOMEM;
			goto out;
		}
		ret = libnvmf_conf_file_parse(ctx, sub, &files[nfiles]);
		if (ret)
			goto out;
		nfiles++;
	}

	ret = check_personas(ctx, files, nfiles);
	if (ret)
		goto out;

	conf = calloc(1, sizeof(*conf));
	if (!conf) {
		ret = -ENOMEM;
		goto out;
	}

	tail = &conf->conns;
	for (i = 0; i < nfiles; i++) {
		ret = resolve_file(ctx, files[0], files[i], &tail);
		if (ret)
			goto out;
	}

	/* The top-level scope: defaults for discovered, un-configured DCs. */
	conf->top_dc_params = build_base(files[0], files[0], true);
	conf->top_ioc_params = build_base(files[0], files[0], false);
	if (!conf->top_dc_params || !conf->top_ioc_params) {
		ret = -ENOMEM;
		goto out;
	}

	ret = 0;

out:
	for (i = 0; i < nfiles; i++)
		libnvmf_conf_file_free(files[i]);
	free(files);
	while (n > 0)
		free(entries[--n]);
	free(entries);
	if (ret) {
		libnvmf_conf_free(conf);
		conf = NULL;
	}
	if (err)
		*err = ret;

	return conf;
}
