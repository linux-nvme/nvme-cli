// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026, Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <Martin.Belanger@dell.com>
 */

/*
 * Resolve the raw configuration models of the main file and its drop-ins
 * into the final connection list.
 *
 * Configuration is applied from least to most specific:
 *
 *   per-type defaults
 *   < [Host]
 *   < endpoint section
 *   < controller= line overrides
 *
 * The resolver merges inherited parameters, validates the configuration, and
 * produces the flat list of resolved connections.
 */

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ccan/list/list.h>

#include <nvme/nvme-types-fabrics.h>

#include "cleanup.h"
#include "compiler-attributes.h"
#include "config-ini.h"
#include "lib.h"
#include "private-fabrics.h"

#define resolve_err(ctx, src, fmt, ...)					\
	libnvme_msg(ctx, LIBNVME_LOG_ERR, "%s: " fmt "\n", src,	\
		    ##__VA_ARGS__)

/*
 * Configuration scope for one file before endpoint-specific overrides.
 */
struct scope {
	struct libnvmf_params *dc_base;  /* DC defaults + [Host] */
	struct libnvmf_params *ioc_base; /* IOC defaults + [Host] */
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
 * Build the base parameters for a connection type.
 *
 * The result is the merge of top-level defaults, file-specific defaults,
 * and the file's [Host] parameters. When @f is the top-level configuration
 * file, the file-specific defaults are already included and are not applied
 * again.
 */
static struct libnvmf_params *build_base(const struct libnvmf_conf_file *top,
					 const struct libnvmf_conf_file *f,
					 bool dc)
{
	struct libnvmf_params *base = libnvmf_params_new();

	if (!base)
		return NULL;

	if (merge_maybe(base, dc ? top->dc_defaults : top->ioc_defaults) ||
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

static void free_conn(struct libnvmf_config_conn *c)
{
	if (!c)
		return;
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

static void free_conns(struct list_head *conns)
{
	struct libnvmf_config_conn *c, *next;

	list_for_each_safe(conns, c, next, entry)
		free_conn(c);
}

__libnvme_public void libnvmf_config_free(struct libnvmf_config *conf)
{
	if (!conf)
		return;
	free_conns(&conf->conns);
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
			struct list_head *conns)
{
	struct libnvmf_config_conn *conn;
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

	list_add_tail(conns, &conn->entry);

	return 0;

fail:
	free_conn(conn);
	return -ENOMEM;
}

static int resolve_file(struct libnvme_global_ctx *ctx,
			const struct libnvmf_conf_file *top,
			const struct libnvmf_conf_file *f,
			struct list_head *conns)
{
	const struct libnvmf_conf_endpoint *ep;
	const struct libnvmf_conf_path *path;
	struct scope scope = { 0 };
	int ret;

	ret = build_scope(&scope, top, f);
	if (ret)
		return ret;

	list_for_each(&f->endpoints, ep, entry) {
		list_for_each(&ep->paths, path, entry) {
			ret = resolve_path(ctx, f, &scope, ep, path, conns);
			if (ret)
				goto out;
		}
	}

out:
	scope_reset(&scope);
	return ret;
}

/*
 * Validate identity relationships between personas.
 *
 * @files contains the top-level configuration file followed by its drop-ins;
 * index 0 refers to the top-level file.
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

int libnvmf_config_load(struct libnvme_global_ctx *ctx, const char *path,
		struct libnvmf_config **out)
{
	struct libnvmf_conf_file **files = NULL;
	struct libnvmf_config *conf = NULL;
	struct dirent **entries = NULL;
	__cleanup_free char *dirname = NULL;
	size_t nfiles = 0, i;
	int ret, n = 0;

	if (!out)
		return -EINVAL;
	*out = NULL;
	if (!ctx || !path)
		return -EINVAL;

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
		if (files[0]) {
			list_head_init(&files[0]->endpoints);
			files[0]->path = xstrdup(path);
		}
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

	list_head_init(&conf->conns);
	for (i = 0; i < nfiles; i++) {
		ret = resolve_file(ctx, files[0], files[i], &conf->conns);
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
	if (ret)
		libnvmf_config_free(conf);
	else
		*out = conf;

	return ret;
}
