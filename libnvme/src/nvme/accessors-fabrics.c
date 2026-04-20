// SPDX-License-Identifier: LGPL-2.1-or-later

/*
 * This file is part of libnvme.
 *
 * Copyright (c) 2025, Dell Technologies Inc. or its subsidiaries.
 * Authors: Martin Belanger <Martin.Belanger@dell.com>
 *
 *   ____                           _           _    ____          _
 *  / ___| ___ _ __   ___ _ __ __ _| |_ ___  __| |  / ___|___   __| | ___
 * | |  _ / _ \ '_ \ / _ \ '__/ _` | __/ _ \/ _` | | |   / _ \ / _` |/ _ \
 * | |_| |  __/ | | |  __/ | | (_| | ||  __/ (_| | | |__| (_) | (_| |  __/
 *  \____|\___|_| |_|\___|_|  \__,_|\__\___|\__,_|  \____\___/ \__,_|\___|
 *
 * Auto-generated struct member accessors (setter/getter)
 *
 * To update run: meson compile -C [BUILD-DIR] update-accessors
 * Or:            make update-accessors
 */
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "accessors-fabrics.h"

#include "private-fabrics.h"
#include "compiler-attributes.h"

/****************************************************************************
 * Accessors for: struct libnvmf_discovery_args
 ****************************************************************************/

__public int libnvmf_discovery_args_new(struct libnvmf_discovery_args **pp)
{
	if (!pp)
		return -EINVAL;
	*pp = calloc(1, sizeof(struct libnvmf_discovery_args));
	if (!*pp)
		return -ENOMEM;
	libnvmf_discovery_args_init_defaults(*pp);
	return 0;
}

__public void libnvmf_discovery_args_free(struct libnvmf_discovery_args *p)
{
	free(p);
}

__public void libnvmf_discovery_args_init_defaults(
		struct libnvmf_discovery_args *p)
{
	if (!p)
		return;
	p->max_retries = 6;
	p->lsp = NVMF_LOG_DISC_LSP_NONE;
}

__public void libnvmf_discovery_args_set_max_retries(
		struct libnvmf_discovery_args *p,
		int max_retries)
{
	p->max_retries = max_retries;
}

__public int libnvmf_discovery_args_get_max_retries(
		const struct libnvmf_discovery_args *p)
{
	return p->max_retries;
}

__public void libnvmf_discovery_args_set_lsp(
		struct libnvmf_discovery_args *p,
		__u8 lsp)
{
	p->lsp = lsp;
}

__public __u8 libnvmf_discovery_args_get_lsp(
		const struct libnvmf_discovery_args *p)
{
	return p->lsp;
}

/****************************************************************************
 * Accessors for: struct libnvmf_uri
 ****************************************************************************/

__public void libnvmf_uri_set_scheme(struct libnvmf_uri *p, const char *scheme)
{
	free(p->scheme);
	p->scheme = scheme ? strdup(scheme) : NULL;
}

__public const char *libnvmf_uri_get_scheme(const struct libnvmf_uri *p)
{
	return p->scheme;
}

__public void libnvmf_uri_set_protocol(
		struct libnvmf_uri *p,
		const char *protocol)
{
	free(p->protocol);
	p->protocol = protocol ? strdup(protocol) : NULL;
}

__public const char *libnvmf_uri_get_protocol(const struct libnvmf_uri *p)
{
	return p->protocol;
}

__public void libnvmf_uri_set_userinfo(
		struct libnvmf_uri *p,
		const char *userinfo)
{
	free(p->userinfo);
	p->userinfo = userinfo ? strdup(userinfo) : NULL;
}

__public const char *libnvmf_uri_get_userinfo(const struct libnvmf_uri *p)
{
	return p->userinfo;
}

__public void libnvmf_uri_set_host(struct libnvmf_uri *p, const char *host)
{
	free(p->host);
	p->host = host ? strdup(host) : NULL;
}

__public const char *libnvmf_uri_get_host(const struct libnvmf_uri *p)
{
	return p->host;
}

__public void libnvmf_uri_set_port(struct libnvmf_uri *p, int port)
{
	p->port = port;
}

__public int libnvmf_uri_get_port(const struct libnvmf_uri *p)
{
	return p->port;
}

__public void libnvmf_uri_set_path_segments(
		struct libnvmf_uri *p,
		const char *const *path_segments)
{
	char **new_array = NULL;
	size_t i;

	if (path_segments) {
		for (i = 0; path_segments[i]; i++)
			;

		new_array = calloc(i + 1, sizeof(char *));
		if (new_array != NULL) {
			for (i = 0; path_segments[i]; i++) {
				new_array[i] = strdup(path_segments[i]);
				if (!new_array[i]) {
					while (i > 0)
						free(new_array[--i]);
					free(new_array);
					new_array = NULL;
					break;
				}
			}
		}
	}

	for (i = 0; p->path_segments && p->path_segments[i]; i++)
		free(p->path_segments[i]);
	free(p->path_segments);
	p->path_segments = new_array;
}

__public const char *const *libnvmf_uri_get_path_segments(
		const struct libnvmf_uri *p)
{
	return (const char *const *)p->path_segments;
}

__public void libnvmf_uri_set_query(struct libnvmf_uri *p, const char *query)
{
	free(p->query);
	p->query = query ? strdup(query) : NULL;
}

__public const char *libnvmf_uri_get_query(const struct libnvmf_uri *p)
{
	return p->query;
}

__public void libnvmf_uri_set_fragment(
		struct libnvmf_uri *p,
		const char *fragment)
{
	free(p->fragment);
	p->fragment = fragment ? strdup(fragment) : NULL;
}

__public const char *libnvmf_uri_get_fragment(const struct libnvmf_uri *p)
{
	return p->fragment;
}

