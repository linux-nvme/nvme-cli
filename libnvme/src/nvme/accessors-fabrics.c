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
 * Accessors for: struct libnvmf_context
 ****************************************************************************/

__libnvme_public const char *libnvmf_context_get_transport(
		const struct libnvmf_context *p)
{
	return p->ctrl_params.transport;
}

__libnvme_public const char *libnvmf_context_get_traddr(
		const struct libnvmf_context *p)
{
	return p->ctrl_params.traddr;
}

__libnvme_public const char *libnvmf_context_get_host_traddr(
		const struct libnvmf_context *p)
{
	return p->ctrl_params.host_traddr;
}

__libnvme_public const char *libnvmf_context_get_host_iface(
		const struct libnvmf_context *p)
{
	return p->ctrl_params.host_iface;
}

__libnvme_public const char *libnvmf_context_get_trsvcid(
		const struct libnvmf_context *p)
{
	return p->ctrl_params.trsvcid;
}

__libnvme_public const char *libnvmf_context_get_subsysnqn(
		const struct libnvmf_context *p)
{
	return p->ctrl_params.subsysnqn;
}

__libnvme_public void libnvmf_context_set_queue_size(
		struct libnvmf_context *p,
		int queue_size)
{
	p->ctrl_params.cfg.queue_size = queue_size;
}

__libnvme_public int libnvmf_context_get_queue_size(
		const struct libnvmf_context *p)
{
	return p->ctrl_params.cfg.queue_size;
}

__libnvme_public void libnvmf_context_set_nr_io_queues(
		struct libnvmf_context *p,
		int nr_io_queues)
{
	p->ctrl_params.cfg.nr_io_queues = nr_io_queues;
}

__libnvme_public int libnvmf_context_get_nr_io_queues(
		const struct libnvmf_context *p)
{
	return p->ctrl_params.cfg.nr_io_queues;
}

__libnvme_public void libnvmf_context_set_reconnect_delay(
		struct libnvmf_context *p,
		int reconnect_delay)
{
	p->ctrl_params.cfg.reconnect_delay = reconnect_delay;
}

__libnvme_public int libnvmf_context_get_reconnect_delay(
		const struct libnvmf_context *p)
{
	return p->ctrl_params.cfg.reconnect_delay;
}

__libnvme_public void libnvmf_context_set_ctrl_loss_tmo(
		struct libnvmf_context *p,
		int ctrl_loss_tmo)
{
	p->ctrl_params.cfg.ctrl_loss_tmo = ctrl_loss_tmo;
}

__libnvme_public int libnvmf_context_get_ctrl_loss_tmo(
		const struct libnvmf_context *p)
{
	return p->ctrl_params.cfg.ctrl_loss_tmo;
}

__libnvme_public void libnvmf_context_set_fast_io_fail_tmo(
		struct libnvmf_context *p,
		int fast_io_fail_tmo)
{
	p->ctrl_params.cfg.fast_io_fail_tmo = fast_io_fail_tmo;
}

__libnvme_public int libnvmf_context_get_fast_io_fail_tmo(
		const struct libnvmf_context *p)
{
	return p->ctrl_params.cfg.fast_io_fail_tmo;
}

__libnvme_public void libnvmf_context_set_keep_alive_tmo(
		struct libnvmf_context *p,
		int keep_alive_tmo)
{
	p->ctrl_params.cfg.keep_alive_tmo = keep_alive_tmo;
}

__libnvme_public int libnvmf_context_get_keep_alive_tmo(
		const struct libnvmf_context *p)
{
	return p->ctrl_params.cfg.keep_alive_tmo;
}

__libnvme_public void libnvmf_context_set_nr_write_queues(
		struct libnvmf_context *p,
		int nr_write_queues)
{
	p->ctrl_params.cfg.nr_write_queues = nr_write_queues;
}

__libnvme_public int libnvmf_context_get_nr_write_queues(
		const struct libnvmf_context *p)
{
	return p->ctrl_params.cfg.nr_write_queues;
}

__libnvme_public void libnvmf_context_set_nr_poll_queues(
		struct libnvmf_context *p,
		int nr_poll_queues)
{
	p->ctrl_params.cfg.nr_poll_queues = nr_poll_queues;
}

__libnvme_public int libnvmf_context_get_nr_poll_queues(
		const struct libnvmf_context *p)
{
	return p->ctrl_params.cfg.nr_poll_queues;
}

__libnvme_public void libnvmf_context_set_tos(
		struct libnvmf_context *p,
		int tos)
{
	p->ctrl_params.cfg.tos = tos;
}

__libnvme_public int libnvmf_context_get_tos(const struct libnvmf_context *p)
{
	return p->ctrl_params.cfg.tos;
}

__libnvme_public void libnvmf_context_set_keyring_id(
		struct libnvmf_context *p,
		long keyring_id)
{
	p->ctrl_params.cfg.keyring_id = keyring_id;
}

__libnvme_public long libnvmf_context_get_keyring_id(
		const struct libnvmf_context *p)
{
	return p->ctrl_params.cfg.keyring_id;
}

__libnvme_public void libnvmf_context_set_tls_key_id(
		struct libnvmf_context *p,
		long tls_key_id)
{
	p->ctrl_params.cfg.tls_key_id = tls_key_id;
}

__libnvme_public long libnvmf_context_get_tls_key_id(
		const struct libnvmf_context *p)
{
	return p->ctrl_params.cfg.tls_key_id;
}

__libnvme_public void libnvmf_context_set_tls_configured_key_id(
		struct libnvmf_context *p,
		long tls_configured_key_id)
{
	p->ctrl_params.cfg.tls_configured_key_id = tls_configured_key_id;
}

__libnvme_public long libnvmf_context_get_tls_configured_key_id(
		const struct libnvmf_context *p)
{
	return p->ctrl_params.cfg.tls_configured_key_id;
}

__libnvme_public void libnvmf_context_set_duplicate_connect(
		struct libnvmf_context *p,
		bool duplicate_connect)
{
	p->ctrl_params.cfg.duplicate_connect = duplicate_connect;
}

__libnvme_public bool libnvmf_context_get_duplicate_connect(
		const struct libnvmf_context *p)
{
	return p->ctrl_params.cfg.duplicate_connect;
}

__libnvme_public void libnvmf_context_set_disable_sqflow(
		struct libnvmf_context *p,
		bool disable_sqflow)
{
	p->ctrl_params.cfg.disable_sqflow = disable_sqflow;
}

__libnvme_public bool libnvmf_context_get_disable_sqflow(
		const struct libnvmf_context *p)
{
	return p->ctrl_params.cfg.disable_sqflow;
}

__libnvme_public void libnvmf_context_set_hdr_digest(
		struct libnvmf_context *p,
		bool hdr_digest)
{
	p->ctrl_params.cfg.hdr_digest = hdr_digest;
}

__libnvme_public bool libnvmf_context_get_hdr_digest(
		const struct libnvmf_context *p)
{
	return p->ctrl_params.cfg.hdr_digest;
}

__libnvme_public void libnvmf_context_set_data_digest(
		struct libnvmf_context *p,
		bool data_digest)
{
	p->ctrl_params.cfg.data_digest = data_digest;
}

__libnvme_public bool libnvmf_context_get_data_digest(
		const struct libnvmf_context *p)
{
	return p->ctrl_params.cfg.data_digest;
}

__libnvme_public void libnvmf_context_set_tls(
		struct libnvmf_context *p,
		bool tls)
{
	p->ctrl_params.cfg.tls = tls;
}

__libnvme_public bool libnvmf_context_get_tls(const struct libnvmf_context *p)
{
	return p->ctrl_params.cfg.tls;
}

__libnvme_public void libnvmf_context_set_concat(
		struct libnvmf_context *p,
		bool concat)
{
	p->ctrl_params.cfg.concat = concat;
}

__libnvme_public bool libnvmf_context_get_concat(
		const struct libnvmf_context *p)
{
	return p->ctrl_params.cfg.concat;
}

__libnvme_public void libnvmf_context_set_default_max_discovery_retries(
		struct libnvmf_context *p,
		int default_max_discovery_retries)
{
	p->default_max_discovery_retries = default_max_discovery_retries;
}

__libnvme_public int libnvmf_context_get_default_max_discovery_retries(
		const struct libnvmf_context *p)
{
	return p->default_max_discovery_retries;
}

__libnvme_public void libnvmf_context_set_default_keep_alive_timeout(
		struct libnvmf_context *p,
		int default_keep_alive_timeout)
{
	p->default_keep_alive_timeout = default_keep_alive_timeout;
}

__libnvme_public int libnvmf_context_get_default_keep_alive_timeout(
		const struct libnvmf_context *p)
{
	return p->default_keep_alive_timeout;
}

__libnvme_public const char *libnvmf_context_get_device(
		const struct libnvmf_context *p)
{
	return p->device;
}

__libnvme_public void libnvmf_context_set_persistent(
		struct libnvmf_context *p,
		bool persistent)
{
	p->persistent = persistent;
}

__libnvme_public bool libnvmf_context_get_persistent(
		const struct libnvmf_context *p)
{
	return p->persistent;
}

__libnvme_public const char *libnvmf_context_get_hostnqn(
		const struct libnvmf_context *p)
{
	return p->hostnqn;
}

__libnvme_public const char *libnvmf_context_get_hostid(
		const struct libnvmf_context *p)
{
	return p->hostid;
}

__libnvme_public const char *libnvmf_context_get_hostkey(
		const struct libnvmf_context *p)
{
	return p->hostkey;
}

__libnvme_public const char *libnvmf_context_get_ctrlkey(
		const struct libnvmf_context *p)
{
	return p->ctrlkey;
}

__libnvme_public const char *libnvmf_context_get_keyring(
		const struct libnvmf_context *p)
{
	return p->keyring;
}

__libnvme_public const char *libnvmf_context_get_tls_key(
		const struct libnvmf_context *p)
{
	return p->tls_key;
}

__libnvme_public const char *libnvmf_context_get_tls_key_identity(
		const struct libnvmf_context *p)
{
	return p->tls_key_identity;
}

/****************************************************************************
 * Accessors for: struct libnvmf_tid
 ****************************************************************************/

__libnvme_public int libnvmf_tid_new(struct libnvmf_tid **pp)
{
	if (!pp)
		return -EINVAL;
	*pp = calloc(1, sizeof(struct libnvmf_tid));
	return *pp ? 0 : -ENOMEM;
}

__libnvme_public void libnvmf_tid_free(struct libnvmf_tid *p)
{
	if (!p)
		return;
	free(p->transport);
	free(p->traddr);
	free(p->trsvcid);
	free(p->subsysnqn);
	free(p->host_traddr);
	free(p->host_iface);
	free(p->hostnqn);
	free(p->hostid);
	free(p->_canonical);
	free(p->_str);
	free(p);
}

__libnvme_public const char *libnvmf_tid_get_transport(
		const struct libnvmf_tid *p)
{
	return p->transport;
}

__libnvme_public const char *libnvmf_tid_get_traddr(const struct libnvmf_tid *p)
{
	return p->traddr;
}

__libnvme_public const char *libnvmf_tid_get_trsvcid(
		const struct libnvmf_tid *p)
{
	return p->trsvcid;
}

__libnvme_public const char *libnvmf_tid_get_subsysnqn(
		const struct libnvmf_tid *p)
{
	return p->subsysnqn;
}

__libnvme_public const char *libnvmf_tid_get_host_traddr(
		const struct libnvmf_tid *p)
{
	return p->host_traddr;
}

__libnvme_public const char *libnvmf_tid_get_host_iface(
		const struct libnvmf_tid *p)
{
	return p->host_iface;
}

__libnvme_public const char *libnvmf_tid_get_hostnqn(
		const struct libnvmf_tid *p)
{
	return p->hostnqn;
}

__libnvme_public const char *libnvmf_tid_get_hostid(const struct libnvmf_tid *p)
{
	return p->hostid;
}

/****************************************************************************
 * Accessors for: struct libnvmf_discovery_args
 ****************************************************************************/

__libnvme_public int libnvmf_discovery_args_new(
		struct libnvmf_discovery_args **pp)
{
	if (!pp)
		return -EINVAL;
	*pp = calloc(1, sizeof(struct libnvmf_discovery_args));
	if (!*pp)
		return -ENOMEM;
	libnvmf_discovery_args_init_defaults(*pp);
	return 0;
}

__libnvme_public void libnvmf_discovery_args_free(
		struct libnvmf_discovery_args *p)
{
	free(p);
}

__libnvme_public void libnvmf_discovery_args_init_defaults(
		struct libnvmf_discovery_args *p)
{
	if (!p)
		return;
	p->max_retries = 6;
	p->lsp = NVMF_LOG_DISC_LSP_NONE;
}

__libnvme_public void libnvmf_discovery_args_set_max_retries(
		struct libnvmf_discovery_args *p,
		int max_retries)
{
	p->max_retries = max_retries;
}

__libnvme_public int libnvmf_discovery_args_get_max_retries(
		const struct libnvmf_discovery_args *p)
{
	return p->max_retries;
}

__libnvme_public void libnvmf_discovery_args_set_lsp(
		struct libnvmf_discovery_args *p,
		__u8 lsp)
{
	p->lsp = lsp;
}

__libnvme_public __u8 libnvmf_discovery_args_get_lsp(
		const struct libnvmf_discovery_args *p)
{
	return p->lsp;
}

/****************************************************************************
 * Accessors for: struct libnvmf_uri
 ****************************************************************************/

__libnvme_public void libnvmf_uri_set_scheme(
		struct libnvmf_uri *p,
		const char *scheme)
{
	free(p->scheme);
	p->scheme = scheme ? strdup(scheme) : NULL;
}

__libnvme_public const char *libnvmf_uri_get_scheme(const struct libnvmf_uri *p)
{
	return p->scheme;
}

__libnvme_public void libnvmf_uri_set_protocol(
		struct libnvmf_uri *p,
		const char *protocol)
{
	free(p->protocol);
	p->protocol = protocol ? strdup(protocol) : NULL;
}

__libnvme_public const char *libnvmf_uri_get_protocol(
		const struct libnvmf_uri *p)
{
	return p->protocol;
}

__libnvme_public void libnvmf_uri_set_userinfo(
		struct libnvmf_uri *p,
		const char *userinfo)
{
	free(p->userinfo);
	p->userinfo = userinfo ? strdup(userinfo) : NULL;
}

__libnvme_public const char *libnvmf_uri_get_userinfo(
		const struct libnvmf_uri *p)
{
	return p->userinfo;
}

__libnvme_public void libnvmf_uri_set_host(
		struct libnvmf_uri *p,
		const char *host)
{
	free(p->host);
	p->host = host ? strdup(host) : NULL;
}

__libnvme_public const char *libnvmf_uri_get_host(const struct libnvmf_uri *p)
{
	return p->host;
}

__libnvme_public void libnvmf_uri_set_port(struct libnvmf_uri *p, int port)
{
	p->port = port;
}

__libnvme_public int libnvmf_uri_get_port(const struct libnvmf_uri *p)
{
	return p->port;
}

__libnvme_public void libnvmf_uri_set_path_segments(
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

__libnvme_public const char *const *libnvmf_uri_get_path_segments(
		const struct libnvmf_uri *p)
{
	return (const char *const *)p->path_segments;
}

__libnvme_public void libnvmf_uri_set_query(
		struct libnvmf_uri *p,
		const char *query)
{
	free(p->query);
	p->query = query ? strdup(query) : NULL;
}

__libnvme_public const char *libnvmf_uri_get_query(const struct libnvmf_uri *p)
{
	return p->query;
}

__libnvme_public void libnvmf_uri_set_fragment(
		struct libnvmf_uri *p,
		const char *fragment)
{
	free(p->fragment);
	p->fragment = fragment ? strdup(fragment) : NULL;
}

__libnvme_public const char *libnvmf_uri_get_fragment(
		const struct libnvmf_uri *p)
{
	return p->fragment;
}

