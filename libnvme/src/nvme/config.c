// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026, Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <Martin.Belanger@dell.com>
 */

/*
 * The public face of the NVMe-oF connection configuration
 * (libnvme/design/CONFIG.md).  Parsing and cascade resolution live in
 * config-ini.c and config-resolve.c; nothing about files, sections or
 * drop-ins crosses this boundary -- consumers see the resolved connection
 * list only.
 */

#include <errno.h>
#include <stddef.h>

#include <nvme/config.h>

#include <ccan/list/list.h>

#include "compiler-attributes.h"
#include "config-ini.h"

#define CONFIG_MAIN_PATH SYSCONFDIR "/nvme/nvme-fabrics.conf"

__libnvme_public int libnvmf_config_read(struct libnvme_global_ctx *ctx,
		const char *file, struct libnvmf_config **out)
{
	if (!out)
		return -EINVAL;
	*out = NULL;
	if (!ctx)
		return -EINVAL;

	return libnvmf_config_load(ctx, file ? file : CONFIG_MAIN_PATH, out);
}

__libnvme_public int libnvmf_config_validate(struct libnvme_global_ctx *ctx,
		const char *file)
{
	struct libnvmf_config *config;
	int err;

	if (!ctx)
		return -EINVAL;

	err = libnvmf_config_load(ctx, file ? file : CONFIG_MAIN_PATH, &config);
	libnvmf_config_free(config);

	return err;
}

__libnvme_public void libnvmf_config_conn_for_each(
		const struct libnvmf_config *config,
		void (*callback)(const struct libnvmf_config_conn *conn,
				 void *user_data),
		void *user_data)
{
	const struct libnvmf_config_conn *conn;

	if (!config || !callback)
		return;

	list_for_each(&config->conns, conn, entry)
		callback(conn, user_data);
}

__libnvme_public bool libnvmf_config_conn_is_dc(
		const struct libnvmf_config_conn *conn)
{
	return conn && conn->is_dc;
}

__libnvme_public const char *libnvmf_config_conn_get_transport(
		const struct libnvmf_config_conn *conn)
{
	return conn ? conn->transport : NULL;
}

__libnvme_public const char *libnvmf_config_conn_get_traddr(
		const struct libnvmf_config_conn *conn)
{
	return conn ? conn->traddr : NULL;
}

__libnvme_public const char *libnvmf_config_conn_get_trsvcid(
		const struct libnvmf_config_conn *conn)
{
	return conn ? conn->trsvcid : NULL;
}

__libnvme_public const char *libnvmf_config_conn_get_subsysnqn(
		const struct libnvmf_config_conn *conn)
{
	return conn ? conn->subsysnqn : NULL;
}

__libnvme_public const char *libnvmf_config_conn_get_host_traddr(
		const struct libnvmf_config_conn *conn)
{
	return conn ? conn->host_traddr : NULL;
}

__libnvme_public const char *libnvmf_config_conn_get_host_iface(
		const struct libnvmf_config_conn *conn)
{
	return conn ? conn->host_iface : NULL;
}

__libnvme_public const char *libnvmf_config_conn_get_hostnqn(
		const struct libnvmf_config_conn *conn)
{
	return conn ? conn->hostnqn : NULL;
}

__libnvme_public const char *libnvmf_config_conn_get_hostid(
		const struct libnvmf_config_conn *conn)
{
	return conn ? conn->hostid : NULL;
}

__libnvme_public const struct libnvmf_params *libnvmf_config_conn_get_params(
		const struct libnvmf_config_conn *conn)
{
	return conn ? conn->params : NULL;
}

__libnvme_public const char *libnvmf_config_conn_get_hostsymname(
		const struct libnvmf_config_conn *conn)
{
	return conn ? conn->hostsymname : NULL;
}

__libnvme_public const char *libnvmf_config_conn_get_source(
		const struct libnvmf_config_conn *conn)
{
	return conn ? conn->source : NULL;
}

__libnvme_public const struct libnvmf_params *libnvmf_config_resolve_discovered(
		const struct libnvmf_config *config,
		const struct libnvmf_config_conn *via_dc,
		bool is_dc)
{
	if (!config)
		return NULL;
	if (via_dc)
		return is_dc ? via_dc->dlp_dc_params : via_dc->dlp_ioc_params;

	return is_dc ? config->top_dc_params : config->top_ioc_params;
}
