/* SPDX-License-Identifier: LGPL-2.1-or-later */

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

#pragma once

/* Opaque: defined only in the generated path-attrs.c. No
 * other file may see its layout -- every field is reachable
 * only through the accessors below.
 */
struct libnvme_path_attrs;

/* Internal: allocate/reset/free the opaque struct. Not part
 * of the public API, not listed in any .ld.
 */
struct libnvme_path_attrs *libnvme_path_attrs_alloc(void);
void libnvme_path_attrs_reset(
		struct libnvme_path_attrs *attrs);
void libnvme_path_attrs_free(
		struct libnvme_path_attrs *attrs);

/**
 * libnvme_path_get_ana_state() - Get ana_state.
 * @p: The &struct libnvme_path instance to query.
 * @ana_state: Where to store the value on success.
 * @dflt: Value to store in @ana_state on failure.
 *
 * Return: 0 on success, -ENOENT if the attribute does not
 *	   exist, or a negative errno on failure.
 */
int libnvme_path_get_ana_state(
		const struct libnvme_path *p,
		const char **ana_state,
		const char *dflt);

/**
 * libnvme_path_get_numa_nodes() - Get numa_nodes.
 * @p: The &struct libnvme_path instance to query.
 * @numa_nodes: Where to store the value on success.
 * @dflt: Value to store in @numa_nodes on failure.
 *
 * Return: 0 on success, -ENOENT if the attribute does not
 *	   exist, or a negative errno on failure.
 */
int libnvme_path_get_numa_nodes(
		const struct libnvme_path *p,
		const char **numa_nodes,
		const char *dflt);

/**
 * libnvme_path_get_grpid() - Get grpid.
 * @p: The &struct libnvme_path instance to query.
 * @grpid: Where to store the value on success.
 * @dflt: Value to store in @grpid on failure.
 *
 * Return: 0 on success, -ENOENT if the attribute does not
 *	   exist, or a negative errno on failure.
 */
int libnvme_path_get_grpid(const struct libnvme_path *p, int *grpid, int dflt);

/**
 * libnvme_path_get_queue_depth() - Get queue_depth.
 * @p: The &struct libnvme_path instance to query.
 * @queue_depth: Where to store the value on success.
 * @dflt: Value to store in @queue_depth on failure.
 *
 * Return: 0 on success, -ENOENT if the attribute does not
 *	   exist, or a negative errno on failure.
 */
int libnvme_path_get_queue_depth(
		const struct libnvme_path *p,
		int *queue_depth,
		int dflt);

/**
 * libnvme_path_get_multipath_failover_count() - Get multipath_failover_count.
 * @p: The &struct libnvme_path instance to query.
 * @multipath_failover_count: Where to store the value on success.
 * @dflt: Value to store in @multipath_failover_count on failure.
 *
 * Return: 0 on success, -ENOENT if the attribute does not
 *	   exist, or a negative errno on failure.
 */
int libnvme_path_get_multipath_failover_count(
		const struct libnvme_path *p,
		long *multipath_failover_count,
		long dflt);

/**
 * libnvme_path_get_command_retry_count() - Get command_retry_count.
 * @p: The &struct libnvme_path instance to query.
 * @command_retry_count: Where to store the value on success.
 * @dflt: Value to store in @command_retry_count on failure.
 *
 * Return: 0 on success, -ENOENT if the attribute does not
 *	   exist, or a negative errno on failure.
 */
int libnvme_path_get_command_retry_count(
		const struct libnvme_path *p,
		long *command_retry_count,
		long dflt);

/**
 * libnvme_path_get_command_error_count() - Get command_error_count.
 * @p: The &struct libnvme_path instance to query.
 * @command_error_count: Where to store the value on success.
 * @dflt: Value to store in @command_error_count on failure.
 *
 * Return: 0 on success, -ENOENT if the attribute does not
 *	   exist, or a negative errno on failure.
 */
int libnvme_path_get_command_error_count(
		const struct libnvme_path *p,
		long *command_error_count,
		long dflt);

