/* SPDX-License-Identifier: LGPL-2.1-or-later */

/**
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
#ifndef _ACCESSORS_FABRICS_H_
#define _ACCESSORS_FABRICS_H_

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

#include <nvme/types.h>

/* Forward declarations. These are internal (opaque) structs. */
struct libnvmf_discovery_args;

/****************************************************************************
 * Accessors for: struct libnvmf_discovery_args
 ****************************************************************************/

/**
 * libnvmf_discovery_args_set_max_retries() - Set max_retries.
 * @p: The &struct libnvmf_discovery_args instance to update.
 * @max_retries: Value to assign to the max_retries field.
 */
void libnvmf_discovery_args_set_max_retries(
		struct libnvmf_discovery_args *p,
		int max_retries);

/**
 * libnvmf_discovery_args_get_max_retries() - Get max_retries.
 * @p: The &struct libnvmf_discovery_args instance to query.
 *
 * Return: The value of the max_retries field.
 */
int libnvmf_discovery_args_get_max_retries(const struct libnvmf_discovery_args *p);

/**
 * libnvmf_discovery_args_set_lsp() - Set lsp.
 * @p: The &struct libnvmf_discovery_args instance to update.
 * @lsp: Value to assign to the lsp field.
 */
void libnvmf_discovery_args_set_lsp(struct libnvmf_discovery_args *p, __u8 lsp);

/**
 * libnvmf_discovery_args_get_lsp() - Get lsp.
 * @p: The &struct libnvmf_discovery_args instance to query.
 *
 * Return: The value of the lsp field.
 */
__u8 libnvmf_discovery_args_get_lsp(const struct libnvmf_discovery_args *p);

#endif /* _ACCESSORS_FABRICS_H_ */
