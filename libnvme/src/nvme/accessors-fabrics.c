// SPDX-License-Identifier: LGPL-2.1-or-later

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
#include <stdlib.h>
#include <string.h>
#include "accessors-fabrics.h"

#include "private-fabrics.h"
#include "compiler_attributes.h"

/****************************************************************************
 * Accessors for: struct libnvmf_discovery_args
 ****************************************************************************/

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

__public __u8 libnvmf_discovery_args_get_lsp(const struct libnvmf_discovery_args *p)
{
	return p->lsp;
}

