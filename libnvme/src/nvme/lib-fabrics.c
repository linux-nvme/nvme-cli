// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 SUSE LLC
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 *
 * The fabrics part of the global context.
 */

#include <sys/types.h>

#include <ifaddrs.h>
#include <stddef.h>

#include "private.h"
#include "private-fabrics.h"

void _libnvmf_ctx_free(struct libnvme_global_ctx *ctx)
{
	freeifaddrs(ctx->ifaddrs_cache); /* NULL-safe */
	ctx->ifaddrs_cache = NULL;
	_libnvmf_free_kernel_options(ctx);
	libnvmf_vendor_free(ctx->vendor);
	ctx->vendor = NULL;
}

void _libnvmf_ctx_test_base_dir_changed(struct libnvme_global_ctx *ctx)
{
	/* The vendor defaults are read from the base directory. */
	libnvmf_vendor_free(ctx->vendor);
	ctx->vendor = NULL;
}
