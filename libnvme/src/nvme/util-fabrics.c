// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026, Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <Martin.Belanger@dell.com>
 */

#include <ccan/endian/endian.h>

#include <libnvme.h>

#include "private-fabrics.h"
#include "util.h"

#include "compiler-attributes.h"

__libnvme_public struct nvmf_ext_attr *libnvmf_exat_ptr_next(
		struct nvmf_ext_attr *p)
{
	__u16 size = libnvmf_exat_size(le16_to_cpu(p->exatlen));

	return (struct nvmf_ext_attr *)((uintptr_t)p + (ptrdiff_t)size);
}

const struct ifaddrs *libnvmf_getifaddrs(struct libnvme_global_ctx *ctx)
{
	if (!ctx->ifaddrs_cache) {
		struct ifaddrs *p;

		if (!getifaddrs(&p))
			ctx->ifaddrs_cache = p;
	}

	return ctx->ifaddrs_cache;
}
