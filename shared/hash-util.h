/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

/* FNV-1a 64-bit over a byte range: fast and dependency-free. */
static inline uint64_t fnv1a_64(const void *buf, size_t len)
{
	const unsigned char *p = buf;
	uint64_t hash = 14695981039346656037ULL;
	size_t i;

	for (i = 0; i < len; i++) {
		hash ^= p[i];
		hash *= 1099511628211ULL;
	}
	return hash;
}
