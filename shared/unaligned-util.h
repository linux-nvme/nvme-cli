/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */
#pragma once

#include <stdint.h>
#include <string.h>

#include <ccan/endian/endian.h>

/*
 * Read little endian values from buffers without alignment guarantees,
 * e.g. fields of a log page at arbitrary offsets.
 */

static inline uint16_t shr_get_unaligned_le16(const void *p)
{
	leint16_t v;

	memcpy(&v, p, sizeof(v));
	return le16_to_cpu(v);
}

static inline uint32_t shr_get_unaligned_le32(const void *p)
{
	leint32_t v;

	memcpy(&v, p, sizeof(v));
	return le32_to_cpu(v);
}

static inline uint64_t shr_get_unaligned_le64(const void *p)
{
	leint64_t v;

	memcpy(&v, p, sizeof(v));
	return le64_to_cpu(v);
}
