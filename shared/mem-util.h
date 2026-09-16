/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of nvme-cli.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>

/*
 * True if at least `size` bytes are available starting at `p`, given the
 * buffer's one-past-the-end pointer `end`. For bounds-checking a variable-
 * length buffer (e.g. a device-reported log page) before reading a fixed-
 * or variable-size chunk out of it. Takes void* so callers can pass any
 * pointer type without casting.
 */
static inline bool shr_buf_has_room(const void *p, const void *end, size_t size)
{
	const unsigned char *pp = p, *pe = end;

	return pp <= pe && size <= (size_t)(pe - pp);
}
