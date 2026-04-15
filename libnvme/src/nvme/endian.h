// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

#pragma once

#if defined(_WIN32) || defined(_WIN64)
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	#define htobe16(x) (x)
	#define htobe32(x) (x)
	#define htobe64(x) (x)
	#define htole16(x) __builtin_bswap16(x)
	#define htole32(x) __builtin_bswap32(x)
	#define htole64(x) __builtin_bswap64(x)
	#define le16toh(x) __builtin_bswap16(x)
	#define le32toh(x) __builtin_bswap32(x)
	#define le64toh(x) __builtin_bswap64(x)
#else
	/* Little-endian (most common case for Windows) */
	#define htobe16(x) __builtin_bswap16(x)
	#define htobe32(x) __builtin_bswap32(x)
	#define htobe64(x) __builtin_bswap64(x)
	#define htole16(x) (x)
	#define htole32(x) (x)
	#define htole64(x) (x)
	#define le16toh(x) (x)
	#define le32toh(x) (x)
	#define le64toh(x) (x)
#endif
#else
#include <endian.h>
#endif
