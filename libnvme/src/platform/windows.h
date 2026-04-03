/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 Micron Technology, Inc.
 *
 * Windows platform-specific definitions and includes.
 */

#pragma once

/* Windows-specific includes - winsock2 before windows.h to avoid warnings */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#undef WIN32_LEAN_AND_MEAN

#include <bcrypt.h>
#include <direct.h>
#include <errno.h>
#include <fcntl.h>
#include <io.h>
#include <process.h>
#include <stdio.h>
#include <time.h>


/* endian.h compatibility */

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


/* sys/param.h compatibility */

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))


/*
 * More compatibility definitions and method implementations will be needed
 * as Windows support is developed. For now, this file serves as a base
 * implementation and an example of the proposed structure.
 */
