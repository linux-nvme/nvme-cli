/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 Micron Technology, Inc.
 *
 * Cross-platform compatibility for unistd.h.
 * Provides functionality that may be missing on some platforms.
 * Compatibility is not comprehensive. Only functionality required by
 * nvme-cli and libnvme is included.
 *
 * Authors: Brandon Busacker <bbusacker@micron.com>
 */
#pragma once

#include <unistd.h>

#if defined(_WIN32)

#include <io.h>
#include <sysinfoapi.h>
#include <winsock2.h>	/* for gethostname */

/* unistd.h POSIX compatibility */

#define fsync _commit

/* getpagesize implementation for Windows */
static inline int getpagesize(void)
{
	SYSTEM_INFO si;

	GetSystemInfo(&si);
	return si.dwPageSize;
}

#endif
