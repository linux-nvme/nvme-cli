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
 * Authors: Broc Going <bgoing@micron.com>
 *          Brandon Capener <bcapener@micron.com>
 */
#pragma once

#include <unistd.h>

#if defined(_WIN32) || defined(_WIN64)

#include <io.h>
#include <sysinfoapi.h>

/* unistd.h POSIX compatibility */

#define STDERR_FILENO 2
#define STDOUT_FILENO 1
#define STDIN_FILENO  0

/* getpagesize implementation for Windows */
static inline int getpagesize(void)
{
	SYSTEM_INFO si;

	GetSystemInfo(&si);
	return si.dwPageSize;
}

/*
 * readlink stub - Windows doesn't have symbolic links in the same way
 * NOTE: This is only used by micron-nvme.c, and can be removed once that
 * has been refactored to not rely on Linux-specific sysfs paths.
 */
static inline ssize_t readlink(const char *path, char *buf, size_t bufsiz)
{
	errno = ENOTSUP;
	return -1;
}

/* fsync implementation for Windows */
static inline int fsync(int fd)
{
	return _commit(fd);
}

#endif