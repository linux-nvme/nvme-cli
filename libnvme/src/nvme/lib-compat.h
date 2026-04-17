/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 Micron Technology, Inc.
 *
 * Cross-platform compatibility definitions, types, and utilities.
 *
 * Authors: Broc Going <bgoing@micron.com>
 *          Brandon Busacker <bbusacker@micron.com>
 */
#pragma once

#if defined(_WIN32) || defined(_WIN64)

#define WIN32_LEAN_AND_MEAN	/* keeps windows.h from including winsock.*/
#include <windows.h>

#include <fcntl.h>
#include <stdio.h>

typedef HANDLE libnvme_fd_t;

#define TEST_FD INVALID_HANDLE_VALUE
#define INIT_FD nullptr

/*
 * Set stdout and stderr to binary mode to prevent Windows text-mode
 * translation from converting LF to CRLF and corrupting raw binary output.
 * Call once at startup.
 */
static inline void libnvme_init(void)
{
	_setmode(_fileno(stdout), O_BINARY);
	_setmode(_fileno(stderr), O_BINARY);
}

#else

typedef int libnvme_fd_t;
#define TEST_FD 0xFD
#define INIT_FD -1

/* Platform initialization - no-op on Linux */
static inline void libnvme_init(void) {}

#endif
