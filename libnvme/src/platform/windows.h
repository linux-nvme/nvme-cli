// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2025 Micron Technology, Inc.
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
#include <signal.h>
#include <stdio.h>
#include <sys/stat.h>
#include <time.h>


/* Platform compatibility helper types and methods */

typedef HANDLE libnvme_fd_t;
#define TEST_FD INVALID_HANDLE_VALUE
#define INIT_FD nullptr

/*
 * Set stdout and stderr to binary mode to prevent Windows text-mode
 * translation from converting LF to CRLF and corrupting raw binary output.
 * Called once at startup from main().
 */
static inline void libnvme_init(void)
{
	_setmode(_fileno(stdout), O_BINARY);
	_setmode(_fileno(stderr), O_BINARY);
}


/* signal.h POSIX compatibility - Windows doesn't have sigaction */

struct sigaction {
	void (*sa_handler)(int);
	int sa_flags;
	int sa_mask;  /* simplified - normally sigset_t */
};

static inline int sigemptyset(int *set)
{
	*set = 0;
	return 0;
}

/*
 * Simplified signal handling using Windows signal() function
 * This is sufficient for handling SIGINT with no mask or flags.
 */
static inline int sigaction(int signum, const struct sigaction *act,
			struct sigaction *oldact)
{
	(void)oldact; /* ignore old action for simplicity */
	if (act && act->sa_handler) {
		signal(signum, act->sa_handler);
		return 0;
	}
	return -1;
}


/* sys/stat.h compatibility */

/* Windows _mkdir doesn't take mode parameter */
/* _mkdir is defined in <direct.h> */
#define mkdir(path, mode) _mkdir(path)
