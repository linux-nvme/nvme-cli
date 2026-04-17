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

/* Platform-specific UUID generation using BCryptGenRandom */
static inline int random_uuid(unsigned char *uuid, size_t len)
{
	NTSTATUS status;

	status = BCryptGenRandom(NULL, uuid, (ULONG)len,
				 BCRYPT_USE_SYSTEM_PREFERRED_RNG);
	if (!BCRYPT_SUCCESS(status))
		return -EIO;

	return 0;
}


/* errno.h compatibility */

#define EREMOTEIO 121	// util.c
#define EDQUOT    122	// util.c
#define ERESTART  85	// util.c
#define ENOTBLK   15	// sfx-nvme.c - could they just use libnvme's check for char device instead?
#define ENAVAIL   119	// nvme.c - just used internally, define a custom, internal error code for this?


/* ifaddrs.h compatibility */

struct ifaddrs {
	struct ifaddrs *ifa_next;
	char *ifa_name;
	unsigned int ifa_flags;
	struct sockaddr *ifa_addr;
	struct sockaddr *ifa_netmask;
	struct sockaddr *ifa_broadaddr;
	void *ifa_data;
};


/* time.h POSIX compatibility */

static inline struct tm *gmtime_r(const time_t *timep, struct tm *result)
{
	if (gmtime_s(result, timep) == 0)
		return result;
	return NULL;
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


/* dlfcn.h compatibility */

static inline void *dlsym(void *handle, const char *symbol)
{
	return (void *)GetProcAddress((HMODULE)handle, symbol);
}
