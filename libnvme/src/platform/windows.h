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


/* sys/param.h compatibility */

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))


/* errno.h compatibility */

#define EREMOTEIO 121
#define EDQUOT    122
#define ERESTART  85
#define ENOTBLK   15
#define ENAVAIL   119


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

static inline void freeifaddrs(struct ifaddrs *ifa) { (void)ifa; }

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


/* stdio.h POSIX extensions */

/* dprintf implementation for Windows */
static inline int dprintf(int fd, const char *format, ...)
{
	va_list args;
	char buffer[4096];
	int result;

	va_start(args, format);
	result = vsnprintf(buffer, sizeof(buffer), format, args);
	va_end(args);
	if (fd == STDERR_FILENO)
		fputs(buffer, stderr);
	else if (fd == STDOUT_FILENO)
		fputs(buffer, stdout);
	return result;
}

/* getline implementation for Windows */
static inline ssize_t getline(char **lineptr, size_t *n, FILE *stream)
{
	char *bufptr = NULL;
	char *p = bufptr;
	size_t size;
	int c;

	if (lineptr == NULL || stream == NULL || n == NULL) {
		errno = EINVAL;
		return -1;
	}

	bufptr = *lineptr;
	size = *n;

	c = fgetc(stream);
	if (c == EOF)
		return -1;

	if (bufptr == NULL) {
		bufptr = (char *)malloc(128);
		if (bufptr == NULL) {
			errno = ENOMEM;
			return -1;
		}
		size = 128;
	}

	p = bufptr;
	while (c != EOF) {
		if ((size_t)(p - bufptr) + 1 >= size) {
			size_t pos = (size_t)(p - bufptr);

			size = size + 128;
			bufptr = (char *)realloc(bufptr, size);
			if (bufptr == NULL) {
				errno = ENOMEM;
				return -1;
			}
			p = bufptr + pos;
		}
		*p++ = c;
		if (c == '\n')
			break;
		c = fgetc(stream);
	}

	*p = '\0';
	*lineptr = bufptr;
	*n = size;

	return p - bufptr;
}

/* open_memstream workaround for Windows - returns a temporary file instead */
static inline FILE *open_memstream(char **ptr, size_t *sizeloc)
{
	FILE *f = tmpfile();

	if (ptr)
		*ptr = NULL;
	if (sizeloc)
		*sizeloc = 0;
	return f;
}


/* string.h POSIX extensions */

/* strsep implementation for Windows */
static inline char *strsep(char **stringp, const char *delim)
{
	char *start = *stringp;
	char *p;

	if (start == NULL)
		return NULL;

	p = strpbrk(start, delim);
	if (p) {
		*p = '\0';
		*stringp = p + 1;
	} else {
		*stringp = NULL;
	}

	return start;
}


/* stdlib.h compatibility */

/* Aligned memory allocation function, use platform_aligned_free to free. */
static inline int posix_memalign(void **memptr, size_t alignment, size_t size)
{
	*memptr = _aligned_malloc(size, alignment);
	return (*memptr == NULL) ? ENOMEM : 0;
}

/*
 * Platform-specific free for aligned memory allocations.
 * Use when posix_memalign is used to allocate memory.
 */
static inline void platform_aligned_free(void *p)
{
	_aligned_free(p);
}

/* reallocarray implementation for Windows */
static inline void *reallocarray(void *ptr, size_t nmemb, size_t size)
{
	size_t total_size;

	/* Check for multiplication overflow */
	if (nmemb != 0 && size > SIZE_MAX / nmemb) {
		errno = ENOMEM;
		return NULL;
	}

	total_size = nmemb * size;
	return realloc(ptr, total_size);
}


/* malloc.h compatibility*/

static inline size_t malloc_usable_size(void *ptr)
{
	return _msize(ptr);
}


/* unistd.h POSIX compatibility */

#define STDERR_FILENO 2
#define STDOUT_FILENO 1
#define STDIN_FILENO  0

/* getpagesize implementation for Windows */
static inline DWORD getpagesize(void)
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
static inline int readlink(const char *path, char *buf, size_t bufsiz)
{
	(void)path;
	(void)buf;
	(void)bufsiz;
	errno = EINVAL;
	return -1;
}

/* fsync implementation for Windows */
static inline int fsync(int fd)
{
	return _commit(fd);
}


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


/* fnmatch.h POSIX compatibility - Only used by fabrics - consider removing */

#define FNM_NOMATCH 1
#define FNM_PATHNAME 0x01

/* Basic fnmatch implementation for Windows:
 * - Supports '*' (match any sequence, including empty) and
 *   '?' (match any single character).
 * - Ignores flags for now; they are accepted for compatibility.
 * Returns 0 on match, FNM_NOMATCH on mismatch.
 */
static inline int fnmatch(const char *pattern, const char *string, int flags)
{
	(void)flags; /* flags currently unused */

	while (*pattern) {
		if (*pattern == '*') {
			/* Skip consecutive '*' characters */
			while (*pattern == '*')
				pattern++;

			if (!*pattern)
				/* Trailing '*' matches the rest of the string */
				return 0;

			/* Try to match the remainder of the pattern at each suffix of string */
			while (*string) {
				if (!fnmatch(pattern, string, flags))
					return 0;
				string++;
			}
			/* No match found for pattern suffix after '*' */
			return FNM_NOMATCH;
		} else if (*pattern == '?') {
			/* '?' matches any single character, if present */
			if (!*string)
				return FNM_NOMATCH;
			pattern++;
			string++;
		} else {
			/* Literal character match */
			if (*pattern != *string)
				return FNM_NOMATCH;
			pattern++;
			string++;
		}
	}

	/* At end of pattern: match only if we're also at end of string */
	return *string ? FNM_NOMATCH : 0;
}


/* limits.h compatibility */

#ifndef NAME_MAX
#define NAME_MAX 260
#endif


/* Windows _mkdir doesn't take mode parameter */
#define mkdir(path, mode) _mkdir(path)

/* Platform-specific fstat wrapper for libnvme_fd_t */
int libnvme_fstat(libnvme_fd_t fd, struct stat *buf);


/* mman.h memory mapping stubs - not supported on Windows */

#define PROT_READ  0x1
#define PROT_WRITE 0x2
#define MAP_SHARED 0x01
#define MAP_FAILED ((void *) -1)

static inline void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
	(void)addr; (void)length; (void)prot; (void)flags; (void)fd; (void)offset;
	errno = ENOSYS;
	return MAP_FAILED;
}

static inline int munmap(void *addr, size_t length)
{
	(void)addr; (void)length;
	errno = ENOSYS;
	return -1;
}


/* dlfcn.h compatibility */

static inline void *dlsym(void *handle, const char *symbol)
{
	return (void *)GetProcAddress((HMODULE)handle, symbol);
}
