// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2025 Micron Technology, Inc.
 *
 * Windows platform-specific definitions and includes.
 * Complete replacement for Windows portions of legacy platform.h
 */

#ifndef _LIBNVME_PLATFORM_WINDOWS_H
#define _LIBNVME_PLATFORM_WINDOWS_H

/* Windows-specific includes - winsock2 before windows.h to avoid warnings */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#undef WIN32_LEAN_AND_MEAN
#include <winioctl.h>
#include <ntddstor.h>
#include <bcrypt.h>
#include <stdint.h>
#include <stdarg.h>
#include <errno.h>
#include <io.h>
#include <direct.h>
#include <process.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>

/* Prevent conflicts with Windows min/max macros */
#ifdef min
#undef min
#endif
#ifdef max  
#undef max
#endif

/* Windows cleanup - no-op since Windows doesn't have cleanup attribute */
#define __nvme_cleanup(fn) /* No cleanup attribute on Windows */

/* Windows endian conversion macros */
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    #define htole16(x) __builtin_bswap16(x)
    #define htole32(x) __builtin_bswap32(x)
    #define htole64(x) __builtin_bswap64(x)
    #define le16toh(x) __builtin_bswap16(x)
    #define le32toh(x) __builtin_bswap32(x)
    #define le64toh(x) __builtin_bswap64(x)
#else
    /* Little-endian (most common case for Windows) */
    #define htole16(x) (x)
    #define htole32(x) (x)
    #define htole64(x) (x)
    #define le16toh(x) (x)
    #define le32toh(x) (x)
    #define le64toh(x) (x)
#endif

/* syslog.h stubs */
#define LOG_EMERG   0
#define LOG_ALERT   1  
#define LOG_CRIT    2
#define LOG_ERR     3
#define LOG_WARNING 4
#define LOG_NOTICE  5
#define LOG_INFO    6
#define LOG_DEBUG   7
static inline void syslog(int priority, const char *format, ...) { (void)priority; (void)format; }
static inline void openlog(const char *ident, int option, int facility) { (void)ident; (void)option; (void)facility; }
static inline void closelog(void) { }

/* poll.h stubs - winsock2.h provides struct pollfd */
#ifndef POLLIN
#define POLLIN  0x001
#endif
#ifndef POLLOUT
#define POLLOUT 0x004
#endif
#ifndef POLLERR
#define POLLERR 0x008
#endif
#ifndef POLLHUP
#define POLLHUP 0x010
#endif
#ifndef POLLNVAL
#define POLLNVAL 0x020
#endif

/* sys/ioctl.h stubs */
#define IOCTL_STORAGE_QUERY_PROPERTY CTL_CODE(IOCTL_STORAGE_BASE, 0x0500, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* Linux ioctl constants - stubs for block device operations */
#ifndef BLKBSZSET
#define BLKBSZSET 0x40081271
#endif
#ifndef BLKRRPART
#define BLKRRPART 0x125F
#endif

/* Windows ioctl stub functions */
static inline int ioctl(int fd, unsigned long request, ...) {
    (void)fd; (void)request;
    errno = ENOSYS;
    return -1;
}

/* Windows file descriptors */
#ifndef STDERR_FILENO
#define STDERR_FILENO 2
#endif
#ifndef STDOUT_FILENO  
#define STDOUT_FILENO 1
#endif
#ifndef STDIN_FILENO
#define STDIN_FILENO 0
#endif

/* Windows sys/param.h compatibility */
#ifndef MAXPATHLEN
#define MAXPATHLEN 260  /* Windows MAX_PATH */
#endif

/* Windows missing error codes */
#ifndef EREMOTEIO
#define EREMOTEIO 121
#endif
#ifndef EDQUOT
#define EDQUOT 122
#endif
#ifndef ERESTART
#define ERESTART 85
#endif
#ifndef ENOTBLK
#define ENOTBLK 15
#endif
#ifndef ENAVAIL
#define ENAVAIL 119
#endif

/* Windows missing socket types */
typedef unsigned long nfds_t;

/* Windows missing mode_t */
#ifndef _MODE_T_
#define _MODE_T_
typedef unsigned int mode_t;
#endif

/* Windows missing socket structures */
struct msghdr {
    void *msg_name;
    socklen_t msg_namelen;
    struct iovec *msg_iov;
    size_t msg_iovlen;
    void *msg_control;
    size_t msg_controllen;
    int msg_flags;
};

struct iovec {
    void *iov_base;
    size_t iov_len;
};

/* Windows missing network structures */
struct ifaddrs {
    struct ifaddrs *ifa_next;
    char *ifa_name;
    unsigned int ifa_flags;
    struct sockaddr *ifa_addr;
    struct sockaddr *ifa_netmask;
    struct sockaddr *ifa_broadaddr;
    void *ifa_data;
};

/* Extract IPv4 from IPv6 mapped address */
#define ipv4_from_in6_addr(addr) &(addr.u.Byte[12])

/* Windows missing POSIX functions */
static inline int dprintf(int fd, const char *format, ...) {
    va_list args;
    char buffer[4096];
    int result;
    va_start(args, format);
    result = vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    if (fd == STDERR_FILENO) {
        fputs(buffer, stderr);
    } else if (fd == STDOUT_FILENO) {
        fputs(buffer, stdout);
    }
    return result;
}

static inline int getpagesize(void) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return si.dwPageSize;
}

static inline int posix_memalign(void **memptr, size_t alignment, size_t size) {
    *memptr = _aligned_malloc(size, alignment);
    return (*memptr == NULL) ? ENOMEM : 0;
}

static inline size_t malloc_usable_size(void *ptr) {
    return _msize(ptr);
}

/* Windows ioctl macros - only define if not already defined by winsock */
#ifndef _IOC_NONE
#define _IOC_NONE  0U
#define _IOC_WRITE 1U
#define _IOC_READ  2U

#define _IOC(dir,type,nr,size) \
    (((dir)  << 30) | \
     ((type) << 8) | \
     ((nr)   << 0) | \
     ((size) << 16))

/* Only define if winsock2.h hasn't already defined them */
#ifndef _IO
#define _IO(type,nr)        _IOC(_IOC_NONE,(type),(nr),0)
#endif
#ifndef _IOR  
#define _IOR(type,nr,size)  _IOC(_IOC_READ,(type),(nr),sizeof(size))
#endif
#ifndef _IOW
#define _IOW(type,nr,size)  _IOC(_IOC_WRITE,(type),(nr),sizeof(size))
#endif
#ifndef _IOWR
#define _IOWR(type,nr,size) _IOC(_IOC_READ|_IOC_WRITE,(type),(nr),sizeof(size))
#endif
#endif /* _IOC_NONE */

/* MIN/min macros for Windows */
#ifndef __cplusplus
#ifndef MIN
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif
#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif
#endif /* __cplusplus */

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

/* ========== POSIX Compatibility Layer ========== */

/* dirent.h emulation for Windows - only if not provided by compiler */
#if !defined(_DIRENT_H_) && !defined(_DIRENT_H)
#include <dirent.h>
#endif

/* If dirent.h is not available, we would define our own, but MinGW provides it */

/* stdio.h POSIX extensions */
ssize_t getline(char **lineptr, size_t *n, FILE *stream);
FILE *open_memstream(char **ptr, size_t *sizeloc);

/* string.h POSIX extensions */
char *strsep(char **stringp, const char *delim);
void *reallocarray(void *ptr, size_t nmemb, size_t size);

/* unistd.h POSIX functions */
int readlink(const char *path, char *buf, size_t bufsiz);

/* unistd.h additions */
#ifndef fsync
#define fsync _commit
#endif
int readlink(const char *path, char *buf, size_t bufsiz);

/* time.h POSIX compatibility */
static inline struct tm *gmtime_r(const time_t *timep, struct tm *result) {
	if (gmtime_s(result, timep) == 0)
		return result;
	return NULL;
}

/* signal.h POSIX compatibility - Windows doesn't have sigaction */
#ifndef _SIGACTION_DEFINED
#define _SIGACTION_DEFINED
#include <signal.h>

struct sigaction {
	void (*sa_handler)(int);
	int sa_flags;
	int sa_mask;  /* simplified - normally sigset_t */
};

#define SA_RESTART 0x10000000

static inline int sigemptyset(int *set) {
	*set = 0;
	return 0;
}

static inline int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact) {
	(void)oldact; /* ignore old action for simplicity */
	if (act && act->sa_handler) {
		signal(signum, act->sa_handler);
		return 0;
	}
	return -1;
}

#endif /* _SIGACTION_DEFINED */

/* fnmatch.h POSIX compatibility */
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

/* limits.h additions */
#ifndef NAME_MAX
#define NAME_MAX 260
#endif

/* sys/stat.h compatibility */
#ifndef S_ISBLK
#define S_ISBLK(m) (0)
#endif

/* mkdir compatibility - Windows _mkdir doesn't take mode parameter */
#ifndef mkdir
#define mkdir(path, mode) _mkdir(path)
#endif

/* Memory mapping stubs - not fully supported on Windows */
#define PROT_READ  0x1
#define PROT_WRITE 0x2
#define MAP_SHARED 0x01
#define MAP_PRIVATE 0x02
#define MAP_ANONYMOUS 0x20
#define MAP_HUGETLB 0x40000
#define MAP_FAILED ((void *) -1)
#define MADV_HUGEPAGE 14

static inline void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
	(void)addr; (void)length; (void)prot; (void)flags; (void)fd; (void)offset;
	errno = ENOSYS;
	return MAP_FAILED;
}

static inline int munmap(void *addr, size_t length) {
	(void)addr; (void)length;
	errno = ENOSYS;
	return -1;
}

static inline int madvise(void *addr, size_t length, int advice) {
	(void)addr; (void)length; (void)advice;
	errno = ENOSYS;
	return -1;
}

/* DLL loading compatibility */
#define RTLD_LAZY 0
static inline void *dlopen(const char *filename, int flag) {
	(void)flag;
	return (void *)LoadLibraryA(filename);
}

static inline void *dlsym(void *handle, const char *symbol) {
	return (void *)GetProcAddress((HMODULE)handle, symbol);
}

static inline int dlclose(void *handle) {
	return FreeLibrary((HMODULE)handle) ? 0 : -1;
}

static inline char *dlerror(void) {
	static char buf[256];
	DWORD err = GetLastError();
	snprintf(buf, sizeof(buf), "Error %lu", err);
	return buf;
}

/* Socket compatibility */
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

/* sendfile stub */
static inline ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count) {
	(void)out_fd; (void)in_fd; (void)offset; (void)count;
	errno = ENOSYS;
	return -1;
}

#endif /* _LIBNVME_PLATFORM_WINDOWS_H */