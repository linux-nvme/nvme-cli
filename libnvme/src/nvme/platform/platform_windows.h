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
#include <stdint.h>
#include <stdarg.h>
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

/* Windows type definitions to replace linux/types.h */
typedef uint8_t  __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
typedef int8_t   __s8;
typedef int16_t  __s16;
typedef int32_t  __s32;
typedef int64_t  __s64;

/* Little-endian types (Windows is little-endian) */
typedef __u16    __le16;
typedef __u32    __le32;
typedef __u64    __le64;
typedef __s16    __le16s;
typedef __s32    __le32s;
typedef __s64    __le64s;

/* Big-endian types for completeness */
typedef __u16    __be16;
typedef __u32    __be32;
typedef __u64    __be64;
typedef __s16    __be16s;
typedef __s32    __be32s;
typedef __s64    __be64s;

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

/* Windows missing socket types */
typedef unsigned long nfds_t;

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
#ifndef MIN
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif
#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

#endif /* _LIBNVME_PLATFORM_WINDOWS_H */