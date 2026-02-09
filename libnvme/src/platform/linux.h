// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2025 Micron Technology, Inc.
 *
 * Linux platform-specific definitions and includes.
 * Complete replacement for Linux portions of legacy platform.h
 */

#ifndef _LIBNVME_PLATFORM_LINUX_H
#define _LIBNVME_PLATFORM_LINUX_H

/* Linux standard includes */
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <poll.h>
#include <syslog.h>

/* Linux-specific includes */
#include <linux/types.h>
#include <endian.h>
#include <net/if.h>

/* Linux cleanup attribute */
#define __nvme_cleanup(fn) __attribute__((__cleanup__(fn)))

/* Extract IPv4 from IPv6 mapped address */
#define ipv4_from_in6_addr(addr) &(addr.s6_addr32[3])

typedef int nvme_fd_t;
#define TEST_FD 0xFD
#define INIT_FD -1

/* Platform-specific fstat wrapper for nvme_fd_t */
static inline int nvme_fstat(nvme_fd_t fd, struct stat *buf)
{
	return fstat(fd, buf);
}

/* Platform-specific UUID generation using /dev/urandom */
static inline int random_uuid(unsigned char *uuid, size_t len)
{
	int f, ret = 0;
	ssize_t n;

	f = open("/dev/urandom", O_RDONLY);
	if (f < 0)
		return -errno;

	n = read(f, uuid, len);
	if (n < 0)
		ret = -errno;
	else if ((size_t)n != len)
		ret = -EIO;

	close(f);
	return ret;
}

#endif /* _LIBNVME_PLATFORM_LINUX_H */