/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */
#pragma once

#include <errno.h>
#include <unistd.h>

/* write() may return a short count; loop until the whole buffer is written. */
static inline int write_all(int fd, const void *buf, size_t len)
{
	const char *p = buf;

	while (len) {
		ssize_t w = write(fd, p, len);

		if (w < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			return -errno;
		}
		if (w == 0) {
			errno = EIO;
			return -EIO;
		}
		p += w;
		len -= w;
	}
	return 0;
}
