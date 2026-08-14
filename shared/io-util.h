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
static inline int shr_write_all(int fd, const void *buf, size_t len)
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

/*
 * Read fd into out until EOF, keeping at most out_len - 1 bytes
 * (NUL-terminated) and discarding any excess. Always reads to EOF so a writer
 * on the other end of a pipe never blocks on a full buffer. An out_len of 0
 * keeps nothing but still drains to EOF.
 * Return: 0 on success, -errno on a read failure.
 */
static inline int shr_read_all(int fd, char *out, size_t out_len)
{
	size_t total = 0;
	ssize_t n = 1; /* non-zero to ensure the drain loop runs */
	char discard[512];

	if (!out && out_len)
		return -EINVAL;

	/* Fill the output buffer with up to out_len - 1 bytes. */
	if (out_len) {
		out[0] = '\0';
		while (total < out_len - 1) {
			n = read(fd, out + total, out_len - 1 - total);
			if (n < 0) {
				if (errno == EINTR)
					continue;
				out[total] = '\0';
				return -errno;
			}
			if (n == 0)
				break;
			total += (size_t)n;
		}
		out[total] = '\0';
	}

	/* Drain any remainder so the writer never blocks on a full pipe. */
	while (n > 0) {
		n = read(fd, discard, sizeof(discard));
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
	}

	return 0;
}
