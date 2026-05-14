/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 Micron Technology, Inc.
 *
 * Cross-platform compatibility for stdio.h.
 * Provides functionality that may be missing on some platforms.
 * Compatibility is not comprehensive. Only functionality required by
 * nvme-cli and libnvme is included.
 *
 * Authors: Brandon Busacker <bbusacker@micron.com>
 */
#pragma once

#include <stdio.h>

#if defined(_WIN32)

#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

/* stdio.h POSIX extensions */

/*
 * open_memstream workaround for Windows - returns a temporary file instead.
 * Must be paired with close_memstream() instead of fclose() to retrieve
 * the accumulated buffer contents.
 */
static inline FILE *open_memstream(char **ptr, size_t *sizeloc)
{
	FILE *f = tmpfile();

	if (ptr)
		*ptr = NULL;
	if (sizeloc)
		*sizeloc = 0;
	return f;
}

/*
 * close_memstream - close a stream opened by open_memstream and retrieve
 * the buffer contents. The caller must free *ptr when done.
 */
static inline int close_memstream(FILE *stream, char **ptr, size_t *sizeloc)
{
	long size;
	char *buf;

	if (!stream || !ptr || !sizeloc)
		return -1;

	fflush(stream);
	fseek(stream, 0, SEEK_END);
	size = ftell(stream);

	if (size > 0) {
		buf = (char *)malloc(size + 1);
		if (buf) {
			fseek(stream, 0, SEEK_SET);
			fread(buf, 1, size, stream);
			buf[size] = '\0';
			*ptr = buf;
			*sizeloc = (size_t)size;
		}
	}

	return fclose(stream);
}

#else

/*
 * On POSIX systems, open_memstream updates ptr/sizeloc on fclose,
 * so close_memstream just calls fclose.
 */
static inline int close_memstream(FILE *stream, char **ptr, size_t *sizeloc)
{
	return fclose(stream);
}

#endif
