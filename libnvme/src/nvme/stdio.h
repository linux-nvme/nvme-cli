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
 * Authors: Brandon Capener <bcapener@micron.com>
 *          Brandon Busacker <bbusacker@micron.com>
*/

#pragma once

#include <stdio.h>

#if defined(_WIN32) || defined(_WIN64)

#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

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

#endif
