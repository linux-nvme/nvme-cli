// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2025 Micron Technology, Inc.
 *
 * Windows platform-specific function implementations.
 * Provides POSIX-compatible functions for Windows.
 */

#ifdef _WIN32

#include "platform/includes.h"

/* getline implementation for Windows */
ssize_t getline(char **lineptr, size_t *n, FILE *stream) {
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
	if (c == EOF) {
		return -1;
	}

	if (bufptr == NULL) {
		bufptr = malloc(128);
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
			bufptr = realloc(bufptr, size);
			if (bufptr == NULL) {
				errno = ENOMEM;
				return -1;
			}
			p = bufptr + pos;
		}
		*p++ = c;
		if (c == '\n') {
			break;
		}
		c = fgetc(stream);
	}

	*p = '\0';
	*lineptr = bufptr;
	*n = size;

	return p - bufptr;
}

/* strsep implementation for Windows */
char *strsep(char **stringp, const char *delim) {
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

/* reallocarray implementation for Windows */
void *reallocarray(void *ptr, size_t nmemb, size_t size)
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

/* readlink stub - Windows doesn't have symbolic links in the same way */
int readlink(const char *path, char *buf, size_t bufsiz) {
	(void)path; (void)buf; (void)bufsiz;
	errno = EINVAL;
	return -1;
}

/* open_memstream stub - returns a temporary file instead */
FILE *open_memstream(char **ptr, size_t *sizeloc) {
	FILE *f = tmpfile();
	if (ptr) *ptr = NULL;
	if (sizeloc) *sizeloc = 0;
	return f;
}

#endif /* _WIN32 */
