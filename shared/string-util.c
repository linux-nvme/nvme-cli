// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "string-util.h"

char *shr_escape(const char *s)
{
	const unsigned char *p;
	size_t n = 1;
	char *e, *q;

	for (p = (const unsigned char *)s; *p; p++)
		n += (*p < 0x20 || *p == 0x7f) ? 4 : 1;

	e = malloc(n);
	if (!e)
		return NULL;

	for (p = (const unsigned char *)s, q = e; *p; p++) {
		if (*p < 0x20 || *p == 0x7f)
			q += snprintf(q, 5, "\\x%02x", *p);
		else
			*q++ = *p;
	}
	*q = '\0';

	return e;
}

ssize_t shr_strscpy(char *dst, const char *src, size_t size)
{
	size_t len;

	if (!size)
		return -E2BIG;

	len = strnlen(src, size);
	if (len == size) {
		memcpy(dst, src, size - 1);
		dst[size - 1] = '\0';
		return -E2BIG;
	}
	memcpy(dst, src, len + 1);

	return len;
}

ssize_t shr_strscat(char *dst, const char *src, size_t size)
{
	size_t len = strnlen(dst, size);
	ssize_t n;

	/* no terminated string in @dst to append to */
	if (len == size)
		return -E2BIG;

	n = shr_strscpy(dst + len, src, size - len);

	return n < 0 ? n : (ssize_t)(len + n);
}

int shr_snprintf_append(char *buf, size_t size, size_t *len,
			const char *fmt, ...)
{
	va_list ap;
	int n;

	if (!size || *len >= size - 1)
		return -E2BIG;

	va_start(ap, fmt);
	n = vsnprintf(buf + *len, size - *len, fmt, ap);
	va_end(ap);

	if (n < 0)
		return -EINVAL;
	if ((size_t)n >= size - *len) {
		*len = size - 1;
		return -E2BIG;
	}
	*len += n;

	return 0;
}
