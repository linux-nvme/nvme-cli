// SPDX-License-Identifier: LGPL-2.1-or-later

#include "util.h"

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void hexdump(const uint8_t *buf, size_t len)
{
	size_t i = 0;

	if (!len)
		return;

	for (;;) {
		fprintf(stderr, "%02X", buf[i++]);
		if (i >= len)
			break;

		fputc(i % 16 > 0 ? ' ' : '\n', stderr);
	}
	fputc('\n', stderr);
}

void fail(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	fputc('\n', stderr);
	abort();
}

void cmp(const void *actual, const void *expected, size_t len, const char *msg)
{
	if (memcmp(actual, expected, len) == 0)
		return;

	fputs(msg, stderr);
	fputs("\nactual:\n", stderr);
	hexdump(actual, len);
	fputs("expected:\n", stderr);
	hexdump(expected, len);
	abort();
}

void arbitrary(void *buf_, size_t len)
{
	uint8_t *buf = buf_;

	while (len--)
		*(buf++) = rand();
}

size_t arbitrary_range(size_t max)
{
	size_t value;
	arbitrary(&value, sizeof(value));
	return value % max;
}
