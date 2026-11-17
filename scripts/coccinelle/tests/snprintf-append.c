// SPDX-License-Identifier: GPL-2.0-or-later
#include <stdarg.h>
#include <stdio.h>

void f(char *buf, size_t len, const char *a, const char *fmt, va_list ap)
{
	char *p = buf;
	int n = 0;

	n += snprintf(buf + n, len - n, "%s", a);
	n += vsnprintf(buf + n, len - n, fmt, ap);
	p += snprintf(p, len - (p - buf), "%s", a);
	/* Not reported: a fixed size, a single call */
	p += snprintf(p, 5, "\\x%02x", *a);
	n = snprintf(buf, len, "%s", a);
}
