// SPDX-License-Identifier: GPL-2.0-or-later
#include <string.h>

void f(char *d, const char *s, size_t n)
{
	strncpy(d, s, n);
	memcpy(d, s, n);
}
