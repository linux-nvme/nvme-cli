// SPDX-License-Identifier: GPL-2.0-or-later
#include <string.h>

void f(const char *s)
{
	char a[16], b[16];
	char *c = b;

	strncpy(a, s, sizeof(a) - 1);
	a[sizeof(a) - 1] = '\0';

	strncpy(c, s, 16 - 1);
	c[16 - 1] = 0;

	/* Not changed: another buffer is terminated. */
	strncpy(a, s, sizeof(a) - 1);
	b[sizeof(a) - 1] = '\0';

	/* Not changed: the copy is not terminated. */
	strncpy(b, s, sizeof(b));
}
