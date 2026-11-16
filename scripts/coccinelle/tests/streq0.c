// SPDX-License-Identifier: GPL-2.0-or-later
#include <string.h>

int f(const char *a, const char *b, const char *s)
{
	int n = 0;

	if (a && !strcmp(a, "x"))
		n++;
	if (!a || strcmp(a, "x"))
		n++;
	if (s && (!a || strcmp(a, "y")))
		n++;
	if (a && strcmp(a, "z") == 0)
		n++;
	if (!a || strcmp(a, "z") != 0)
		n++;
	/* Not changed: no '!', a variable operand, no guard, another guard */
	if (a && strcmp(a, "x"))
		n++;
	if (a && !strcmp(a, b))
		n++;
	if (!strcmp(a, "x"))
		n++;
	if (a && !strcmp(b, "x"))
		n++;

	return n;
}
