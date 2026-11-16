// SPDX-License-Identifier: GPL-2.0-or-later
#include <string.h>

int f(const char *a, const char *b, const char *s)
{
	int n = 0;

	if (shr_streq0(a, "x"))
		n++;
	if (!shr_streq0(a, "x"))
		n++;
	if (s && !shr_streq0(a, "y"))
		n++;
	if (shr_streq0(a, "z"))
		n++;
	if (!shr_streq0(a, "z"))
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
