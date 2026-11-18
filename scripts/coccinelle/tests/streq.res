// SPDX-License-Identifier: GPL-2.0-or-later
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

int cmp(const void *a, const void *b);

bool f(const char *a, const char *b, int n)
{
	bool eq;

	if (streq(a, "x"))
		n++;
	if (streq(a, b))
		n++;
	if (!streq(a, b))
		n++;
	if (!streq(a, b))
		n++;
	while (n && !streq(a, b))
		n--;
	if (n > 2 || streq(b, "y"))
		return true;
	eq = streq(a, b);
	n = !streq(a, b) ? 1 : 2;
	/* Not changed: the order matters */
	if (strcmp(a, b) < 0)
		n++;
	n = strcmp(a, b);
	return eq && n;
}

int cmp(const void *a, const void *b)
{
	return strcmp(*(const char **)a, *(const char **)b);
}
