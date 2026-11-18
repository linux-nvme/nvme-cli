// SPDX-License-Identifier: GPL-2.0-or-later
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

int cmp(const void *a, const void *b);

bool f(const char *a, const char *b, int n)
{
	bool eq;

	if (!strcmp(a, "x"))
		n++;
	if (strcmp(a, b) == 0)
		n++;
	if (strcmp(a, b))
		n++;
	if (strcmp(a, b) != 0)
		n++;
	while (n && strcmp(a, b))
		n--;
	if (n > 2 || !strcmp(b, "y"))
		return true;
	eq = !strcmp(a, b);
	n = strcmp(a, b) ? 1 : 2;
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
