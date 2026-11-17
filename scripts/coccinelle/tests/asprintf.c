// SPDX-License-Identifier: GPL-2.0-or-later
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *f(const char *a, const char *b)
{
	size_t len = strlen(a) + strlen(b) + 2;
	char *p;
	int ret;

	p = malloc(len);
	if (!p)
		return NULL;
	snprintf(p, len, "%s/%s", a, b);
	free(p);

	p = malloc(len);
	if (!p)
		return NULL;
	ret = snprintf(p, len, "%s", a);
	if (ret < 0)
		return NULL;
	free(p);

	/* Not reported: another size, a string built piece by piece */
	p = malloc(len);
	if (!p)
		return NULL;
	snprintf(p, 5, "%s", a);
	free(p);

	p = malloc(len);
	if (!p)
		return NULL;
	ret = 0;
	ret += snprintf(p + ret, len - ret, "%s", a);

	return p;
}
