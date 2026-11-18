// SPDX-License-Identifier: GPL-2.0-or-later
#include <stdio.h>
#include <string.h>

void f(char *buf, size_t len, const unsigned char *a, int n)
{
	char tmp[3], *p = buf;
	int i;

	for (i = 0; i < n; i++)
		p += sprintf(p, "%02x", a[i]);
	for (i = 0; i < n; i++)
		sprintf(&buf[i * 2], "%02X", a[n - 1 - i]);
	for (i = 0; i < n; i++) {
		snprintf(tmp, sizeof(tmp), "%02x", a[i]);
		strcat(buf, tmp);
	}
	/* Not reported: one byte, not in a loop */
	sprintf(buf, "%02x", a[0]);
	/* Not reported: another format */
	for (i = 0; i < n; i++)
		printf("%02x", a[i]);
	for (i = 0; i < n; i++)
		sprintf(buf + 3 * i, "%02x ", a[i]);
}
