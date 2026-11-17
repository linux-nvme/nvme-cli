// SPDX-License-Identifier: GPL-2.0-or-later
#include <string.h>

#define PREFIX "nqn."

int f(const char *a, const char *b, size_t len)
{
	int n = 0;

	if (!strncmp(a, "nvme", 4))
		n++;
	if (strncmp(a, "nvme", 4) == 0)
		n++;
	if (strncmp(a, "nvme", 4) != 0)
		n++;
	if (strncmp(a, "loop", 4) && strncmp(a, "pcie", 4))
		n++;
	if (!strncmp(a, "mctp:", strlen("mctp:")))
		n++;
	if (!strncmp(a, "\\\\.\\", 4))
		n++;
	if (strncmp(a, PREFIX, strlen(PREFIX)))
		n++;
	if (!strncmp(a, b, strlen(b)))
		n++;
	if (strstarts("register", b))
		n++;
	/* Not changed: another length, a variable length */
	if (!strncmp(a, "nvme", 3))
		n++;
	if (!strncmp(a, "nvme", 5))
		n++;
	if (!strncmp(a, b, len))
		n++;
	if (!strncmp(a, "nvme", len))
		n++;
	/* Not changed: ordering */
	if (strncmp(a, "nvme", 4) < 0)
		n++;
	n += strncmp(a, "nvme", 4);

	return n + strncmp(a, b, strlen(b));
}
