// SPDX-License-Identifier: GPL-2.0-or-later
#include <string.h>

#define PREFIX "nqn."

int f(const char *a, const char *b, size_t len)
{
	int n = 0;

	if (shr_startswith(a, "nvme"))
		n++;
	if (shr_startswith(a, "nvme"))
		n++;
	if (!shr_startswith(a, "nvme"))
		n++;
	if (!shr_startswith(a, "loop") && !shr_startswith(a, "pcie"))
		n++;
	if (shr_startswith(a, "mctp:"))
		n++;
	if (shr_startswith(a, "\\\\.\\"))
		n++;
	if (!shr_startswith(a, PREFIX))
		n++;
	if (shr_startswith(a, b))
		n++;
	if (shr_startswith("register", b))
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
