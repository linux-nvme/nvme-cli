// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 */

#include <stdio.h>

#include "progress-util.h"

void shr_spinner(const char *label, float percent, FILE *stream)
{
	static const char dash[51] = {[0 ... 49] = '=', '\0'};
	static const char space[51] = {[0 ... 49] = ' ', '\0'};
	static const char spin[] = {'-', '\\', '|', '/' };
	static int progress;
	static int i;
	const char *dn = label ? label : "";

	if (percent < 0)
		percent = 0;
	else if (percent > 1)
		percent = 1;

	progress = (int)(percent * 100.0);
	if (progress < 2)
		fprintf(stream, "\r%s [%c%.*s] %3d%%", dn,
			spin[i % 4], 49,
			space, progress);
	else if (progress < 100)
		fprintf(stream, "\r%s [%.*s%c%.*s] %3d%%", dn,
			progress / 2 - 1, dash,
			spin[i % 4], 50 - progress / 2,
			space, progress);
	else
		fprintf(stream, "\r%s [%.*s] %3d%%\n", dn,
			50, dash, 100);
	i++;

	fflush(stream);
}
