// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 */

#include <stdio.h>

#include "time-util.h"

int shr_format_ts(time_t time_ms, char *ts_buf)
{
	struct tm  time_info;
	time_t     time_s, ms;
	char       buf[80];

	time_s = time_ms / 1000;
	ms = time_ms % 1000;

	gmtime_r(&time_s, &time_info);

	strftime(buf, sizeof(buf), "%Y-%m-%dD|%H:%M:%S", &time_info);
	sprintf(ts_buf, "%s:%03llu", buf, (unsigned long long)ms);

	return 0;
}

unsigned long long shr_elapsed_utime(struct timeval start_time,
				      struct timeval end_time)
{
	return (end_time.tv_sec - start_time.tv_sec) * 1000000 +
		(end_time.tv_usec - start_time.tv_usec);
}
