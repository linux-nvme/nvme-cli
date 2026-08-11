/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of nvme-cli.
 */
#pragma once

#include <sys/time.h>
#include <time.h>

/*
 * Format time_ms (milliseconds since the epoch) as "Y-M-D|H:M:S:MS" into
 * ts_buf, which must be at least 32 bytes. Return: 0.
 */
int shr_format_ts(time_t time_ms, char *ts_buf);

unsigned long long shr_elapsed_utime(struct timeval start_time,
				      struct timeval end_time);
