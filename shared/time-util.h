/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of nvme-cli.
 */
#pragma once

#include <stdint.h>
#include <sys/time.h>
#include <time.h>

#define SHR_USEC_PER_MSEC	UINT64_C(1000)
#define SHR_USEC_PER_SEC	UINT64_C(1000000)
#define SHR_USEC_PER_MINUTE	(UINT64_C(60) * SHR_USEC_PER_SEC)
#define SHR_USEC_PER_HOUR	(UINT64_C(60) * SHR_USEC_PER_MINUTE)
#define SHR_USEC_PER_DAY	(UINT64_C(24) * SHR_USEC_PER_HOUR)
#define SHR_USEC_PER_WEEK	(UINT64_C(7) * SHR_USEC_PER_DAY)
#define SHR_USEC_PER_MONTH	(UINT64_C(2629800) * SHR_USEC_PER_SEC)
#define SHR_USEC_PER_YEAR	(UINT64_C(31557600) * SHR_USEC_PER_SEC)

/* "infinity", and the value no finite span may reach. */
#define SHR_USEC_INFINITY	UINT64_MAX

/*
 * Format time_ms (milliseconds since the epoch) as "Y-M-D|H:M:S:MS" into
 * ts_buf, which must be at least 32 bytes. Return: 0.
 */
int shr_format_ts(time_t time_ms, char *ts_buf);

unsigned long long shr_elapsed_utime(struct timeval start_time,
				      struct timeval end_time);

/*
 * Parse a time span using the systemd parse_time() convention: one or more
 * "<number><unit>" terms that are summed ("3 days 5 hours"), a fractional
 * number ("1.5h"), or the keyword "infinity" (SHR_USEC_INFINITY). A term
 * with no unit takes default_unit, which must be non-zero. Negative values
 * are rejected. Recognized units are seconds/second/sec/s,
 * minutes/minute/min/m, hours/hour/hr/h, days/day/d, weeks/week/w,
 * months/month/M, years/year/y, msec/ms and usec/us (also spelled with
 * either micro sign). Note "M" is months and "m" is minutes.
 * Return: 0 on success (*out set, in microseconds), -EINVAL on a syntax
 * error, -ERANGE on a negative value or on overflow.
 */
int shr_parse_time(const char *str, uint64_t *out, uint64_t default_unit);
