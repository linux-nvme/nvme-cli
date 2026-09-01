// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ccan/array_size/array_size.h>

#include "string-util.h"
#include "time-util.h"

#define WHITESPACE " \t\n\r"
#define DIGITS "0123456789"

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

/*
 * Copied from systemd's src/basic/time-util.c at commit 21de611f695b
 * Same LGPL-2.1-or-later license as nvme-cli; no copyright notice in systemd
 * A time span in systemd means the same here.
 *
 * 2026-09-01: Changes compared to systemd. Renamed to shr_parse_time(),
 * uint64_t for usec_t, shr_startswith()/strspn() for systemd's helpers.
 * Only ERANGE counts as a strtoll() failure, for musl.
 */
static const char *extract_multiplier(const char *p, uint64_t *ret)
{
	static const struct {
		const char *suffix;
		uint64_t usec;
	} table[] = {
		{ "seconds", SHR_USEC_PER_SEC    },
		{ "second",  SHR_USEC_PER_SEC    },
		{ "sec",     SHR_USEC_PER_SEC    },
		{ "s",       SHR_USEC_PER_SEC    },
		{ "minutes", SHR_USEC_PER_MINUTE },
		{ "minute",  SHR_USEC_PER_MINUTE },
		{ "min",     SHR_USEC_PER_MINUTE },
		{ "months",  SHR_USEC_PER_MONTH  },
		{ "month",   SHR_USEC_PER_MONTH  },
		{ "M",       SHR_USEC_PER_MONTH  },
		{ "msec",    SHR_USEC_PER_MSEC   },
		{ "ms",      SHR_USEC_PER_MSEC   },
		{ "m",       SHR_USEC_PER_MINUTE },
		{ "hours",   SHR_USEC_PER_HOUR   },
		{ "hour",    SHR_USEC_PER_HOUR   },
		{ "hr",      SHR_USEC_PER_HOUR   },
		{ "h",       SHR_USEC_PER_HOUR   },
		{ "days",    SHR_USEC_PER_DAY    },
		{ "day",     SHR_USEC_PER_DAY    },
		{ "d",       SHR_USEC_PER_DAY    },
		{ "weeks",   SHR_USEC_PER_WEEK   },
		{ "week",    SHR_USEC_PER_WEEK   },
		{ "w",       SHR_USEC_PER_WEEK   },
		{ "years",   SHR_USEC_PER_YEAR   },
		{ "year",    SHR_USEC_PER_YEAR   },
		{ "y",       SHR_USEC_PER_YEAR   },
		{ "usec",    1                   },
		{ "us",      1                   },
		{ "μs",     1                   }, // U+03BC GREEK SMALL MU
		{ "µs",     1                   }, // U+00B5 MICRO SIGN
	};
	size_t i;

	for (i = 0; i < ARRAY_SIZE(table); i++) {
		const char *e = shr_startswith(p, table[i].suffix);

		if (e) {
			*ret = table[i].usec;
			return e;
		}
	}

	return p;
}

int shr_parse_time(const char *str, uint64_t *out, uint64_t default_unit)
{
	const char *p, *s;
	uint64_t usec = 0;
	bool something = false;

	if (!str || !default_unit)
		return -EINVAL;

	p = str + strspn(str, WHITESPACE);
	s = shr_startswith(p, "infinity");
	if (s) {
		if (s[strspn(s, WHITESPACE)] != '\0')
			return -EINVAL;

		if (out)
			*out = SHR_USEC_INFINITY;

		return 0;
	}

	for (;;) {
		uint64_t multiplier = default_unit, k;
		long long l;
		char *e;

		p += strspn(p, WHITESPACE);
		if (*p == '\0') {
			if (!something)
				return -EINVAL;
			break;
		}

		if (*p == '-') // reject "-0" too
			return -ERANGE;

		errno = 0;
		l = strtoll(p, &e, 10);
		// musl sets EINVAL when no digits are converted, glibc does
		// not; that case is rejected below where it is not allowed
		if (errno == ERANGE)
			return -ERANGE;
		if (l < 0)
			return -ERANGE;

		if (*e == '.') {
			p = e + 1;
			p += strspn(p, DIGITS);
		} else {
			if (e == p)
				return -EINVAL;
			p = e;
		}

		s = extract_multiplier(p + strspn(p, WHITESPACE), &multiplier);
		// Reject "12.34.56", but accept "12.34 .56" and "12.34s.56"
		if (s == p && *s != '\0')
			return -EINVAL;

		p = s;

		if ((uint64_t)l >= SHR_USEC_INFINITY / multiplier)
			return -ERANGE;

		k = (uint64_t)l * multiplier;
		if (k >= SHR_USEC_INFINITY - usec)
			return -ERANGE;

		usec += k;
		something = true;

		if (*e == '.') {
			uint64_t m = multiplier / 10;
			const char *b;

			for (b = e + 1; *b >= '0' && *b <= '9'; b++, m /= 10) {
				k = (uint64_t)(*b - '0') * m;
				if (k >= SHR_USEC_INFINITY - usec)
					return -ERANGE;

				usec += k;
			}

			// Reject "0.-0", "3.+1", "3. 1", "3.sec" and "3.hoge"
			if (b == e + 1)
				return -EINVAL;
		}
	}

	if (out)
		*out = usec;

	return 0;
}
