// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 */
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include <shared/time-util.h>

static bool check_str(const char *name, const char *got, const char *want)
{
	bool eq = got && !strcmp(got, want);

	if (eq) {
		printf(" - %s [PASS]\n", name);
		return true;
	}

	printf(" - %s: got \"%s\", want \"%s\" [FAIL]\n", name, got ? got : "(null)", want);
	return false;
}

static bool check_ull(const char *name, unsigned long long got, unsigned long long want)
{
	if (got == want) {
		printf(" - %s [PASS]\n", name);
		return true;
	}

	printf(" - %s: got %llu, want %llu [FAIL]\n", name, got, want);
	return false;
}

static bool test_format_ts(void)
{
	char buf[64];
	bool pass = true;
	int ret;

	printf("test_format_ts:\n");

	/* 2024-01-02T03:24:05.678Z, in epoch milliseconds */
	ret = shr_format_ts(1704165845678LL, buf);
	pass &= check_str("return value", ret == 0 ? "0" : "nonzero", "0");
	pass &= check_str("formatted timestamp", buf, "2024-01-02D|03:24:05:678");

	ret = shr_format_ts(0, buf);
	pass &= check_str("return value for epoch", ret == 0 ? "0" : "nonzero", "0");
	pass &= check_str("epoch formats to zero time", buf, "1970-01-01D|00:00:00:000");

	return pass;
}

static bool test_elapsed_utime(void)
{
	struct timeval start = { .tv_sec = 10, .tv_usec = 500000 };
	struct timeval end = { .tv_sec = 12, .tv_usec = 250000 };
	bool pass = true;

	printf("test_elapsed_utime:\n");

	pass &= check_ull("elapsed time spanning a carry from usec into sec",
			   shr_elapsed_utime(start, end), 1750000ULL);
	pass &= check_ull("elapsed time of identical timestamps is zero",
			   shr_elapsed_utime(start, start), 0ULL);

	return pass;
}


static bool check_time(const char *str, uint64_t default_unit, uint64_t want)
{
	uint64_t got = 0;
	int ret;

	ret = shr_parse_time(str, &got, default_unit);
	if (ret == 0 && got == want) {
		printf(" - \"%s\" [PASS]\n", str);
		return true;
	}

	printf(" - \"%s\": ret=%d value=%llu, want ret=0 value=%llu [FAIL]\n",
	       str, ret, (unsigned long long)got, (unsigned long long)want);
	return false;
}

static bool check_time_err(const char *str, int want)
{
	uint64_t got = 0;
	int ret;

	ret = shr_parse_time(str, &got, SHR_USEC_PER_SEC);
	if (ret == want) {
		printf(" - \"%s\" rejected [PASS]\n", str);
		return true;
	}

	printf(" - \"%s\": got ret=%d, want ret=%d [FAIL]\n", str, ret, want);
	return false;
}

static bool test_parse_time_units(void)
{
	bool pass = true;

	printf("test_parse_time_units:\n");

	/*
	 * Every suffix in the table, so a future edit that drops one is
	 * caught here rather than by a user whose config stops parsing.
	 */
	pass &= check_time("1usec", SHR_USEC_PER_SEC, 1);
	pass &= check_time("1us", SHR_USEC_PER_SEC, 1);
	pass &= check_time("1μs", SHR_USEC_PER_SEC, 1);
	pass &= check_time("1µs", SHR_USEC_PER_SEC, 1);
	pass &= check_time("1msec", SHR_USEC_PER_SEC, SHR_USEC_PER_MSEC);
	pass &= check_time("500ms", SHR_USEC_PER_SEC, 500 * SHR_USEC_PER_MSEC);
	pass &= check_time("5s", SHR_USEC_PER_SEC, 5 * SHR_USEC_PER_SEC);
	pass &= check_time("5sec", SHR_USEC_PER_SEC, 5 * SHR_USEC_PER_SEC);
	pass &= check_time("5second", SHR_USEC_PER_SEC, 5 * SHR_USEC_PER_SEC);
	pass &= check_time("5seconds", SHR_USEC_PER_SEC, 5 * SHR_USEC_PER_SEC);
	pass &= check_time("1min", SHR_USEC_PER_SEC, SHR_USEC_PER_MINUTE);
	pass &= check_time("1minute", SHR_USEC_PER_SEC, SHR_USEC_PER_MINUTE);
	pass &= check_time("1minutes", SHR_USEC_PER_SEC, SHR_USEC_PER_MINUTE);
	pass &= check_time("1hr", SHR_USEC_PER_SEC, SHR_USEC_PER_HOUR);
	pass &= check_time("1hour", SHR_USEC_PER_SEC, SHR_USEC_PER_HOUR);
	pass &= check_time("1hours", SHR_USEC_PER_SEC, SHR_USEC_PER_HOUR);
	pass &= check_time("1d", SHR_USEC_PER_SEC, SHR_USEC_PER_DAY);
	pass &= check_time("1day", SHR_USEC_PER_SEC, SHR_USEC_PER_DAY);
	pass &= check_time("1days", SHR_USEC_PER_SEC, SHR_USEC_PER_DAY);
	pass &= check_time("1w", SHR_USEC_PER_SEC, SHR_USEC_PER_WEEK);
	pass &= check_time("1week", SHR_USEC_PER_SEC, SHR_USEC_PER_WEEK);
	pass &= check_time("1weeks", SHR_USEC_PER_SEC, SHR_USEC_PER_WEEK);
	pass &= check_time("1month", SHR_USEC_PER_SEC, SHR_USEC_PER_MONTH);
	pass &= check_time("1months", SHR_USEC_PER_SEC, SHR_USEC_PER_MONTH);
	pass &= check_time("1y", SHR_USEC_PER_SEC, SHR_USEC_PER_YEAR);
	pass &= check_time("1year", SHR_USEC_PER_SEC, SHR_USEC_PER_YEAR);
	pass &= check_time("1years", SHR_USEC_PER_SEC, SHR_USEC_PER_YEAR);

	/* "M" is months and "m" is minutes: case matters. */
	pass &= check_time("1M", SHR_USEC_PER_SEC, SHR_USEC_PER_MONTH);
	pass &= check_time("1m", SHR_USEC_PER_SEC, SHR_USEC_PER_MINUTE);

	return pass;
}

static bool test_parse_time(void)
{
	bool pass = true;

	printf("test_parse_time:\n");

	pass &= check_time("infinity", SHR_USEC_PER_SEC, SHR_USEC_INFINITY);
	pass &= check_time("  infinity  ", SHR_USEC_PER_SEC, SHR_USEC_INFINITY);
	pass &= check_time("0", SHR_USEC_PER_SEC, 0);

	/* A bare number takes default_unit, so "72" is not 72 hours. */
	pass &= check_time("72", SHR_USEC_PER_SEC, 72 * SHR_USEC_PER_SEC);
	pass &= check_time("72", SHR_USEC_PER_HOUR, 72 * SHR_USEC_PER_HOUR);

	/* Terms are summed, with or without separating whitespace. */
	pass &= check_time("72hours", SHR_USEC_PER_SEC, 72 * SHR_USEC_PER_HOUR);
	pass &= check_time("72 h", SHR_USEC_PER_SEC, 72 * SHR_USEC_PER_HOUR);
	pass &= check_time("3 days 5 hours", SHR_USEC_PER_SEC,
			   3 * SHR_USEC_PER_DAY + 5 * SHR_USEC_PER_HOUR);
	pass &= check_time("3d5h", SHR_USEC_PER_SEC,
			   3 * SHR_USEC_PER_DAY + 5 * SHR_USEC_PER_HOUR);
	pass &= check_time("1h30m", SHR_USEC_PER_SEC,
			   SHR_USEC_PER_HOUR + 30 * SHR_USEC_PER_MINUTE);
	pass &= check_time("  2 d  ", SHR_USEC_PER_SEC, 2 * SHR_USEC_PER_DAY);

	/* Fractions. */
	pass &= check_time("1.5h", SHR_USEC_PER_SEC,
			   SHR_USEC_PER_HOUR + 30 * SHR_USEC_PER_MINUTE);
	pass &= check_time("0.5s", SHR_USEC_PER_SEC, 500 * SHR_USEC_PER_MSEC);
	pass &= check_time("12.34 .56", SHR_USEC_PER_SEC, 12900000);

	return pass;
}

static bool test_parse_time_rejects(void)
{
	bool pass = true;

	printf("test_parse_time_rejects:\n");

	pass &= check_time_err("", -EINVAL);
	pass &= check_time_err("   ", -EINVAL);
	pass &= check_time_err("hours", -EINVAL);
	pass &= check_time_err("1hoge", -EINVAL);
	pass &= check_time_err("12.34.56", -EINVAL);
	pass &= check_time_err("3.sec", -EINVAL);
	pass &= check_time_err("infinityx", -EINVAL);

	/* Negatives are rejected, not clamped: say "infinity" instead. */
	pass &= check_time_err("-1", -ERANGE);
	pass &= check_time_err("-0", -ERANGE);
	pass &= check_time_err("1h -1m", -ERANGE);

	/* Overflow on the multiply, and on the sum of two valid terms. */
	pass &= check_time_err("100000000000000y", -ERANGE);
	pass &= check_time_err("300000y 300000y", -ERANGE);

	/*
	 * A colon-separated span is pytimeparse syntax, not systemd's. It
	 * must stay rejected so nvme-stas and nvme-discoverd agree.
	 */
	pass &= check_time_err("1:30", -EINVAL);

	return pass;
}

int main(void)
{
	bool pass = true;

	pass &= test_format_ts();
	pass &= test_elapsed_utime();
	pass &= test_parse_time_units();
	pass &= test_parse_time();
	pass &= test_parse_time_rejects();

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
