// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 */
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

int main(void)
{
	bool pass = true;

	pass &= test_format_ts();
	pass &= test_elapsed_utime();

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
