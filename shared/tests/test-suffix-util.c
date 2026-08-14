// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

#include <errno.h>
#include <locale.h>
#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <shared/suffix-util.h>

static bool check_ret(const char *name, int got, int want)
{
	if (got == want) {
		printf(" - %s [PASS]\n", name);
		return true;
	}

	printf(" - %s: got %d, want %d [FAIL]\n", name, got, want);
	return false;
}

static bool check_u64(const char *name, uint64_t got, uint64_t want)
{
	if (got == want) {
		printf(" - %s [PASS]\n", name);
		return true;
	}

	printf(" - %s: got %llu, want %llu [FAIL]\n",
	       name, (unsigned long long)got, (unsigned long long)want);
	return false;
}

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

struct parse_test {
	const char *val;
	uint64_t exp;
	int ret;
};

static bool test_suffix_si_parse(void)
{
	static const struct parse_test tests[] = {
		{ "11995709440", 11995709440ULL, 0 },
		{ "1199570940", 1199570940ULL, 0 },
		{ "234.567M", 234567000ULL, 0 },
		{ "1.2k", 1200ULL, 0 },
		{ "6.14T", 6140000000000ULL, 0 },
		{ "123.4567k", 123456ULL, 0 },
		{ "12345.6789101112M", 12345678910ULL, 0 },
		{ "6.14", 6ULL, 0 },
		{ "6.14#", 0, -EINVAL },
		{ "2,33", 0, -EINVAL },
		{ "3..3", 0, -EINVAL },
		{ "123.12MM", 0, -EINVAL },
		{ "800G", 800000000000ULL, 0 },
		{ "800GG", 0, -EINVAL },
		{ "800G800", 0, -EINVAL },
		{ "800.0G", 800000000000ULL, 0 },
		{ "800.G", 0, -EINVAL },
		{ "800.", 0, -EINVAL },
	};
	bool pass = true;
	unsigned int i;

	printf("test_suffix_si_parse:\n");

	setlocale(LC_NUMERIC, "C");

	for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
		char *endptr;
		uint64_t num = 0;
		int ret = shr_suffix_si_parse(tests[i].val, &endptr, &num);
		char desc[64];

		snprintf(desc, sizeof(desc), "\"%s\"", tests[i].val);
		pass &= check_ret(desc, ret, tests[i].ret);
		if (ret == 0 && tests[i].ret == 0)
			pass &= check_u64(desc, num, tests[i].exp);
	}

	return pass;
}

static bool test_suffix_binary_parse(void)
{
	static const struct parse_test tests[] = {
		{ "1234", 1234ULL, 0 },
		{ "1Ki", 1024ULL, 0 },
		{ "34Gi", 36507222016ULL, 0 },
		{ "34.9Ki", 0, -EINVAL },
		{ "32Gii", 0, -EINVAL },
	};
	bool pass = true;
	unsigned int i;

	printf("test_suffix_binary_parse:\n");

	for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
		char *endptr;
		uint64_t num = 0;
		int ret = shr_suffix_binary_parse(tests[i].val, &endptr, &num);
		char desc[64];

		snprintf(desc, sizeof(desc), "\"%s\"", tests[i].val);
		pass &= check_ret(desc, ret, tests[i].ret);
		if (ret == 0 && tests[i].ret == 0)
			pass &= check_u64(desc, num, tests[i].exp);
	}

	return pass;
}

static bool test_suffix_si_get(void)
{
	bool pass = true;
	double val;

	printf("test_suffix_si_get:\n");

	val = 1500.0;
	pass &= check_str("1500 -> k suffix", shr_suffix_si_get(&val), "k");
	pass &= check_ret("1500 -> value scaled", (int)(val * 1000), 1500);

	val = 42.0;
	pass &= check_str("below 1k has no suffix", shr_suffix_si_get(&val), "");

	return pass;
}

static bool test_suffix_si_get_ld(void)
{
	bool pass = true;
	long double val = 5000000.0L;

	printf("test_suffix_si_get_ld:\n");

	pass &= check_str("5000000 -> M suffix", shr_suffix_si_get_ld(&val), "M");
	pass &= check_ret("5000000 -> value scaled", (int)val, 5);

	return pass;
}

static bool test_suffix_binary_get(void)
{
	bool pass = true;
	long long val = 2048;

	printf("test_suffix_binary_get:\n");

	pass &= check_str("2048 -> Ki suffix", shr_suffix_binary_get(&val), "Ki");
	pass &= check_ret("2048 -> value scaled", (int)val, 2);

	val = 42;
	pass &= check_str("below 1Ki has no suffix", shr_suffix_binary_get(&val), "");

	return pass;
}

static bool test_suffix_dbinary_get(void)
{
	bool pass = true;
	double val = 3.0 * (1LL << 20);

	printf("test_suffix_dbinary_get:\n");

	pass &= check_str("3 Mi -> Mi suffix", shr_suffix_dbinary_get(&val), "Mi");
	pass &= check_ret("3 Mi -> value scaled", (int)val, 3);

	return pass;
}

int main(void)
{
	bool pass = true;

	pass &= test_suffix_si_parse();
	pass &= test_suffix_binary_parse();
	pass &= test_suffix_si_get();
	pass &= test_suffix_si_get_ld();
	pass &= test_suffix_binary_get();
	pass &= test_suffix_dbinary_get();

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
