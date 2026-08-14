// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2022 Jeremy Kerr
 * Copyright (c) 2023 Tokunori Ikegami
 *
 * Authors: Jeremy Kerr <jk@codeconstruct.com.au>
 *          Tokunori Ikegami <ikegami.t@gmail.com>
 *          Daniel Wagner <dwagner@suse.de>
 */

#include <locale.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <shared/uint128-util.h>

#define U128(w0, w1, w2, w3) { .words = { w0, w1, w2, w3 } }

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

static bool check_bool(const char *name, bool got, bool want)
{
	if (got == want) {
		printf(" - %s [PASS]\n", name);
		return true;
	}

	printf(" - %s: got %d, want %d [FAIL]\n", name, got, want);
	return false;
}

static bool test_uint128_from_le(void)
{
	bool pass = true;
	uint8_t le[16] = {
		0x01, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x00, 0x00,
		0x03, 0x00, 0x00, 0x00,
		0x04, 0x00, 0x00, 0x00,
	};
	shr_uint128_t val = le128_to_cpu(le);

	printf("test_uint128_from_le:\n");

	pass &= check_bool("word[0] (most significant)", val.words[0] == 4, true);
	pass &= check_bool("word[1]", val.words[1] == 3, true);
	pass &= check_bool("word[2]", val.words[2] == 2, true);
	pass &= check_bool("word[3] (least significant)", val.words[3] == 1, true);

	return pass;
}

static bool test_int128_to_double(void)
{
	bool pass = true;
	uint8_t le[16] = { 0 };

	le[0] = 42;
	printf("test_int128_to_double:\n");
	pass &= check_bool("42 -> 42.0", int128_to_double(le) == 42.0L, true);

	return pass;
}

static bool test_uint128_to_double(void)
{
	bool pass = true;
	shr_uint128_t val = U128(0, 0, 0, 42);

	printf("test_uint128_to_double:\n");
	pass &= check_bool("42 -> 42.0", uint128_t_to_double(val) == 42.0L, true);

	return pass;
}

struct tostr_test {
	const char *locale;
	shr_uint128_t val;
	const char *exp;
};

static struct tostr_test tostr_tests[] = {
	{ NULL, U128(0, 0, 0, 0), "0" },
	{ NULL, U128(0, 0, 0, 1), "1" },
	{ NULL, U128(0, 0, 0, 10), "10" },
	{ NULL, U128(4, 3, 2, 1), "316912650112397582603894390785" },
	{
		NULL,
		U128(0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff),
		"340282366920938463463374607431768211455"
	},
	{ "fr_FR.utf-8", U128(0, 0, 0, 1000), "1%s000" },
};

static bool test_uint128_to_string(void)
{
	bool pass = true;
	unsigned int i;

	printf("test_uint128_to_string:\n");

	for (i = 0; i < sizeof(tostr_tests) / sizeof(tostr_tests[0]); i++) {
		struct tostr_test *test = &tostr_tests[i];
		const char *exp = test->exp;
		char exp_buf[64];
		char *str;

		if (!setlocale(LC_NUMERIC, test->locale))
			continue;

		if (test->locale) {
			/* For locale tests, adapt to what the system provides.
			 * musl libc may not support thousands_sep for all locales. */
			struct lconv *lc = localeconv();
			const char *sep = lc->thousands_sep;

			if (!sep || !*sep) {
				fprintf(stderr,
					"WARNING: thousands_sep is empty for this system's %s locale! Skipping test...\n",
					test->locale);
				continue;
			}

			if (strstr(test->exp, "%s")) {
				snprintf(exp_buf, sizeof(exp_buf), test->exp, sep);
				exp = exp_buf;
			}
			str = uint128_t_to_l10n_string(test->val);
		} else {
			str = uint128_t_to_string(test->val);
		}

		pass &= check_str(test->locale ? test->locale : "default locale", str, exp);
	}

	setlocale(LC_NUMERIC, "C");

	return pass;
}

struct si_test {
	shr_uint128_t val;
	uint32_t bytes_per_unit;
	const char *exp;
};

static struct si_test si_tests[] = {
	{ U128(0, 0, 0, 0), 1, "0.00 B" },
	{ U128(0, 0, 0, 1), 1, "1.00 B" },
	{ U128(0, 0, 0, 10), 1, "10.00 B" },
	{ U128(4, 3, 2, 1), 1, "316.91 RB" },
	{ U128(0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff), 1, "340282366.92 QB" },
	{ U128(0, 0, 0, 0xae0dc2), 1000 * 512, "5.84 TB" },
	{ U128(0, 0, 0, 0xf9c546), 1000 * 512, "8.38 TB" },
	{ U128(0, 0, 0, 0x4c2aa594), 1000 * 512, "654.27 TB" },
	{ U128(0, 0, 0, 0x5b013de8), 1000 * 512, "781.73 TB" },
};

static bool test_uint128_to_si_string(void)
{
	bool pass = true;
	unsigned int i;

	printf("test_uint128_to_si_string:\n");

	for (i = 0; i < sizeof(si_tests) / sizeof(si_tests[0]); i++) {
		struct si_test *test = &si_tests[i];
		char *str = uint128_t_to_si_string(test->val, test->bytes_per_unit);

		pass &= check_str(test->exp, str, test->exp);
	}

	return pass;
}

int main(void)
{
	bool pass = true;

	pass &= test_uint128_from_le();
	pass &= test_int128_to_double();
	pass &= test_uint128_to_double();
	pass &= test_uint128_to_string();
	pass &= test_uint128_to_si_string();

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
