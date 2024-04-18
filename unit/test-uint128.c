// SPDX-License-Identifier: GPL-2.0-or-later

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <locale.h>

#include "../util/types.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))

/* create a uint128_t from four uint32_ts. w0 is the most significant value,
 * w2 the least */
#define U128(w0, w1, w2, w3) { .words = { w0, w1, w2, w3 } }

static int test_rc;

static void check_str(nvme_uint128_t val, const char *exp, const char *res)
{
	if (!strcmp(res, exp))
		return;

	printf("ERROR: printing {%08x.%08x.%08x.%08x}, got '%s', expected '%s'\n",
	       val.words[3], val.words[2], val.words[1], val.words[0],
	       res, exp);

	test_rc = 1;
}

struct tostr_test {
	const char *locale;
	nvme_uint128_t val;
	const char *exp;
};

static struct tostr_test tostr_tests[] = {
	{ NULL, U128(0, 0, 0, 0),"0" },
	{ NULL, U128(0, 0, 0, 1), "1" },
	{ NULL, U128(0, 0, 0, 10), "10" },
	{ NULL, U128(4, 3, 2, 1), "316912650112397582603894390785" },
	{
		NULL,
		U128(0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff),
		"340282366920938463463374607431768211455"
	},
	{ "fr_FR.utf-8", U128(0, 0, 0, 1000), "1\u202f000" },
};

void tostr_test(struct tostr_test *test)
{
	char *str;

	if (!setlocale(LC_NUMERIC, test->locale))
		return;

	if (test->locale)
		str = uint128_t_to_l10n_string(test->val);
	else
		str = uint128_t_to_string(test->val);

	check_str(test->val, test->exp, str);
}

int main(void)
{
	unsigned int i;

	test_rc = 0;

	for (i = 0; i < ARRAY_SIZE(tostr_tests); i++)
		tostr_test(&tostr_tests[i]);

	return test_rc ? EXIT_FAILURE : EXIT_SUCCESS;
}
