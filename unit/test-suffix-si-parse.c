// SPDX-License-Identifier: GPL-2.0-or-later

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <locale.h>

#include "../util/suffix.h"
#include "../util/types.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))

static int test_rc;

static void check_num(const char *val, __u64 exp, __u64 num)
{
	if (exp == num)
		return;

	printf("ERROR: printing {%s},  got '%llu', expected '%llu'\n",
	       val, (unsigned long long)num, (unsigned long long)exp);

	test_rc = 1;
}

struct tonum_test {
	const char *val;
	const uint64_t exp;
	int ret;
};

static struct tonum_test tonum_tests[] = {
	{ "11995709440", 11995709440, 0 },
	{ "1199570940", 1199570940, 0},
	{ "234.567M", 234567000, 0 },
	{ "1.2k", 1200, 0 },
	{ "6.14T", 6140000000000, 0 },
	{ "123.4567k", 123456, 0 },
	{ "12345.6789101112M", 12345678910, 0},
	{ "6.14", 6, 0 },
	{ "6.14#", 0, -EINVAL },
	{ "2,33", 0, -EINVAL },
	{ "3..3", 0, -EINVAL },
	{ "123.12MM", 0, -EINVAL },
};

void tonum_test(struct tonum_test *test)
{
	char *endptr;
	uint64_t num;
	int ret;

	ret = suffix_si_parse(test->val, &endptr, &num);
	if (ret != test->ret) {
		printf("ERROR: converting {%s} failed\n", test->val);
		test_rc = 1;
		return;
	}
	if (ret)
		return;

	check_num(test->val, test->exp, num);
}

int main(void)
{
	unsigned int i;

	test_rc = 0;
	setlocale(LC_NUMERIC, "C");

	for (i = 0; i < ARRAY_SIZE(tonum_tests); i++)
		tonum_test(&tonum_tests[i]);

	return test_rc ? EXIT_FAILURE : EXIT_SUCCESS;
}
