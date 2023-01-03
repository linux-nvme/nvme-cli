// SPDX-License-Identifier: GPL-2.0-or-later

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "../util/suffix.h"
#include "../util/types.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))

static int test_rc;

static void check_num(const char *val, int lbas, __u64 exp, __u64 num)
{
	if (exp == num)
		return;

	printf("ERROR: printing {%s} (lbas %d), got '%llu', expected '%llu'\n",
	       val, lbas, (unsigned long long)num, (unsigned long long)exp);

	test_rc = 1;
}

struct tonum_test {
	const char *val;
	int lbas;
	const __u64 exp;
};

static struct tonum_test tonum_tests[] = {
	{ "11995709440", 512, 11995709440 },
	{ "1199570940", 512, 1199570940 },
	{ "6.14T", 512, 11992187500 },
	{ "6.14T", 520, 11807692307 },
	{ "6.14T", 4096, 1499023437 },
	{ "6.14", 512, 0 },
	{ "6.14#", 512, 0 },
};

void tonum_test(struct tonum_test *test)
{
	__u64 num;
	bool suffixed;

	num = suffix_si_parse(test->val, &suffixed);

	if (suffixed)
		num /= test->lbas;

	check_num(test->val, test->lbas, test->exp, num);
}

int main(void)
{
	unsigned int i;

	test_rc = 0;

	for (i = 0; i < ARRAY_SIZE(tonum_tests); i++)
		tonum_test(&tonum_tests[i]);

	return test_rc ? EXIT_FAILURE : EXIT_SUCCESS;
}
