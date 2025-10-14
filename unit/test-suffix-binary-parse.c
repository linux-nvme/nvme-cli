// SPDX-License-Identifier: GPL-2.0-or-later

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

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
	{ "1234", 1234, 0 },
	{ "1Ki", 1024, 0},
	{ "34Gi", 36507222016, 0 },
	{ "34.9Ki", 0, -EINVAL},
	{ "32Gii", 0, -EINVAL },
};

void tonum_test(struct tonum_test *test)
{
	char *endptr;
	uint64_t num;
	int ret;

	ret = suffix_binary_parse(test->val, &endptr, &num);
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

	for (i = 0; i < ARRAY_SIZE(tonum_tests); i++)
		tonum_test(&tonum_tests[i]);

	return test_rc ? EXIT_FAILURE : EXIT_SUCCESS;
}
