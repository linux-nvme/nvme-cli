// SPDX-License-Identifier: GPL-2.0-or-later

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "../util/types.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))

/* create a uint128_t from four uint32_ts. w0 is the most significant value,
 * w2 the least */
#define U128(w0, w1, w2, w3) { .words = { w0, w1, w2, w3 } }

static int test_rc;

static void check_str(nvme_uint128_t val, __u32 bytes_per_unit, const char *exp,
		      const char *res)
{
	if (!strcmp(res, exp))
		return;

	printf("ERROR: printing {%08x.%08x.%08x.%08x} (bytes per unit %u), got '%s', expected '%s'\n",
	       val.words[3], val.words[2], val.words[1], val.words[0],
	       bytes_per_unit, res, exp);

	test_rc = 1;
}

struct tostr_test {
	nvme_uint128_t val;
	__u32 bytes_per_unit;
	const char *exp;
};

static struct tostr_test tostr_tests[] = {
	{ U128(0, 0, 0, 0), 1, "0.00 B" },
	{ U128(0, 0, 0, 1), 1, "1.00 B" },
	{ U128(0, 0, 0, 10), 1, "10.00 B" },
	{ U128(4, 3, 2, 1), 1, "316.91 RB" },
	{ U128(0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff), 1,
	  "340282366.92 QB" },
	{ U128(0, 0, 0, 0xae0dc2), 1000 * 512, "5.84 TB" },
	{ U128(0, 0, 0, 0xf9c546), 1000 * 512, "8.38 TB" },
	{ U128(0, 0, 0, 0x4c2aa594), 1000 * 512, "654.27 TB" },
	{ U128(0, 0, 0, 0x5b013de8), 1000 * 512, "781.73 TB" },
};

void tostr_test(struct tostr_test *test)
{
	char *str;
	str = uint128_t_to_si_string(test->val, test->bytes_per_unit);
	check_str(test->val, test->bytes_per_unit, test->exp, str);
}

int main(void)
{
	unsigned int i;

	test_rc = 0;

	for (i = 0; i < ARRAY_SIZE(tostr_tests); i++)
		tostr_test(&tostr_tests[i]);

	return test_rc ? EXIT_FAILURE : EXIT_SUCCESS;
}
