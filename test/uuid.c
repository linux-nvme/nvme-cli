// SPDX-License-Identifier: LGPL-2.1-or-later
/**
 * This file is part of libnvme.
 * Copyright (c) 2022 Daniel Wagner, SUSE Software Solutions
 */

#include <string.h>
#include <stdlib.h>

#include <ccan/array_size/array_size.h>

#include <libnvme.h>

static int test_rc;

struct test_data {
	unsigned char uuid[NVME_UUID_LEN];
	const char *str;
};

static struct test_data test_data[] = {
	{ { 0 },	         "00000000-0000-0000-0000-000000000000" },
	{ { [0 ... 15] = 0xff }, "ffffffff-ffff-ffff-ffff-ffffffffffff" },
	{ { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0f, 0x10 },
				 "00010203-0405-0607-0809-0a0b0c0d0f10" },
};

static void check_str(const char *exp, const char *res)
{
	if (!strcmp(res, exp))
		return;

	printf("ERROR: got '%s', expected '%s'\n", res, exp);

	test_rc = 1;
}

static void print_uuid_hex(const unsigned char uuid[NVME_UUID_LEN])
{
	for (int i = 0; i < NVME_UUID_LEN; i++)
		printf("%02x", uuid[i]);
}

static void check_uuid(unsigned char exp[NVME_UUID_LEN],
		       unsigned char res[NVME_UUID_LEN])
{
	if (!memcmp(exp, res, NVME_UUID_LEN))
		return;

	printf("ERROR: got '");
	print_uuid_hex(exp);
	printf("', expected '");
	print_uuid_hex(res);
	printf("'\n");
}

static void tostr_test(struct test_data *test)
{
	char str[NVME_UUID_LEN_STRING];

	if (nvme_uuid_to_string(test->uuid, str)) {
		test_rc = 1;
		printf("ERROR: nvme_uuid_to_string() failed\n");
		return;
	}
	check_str(test->str, str);
}

static void fromstr_test(struct test_data *test)
{

	unsigned char uuid[NVME_UUID_LEN];

	if (nvme_uuid_from_string(test->str, uuid)) {
		test_rc = 1;
		printf("ERROR: nvme_uuid_from_string() failed\n");
		return;
	}
	check_uuid(test->uuid, uuid);
}

static void random_uuid_test(void)
{
	unsigned char uuid1[NVME_UUID_LEN], uuid2[NVME_UUID_LEN];
	char str1[NVME_UUID_LEN_STRING], str2[NVME_UUID_LEN_STRING];

	if (nvme_uuid_random(uuid1) || nvme_uuid_random(uuid2)) {
		test_rc = 1;
		printf("ERROR: nvme_uuid_random() failed\n");
		return;
	}

	if (!memcmp(uuid1, uuid2, NVME_UUID_LEN)) {
		test_rc = 1;
		printf("ERROR: generated random numbers are equal\n");
		return;
	}

	if (nvme_uuid_to_string(uuid1, str1) ||
	    nvme_uuid_to_string(uuid2, str2)) {
		test_rc = 1;
		printf("ERROR: could not stringify randomly generated UUID\n");
		return;
	}
	printf("PASS: generated UUIDs %s %s\n", str1, str2);
}

int main(void)
{
	for (int i = 0; i < ARRAY_SIZE(test_data); i++)
		tostr_test(&test_data[i]);

	for (int i = 0; i < ARRAY_SIZE(test_data); i++)
		fromstr_test(&test_data[i]);

	random_uuid_test();

	return test_rc ? EXIT_FAILURE : EXIT_SUCCESS;
}
