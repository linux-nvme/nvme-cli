// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <shared/parse-util.h>

static bool check_bool(const char *value, int want_ret, bool want_out)
{
	bool out = false;
	int ret;

	ret = shr_parse_bool(value, &out);
	if (ret != want_ret || (!ret && out != want_out)) {
		printf(" - \"%s\": got ret=%d out=%d, want ret=%d out=%d [FAIL]\n",
		       value, ret, out, want_ret, want_out);
		return false;
	}

	printf(" - \"%s\" [PASS]\n", value);
	return true;
}

static bool test_accepted_spellings(void)
{
	bool pass = true;

	printf("test_accepted_spellings:\n");

	pass &= check_bool("1", 0, true);
	pass &= check_bool("yes", 0, true);
	pass &= check_bool("y", 0, true);
	pass &= check_bool("true", 0, true);
	pass &= check_bool("t", 0, true);
	pass &= check_bool("on", 0, true);

	pass &= check_bool("0", 0, false);
	pass &= check_bool("no", 0, false);
	pass &= check_bool("n", 0, false);
	pass &= check_bool("false", 0, false);
	pass &= check_bool("f", 0, false);
	pass &= check_bool("off", 0, false);

	return pass;
}

static bool test_case_insensitive(void)
{
	bool pass = true;

	printf("test_case_insensitive:\n");

	pass &= check_bool("YES", 0, true);
	pass &= check_bool("True", 0, true);
	pass &= check_bool("ON", 0, true);
	pass &= check_bool("NO", 0, false);
	pass &= check_bool("False", 0, false);
	pass &= check_bool("OFF", 0, false);

	return pass;
}

static bool test_rejected(void)
{
	bool pass = true;

	printf("test_rejected:\n");

	pass &= check_bool("maybe", -EINVAL, false);
	pass &= check_bool("", -EINVAL, false);
	pass &= check_bool("2", -EINVAL, false);
	pass &= check_bool("yesplease", -EINVAL, false);

	return pass;
}

static bool check_int_ret(const char *name, int got, int want)
{
	if (got == want) {
		printf(" - %s [PASS]\n", name);
		return true;
	}

	printf(" - %s: got %d, want %d [FAIL]\n", name, got, want);
	return false;
}

static bool test_csv_int(void)
{
	char buf[] = "1,2,3";
	int val[8] = { 0 };
	bool pass = true;
	int ret;

	printf("test_csv_int:\n");

	ret = shr_parse_csv_int(buf, val, 8);
	pass &= check_int_ret("parses three entries", ret, 3);
	pass &= check_int_ret("val[0]", val[0], 1);
	pass &= check_int_ret("val[1]", val[1], 2);
	pass &= check_int_ret("val[2]", val[2], 3);

	{
		char empty[] = "";

		ret = shr_parse_csv_int(empty, val, 8);
		pass &= check_int_ret("empty string is a no-op success", ret, 0);
	}

	{
		char overflow[] = "1,2,3";

		ret = shr_parse_csv_int(overflow, val, 2);
		pass &= check_int_ret("more entries than max_length fails", ret, -1);
	}

	{
		char bad[] = "1,notanumber";

		ret = shr_parse_csv_int(bad, val, 8);
		pass &= check_int_ret("a non-numeric entry fails", ret, -1);
	}

	return pass;
}

static bool test_csv_ushort(void)
{
	char buf[] = "10,20";
	unsigned short val[8] = { 0 };
	bool pass = true;
	int ret;

	printf("test_csv_ushort:\n");

	ret = shr_parse_csv_ushort(buf, val, 8);
	pass &= check_int_ret("parses two entries", ret, 2);
	pass &= check_int_ret("val[0]", val[0], 10);
	pass &= check_int_ret("val[1]", val[1], 20);

	{
		char overflow[] = "70000";

		ret = shr_parse_csv_ushort(overflow, val, 8);
		pass &= check_int_ret("value beyond UINT16_MAX fails", ret, -1);
	}

	return pass;
}

static bool test_csv_uint(void)
{
	char buf[] = "1,2,3";
	unsigned int val[8] = { 0 };
	bool pass = true;
	int ret;

	printf("test_csv_uint:\n");

	ret = shr_parse_csv_uint(buf, val, 8);
	pass &= check_int_ret("parses three entries", ret, 3);
	pass &= check_int_ret("val[0]", val[0], 1);
	pass &= check_int_ret("val[1]", val[1], 2);
	pass &= check_int_ret("val[2]", val[2], 3);

	{
		char overflow[] = "4294967296";

		ret = shr_parse_csv_uint(overflow, val, 8);
		pass &= check_int_ret("value beyond UINT32_MAX fails", ret, -1);
	}

	return pass;
}

static bool test_csv_ulonglong(void)
{
	char buf[] = "42";
	unsigned long long val[8] = { 0 };
	bool pass = true;
	int ret;

	printf("test_csv_ulonglong:\n");

	ret = shr_parse_csv_ulonglong(buf, val, 8);
	pass &= check_int_ret("parses one entry", ret, 1);
	pass &= check_int_ret("val[0]", (int)val[0], 42);

	return pass;
}

static bool test_csv_u16(void)
{
	char buf[] = "10,20";
	uint16_t val[8] = { 0 };
	bool pass = true;
	int ret;

	printf("test_csv_u16:\n");

	ret = shr_parse_csv_u16(buf, val, 8);
	pass &= check_int_ret("parses two entries", ret, 2);
	pass &= check_int_ret("val[0]", val[0], 10);
	pass &= check_int_ret("val[1]", val[1], 20);

	{
		char overflow[] = "70000";

		ret = shr_parse_csv_u16(overflow, val, 8);
		pass &= check_int_ret("value beyond UINT16_MAX fails", ret, -1);
	}

	return pass;
}

static bool test_csv_u32(void)
{
	char buf[] = "1,2,3";
	uint32_t val[8] = { 0 };
	bool pass = true;
	int ret;

	printf("test_csv_u32:\n");

	ret = shr_parse_csv_u32(buf, val, 8);
	pass &= check_int_ret("parses three entries", ret, 3);
	pass &= check_int_ret("val[0]", val[0], 1);
	pass &= check_int_ret("val[1]", val[1], 2);
	pass &= check_int_ret("val[2]", val[2], 3);

	{
		char overflow[] = "4294967296";

		ret = shr_parse_csv_u32(overflow, val, 8);
		pass &= check_int_ret("value beyond UINT32_MAX fails", ret, -1);
	}

	return pass;
}

static bool test_csv_u64(void)
{
	char buf[] = "42";
	uint64_t val[8] = { 0 };
	bool pass = true;
	int ret;

	printf("test_csv_u64:\n");

	ret = shr_parse_csv_u64(buf, val, 8);
	pass &= check_int_ret("parses one entry", ret, 1);
	pass &= check_int_ret("val[0]", (int)val[0], 42);

	return pass;
}

static bool test_csv_u8(void)
{
	char buf[] = "42,0,255";
	uint8_t val[8] = { 0 };
	bool pass = true;
	int ret;

	printf("test_csv_u8:\n");

	ret = shr_parse_csv_u8(buf, val, 8);
	pass &= check_int_ret("parses one entry", ret, 3);
	pass &= check_int_ret("val[0]", val[0], 42);
	pass &= check_int_ret("val[1]", val[1], 0);
	pass &= check_int_ret("val[2]", val[2], 255);

	{
		char overflow[] = "256";

		ret = shr_parse_csv_u8(overflow, val, 8);
		pass &= check_int_ret("value beyond UINT8_MAX fails", ret, -1);
	}

	return pass;
}

#ifdef NVME_HAVE_INT128
static char *get_int128_str(uint128_t n, char *str)
{
	char buf[40];
	int i = 0;

	if (!n) {
		sprintf(str, "0");
		return str;
	}

	while (n > 0) {
		buf[i++] = (char)('0' + (n % 10));
		n /= 10;
	}

	while (i > 0)
		sprintf(&str[strlen(str)], "%c", buf[--i]);

	return str;
}

static bool check_uint128_ret(const char *name, uint128_t got, uint128_t want)
{
	char got_str[40] = { 0 };
	char want_str[40] = { 0 };

	if (got == want) {
		printf(" - %s [PASS]\n", name);
		return true;
	}

	printf(" - %s: got %s, want %s [FAIL]\n", name,
	       get_int128_str(got, got_str), get_int128_str(want, want_str));

	return false;
}

static bool test_csv_u128(void)
{
	const uint128_t want =
	    UINT128_CONST(0x123e4567e89b12d3ULL, 0xa456426614174000ULL);
	char buf[] = "42,2147483647,0x123e4567e89b12d3a456426614174000";
	uint128_t val[8] = { 0 };
	bool pass = true;
	int ret;

	printf("test_csv_u128:\n");

	ret = shr_parse_csv_u128(buf, val, 8);
	pass &= check_int_ret("parses one entry", ret, 3);
	pass &= check_int_ret("val[0]", (int)val[0], 42);
	pass &= check_int_ret("val[1]", (int)val[1], 2147483647);
	pass &= check_uint128_ret("val[2]", val[2], want);

	return pass;
}
#else /* NVME_HAVE_INT128 */
#define test_csv_u128() true
#endif /* NVME_HAVE_INT128 */

int main(void)
{
	bool pass = true;

	pass &= test_accepted_spellings();
	pass &= test_case_insensitive();
	pass &= test_rejected();
	pass &= test_csv_int();
	pass &= test_csv_ushort();
	pass &= test_csv_uint();
	pass &= test_csv_ulonglong();
	pass &= test_csv_u8();
	pass &= test_csv_u16();
	pass &= test_csv_u32();
	pass &= test_csv_u64();
	pass &= test_csv_u128();

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
