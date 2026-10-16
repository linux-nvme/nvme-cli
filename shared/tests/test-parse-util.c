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

#include <ccan/array_size/array_size.h>
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

static bool check_u64(const char *value, uint64_t max, int want_ret,
		      uint64_t want)
{
	uint64_t out = 0;
	int ret;

	ret = shr_parse_u64(value, max, &out);
	if (ret != want_ret || (!ret && out != want)) {
		printf(" - \"%s\": got ret=%d out=%llu [FAIL]\n", value, ret,
		       (unsigned long long)out);
		return false;
	}
	printf(" - \"%s\" [PASS]\n", value);
	return true;
}

static bool test_u64(void)
{
	bool pass = true;

	printf("test_u64:\n");

	pass &= check_u64("0", UINT64_MAX, 0, 0);
	pass &= check_u64("42", UINT64_MAX, 0, 42);
	pass &= check_u64("0x1F", UINT64_MAX, 0, 31);
	pass &= check_u64("010", UINT64_MAX, 0, 8);
	pass &= check_u64("18446744073709551615", UINT64_MAX, 0, UINT64_MAX);
	pass &= check_u64("18446744073709551616", UINT64_MAX, -ERANGE, 0);
	pass &= check_u64("256", 255, -ERANGE, 0);
	pass &= check_u64("255", 255, 0, 255);
	pass &= check_u64("", UINT64_MAX, -EINVAL, 0);
	pass &= check_u64(" 1", UINT64_MAX, -EINVAL, 0);
	pass &= check_u64("1 ", UINT64_MAX, -EINVAL, 0);
	pass &= check_u64("+1", UINT64_MAX, -EINVAL, 0);
	pass &= check_u64("-1", UINT64_MAX, -EINVAL, 0);
	pass &= check_u64("1x", UINT64_MAX, -EINVAL, 0);
	pass &= check_u64("0x", UINT64_MAX, -EINVAL, 0);
	pass &= check_u64("08", UINT64_MAX, -EINVAL, 0);
	pass &= check_u64(NULL, UINT64_MAX, -EINVAL, 0);

	return pass;
}

static bool check_s64(const char *value, int64_t min, int64_t max,
		      int want_ret, int64_t want)
{
	int64_t out = 0;
	int ret;

	ret = shr_parse_s64(value, min, max, &out);
	if (ret != want_ret || (!ret && out != want)) {
		printf(" - \"%s\": got ret=%d out=%lld [FAIL]\n", value, ret,
		       (long long)out);
		return false;
	}
	printf(" - \"%s\" [PASS]\n", value);
	return true;
}

static bool test_s64(void)
{
	bool pass = true;

	printf("test_s64:\n");

	pass &= check_s64("-5", INT32_MIN, INT32_MAX, 0, -5);
	pass &= check_s64("2147483647", INT32_MIN, INT32_MAX, 0, INT32_MAX);
	pass &= check_s64("2147483648", INT32_MIN, INT32_MAX, -ERANGE, 0);
	pass &= check_s64("-2147483649", INT32_MIN, INT32_MAX, -ERANGE, 0);
	pass &= check_s64("-0x10", INT32_MIN, INT32_MAX, 0, -16);
	pass &= check_s64("9223372036854775808", INT64_MIN, INT64_MAX,
			  -ERANGE, 0);
	pass &= check_s64("--1", INT32_MIN, INT32_MAX, -EINVAL, 0);
	pass &= check_s64("- 1", INT32_MIN, INT32_MAX, -EINVAL, 0);
	pass &= check_s64("-", INT32_MIN, INT32_MAX, -EINVAL, 0);
	pass &= check_s64("1x", INT32_MIN, INT32_MAX, -EINVAL, 0);

	return pass;
}

static bool check_double(const char *value, int want_ret, double want)
{
	double out = 0;
	int ret;

	ret = shr_parse_double(value, &out);
	if (ret != want_ret || (!ret && out != want)) {
		printf(" - \"%s\": got ret=%d out=%f [FAIL]\n", value, ret,
		       out);
		return false;
	}
	printf(" - \"%s\" [PASS]\n", value);
	return true;
}

static bool test_double(void)
{
	bool pass = true;

	printf("test_double:\n");

	pass &= check_double("1.5", 0, 1.5);
	pass &= check_double("-0.25", 0, -0.25);
	pass &= check_double("1e3", 0, 1000);
	pass &= check_double(".5", 0, 0.5);
	pass &= check_double("nan", -EINVAL, 0);
	pass &= check_double("inf", -EINVAL, 0);
	pass &= check_double("1e999", -EINVAL, 0);
	pass &= check_double(" 1", -EINVAL, 0);
	pass &= check_double("1 ", -EINVAL, 0);
	pass &= check_double("1,5", -EINVAL, 0);
	pass &= check_double("", -EINVAL, 0);

	return pass;
}

static bool test_csv_strict(void)
{
	static const struct {
		const char *in;
		int want;
	} tests[] = {
		{ "1, 2", 2 },
		{ " 1 ,2 ", 2 },
		{ "1,,2", 2 },
		{ "1,2,", 2 },
		{ ",1", 1 },
		{ "1,-2", -1 },
		{ "+1", -1 },
		{ "4294967296", -1 },
		{ "0x10,010", 2 },
	};
	unsigned int val[8];
	bool pass = true;
	unsigned int i;

	printf("test_csv_strict:\n");

	for (i = 0; i < ARRAY_SIZE(tests); i++) {
		char buf[64];

		snprintf(buf, sizeof(buf), "%s", tests[i].in);
		pass &= check_int_ret(tests[i].in,
				      shr_parse_csv_uint(buf, val, 8),
				      tests[i].want);
	}

	return pass;
}

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
	pass &= test_u64();
	pass &= test_s64();
	pass &= test_double();
	pass &= test_csv_strict();

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
