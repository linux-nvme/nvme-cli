// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE LLC
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

/*
 * Unit tests for bitfields.c: extracting a field of a 64 bit value and
 * decoding it in each format.
 */

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#include "bitfields.h"

static const char * const strs[] = { "zero", NULL, "two" };

static bool check_str(const char *what, const struct bitfield *f,
		      uint64_t value, const char *expected)
{
	char buf[64];
	int len = bitfield_str(f, value, buf, sizeof(buf));

	if (strcmp(buf, expected) || len != (int)strlen(expected)) {
		printf(" - %s: \"%s\" (%d), expected \"%s\" [FAIL]\n", what,
		       buf, len, expected);
		return false;
	}
	printf(" - %s [PASS]\n", what);
	return true;
}

static bool test_get(void)
{
	const struct bitfield low = BITFIELD("low", 0, 0xff, BF_DEC);
	const struct bitfield mid = BITFIELD("mid", 20, 0xf, BF_DEC);
	const struct bitfield top = BITFIELD("top", 63, 0x1, BF_DEC);
	const struct bitfield all = BITFIELD("all", 0, UINT64_MAX, BF_DEC);
	bool pass = true;

	printf("bitfield_get\n");
	pass &= bitfield_get(&low, 0x1234) == 0x34;
	pass &= bitfield_get(&mid, 0xa00000) == 0xa;
	pass &= bitfield_get(&mid, 0xff0fffff) == 0x0;
	pass &= bitfield_get(&top, UINT64_C(1) << 63) == 1;
	pass &= bitfield_get(&top, ~(UINT64_C(1) << 63)) == 0;
	pass &= bitfield_get(&all, UINT64_MAX) == UINT64_MAX;
	printf(" - shift and mask [%s]\n", pass ? "PASS" : "FAIL");

	return pass;
}

static bool test_formats(void)
{
	const struct bitfield dec = BITFIELD("dec", 8, 0xff, BF_DEC);
	const struct bitfield dec1 = BITFIELD("dec1", 0, 0xffff, BF_DEC1);
	const struct bitfield hex = BITFIELD("hex", 4, 0xfff, BF_HEX);
	const struct bitfield addr = BITFIELD("addr", 12,
					      UINT64_C(0xfffffffffffff),
					      BF_ADDR);
	const struct bitfield yes = BITFIELD("yes", 3, 1, BF_YESNO);
	const struct bitfield sup = BITFIELD("sup", 3, 1, BF_SUPPORTED);
	const struct bitfield ena = BITFIELD("ena", 3, 1, BF_ENABLED);
	const struct bitfield str = BITFIELD_STR("str", 0, 0x3, strs);
	const struct bitfield pow2 = BITFIELD_POW2("pow2", 0, 0xf, 12);
	const struct bitfield ms = BITFIELD("ms", 16, 0xffff, BF_MS500);
	bool pass = true;

	printf("bitfield_str\n");
	pass &= check_str("decimal", &dec, 0x1234, "18");
	pass &= check_str("decimal of 0", &dec, 0x00ff, "0");
	pass &= check_str("0's based", &dec1, 0x0fff, "4096");
	pass &= check_str("0's based of all ones", &dec1, 0xffff, "65536");
	pass &= check_str("hex", &hex, 0x12340, "0x234");
	pass &= check_str("hex of 0", &hex, 0xf, "0");
	pass &= check_str("address in place", &addr, 0x12345fff,
			  "0x12345000");
	pass &= check_str("64 bit address", &addr, UINT64_MAX,
			  "0xfffffffffffff000");
	pass &= check_str("yes", &yes, 0x8, "Yes");
	pass &= check_str("no", &yes, 0x7, "No");
	pass &= check_str("supported", &sup, 0x8, "Supported");
	pass &= check_str("not supported", &sup, 0, "Not Supported");
	pass &= check_str("enabled", &ena, 0x8, "Enabled");
	pass &= check_str("disabled", &ena, 0, "Disabled");
	pass &= check_str("string", &str, 2, "two");
	pass &= check_str("string hole", &str, 1, "Reserved");
	pass &= check_str("string past the table", &str, 3, "Reserved");
	pass &= check_str("power of two", &pow2, 0, "4096 bytes");
	pass &= check_str("power of two of 4", &pow2, 4, "65536 bytes");
	pass &= check_str("500 ms units", &ms, 0x50000, "2500 ms");
	pass &= check_str("500 ms of all ones", &ms, 0xffff0000,
			  "32767500 ms");

	return pass;
}

static bool test_power_of_two_too_large(void)
{
	const struct bitfield pow2 = BITFIELD_POW2("pow2", 0, 0xff, 12);
	bool pass;

	printf("bitfield_str power of two past 64 bits\n");
	pass = check_str("2^64 and above", &pow2, 52, "2^64 bytes");
	pass &= check_str("largest in 64 bits", &pow2, 51,
			  "9223372036854775808 bytes");

	return pass;
}

static bool test_truncated(void)
{
	const struct bitfield sup = BITFIELD("sup", 0, 1, BF_SUPPORTED);
	char buf[4];
	int len;

	printf("bitfield_str into a short buffer\n");
	len = bitfield_str(&sup, 0, buf, sizeof(buf));
	if (len != (int)strlen("Not Supported") || strcmp(buf, "Not")) {
		printf(" - truncated: \"%s\" (%d) [FAIL]\n", buf, len);
		return false;
	}
	printf(" - truncated, full length returned [PASS]\n");
	return true;
}

int main(void)
{
	bool pass = true;

	pass &= test_get();
	pass &= test_formats();
	pass &= test_power_of_two_too_large();
	pass &= test_truncated();

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
