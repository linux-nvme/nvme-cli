// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <shared/hex-util.h>

static bool check_int(const char *name, int got, int want)
{
	if (got == want) {
		printf(" - %s [PASS]\n", name);
		return true;
	}

	printf(" - %s: got %d, want %d [FAIL]\n", name, got, want);
	return false;
}

static bool check_mem(const char *name, const char *got, const char *want, size_t len)
{
	bool eq = got && !memcmp(got, want, len);

	if (eq) {
		printf(" - %s [PASS]\n", name);
		return true;
	}

	printf(" - %s [FAIL]\n", name);
	return false;
}

static bool test_hex_to_int(void)
{
	bool pass = true;

	printf("test_hex_to_int:\n");

	pass &= check_int("digit '0'", shr_hex_to_int('0'), 0);
	pass &= check_int("digit '9'", shr_hex_to_int('9'), 9);
	pass &= check_int("uppercase 'A'", shr_hex_to_int('A'), 10);
	pass &= check_int("uppercase 'F'", shr_hex_to_int('F'), 15);
	pass &= check_int("lowercase 'a'", shr_hex_to_int('a'), 10);
	pass &= check_int("lowercase 'f'", shr_hex_to_int('f'), 15);
	pass &= check_int("non-hex character", shr_hex_to_int('g'), -1);

	return pass;
}

static bool test_hex_to_ascii(void)
{
	bool pass = true;
	char *res;

	printf("test_hex_to_ascii:\n");

	res = shr_hex_to_ascii("68656c6c6f");
	pass &= check_mem("even-length hex string decodes", res, "hello", 5);
	free(res);

	res = shr_hex_to_ascii("168656c6c6f");
	pass &= check_mem("odd-length hex string is left-padded with 0",
			  res, "\x01hello", 6);
	free(res);

	res = shr_hex_to_ascii("");
	pass &= check_int("empty input returns NULL", res == NULL, 1);
	free(res);

	res = shr_hex_to_ascii("68656c6c6g");
	pass &= check_int("invalid hex digit returns NULL", res == NULL, 1);
	free(res);

	res = shr_hex_to_ascii("z");
	pass &= check_int("invalid odd-length hex digit returns NULL", res == NULL, 1);
	free(res);

	return pass;
}

static bool test_bin_to_hex(void)
{
	const unsigned char bin[] = { 0x00, 0x1f, 0xa0, 0xff };
	char buf[9];
	bool pass = true;
	int ret;

	printf("test_bin_to_hex:\n");

	ret = shr_bin_to_hex(buf, sizeof(buf), bin, sizeof(bin), 0);
	if (ret != 8 || strcmp(buf, "001fa0ff")) {
		printf(" - lower case [FAIL] got %d '%s'\n", ret, buf);
		pass = false;
	} else {
		printf(" - lower case [PASS]\n");
	}

	ret = shr_bin_to_hex(buf, sizeof(buf), bin, sizeof(bin),
			     SHR_HEX_UPPER);
	if (ret != 8 || strcmp(buf, "001FA0FF")) {
		printf(" - upper case [FAIL] got %d '%s'\n", ret, buf);
		pass = false;
	} else {
		printf(" - upper case [PASS]\n");
	}

	ret = shr_bin_to_hex(buf, sizeof(buf), bin, sizeof(bin),
			     SHR_HEX_REVERSE);
	if (ret != 8 || strcmp(buf, "ffa01f00")) {
		printf(" - reverse [FAIL] got %d '%s'\n", ret, buf);
		pass = false;
	} else {
		printf(" - reverse [PASS]\n");
	}

	ret = shr_bin_to_hex(buf, sizeof(buf) - 1, bin, sizeof(bin), 0);
	if (ret != -E2BIG || buf[0]) {
		printf(" - too small [FAIL] got %d\n", ret);
		pass = false;
	} else {
		printf(" - too small [PASS]\n");
	}

	ret = shr_bin_to_hex(buf, 1, bin, 0, 0);
	if (ret != 0 || buf[0]) {
		printf(" - empty [FAIL] got %d\n", ret);
		pass = false;
	} else {
		printf(" - empty [PASS]\n");
	}

	return pass;
}

int main(void)
{
	bool pass = true;

	pass &= test_hex_to_int();
	pass &= test_hex_to_ascii();
	pass &= test_bin_to_hex();

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
