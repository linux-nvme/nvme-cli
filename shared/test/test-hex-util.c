// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <hex-util.h>

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

	return pass;
}

int main(void)
{
	bool pass = true;

	pass &= test_hex_to_int();
	pass &= test_hex_to_ascii();

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
