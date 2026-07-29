// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <crc32.h>

static bool check(const char *name, uint32_t got, uint32_t want)
{
	if (got == want) {
		printf(" - %s [PASS]\n", name);
		return true;
	}

	printf(" - %s: got 0x%08X, want 0x%08X [FAIL]\n", name, got, want);
	return false;
}

static bool test_known_vectors(void)
{
	bool pass = true;

	printf("test_known_vectors:\n");

	/* The standard CRC-32/ISO-HDLC check value, seeded with 0. */
	pass &= check("\"123456789\"",
		      shr_crc32(0, "123456789", 9), 0xCBF43926);
	pass &= check("empty input", shr_crc32(0, "", 0), 0x00000000);
	pass &= check("\"a\"", shr_crc32(0, "a", 1), 0xE8B7BE43);

	return pass;
}

static bool test_chaining_matches_single_call(void)
{
	uint32_t chained, direct;
	bool pass;

	printf("test_chaining_matches_single_call:\n");

	chained = shr_crc32(shr_crc32(0, "foo", 3), "bar", 3);
	direct = shr_crc32(0, "foobar", 6);

	pass = check("two chained calls == one call over the concatenation",
		     chained, direct);

	return pass;
}

int main(void)
{
	bool pass = true;

	pass &= test_known_vectors();
	pass &= test_chaining_matches_single_call();

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
