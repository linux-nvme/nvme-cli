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
#include <string.h>

#include <hash-util.h>

static bool check(const char *name, uint64_t got, uint64_t want)
{
	if (got == want) {
		printf(" - %s [PASS]\n", name);
		return true;
	}

	printf(" - %s: got 0x%016lX, want 0x%016lX [FAIL]\n",
	       name, (unsigned long)got, (unsigned long)want);
	return false;
}

static bool test_known_vectors(void)
{
	bool pass = true;

	printf("test_known_vectors:\n");

	/* Reference FNV-1a 64-bit values (fnv1a64 offset basis / test set). */
	pass &= check("empty input", shr_fnv1a_64("", 0),
		      0xcbf29ce484222325ULL);
	pass &= check("\"a\"", shr_fnv1a_64("a", 1), 0xaf63dc4c8601ec8cULL);
	pass &= check("\"foobar\"", shr_fnv1a_64("foobar", 6),
		      0x85944171f73967e8ULL);
	pass &= check("\"123456789\"", shr_fnv1a_64("123456789", 9),
		      0x06d5573923c6cdfcULL);

	return pass;
}

static bool test_deterministic(void)
{
	uint64_t h1, h2;
	bool pass;

	printf("test_deterministic:\n");

	h1 = shr_fnv1a_64("same input", strlen("same input"));
	h2 = shr_fnv1a_64("same input", strlen("same input"));

	pass = check("two calls on identical input match", h1, h2);

	return pass;
}

static bool test_different_inputs_differ(void)
{
	uint64_t h1, h2;
	bool pass;

	printf("test_different_inputs_differ:\n");

	h1 = shr_fnv1a_64("input-a", 7);
	h2 = shr_fnv1a_64("input-b", 7);

	if (h1 != h2) {
		printf(" - single-byte difference changes the hash [PASS]\n");
		pass = true;
	} else {
		printf(" - single-byte difference changes the hash [FAIL]\n");
		pass = false;
	}

	return pass;
}

int main(void)
{
	bool pass = true;

	pass &= test_known_vectors();
	pass &= test_deterministic();
	pass &= test_different_inputs_differ();

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
