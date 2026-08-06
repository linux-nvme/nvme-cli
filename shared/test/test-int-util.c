// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2025 Tokunori Ikegami
 *
 * Authors: Tokunori Ikegami <ikegami.t@gmail.com>
 *          Daniel Wagner <dwagner@suse.de>
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <int-util.h>

static bool check_u64(const char *name, uint64_t got, uint64_t want)
{
	if (got == want) {
		printf(" - %s [PASS]\n", name);
		return true;
	}

	printf(" - %s: got %llu, want %llu [FAIL]\n",
	       name, (unsigned long long)got, (unsigned long long)want);
	return false;
}

static bool test_int48_to_long(void)
{
	bool pass = true;
	uint8_t zero[6] = { 0 };
	uint8_t one[6] = { 1, 0, 0, 0, 0, 0 };
	uint8_t max[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

	printf("test_int48_to_long:\n");

	pass &= check_u64("zero", int48_to_long(zero), 0);
	pass &= check_u64("one", int48_to_long(one), 1);
	pass &= check_u64("max", int48_to_long(max), 0xffffffffffffULL);

	return pass;
}

static bool test_int56_to_long(void)
{
	bool pass = true;
	uint8_t zero[7] = { 0 };
	uint8_t one[7] = { 1, 0, 0, 0, 0, 0, 0 };
	uint8_t max[7] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

	printf("test_int56_to_long:\n");

	pass &= check_u64("zero", int56_to_long(zero), 0);
	pass &= check_u64("one", int56_to_long(one), 1);
	pass &= check_u64("max", int56_to_long(max), 0xffffffffffffffULL);

	return pass;
}

int main(void)
{
	bool pass = true;

	pass &= test_int48_to_long();
	pass &= test_int56_to_long();

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
