// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <shared/unaligned-util.h>

static bool check_ret(const char *name, unsigned long long got,
		      unsigned long long want)
{
	if (got == want) {
		printf(" - %s [PASS]\n", name);
		return true;
	}

	printf(" - %s: got 0x%llx, want 0x%llx [FAIL]\n", name, got, want);
	return false;
}

static bool test_get_unaligned(void)
{
	/* The values start at offset 1, so they are not aligned. */
	unsigned char buf[9] __attribute__((aligned(8))) = {
		0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
	};
	bool pass = true;

	printf("test_get_unaligned:\n");

	pass &= check_ret("reads a little-endian 16-bit value",
			  shr_get_unaligned_le16(buf + 1), 0x2211);
	pass &= check_ret("reads a little-endian 32-bit value",
			  shr_get_unaligned_le32(buf + 1), 0x44332211);
	pass &= check_ret("reads a little-endian 64-bit value",
			  shr_get_unaligned_le64(buf + 1),
			  0x8877665544332211ULL);

	return pass;
}

int main(void)
{
	bool pass = true;

	pass &= test_get_unaligned();

	return pass ? EXIT_SUCCESS : EXIT_FAILURE;
}
