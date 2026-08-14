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
#include <string.h>

#include <shared/mmio-util.h>

static bool check_ret(const char *name, unsigned long long got, unsigned long long want)
{
	if (got == want) {
		printf(" - %s [PASS]\n", name);
		return true;
	}

	printf(" - %s: got 0x%llx, want 0x%llx [FAIL]\n", name, got, want);
	return false;
}

static bool check_bool(const char *name, bool got)
{
	printf(" - %s [%s]\n", name, got ? "PASS" : "FAIL");
	return got;
}

static bool test_read32(void)
{
	unsigned char reg[4] __attribute__((aligned(4))) = { 0x11, 0x22, 0x33, 0x44 };
	bool pass = true;

	printf("test_read32:\n");

	pass &= check_ret("reads a little-endian 32-bit register",
			   shr_mmio_read32(reg), 0x44332211);

	return pass;
}

static bool test_write32(void)
{
	unsigned char reg[4] __attribute__((aligned(4))) = { 0 };
	unsigned char want[4] = { 0x11, 0x22, 0x33, 0x44 };
	bool pass = true;

	printf("test_write32:\n");

	shr_mmio_write32(reg, 0x44332211);
	pass &= check_bool("writes a 32-bit value as little-endian bytes",
			    !memcmp(reg, want, sizeof(want)));

	return pass;
}

static bool test_read64(void)
{
	unsigned char reg[8] __attribute__((aligned(8))) = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
	bool pass = true;

	printf("test_read64:\n");

	pass &= check_ret("reads a little-endian 64-bit register as 2 32-bit halves",
			   shr_mmio_read64(reg), 0x8877665544332211ULL);

	return pass;
}

static bool test_write64(void)
{
	unsigned char reg64[8] __attribute__((aligned(8))) = { 0 };
	unsigned char want64[8] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
	unsigned char reg32[8] __attribute__((aligned(8))) = { 0 };
	bool pass = true;

	printf("test_write64:\n");

	shr_mmio_write64(reg64, 0x8877665544332211ULL, false);
	pass &= check_bool("write32=false writes a single 64-bit little-endian value",
			    !memcmp(reg64, want64, sizeof(want64)));

	shr_mmio_write64(reg32, 0x8877665544332211ULL, true);
	pass &= check_ret("write32=true writes the low half as a 32-bit register",
			   shr_mmio_read32(reg32), 0x44332211);
	pass &= check_ret("write32=true writes the high half as the next 32-bit register",
			   shr_mmio_read32(reg32 + 4), 0x88776655);

	return pass;
}

int main(void)
{
	bool pass = true;

	pass &= test_read32();
	pass &= test_write32();
	pass &= test_read64();
	pass &= test_write64();

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
