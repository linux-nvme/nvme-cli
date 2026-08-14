// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 */
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <shared/temp-util.h>

static bool check_long(const char *name, long got, long want)
{
	if (got == want) {
		printf(" - %s [PASS]\n", name);
		return true;
	}

	printf(" - %s: got %ld, want %ld [FAIL]\n", name, got, want);
	return false;
}

int main(void)
{
	bool pass = true;

	printf("test_temp_conversions:\n");

	pass &= check_long("0 K -> -273 C", shr_kelvin_to_celsius(0), -273);
	pass &= check_long("273 K -> 0 C", shr_kelvin_to_celsius(273), 0);
	pass &= check_long("0 C -> 32 F", shr_celsius_to_fahrenheit(0), 32);
	pass &= check_long("100 C -> 212 F", shr_celsius_to_fahrenheit(100), 212);
	pass &= check_long("373 K -> 212 F", shr_kelvin_to_fahrenheit(373), 212);

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
