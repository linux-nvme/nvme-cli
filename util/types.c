// SPDX-License-Identifier: GPL-2.0-or-later

#include <inttypes.h>
#include <stdio.h>

#include "types.h"

__uint128_t le128_to_cpu(__u8 *data)
{
	int i;
	__uint128_t result = 0;

	for (i = 0; i < 16; i++) {
		result *= 256;
		result += data[15 - i];
	}
	return result;
}

long double int128_to_double(__u8 *data)
{
	int i;
	long double result = 0;

	for (i = 0; i < 16; i++) {
		result *= 256;
		result += data[15 - i];
	}
	return result;
}

uint64_t int48_to_long(__u8 *data)
{
	int i;
	uint64_t result = 0;

	for (i = 0; i < 6; i++) {
		result *= 256;
		result += data[5 - i];
	}
	return result;
}

char str_uint128[40];
char *uint128_t_to_string(__uint128_t val)
{
	char str_rev[40]; /* __uint128_t  maximum string length is 39 */
	int i, j;

	for (i = 0; val > 0; i++) {
		str_rev[i] = (val % 10) + 48;
		val /= 10;
	}

	for (j = 0; i >= 0;) {
		str_uint128[j++] = str_rev[--i];
	}
	str_uint128[j] = '\0';

	return str_uint128;
}

const char *util_uuid_to_string(uuid_t uuid)
{
	/* large enough to hold uuid str (37) + null-termination byte */
	static char uuid_str[40];

	uuid_unparse_lower(uuid, uuid_str);

	return uuid_str;
}

const char *util_fw_to_string(char *c)
{
	static char ret[9];
	int i;

	for (i = 0; i < 8; i++)
		ret[i] = c[i] >= '!' && c[i] <= '~' ? c[i] : '.';
	ret[i] = '\0';
	return ret;
}
