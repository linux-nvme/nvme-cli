// SPDX-License-Identifier: GPL-2.0-or-later

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include <ccan/endian/endian.h>

#include "types.h"

nvme_uint128_t le128_to_cpu(__u8 *data)
{
	nvme_uint128_t u;
	nvme_uint128_t tmp;
	memcpy(tmp.bytes, data, 16);
	u.words[0] = le32_to_cpu(tmp.words[3]);
	u.words[1] = le32_to_cpu(tmp.words[2]);
	u.words[2] = le32_to_cpu(tmp.words[1]);
	u.words[3] = le32_to_cpu(tmp.words[0]);
	return u;
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

char *uint128_t_to_string(nvme_uint128_t val)
{
	static char str[40];
	int idx = 40;
	__u64 div, rem;

	/* terminate at the end, and build up from the ones */
	str[--idx] = '\0';

	do {
		rem = val.words[0];

		div = rem / 10;
		rem = ((rem - div * 10) << 32) + val.words[1];
		val.words[0] = div;

		div = rem / 10;
		rem = ((rem - div * 10) << 32) + val.words[2];
		val.words[1] = div;

		div = rem / 10;
		rem = ((rem - div * 10) << 32) + val.words[3];
		val.words[2] = div;

		div = rem / 10;
		rem = rem - div * 10;
		val.words[3] = div;

		str[--idx] = '0' + rem;
	} while (val.words[0] || val.words[1] || val.words[2] || val.words[3]);

	return str + idx;
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
