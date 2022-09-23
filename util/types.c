// SPDX-License-Identifier: GPL-2.0-or-later

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "types.h"

nvme_uint128_t le128_to_cpu(__u8 *data)
{
	nvme_uint128_t u;

	memcpy(u.v, data, 16);

#if HAVE_BIG_ENDIAN
	u.q[0] = le64_to_cpu(u.q[0]);
	u.q[1] = le64_to_cpu(u.q[1]);
#endif
	return u;
}

char *uint128_to_string(nvme_uint128_t val)
{
	static char buf[40];

	if (val.q[1])
		snprintf(buf, sizeof(buf), "0x%" PRIx64 "%08" PRIx64, val.q[1], val.q[0]);
	else
		snprintf(buf, sizeof(buf), "0x%" PRIx64, val.q[0]);

	return buf;
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
