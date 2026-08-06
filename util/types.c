// SPDX-License-Identifier: GPL-2.0-or-later

#include <inttypes.h>
#include <limits.h>

#include "types.h"

static uint64_t int_to_long(int bits, const __u8 *data)
{
	int i;
	uint64_t result = 0;
	int bytes = (bits + CHAR_BIT - 1) / CHAR_BIT;

	for (i = 0; i < bytes; i++) {
		result <<= CHAR_BIT;
		result += data[bytes - 1 - i];
	}

	return result;
}

uint64_t int48_to_long(const __u8 *data)
{
	return int_to_long(48, data);
}

uint64_t int56_to_long(const __u8 *data)
{
	return int_to_long(56, data);
}

const char *util_uuid_to_string(unsigned char uuid[NVME_UUID_LEN])
{
	static char uuid_str[NVME_UUID_LEN_STRING];

	libnvme_uuid_to_string(uuid, uuid_str);

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

