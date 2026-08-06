// SPDX-License-Identifier: GPL-2.0-or-later

#include <inttypes.h>

#include "types.h"

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

