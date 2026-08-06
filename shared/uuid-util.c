// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 */

#include <stdio.h>

#include "uuid-util.h"

const char *shr_uuid_to_string(unsigned char uuid[SHR_UUID_LEN])
{
	static char str[SHR_UUID_LEN_STRING];

	snprintf(str, sizeof(str),
		 "%02x%02x%02x%02x-%02x%02x-%02x%02x-"
		 "%02x%02x-%02x%02x%02x%02x%02x%02x",
		 uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5],
		 uuid[6], uuid[7], uuid[8], uuid[9], uuid[10], uuid[11],
		 uuid[12], uuid[13], uuid[14], uuid[15]);

	return str;
}

const char *shr_fw_to_string(char *c)
{
	static char ret[9];
	int i;

	for (i = 0; i < 8; i++)
		ret[i] = c[i] >= '!' && c[i] <= '~' ? c[i] : '.';
	ret[i] = '\0';
	return ret;
}
