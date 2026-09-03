// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <ctype.h>
#include <string.h>

#include "nqn-util.h"
#include "uuid-util.h"

#define NQN_PREFIX	"nqn."
#define NQN_UUID_PREFIX	"nqn.2014-08.org.nvmexpress:uuid:"

/* Length of a "yyyy-mm" date code. */
#define NQN_DATE_LEN	7

/* A "yyyy-mm" date code, as in "2014-08". */
static bool date_code_valid(const char *p)
{
	int i;

	for (i = 0; i < 4; i++) {
		if (!isdigit((unsigned char)p[i]))
			return false;
	}

	if (p[4] != '-')
		return false;

	return isdigit((unsigned char)p[5]) && isdigit((unsigned char)p[6]);
}

bool shr_nqn_valid(const char *nqn)
{
	const char *p;
	size_t len;

	if (!nqn)
		return false;

	len = strlen(nqn);
	if (len > SHR_NQN_MAX_LEN)
		return false;

	if (strncmp(nqn, NQN_PREFIX, strlen(NQN_PREFIX)))
		return false;

	if (!strncmp(nqn, NQN_UUID_PREFIX, strlen(NQN_UUID_PREFIX)))
		return shr_uuid_str_valid(nqn + strlen(NQN_UUID_PREFIX));

	/* "nqn." + "yyyy-mm" + "." + at least one more character */
	if (len < strlen(NQN_PREFIX) + NQN_DATE_LEN + 2)
		return false;

	p = nqn + strlen(NQN_PREFIX);

	return date_code_valid(p) && p[NQN_DATE_LEN] == '.';
}
