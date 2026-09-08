// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "cleanup-util.h"
#include "machine-id-util.h"
#include "sha256-util.h"

#define MACHINE_ID_LEN_STRING	32

static int parse_hex_digit(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;

	return -EINVAL;
}

static int read_machine_id(const char *path, unsigned char id[SHR_UUID_LEN])
{
	char buf[MACHINE_ID_LEN_STRING + 2] = {};
	__cleanup_file FILE *f = NULL;
	bool all_zero = true;
	size_t len, i;

	f = fopen(path, "re");
	if (!f)
		return -errno;

	/*
	 * An empty file, and the "uninitialized" marker systemd writes during
	 * the first boot of an image, are both too short to parse.
	 */
	len = fread(buf, 1, sizeof(buf) - 1, f);
	if (len < MACHINE_ID_LEN_STRING)
		return -EINVAL;

	for (i = 0; i < SHR_UUID_LEN; i++) {
		int hi = parse_hex_digit(buf[i * 2]);
		int lo = parse_hex_digit(buf[i * 2 + 1]);

		if (hi < 0 || lo < 0)
			return -EINVAL;

		id[i] = (hi << 4) | lo;
		if (id[i])
			all_zero = false;
	}

	return all_zero ? -EINVAL : 0;
}

int shr_machine_id_app_specific(const char *path,
		const unsigned char app_id[SHR_UUID_LEN],
		unsigned char out[SHR_UUID_LEN])
{
	unsigned char hmac[SHR_SHA256_DIGEST_SIZE];
	unsigned char id[SHR_UUID_LEN];
	int ret;

	if (!path || !app_id || !out)
		return -EINVAL;

	ret = read_machine_id(path, id);
	if (ret)
		return ret;

	shr_hmac_sha256_raw(id, sizeof(id), app_id, SHR_UUID_LEN, hmac);

	/* Keep the first half only. */
	memcpy(out, hmac, SHR_UUID_LEN);

	/* RFC 9562: version 4, variant DCE. */
	out[6] = (out[6] & 0x0f) | 0x40;
	out[8] = (out[8] & 0x3f) | 0x80;

	return 0;
}
