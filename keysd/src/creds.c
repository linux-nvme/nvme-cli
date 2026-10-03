// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <systemd/sd-json.h>
#include <systemd/sd-varlink.h>

#include <shared/cleanup-util.h>
#include <shared/fs-util.h>
#include <shared/string-util.h>

#include "creds.h"

#define CREDS_VARLINK_ADDRESS "/run/systemd/io.systemd.Credentials"
#define CREDS_VARLINK_DECRYPT "io.systemd.Credentials.Decrypt"

/*
 * Copy the base64 "data" field of @reply into @buf. The decoded copy is
 * cleared before it is freed.
 */
static int copy_plaintext(sd_json_variant *reply, char *buf, size_t size)
{
	sd_json_variant *data;
	void *plain = NULL;
	size_t plain_len = 0;
	int r;

	data = sd_json_variant_by_key(reply, "data");
	if (!data)
		return -EBADMSG;

	r = sd_json_variant_unbase64(data, &plain, &plain_len);
	if (r < 0)
		return r;

	if (plain_len >= size) {
		r = -EFBIG;
		goto out;
	}

	memcpy(buf, plain, plain_len);
	buf[plain_len] = '\0';
	shr_rtrim(buf);

out:
	explicit_bzero(plain, plain_len);
	free(plain);

	return r;
}

int creds_decrypt(const char *dir, const char *name, char *buf, size_t size,
		  char **error)
{
	__cleanup_free char *blob = NULL;
	sd_json_variant *reply = NULL;
	const char *error_id = NULL;
	sd_varlink *link = NULL;
	int r;

	*error = NULL;

	// The file holds the encrypted credential in base64.
	r = shr_read_file_as_string(dir, name, NULL, &blob);
	if (r < 0)
		return r;

	r = sd_varlink_connect_address(&link, CREDS_VARLINK_ADDRESS);
	if (r < 0)
		return r;

	// Clear the reply, which holds the plaintext, when it is freed.
	r = sd_varlink_set_input_sensitive(link);
	if (r < 0)
		goto out;

	r = sd_varlink_callbo(link, CREDS_VARLINK_DECRYPT, &reply, &error_id,
			      SD_JSON_BUILD_PAIR_STRING("name", name),
			      SD_JSON_BUILD_PAIR_STRING("blob", blob));
	if (r < 0)
		goto out;

	if (error_id) {
		*error = strdup(error_id);
		r = -EBADMSG;
		goto out;
	}

	r = copy_plaintext(reply, buf, size);

out:
	// The reply belongs to the link.
	sd_varlink_flush_close_unref(link);

	return r;
}
