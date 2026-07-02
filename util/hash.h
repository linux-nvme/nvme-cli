/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

/*
 * Compute HMAC-SHA256 over data using key. Returns a newly allocated 32-byte
 * buffer the caller must free(), or NULL on failure.
 */
unsigned char *create_hmac_sha256(unsigned char *data, int datalen,
		unsigned char *key, int keylen);

/*
 * Compute MD5 over data. Returns a newly allocated 16-byte buffer the caller
 * must free(), or NULL on failure.
 */
unsigned char *create_md5(unsigned char *data, int datalen);
