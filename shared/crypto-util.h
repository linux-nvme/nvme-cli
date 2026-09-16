/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of nvme-cli.
 */
#pragma once

/*
 * Compute HMAC-SHA256 over data using key. Returns a newly allocated 32-byte
 * buffer the caller must free(), or NULL on failure.
 */
unsigned char *shr_hmac_sha256(unsigned char *data, int datalen,
		unsigned char *key, int keylen);

/*
 * Compute MD5 over data. Returns a newly allocated 16-byte buffer the caller
 * must free(), or NULL on failure.
 */
unsigned char *shr_md5(unsigned char *data, int datalen);

/*
 * Fill buf with len bytes from the platform's CSPRNG. Returns 0 on success,
 * -1 on failure (buf is left unmodified).
 */
int shr_getrandom(void *buf, unsigned int len);
