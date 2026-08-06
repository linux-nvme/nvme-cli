// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE LLC
 *
 * Authors: Daniel Wagner <dwagner@suse.com>
 */
#include <stdio.h>
#include <stdlib.h>

#include "crypto-util.h"

#ifdef CONFIG_OPENSSL
#include <openssl/evp.h>

#define HMAC_SHA256_HASH_SIZE	32
#define MD5_HASH_SIZE		16

/*
 * Function that computes hmac-sha256 hash of given data and key pair. Returns
 * byte stream (non-null terminated) upon success, NULL otherwise.
 */
unsigned char *shr_hmac_sha256(unsigned char *data, int datalen,
		unsigned char *key, int keylen)
{
	unsigned char *hash;
	size_t hash_len;

	hash = calloc(HMAC_SHA256_HASH_SIZE, 1);
	if (!hash)
		return NULL;

	if (!EVP_Q_mac(NULL, "HMAC", NULL, "SHA256", NULL,
		       key, keylen, data, datalen, hash,
		       HMAC_SHA256_HASH_SIZE, &hash_len) ||
	    hash_len != HMAC_SHA256_HASH_SIZE) {
		free(hash);
		return NULL;
	}

	return hash;
}

/*
 * Function that computes md5 of given buffer.
 * Returns byte stream (non-null terminated) upon success, NULL otherwise.
 */
unsigned char *shr_md5(unsigned char *data, int datalen)
{
	unsigned char *hash;
	unsigned int hash_len;

	hash = calloc(MD5_HASH_SIZE, 1);
	if (!hash)
		return NULL;

	if (!EVP_Digest(data, datalen, hash, &hash_len, EVP_md5(), NULL) ||
	    hash_len != MD5_HASH_SIZE) {
		free(hash);
		return NULL;
	}

	return hash;
}
#else /* CONFIG_OPENSSL */
unsigned char *shr_hmac_sha256(unsigned char *data, int datalen,
		unsigned char *key, int keylen)
{
	fprintf(stderr, "%s: nvme-cli was built without OpenSSL support\n", __func__);
	return NULL;
}

unsigned char *shr_md5(unsigned char *data, int datalen)
{
	fprintf(stderr, "%s: nvme-cli was built without OpenSSL support\n", __func__);
	return NULL;
}
#endif /* CONFIG_OPENSSL */
