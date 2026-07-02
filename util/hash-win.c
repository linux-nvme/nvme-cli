// SPDX-License-Identifier: GPL-2.0-or-later
#include <stdlib.h>

#include <windows.h>
#include <bcrypt.h>

#include "hash.h"

#define HMAC_SHA256_ALGO_NAME		BCRYPT_SHA256_ALGORITHM
#define MD5_HASH_ALGO_NAME		BCRYPT_MD5_ALGORITHM
#define HMAC_SHA256_HASH_SIZE		32
#define MD5_HASH_HASH_SIZE		16

/*
 * Utility function to create hash value of given data (with given key) using
 * given hash algorithm; this function uses Windows BCrypt services
 */
static unsigned char *create_hash(LPCWSTR algo, int hash_size,
		unsigned char *data, int datalen, unsigned char *key,
		int keylen)
{
	BCRYPT_ALG_HANDLE alg_handle = NULL;
	BCRYPT_HASH_HANDLE hash_handle = NULL;
	unsigned char *hash = NULL;
	NTSTATUS status;
	ULONG flags = 0;

	if (key != NULL && keylen > 0)
		flags = BCRYPT_ALG_HANDLE_HMAC_FLAG;

	status = BCryptOpenAlgorithmProvider(&alg_handle, algo, NULL, flags);
	if (!BCRYPT_SUCCESS(status))
		goto out;

	status = BCryptCreateHash(alg_handle, &hash_handle, NULL, 0,
				  key, keylen, 0);
	if (!BCRYPT_SUCCESS(status))
		goto out;

	status = BCryptHashData(hash_handle, data, datalen, 0);
	if (!BCRYPT_SUCCESS(status))
		goto out;

	hash = (unsigned char *)calloc(hash_size, 1);
	if (!hash)
		goto out;

	status = BCryptFinishHash(hash_handle, hash, hash_size, 0);
	if (!BCRYPT_SUCCESS(status)) {
		free(hash);
		hash = NULL;
	}

out:
	if (hash_handle)
		BCryptDestroyHash(hash_handle);
	if (alg_handle)
		BCryptCloseAlgorithmProvider(alg_handle, 0);

	return hash;
}

/* Function that computes hmac-sha256 hash of given data and key pair. Returns
 * byte stream (non-null terminated) upon success, NULL otherwise.
 */
unsigned char *create_hmac_sha256(unsigned char *data, int datalen,
		unsigned char *key, int keylen)
{
	return create_hash(HMAC_SHA256_ALGO_NAME,
			   HMAC_SHA256_HASH_SIZE,
			   data,
			   datalen,
			   key,
			   keylen);
}

/* Function that computes md5 of given buffer.
 * Returns byte stream (non-null terminated) upon success, NULL otherwise.
 */
unsigned char *create_md5(unsigned char *data, int datalen)
{
	return create_hash(MD5_HASH_ALGO_NAME,
			   MD5_HASH_HASH_SIZE,
			   data,
			   datalen,
			   NULL,
			   0);
}
