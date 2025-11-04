// SPDX-License-Identifier: LGPL-2.1-or-later
/**
 * This file is part of libnvme.
 * Copyright (c) 2025 SUSE LLC.
 *
 * Authors: Daniel Wagner <wagi@kernel.org>
 */

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <stdio.h>
#include <string.h>

#define SHA256_LEN 32

static EVP_PKEY_CTX *setup_ctx(void)
{
	EVP_PKEY_CTX *ctx = NULL;
	const char *salt = "salt";
	const char *key = "key";

	ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	if (!ctx)
		return NULL;
	if (EVP_PKEY_derive_init(ctx) <= 0)
		goto free_ctx;
	if (EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) <= 0)
		goto free_ctx;
	if (EVP_PKEY_CTX_set1_hkdf_salt(ctx,
			(unsigned char *)salt, strlen(salt)) <= 0)
		goto free_ctx;
	if (EVP_PKEY_CTX_set1_hkdf_key(ctx,
			(unsigned char *)key, strlen(key)) <= 0)
		goto free_ctx;

	return ctx;

free_ctx:
	EVP_PKEY_CTX_free(ctx);
	return NULL;
}

int main(void)
{
	unsigned char out[SHA256_LEN], out2[SHA256_LEN];
	size_t len = sizeof(out);
	const char *a = "a";
	const char *b = "b";
	EVP_PKEY_CTX *ctx;

	/* out = A + B */
	ctx = setup_ctx();
	if (!ctx)
		return 1;
	if (EVP_PKEY_CTX_add1_hkdf_info(ctx,
			(unsigned char *)a, strlen(a)) <= 0)
		goto free_ctx;
	if (EVP_PKEY_CTX_add1_hkdf_info(ctx,
			(unsigned char *)b, strlen(b)) <= 0)
		goto free_ctx;
	if (EVP_PKEY_derive(ctx, out, &len) <= 0)
		goto free_ctx;
	EVP_PKEY_CTX_free(ctx);

	/* out = B */
	ctx = setup_ctx();
	if (!ctx)
		return 1;
	if (EVP_PKEY_CTX_add1_hkdf_info(ctx,
			(unsigned char *)b, strlen(b)) <= 0)
		goto free_ctx;
	if (EVP_PKEY_derive(ctx, out2, &len) <= 0)
		goto free_ctx;
	EVP_PKEY_CTX_free(ctx);

	printf("EVP_PKEY_CTX_add1_hkdf_info behavior: ");
	if (!memcmp(out, out2, len)) {
		printf("set\n");
		return 1;
	}

	printf("add\n");
	return 0;

free_ctx:
	EVP_PKEY_CTX_free(ctx);
	return 1;
}
