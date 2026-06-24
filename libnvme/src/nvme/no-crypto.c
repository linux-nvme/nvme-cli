// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2025 Micron Technology, Inc.
 *
 * Authors: Brandon Busacker <bbusacker@micron.com>
 */

#include <errno.h>

#include <nvme/crypto.h>

#include "compiler-attributes.h"

__libnvme_public int libnvmf_export_tls_key_versioned(struct libnvme_global_ctx *ctx,
				  unsigned char version, unsigned char hmac,
				  const unsigned char *key_data,
				  size_t key_len, char **identity)
{
	return -ENOTSUP;
}

__libnvme_public int libnvmf_export_tls_key(struct libnvme_global_ctx *ctx,
	const unsigned char *key_data, int key_len, char **identity)
{
	return -ENOTSUP;
}

__libnvme_public int libnvmf_import_tls_key_versioned(struct libnvme_global_ctx *ctx,
				  const char *encoded_key,
				  unsigned char *version,
				  unsigned char *hmac,
				  size_t *key_len,
				  unsigned char **key)
{
	return -ENOTSUP;
}

__libnvme_public int libnvmf_import_tls_key(struct libnvme_global_ctx *ctx, const char *encoded_key,
			int *key_len, unsigned int *hmac, unsigned char **key)
{
	return -ENOTSUP;
}

__libnvme_public int libnvmf_read_key(struct libnvme_global_ctx *ctx, long keyring_id,
		long key_id, int *len, unsigned char **key)
{
	return -ENOTSUP;
}

__libnvme_public int libnvmf_lookup_keyring(struct libnvme_global_ctx *ctx,
		const char *keyring, long *key)
{
	return -ENOTSUP;
}

__libnvme_public int libnvmf_update_key(struct libnvme_global_ctx *ctx, long keyring_id,
		const char *key_type, const char *identity,
		unsigned char *key_data, int key_len, long *key)
{
	return -ENOTSUP;
}

__libnvme_public int libnvmf_revoke_tls_key(struct libnvme_global_ctx *ctx, const char *keyring,
		const char *key_type, const char *identity)
{
	return -ENOTSUP;
}

__libnvme_public int libnvmf_scan_tls_keys(struct libnvme_global_ctx *ctx, const char *keyring,
		libnvmf_scan_tls_keys_cb_t cb, void *data)
{
	return -ENOTSUP;
}

__libnvme_public char *libnvmf_describe_key_serial(struct libnvme_global_ctx *ctx,
		long key_id)
{
	return NULL;
}

__libnvme_public int libnvmf_insert_tls_key_versioned(struct libnvme_global_ctx *ctx,
		const char *keyring, const char *key_type,
		const char *hostnqn, const char *subsysnqn,
		int version, int hmac,
		unsigned char *configured_key, int key_len,
		long *key)
{
	return -ENOTSUP;
}

__libnvme_public int libnvmf_generate_tls_key_identity_compat(struct libnvme_global_ctx *ctx,
		const char *hostnqn, const char *subsysnqn,
		int version, int hmac, unsigned char *configured_key,
		int key_len, char **identity)
{
	return -ENOTSUP;
}

__libnvme_public int libnvmf_insert_tls_key_compat(struct libnvme_global_ctx *ctx,
		const char *keyring, const char *key_type,
		const char *hostnqn, const char *subsysnqn,
		int version, int hmac,
		unsigned char *configured_key, int key_len,
		long *key)
{
	return -ENOTSUP;
}

__libnvme_public int libnvmf_generate_tls_key_identity(struct libnvme_global_ctx *ctx,
		const char *hostnqn, const char *subsysnqn,
		int version, int hmac,
		unsigned char *configured_key, int key_len,
		char **identity)
{
	return -ENOTSUP;
}

__libnvme_public int libnvmf_gen_dhchap_key(struct libnvme_global_ctx *ctx,
		char *hostnqn, enum libnvmf_hmac_alg hmac,
		unsigned int key_len, unsigned char *secret,
		unsigned char *key)
{
	return -ENOTSUP;
}

__libnvme_public int libnvmf_create_raw_secret(struct libnvme_global_ctx *ctx,
		const char *secret, size_t key_len, unsigned char **raw_secret)
{
	return -ENOTSUP;
}
