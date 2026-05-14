// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2025 Micron Technology, Inc.
 *
 * Windows stub implementations for Linux-specific functionality
 * that is excluded from the Windows build (tree, filters, etc.)
 */

#include <errno.h>
#include <stdio.h>

#include <nvme/linux.h>
#include <nvme/types.h>

#include "private.h"
#include "tree.h"
#include "compiler-attributes.h"

/* Logging control for stub calls */
static int stub_log_enabled = 0;

static void stub_log(const char *func)
{
	if (stub_log_enabled)
		fprintf(stderr, "libnvme-stub: %s() called (not supported on Windows)\n", func);
}

void libnvme_stubs_set_debug(int enable)
{
	stub_log_enabled = enable;
}

/*
 * TLS/PSK key management stubs (linux.c functions)
 */
__libnvme_public int libnvme_export_tls_key_versioned(struct libnvme_global_ctx *ctx,
				  unsigned char version, unsigned char hmac,
				  const unsigned char *key_data,
				  size_t key_len, char **identity)
{
	stub_log(__func__);
	(void)ctx;
	(void)version;
	(void)hmac;
	(void)key_data;
	(void)key_len;
	(void)identity;
	errno = ENOTSUP;
	return -1;
}

__libnvme_public int libnvme_export_tls_key(struct libnvme_global_ctx *ctx,
	const unsigned char *key_data, int key_len, char **identity)
{
	stub_log(__func__);
	(void)ctx;
	(void)key_data;
	(void)key_len;
	(void)identity;
	errno = ENOTSUP;
	return -1;
}

__libnvme_public int libnvme_import_tls_key_versioned(struct libnvme_global_ctx *ctx,
				  const char *encoded_key,
				  unsigned char *version,
				  unsigned char *hmac,
				  size_t *key_len,
				  unsigned char **key)
{
	stub_log(__func__);
	(void)ctx;
	(void)encoded_key;
	(void)version;
	(void)hmac;
	(void)key_len;
	(void)key;
	errno = ENOTSUP;
	return -1;
}

__libnvme_public int libnvme_import_tls_key(struct libnvme_global_ctx *ctx, const char *encoded_key,
			int *key_len, unsigned int *hmac, unsigned char **key)
{
	stub_log(__func__);
	(void)ctx;
	(void)encoded_key;
	(void)key_len;
	(void)hmac;
	(void)key;
	errno = ENOTSUP;
	return -1;
}

/*
 * Linux keyring and TLS key management stubs (linux.c)
 * These are used by nvme-cli security commands
 */
__libnvme_public int libnvme_read_key(struct libnvme_global_ctx *ctx, long keyring_id,
		long key_id, int *len, unsigned char **key)
{
	stub_log(__func__);
	(void)ctx;
	(void)keyring_id;
	(void)key_id;
	(void)len;
	(void)key;
	errno = ENOTSUP;
	return -1;
}

__libnvme_public int libnvme_lookup_keyring(struct libnvme_global_ctx *ctx,
		const char *keyring, long *key)
{
	stub_log(__func__);
	(void)ctx;
	(void)keyring;
	(void)key;
	errno = ENOTSUP;
	return -1;
}

__libnvme_public int libnvme_update_key(struct libnvme_global_ctx *ctx, long keyring_id,
		const char *key_type, const char *identity,
		unsigned char *key_data, int key_len, long *key)
{
	stub_log(__func__);
	(void)ctx;
	(void)keyring_id;
	(void)key_type;
	(void)identity;
	(void)key_data;
	(void)key_len;
	(void)key;
	errno = ENOTSUP;
	return -1;
}

__libnvme_public int libnvme_revoke_tls_key(struct libnvme_global_ctx *ctx, const char *keyring,
		const char *key_type, const char *identity)
{
	stub_log(__func__);
	(void)ctx;
	(void)keyring;
	(void)key_type;
	(void)identity;
	errno = ENOTSUP;
	return -1;
}

__libnvme_public int libnvme_scan_tls_keys(struct libnvme_global_ctx *ctx, const char *keyring,
		libnvme_scan_tls_keys_cb_t cb, void *data)
{
	stub_log(__func__);
	(void)ctx;
	(void)keyring;
	(void)cb;
	(void)data;
	errno = ENOTSUP;
	return -1;
}

__libnvme_public char *libnvme_describe_key_serial(struct libnvme_global_ctx *ctx,
		long key_id)
{
	stub_log(__func__);
	(void)ctx;
	(void)key_id;
	return NULL;
}

__libnvme_public int libnvme_insert_tls_key_versioned(struct libnvme_global_ctx *ctx,
		const char *keyring, const char *key_type,
		const char *hostnqn, const char *subsysnqn,
		int version, int hmac,
		unsigned char *configured_key, int key_len,
		long *key)
{
	stub_log(__func__);
	(void)ctx;
	(void)keyring;
	(void)key_type;
	(void)hostnqn;
	(void)subsysnqn;
	(void)version;
	(void)hmac;
	(void)configured_key;
	(void)key_len;
	(void)key;
	errno = ENOTSUP;
	return -1;
}

__libnvme_public int libnvme_generate_tls_key_identity_compat(struct libnvme_global_ctx *ctx,
		const char *hostnqn, const char *subsysnqn,
		int version, int hmac, unsigned char *configured_key,
		int key_len, char **identity)
{
	stub_log(__func__);
	(void)ctx;
	(void)hostnqn;
	(void)subsysnqn;
	(void)version;
	(void)hmac;
	(void)configured_key;
	(void)key_len;
	(void)identity;
	errno = ENOTSUP;
	return -1;
}

__libnvme_public int libnvme_insert_tls_key_compat(struct libnvme_global_ctx *ctx,
		const char *keyring, const char *key_type,
		const char *hostnqn, const char *subsysnqn,
		int version, int hmac,
		unsigned char *configured_key, int key_len,
		long *key)
{
	stub_log(__func__);
	(void)ctx;
	(void)keyring;
	(void)key_type;
	(void)hostnqn;
	(void)subsysnqn;
	(void)version;
	(void)hmac;
	(void)configured_key;
	(void)key_len;
	(void)key;
	errno = ENOTSUP;
	return -1;
}

__libnvme_public int libnvme_generate_tls_key_identity(struct libnvme_global_ctx *ctx,
		const char *hostnqn, const char *subsysnqn,
		int version, int hmac,
		unsigned char *configured_key, int key_len,
		char **identity)
{
	stub_log(__func__);
	(void)ctx;
	(void)hostnqn;
	(void)subsysnqn;
	(void)version;
	(void)hmac;
	(void)configured_key;
	(void)key_len;
	(void)identity;
	errno = ENOTSUP;
	return -1;
}

__libnvme_public char *libnvme_read_hostnqn(void)
{
	stub_log(__func__);
	/* No /etc/nvme/hostnqn equivalent on Windows */
	return NULL;
}

__libnvme_public int libnvme_gen_dhchap_key(struct libnvme_global_ctx *ctx,
		char *hostnqn, enum libnvme_hmac_alg hmac,
		unsigned int key_len, unsigned char *secret,
		unsigned char *key)
{
	stub_log(__func__);
	(void)ctx;
	(void)hostnqn;
	(void)hmac;
	(void)key_len;
	(void)secret;
	(void)key;
	errno = ENOTSUP;
	return -1;
}

__libnvme_public int libnvme_create_raw_secret(struct libnvme_global_ctx *ctx,
		const char *secret, size_t key_len, unsigned char **raw_secret)
{
	stub_log(__func__);
	return -ENOTSUP;
}

/* Hostnqn generation */
__libnvme_public char *libnvme_generate_hostnqn(void)
{
	stub_log(__func__);
	/* Could implement UUID-based generation, but for now just fail */
	return NULL;
}
