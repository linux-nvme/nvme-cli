// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 * 	    Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 */

#include <errno.h>
#include <fcntl.h>
#ifndef _GNU_SOURCE
#include <libgen.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>

#include <sys/ioctl.h>
#include <sys/param.h>
#if HAVE_SYS_RANDOM
#include <sys/random.h>
#endif
#include <sys/stat.h>

#ifndef _GNU_SOURCE
#include <libgen.h>
#endif

#ifdef CONFIG_OPENSSL
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#endif

#ifdef CONFIG_KEYUTILS
#include <keyutils.h>

#define NVME_TLS_DEFAULT_KEYRING ".nvme"
#endif

#include <ccan/endian/endian.h>

#include <libnvme.h>

#include "crc32.h"
#include "base64.h"
#include "cleanup.h"
#include "private.h"
#include "compiler-attributes.h"

#define NVMF_HOSTID_SIZE	37

#define NVMF_HOSTNQN_FILE	SYSCONFDIR "/nvme/hostnqn"
#define NVMF_HOSTID_FILE	SYSCONFDIR "/nvme/hostid"

static int __nvme_set_attr(const char *path, const char *value)
{
	__cleanup_fd int fd = -1;

	fd = open(path, O_WRONLY);
	if (fd < 0) {
#if 0
		libnvme_msg(LOG_DEBUG, "Failed to open %s: %s\n", path,
			 strerror(errno));
#endif
		return -errno;
	}
	return write(fd, value, strlen(value));
}

int libnvme_set_attr(const char *dir, const char *attr, const char *value)
{
	__cleanup_free char *path = NULL;
	int ret;

	ret = asprintf(&path, "%s/%s", dir, attr);
	if (ret < 0)
		return -ENOMEM;

	return __nvme_set_attr(path, value);
}

static char *__nvme_get_attr(const char *path)
{
	char value[4096] = { 0 };
	int ret, fd;
	int saved_errno;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return NULL;

	ret = read(fd, value, sizeof(value) - 1);
	saved_errno = errno;
	close(fd);
	if (ret < 0) {
		errno = saved_errno;
		return NULL;
	}
	errno = 0;
	if (!strlen(value))
		return NULL;

	if (value[strlen(value) - 1] == '\n')
		value[strlen(value) - 1] = '\0';
	while (strlen(value) > 0 && value[strlen(value) - 1] == ' ')
		value[strlen(value) - 1] = '\0';

	return strlen(value) ? strdup(value) : NULL;
}

__public char *libnvme_get_attr(const char *dir, const char *attr)
{
	__cleanup_free char *path = NULL;
	int ret;

	ret = asprintf(&path, "%s/%s", dir, attr);
	if (ret < 0)
		return NULL;

	return __nvme_get_attr(path);
}

__public char *libnvme_get_subsys_attr(libnvme_subsystem_t s, const char *attr)
{
	return libnvme_get_attr(libnvme_subsystem_get_sysfs_dir(s), attr);
}

__public char *libnvme_get_ctrl_attr(libnvme_ctrl_t c, const char *attr)
{
	return libnvme_get_attr(libnvme_ctrl_get_sysfs_dir(c), attr);
}

__public char *libnvme_get_ns_attr(libnvme_ns_t n, const char *attr)
{
	return libnvme_get_attr(libnvme_ns_get_sysfs_dir(n), attr);
}

__public char *libnvme_get_path_attr(libnvme_path_t p, const char *attr)
{
	return libnvme_get_attr(libnvme_path_get_sysfs_dir(p), attr);
}

#ifndef CONFIG_OPENSSL
static unsigned char default_hmac(size_t key_len)
{
	return LIBNVME_HMAC_ALG_NONE;
}

__public int libnvme_gen_dhchap_key(struct libnvme_global_ctx *ctx,
		char *hostnqn, enum libnvme_hmac_alg hmac,
		unsigned int key_len, unsigned char *secret,
		unsigned char *key)
{
	if (hmac != LIBNVME_HMAC_ALG_NONE) {
		libnvme_msg(ctx, LOG_ERR, "HMAC transformation not supported; "
			"recompile with OpenSSL support.\n");
		return -EINVAL;
	}

	memcpy(key, secret, key_len);
	return 0;
}

__public int libnvme_create_raw_secret(struct libnvme_global_ctx *ctx,
		const char *secret, size_t key_len, unsigned char **raw_secret)
{
	libnvme_msg(ctx, LOG_ERR, "NVMe TLS 2.0 is not supported; "
		 "recompile with OpenSSL support.\n");
	return -ENOTSUP;
}

static int derive_retained_key(struct libnvme_global_ctx *ctx,
		int hmac, const char *hostnqn, unsigned char *generated,
		unsigned char *retained, size_t key_len)
{
	libnvme_msg(ctx, LOG_ERR, "NVMe TLS is not supported; "
		 "recompile with OpenSSL support.\n");
	return -ENOTSUP;
}

static int derive_retained_key_compat(struct libnvme_global_ctx *ctx,
		int hmac, const char *hostnqn, unsigned char *generated,
		unsigned char *retained, size_t key_len)
{
	libnvme_msg(ctx, LOG_ERR, "NVMe TLS is not supported; "
		 "recompile with OpenSSL support.\n");
	return -ENOTSUP;
}

static int derive_psk_digest(struct libnvme_global_ctx *ctx,
		const char *hostnqn, const char *subsysnqn,
		int version, int cipher,
		unsigned char *retained, size_t key_len,
		char *digest, size_t digest_len)
{
	libnvme_msg(ctx, LOG_ERR, "NVMe TLS 2.0 is not supported; "
		 "recompile with OpenSSL support.\n");
	return -ENOTSUP;
}

static int derive_tls_key(struct libnvme_global_ctx *ctx,
		int version, unsigned char cipher, const char *context,
		unsigned char *retained, unsigned char *psk, size_t key_len)
{
	libnvme_msg(ctx, LOG_ERR, "NVMe TLS is not supported; "
		 "recompile with OpenSSL support.\n");
	return -ENOTSUP;
}

static int derive_tls_key_compat(struct libnvme_global_ctx *ctx,
		int version, unsigned char cipher, const char *context,
		unsigned char *retained, unsigned char *psk, size_t key_len)
{
	libnvme_msg(ctx, LOG_ERR, "NVMe TLS is not supported; "
		 "recompile with OpenSSL support.\n");
	return -ENOTSUP;
}
#else /* CONFIG_OPENSSL */
static unsigned char default_hmac(size_t key_len)
{
	unsigned char hmac = LIBNVME_HMAC_ALG_NONE;

	switch (key_len) {
	case 32:
		hmac = LIBNVME_HMAC_ALG_SHA2_256;
		break;
	case 48:
		hmac = LIBNVME_HMAC_ALG_SHA2_384;
		break;
	case 64:
		hmac = LIBNVME_HMAC_ALG_SHA2_512;
		break;
	default:
		break;
	}
	return hmac;
}

static const EVP_MD *select_hmac(int hmac, size_t *hmac_len)
{
	const EVP_MD *md = NULL;

	switch (hmac) {
	case LIBNVME_HMAC_ALG_SHA2_256:
		md = EVP_sha256();
		*hmac_len = 32;
		break;
	case LIBNVME_HMAC_ALG_SHA2_384:
		md = EVP_sha384();
		*hmac_len = 48;
		break;
	default:
		*hmac_len = 0;
		break;
	}
	return md;
}

static DEFINE_CLEANUP_FUNC(
	cleanup_evp_pkey_ctx, EVP_PKEY_CTX *, EVP_PKEY_CTX_free)
#define __cleanup_evp_pkey_ctx __cleanup(cleanup_evp_pkey_ctx)

/* NVMe is using the TLS 1.3 HkdfLabel structure */
#define HKDF_INFO_MAX_LEN 514
#define HKDF_INFO_LABEL_MAX 256
#define HKDF_INFO_CONTEXT_MAX 256

/*
 * derive_retained_key()
 *
 * Derive a retained key according to NVMe TCP Transport specification:
 *
 * The retained PSK is derived from the configured PSK. The configured PSK
 * shall be destroyed as soon as the retained PSK is generated and stored.
 * Each NVMe/TCP entity shall support:
 * 1) transforming the configured PSK into a retained PSK before it is stored
 *    by the NVMe/TCP entity for repeated use with another NVMe/TCP entity; and
 * 2) using the configured PSK as a retained PSK.
 *
 * The method to derive a retained PSK from a configured PSK shall be using
 * the HKDF-Extract and HKDF-Expand-Label operations (refer to RFC 5869 and
 * RFC 8446):
 * 1. PRK = HKDF-Extract(0, Configured PSK); and
 * 2. Retained PSK = HKDF-Expand-Label(PRK, “HostNQN”, NQNh,
 *                                     Length(Configured PSK)),
 * where NQNh is the NQN of the host.
 *
 * 'hmac' indicates the hash function to be used to transform the configured
 * PSK in a retained PSK, encoded as follows:
 *
 * - 0 indicates no transform (i.e., the configured PSK is used as a
 *   retained PSK)
 * - 1 indicates SHA-256
 * - 2 indicates SHA-384
 */
static int derive_retained_key(struct libnvme_global_ctx *ctx,
		int hmac, const char *hostnqn,
		unsigned char *configured, unsigned char *retained,
		size_t key_len)
{
	__cleanup_evp_pkey_ctx EVP_PKEY_CTX *ectx = NULL;
	__cleanup_free uint8_t *hkdf_info = NULL;
	char *hkdf_label;
	const EVP_MD *md;
	size_t hmac_len;
	char *pos;
	int ret;

	/* +1 byte so that the snprintf terminating null can not overflow */
	hkdf_info = malloc(HKDF_INFO_MAX_LEN + 1);
	if (!hkdf_info)
		return -ENOMEM;

	if (hmac == LIBNVME_HMAC_ALG_NONE) {
		memcpy(retained, configured, key_len);
		return key_len;
	}

	md = select_hmac(hmac, &hmac_len);
	if (!md || !hmac_len)
		return -EINVAL;

	ectx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	if (!ectx)
		return -ENOMEM;

	if (EVP_PKEY_derive_init(ectx) <= 0)
		return -ENOMEM;

	if (EVP_PKEY_CTX_set_hkdf_md(ectx, md) <= 0)
		return -ENOKEY;

	if (EVP_PKEY_CTX_set1_hkdf_key(ectx, configured, key_len) <= 0)
		return -ENOKEY;

	if (key_len > USHRT_MAX)
		return -EINVAL;

	pos = (char *)hkdf_info;
	*(uint16_t *)pos = htons(key_len & 0xFFFF);
	pos += sizeof(uint16_t);

	hkdf_label = "tls13 HostNQN";
	ret = snprintf(pos, HKDF_INFO_LABEL_MAX + 1, "%c%s",
		       (int)strlen(hkdf_label), hkdf_label);
	if (ret <= 0 || ret > HKDF_INFO_LABEL_MAX)
		return -ENOKEY;
	pos += ret;

	ret = snprintf(pos, HKDF_INFO_CONTEXT_MAX + 1, "%c%s",
		       (int)strlen(hostnqn), hostnqn);
	if (ret <= 0 || ret > HKDF_INFO_CONTEXT_MAX)
		return -ENOKEY;
	pos += ret;

	if (EVP_PKEY_CTX_add1_hkdf_info(ectx, hkdf_info,
					(pos - (char *)hkdf_info)) <= 0)
		return -ENOKEY;

	if (EVP_PKEY_derive(ectx, retained, &key_len) <= 0)
		return -ENOKEY;

	return key_len;
}

static int derive_retained_key_compat(struct libnvme_global_ctx *ctx,
		int hmac, const char *hostnqn, unsigned char *configured,
		unsigned char *retained, size_t key_len)
{
	__cleanup_evp_pkey_ctx EVP_PKEY_CTX *ectx = NULL;
	__cleanup_free uint8_t *hkdf_info = NULL;
	const EVP_MD *md;
	size_t hmac_len;
	char *pos;
	int ret;

	if (hmac == LIBNVME_HMAC_ALG_NONE) {
		memcpy(retained, configured, key_len);
		return key_len;
	}

	md = select_hmac(hmac, &hmac_len);
	if (!md || !hmac_len)
		return -EINVAL;

	ectx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	if (!ectx)
		return -ENOMEM;

	if (EVP_PKEY_derive_init(ectx) <= 0)
		return -ENOMEM;

	if (EVP_PKEY_CTX_set_hkdf_md(ectx, md) <= 0)
		return -ENOKEY;

	if (EVP_PKEY_CTX_set1_hkdf_key(ectx, configured, key_len) <= 0)
		return -ENOKEY;

	/* +1 byte so that the snprintf terminating null can not overflow */
	hkdf_info = malloc(HKDF_INFO_MAX_LEN + 1);
	if (!hkdf_info)
		return -ENOMEM;

	pos = (char *)hkdf_info;
	*(uint16_t *)pos = cpu_to_le16(key_len);
	pos += sizeof(uint16_t);

	ret = snprintf(pos, HKDF_INFO_LABEL_MAX + 1,
		       "tls13 HostNQN%s", hostnqn);
	if (ret <= 0 || ret > HKDF_INFO_LABEL_MAX)
		return -ENOKEY;
	pos += ret;

	if (EVP_PKEY_CTX_add1_hkdf_info(ectx, hkdf_info,
					(pos - (char *)hkdf_info)) <= 0)
		return -ENOKEY;

	if (EVP_PKEY_derive(ectx, retained, &key_len) <= 0)
		return -ENOKEY;

	return key_len;
}

/*
 * derive_tls_key()
 *
 * Derive a TLS PSK from a retained PSK.
 *
 * The TLS PSK shall be derived as follows from an input PSK (i.e., either
 * a retained PSK or a generated PSK) and a PSK identity using the HKDF-Extract
 * and HKDF-Expand-Label operations (refer to RFC 5869 and RFC 8446) where the
 * hash function is the one specified by the hash specifier of the PSK identity:
 * 1. PRK = HKDF-Extract(0, Input PSK); and
 * 2. TLS PSK = HKDF-Expand-Label(PRK, “nvme-tls-psk”, PskIdentity, L),
 * where PskIdentity is the PSK identity and L is the output size in bytes of
 * the hash function (i.e., 32 for SHA-256 and 48 for SHA-384).
 *
 * Note that this is _not_ the hash value as specified by the configured key,
 * but rather the hash function of the cipher suite associated with the
 * PSK:
 * - 1 indicates SHA-245 (for the TLS_AES_128_GCM_SHA256 cipher suite)
 * - 2 indicates SHA-384 (for the TLS_AES_256_GCM_SHA384 cipher suite)
 *
 * and the value '0' is invalid here.
 */

static int derive_tls_key(struct libnvme_global_ctx *ctx,
		int version, unsigned char cipher, const char *context,
		unsigned char *retained, unsigned char *psk, size_t key_len)
{
	__cleanup_evp_pkey_ctx EVP_PKEY_CTX *ectx = NULL;
	__cleanup_free uint8_t *hkdf_info = NULL;
	char *hkdf_label;
	const EVP_MD *md;
	size_t hmac_len;
	char *pos;
	int ret;

	/* +1 byte so that the snprintf terminating null can not overflow */
	hkdf_info = malloc(HKDF_INFO_MAX_LEN + 1);
	if (!hkdf_info)
		return -ENOMEM;

	md = select_hmac(cipher, &hmac_len);
	if (!md || !hmac_len)
		return -EINVAL;

	ectx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	if (!ectx)
		return -ENOMEM;

	if (EVP_PKEY_derive_init(ectx) <= 0)
		return -ENOMEM;

	if (EVP_PKEY_CTX_set_hkdf_md(ectx, md) <= 0)
		return -ENOKEY;

	if (EVP_PKEY_CTX_set1_hkdf_key(ectx, retained, key_len) <= 0)
		return -ENOKEY;

	if (key_len > USHRT_MAX)
		return -EINVAL;

	pos = (char *)hkdf_info;
	*(uint16_t *)pos = htons(key_len & 0xFFFF);
	pos += sizeof(uint16_t);

	hkdf_label = "tls13 nvme-tls-psk";
	ret = snprintf(pos, HKDF_INFO_LABEL_MAX + 1, "%c%s",
		       (int)strlen(hkdf_label), hkdf_label);
	if (ret <= 0 || ret > HKDF_INFO_LABEL_MAX)
		return -ENOKEY;
	pos += ret;

	switch (version) {
	case 0:
		ret = snprintf(pos, HKDF_INFO_CONTEXT_MAX + 1, "%c%s",
			       (int)strlen(context), context);
		if (ret <= 0 || ret > HKDF_INFO_CONTEXT_MAX)
			return -ENOKEY;
		pos += ret;
		break;
	case 1:
		ret = snprintf(pos, HKDF_INFO_CONTEXT_MAX + 1, "%c%02d %s",
			       (int)strlen(context) + 3, cipher, context);
		if (ret <= 0 || ret > HKDF_INFO_CONTEXT_MAX)
			return -ENOKEY;
		pos += ret;
		break;
	default:
		return -ENOKEY;
	}

	if (EVP_PKEY_CTX_add1_hkdf_info(ectx, hkdf_info,
					(pos - (char *)hkdf_info)) <= 0)
		return -ENOKEY;

	if (EVP_PKEY_derive(ectx, psk, &key_len) <= 0)
		return -ENOKEY;

	return key_len;
}

static int derive_tls_key_compat(struct libnvme_global_ctx *ctx,
		int version, unsigned char cipher, const char *context,
		unsigned char *retained, unsigned char *psk, size_t key_len)
{
	__cleanup_evp_pkey_ctx EVP_PKEY_CTX *ectx = NULL;
	__cleanup_free uint8_t *hkdf_info = NULL;
	const EVP_MD *md;
	size_t hmac_len;
	char *pos;
	int ret;

	md = select_hmac(cipher, &hmac_len);
	if (!md || !hmac_len)
		return -EINVAL;

	ectx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	if (!ectx)
		return -ENOMEM;

	if (EVP_PKEY_derive_init(ectx) <= 0)
		return -ENOMEM;

	if (EVP_PKEY_CTX_set_hkdf_md(ectx, md) <= 0)
		return -ENOKEY;

	if (EVP_PKEY_CTX_set1_hkdf_key(ectx, retained, key_len) <= 0)
		return -ENOKEY;

	/* +1 byte so that the snprintf terminating null can not overflow */
	hkdf_info = malloc(HKDF_INFO_MAX_LEN + 1);
	if (!hkdf_info)
		return -ENOMEM;

	pos = (char *)hkdf_info;
	*(uint16_t *)pos = cpu_to_le16(key_len);
	pos += sizeof(uint16_t);

	ret = snprintf(pos, HKDF_INFO_LABEL_MAX + 1, "tls13 nvme-tls-psk");
	if (ret <= 0 || ret > HKDF_INFO_LABEL_MAX)
		return -ENOKEY;
	pos += ret;

	switch (version) {
	case 0:
		ret = snprintf(pos, HKDF_INFO_CONTEXT_MAX + 1, "%s", context);
		if (ret <= 0 || ret > HKDF_INFO_CONTEXT_MAX)
			return -ENOKEY;
		pos += ret;
		break;
	case 1:
		ret = snprintf(pos, HKDF_INFO_CONTEXT_MAX + 1, "%02d %s",
			       cipher, context);
		if (ret <= 0 || ret > HKDF_INFO_CONTEXT_MAX)
			return -ENOKEY;
		pos += ret;
		break;
	default:
		return -ENOKEY;
	}

	if (EVP_PKEY_CTX_add1_hkdf_info(ectx, hkdf_info,
					(pos - (char *)hkdf_info)) <= 0)
		return -ENOKEY;

	if (EVP_PKEY_derive(ectx, psk, &key_len) <= 0)
		return -ENOKEY;

	return key_len;
}

static DEFINE_CLEANUP_FUNC(
	cleanup_ossl_lib_ctx, OSSL_LIB_CTX *, OSSL_LIB_CTX_free)
#define __cleanup_ossl_lib_ctx __cleanup(cleanup_ossl_lib_ctx)
static DEFINE_CLEANUP_FUNC(cleanup_evp_mac_ctx, EVP_MAC_CTX *, EVP_MAC_CTX_free)
#define __cleanup_evp_mac_ctx __cleanup(cleanup_evp_mac_ctx)
static DEFINE_CLEANUP_FUNC(cleanup_evp_mac, EVP_MAC *, EVP_MAC_free)
#define __cleanup_evp_mac __cleanup(cleanup_evp_mac)

__public int libnvme_gen_dhchap_key(struct libnvme_global_ctx *ctx,
		char *hostnqn, enum libnvme_hmac_alg hmac,
		unsigned int key_len, unsigned char *secret,
		unsigned char *key)
{
	const char hmac_seed[] = "NVMe-over-Fabrics";
	__cleanup_ossl_lib_ctx OSSL_LIB_CTX *lib_ctx = NULL;
	__cleanup_evp_mac_ctx EVP_MAC_CTX *mac_ctx = NULL;
	__cleanup_evp_mac EVP_MAC *mac = NULL;
	OSSL_PARAM params[2], *p = params;
	char *progq = NULL;
	char *digest;
	size_t len;

	lib_ctx = OSSL_LIB_CTX_new();
	if (!lib_ctx)
		return -ENOMEM;

	mac = EVP_MAC_fetch(lib_ctx, OSSL_MAC_NAME_HMAC, progq);
	if (!mac)
		return -ENOMEM;

	mac_ctx = EVP_MAC_CTX_new(mac);
	if (!mac_ctx)
		return -ENOMEM;

	switch (hmac) {
	case LIBNVME_HMAC_ALG_NONE:
		memcpy(key, secret, key_len);
		return 0;
	case LIBNVME_HMAC_ALG_SHA2_256:
		digest = OSSL_DIGEST_NAME_SHA2_256;
		break;
	case LIBNVME_HMAC_ALG_SHA2_384:
		digest = OSSL_DIGEST_NAME_SHA2_384;
		break;
	case LIBNVME_HMAC_ALG_SHA2_512:
		digest = OSSL_DIGEST_NAME_SHA2_512;
		break;
	default:
		return -EINVAL;
	}
	*p++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
						digest,
						0);
	*p = OSSL_PARAM_construct_end();

	if (!EVP_MAC_init(mac_ctx, secret, key_len, params))
		return -ENOKEY;

	if (!EVP_MAC_update(mac_ctx, (unsigned char *)hostnqn,
			    strlen(hostnqn)))
		return -ENOKEY;

	if (!EVP_MAC_update(mac_ctx, (unsigned char *)hmac_seed,
			    strlen(hmac_seed)))
		return -ENOKEY;

	if (!EVP_MAC_final(mac_ctx, key, &len, key_len))
		return -ENOKEY;

	if (len != key_len)
		return -EMSGSIZE;

	return 0;
}

static int derive_psk_digest(struct libnvme_global_ctx *ctx,
		const char *hostnqn, const char *subsysnqn,
		int version, int cipher,
		unsigned char *retained, size_t key_len,
		char *digest, size_t digest_len)
{
	static const char hmac_seed[] = "NVMe-over-Fabrics";
	__cleanup_ossl_lib_ctx OSSL_LIB_CTX *lib_ctx = NULL;
	__cleanup_evp_mac_ctx EVP_MAC_CTX *mac_ctx = NULL;
	__cleanup_free unsigned char *psk_ctx = NULL;
	__cleanup_evp_mac EVP_MAC *mac = NULL;
	OSSL_PARAM params[2], *p = params;
	size_t hmac_len;
	char *progq = NULL;
	char *dig = NULL;
	size_t len;

	lib_ctx = OSSL_LIB_CTX_new();
	if (!lib_ctx)
		return -ENOMEM;

	mac = EVP_MAC_fetch(lib_ctx, OSSL_MAC_NAME_HMAC, progq);
	if (!mac)
		return -ENOMEM;

	mac_ctx = EVP_MAC_CTX_new(mac);
	if (!mac_ctx)
		return -ENOMEM;

	switch (cipher) {
	case LIBNVME_HMAC_ALG_SHA2_256:
		dig = OSSL_DIGEST_NAME_SHA2_256;
		break;
	case LIBNVME_HMAC_ALG_SHA2_384:
		dig = OSSL_DIGEST_NAME_SHA2_384;
		break;
	default:
		return -EINVAL;
	}

	*p++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
						dig, 0);
	*p = OSSL_PARAM_construct_end();

	psk_ctx = malloc(key_len);
	if (!psk_ctx)
		return -ENOMEM;

	if (!EVP_MAC_init(mac_ctx, retained, key_len, params))
		return -ENOKEY;

	if (!EVP_MAC_update(mac_ctx, (unsigned char *)hostnqn,
			    strlen(hostnqn)))
		return -ENOKEY;

	if (!EVP_MAC_update(mac_ctx, (unsigned char *)" ", 1))
		return -ENOKEY;

	if (!EVP_MAC_update(mac_ctx, (unsigned char *)subsysnqn,
			    strlen(subsysnqn)))
		return -ENOKEY;

	if (!EVP_MAC_update(mac_ctx, (unsigned char *)" ", 1))
		return -ENOKEY;

	if (!EVP_MAC_update(mac_ctx, (unsigned char *)hmac_seed,
			    strlen(hmac_seed)))
		return -ENOKEY;

	if (!EVP_MAC_final(mac_ctx, psk_ctx, &hmac_len, key_len))
		return -ENOKEY;

	if (hmac_len > key_len)
		return -EMSGSIZE;

	if (hmac_len * 2 > digest_len)
		return -EINVAL;

	memset(digest, 0, digest_len);
	len = base64_encode(psk_ctx, hmac_len, digest);
	if (len < 0)
		return len;

	return strlen(digest);
}

static ssize_t getrandom_bytes(void *buf, size_t buflen)
{
	ssize_t result;
#if HAVE_SYS_RANDOM
	result = getrandom(buf, buflen, GRND_NONBLOCK);
#else
	__cleanup_fd int fd = -1;

	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0)
		return -errno;
	result = read(fd, buf, buflen);
#endif
	if (result < 0)
		return -errno;
	return result;
}

static ssize_t getswordfish(struct libnvme_global_ctx *ctx,
		const char *seed, void *buf, size_t buflen)
{
	unsigned char hash[EVP_MAX_MD_SIZE];
	EVP_MD_CTX *md_ctx;
	size_t copied = 0;

	md_ctx = EVP_MD_CTX_new();
	if (!md_ctx)
		return -ENOMEM;

	while (copied < buflen) {
		unsigned int counter = 0;
		unsigned int hash_len;
		size_t to_copy;

		if (EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL) != 1)
			goto err;

		EVP_DigestUpdate(md_ctx, seed, strlen(seed));
		EVP_DigestUpdate(md_ctx, &counter, sizeof(counter));

		if (EVP_DigestFinal_ex(md_ctx, hash, &hash_len) != 1)
			goto err;

		to_copy = buflen - copied;
		if (to_copy > hash_len)
			to_copy = hash_len;

		memcpy((unsigned char *)buf + copied, hash, to_copy);
		copied += to_copy;
		counter++;
	}

	EVP_MD_CTX_free(md_ctx);
	return buflen;

err:
	EVP_MD_CTX_free(md_ctx);
	return -EIO;
}

__public int libnvme_create_raw_secret(struct libnvme_global_ctx *ctx,
		const char *secret, size_t key_len, unsigned char **raw_secret)
{
	__cleanup_free unsigned char *buf = NULL;
	int secret_len = 0, i, err;
	unsigned int c;

	if (key_len != 32 && key_len != 48 && key_len != 64) {
		libnvme_msg(ctx, LOG_ERR, "Invalid key length %ld", key_len);
		return -EINVAL;
	}

	buf = malloc(key_len);
	if (!buf)
		return -ENOMEM;

	if (!secret) {
		err = getrandom_bytes(buf, key_len);
		if (err < 0)
			return err;

		goto out;
	}

	if (strlen(secret) < 4) {
		libnvme_msg(ctx, LOG_ERR, "Input secret too short\n");
		return -EINVAL;
	}

	if (!strncmp(secret, "pin:", 4)) {
		err = getswordfish(ctx, &secret[4], buf, key_len);
		if (err < 0)
			return err;

		goto out;
	}

	for (i = 0; i < strlen(secret); i += 2) {
		if (sscanf(&secret[i], "%02x", &c) != 1) {
			libnvme_msg(ctx, LOG_ERR,
				"Invalid secret '%s'", secret);
			return -EINVAL;
		}
		if (i >= key_len * 2) {
			libnvme_msg(ctx, LOG_ERR,
				"Skipping excess secret bytes\n");
			break;
		}
		buf[secret_len++] = (unsigned char)c;
	}
	if (secret_len != key_len) {
		libnvme_msg(ctx, LOG_ERR,
			"Invalid key length (%d bytes)\n", secret_len);
		return -EINVAL;
	}

out:
	*raw_secret = buf;
	buf = NULL;
	return 0;
}

#endif /* CONFIG_OPENSSL */

static int gen_tls_identity(const char *hostnqn, const char *subsysnqn,
			    int version, int cipher, char *digest,
			    char *identity)
{
	if (version == 0) {
		sprintf(identity, "NVMe%01dR%02d %s %s",
			version, cipher, hostnqn, subsysnqn);
		return strlen(identity);
	}
	if (version > 1 || !digest)
		return -EINVAL;

	sprintf(identity, "NVMe%01dR%02d %s %s %s",
		version, cipher, hostnqn, subsysnqn, digest);
	return strlen(identity);
}

static int derive_nvme_keys(struct libnvme_global_ctx *ctx,
		const char *hostnqn, const char *subsysnqn,
		char *identity, int version,
		int hmac, unsigned char *configured,
		unsigned char *psk, int key_len, bool compat)
{
	__cleanup_free unsigned char *retained = NULL;
	__cleanup_free char *digest = NULL;
	char *context = identity;
	unsigned char cipher;
	int ret = -1;

	if (!hostnqn || !subsysnqn || !identity || !psk)
		return -EINVAL;

	retained = malloc(key_len);
	if (!retained)
		return -ENOMEM;

	if (compat)
		ret = derive_retained_key_compat(ctx, hmac, hostnqn, configured,
						 retained, key_len);
	else
		ret = derive_retained_key(ctx, hmac, hostnqn, configured,
					  retained, key_len);
	if (ret < 0)
		return ret;

	if (hmac == LIBNVME_HMAC_ALG_NONE)
		cipher = default_hmac(key_len);
	else
		cipher = hmac;

	if (version == 1) {
		size_t digest_len = 2 * key_len;

		digest = malloc(digest_len);
		if (!digest)
			return -ENOMEM;

		ret = derive_psk_digest(ctx, hostnqn, subsysnqn, version,
					cipher, retained, key_len, digest,
					digest_len);
		if (ret < 0)
			return ret;
		context = digest;
	}
	ret = gen_tls_identity(hostnqn, subsysnqn, version, cipher,
			       digest, identity);
	if (ret < 0)
		return ret;
	if (compat)
		return derive_tls_key_compat(ctx, version, cipher, context,
			retained, psk, key_len);
	return derive_tls_key(ctx, version, cipher, context, retained,
			psk, key_len);
}

static ssize_t nvme_identity_len(int hmac, int version, const char *hostnqn,
				 const char *subsysnqn)
{
	ssize_t len;

	if (!hostnqn || !subsysnqn)
		return -EINVAL;

	len = strlen(hostnqn) + strlen(subsysnqn) + 12;
	if (version == 1) {
		len += 66;
		if (hmac == LIBNVME_HMAC_ALG_SHA2_384)
			len += 32;
	} else if (version > 1) {
		return -EINVAL;
	}
	return len;
}

__public int libnvme_generate_tls_key_identity(struct libnvme_global_ctx *ctx,
		const char *hostnqn, const char *subsysnqn,
		int version, int hmac,
		unsigned char *configured_key, int key_len,
		char **ident)
{
	__cleanup_free unsigned char *psk = NULL;
	__cleanup_free char *identity = NULL;
	ssize_t identity_len;
	int ret;

	identity_len = nvme_identity_len(hmac, version, hostnqn, subsysnqn);
	if (identity_len < 0)
		return -EINVAL;

	identity = malloc(identity_len);
	if (!identity)
		return -ENOMEM;

	psk = malloc(key_len);
	if (!psk)
		return -ENOMEM;

	memset(psk, 0, key_len);
	ret = derive_nvme_keys(ctx, hostnqn, subsysnqn, identity, version, hmac,
			       configured_key, psk, key_len, false);
	if (ret != key_len) {
		if (ret < 0)
			return ret;
		return -ENOKEY;
	}

	*ident = identity;
	identity = NULL;

	return 0;
}

__public int libnvme_generate_tls_key_identity_compat(struct libnvme_global_ctx *ctx,
		const char *hostnqn, const char *subsysnqn,
		int version, int hmac, unsigned char *configured_key,
		int key_len, char **ident)
{
	__cleanup_free unsigned char *psk = NULL;
	__cleanup_free char *identity = NULL;
	ssize_t identity_len;
	int ret;

	identity_len = nvme_identity_len(hmac, version, hostnqn, subsysnqn);
	if (identity_len < 0)
		return -EINVAL;

	identity = malloc(identity_len);
	if (!identity)
		return -ENOMEM;

	psk = malloc(key_len);
	if (!psk)
		return -ENOMEM;

	memset(psk, 0, key_len);
	ret = derive_nvme_keys(ctx, hostnqn, subsysnqn, identity, version, hmac,
			       configured_key, psk, key_len, true);
	if (ret != key_len) {
		if (ret < 0)
			return ret;
		return -ENOKEY;
	}

	*ident = identity;
	identity = NULL;

	return 0;
}

#ifdef CONFIG_KEYUTILS
__public int libnvme_lookup_keyring(struct libnvme_global_ctx *ctx, const char *keyring,
		long *key)
{
	key_serial_t keyring_id;

	if (!keyring)
		keyring = NVME_TLS_DEFAULT_KEYRING;
	keyring_id = find_key_by_type_and_desc("keyring", keyring, 0);
	if (keyring_id < 0)
		return -errno;

	*key = keyring_id;
	return 0;
}

__public char *libnvme_describe_key_serial(struct libnvme_global_ctx *ctx, long key_id)
{
	__cleanup_free char *str = NULL;
	char *last;

	if (keyctl_describe_alloc(key_id, &str) < 0)
		return NULL;

	last = strrchr(str, ';');
	if (!last)
		return NULL;

	last++;
	if (strlen(last) == 0)
		return NULL;

	return strdup(last);
}

__public int libnvme_lookup_key(struct libnvme_global_ctx *ctx, const char *type,
		const char *identity, long *keyp)
{
	key_serial_t key;

	key = keyctl_search(KEY_SPEC_SESSION_KEYRING, type, identity, 0);
	if (key < 0)
		return -errno;

	*keyp = key;
	return 0;
}

__public int libnvme_set_keyring(struct libnvme_global_ctx *ctx, long key_id)
{
	long err;

	if (key_id == 0) {
		if (libnvme_lookup_keyring(ctx, NULL, &key_id))
			return -ENOKEY;
	}

	err = keyctl_link(key_id, KEY_SPEC_SESSION_KEYRING);
	if (err < 0)
		return -errno;
	return 0;
}

__public int libnvme_read_key(struct libnvme_global_ctx *ctx, long keyring_id,
		long key_id, int *len, unsigned char **key)
{
	void *buffer;
	int ret;

	ret = libnvme_set_keyring(ctx, keyring_id);
	if (ret < 0)
		return ret;

	ret = keyctl_read_alloc(key_id, &buffer);
	if (ret < 0)
		return ret;

	*len = ret;
	*key = buffer;
	return 0;
}

__public int libnvme_update_key(struct libnvme_global_ctx *ctx, long keyring_id,
		const char *key_type, const char *identity,
		unsigned char *key_data, int key_len, long *keyp)
{
	long key;

	key = keyctl_search(keyring_id, key_type, identity, 0);
	if (key > 0) {
		if (keyctl_revoke(key) < 0)
			return -errno;
	}
	key = add_key(key_type, identity,
		      key_data, key_len, keyring_id);
	if (key < 0)
		return -errno;

	*keyp = key;
	return 0;
}

struct __scan_keys_data {
	struct libnvme_global_ctx *ctx;
	libnvme_scan_tls_keys_cb_t cb;
	key_serial_t keyring;
	void *data;
};

int __scan_keys_cb(key_serial_t parent, key_serial_t key, char *desc,
		int desc_len, void *data)
{
	struct __scan_keys_data *d = data;
	int ver, hmac, uid, gid, perm;
	char type, *ptr;

	if (desc_len < 6)
		return 0;
	if (sscanf(desc, "psk;%d;%d;%08x;NVMe%01d%c%02d %*s",
		   &uid, &gid, &perm, &ver, &type, &hmac) != 6)
		return 0;
	/* skip key type */
	ptr = strchr(desc, ';');
	if (!ptr)
		return 0;
	/* skip key uid */
	ptr = strchr(ptr + 1, ';');
	if (!ptr)
		return 0;
	/* skip key gid */
	ptr = strchr(ptr + 1, ';');
	if (!ptr)
		return 0;
	/* skip key permissions */
	ptr = strchr(ptr + 1, ';');
	if (!ptr)
		return 0;
	/* Only use the key description for the callback */
	(d->cb)(d->ctx, d->keyring, key, ptr + 1, strlen(ptr) - 1, d->data);
	return 1;
}

__public int libnvme_scan_tls_keys(struct libnvme_global_ctx *ctx, const char *keyring,
		libnvme_scan_tls_keys_cb_t cb, void *data)
{
	struct __scan_keys_data d;
	long keyring_id;
	int ret;

	ret = libnvme_lookup_keyring(ctx, keyring, &keyring_id);
	if (ret)
		return ret;

	if (!keyring_id)
		return -EINVAL;

	ret = libnvme_set_keyring(ctx, keyring_id);
	if (ret < 0)
		return ret;

	d.ctx = ctx;
	d.keyring = keyring_id;
	d.cb = cb;
	d.data = data;
	ret = recursive_key_scan(keyring_id, __scan_keys_cb, &d);
	return ret;
}

static int __nvme_insert_tls_key(struct libnvme_global_ctx *ctx,
		key_serial_t keyring_id, const char *key_type,
		const char *hostnqn, const char *subsysnqn,
		int version, int hmac, unsigned char *configured_key,
		int key_len, bool compat, long *keyp)
{
	__cleanup_free unsigned char *psk = NULL;
	__cleanup_free char *identity = NULL;
	ssize_t identity_len;
	long key;
	int ret;

	identity_len = nvme_identity_len(hmac, version, hostnqn, subsysnqn);
	if (identity_len < 0)
		return identity_len;

	identity = malloc(identity_len);
	if (!identity)
		return -ENOMEM;
	memset(identity, 0, identity_len);

	psk = malloc(key_len);
	if (!psk)
		return -ENOMEM;
	memset(psk, 0, key_len);
	ret = derive_nvme_keys(ctx, hostnqn, subsysnqn, identity, version, hmac,
			       configured_key, psk, key_len, compat);
	if (ret != key_len) {
		if (ret < 0)
			return ret;
		return -ENOKEY;
	}

	ret = libnvme_update_key(ctx, keyring_id, key_type, identity,
			      psk, key_len, &key);
	if (ret)
		return ret;

	*keyp = key;
	return 0;
}

__public int libnvme_insert_tls_key_versioned(struct libnvme_global_ctx *ctx,
		const char *keyring, const char *key_type,
		const char *hostnqn, const char *subsysnqn,
		int version, int hmac,
		unsigned char *configured_key, int key_len,
		long *key)
{
	long keyring_id;
	int ret;

	ret = libnvme_lookup_keyring(ctx, keyring, &keyring_id);
	if (ret)
		return ret;

	ret = libnvme_set_keyring(ctx, keyring_id);
	if (ret < 0)
		return 0;

	return __nvme_insert_tls_key(ctx, keyring_id, key_type,
		hostnqn, subsysnqn, version, hmac,
		configured_key, key_len, false, key);
}

__public int libnvme_insert_tls_key_compat(struct libnvme_global_ctx *ctx,
		const char *keyring, const char *key_type,
		const char *hostnqn, const char *subsysnqn,
		int version, int hmac,
		unsigned char *configured_key, int key_len,
		long *key)
{
	long keyring_id;
	int ret;

	ret = libnvme_lookup_keyring(ctx, keyring, &keyring_id);
	if (ret)
		return ret;

	ret = libnvme_set_keyring(ctx, keyring_id);
	if (ret < 0)
		return 0;

	return __nvme_insert_tls_key(ctx, keyring_id, key_type,
		hostnqn, subsysnqn, version, hmac,
		configured_key, key_len, true, key);
}

__public int libnvme_revoke_tls_key(struct libnvme_global_ctx *ctx,
		const char *keyring, const char *key_type,
		const char *identity)
{
	long keyring_id, key;
	int ret;

	ret = libnvme_lookup_keyring(ctx, keyring, &keyring_id);
	if (ret)
		return ret;

	key = keyctl_search(keyring_id, key_type, identity, 0);
	if (key < 0)
		return -errno;

	key = keyctl_revoke(key);
	if (key < 0)
		return -errno;

	return 0;
}

static int __nvme_import_tls_key(struct libnvme_global_ctx *ctx, long keyring_id,
		const char *hostnqn, const char *subsysnqn,
		const char *identity, const char *key,
		long *keyp)
{
	__cleanup_free unsigned char *key_data = NULL;
	unsigned char version;
	unsigned char hmac;
	size_t key_len;
	int ret;

	ret = libnvme_import_tls_key_versioned(ctx, key, &version,
					    &hmac, &key_len, &key_data);
	if (ret)
		return ret;

	if (hmac == LIBNVME_HMAC_ALG_NONE || !identity) {
		/*
		 * This is a configured key (hmac 0) or we don't know the
		 * identity and so the assumtion is it is also a
		 * configured key. Derive a new key and load the newly
		 * created key into the keystore.
		 */
		return __nvme_insert_tls_key(ctx, keyring_id, "psk",
			hostnqn, subsysnqn, version, hmac,
			key_data, key_len, false, keyp);
	}

	return libnvme_update_key(ctx, keyring_id, "psk", identity,
			      key_data, key_len, keyp);
}

int __libnvme_import_keys_from_config(libnvme_host_t h, libnvme_ctrl_t c,
		long *keyring_id, long *key_id)
{
	const char *hostnqn = libnvme_host_get_hostnqn(h);
	const char *subsysnqn = libnvme_ctrl_get_subsysnqn(c);
	const char *keyring, *key, *identity;
	long kr_id = 0, id = 0;
	int ret;

	if (!hostnqn || !subsysnqn) {
		libnvme_msg(h->ctx, LOG_ERR, "Invalid NQNs (%s, %s)\n",
			 hostnqn, subsysnqn);
		return -EINVAL;
	}

	/* If we don't have a key avoid all keyring operations */
	key = libnvme_ctrl_get_tls_key(c);
	if (!key)
		goto out;

	keyring = libnvme_ctrl_get_keyring(c);
	if (keyring) {
		ret = libnvme_lookup_keyring(h->ctx, keyring, &kr_id);
		if (ret)
			return ret;
	} else
		kr_id = c->cfg.keyring;

	/*
	 * Fallback to the default keyring. Note this will also add the
	 * keyring to connect command line and to the JSON config output.
	 * That means we are explicitly selecting the keyring.
	 */
	if (!kr_id) {
		ret = libnvme_lookup_keyring(h->ctx, ".nvme", &kr_id);
		if (ret)
			return ret;
	}

	if (libnvme_set_keyring(h->ctx, kr_id) < 0) {
		libnvme_msg(h->ctx, LOG_ERR, "Failed to set keyring\n");
		return -errno;
	}

	identity = libnvme_ctrl_get_tls_key_identity(c);
	if (identity) {
		ret = libnvme_lookup_key(h->ctx, "psk", identity, &id);
		if (ret && !(ret == -ENOKEY || ret == -EKEYREVOKED)) {
			libnvme_msg(h->ctx, LOG_ERR,
				 "Failed to lookup key for identity %s, error %d\n",
				  identity, ret);
			return ret;
		}
	}

	if (!id) {
		ret = __nvme_import_tls_key(h->ctx, kr_id, hostnqn,
					    subsysnqn, identity, key, &id);
		if (ret) {
			libnvme_msg(h->ctx, LOG_ERR,
				 "Failed to insert TLS KEY, error %d\n", ret);
			return ret;
		}
	}

out:
	*keyring_id = kr_id;
	*key_id = id;

	return 0;
}
#else
__public int libnvme_lookup_keyring(struct libnvme_global_ctx *ctx, const char *keyring,
		long *key)
{
	libnvme_msg(ctx, LOG_ERR, "key operations not supported; "
		 "recompile with keyutils support.\n");
	return -ENOTSUP;
}

__public char *libnvme_describe_key_serial(struct libnvme_global_ctx *ctx, long key_id)
{
	libnvme_msg(ctx, LOG_ERR, "key operations not supported; "
		 "recompile with keyutils support.\n");
	return NULL;
}

__public int libnvme_lookup_key(struct libnvme_global_ctx *ctx, const char *type,
		const char *identity, long *key)
{
	libnvme_msg(ctx, LOG_ERR, "key operations not supported; "
		 "recompile with keyutils support.\n");
	return -ENOTSUP;
}

__public int libnvme_set_keyring(struct libnvme_global_ctx *ctx, long key_id)
{
	libnvme_msg(ctx, LOG_ERR, "key operations not supported; "
		 "recompile with keyutils support.\n");
	return -ENOTSUP;
}

__public int libnvme_read_key(struct libnvme_global_ctx *ctx, long keyring_id,
		long key_id, int *len, unsigned char **key)
{
	libnvme_msg(ctx, LOG_ERR, "key operations not supported; "
		 "recompile with keyutils support.\n");
	return -ENOTSUP;
}

__public int libnvme_update_key(struct libnvme_global_ctx *ctx, long keyring_id,
		const char *key_type, const char *identity,
		unsigned char *key_data, int key_len, long *key)
{
	libnvme_msg(ctx, LOG_ERR, "key operations not supported; "
		 "recompile with keyutils support.\n");
	return -ENOTSUP;
}

__public int libnvme_scan_tls_keys(struct libnvme_global_ctx *ctx, const char *keyring,
		libnvme_scan_tls_keys_cb_t cb, void *data)
{
	libnvme_msg(ctx, LOG_ERR, "key operations not supported; "
		 "recompile with keyutils support.\n");
	return -ENOTSUP;
}

__public int libnvme_insert_tls_key_versioned(struct libnvme_global_ctx *ctx,
		const char *keyring, const char *key_type,
		const char *hostnqn, const char *subsysnqn,
		int version, int hmac,
		unsigned char *configured_key, int key_len,
		long *keyp)
{
	libnvme_msg(ctx, LOG_ERR, "key operations not supported; "
		 "recompile with keyutils support.\n");
	return -ENOTSUP;
}

__public int libnvme_insert_tls_key_compat(struct libnvme_global_ctx *ctx,
		const char *keyring, const char *key_type,
		const char *hostnqn, const char *subsysnqn,
		int version, int hmac,
		unsigned char *configured_key, int key_len,
		long *keyp)
{
	libnvme_msg(ctx, LOG_ERR, "key operations not supported; "
		 "recompile with keyutils support.\n");
	return -ENOTSUP;
}

__public int libnvme_revoke_tls_key(struct libnvme_global_ctx *ctx,
		const char *keyring, const char *key_type,
		const char *identity)
{
	libnvme_msg(ctx, LOG_ERR, "key operations not supported; "
		 "recompile with keyutils support.\n");
	return -ENOTSUP;
}

int __libnvme_import_keys_from_config(libnvme_host_t h, libnvme_ctrl_t c,
				   long *keyring_id, long *key_id)
{
	*keyring_id = 0;
	*key_id = 0;

	return 0;
}
#endif

__public int libnvme_insert_tls_key(struct libnvme_global_ctx *ctx,
		const char *keyring, const char *key_type,
		const char *hostnqn, const char *subsysnqn, int hmac,
		unsigned char *configured_key, int key_len, long *key)
{
	return libnvme_insert_tls_key_versioned(ctx, keyring, key_type,
					     hostnqn, subsysnqn, 0, hmac,
					     configured_key, key_len, key);
}

/*
 * PSK Interchange Format
 * NVMeTLSkey-<v>:<xx>:<s>:
 *
 * x: version as one ASCII char
 * yy: hmac encoded as two ASCII chars
 *     00: no transform ('configured PSK')
 *     01: SHA-256
 *     02: SHA-384
 * s:  32 or 48 bytes binary followed by a CRC-32 of the configured PSK
 *     (4 bytes) encoded as base64
 */
__public int libnvme_export_tls_key_versioned(struct libnvme_global_ctx *ctx,
		unsigned char version, unsigned char hmac,
		const unsigned char *key_data,
		size_t key_len, char **encoded_keyp)
{
	unsigned int raw_len, encoded_len, len;
	unsigned long crc = crc32(0L, NULL, 0);
	unsigned char raw_secret[52];
	char *encoded_key;

	switch (hmac) {
	case LIBNVME_HMAC_ALG_NONE:
		if (key_len != 32 && key_len != 48)
			return -EINVAL;
		break;
	case LIBNVME_HMAC_ALG_SHA2_256:
		if (key_len != 32)
			return -EINVAL;
		break;
	case LIBNVME_HMAC_ALG_SHA2_384:
		if (key_len != 48)
			return -EINVAL;
		break;
	default:
		return -EINVAL;
	}
	raw_len = key_len;

	memcpy(raw_secret, key_data, raw_len);
	crc = crc32(crc, raw_secret, raw_len);
	raw_secret[raw_len++] = crc & 0xff;
	raw_secret[raw_len++] = (crc >> 8) & 0xff;
	raw_secret[raw_len++] = (crc >> 16) & 0xff;
	raw_secret[raw_len++] = (crc >> 24) & 0xff;

	encoded_len = (raw_len * 2) + 20;
	encoded_key = malloc(encoded_len);
	if (!encoded_key)
		return -ENOMEM;

	memset(encoded_key, 0, encoded_len);
	len = sprintf(encoded_key, "NVMeTLSkey-%x:%02x:", version, hmac);
	len += base64_encode(raw_secret, raw_len, encoded_key + len);
	encoded_key[len++] = ':';
	encoded_key[len++] = '\0';

	*encoded_keyp = encoded_key;
	return 0;
}

__public int libnvme_export_tls_key(struct libnvme_global_ctx *ctx,
		const unsigned char *key_data, int key_len, char **key)
{
	unsigned char hmac;

	if (key_len == 32)
		hmac = LIBNVME_HMAC_ALG_SHA2_256;
	else
		hmac = LIBNVME_HMAC_ALG_SHA2_384;

	return libnvme_export_tls_key_versioned(ctx, 1, hmac, key_data,
		key_len, key);
}

__public int libnvme_import_tls_key_versioned(struct libnvme_global_ctx *ctx,
		const char *encoded_key, unsigned char *version,
		unsigned char *hmac, size_t *key_len,
		unsigned char **keyp)
{
	unsigned char decoded_key[128], *key_data;
	unsigned int crc = crc32(0L, NULL, 0);
	unsigned int key_crc;
	int err, _version, _hmac, decoded_len;
	size_t len;

	if (sscanf(encoded_key, "NVMeTLSkey-%d:%02x:*s",
		   &_version, &_hmac) != 2)
		return -EINVAL;

	if (_version != 1)
		return -EINVAL;

	*version = _version;

	len = strlen(encoded_key);
	switch (_hmac) {
	case LIBNVME_HMAC_ALG_NONE:
		if (len != 65 && len != 89)
			return -EINVAL;
		break;
	case LIBNVME_HMAC_ALG_SHA2_256:
		if (len != 65)
			return -EINVAL;
		break;
	case LIBNVME_HMAC_ALG_SHA2_384:
		if (len != 89)
			return -EINVAL;
		break;
	default:
		return -EINVAL;
	}
	*hmac = _hmac;

	err = base64_decode(encoded_key + 16, len - 17, decoded_key);
	if (err < 0)
		return -ENOKEY;

	decoded_len = err;
	decoded_len -= 4;
	if (decoded_len != 32 && decoded_len != 48)
		return -ENOKEY;

	crc = crc32(crc, decoded_key, decoded_len);
	key_crc = ((uint32_t)decoded_key[decoded_len]) |
		((uint32_t)decoded_key[decoded_len + 1] << 8) |
		((uint32_t)decoded_key[decoded_len + 2] << 16) |
		((uint32_t)decoded_key[decoded_len + 3] << 24);
	if (key_crc != crc) {
		libnvme_msg(ctx, LOG_ERR, "CRC mismatch (key %08x, crc %08x)",
			 key_crc, crc);
		return -ENOKEY;
	}

	key_data = malloc(decoded_len);
	if (!key_data)
		return -ENOMEM;
	memcpy(key_data, decoded_key, decoded_len);

	*key_len = decoded_len;
	*keyp = key_data;
	return 0;
}

__public int libnvme_import_tls_key(struct libnvme_global_ctx *ctx, const char *encoded_key,
		int *key_len, unsigned int *hmac, unsigned char **keyp)
{
	unsigned char version, _hmac;
	unsigned char *psk;
	size_t len;
	int ret;

	ret = libnvme_import_tls_key_versioned(ctx, encoded_key, &version,
					    &_hmac, &len, &psk);
	if (ret)
		return ret;

	*hmac = _hmac;
	*key_len = len;
	*keyp = psk;
	return 0;
}

static int uuid_from_device_tree(char *system_uuid)
{
	__cleanup_fd int f = -1;
	ssize_t len;

	f = open(libnvme_uuid_ibm_filename(), O_RDONLY);
	if (f < 0)
		return -ENXIO;

	memset(system_uuid, 0, NVME_UUID_LEN_STRING);
	len = read(f, system_uuid, NVME_UUID_LEN_STRING - 1);
	if (len < 0)
		return -ENXIO;

	return strlen(system_uuid) ? 0 : -ENXIO;
}

/*
 * See System Management BIOS (SMBIOS) Reference Specification
 * https://www.dmtf.org/sites/default/files/standards/documents/DSP0134_3.2.0.pdf
 */
#define DMI_SYSTEM_INFORMATION	1

static bool is_dmi_uuid_valid(const char *buf, size_t len)
{
	int i;

	/* UUID bytes are from byte 8 to 23 */
	if (len < 24)
		return false;

	/* Test it's a invalid UUID with all zeros */
	for (i = 8; i < 24; i++) {
		if (buf[i])
			break;
	}
	if (i == 24)
		return false;

	return true;
}

static int uuid_from_dmi_entries(char *system_uuid)
{
	__cleanup_dir DIR *d = NULL;
	const char *entries_dir = libnvme_dmi_entries_dir();
	int f;
	struct dirent *de;
	char buf[512] = {0};

	system_uuid[0] = '\0';
	d = opendir(entries_dir);
	if (!d)
		return -ENXIO;
	while ((de = readdir(d))) {
		char filename[PATH_MAX];
		int len, type;

		if (de->d_name[0] == '.')
			continue;
		sprintf(filename, "%s/%s/type", entries_dir, de->d_name);
		f = open(filename, O_RDONLY);
		if (f < 0)
			continue;
		len = read(f, buf, 512);
		close(f);
		if (len <= 0)
			continue;
		if (sscanf(buf, "%d", &type) != 1)
			continue;
		if (type != DMI_SYSTEM_INFORMATION)
			continue;
		sprintf(filename, "%s/%s/raw", entries_dir, de->d_name);
		f = open(filename, O_RDONLY);
		if (f < 0)
			continue;
		len = read(f, buf, 512);
		close(f);
		if (len <= 0)
			continue;

		if (!is_dmi_uuid_valid(buf, len))
			continue;

		/* Sigh. https://en.wikipedia.org/wiki/Overengineering */
		/* DMTF SMBIOS 3.0 Section 7.2.1 System UUID */
		sprintf(system_uuid,
			"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-"
			"%02x%02x%02x%02x%02x%02x",
			(uint8_t)buf[8 + 3], (uint8_t)buf[8 + 2],
			(uint8_t)buf[8 + 1], (uint8_t)buf[8 + 0],
			(uint8_t)buf[8 + 5], (uint8_t)buf[8 + 4],
			(uint8_t)buf[8 + 7], (uint8_t)buf[8 + 6],
			(uint8_t)buf[8 + 8], (uint8_t)buf[8 + 9],
			(uint8_t)buf[8 + 10], (uint8_t)buf[8 + 11],
			(uint8_t)buf[8 + 12], (uint8_t)buf[8 + 13],
			(uint8_t)buf[8 + 14], (uint8_t)buf[8 + 15]);
		break;
	}
	return strlen(system_uuid) ? 0 : -ENXIO;
}

#define PATH_DMI_PROD_UUID  "/sys/class/dmi/id/product_uuid"

/**
 * uuid_from_product_uuid() - Get system UUID from product_uuid
 * @system_uuid: Where to save the system UUID.
 *
 * Return: 0 on success, -ENXIO otherwise.
 */
static int uuid_from_product_uuid(char *system_uuid)
{
	__cleanup_file FILE *stream = NULL;
	ssize_t nread;
	__cleanup_free char *line = NULL;
	size_t len = 0;

	stream = fopen(PATH_DMI_PROD_UUID, "re");
	if (!stream)
		return -ENXIO;
	system_uuid[0] = '\0';

	nread = getline(&line, &len, stream);
	if (nread != NVME_UUID_LEN_STRING)
		return -ENXIO;

	/* The kernel is handling the byte swapping according DMTF
	 * SMBIOS 3.0 Section 7.2.1 System UUID */

	memcpy(system_uuid, line, NVME_UUID_LEN_STRING - 1);
	system_uuid[NVME_UUID_LEN_STRING - 1] = '\0';

	return 0;
}

/**
 * uuid_from_dmi() - read system UUID
 * @system_uuid: buffer for the UUID
 *
 * The system UUID can be read from two different locations:
 *
 *     1) /sys/class/dmi/id/product_uuid
 *     2) /sys/firmware/dmi/entries
 *
 * Note that the second location is not present on Debian-based systems.
 *
 * Return: 0 on success, negative errno otherwise.
 */
static int uuid_from_dmi(char *system_uuid)
{
	int ret = uuid_from_product_uuid(system_uuid);
	if (ret != 0)
		ret = uuid_from_dmi_entries(system_uuid);
	return ret;
}

__public char *libnvme_generate_hostid(void)
{
	int ret;
	char uuid_str[NVME_UUID_LEN_STRING];
	unsigned char uuid[NVME_UUID_LEN];

	ret = uuid_from_dmi(uuid_str);
	if (ret < 0)
		ret = uuid_from_device_tree(uuid_str);
	if (ret < 0) {
		if (libnvme_random_uuid(uuid) < 0)
			memset(uuid, 0, NVME_UUID_LEN);
		libnvme_uuid_to_string(uuid, uuid_str);
	}

	return strdup(uuid_str);
}

__public char *libnvme_generate_hostnqn_from_hostid(char *hostid)
{
	char *hid = NULL;
	char *hostnqn;
	int ret;

	if (!hostid)
		hostid = hid = libnvme_generate_hostid();

	ret = asprintf(&hostnqn, "nqn.2014-08.org.nvmexpress:uuid:%s", hostid);
	free(hid);

	return (ret < 0) ? NULL : hostnqn;
}

__public char *libnvme_generate_hostnqn(void)
{
	return libnvme_generate_hostnqn_from_hostid(NULL);
}

static char *nvmf_read_file(const char *f, int len)
{
	char buf[len];
	__cleanup_fd int fd = -1;
	int ret;

	fd = open(f, O_RDONLY);
	if (fd < 0)
		return NULL;

	memset(buf, 0, len);
	ret = read(fd, buf, len - 1);

	if (ret < 0 || !strlen(buf))
		return NULL;
	return strndup(buf, strcspn(buf, "\n"));
}

__public char *libnvme_read_hostnqn(void)
{
	char *hostnqn = getenv("LIBNVME_HOSTNQN");

	if (hostnqn) {
		if (!strcmp(hostnqn, ""))
			return NULL;
		return strdup(hostnqn);
	}

	return nvmf_read_file(NVMF_HOSTNQN_FILE, NVMF_NQN_SIZE);
}

__public char *libnvme_read_hostid(void)
{
	char *hostid = getenv("LIBNVME_HOSTID");

	if (hostid) {
		if (!strcmp(hostid, ""))
			return NULL;
		return strdup(hostid);
	}

	return nvmf_read_file(NVMF_HOSTID_FILE, NVMF_HOSTID_SIZE);
}
