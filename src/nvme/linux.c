// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 * 	    Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <sys/param.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#ifdef CONFIG_OPENSSL
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>

#ifdef CONFIG_OPENSSL_3
#include <openssl/core_names.h>
#include <openssl/params.h>
#endif
#endif

#ifdef CONFIG_KEYUTILS
#include <keyutils.h>

#define NVME_TLS_DEFAULT_KEYRING ".nvme"
#endif

#include <ccan/endian/endian.h>

#include "cleanup.h"
#include "linux.h"
#include "tree.h"
#include "log.h"
#include "private.h"
#include "base64.h"
#include "crc32.h"

static int __nvme_open(const char *name)
{
	_cleanup_free_ char *path = NULL;
	int ret;

	ret = asprintf(&path, "%s/%s", "/dev", name);
	if (ret < 0) {
		errno = ENOMEM;
		return -1;
	}

	return open(path, O_RDONLY);
}

int nvme_open(const char *name)
{
	int ret, fd, id, ns;
	struct stat stat;
	bool c;

	ret = sscanf(name, "nvme%dn%d", &id, &ns);
	if (ret != 1 && ret != 2) {
		errno = EINVAL;
		return -1;
	}
	c = ret == 1;

	fd = __nvme_open(name);
	if (fd < 0)
		return fd;

	ret = fstat(fd, &stat);
	if (ret < 0)
		goto close_fd;

	if (c) {
		if (!S_ISCHR(stat.st_mode)) {
			errno = EINVAL;
			goto close_fd;
		}
	} else if (!S_ISBLK(stat.st_mode)) {
		errno = EINVAL;
		goto close_fd;
	}

	return fd;

close_fd:
	close(fd);
	return -1;
}

int nvme_fw_download_seq(int fd, __u32 size, __u32 xfer, __u32 offset,
			 void *buf)
{
	int err = 0;
	struct nvme_fw_download_args args = {
		.args_size = sizeof(args),
		.fd = fd,
		.offset = offset,
		.data_len = xfer,
		.data = buf,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result = NULL,
	};

	while (size > 0) {
		args.data_len = MIN(xfer, size);
		err = nvme_fw_download(&args);
		if (err)
			break;

		args.data += xfer;
		size -= xfer;
		args.offset += xfer;
	}

	return err;
}

int nvme_get_telemetry_max(int fd, enum nvme_telemetry_da *da, size_t *data_tx)
{
	_cleanup_free_ struct nvme_id_ctrl *id_ctrl = NULL;
	int err;

	id_ctrl = __nvme_alloc(sizeof(*id_ctrl));
	if (!id_ctrl) {
		errno = ENOMEM;
		return -1;
	}
	err = nvme_identify_ctrl(fd, id_ctrl);
	if (err)
		return err;

	if (data_tx) {
		*data_tx = id_ctrl->mdts;
		if (id_ctrl->mdts) {
			/* assuming CAP.MPSMIN is zero minimum Memory Page Size is at least
			 * 4096 bytes
			 */
			*data_tx = (1 << id_ctrl->mdts) * 4096;
		}
	}
	if (da) {
		if (id_ctrl->lpa & 0x8)
			*da = NVME_TELEMETRY_DA_3;
		if (id_ctrl->lpa & 0x40)
			*da = NVME_TELEMETRY_DA_4;

	}
	return err;
}

int nvme_get_telemetry_log(int fd, bool create, bool ctrl, bool rae, size_t max_data_tx,
			   enum nvme_telemetry_da da, struct nvme_telemetry_log **buf,
			   size_t *size)
{
	static const __u32 xfer = NVME_LOG_TELEM_BLOCK_SIZE;

	struct nvme_telemetry_log *telem;
	enum nvme_cmd_get_log_lid lid;
	_cleanup_free_ void *log = NULL;
	void *tmp;
	int err;
	size_t dalb;
	struct nvme_get_log_args args = {
		.args_size = sizeof(args),
		.fd = fd,
		.nsid = NVME_NSID_NONE,
		.lsp = NVME_LOG_LSP_NONE,
		.lsi = NVME_LOG_LSI_NONE,
		.uuidx = NVME_UUID_NONE,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result = NULL,
		.csi = NVME_CSI_NVM,
		.rae = rae,
		.ot = false,
	};

	*size = 0;

	log = __nvme_alloc(xfer);
	if (!log) {
		errno = ENOMEM;
		return -1;
	}

	if (ctrl) {
		err = nvme_get_log_telemetry_ctrl(fd, true, 0, xfer, log);
		lid = NVME_LOG_LID_TELEMETRY_CTRL;
	} else {
		lid = NVME_LOG_LID_TELEMETRY_HOST;
		if (create)
			err = nvme_get_log_create_telemetry_host(fd, log);
		else
			err = nvme_get_log_telemetry_host(fd, 0, xfer, log);
	}

	if (err)
		return err;

	telem = log;
	if (ctrl && !telem->ctrlavail) {
		*buf = log;
		log = NULL;
		*size = xfer;
		return 0;
	}

	switch (da) {
	case NVME_TELEMETRY_DA_1:
		dalb = le16_to_cpu(telem->dalb1);
		break;
	case NVME_TELEMETRY_DA_2:
		dalb = le16_to_cpu(telem->dalb2);
		break;
	case NVME_TELEMETRY_DA_3:
		/* dalb3 >= dalb2 >= dalb1 */
		dalb = le16_to_cpu(telem->dalb3);
		break;
	case NVME_TELEMETRY_DA_4:
		dalb = le32_to_cpu(telem->dalb4);
		break;
	default:
		errno = EINVAL;
		return -1;
	}

	if (dalb == 0) {
		errno = ENOENT;
		return -1;
	}

	*size = (dalb + 1) * xfer;
	tmp = __nvme_realloc(log, *size);
	if (!tmp) {
		errno = ENOMEM;
		return -1;
	}
	log = tmp;

	args.lid = lid;
	args.log = log;
	args.len = *size;
	err = nvme_get_log_page(fd, max_data_tx, &args);
	if (err)
		return err;

	*buf = log;
	log = NULL;
	return 0;
}


static int nvme_check_get_telemetry_log(int fd, bool create, bool ctrl, bool rae,
					struct nvme_telemetry_log **log, enum nvme_telemetry_da da,
					size_t *size)
{
	enum nvme_telemetry_da max_da = 0;
	int err = nvme_get_telemetry_max(fd, &max_da, NULL);

	if (err)
		return err;
	if (da > max_da) {
		errno = ENOENT;
		return -1;
	}
	return nvme_get_telemetry_log(fd, create, ctrl, rae, 4096, da, log, size);
}


int nvme_get_ctrl_telemetry(int fd, bool rae, struct nvme_telemetry_log **log,
		enum nvme_telemetry_da da, size_t *size)
{
	return nvme_check_get_telemetry_log(fd, false, true, rae, log, da, size);
}

int nvme_get_host_telemetry(int fd, struct nvme_telemetry_log **log,
		enum nvme_telemetry_da da, size_t *size)
{
	return nvme_check_get_telemetry_log(fd, false, false, false, log, da, size);
}

int nvme_get_new_host_telemetry(int fd, struct nvme_telemetry_log **log,
		enum nvme_telemetry_da da, size_t *size)
{
	return nvme_check_get_telemetry_log(fd, true, false, false, log, da, size);
}

int nvme_get_lba_status_log(int fd, bool rae, struct nvme_lba_status_log **log)
{
	_cleanup_free_ struct nvme_lba_status_log *buf = NULL;
	__u32 size;
	void *tmp;
	int err;
	struct nvme_get_log_args args = {
		.args_size = sizeof(args),
		.fd = fd,
		.nsid = NVME_NSID_NONE,
		.lsp = NVME_LOG_LSP_NONE,
		.lsi = NVME_LOG_LSI_NONE,
		.uuidx = NVME_UUID_NONE,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result = NULL,
		.csi = NVME_CSI_NVM,
		.rae = rae,
		.ot = false,
	};

	buf = malloc(sizeof(*buf));
	if (!buf)
		return -1;

	err = nvme_get_log_lba_status(fd, true, 0, sizeof(*buf), buf);
	if (err) {
		*log = NULL;
		return err;
	}

	size = le32_to_cpu(buf->lslplen);
	if (!size) {
		*log = buf;
		buf = NULL;
		return 0;
	}

	tmp = realloc(buf, size);
	if (!tmp) {
		*log = NULL;
		return -1;
	}
	buf = tmp;

	args.lid = NVME_LOG_LID_LBA_STATUS;
	args.log = buf;
	args.len = size;
	err = nvme_get_log_page(fd, 4096, &args);
	if (err) {
		*log = NULL;
		return err;
	}

	*log = buf;
	buf = NULL;
	return 0;
}

static int nvme_ns_attachment(int fd, __u32 nsid, __u16 num_ctrls,
			      __u16 *ctrlist, bool attach, __u32 timeout)
{
	struct nvme_ctrl_list cntlist = { 0 };
	struct nvme_ns_attach_args args = {
		.args_size = sizeof(args),
		.fd = fd,
		.nsid = nsid,
		.sel = NVME_NS_ATTACH_SEL_CTRL_DEATTACH,
		.ctrlist = &cntlist,
		.timeout = timeout,
	};

	if (attach)
		args.sel = NVME_NS_ATTACH_SEL_CTRL_ATTACH;

	nvme_init_ctrl_list(args.ctrlist, num_ctrls, ctrlist);
	return nvme_ns_attach(&args);
}

int nvme_namespace_attach_ctrls(int fd, __u32 nsid, __u16 num_ctrls,
				__u16 *ctrlist)
{
	return nvme_ns_attachment(fd, nsid, num_ctrls, ctrlist, true,
				  NVME_DEFAULT_IOCTL_TIMEOUT);
}

int nvme_namespace_detach_ctrls(int fd, __u32 nsid, __u16 num_ctrls,
				__u16 *ctrlist)
{
	return nvme_ns_attachment(fd, nsid, num_ctrls, ctrlist, false,
				  NVME_DEFAULT_IOCTL_TIMEOUT);
}

size_t nvme_get_ana_log_len_from_id_ctrl(const struct nvme_id_ctrl *id_ctrl,
					 bool rgo)
{
	__u32 nanagrpid = le32_to_cpu(id_ctrl->nanagrpid);
	size_t size = sizeof(struct nvme_ana_log) +
		nanagrpid * sizeof(struct nvme_ana_group_desc);

	return rgo ? size : size + le32_to_cpu(id_ctrl->mnan) * sizeof(__le32);
}

int nvme_get_ana_log_len(int fd, size_t *analen)
{
	_cleanup_free_ struct nvme_id_ctrl *ctrl = NULL;
	int ret;

	ctrl = __nvme_alloc(sizeof(*ctrl));
	if (!ctrl) {
		errno = ENOMEM;
		return -1;
	}
	ret = nvme_identify_ctrl(fd, ctrl);
	if (ret)
		return ret;

	*analen = nvme_get_ana_log_len_from_id_ctrl(ctrl, false);
	return 0;
}

int nvme_get_logical_block_size(int fd, __u32 nsid, int *blksize)
{
	_cleanup_free_ struct nvme_id_ns *ns = NULL;
	__u8 flbas;
	int ret;

	ns = __nvme_alloc(sizeof(*ns));
	if (!ns) {
		errno = ENOMEM;
		return -1;
	}
	ret = nvme_identify_ns(fd, nsid, ns);
	if (ret)
		return ret;

	nvme_id_ns_flbas_to_lbaf_inuse(ns->flbas, &flbas);
	*blksize = 1 << ns->lbaf[flbas].ds;

	return 0;
}

static int __nvme_set_attr(const char *path, const char *value)
{
	_cleanup_fd_ int fd = -1;

	fd = open(path, O_WRONLY);
	if (fd < 0) {
#if 0
		nvme_msg(LOG_DEBUG, "Failed to open %s: %s\n", path,
			 strerror(errno));
#endif
		return -1;
	}
	return write(fd, value, strlen(value));
}

int nvme_set_attr(const char *dir, const char *attr, const char *value)
{
	_cleanup_free_ char *path = NULL;
	int ret;

	ret = asprintf(&path, "%s/%s", dir, attr);
	if (ret < 0)
		return -1;

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

char *nvme_get_attr(const char *dir, const char *attr)
{
	_cleanup_free_ char *path = NULL;
	int ret;

	ret = asprintf(&path, "%s/%s", dir, attr);
	if (ret < 0) {
		errno = ENOMEM;
		return NULL;
	}

	return __nvme_get_attr(path);
}

char *nvme_get_subsys_attr(nvme_subsystem_t s, const char *attr)
{
	return nvme_get_attr(nvme_subsystem_get_sysfs_dir(s), attr);
}

char *nvme_get_ctrl_attr(nvme_ctrl_t c, const char *attr)
{
	return nvme_get_attr(nvme_ctrl_get_sysfs_dir(c), attr);
}

char *nvme_get_ns_attr(nvme_ns_t n, const char *attr)
{
	return nvme_get_attr(nvme_ns_get_sysfs_dir(n), attr);
}

char *nvme_get_path_attr(nvme_path_t p, const char *attr)
{
	return nvme_get_attr(nvme_path_get_sysfs_dir(p), attr);
}

#ifndef CONFIG_OPENSSL
static unsigned char default_hmac(size_t key_len)
{
	return NVME_HMAC_ALG_NONE;
}

int nvme_gen_dhchap_key(char *hostnqn, enum nvme_hmac_alg hmac,
			unsigned int key_len, unsigned char *secret,
			unsigned char *key)
{
	if (hmac != NVME_HMAC_ALG_NONE) {
		nvme_msg(NULL, LOG_ERR, "HMAC transformation not supported; " \
			"recompile with OpenSSL support.\n");
		errno = -EINVAL;
		return -1;
	}

	memcpy(key, secret, key_len);
	return 0;
}

static int derive_retained_key(int hmac, const char *hostnqn,
			       unsigned char *generated,
			       unsigned char *retained,
			       size_t key_len)
{
	nvme_msg(NULL, LOG_ERR, "NVMe TLS is not supported; "
		 "recompile with OpenSSL support.\n");
	errno = ENOTSUP;
	return -1;
}

static int derive_psk_digest(const char *hostnqn, const char *subsysnqn,
			     int version, int cipher,
			     unsigned char *retained, size_t key_len,
			     char *digest, size_t digest_len)
{
	nvme_msg(NULL, LOG_ERR, "NVMe TLS 2.0 is not supported; "
		 "recompile with OpenSSL support.\n");
	errno = ENOTSUP;
	return -1;
}

static int derive_tls_key(int version, int cipher, const char *context,
			  unsigned char *retained,
			  unsigned char *psk, size_t key_len)
{
	nvme_msg(NULL, LOG_ERR, "NVMe TLS is not supported; "
		 "recompile with OpenSSL support.\n");
	errno = ENOTSUP;
	return -1;
}
#else /* CONFIG_OPENSSL */
static unsigned char default_hmac(size_t key_len)
{
	unsigned char hmac = NVME_HMAC_ALG_NONE;

	switch (key_len) {
	case 32:
		hmac = NVME_HMAC_ALG_SHA2_256;
		break;
	case 48:
		hmac = NVME_HMAC_ALG_SHA2_384;
		break;
	case 64:
		hmac = NVME_HMAC_ALG_SHA2_512;
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
	case NVME_HMAC_ALG_SHA2_256:
		md = EVP_sha256();
		*hmac_len = 32;
		break;
	case NVME_HMAC_ALG_SHA2_384:
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
#define _cleanup_evp_pkey_ctx_ __cleanup__(cleanup_evp_pkey_ctx)

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
static int derive_retained_key(int hmac, const char *hostnqn,
			       unsigned char *configured,
			       unsigned char *retained,
			       size_t key_len)
{
	_cleanup_evp_pkey_ctx_ EVP_PKEY_CTX *ctx = NULL;
	uint16_t length = key_len & 0xFFFF;
	const EVP_MD *md;
	size_t hmac_len;

	if (hmac == NVME_HMAC_ALG_NONE) {
		memcpy(retained, configured, key_len);
		return key_len;
	}

	md = select_hmac(hmac, &hmac_len);
	if (!md || !hmac_len) {
		errno = EINVAL;
		return -1;
	}

	ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	if (!ctx) {
		errno = ENOMEM;
		return -1;
	}

	if (EVP_PKEY_derive_init(ctx) <= 0) {
		errno = ENOMEM;
		return -1;
	}
	if (EVP_PKEY_CTX_set_hkdf_md(ctx, md) <= 0) {
		errno = ENOKEY;
		return -1;
	}
	if (EVP_PKEY_CTX_set1_hkdf_key(ctx, configured, key_len) <= 0) {
		errno = ENOKEY;
		return -1;
	}
	if (EVP_PKEY_CTX_add1_hkdf_info(ctx,
			(const unsigned char *)&length, 2) <= 0) {
		errno = ENOKEY;
		return -1;
	}
	if (EVP_PKEY_CTX_add1_hkdf_info(ctx,
			(const unsigned char *)"tls13 ", 6) <= 0) {
		errno = ENOKEY;
		return -1;
	}
	if (EVP_PKEY_CTX_add1_hkdf_info(ctx,
			(const unsigned char *)"HostNQN", 7) <= 0) {
		errno = ENOKEY;
		return -1;
	}
	if (EVP_PKEY_CTX_add1_hkdf_info(ctx,
			(const unsigned char *)hostnqn, strlen(hostnqn)) <= 0) {
		errno = ENOKEY;
		return -1;
	}

	if (EVP_PKEY_derive(ctx, retained, &key_len) <= 0) {
		errno = ENOKEY;
		return -1;
	}

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
static int derive_tls_key(int version, unsigned char cipher,
			  const char *context, unsigned char *retained,
			  unsigned char *psk, size_t key_len)
{
	_cleanup_evp_pkey_ctx_ EVP_PKEY_CTX *ctx = NULL;
	uint16_t length = key_len & 0xFFFF;
	const EVP_MD *md;
	size_t hmac_len;

	md = select_hmac(cipher, &hmac_len);
	if (!md || !hmac_len) {
		errno = EINVAL;
		return -1;
	}

	ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	if (!ctx) {
		errno = ENOMEM;
		return -1;
	}

	if (EVP_PKEY_derive_init(ctx) <= 0) {
		errno = ENOMEM;
		return -1;
	}
	if (EVP_PKEY_CTX_set_hkdf_md(ctx, md) <= 0) {
		errno = ENOKEY;
		return -1;
	}
	if (EVP_PKEY_CTX_set1_hkdf_key(ctx, retained, key_len) <= 0) {
		errno = ENOKEY;
		return -1;
	}
	if (EVP_PKEY_CTX_add1_hkdf_info(ctx,
			(const unsigned char *)&length, 2) <= 0) {
		errno = ENOKEY;
		return -1;
	}
	if (EVP_PKEY_CTX_add1_hkdf_info(ctx,
			(const unsigned char *)"tls13 ", 6) <= 0) {
		errno = ENOKEY;
		return -1;
	}
	if (EVP_PKEY_CTX_add1_hkdf_info(ctx,
			(const unsigned char *)"nvme-tls-psk", 12) <= 0) {
		errno = ENOKEY;
		return -1;
	}
	if (version == 1) {
		char hash_str[5];

		sprintf(hash_str, "%02d ", cipher);
		if (EVP_PKEY_CTX_add1_hkdf_info(ctx,
				(const unsigned char *)hash_str,
				strlen(hash_str)) <= 0) {
			errno = ENOKEY;
			return -1;
		}
	}
	if (EVP_PKEY_CTX_add1_hkdf_info(ctx,
			(const unsigned char *)context,
			strlen(context)) <= 0) {
		errno = ENOKEY;
		return -1;
	}

	if (EVP_PKEY_derive(ctx, psk, &key_len) <= 0) {
		errno = ENOKEY;
		return -1;
	}

	return key_len;
}
#endif /* CONFIG_OPENSSL */

#ifdef CONFIG_OPENSSL_1
static DEFINE_CLEANUP_FUNC(cleanup_hmac_ctx, HMAC_CTX *, HMAC_CTX_free)
#define _cleanup_hmac_ctx_ __cleanup__(cleanup_hmac_ctx)

int nvme_gen_dhchap_key(char *hostnqn, enum nvme_hmac_alg hmac,
			unsigned int key_len, unsigned char *secret,
			unsigned char *key)
{
	const char hmac_seed[] = "NVMe-over-Fabrics";
	_cleanup_hmac_ctx_ HMAC_CTX *hmac_ctx = NULL;
	const EVP_MD *md;

	hmac_ctx = HMAC_CTX_new();
	if (!hmac_ctx) {
		errno = ENOMEM;
		return -1;
	}

	switch (hmac) {
	case NVME_HMAC_ALG_NONE:
		memcpy(key, secret, key_len);
		return 0;
	case NVME_HMAC_ALG_SHA2_256:
		md = EVP_sha256();
		break;
	case NVME_HMAC_ALG_SHA2_384:
		md = EVP_sha384();
		break;
	case NVME_HMAC_ALG_SHA2_512:
		md = EVP_sha512();
		break;
	default:
		errno = EINVAL;
		return -1;
	}

	if (!md) {
		errno = EINVAL;
		return -1;
	}

	if (!HMAC_Init_ex(hmac_ctx, secret, key_len, md, NULL)) {
		errno = ENOMEM;
		return -1;
	}

	if (!HMAC_Update(hmac_ctx, (unsigned char *)hostnqn,
			 strlen(hostnqn))) {
		errno = ENOKEY;
		return -1;
	}

	if (!HMAC_Update(hmac_ctx, (unsigned char *)hmac_seed,
			 strlen(hmac_seed))) {
		errno = ENOKEY;
		return -1;
	}

	if (!HMAC_Final(hmac_ctx, key, &key_len)) {
		errno = ENOKEY;
		return -1;
	}

	return 0;
}

static int derive_psk_digest(const char *hostnqn, const char *subsysnqn,
			     int version, int cipher,
			     unsigned char *retained, size_t key_len,
			     char *digest, size_t digest_len)
{
	static const char hmac_seed[] = "NVMe-over-Fabrics";
	_cleanup_hmac_ctx_ HMAC_CTX *hmac_ctx = NULL;
	_cleanup_free_ unsigned char *psk_ctx = NULL;
	const EVP_MD *md;
	size_t hmac_len;
	size_t len;

	hmac_ctx = HMAC_CTX_new();
	if (!hmac_ctx) {
		errno = ENOMEM;
		return -1;
	}
	md = select_hmac(cipher, &hmac_len);
	if (!md || !hmac_len) {
		errno = EINVAL;
		return -1;
	}

	psk_ctx = malloc(key_len);
	if (!psk_ctx) {
		errno = ENOMEM;
		return -1;
	}
	if (!HMAC_Init_ex(hmac_ctx, retained, key_len, md, NULL)) {
		errno = ENOMEM;
		return -1;
	}
	if (!HMAC_Update(hmac_ctx, (unsigned char *)hostnqn,
			 strlen(hostnqn))) {
		errno = ENOKEY;
		return -1;
	}
	if (!HMAC_Update(hmac_ctx, (unsigned char *)" ", 1)) {
		errno = ENOKEY;
		return -1;
	}
	if (!HMAC_Update(hmac_ctx, (unsigned char *)subsysnqn,
			 strlen(subsysnqn))) {
		errno = ENOKEY;
		return -1;
	}
	if (!HMAC_Update(hmac_ctx, (unsigned char *)" ", 1)) {
		errno = ENOKEY;
		return -1;
	}
	if (!HMAC_Update(hmac_ctx, (unsigned char *)hmac_seed,
			 strlen(hmac_seed))) {
		errno = ENOKEY;
		return -1;
	}
	if (!HMAC_Final(hmac_ctx, psk_ctx, (unsigned int *)&key_len)) {
		errno = ENOKEY;
		return -1;
	}
	if (key_len * 2 > digest_len) {
		errno = EINVAL;
		return -1;
	}
	memset(digest, 0, digest_len);
	len = base64_encode(psk_ctx, key_len, digest);
	if (len < 0) {
		errno = ENOKEY;
		return len;
	}
	return strlen(digest);
}

#endif /* !CONFIG_OPENSSL_1 */

#ifdef CONFIG_OPENSSL_3
static DEFINE_CLEANUP_FUNC(
	cleanup_ossl_lib_ctx, OSSL_LIB_CTX *, OSSL_LIB_CTX_free)
#define _cleanup_ossl_lib_ctx_ __cleanup__(cleanup_ossl_lib_ctx)
static DEFINE_CLEANUP_FUNC(cleanup_evp_mac_ctx, EVP_MAC_CTX *, EVP_MAC_CTX_free)
#define _cleanup_evp_mac_ctx_ __cleanup__(cleanup_evp_mac_ctx)
static DEFINE_CLEANUP_FUNC(cleanup_evp_mac, EVP_MAC *, EVP_MAC_free)
#define _cleanup_evp_mac_ __cleanup__(cleanup_evp_mac)

int nvme_gen_dhchap_key(char *hostnqn, enum nvme_hmac_alg hmac,
			unsigned int key_len, unsigned char *secret,
			unsigned char *key)
{
	const char hmac_seed[] = "NVMe-over-Fabrics";
	_cleanup_ossl_lib_ctx_ OSSL_LIB_CTX *lib_ctx = NULL;
	_cleanup_evp_mac_ctx_ EVP_MAC_CTX *mac_ctx = NULL;
	_cleanup_evp_mac_ EVP_MAC *mac = NULL;
	OSSL_PARAM params[2], *p = params;
	char *progq = NULL;
	char *digest;
	size_t len;

	lib_ctx = OSSL_LIB_CTX_new();
	if (!lib_ctx) {
		errno = ENOMEM;
		return -1;
	}

	mac = EVP_MAC_fetch(lib_ctx, OSSL_MAC_NAME_HMAC, progq);
	if (!mac) {
		errno = ENOMEM;
		return -1;
	}

	mac_ctx = EVP_MAC_CTX_new(mac);
	if (!mac_ctx) {
		errno = ENOMEM;
		return -1;
	}

	switch (hmac) {
	case NVME_HMAC_ALG_NONE:
		memcpy(key, secret, key_len);
		return 0;
	case NVME_HMAC_ALG_SHA2_256:
		digest = OSSL_DIGEST_NAME_SHA2_256;
		break;
	case NVME_HMAC_ALG_SHA2_384:
		digest = OSSL_DIGEST_NAME_SHA2_384;
		break;
	case NVME_HMAC_ALG_SHA2_512:
		digest = OSSL_DIGEST_NAME_SHA2_512;
		break;
	default:
		errno = EINVAL;
		return -1;
	}
	*p++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
						digest,
						0);
	*p = OSSL_PARAM_construct_end();

	if (!EVP_MAC_init(mac_ctx, secret, key_len, params)) {
		errno = ENOKEY;
		return -1;
	}

	if (!EVP_MAC_update(mac_ctx, (unsigned char *)hostnqn,
			    strlen(hostnqn))) {
		errno = ENOKEY;
		return -1;
	}

	if (!EVP_MAC_update(mac_ctx, (unsigned char *)hmac_seed,
			    strlen(hmac_seed))) {
		errno = ENOKEY;
		return -1;
	}

	if (!EVP_MAC_final(mac_ctx, key, &len, key_len)) {
		errno = ENOKEY;
		return -1;
	}

	if (len != key_len) {
		errno = EMSGSIZE;
		return -1;
	}

	return 0;
}

static int derive_psk_digest(const char *hostnqn, const char *subsysnqn,
			     int version, int cipher,
			     unsigned char *retained, size_t key_len,
			     char *digest, size_t digest_len)
{
	static const char hmac_seed[] = "NVMe-over-Fabrics";
	_cleanup_ossl_lib_ctx_ OSSL_LIB_CTX *lib_ctx = NULL;
	_cleanup_evp_mac_ctx_ EVP_MAC_CTX *mac_ctx = NULL;
	_cleanup_free_ unsigned char *psk_ctx = NULL;
	_cleanup_evp_mac_ EVP_MAC *mac = NULL;
	OSSL_PARAM params[2], *p = params;
	size_t hmac_len;
	char *progq = NULL;
	char *dig = NULL;
	size_t len;

	lib_ctx = OSSL_LIB_CTX_new();
	if (!lib_ctx) {
		errno = ENOMEM;
		return -1;
	}
	mac = EVP_MAC_fetch(lib_ctx, OSSL_MAC_NAME_HMAC, progq);
	if (!mac) {
		errno = ENOMEM;
		return -1;
	}

	mac_ctx = EVP_MAC_CTX_new(mac);
	if (!mac_ctx) {
		errno = ENOMEM;
		return -1;
	}
	switch (cipher) {
	case NVME_HMAC_ALG_SHA2_256:
		dig = OSSL_DIGEST_NAME_SHA2_256;
		break;
	case NVME_HMAC_ALG_SHA2_384:
		dig = OSSL_DIGEST_NAME_SHA2_384;
		break;
	default:
		errno = EINVAL;
		break;
	}
	if (!dig)
		return -1;
	*p++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
						dig, 0);
	*p = OSSL_PARAM_construct_end();

	psk_ctx = malloc(key_len);
	if (!psk_ctx) {
		errno = ENOMEM;
		return -1;
	}

	if (!EVP_MAC_init(mac_ctx, retained, key_len, params)) {
		errno = ENOKEY;
		return -1;
	}
	if (!EVP_MAC_update(mac_ctx, (unsigned char *)hostnqn,
			    strlen(hostnqn))) {
		errno = ENOKEY;
		return -1;
	}
	if (!EVP_MAC_update(mac_ctx, (unsigned char *)" ", 1)) {
		errno = ENOKEY;
		return -1;
	}
	if (!EVP_MAC_update(mac_ctx, (unsigned char *)subsysnqn,
			    strlen(subsysnqn))) {
		errno = ENOKEY;
		return -1;
	}
	if (!EVP_MAC_update(mac_ctx, (unsigned char *)" ", 1)) {
		errno = ENOKEY;
		return -1;
	}
	if (!EVP_MAC_update(mac_ctx, (unsigned char *)hmac_seed,
			    strlen(hmac_seed))) {
		errno = ENOKEY;
		return -1;
	}
	if (!EVP_MAC_final(mac_ctx, psk_ctx, &hmac_len, key_len)) {
		errno = ENOKEY;
		return -1;
	}
	if (hmac_len > key_len) {
		errno = EMSGSIZE;
		return -1;
	}
	if (hmac_len * 2 > digest_len) {
		errno = EINVAL;
		return -1;
	}
	memset(digest, 0, digest_len);
	len = base64_encode(psk_ctx, hmac_len, digest);
	if (len < 0) {
		errno = ENOKEY;
		return len;
	}
	return strlen(digest);
}
#endif /* !CONFIG_OPENSSL_3 */

static int gen_tls_identity(const char *hostnqn, const char *subsysnqn,
			    int version, int cipher, char *digest,
			    char *identity)
{
	if (version == 0) {
		sprintf(identity, "NVMe%01dR%02d %s %s",
			version, cipher, hostnqn, subsysnqn);
		return strlen(identity);
	}
	if (version > 1) {
		errno = EINVAL;
		return -1;
	}

	sprintf(identity, "NVMe%01dR%02d %s %s %s",
		version, cipher, hostnqn, subsysnqn, digest);
	return strlen(identity);
}

static int derive_nvme_keys(const char *hostnqn, const char *subsysnqn,
			    char *identity, int version,
			    int hmac, unsigned char *configured,
			    unsigned char *psk, int key_len)
{
	_cleanup_free_ unsigned char *retained = NULL;
	_cleanup_free_ char *digest = NULL;
	char *context = identity;
	unsigned char cipher;
	int ret = -1;

	if (!hostnqn || !subsysnqn || !identity || !psk) {
		errno = EINVAL;
		return -1;
	}

	retained = malloc(key_len);
	if (!retained) {
		errno = ENOMEM;
		return -1;
	}
	ret = derive_retained_key(hmac, hostnqn, configured, retained, key_len);
	if (ret < 0)
		return ret;

	if (hmac == NVME_HMAC_ALG_NONE)
		cipher = default_hmac(key_len);
	else
		cipher = hmac;

	if (version == 1) {
		size_t digest_len = 2 * key_len;

		digest = malloc(digest_len);
		if (!digest) {
			errno = ENOMEM;
			return -1;
		}
		ret = derive_psk_digest(hostnqn, subsysnqn, version, cipher,
					retained, key_len,
					digest, digest_len);
		if (ret < 0)
			return ret;
		context = digest;
	}
	ret = gen_tls_identity(hostnqn, subsysnqn, version, cipher,
			       digest, identity);
	if (ret < 0)
		return ret;
	return derive_tls_key(version, cipher, context, retained,
			      psk, key_len);
}

static ssize_t nvme_identity_len(int hmac, int version, const char *hostnqn,
				 const char *subsysnqn)
{
	ssize_t len;

	if (!hostnqn || !subsysnqn) {
		errno = EINVAL;
		return -1;
	}

	len = strlen(hostnqn) + strlen(subsysnqn) + 12;
	if (version == 1) {
		len += 66;
		if (hmac == NVME_HMAC_ALG_SHA2_384)
			len += 32;
	} else if (version > 1) {
		errno = EINVAL;
		return -1;
	}
	return len;
}

char *nvme_generate_tls_key_identity(const char *hostnqn, const char *subsysnqn,
				     int version, int hmac,
				     unsigned char *configured_key, int key_len)
{
	_cleanup_free_ unsigned char *psk = NULL;
	char *identity;
	ssize_t identity_len;
	int ret = -1;

	identity_len = nvme_identity_len(hmac, version, hostnqn, subsysnqn);
	if (identity_len < 0)
		return NULL;

	identity = malloc(identity_len);
	if (!identity)
		return NULL;

	psk = malloc(key_len);
	if (!psk)
		goto out_free_identity;

	memset(psk, 0, key_len);
	ret = derive_nvme_keys(hostnqn, subsysnqn, identity, version, hmac,
			       configured_key, psk, key_len);
out_free_identity:
	if (ret < 0) {
		free(identity);
		identity = NULL;
	}
	return identity;
}

#ifdef CONFIG_KEYUTILS
long nvme_lookup_keyring(const char *keyring)
{
	key_serial_t keyring_id;

	if (!keyring)
		keyring = NVME_TLS_DEFAULT_KEYRING;
	keyring_id = find_key_by_type_and_desc("keyring", keyring, 0);
	if (keyring_id < 0)
		return 0;
	return keyring_id;
}

char *nvme_describe_key_serial(long key_id)
{
	_cleanup_free_ char *str = NULL;
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

long nvme_lookup_key(const char *type, const char *identity)
{
	key_serial_t key;

	key = keyctl_search(KEY_SPEC_SESSION_KEYRING, type, identity, 0);
	if (key < 0)
		return 0;
	return key;
}

int nvme_set_keyring(long key_id)
{
	long err;

	if (key_id == 0) {
		key_id = nvme_lookup_keyring(NULL);
		if (key_id == 0) {
			errno = ENOKEY;
			return -1;
		}
	}

	err = keyctl_link(key_id, KEY_SPEC_SESSION_KEYRING);
	if (err < 0)
		return -1;
	return 0;
}

unsigned char *nvme_read_key(long keyring_id, long key_id, int *len)
{
	void *buffer;
	int ret;

	ret = nvme_set_keyring(keyring_id);
	if (ret < 0) {
		errno = -ret;
		return NULL;
	}
	ret = keyctl_read_alloc(key_id, &buffer);
	if (ret < 0) {
		errno = -ret;
		buffer = NULL;
	} else
		*len = ret;

	return buffer;
}

long nvme_update_key(long keyring_id, const char *key_type,
		     const char *identity, unsigned char *key_data,
		     int key_len)
{
	long key;

	key = keyctl_search(keyring_id, key_type, identity, 0);
	if (key > 0) {
		if (keyctl_revoke(key) < 0)
			return 0;
	}
	key = add_key(key_type, identity,
		      key_data, key_len, keyring_id);
	if (key < 0)
		key = 0;
	return key;
}

struct __scan_keys_data {
	nvme_scan_tls_keys_cb_t cb;
	key_serial_t keyring;
	void *data;
};

int __scan_keys_cb(key_serial_t parent, key_serial_t key,
		   char *desc, int desc_len, void *data)
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
	(d->cb)(d->keyring, key, ptr + 1, strlen(ptr) - 1, d->data);
	return 1;
}

int nvme_scan_tls_keys(const char *keyring, nvme_scan_tls_keys_cb_t cb,
		       void *data)
{
	struct __scan_keys_data d;
	key_serial_t keyring_id = nvme_lookup_keyring(keyring);
	int ret;

	if (!keyring_id) {
		errno = EINVAL;
		return -1;
	}
	ret = nvme_set_keyring(keyring_id);
	if (ret < 0)
		return ret;

	d.keyring = keyring_id;
	d.cb = cb;
	d.data = data;
	ret = recursive_key_scan(keyring_id, __scan_keys_cb, &d);
	return ret;
}

static long __nvme_insert_tls_key_versioned(key_serial_t keyring_id, const char *key_type,
					    const char *hostnqn, const char *subsysnqn,
					    int version, int hmac,
					    unsigned char *configured_key, int key_len)
{
	_cleanup_free_ unsigned char *psk = NULL;
	_cleanup_free_ char *identity = NULL;
	ssize_t identity_len;
	key_serial_t key;
	int ret;

	identity_len = nvme_identity_len(hmac, version, hostnqn, subsysnqn);
	if (identity_len < 0)
		return 0;

	identity = malloc(identity_len);
	if (!identity) {
		errno = ENOMEM;
		return 0;
	}
	memset(identity, 0, identity_len);

	psk = malloc(key_len);
	if (!psk) {
		errno = ENOMEM;
		return 0;
	}
	memset(psk, 0, key_len);
	ret = derive_nvme_keys(hostnqn, subsysnqn, identity, version, hmac,
			       configured_key, psk, key_len);
	if (ret != key_len) {
		errno = ENOKEY;
		return 0;
	}

	key = nvme_update_key(keyring_id, key_type, identity,
			      psk, key_len);
	return key;
}

long nvme_insert_tls_key_versioned(const char *keyring, const char *key_type,
				   const char *hostnqn, const char *subsysnqn,
				   int version, int hmac,
				   unsigned char *configured_key, int key_len)
{
	key_serial_t keyring_id;
	int ret;

	keyring_id = nvme_lookup_keyring(keyring);
	if (keyring_id == 0) {
		errno = ENOKEY;
		return 0;
	}

	ret = nvme_set_keyring(keyring_id);
	if (ret < 0)
		return 0;
	return __nvme_insert_tls_key_versioned(keyring_id, key_type,
					       hostnqn, subsysnqn,
					       version, hmac,
					       configured_key, key_len);
}

long nvme_revoke_tls_key(const char *keyring, const char *key_type,
			 const char *identity)
{
	key_serial_t keyring_id;
	long key;

	keyring_id = nvme_lookup_keyring(keyring);
	if (keyring_id == 0) {
		errno = ENOKEY;
		return 0;
	}

	key = keyctl_search(keyring_id, key_type, identity, 0);
	if (key < 0)
		return -1;

	return keyctl_revoke(key);
}

static int __nvme_insert_tls_key(long keyring_id,
				 const char *hostnqn, const char *subsysnqn,
				 const char *identity, const char *key)
{
	_cleanup_free_ unsigned char *key_data = NULL;
	unsigned char version;
	unsigned char hmac;
	size_t key_len;

	key_data = nvme_import_tls_key_versioned(key, &version,
						 &hmac, &key_len);
	if (!key_data)
		return -EINVAL;

	if (hmac == NVME_HMAC_ALG_NONE || !identity) {
		/*
		 * This is a configured key (hmac 0) or we don't know the
		 * identity and so the assumtion is it is also a
		 * configured key. Derive a new key and load the newly
		 * created key into the keystore.
		 */
		return __nvme_insert_tls_key_versioned(keyring_id, "psk",
						       hostnqn, subsysnqn,
						       version, hmac,
						       key_data, key_len);
	}

	return nvme_update_key(keyring_id, "psk", identity,
			       key_data, key_len);
}

int __nvme_import_keys_from_config(nvme_host_t h, nvme_ctrl_t c,
				   long *keyring_id, long *key_id)
{
	const char *hostnqn = nvme_host_get_hostnqn(h);
	const char *subsysnqn = nvme_ctrl_get_subsysnqn(c);
	const char *keyring, *key, *identity;
	long kr_id, id = 0;

	if (!hostnqn || !subsysnqn) {
		nvme_msg(h->r, LOG_ERR, "Invalid NQNs (%s, %s)\n",
			 hostnqn, subsysnqn);
		return -EINVAL;
	}

	keyring = nvme_ctrl_get_keyring(c);
	if (keyring)
		kr_id = nvme_lookup_keyring(keyring);
	else
		kr_id = c->cfg.keyring;

	/*
	 * Fallback to the default keyring. Note this will also add the
	 * keyring to connect command line and to the JSON config output.
	 * That means we are explicitly selecting the keyring.
	 */
	if (!kr_id)
		kr_id = nvme_lookup_keyring(".nvme");

	if (nvme_set_keyring(kr_id) < 0) {
		nvme_msg(h->r, LOG_ERR, "Failed to set keyring\n");
		return -errno;
	}

	key = nvme_ctrl_get_tls_key(c);
	if (!key)
		return 0;

	identity = nvme_ctrl_get_tls_key_identity(c);
	if (identity)
		id = nvme_lookup_key("psk", identity);

	if (!id)
		id = __nvme_insert_tls_key(kr_id, hostnqn,
					   subsysnqn, identity, key);

	if (id <= 0) {
		nvme_msg(h->r, LOG_ERR, "Failed to insert TLS KEY, error %d\n",
			 errno);
		return -errno;
	}

	*keyring_id = kr_id;
	*key_id = id;

	return 0;
}
#else
long nvme_lookup_keyring(const char *keyring)
{
	nvme_msg(NULL, LOG_ERR, "key operations not supported; "\
		 "recompile with keyutils support.\n");
	errno = ENOTSUP;
	return 0;
}

char *nvme_describe_key_serial(long key_id)
{
	nvme_msg(NULL, LOG_ERR, "key operations not supported; "\
		 "recompile with keyutils support.\n");
	errno = ENOTSUP;
	return NULL;
}

long nvme_lookup_key(const char *type, const char *identity)
{
	nvme_msg(NULL, LOG_ERR, "key operations not supported; "\
		 "recompile with keyutils support.\n");
	errno = ENOTSUP;
	return 0;
}

int nvme_set_keyring(long key_id)
{
	nvme_msg(NULL, LOG_ERR, "key operations not supported; "\
		 "recompile with keyutils support.\n");
	errno = ENOTSUP;
	return -1;
}

unsigned char *nvme_read_key(long keyring_id, long key_id, int *len)
{
	errno = ENOTSUP;
	return NULL;
}

long nvme_update_key(long keyring_id, const char *key_type,
		     const char *identity, unsigned char *key_data,
		     int key_len)
{
	errno = ENOTSUP;
	return 0;
}

int nvme_scan_tls_keys(const char *keyring, nvme_scan_tls_keys_cb_t cb,
		       void *data)
{
	errno = ENOTSUP;
	return -1;
}

long nvme_insert_tls_key_versioned(const char *keyring, const char *key_type,
				   const char *hostnqn, const char *subsysnqn,
				   int version, int hmac,
				   unsigned char *configured_key, int key_len)
{
	nvme_msg(NULL, LOG_ERR, "key operations not supported; "
		 "recompile with keyutils support.\n");
	errno = ENOTSUP;
	return -1;
}

long nvme_revoke_tls_key(const char *keyring, const char *key_type,
			 const char *identity)
{
	nvme_msg(NULL, LOG_ERR, "key operations not supported; "
		 "recompile with keyutils support.\n");
	errno = ENOTSUP;
	return -1;
}

int __nvme_import_keys_from_config(nvme_host_t h, nvme_ctrl_t c,
				   long *keyring_id, long *key_id)
{
	return -ENOTSUP;
}
#endif

long nvme_insert_tls_key(const char *keyring, const char *key_type,
			 const char *hostnqn, const char *subsysnqn, int hmac,
			 unsigned char *configured_key, int key_len)
{
	return nvme_insert_tls_key_versioned(keyring, key_type,
					     hostnqn, subsysnqn, 0, hmac,
					     configured_key, key_len);
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
char *nvme_export_tls_key_versioned(unsigned char version, unsigned char hmac,
				    const unsigned char *key_data,
				    size_t key_len)
{
	unsigned int raw_len, encoded_len, len;
	unsigned long crc = crc32(0L, NULL, 0);
	unsigned char raw_secret[52];
	char *encoded_key;

	switch (hmac) {
	case NVME_HMAC_ALG_NONE:
		if (key_len != 32 && key_len != 48)
			goto err_inval;
		break;
	case NVME_HMAC_ALG_SHA2_256:
		if (key_len != 32)
			goto err_inval;
		break;
	case NVME_HMAC_ALG_SHA2_384:
		if (key_len != 48)
			goto err_inval;
		break;
	default:
		goto err_inval;
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
	if (!encoded_key) {
		errno = ENOMEM;
		return NULL;
	}
	memset(encoded_key, 0, encoded_len);
	len = sprintf(encoded_key, "NVMeTLSkey-%x:%02x:", version, hmac);
	len += base64_encode(raw_secret, raw_len, encoded_key + len);
	encoded_key[len++] = ':';
	encoded_key[len++] = '\0';

	return encoded_key;

err_inval:
	errno = EINVAL;
	return NULL;

}

char *nvme_export_tls_key(const unsigned char *key_data, int key_len)
{
	unsigned char hmac;

	if (key_len == 32)
		hmac = NVME_HMAC_ALG_SHA2_256;
	else
		hmac = NVME_HMAC_ALG_SHA2_384;

	return nvme_export_tls_key_versioned(1, hmac, key_data, key_len);
}

unsigned char *nvme_import_tls_key_versioned(const char *encoded_key,
					     unsigned char *version,
					     unsigned char *hmac,
					     size_t *key_len)
{
	unsigned char decoded_key[128], *key_data;
	unsigned int crc = crc32(0L, NULL, 0);
	unsigned int key_crc;
	int err, _version, _hmac, decoded_len;
	size_t len;

	if (sscanf(encoded_key, "NVMeTLSkey-%d:%02x:*s",
		   &_version, &_hmac) != 2) {
		errno = EINVAL;
		return NULL;
	}

	if (_version != 1) {
		errno = EINVAL;
		return NULL;
	}
	*version = _version;

	len = strlen(encoded_key);
	switch (_hmac) {
	case NVME_HMAC_ALG_NONE:
		if (len != 65 && len != 89)
			goto err_inval;
		break;
	case NVME_HMAC_ALG_SHA2_256:
		if (len != 65)
			goto err_inval;
		break;
	case NVME_HMAC_ALG_SHA2_384:
		if (len != 89)
			goto err_inval;
		break;
	default:
		errno = EINVAL;
		return NULL;
	}
	*hmac = _hmac;

	err = base64_decode(encoded_key + 16, len - 17, decoded_key);
	if (err < 0) {
		errno = ENOKEY;
		return NULL;
	}
	decoded_len = err;
	decoded_len -= 4;
	if (decoded_len != 32 && decoded_len != 48) {
		errno = ENOKEY;
		return NULL;
	}
	crc = crc32(crc, decoded_key, decoded_len);
	key_crc = ((uint32_t)decoded_key[decoded_len]) |
		((uint32_t)decoded_key[decoded_len + 1] << 8) |
		((uint32_t)decoded_key[decoded_len + 2] << 16) |
		((uint32_t)decoded_key[decoded_len + 3] << 24);
	if (key_crc != crc) {
		nvme_msg(NULL, LOG_ERR, "CRC mismatch (key %08x, crc %08x)",
			 key_crc, crc);
		errno = ENOKEY;
		return NULL;
	}

	key_data = malloc(decoded_len);
	if (!key_data) {
		errno = ENOMEM;
		return NULL;
	}
	memcpy(key_data, decoded_key, decoded_len);

	*key_len = decoded_len;
	return key_data;

err_inval:
	errno = EINVAL;
	return NULL;
}

unsigned char *nvme_import_tls_key(const char *encoded_key, int *key_len,
				   unsigned int *hmac)
{
	unsigned char version, _hmac;
	unsigned char *psk;
	size_t len;

	psk = nvme_import_tls_key_versioned(encoded_key, &version,
					    &_hmac, &len);
	if (!psk)
		return NULL;

	*hmac = _hmac;
	*key_len = len;
	return psk;
}
