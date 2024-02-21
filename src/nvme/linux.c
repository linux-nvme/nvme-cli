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
#include <openssl/engine.h>
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
	_cleanup_free_ void *log;
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

	log = malloc(xfer);
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
	tmp = realloc(log, *size);
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
	__u32 size;
	_cleanup_free_ struct nvme_lba_status_log *buf;
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

	*analen = sizeof(struct nvme_ana_log) +
		le32_to_cpu(ctrl->nanagrpid) * sizeof(struct nvme_ana_group_desc) +
		le32_to_cpu(ctrl->mnan) * sizeof(__le32);
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

static int gen_tls_identity(const char *hostnqn, const char *subsysnqn,
			    int version, int hmac, char *identity,
			    unsigned char *retained, size_t key_len)
{
	if (version != 0) {
		nvme_msg(NULL, LOG_ERR, "NVMe TLS 2.0 is not supported; "
			 "recompile with OpenSSL support.\n");
		errno = ENOTSUP;
		return -1;
	}
	sprintf(identity, "NVMe0R%02d %s %s",
		hmac, hostnqn, subsysnqn);
	return strlen(identity);
}

static int derive_tls_key(int hmac, const char *identity,
			  unsigned char *retained,
			  unsigned char *psk, size_t key_len)
{
	nvme_msg(NULL, LOG_ERR, "NVMe TLS is not supported; "
		 "recompile with OpenSSL support.\n");
	errno = ENOTSUP;
	return -1;
}
#else /* CONFIG_OPENSSL */
static const EVP_MD *select_hmac(int hmac, size_t *key_len)
{
	const EVP_MD *md = NULL;

	switch (hmac) {
	case NVME_HMAC_ALG_SHA2_256:
		md = EVP_sha256();
		*key_len = 32;
		break;
	case NVME_HMAC_ALG_SHA2_384:
		md = EVP_sha384();
		*key_len = 48;
		break;
	default:
		break;
	}
	return md;
}

static DEFINE_CLEANUP_FUNC(
	cleanup_evp_pkey_ctx, EVP_PKEY_CTX *, EVP_PKEY_CTX_free)
#define _cleanup_evp_pkey_ctx_ __cleanup__(cleanup_evp_pkey_ctx)

static int derive_retained_key(int hmac, const char *hostnqn,
			       unsigned char *generated,
			       unsigned char *retained,
			       size_t key_len)
{
	const EVP_MD *md;
	_cleanup_evp_pkey_ctx_ EVP_PKEY_CTX *ctx = NULL;
	uint16_t length = key_len & 0xFFFF;
	size_t hmac_len;

	md = select_hmac(hmac, &hmac_len);
	if (!md || hmac_len > key_len) {
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
	if (EVP_PKEY_CTX_set1_hkdf_key(ctx, generated, key_len) <= 0) {
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

static int derive_tls_key(int hmac, const char *identity,
			  unsigned char *retained,
			  unsigned char *psk, size_t key_len)
{
	const EVP_MD *md;
	_cleanup_evp_pkey_ctx_ EVP_PKEY_CTX *ctx = NULL;
	size_t hmac_len;
	uint16_t length = key_len & 0xFFFF;

	md = select_hmac(hmac, &hmac_len);
	if (!md || hmac_len > key_len) {
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
	if (EVP_PKEY_CTX_add1_hkdf_info(ctx,
			(const unsigned char *)identity,
			strlen(identity)) <= 0) {
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

	ENGINE_load_builtin_engines();
	ENGINE_register_all_complete();

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

static int gen_tls_identity(const char *hostnqn, const char *subsysnqn,
			    int version, int hmac, char *identity,
			    unsigned char *retained, size_t key_len)
{
	static const char hmac_seed[] = "NVMe-over-Fabrics";
	size_t hmac_len;
	const EVP_MD *md = select_hmac(hmac, &hmac_len);
	_cleanup_hmac_ctx_ HMAC_CTX *hmac_ctx = NULL;
	_cleanup_free_ unsigned char *psk_ctx = NULL;
	_cleanup_free_ char *enc_ctx = NULL;
	size_t len;

	if (version == 0) {
		sprintf(identity, "NVMe%01dR%02d %s %s",
			version, hmac, hostnqn, subsysnqn);
		return strlen(identity);
	}
	if (version > 1) {
		errno = EINVAL;
		return -1;
	}

	hmac_ctx = HMAC_CTX_new();
	if (!hmac_ctx) {
		errno = ENOMEM;
		return -1;
	}
	if (!md) {
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
	enc_ctx = malloc(key_len * 2);
	memset(enc_ctx, 0, key_len * 2);
	len = base64_encode(psk_ctx, key_len, enc_ctx);
	if (len < 0) {
		errno = ENOKEY;
		return len;
	}
	sprintf(identity, "NVMe%01dR%02d %s %s %s",
		version, hmac, hostnqn, subsysnqn, enc_ctx);
	return strlen(identity);
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
	OSSL_PARAM params[2], *p = params;
	_cleanup_ossl_lib_ctx_ OSSL_LIB_CTX *lib_ctx = NULL;
	_cleanup_evp_mac_ctx_ EVP_MAC_CTX *mac_ctx = NULL;
	_cleanup_evp_mac_ EVP_MAC *mac = NULL;
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

static int gen_tls_identity(const char *hostnqn, const char *subsysnqn,
			    int version, int hmac, char *identity,
			    unsigned char *retained, size_t key_len)
{
	static const char hmac_seed[] = "NVMe-over-Fabrics";
	size_t hmac_len;
	OSSL_PARAM params[2], *p = params;
	_cleanup_ossl_lib_ctx_ OSSL_LIB_CTX *lib_ctx = NULL;
	_cleanup_evp_mac_ctx_ EVP_MAC_CTX *mac_ctx = NULL;
	_cleanup_evp_mac_ EVP_MAC *mac = NULL;
	char *progq = NULL;
	char *digest = NULL;
	_cleanup_free_ unsigned char *psk_ctx = NULL;
	_cleanup_free_ char *enc_ctx = NULL;
	size_t len;

	if (version == 0) {
		sprintf(identity, "NVMe%01dR%02d %s %s",
			version, hmac, hostnqn, subsysnqn);
		return strlen(identity);
	}
	if (version > 1) {
		errno = EINVAL;
		return -1;
	}

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
	case NVME_HMAC_ALG_SHA2_256:
		digest = OSSL_DIGEST_NAME_SHA2_256;
		break;
	case NVME_HMAC_ALG_SHA2_384:
		digest = OSSL_DIGEST_NAME_SHA2_384;
		break;
	default:
		errno = EINVAL;
		break;
	}
	if (!digest)
		return -1;
	*p++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
						digest, 0);
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
	enc_ctx = malloc(hmac_len * 2);
	memset(enc_ctx, 0, hmac_len * 2);
	len = base64_encode(psk_ctx, hmac_len, enc_ctx);
	if (len < 0) {
		errno = ENOKEY;
		return len;
	}
	sprintf(identity, "NVMe%01dR%02d %s %s %s",
		version, hmac, hostnqn, subsysnqn, enc_ctx);
	return strlen(identity);
}
#endif /* !CONFIG_OPENSSL_3 */

static int derive_nvme_keys(const char *hostnqn, const char *subsysnqn,
			    char *identity, int version,
			    int hmac, unsigned char *configured,
			    unsigned char *psk, int key_len)
{
	_cleanup_free_ unsigned char *retained = NULL;
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
	ret = gen_tls_identity(hostnqn, subsysnqn, version, hmac,
			       identity, retained, key_len);
	if (ret < 0)
		return ret;
	return derive_tls_key(hmac, identity, retained, psk, key_len);
}

static size_t nvme_identity_len(int hmac, int version, const char *hostnqn,
				const char *subsysnqn)
{
	size_t len;

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
	char *identity;
	size_t identity_len;
	_cleanup_free_ unsigned char *psk = NULL;
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
	char *desc;

	if (keyctl_describe_alloc(key_id, &desc) < 0)
		desc = NULL;
	return desc;
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

	err = keyctl_link(key_id, KEY_SPEC_SESSION_KEYRING);
	if (err < 0)
		return -1;
	return 0;
}

long nvme_insert_tls_key_versioned(const char *keyring, const char *key_type,
				   const char *hostnqn, const char *subsysnqn,
				   int version, int hmac,
				   unsigned char *configured_key, int key_len)
{
	key_serial_t keyring_id, key;
	_cleanup_free_ char *identity = NULL;
	size_t identity_len;
	_cleanup_free_ unsigned char *psk = NULL;
	int ret = -1;

	keyring_id = nvme_lookup_keyring(keyring);
	if (keyring_id == 0)
		return -1;

	identity_len = nvme_identity_len(hmac, version, hostnqn, subsysnqn);
	if (identity_len < 0)
		return -1;

	identity = malloc(identity_len);
	if (!identity) {
		errno = ENOMEM;
		return -1;
	}

	psk = malloc(key_len);
	if (!psk) {
		errno = ENOMEM;
		return 0;
	}
	memset(psk, 0, key_len);
	ret = derive_nvme_keys(hostnqn, subsysnqn, identity, version, hmac,
			       configured_key, psk, key_len);
	if (ret != key_len)
		return 0;

	key = keyctl_search(keyring_id, key_type, identity, 0);
	if (key > 0) {
		if (keyctl_update(key, psk, key_len) < 0)
			key = 0;
	} else {
		key = add_key(key_type, identity,
			      psk, key_len, keyring_id);
		if (key < 0)
			key = 0;
	}
	return key;
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
#endif

long nvme_insert_tls_key(const char *keyring, const char *key_type,
			 const char *hostnqn, const char *subsysnqn, int hmac,
			 unsigned char *configured_key, int key_len)
{
	return nvme_insert_tls_key_versioned(keyring, key_type,
					     hostnqn, subsysnqn, 0, hmac,
					     configured_key, key_len);
}
