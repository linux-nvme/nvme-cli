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

#ifdef CONFIG_OPENSSL_3
#include <openssl/core_names.h>
#include <openssl/params.h>
#endif
#endif

#include <ccan/endian/endian.h>

#include "linux.h"
#include "tree.h"
#include "log.h"

static int __nvme_open(const char *name)
{
	char *path;
	int fd, ret;

	ret = asprintf(&path, "%s/%s", "/dev", name);
	if (ret < 0) {
		errno = ENOMEM;
		return -1;
	}

	fd = open(path, O_RDONLY);
	free(path);
	return fd;
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

int __nvme_get_log_page(int fd, __u32 nsid, __u8 log_id, bool rae,
			__u32 xfer_len, __u32 data_len, void *data)
{
	__u64 offset = 0, xfer;
	bool retain = true;
	void *ptr = data;
	int ret;
	struct nvme_get_log_args args = {
		.args_size = sizeof(args),
		.fd = fd,
		.nsid = nsid,
		.lid = log_id,
		.lsp = NVME_LOG_LSP_NONE,
		.lsi = NVME_LOG_LSI_NONE,
		.uuidx = NVME_UUID_NONE,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result = NULL,
		.csi = NVME_CSI_NVM,
		.ot = false,
	};

	/*
	 * 4k is the smallest possible transfer unit, so restricting to 4k
	 * avoids having to check the MDTS value of the controller.
	 */
	do {
		xfer = data_len - offset;
		if (xfer > xfer_len)
			xfer  = xfer_len;

		/*
		 * Always retain regardless of the RAE parameter until the very
		 * last portion of this log page so the data remains latched
		 * during the fetch sequence.
		 */
		if (offset + xfer == data_len)
			retain = rae;

		args.lpo = offset;
		args.len = xfer;
		args.log = ptr;
		args.rae = retain;
		ret = nvme_get_log(&args);
		if (ret)
			return ret;

		offset += xfer;
		ptr += xfer;
	} while (offset < data_len);

	return 0;
}

int nvme_get_log_page(int fd, __u32 nsid, __u8 log_id, bool rae,
		      __u32 data_len, void *data)
{
	return __nvme_get_log_page(fd, nsid, log_id, rae, 4096, data_len, data);
}

static int nvme_get_telemetry_log(int fd, bool create, bool ctrl, bool rae,
				  struct nvme_telemetry_log **buf)
{
	static const __u32 xfer = NVME_LOG_TELEM_BLOCK_SIZE;

	struct nvme_telemetry_log *telem;
	enum nvme_cmd_get_log_lid lid;
	void *log, *tmp;
	__u32 size;
	int err;

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
		goto free;

	telem = log;
	if (ctrl && !telem->ctrlavail) {
		*buf = log;
		return 0;
	}

	/* dalb3 >= dalb2 >= dalb1 */
	size = (le16_to_cpu(telem->dalb3) + 1) * xfer;
	tmp = realloc(log, size);
	if (!tmp) {
		errno = ENOMEM;
		err = -1;
		goto free;
	}
	log = tmp;

	err = nvme_get_log_page(fd, NVME_NSID_NONE, lid, rae, size, (void *)log);
	if (!err) {
		*buf = log;
		return 0;
	}
free:
	free(log);
	return err;
}

int nvme_get_ctrl_telemetry(int fd, bool rae, struct nvme_telemetry_log **log)
{
	return nvme_get_telemetry_log(fd, false, true, rae, log);
}

int nvme_get_host_telemetry(int fd, struct nvme_telemetry_log **log)
{
	return nvme_get_telemetry_log(fd, false, false, false, log);
}

int nvme_get_new_host_telemetry(int fd, struct nvme_telemetry_log **log)
{
	return nvme_get_telemetry_log(fd, true, false, false, log);
}

int nvme_get_lba_status_log(int fd, bool rae, struct nvme_lba_status_log **log)
{
	__u32 size = sizeof(struct nvme_lba_status_log);
	void *buf, *tmp;
	int err;

	buf = malloc(size);
	if (!buf)
		return -1;

	*log = buf;
	err = nvme_get_log_lba_status(fd, true, 0, size, buf);
	if (err)
		goto free;

	size = le32_to_cpu((*log)->lslplen);
	if (!size)
		return 0;

	tmp = realloc(buf, size);
	if (!tmp) {
		err = -1;
		goto free;
	}
	buf = tmp;
	*log = buf;

	err = nvme_get_log_page(fd, NVME_NSID_NONE, NVME_LOG_LID_LBA_STATUS,
				rae, size, buf);
	if (!err)
		return 0;

free:
	*log = NULL;
	free(buf);
	return err;
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
	struct nvme_id_ctrl ctrl;
	int ret;

	ret = nvme_identify_ctrl(fd, &ctrl);
	if (ret)
		return ret;

	*analen = sizeof(struct nvme_ana_log) +
		le32_to_cpu(ctrl.nanagrpid) * sizeof(struct nvme_ana_group_desc) +
		le32_to_cpu(ctrl.mnan) * sizeof(__le32);
	return 0;
}

int nvme_get_logical_block_size(int fd, __u32 nsid, int *blksize)
{
	struct nvme_id_ns ns;
	int flbas;
	int ret;

	ret = nvme_identify_ns(fd, nsid, &ns);
	if (ret)
		return ret;

	flbas = ns.flbas & NVME_NS_FLBAS_LBA_MASK;
	*blksize = 1 << ns.lbaf[flbas].ds;

	return 0;
}

static int __nvme_set_attr(const char *path, const char *value)
{
	int ret, fd;

	fd = open(path, O_WRONLY);
	if (fd < 0) {
#if 0
		nvme_msg(LOG_DEBUG, "Failed to open %s: %s\n", path,
			 strerror(errno));
#endif
		return -1;
	}
	ret = write(fd, value, strlen(value));
	close(fd);
	return ret;
}

int nvme_set_attr(const char *dir, const char *attr, const char *value)
{
	char *path;
	int ret;

	ret = asprintf(&path, "%s/%s", dir, attr);
	if (ret < 0)
		return -1;

	ret = __nvme_set_attr(path, value);
	free(path);
	return ret;
}

static char *__nvme_get_attr(const char *path)
{
	char value[4096] = { 0 };
	int ret, fd;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
#if 0
		nvme_msg(LOG_DEBUG, "Failed to open %s: %s\n", path,
			 strerror(errno));
#endif
		return NULL;
	}

	ret = read(fd, value, sizeof(value) - 1);
	close(fd);
	if (ret < 0 || !strlen(value)) {
		return NULL;
	}

	if (value[strlen(value) - 1] == '\n')
		value[strlen(value) - 1] = '\0';
	while (strlen(value) > 0 && value[strlen(value) - 1] == ' ')
		value[strlen(value) - 1] = '\0';

	return strlen(value) ? strdup(value) : NULL;
}

char *nvme_get_attr(const char *dir, const char *attr)
{
	char *path, *value;
	int ret;

	ret = asprintf(&path, "%s/%s", dir, attr);
	if (ret < 0)
		return NULL;

	value = __nvme_get_attr(path);
	free(path);
	return value;
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
		nvme_msg(LOG_ERR, "HMAC transformation not supported; " \
			"recompile with OpenSSL support.\n");
		errno = -EINVAL;
		return -1;
	}

	memcpy(key, secret, key_len);
	return 0;
}
#endif /* !CONFIG_OPENSSL */

#ifdef CONFIG_OPENSSL_1
int nvme_gen_dhchap_key(char *hostnqn, enum nvme_hmac_alg hmac,
			unsigned int key_len, unsigned char *secret,
			unsigned char *key)
{
	const char hmac_seed[] = "NVMe-over-Fabrics";
	HMAC_CTX *hmac_ctx;
	const EVP_MD *md;
	int err = -1;

	ENGINE_load_builtin_engines();
	ENGINE_register_all_complete();

	hmac_ctx = HMAC_CTX_new();
	if (!hmac_ctx) {
		nvme_msg(LOG_ERR, "OpenSSL: could not create HMAC context\n");
		errno = ENOENT;
		return err;
	}

	switch (hmac) {
	case NVME_HMAC_ALG_NONE:
		memcpy(key, secret, key_len);
		err = 0;
		goto out;
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
		goto out;
	}

	if (!md) {
		nvme_msg(LOG_ERR, "OpenSSL: could not fetch hash function\n");
		errno = ENOENT;
		goto out;
	}

	if (!HMAC_Init_ex(hmac_ctx, secret, key_len, md, NULL)) {
		nvme_msg(LOG_ERR, "OpenSSL: initializing HMAC context failed\n");
		errno = ENOENT;
		goto out;
	}

	if (!HMAC_Update(hmac_ctx, (unsigned char *)hostnqn,
			 strlen(hostnqn))) {
		nvme_msg(LOG_ERR, "OpenSSL: HMAC for hostnqn failed\n");
		errno = ENOENT;
		goto out;
	}

	if (!HMAC_Update(hmac_ctx, (unsigned char *)hmac_seed,
			 strlen(hmac_seed))) {
		nvme_msg(LOG_ERR, "OpenSSL: HMAC for seed failed\n");
		errno = ENOENT;
		goto out;
	}

	if (!HMAC_Final(hmac_ctx, key, &key_len)) {
		nvme_msg(LOG_ERR, "OpenSSL: finializing MAC failed\n");
		errno = ENOENT;
		goto out;
	}

	err = 0;

out:
	HMAC_CTX_free(hmac_ctx);
	return err;
}
#endif /* !CONFIG_OPENSSL_1 */

#ifdef CONFIG_OPENSSL_3
int nvme_gen_dhchap_key(char *hostnqn, enum nvme_hmac_alg hmac,
			unsigned int key_len, unsigned char *secret,
			unsigned char *key)
{
	const char hmac_seed[] = "NVMe-over-Fabrics";
	OSSL_PARAM params[2], *p = params;
	OSSL_LIB_CTX *lib_ctx;
	EVP_MAC_CTX *mac_ctx = NULL;
	EVP_MAC *mac = NULL;
	char *progq = NULL;
	char *digest;
	size_t len;
	int err = -1;

	lib_ctx = OSSL_LIB_CTX_new();
	if (!lib_ctx) {
		nvme_msg(LOG_ERR, "OpenSSL: Library initializing failed\n");
		errno = ENOENT;
		return err;
	}

	mac = EVP_MAC_fetch(lib_ctx, OSSL_MAC_NAME_HMAC, progq);
	if (!mac) {
		nvme_msg(LOG_ERR, "OpenSSL: could not fetch HMAC algorithm\n");
		errno = EINVAL;
		goto out;
	}

	mac_ctx = EVP_MAC_CTX_new(mac);
	if (!mac_ctx) {
		nvme_msg(LOG_ERR, "OpenSSL: could not create HMAC context\n");
		errno = ENOENT;
		goto out;
	}

	switch (hmac) {
	case NVME_HMAC_ALG_NONE:
		memcpy(key, secret, key_len);
		err = 0;
		goto out;
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
		goto out;
	}
	*p++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
						digest,
						0);
	*p = OSSL_PARAM_construct_end();

	if (!EVP_MAC_init(mac_ctx, secret, key_len, params)) {
		nvme_msg(LOG_ERR, "OpenSSL: could not initialize HMAC context\n");
		errno = EINVAL;
		goto out;
	}

	if (!EVP_MAC_update(mac_ctx, (unsigned char *)hostnqn,
			    strlen(hostnqn))) {
		nvme_msg(LOG_ERR, "OpenSSL: HMAC for hostnqn failed\n");
		errno = ENOENT;
		goto out;
	}

	if (!EVP_MAC_update(mac_ctx, (unsigned char *)hmac_seed,
			    strlen(hmac_seed))) {
		nvme_msg(LOG_ERR, "OpenSSL: HMAC for seed failed\n");
		errno = ENOENT;
		goto out;
	}

	if (!EVP_MAC_final(mac_ctx, key, &len, key_len)) {
		nvme_msg(LOG_ERR, "OpenSSL: finializing MAC failed\n");
		errno = ENOENT;
		goto out;
	}

	if (len != key_len) {
		nvme_msg(LOG_ERR, "OpenSSL: generated HMAC has an unexpected lenght\n");
		errno = EINVAL;
		goto out;
	}

	err = 0;

out:
	EVP_MAC_CTX_free(mac_ctx);
	EVP_MAC_free(mac);
	OSSL_LIB_CTX_free(lib_ctx);

	return err;
}
#endif /* !CONFIG_OPENSSL_3 */
