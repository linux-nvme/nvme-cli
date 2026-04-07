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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <linux/fs.h>
#endif

#include <ccan/build_assert/build_assert.h>
#include <ccan/endian/endian.h>
#include <ccan/minmax/minmax.h>

#include <libnvme.h>

#include "private.h"
#include "compiler_attributes.h"

#ifndef _WIN32
static int nvme_verify_chr(struct nvme_transport_handle *hdl)
{
	static struct stat nvme_stat;
	int err = nvme_fstat(hdl->fd, &nvme_stat);

	if (err < 0)
		return -errno;

	if (!S_ISCHR(nvme_stat.st_mode))
		return -EINVAL;
	return 0;
}

__public int nvme_reset_subsystem(struct nvme_transport_handle *hdl)
{
	int ret;

	ret = nvme_verify_chr(hdl);
	if (ret)
		return ret;

	ret = ioctl(hdl->fd, NVME_IOCTL_SUBSYS_RESET);
	if (ret < 0)
		return -errno;
	return ret;
}

__public int nvme_reset_ctrl(struct nvme_transport_handle *hdl)
{
	int ret;

	ret = nvme_verify_chr(hdl);
	if (ret)
		return ret;

	ret = ioctl(hdl->fd, NVME_IOCTL_RESET);
	if (ret < 0)
		return -errno;
	return ret;
}

__public int nvme_rescan_ns(struct nvme_transport_handle *hdl)
{
	int ret;

	ret = nvme_verify_chr(hdl);
	if (ret)
		return ret;

	ret = ioctl(hdl->fd, NVME_IOCTL_RESCAN);
	if (ret < 0)
		return -errno;
	return ret;
}

__public int nvme_get_nsid(struct nvme_transport_handle *hdl, __u32 *nsid)
{
	__u32 tmp;

	errno = 0;
	tmp = ioctl(hdl->fd, NVME_IOCTL_ID);
	if (errno)
		return -errno;

	*nsid = tmp;
	return 0;
}

__public int nvme_update_block_size(struct nvme_transport_handle *hdl,
		int block_size)
{
	int ret;
	nvme_fd_t fd = nvme_transport_handle_get_fd(hdl);

	ret = ioctl(fd, BLKBSZSET, &block_size);
	if (ret < 0)
		return -errno;

	ret = ioctl(fd, BLKRRPART);
	if (ret < 0)
		return -errno;

	return 0;
}
#endif

void *__nvme_submit_entry(struct nvme_transport_handle *hdl,
		struct nvme_passthru_cmd *cmd)
{
	return NULL;
}

void __nvme_submit_exit(struct nvme_transport_handle *hdl,
		struct nvme_passthru_cmd *cmd, int err, void *user_data)
{
}

bool __nvme_decide_retry(struct nvme_transport_handle *hdl,
		struct nvme_passthru_cmd *cmd, int err)
{
	return false;
}

#ifndef _WIN32
/*
 * The 64 bit version is the preferred version to use, but for backwards
 * compatibility keep a 32 version.
 */
static int nvme_submit_passthru32(struct nvme_transport_handle *hdl,
		unsigned long ioctl_cmd, struct nvme_passthru_cmd *cmd)
{
	struct linux_passthru_cmd32 cmd32;
	void *user_data;
	int err = 0;

	user_data = hdl->submit_entry(hdl, cmd);
	if (hdl->ctx->dry_run)
		goto out;

	memcpy(&cmd32, cmd, offsetof(struct linux_passthru_cmd32, result));
	cmd32.result = 0;

	do {
		err = ioctl(hdl->fd, ioctl_cmd, &cmd32);
		if (err >= 0)
			break;
		err = -errno;
	} while (hdl->decide_retry(hdl, cmd, err));

out:
	cmd->result = cmd32.result;
	hdl->submit_exit(hdl, cmd, err, user_data);
	return err;
}

/*
 * supported since kernel 5.4, see
 * 65e68edce0db ("nvme: allow 64-bit results in passthru commands")
 */
static int nvme_submit_passthru64(struct nvme_transport_handle *hdl,
		unsigned long ioctl_cmd, struct nvme_passthru_cmd *cmd)
{
	void *user_data;
	int err = 0;

	user_data = hdl->submit_entry(hdl, cmd);
	if (hdl->ctx->dry_run)
		goto out;

	do {
		/*
		 * struct nvme_passtrhu_cmd is identically to struct
		 * linux_passthru_cmd64, thus just pass it in directly.
		 */
		err = ioctl(hdl->fd, ioctl_cmd, cmd);
		if (err >= 0)
			break;
		err = -errno;
	} while (hdl->decide_retry(hdl, cmd, err));

out:
	hdl->submit_exit(hdl, cmd, err, user_data);
	return err;
}

__public int nvme_submit_io_passthru(struct nvme_transport_handle *hdl,
		struct nvme_passthru_cmd *cmd)
{
	if (hdl->ioctl_io64)
		return nvme_submit_passthru64(hdl, NVME_IOCTL_IO64_CMD, cmd);
	return nvme_submit_passthru32(hdl, NVME_IOCTL_IO_CMD, cmd);
}

__public int nvme_submit_admin_passthru(struct nvme_transport_handle *hdl,
		struct nvme_passthru_cmd *cmd)
{
	switch (hdl->type) {
	case NVME_TRANSPORT_HANDLE_TYPE_DIRECT:
		if (hdl->ioctl_admin64)
			return nvme_submit_passthru64(hdl,
				NVME_IOCTL_ADMIN64_CMD, cmd);
		if (cmd->opcode == nvme_admin_fabrics)
			return -ENOTSUP;
		return nvme_submit_passthru32(hdl,
				NVME_IOCTL_ADMIN_CMD, cmd);
	case NVME_TRANSPORT_HANDLE_TYPE_MI:
		return nvme_mi_admin_admin_passthru(hdl, cmd);
	default:
		break;
	}

	return -ENOTSUP;
}
#endif /* !_WIN32 */