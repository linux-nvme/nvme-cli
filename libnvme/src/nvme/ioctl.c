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
#include <unistd.h>

#include <linux/fs.h>

#include <sys/ioctl.h>
#include <sys/stat.h>

#include <ccan/build_assert/build_assert.h>
#include <ccan/endian/endian.h>
#include <ccan/minmax/minmax.h>

#include <libnvme.h>

#include "private.h"
#include "compiler-attributes.h"

static int nvme_verify_chr(struct libnvme_transport_handle *hdl)
{
	static struct stat nvme_stat;
	int err = fstat(hdl->fd, &nvme_stat);

	if (err < 0)
		return -errno;

	if (!S_ISCHR(nvme_stat.st_mode))
		return -EINVAL;
	return 0;
}

__public int libnvme_reset_subsystem(struct libnvme_transport_handle *hdl)
{
	int ret;

	ret = nvme_verify_chr(hdl);
	if (ret)
		return ret;

	ret = ioctl(hdl->fd, LIBNVME_IOCTL_SUBSYS_RESET);
	if (ret < 0)
		return -errno;
	return ret;
}

__public int libnvme_reset_ctrl(struct libnvme_transport_handle *hdl)
{
	int ret;

	ret = nvme_verify_chr(hdl);
	if (ret)
		return ret;

	ret = ioctl(hdl->fd, LIBNVME_IOCTL_RESET);
	if (ret < 0)
		return -errno;
	return ret;
}

__public int libnvme_rescan_ns(struct libnvme_transport_handle *hdl)
{
	int ret;

	ret = nvme_verify_chr(hdl);
	if (ret)
		return ret;

	ret = ioctl(hdl->fd, LIBNVME_IOCTL_RESCAN);
	if (ret < 0)
		return -errno;
	return ret;
}

__public int libnvme_get_nsid(struct libnvme_transport_handle *hdl, __u32 *nsid)
{
	__u32 tmp;

	errno = 0;
	tmp = ioctl(hdl->fd, LIBNVME_IOCTL_ID);
	if (errno)
		return -errno;

	*nsid = tmp;
	return 0;
}

__public int libnvme_update_block_size(struct libnvme_transport_handle *hdl,
		int block_size)
{
	int ret;
	int fd = libnvme_transport_handle_get_fd(hdl);

	ret = ioctl(fd, BLKBSZSET, &block_size);
	if (ret < 0)
		return -errno;

	ret = ioctl(fd, BLKRRPART);
	if (ret < 0)
		return -errno;

	return 0;
}

void *__libnvme_submit_entry(struct libnvme_transport_handle *hdl,
		struct libnvme_passthru_cmd *cmd)
{
	return NULL;
}

void __libnvme_submit_exit(struct libnvme_transport_handle *hdl,
		struct libnvme_passthru_cmd *cmd, int err, void *user_data)
{
}

bool __libnvme_decide_retry(struct libnvme_transport_handle *hdl,
		struct libnvme_passthru_cmd *cmd, int err)
{
	return false;
}

/*
 * The 64 bit version is the preferred version to use, but for backwards
 * compatibility keep a 32 version.
 */
static int libnvme_submit_passthru32(struct libnvme_transport_handle *hdl,
		unsigned long ioctl_cmd, struct libnvme_passthru_cmd *cmd)
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
static int libnvme_submit_passthru64(struct libnvme_transport_handle *hdl,
		unsigned long ioctl_cmd, struct libnvme_passthru_cmd *cmd)
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

__public int libnvme_submit_io_passthru(struct libnvme_transport_handle *hdl,
		struct libnvme_passthru_cmd *cmd)
{
	if (!hdl)
		return -ENODEV;

	if (!cmd->timeout_ms && hdl->timeout)
		cmd->timeout_ms = hdl->timeout;

	if (hdl->ioctl_io64)
		return libnvme_submit_passthru64(hdl,
			LIBNVME_IOCTL_IO64_CMD, cmd);
	return libnvme_submit_passthru32(hdl, LIBNVME_IOCTL_IO_CMD, cmd);
}

__public int libnvme_submit_admin_passthru(struct libnvme_transport_handle *hdl,
		struct libnvme_passthru_cmd *cmd)
{
	if (!hdl)
		return -ENODEV;

	if (hdl->uring_enabled)
		return libnvme_submit_admin_passthru_async(hdl, cmd);

	if (!cmd->timeout_ms && hdl->timeout)
		cmd->timeout_ms = hdl->timeout;

	switch (hdl->type) {
	case LIBNVME_TRANSPORT_HANDLE_TYPE_DIRECT:
		if (hdl->ioctl_admin64)
			return libnvme_submit_passthru64(hdl,
				LIBNVME_IOCTL_ADMIN64_CMD, cmd);
		if (cmd->opcode == nvme_admin_fabrics)
			return -ENOTSUP;
		return libnvme_submit_passthru32(hdl,
				LIBNVME_IOCTL_ADMIN_CMD, cmd);
	case LIBNVME_TRANSPORT_HANDLE_TYPE_MI:
		return libnvme_mi_admin_admin_passthru(hdl, cmd);
	default:
		break;
	}

	return -ENOTSUP;
}
