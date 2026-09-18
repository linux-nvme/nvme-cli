// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */
#include <errno.h>
#include <stddef.h>
#include <string.h>

#include <sys/ioctl.h>
#include <sys/stat.h>

#include <shared/compiler-attributes-util.h>

#include <libnvme.h>

#include "private.h"
#include "loopback.h"

/*
 * FreeBSD's nvme(4) driver implements the same "Linux compatible" NVMe
 * ioctls as the Linux kernel (NVME_IOCTL_ID, NVME_IOCTL_ADMIN_CMD,
 * NVME_IOCTL_IO_CMD, NVME_IOCTL_RESET; see sys/dev/nvme/nvme_linux.h in
 * the FreeBSD source), so this mirrors ioctl-linux.c almost verbatim.
 * Two things FreeBSD doesn't have: the 64-bit passthru ioctls (only the
 * 32-bit struct is supported, which the existing ioctl32/64 probing in
 * ioctl_admin_passthru()/ioctl_io_passthru() already falls back away
 * from via -ENOTTY), and Linux's BLKBSZSET/BLKRRPART block-device
 * ioctls.
 */

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

__shr_public int libnvme_reset_subsystem(
		struct libnvme_transport_handle *hdl)
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

__shr_public int libnvme_reset_ctrl(struct libnvme_transport_handle *hdl)
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

__shr_public int libnvme_rescan_ns(struct libnvme_transport_handle *hdl)
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

__shr_public int libnvme_get_nsid(
		struct libnvme_transport_handle *hdl, __u32 *nsid)
{
	__u32 tmp;

	errno = 0;
	tmp = ioctl(hdl->fd, LIBNVME_IOCTL_ID);
	if (errno)
		return -errno;

	*nsid = tmp;
	return 0;
}

__shr_public int libnvme_update_block_size(
		__shr_unused struct libnvme_transport_handle *hdl,
		__shr_unused int block_size)
{
	/* FreeBSD has no equivalent of Linux's BLKBSZSET/BLKRRPART. */
	return -ENOTSUP;
}

/*
 * The 64 bit version is the preferred version to use, but for backwards
 * compatibility keep a 32 version.
 */
static int ioctl_passthru32(struct libnvme_transport_handle *hdl,
		unsigned long ioctl_cmd, struct libnvme_passthru_cmd *cmd)
{
	struct linux_passthru_cmd32 cmd32 = {};
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
 * Not supported by FreeBSD's nvme(4) Linux-compatible ioctls today, but
 * kept symmetric with ioctl-linux.c: the 64-bit ioctl numbers below are
 * simply never claimed by the driver, so this returns -ENOTTY and the
 * generic probing logic in ioctl_admin_passthru()/ioctl_io_passthru()
 * permanently falls back to the 32-bit path on first use.
 */
static int ioctl_passthru64(struct libnvme_transport_handle *hdl,
		unsigned long ioctl_cmd, struct libnvme_passthru_cmd *cmd)
{
	void *user_data;
	int err = 0;

	user_data = hdl->submit_entry(hdl, cmd);
	if (hdl->ctx->dry_run)
		goto out;

	do {
		err = ioctl(hdl->fd, ioctl_cmd, cmd);
		if (err >= 0)
			break;
		err = -errno;
	} while (hdl->decide_retry(hdl, cmd, err));

out:
	hdl->submit_exit(hdl, cmd, err, user_data);
	return err;
}

static int ioctl_io_passthru(struct libnvme_transport_handle *hdl,
		struct libnvme_passthru_cmd *cmd)
{
	int err;

	if (hdl->ioctl_io_state == IOCTL_STATE_IOCTL64)
		return ioctl_passthru64(hdl,
			LIBNVME_IOCTL_IO64_CMD, cmd);

	if (hdl->ioctl_io_state == IOCTL_STATE_IOCTL32 ||
			!hdl->ctx->ioctl_probing)
		goto do_ioctl32;

	err = ioctl_passthru64(hdl, LIBNVME_IOCTL_IO64_CMD, cmd);
	if (err >= 0 || err != -ENOTTY) {
		hdl->ioctl_io_state = IOCTL_STATE_IOCTL64;
		return err;
	}

	hdl->ioctl_io_state = IOCTL_STATE_IOCTL32;

do_ioctl32:
	return ioctl_passthru32(hdl, LIBNVME_IOCTL_IO_CMD, cmd);
}

static int ioctl_admin_passthru(struct libnvme_transport_handle *hdl,
		struct libnvme_passthru_cmd *cmd)
{
	int err;

	if (hdl->ioctl_admin_state == IOCTL_STATE_IOCTL64)
		return ioctl_passthru64(hdl,
				LIBNVME_IOCTL_ADMIN64_CMD, cmd);

	if (hdl->ioctl_admin_state == IOCTL_STATE_IOCTL32 ||
			!hdl->ctx->ioctl_probing)
		goto do_ioctl32;

	err = ioctl_passthru64(hdl, LIBNVME_IOCTL_ADMIN64_CMD, cmd);
	if (err >= 0 || err != -ENOTTY) {
		hdl->ioctl_admin_state = IOCTL_STATE_IOCTL64;
		return err;
	}

	hdl->ioctl_admin_state = IOCTL_STATE_IOCTL32;

do_ioctl32:
	if (cmd->opcode == nvme_admin_fabrics)
		return -ENOTSUP;

	return ioctl_passthru32(hdl, LIBNVME_IOCTL_ADMIN_CMD, cmd);
}

__shr_public int libnvme_exec_admin_passthru(
		struct libnvme_transport_handle *hdl,
		struct libnvme_passthru_cmd *cmd)
{
	if (!hdl)
		return -ENODEV;

	if (!cmd->timeout_ms && hdl->timeout)
		cmd->timeout_ms = hdl->timeout;

	switch (hdl->type) {
	case LIBNVME_TRANSPORT_HANDLE_TYPE_DIRECT:
		return ioctl_admin_passthru(hdl, cmd);
	case LIBNVME_TRANSPORT_HANDLE_TYPE_MI:
		return libnvme_mi_admin_admin_passthru(hdl, cmd);
	case LIBNVME_TRANSPORT_HANDLE_TYPE_LOOPBACK:
		return __libnvme_loopback_admin_passthru(hdl, cmd);
	default:
		break;
	}

	return -ENOTSUP;
}

__shr_public int libnvme_exec_io_passthru(
		struct libnvme_transport_handle *hdl,
		struct libnvme_passthru_cmd *cmd)
{
	if (!hdl)
		return -ENODEV;

	if (!cmd->timeout_ms && hdl->timeout)
		cmd->timeout_ms = hdl->timeout;

	switch (hdl->type) {
	case LIBNVME_TRANSPORT_HANDLE_TYPE_DIRECT:
		return ioctl_io_passthru(hdl, cmd);
	case LIBNVME_TRANSPORT_HANDLE_TYPE_LOOPBACK:
		return __libnvme_loopback_io_passthru(hdl, cmd);
	default:
		break;
	}

	return -ENOTSUP;
}
