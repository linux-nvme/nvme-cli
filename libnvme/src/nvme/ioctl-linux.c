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
#include <sys/mman.h>
#include <sys/stat.h>

#include <ccan/build_assert/build_assert.h>
#include <ccan/endian/endian.h>
#include <ccan/minmax/minmax.h>

#include <shared/compiler-attributes-util.h>
#include <shared/fs-util.h>
#include <shared/mmio-util.h>

#include <libnvme.h>

#include "cleanup.h"
#include "private.h"
#include "loopback.h"

static int nvme_verify_chr(struct libnvme_transport_handle *hdl)
{
	struct stat nvme_stat;
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
		struct libnvme_transport_handle *hdl, int block_size)
{
	int ret;
	libnvme_fd_t fd = libnvme_transport_handle_get_fd(hdl);

	ret = ioctl(fd, BLKBSZSET, &block_size);
	if (ret < 0)
		return -errno;

	ret = ioctl(fd, BLKRRPART);
	if (ret < 0)
		return -errno;

	return 0;
}

__shr_public int libnvme_reread_partitions(struct libnvme_transport_handle *hdl)
{
	if (!libnvme_transport_handle_is_ns(hdl))
		return -EINVAL;

	if (ioctl(hdl->fd, BLKRRPART) < 0)
		return -errno;

	return 0;
}

#define NVME_REG_MAP_SIZE 0x1000

static int nvme_map_regs(struct libnvme_transport_handle *hdl, bool writable,
		void **regs)
{
	const char *name = libnvme_transport_handle_get_name(hdl);
	__cleanup_free char *path = NULL;
	__cleanup_fd int fd = -1;
	int prot = PROT_READ;
	void *base;

	if (hdl->type != LIBNVME_TRANSPORT_HANDLE_TYPE_DIRECT)
		return -ENOTSUP;
	if (libnvme_transport_handle_is_ns(hdl))
		return -EINVAL;

	if (asprintf(&path, "%s/%s/device/resource0",
		     libnvme_ctrl_sysfs_dir(hdl->ctx), name) < 0)
		return -ENOMEM;

	if (writable)
		prot |= PROT_WRITE;

	fd = open(path, (writable ? O_RDWR : O_RDONLY) | O_CLOEXEC);
	if (fd < 0) {
		libnvme_msg(hdl->ctx, LIBNVME_LOG_INFO,
			"%s did not find a pci resource, open failed %s\n",
			name, libnvme_strerror(errno));
		return -errno;
	}

	base = mmap(NULL, shr_getpagesize(), prot, MAP_SHARED, fd, 0);
	if (base == MAP_FAILED) {
		libnvme_msg(hdl->ctx, LIBNVME_LOG_INFO,
			"Failed to map registers to userspace.\n\n"
			"Did your kernel enable CONFIG_IO_STRICT_DEVMEM?\n"
			"You can disable this feature with command line argument\n\n"
			"\tio_memory=relaxed\n\n"
			"Also ensure secure boot is disabled.\n");
		return -errno;
	}

	*regs = base;
	return 0;
}

static bool nvme_reg_range_valid(__u32 offset, __u32 len)
{
	if (offset % sizeof(__u32) || len % sizeof(__u32))
		return false;

	return offset <= NVME_REG_MAP_SIZE &&
		len <= NVME_REG_MAP_SIZE - offset;
}

__shr_public int libnvme_read_regs(struct libnvme_transport_handle *hdl,
		__u32 offset, void *buf, __u32 len)
{
	__u32 *dst = buf;
	void *regs;
	__u32 i;
	int ret;

	if (!nvme_reg_range_valid(offset, len))
		return -EINVAL;

	ret = nvme_map_regs(hdl, false, &regs);
	if (ret)
		return ret;

	for (i = 0; i < len / sizeof(__u32); i++)
		dst[i] = cpu_to_le32(shr_mmio_read32(regs + offset +
						     i * sizeof(__u32)));

	munmap(regs, shr_getpagesize());

	return 0;
}

__shr_public int libnvme_write_reg32(struct libnvme_transport_handle *hdl,
		__u32 offset, __u32 value)
{
	void *regs;
	int ret;

	if (!nvme_reg_range_valid(offset, sizeof(value)))
		return -EINVAL;

	ret = nvme_map_regs(hdl, true, &regs);
	if (ret)
		return ret;

	shr_mmio_write32(regs + offset, value);
	munmap(regs, shr_getpagesize());

	return 0;
}

__shr_public int libnvme_write_reg64(struct libnvme_transport_handle *hdl,
		__u32 offset, __u64 value, bool mmio32)
{
	void *regs;
	int ret;

	if (offset % sizeof(value) ||
	    !nvme_reg_range_valid(offset, sizeof(value)))
		return -EINVAL;

	ret = nvme_map_regs(hdl, true, &regs);
	if (ret)
		return ret;

	shr_mmio_write64(regs + offset, value, mmio32);
	munmap(regs, shr_getpagesize());

	return 0;
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

	memcpy(&cmd32, cmd, offsetof(struct linux_passthru_cmd32, result));
	cmd32.result = 0;

	do {
		err = ioctl(hdl->fd, ioctl_cmd, &cmd32);
		if (err >= 0)
			break;
		err = -errno;
	} while (hdl->decide_retry(hdl, cmd, err));

	cmd->result = cmd32.result;
	hdl->submit_exit(hdl, cmd, err, user_data);
	return err;
}

/*
 * supported since kernel 5.4, see
 * 65e68edce0db ("nvme: allow 64-bit results in passthru commands")
 */
static int ioctl_passthru64(struct libnvme_transport_handle *hdl,
		unsigned long ioctl_cmd, struct libnvme_passthru_cmd *cmd)
{
	void *user_data;
	int err = 0;

	user_data = hdl->submit_entry(hdl, cmd);

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
	struct libnvme_passthru_completion completion;
	int err;

	if (!hdl)
		return -ENODEV;

	if (!cmd->timeout_ms && hdl->timeout)
		cmd->timeout_ms = hdl->timeout;

	if (hdl->ctx->dry_run)
		return __libnvme_exec_dry_run(hdl, cmd);

	if (hdl->type != LIBNVME_TRANSPORT_HANDLE_TYPE_DIRECT)
		goto no_uring;

	if (hdl->uring_state == LIBNVME_IO_URING_STATE_NOT_AVAILABLE)
		goto no_uring;

	err = libnvme_submit_admin_passthru(hdl, cmd, NULL);
	if (err) {
		if (err == -ENOTSUP)
			goto no_uring;

		return err;
	}

	err = libnvme_reap_passthru(hdl, &completion);
	if (err)
		return err;

	return completion.status;

no_uring:
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
	struct libnvme_passthru_completion completion;
	int err;

	if (!hdl)
		return -ENODEV;

	if (!cmd->timeout_ms && hdl->timeout)
		cmd->timeout_ms = hdl->timeout;

	if (hdl->ctx->dry_run)
		return __libnvme_exec_dry_run(hdl, cmd);

	if (hdl->type != LIBNVME_TRANSPORT_HANDLE_TYPE_DIRECT)
		goto no_uring;

	if (hdl->uring_state == LIBNVME_IO_URING_STATE_NOT_AVAILABLE)
		goto no_uring;

	err = libnvme_submit_io_passthru(hdl, cmd, NULL);
	if (err) {
		if (err == -ENOTSUP)
			goto no_uring;

		return err;
	}

	err = libnvme_reap_passthru(hdl, &completion);
	if (err)
		return err;

	return completion.status;

no_uring:
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
