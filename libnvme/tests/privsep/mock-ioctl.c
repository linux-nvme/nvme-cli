// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 *
 * Preloaded into nvme-privsep-helper. Emulates the NVMe passthru ioctls
 * on the NVME_TEST_FD file descriptor:
 *
 * - host to controller commands return the byte sum of the data and
 *   metadata buffers as result
 * - other commands fill the data buffer with (index + cdw10) and the
 *   metadata buffer with 0xa5, and return nsid + 0x1000 as result
 * - opcode MOCK_OPC_ERROR additionally returns MOCK_STATUS
 * - opcode MOCK_OPC_EXIT terminates the helper
 * - buffers which are not page aligned fail with EINVAL, as the nvmet file
 *   backend does with direct I/O
 *
 * It also emulates the controller /dev/nvme0 and the namespace /dev/nvme0n1
 * on top of /dev/null:
 *
 * - reset and rescan succeed, subsystem reset fails with EBUSY
 * - the namespace has the nsid MOCK_NSID
 * - BLKRRPART succeeds, BLKBSZSET accepts only MOCK_BLOCK_SIZE
 */
/*
 * This file defines both open() and open64(), and both fstat() and
 * fstat64(). Undefine the LFS and time64 macros, as libmock_nvme.c does,
 * so that glibc does not rename the definitions.
 */
#undef _FILE_OFFSET_BITS
#undef _TIME_BITS
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/stat.h>

#include <linux/fs.h>
#include <linux/nvme_ioctl.h>

#include "mock.h"

static int mock_passthru(struct nvme_passthru_cmd64 *cmd)
{
	unsigned char *data = (unsigned char *)(uintptr_t)cmd->addr;
	unsigned char *md = (unsigned char *)(uintptr_t)cmd->metadata;
	__u64 sum = 0;
	__u32 i;

	if ((cmd->data_len && (uintptr_t)data % 4096) ||
	    (cmd->metadata_len && (uintptr_t)md % 4096)) {
		errno = EINVAL;
		return -1;
	}

	if (cmd->opcode == MOCK_OPC_EXIT)
		_exit(0);

	if (cmd->opcode & 1) {
		for (i = 0; i < cmd->data_len; i++)
			sum += data[i];
		for (i = 0; i < cmd->metadata_len; i++)
			sum += md[i];
		cmd->result = sum;
		return 0;
	}

	for (i = 0; i < cmd->data_len; i++)
		data[i] = (i + cmd->cdw10) & 0xff;
	if (cmd->metadata_len)
		memset(md, 0xa5, cmd->metadata_len);
	cmd->result = cmd->nsid + 0x1000;

	return cmd->opcode == MOCK_OPC_ERROR ? MOCK_STATUS : 0;
}

typedef int (*open_fn)(const char *path, int flags, ...);
typedef int (*close_fn)(int fd);
typedef int (*fstat_fn)(int fd, void *buf);
typedef int (*ioctl_fn)(int fd, unsigned long request, ...);

/* The descriptors of the emulated devices, -1 if not open. */
static int ctrl_fd = -1, ns_fd = -1;

static int mock_ret(int err)
{
	if (!err)
		return 0;
	errno = err;
	return -1;
}

static int mock_ctrl_ioctl(unsigned long request)
{
	switch (request) {
	case NVME_IOCTL_RESET:
	case NVME_IOCTL_RESCAN:
		return 0;
	case NVME_IOCTL_SUBSYS_RESET:
		return mock_ret(EBUSY);
	}

	return mock_ret(ENOTTY);
}

static int mock_ns_ioctl(unsigned long request, void *arg)
{
	switch (request) {
	case NVME_IOCTL_ID:
		return MOCK_NSID;
	case BLKRRPART:
		return 0;
	case BLKBSZSET:
		return mock_ret(*(int *)arg == MOCK_BLOCK_SIZE ? 0 : EINVAL);
	}

	return mock_ret(ENOTTY);
}

static int mock_open(const char *path, int flags, mode_t mode,
		const char *sym)
{
	open_fn real_open = dlsym(RTLD_NEXT, sym);
	bool ctrl = !strcmp(path, "/dev/nvme0");
	bool ns = !strcmp(path, "/dev/nvme0n1");
	int fd;

	if (!real_open) {
		errno = EIO;
		return -1;
	}
	if (ctrl || ns)
		path = "/dev/null";

	fd = real_open(path, flags, mode);
	if (fd >= 0 && ctrl)
		ctrl_fd = fd;
	else if (fd >= 0 && ns)
		ns_fd = fd;

	return fd;
}

int open(const char *path, int flags, ...)
{
	mode_t mode = 0;
	va_list ap;

	if (flags & (O_CREAT | O_TMPFILE)) {
		va_start(ap, flags);
		mode = va_arg(ap, mode_t);
		va_end(ap);
	}

	return mock_open(path, flags, mode, "open");
}

int open64(const char *path, int flags, ...)
{
	mode_t mode = 0;
	va_list ap;

	if (flags & (O_CREAT | O_TMPFILE)) {
		va_start(ap, flags);
		mode = va_arg(ap, mode_t);
		va_end(ap);
	}

	return mock_open(path, flags, mode, "open64");
}

int close(int fd)
{
	static close_fn real_close;

	if (fd == ctrl_fd)
		ctrl_fd = -1;
	else if (fd == ns_fd)
		ns_fd = -1;

	if (!real_close)
		real_close = dlsym(RTLD_NEXT, "close");
	if (!real_close) {
		errno = EIO;
		return -1;
	}

	return real_close(fd);
}

/* Patches only st_mode, which works for every struct stat variant. */
static int mock_fstat(int fd, void *buf, const char *sym)
{
	fstat_fn real_fstat = dlsym(RTLD_NEXT, sym);
	int ret;

	if (!real_fstat) {
		errno = EIO;
		return -1;
	}

	ret = real_fstat(fd, buf);
	if (!ret && fd == ctrl_fd)
		((struct stat *)buf)->st_mode = S_IFCHR | 0600;
	else if (!ret && fd == ns_fd)
		((struct stat *)buf)->st_mode = S_IFBLK | 0600;

	return ret;
}

int fstat(int fd, struct stat *buf)
{
	return mock_fstat(fd, buf, "fstat");
}

int fstat64(int fd, struct stat64 *buf)
{
	return mock_fstat(fd, buf, "fstat64");
}

int __fstat64_time64(int fd, void *buf);
int __fstat64_time64(int fd, void *buf)
{
	return mock_fstat(fd, buf, "__fstat64_time64");
}

static int mock_ioctl(int fd, unsigned long request, void *arg,
		const char *sym)
{
	ioctl_fn real_ioctl;

	if (fd == MOCK_FD && (request == NVME_IOCTL_ADMIN64_CMD ||
			      request == NVME_IOCTL_IO64_CMD))
		return mock_passthru(arg);
	if (fd >= 0 && fd == ctrl_fd)
		return mock_ctrl_ioctl(request);
	if (fd >= 0 && fd == ns_fd)
		return mock_ns_ioctl(request, arg);

	real_ioctl = dlsym(RTLD_NEXT, sym);
	if (!real_ioctl) {
		errno = ENOTTY;
		return -1;
	}

	return real_ioctl(fd, request, arg);
}

int ioctl(int fd, unsigned long request, ...)
{
	va_list ap;
	void *arg;

	va_start(ap, request);
	arg = va_arg(ap, void *);
	va_end(ap);

	return mock_ioctl(fd, request, arg, "ioctl");
}

/* 32-bit architectures with a 64-bit time_t call this one. */
int __ioctl_time64(int fd, unsigned long request, ...);
int __ioctl_time64(int fd, unsigned long request, ...)
{
	va_list ap;
	void *arg;

	va_start(ap, request);
	arg = va_arg(ap, void *);
	va_end(ap);

	return mock_ioctl(fd, request, arg, "__ioctl_time64");
}
