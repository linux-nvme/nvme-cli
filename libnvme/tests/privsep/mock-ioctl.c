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
 */
#include <dlfcn.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <sys/ioctl.h>

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

int ioctl(int fd, unsigned long request, ...)
{
	static int (*real_ioctl)(int, unsigned long, ...);
	va_list ap;
	void *arg;

	va_start(ap, request);
	arg = va_arg(ap, void *);
	va_end(ap);

	if (fd == MOCK_FD && (request == NVME_IOCTL_ADMIN64_CMD ||
			      request == NVME_IOCTL_IO64_CMD))
		return mock_passthru(arg);

	if (!real_ioctl)
		real_ioctl = dlsym(RTLD_NEXT, "ioctl");
	if (!real_ioctl) {
		errno = ENOTTY;
		return -1;
	}

	return real_ioctl(fd, request, arg);
}
