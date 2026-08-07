// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <libnvme.h>

#include <compiler-attributes.h>

#include "private.h"

/*
 * FreeBSD: opening a device node is plain POSIX and portable, so this
 * mirrors lib-linux.c's approach without assuming Linux's "nvme%dn%d"
 * naming scheme. Actual command submission is stubbed out in
 * ioctl-freebsd.c.
 */

static int __libnvme_transport_handle_open_direct(
		struct libnvme_transport_handle *hdl, const char *devname)
{
	int ret;

	hdl->type = LIBNVME_TRANSPORT_HANDLE_TYPE_DIRECT;

	hdl->fd = open(devname, O_RDONLY);
	if (hdl->fd < 0)
		return -errno;

	ret = fstat(hdl->fd, &hdl->stat);
	if (ret < 0) {
		close(hdl->fd);
		return -errno;
	}

	if (!S_ISCHR(hdl->stat.st_mode) && !S_ISBLK(hdl->stat.st_mode)) {
		close(hdl->fd);
		return -EINVAL;
	}

	return 0;
}

void __libnvme_transport_handle_close_direct(
		struct libnvme_transport_handle *hdl)
{
	libnvme_close_uring(hdl);
	close(hdl->fd);
	free(hdl);
}

__shr_public int libnvme_open(
		struct libnvme_global_ctx *ctx, const char *name,
		struct libnvme_transport_handle **hdlp)
{
	struct libnvme_transport_handle *hdl;
	int ret;

	hdl = __libnvme_create_transport_handle(ctx);
	if (!hdl)
		return -ENOMEM;

	hdl->name = strdup(name);
	if (!hdl->name) {
		free(hdl);
		return -ENOMEM;
	}

	if (!strncmp(name, "NVME_TEST_FD", 12)) {
		hdl->type = LIBNVME_TRANSPORT_HANDLE_TYPE_DIRECT;
		hdl->fd = LIBNVME_TEST_FD;

		if (!strcmp(name, "NVME_TEST_FD64"))
			hdl->ioctl_admin_state = IOCTL_STATE_IOCTL64;

		*hdlp = hdl;
		return 0;
	}

	if (!strncmp(name, "mctp:", strlen("mctp:"))) {
		libnvme_close(hdl);
		return -ENOTSUP;
	}

	ret = __libnvme_transport_handle_open_direct(hdl, name);
	if (ret) {
		libnvme_close(hdl);
		return ret;
	}

	*hdlp = hdl;

	return 0;
}

__shr_public void libnvme_close(struct libnvme_transport_handle *hdl)
{
	if (!hdl)
		return;

	free(hdl->name);

	switch (hdl->type) {
	case LIBNVME_TRANSPORT_HANDLE_TYPE_DIRECT:
		__libnvme_transport_handle_close_direct(hdl);
		break;
	case LIBNVME_TRANSPORT_HANDLE_TYPE_MI:
	case LIBNVME_TRANSPORT_HANDLE_TYPE_UNKNOWN:
		free(hdl);
		break;
	}
}
