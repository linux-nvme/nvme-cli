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

#include <shared/compiler-attributes-util.h>
#include <shared/fs-util.h>

#include "cleanup.h"
#include "private.h"

/*
 * FreeBSD's nvme(4) driver exposes both the controller (/dev/nvmeX) and
 * its namespaces (/dev/nvmeXnY) as character devices -- there is no
 * separate block device node the way Linux has /dev/nvmeXnY as a block
 * device, so only S_ISCHR is checked here.
 */

static int __libnvme_transport_handle_open_direct(
		struct libnvme_transport_handle *hdl, const char *devname,
		int flags)
{
	__cleanup_free char *path = NULL;
	char *name;
	int ret;

	hdl->type = LIBNVME_TRANSPORT_HANDLE_TYPE_DIRECT;

	name = shr_basename(devname);

	ret = asprintf(&path, "%s/%s", "/dev", name);
	if (ret < 0)
		return -ENOMEM;

	hdl->fd = open(path, flags);
	if (hdl->fd < 0)
		return -errno;

	ret = fstat(hdl->fd, &hdl->stat);
	if (ret < 0) {
		close(hdl->fd);
		return -errno;
	}

	if (!S_ISCHR(hdl->stat.st_mode)) {
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
		struct libnvme_global_ctx *ctx, const char *name, int flags,
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

	ret = __libnvme_transport_handle_open_direct(hdl, name, flags);
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
	case LIBNVME_TRANSPORT_HANDLE_TYPE_LOOPBACK:
	case LIBNVME_TRANSPORT_HANDLE_TYPE_UNKNOWN:
		free(hdl);
		break;
	}
}
