// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 *	    Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 */

#include <fcntl.h>
#include <sys/ioctl.h>

#include <libnvme.h>

#include "cleanup.h"
#include "cleanup-linux.h"
#include "compiler-attributes.h"
#include "private.h"
#include "private-mi.h"

static int __nvme_transport_handle_open_direct(
		struct libnvme_transport_handle *hdl, const char *devname)
{
	__cleanup_free char *path = NULL;
	char *name;
	int ret, id, ns;
	bool c = true;

	name = libnvme_basename(devname);

	hdl->type = LIBNVME_TRANSPORT_HANDLE_TYPE_DIRECT;

	ret = sscanf(name, "nvme%dn%d", &id, &ns);
	if (ret == 2)
		c = false;
	else if (ret != 1 && sscanf(name, "ng%dn%d", &id, &ns) != 2)
		return -EINVAL;

	ret = asprintf(&path, "%s/%s", "/dev", name);
	if (ret < 0)
		return -ENOMEM;

	hdl->fd = open(path, O_RDONLY);
	if (hdl->fd < 0)
		return -errno;

	ret = fstat(hdl->fd, &hdl->stat);
	if (ret < 0)
		return -errno;

	if (c) {
		if (!S_ISCHR(hdl->stat.st_mode))
			return -EINVAL;
		ret = __libnvme_transport_handle_open_uring(hdl);
		if (ret && ret != -ENOTSUP) {
			close(hdl->fd);
			return ret;
		}
	} else if (!S_ISBLK(hdl->stat.st_mode)) {
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

__libnvme_public int libnvme_open(
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

	if (!strncmp(name, "mctp:", strlen("mctp:")))
		ret = __libnvme_transport_handle_open_mi(hdl, name);
	else
		ret = __nvme_transport_handle_open_direct(hdl, name);

	if (ret) {
		libnvme_close(hdl);
		return ret;
	}

	*hdlp = hdl;

	return 0;
}

__libnvme_public void libnvme_close(struct libnvme_transport_handle *hdl)
{
	if (!hdl)
		return;

	free(hdl->name);

	switch (hdl->type) {
	case LIBNVME_TRANSPORT_HANDLE_TYPE_DIRECT:
		__libnvme_transport_handle_close_direct(hdl);
		break;
	case LIBNVME_TRANSPORT_HANDLE_TYPE_MI:
		__libnvme_transport_handle_close_mi(hdl);
		break;
	case LIBNVME_TRANSPORT_HANDLE_TYPE_UNKNOWN:
		free(hdl);
		break;
	}
}
