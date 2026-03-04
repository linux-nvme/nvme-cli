// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 *	    Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 */

#include <libnvme.h>

#include "cleanup.h"
#include "private.h"

#include <libgen.h>
#include <fcntl.h>
#include <sys/ioctl.h>

struct nvme_global_ctx *nvme_create_global_ctx(FILE *fp, int log_level)
{
	struct nvme_global_ctx *ctx;
	int fd;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return NULL;

	if (fp) {
		fd = fileno(fp);
		if (fd < 0) {
			free(ctx);
			return NULL;
		}
	} else
		fd = STDERR_FILENO;

	ctx->log.fd = fd;
	ctx->log.level = log_level;

	list_head_init(&ctx->hosts);
	list_head_init(&ctx->endpoints);

	ctx->ioctl_probing = true;

	return ctx;
}

void nvme_free_global_ctx(struct nvme_global_ctx *ctx)
{
	struct nvme_host *h, *_h;

	if (!ctx)
		return;

	freeifaddrs(ctx->ifaddrs_cache); /* NULL-safe */
	ctx->ifaddrs_cache = NULL;

	free(ctx->options);
	nvme_for_each_host_safe(ctx, h, _h)
		__nvme_free_host(h);
	free(ctx->config_file);
	free(ctx->application);
	free(ctx);
}

void nvme_set_dry_run(struct nvme_global_ctx *ctx, bool enable)
{
	ctx->dry_run = enable;
}

void nvme_set_ioctl_probing(struct nvme_global_ctx *ctx, bool enable)
{
	ctx->ioctl_probing = enable;
}

void nvme_transport_handle_set_submit_entry(struct nvme_transport_handle *hdl,
		void *(*submit_entry)(struct nvme_transport_handle *hdl,
				struct nvme_passthru_cmd *cmd))
{
	hdl->submit_entry = submit_entry;
	if (!hdl->submit_exit)
		hdl->submit_exit = __nvme_submit_exit;
}

void nvme_transport_handle_set_submit_exit(struct nvme_transport_handle *hdl,
		void (*submit_exit)(struct nvme_transport_handle *hdl,
				struct nvme_passthru_cmd *cmd,
				int err, void *user_data))
{
	hdl->submit_exit = submit_exit;
	if (!hdl->submit_exit)
		hdl->submit_exit = __nvme_submit_exit;
}

void nvme_transport_handle_set_decide_retry(struct nvme_transport_handle *hdl,
		bool (*decide_retry)(struct nvme_transport_handle *hdl,
				struct nvme_passthru_cmd *cmd, int err))
{
	hdl->decide_retry = decide_retry;
	if (!hdl->decide_retry)
		hdl->decide_retry = __nvme_decide_retry;
}

static int __nvme_transport_handle_open_direct(
		struct nvme_transport_handle *hdl, const char *devname)
{
	struct nvme_passthru_cmd dummy = { 0 };
	_cleanup_free_ char *path = NULL;
	_cleanup_free_ char *_devname = NULL;
	char *name;
	int ret, id, ns;
	bool c = true;

	_devname = strdup(devname);
	if (!_devname)
		return -ENOMEM;
	name = basename(_devname);

	hdl->type = NVME_TRANSPORT_HANDLE_TYPE_DIRECT;

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
	} else if (!S_ISBLK(hdl->stat.st_mode)) {
		return -EINVAL;
	}

	if (hdl->ctx->ioctl_probing) {
		ret = ioctl(hdl->fd, NVME_IOCTL_ADMIN64_CMD, &dummy);
		if (ret > 0)
			hdl->ioctl64 = true;
	}

	return 0;
}

void __nvme_transport_handle_close_direct(struct nvme_transport_handle *hdl)
{
	close(hdl->fd);
	free(hdl);
}

struct nvme_transport_handle *__nvme_create_transport_handle(
		struct nvme_global_ctx *ctx)
{
	struct nvme_transport_handle *hdl;

	hdl = calloc(1, sizeof(*hdl));
	if (!hdl)
		return NULL;

	hdl->ctx = ctx;
	hdl->submit_entry = __nvme_submit_entry;
	hdl->submit_exit = __nvme_submit_exit;
	hdl->decide_retry = __nvme_decide_retry;

	return hdl;
}

int nvme_open(struct nvme_global_ctx *ctx, const char *name,
	      struct nvme_transport_handle **hdlp)
{
	struct nvme_transport_handle *hdl;
	int ret;

	hdl = __nvme_create_transport_handle(ctx);
	if (!hdl)
		return -ENOMEM;

	hdl->name = strdup(name);
	if (!hdl->name) {
		free(hdl);
		return -ENOMEM;
	}

	if (!strncmp(name, "NVME_TEST_FD", 12)) {
		hdl->type = NVME_TRANSPORT_HANDLE_TYPE_DIRECT;
		hdl->fd = 0xFD;

		if (!strcmp(name, "NVME_TEST_FD64"))
			hdl->ioctl64 = true;

		*hdlp = hdl;
		return 0;
	}

	if (!strncmp(name, "mctp:", strlen("mctp:")))
		ret = __nvme_transport_handle_open_mi(hdl, name);
	else
		ret = __nvme_transport_handle_open_direct(hdl, name);

	if (ret) {
		nvme_close(hdl);
		return ret;
	}

	*hdlp = hdl;

	return 0;
}

void nvme_close(struct nvme_transport_handle *hdl)
{
	if (!hdl)
		return;

	free(hdl->name);

	switch (hdl->type) {
	case NVME_TRANSPORT_HANDLE_TYPE_DIRECT:
		__nvme_transport_handle_close_direct(hdl);
		break;
	case NVME_TRANSPORT_HANDLE_TYPE_MI:
		__nvme_transport_handle_close_mi(hdl);
		break;
	case NVME_TRANSPORT_HANDLE_TYPE_UNKNOWN:
		free(hdl);
		break;
	}
}

int nvme_transport_handle_get_fd(struct nvme_transport_handle *hdl)
{
	return hdl->fd;
}

const char *nvme_transport_handle_get_name(struct nvme_transport_handle *hdl)
{
	return basename(hdl->name);
}

bool nvme_transport_handle_is_blkdev(struct nvme_transport_handle *hdl)
{
	return S_ISBLK(hdl->stat.st_mode);
}

bool nvme_transport_handle_is_chardev(struct nvme_transport_handle *hdl)
{
	return S_ISCHR(hdl->stat.st_mode);
}

bool nvme_transport_handle_is_direct(struct nvme_transport_handle *hdl)
{
	return hdl->type == NVME_TRANSPORT_HANDLE_TYPE_DIRECT;
}

bool nvme_transport_handle_is_mi(struct nvme_transport_handle *hdl)
{
	return hdl->type == NVME_TRANSPORT_HANDLE_TYPE_MI;
}

