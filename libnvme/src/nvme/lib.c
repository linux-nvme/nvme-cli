// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 *	    Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 */

#include <fcntl.h>
#include <libgen.h>
#include <strings.h>

#ifdef CONFIG_FABRICS
#include <sys/types.h>

#include <ifaddrs.h>
#endif

#include <libnvme.h>

#include "cleanup.h"
#include "cleanup-linux.h"
#include "private.h"
#include "private-mi.h"
#include "compiler-attributes.h"

static bool libnvme_mi_probe_enabled_default(void)
{
	char *val;

	val = getenv("LIBNVME_MI_PROBE_ENABLED");
	if (!val)
		return true;

	return strcmp(val, "0") &&
		strcasecmp(val, "false") &&
		strncasecmp(val, "disable", 7);

}

__public struct libnvme_global_ctx *libnvme_create_global_ctx(FILE *fp, int log_level)
{
	struct libnvme_global_ctx *ctx;
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
	ctx->mi_probe_enabled = libnvme_mi_probe_enabled_default();

	return ctx;
}

__public void libnvme_free_global_ctx(struct libnvme_global_ctx *ctx)
{
	struct libnvme_host *h, *_h;
#ifdef CONFIG_MI
	libnvme_mi_ep_t ep, tmp;
#endif

	if (!ctx)
		return;

#ifdef CONFIG_FABRICS
	freeifaddrs(ctx->ifaddrs_cache); /* NULL-safe */
	ctx->ifaddrs_cache = NULL;
	free(ctx->options);
#endif

	libnvme_for_each_host_safe(ctx, h, _h)
		__libnvme_free_host(h);
#ifdef CONFIG_MI
	libnvme_mi_for_each_endpoint_safe(ctx, ep, tmp)
		libnvme_mi_close(ep);
#endif
	free(ctx->config_file);
	free(ctx->application);
	libnvme_close_uring(ctx);
	free(ctx);
}

__public void libnvme_set_dry_run(struct libnvme_global_ctx *ctx, bool enable)
{
	ctx->dry_run = enable;
}

__public void libnvme_set_ioctl_probing(struct libnvme_global_ctx *ctx, bool enable)
{
	ctx->ioctl_probing = enable;
}

__public void libnvme_transport_handle_set_submit_entry(struct libnvme_transport_handle *hdl,
		void *(*submit_entry)(struct libnvme_transport_handle *hdl,
				struct libnvme_passthru_cmd *cmd))
{
	hdl->submit_entry = submit_entry;
	if (!hdl->submit_exit)
		hdl->submit_exit = __libnvme_submit_exit;
}

__public void libnvme_transport_handle_set_submit_exit(struct libnvme_transport_handle *hdl,
		void (*submit_exit)(struct libnvme_transport_handle *hdl,
				struct libnvme_passthru_cmd *cmd,
				int err, void *user_data))
{
	hdl->submit_exit = submit_exit;
	if (!hdl->submit_exit)
		hdl->submit_exit = __libnvme_submit_exit;
}

__public void libnvme_transport_handle_set_decide_retry(struct libnvme_transport_handle *hdl,
		bool (*decide_retry)(struct libnvme_transport_handle *hdl,
				struct libnvme_passthru_cmd *cmd, int err))
{
	hdl->decide_retry = decide_retry;
	if (!hdl->decide_retry)
		hdl->decide_retry = __libnvme_decide_retry;
}

#ifndef _WIN32
static int __nvme_transport_handle_open_direct(
		struct libnvme_transport_handle *hdl, const char *devname)
{
	struct libnvme_passthru_cmd dummy = { 0 };
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

	if (hdl->ctx->ioctl_probing) {
		/* avoid kernel logging 'cmd does not match nsid' */
		dummy.nsid = ns;
		ret = ioctl(hdl->fd, LIBNVME_IOCTL_ADMIN64_CMD, &dummy);
		if (ret > 0) {
			hdl->ioctl_admin64 = true;
			ret = ioctl(hdl->fd, LIBNVME_IOCTL_IO64_CMD, &dummy);
			if (ret != -1 || errno != ENOTTY)
				hdl->ioctl_io64 = true;
		}
	}

	return 0;
}

void __libnvme_transport_handle_close_direct(
		struct libnvme_transport_handle *hdl)
{
	close(hdl->fd);
	free(hdl);
}
#endif /* !_WIN32 */

struct libnvme_transport_handle *__libnvme_create_transport_handle(
		struct libnvme_global_ctx *ctx)
{
	struct libnvme_transport_handle *hdl;

	hdl = calloc(1, sizeof(*hdl));
	if (!hdl)
		return NULL;

	hdl->ctx = ctx;
	hdl->submit_entry = __libnvme_submit_entry;
	hdl->submit_exit = __libnvme_submit_exit;
	hdl->decide_retry = __libnvme_decide_retry;

	return hdl;
}

#ifndef _WIN32
__public int libnvme_open(struct libnvme_global_ctx *ctx, const char *name,
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
		hdl->fd = 0xFD;

		if (!strcmp(name, "NVME_TEST_FD64"))
			hdl->ioctl_admin64 = true;

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

__public void libnvme_close(struct libnvme_transport_handle *hdl)
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
#endif /* !_WIN32 */

__public libnvme_fd_t libnvme_transport_handle_get_fd(struct libnvme_transport_handle *hdl)
{
	return hdl->fd;
}

__public const char *libnvme_transport_handle_get_name(struct libnvme_transport_handle *hdl)
{
	return basename(hdl->name);
}

__public bool libnvme_transport_handle_is_blkdev(struct libnvme_transport_handle *hdl)
{
	return S_ISBLK(hdl->stat.st_mode);
}

__public bool libnvme_transport_handle_is_chardev(struct libnvme_transport_handle *hdl)
{
	return S_ISCHR(hdl->stat.st_mode);
}

__public bool libnvme_transport_handle_is_direct(struct libnvme_transport_handle *hdl)
{
	return hdl->type == LIBNVME_TRANSPORT_HANDLE_TYPE_DIRECT;
}

__public bool libnvme_transport_handle_is_mi(struct libnvme_transport_handle *hdl)
{
	return hdl->type == LIBNVME_TRANSPORT_HANDLE_TYPE_MI;
}

