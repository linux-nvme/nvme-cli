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

/*
 * A test base directory is accepted only when it is confined to /tmp and free
 * of ".." components, so it can never redirect libnvme onto a production or
 * system path (/etc, /usr, ...).  Shared by ctx creation and the setter.
 */
static bool is_valid_test_base_dir(const char *path)
{
	return path && !strncmp(path, "/tmp/", 5) && !strstr(path, "..");
}

__libnvme_public struct libnvme_global_ctx *libnvme_create_global_ctx(void)
{
	struct libnvme_global_ctx *ctx;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return NULL;

	ctx->log.fd = STDERR_FILENO;
	ctx->log.level = LIBNVME_DEFAULT_LOGLEVEL;

	list_head_init(&ctx->hosts);
	list_head_init(&ctx->endpoints);

	ctx->ioctl_probing = true;
	ctx->mi_probe_enabled = true;

	return ctx;
}

__libnvme_public int libnvme_set_owner(struct libnvme_global_ctx *ctx,
				       const char *owner)
{
	char *dup;

	if (!ctx || !owner)
		return -EINVAL;
	dup = strdup(owner);
	if (!dup)
		return -ENOMEM;
	free(ctx->owner);
	ctx->owner = dup;
	return 0;
}

__libnvme_public int libnvme_set_test_base_dir(struct libnvme_global_ctx *ctx,
					       const char *path)
{
	char *dup = NULL;

	if (!ctx)
		return -EINVAL;
	if (path) {
		if (!is_valid_test_base_dir(path))
			return -EINVAL;
		dup = strdup(path);
		if (!dup)
			return -ENOMEM;
	}
	free(ctx->test_base_dir);
	ctx->test_base_dir = dup;
	return 0;
}

__libnvme_public int libnvme_set_test_sysfs_dir(struct libnvme_global_ctx *ctx,
					       const char *path)
{
	char *dup = NULL;

	if (!ctx)
		return -EINVAL;
	if (path) {
		dup = strdup(path);
		if (!dup)
			return -ENOMEM;
	}
	free(ctx->test_sysfs_dir);
	ctx->test_sysfs_dir = dup;
	return 0;
}

__libnvme_public void libnvme_set_force_4k(struct libnvme_global_ctx *ctx,
					   bool enable)
{
	if (!ctx)
		return;

	ctx->force_4k = enable;
}

__libnvme_public void libnvme_set_probe_enabled(struct libnvme_global_ctx *ctx,
						bool enabled)
{
	if (!ctx)
		return;

	ctx->mi_probe_enabled = enabled;
}

__libnvme_public void libnvme_free_global_ctx(struct libnvme_global_ctx *ctx)
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
	free(ctx->hostnqn);
	free(ctx->hostid);

	libnvme_for_each_host_safe(ctx, h, _h)
		__libnvme_free_host(h);
#ifdef CONFIG_MI
	libnvme_mi_for_each_endpoint_safe(ctx, ep, tmp)
		libnvme_mi_close(ep);
#endif
	free(ctx->config_file);
	free(ctx->owner);
	free(ctx->test_base_dir);
	free(ctx->test_sysfs_dir);
	free(ctx);
}

__libnvme_public void libnvme_set_dry_run(
		struct libnvme_global_ctx *ctx, bool enable)
{
	ctx->dry_run = enable;
}

__libnvme_public void libnvme_set_ioctl_probing(
		struct libnvme_global_ctx *ctx, bool enable)
{
	ctx->ioctl_probing = enable;
}

__libnvme_public void libnvme_transport_handle_set_submit_entry(
		struct libnvme_transport_handle *hdl,
		void *(*submit_entry)(struct libnvme_transport_handle *hdl,
				struct libnvme_passthru_cmd *cmd))
{
	hdl->submit_entry = submit_entry;
	if (!hdl->submit_exit)
		hdl->submit_exit = __libnvme_submit_exit;
}

__libnvme_public void libnvme_transport_handle_set_submit_exit(
		struct libnvme_transport_handle *hdl,
		void (*submit_exit)(struct libnvme_transport_handle *hdl,
				struct libnvme_passthru_cmd *cmd,
				int err, void *user_data))
{
	hdl->submit_exit = submit_exit;
	if (!hdl->submit_exit)
		hdl->submit_exit = __libnvme_submit_exit;
}

__libnvme_public void libnvme_transport_handle_set_decide_retry(
		struct libnvme_transport_handle *hdl,
		bool (*decide_retry)(struct libnvme_transport_handle *hdl,
				struct libnvme_passthru_cmd *cmd, int err))
{
	hdl->decide_retry = decide_retry;
	if (!hdl->decide_retry)
		hdl->decide_retry = __libnvme_decide_retry;
}

__libnvme_public void libnvme_transport_handle_set_timeout(
		struct libnvme_transport_handle *hdl, __u32 timeout_ms)
{
	hdl->timeout = timeout_ms;
}

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

__libnvme_public libnvme_fd_t libnvme_transport_handle_get_fd(
		struct libnvme_transport_handle *hdl)
{
	return hdl->fd;
}

__libnvme_public const char *libnvme_transport_handle_get_name(
		struct libnvme_transport_handle *hdl)
{
	return basename(hdl->name);
}

__libnvme_public bool libnvme_transport_handle_is_ctrl(
		struct libnvme_transport_handle *hdl)
{
	return S_ISCHR(hdl->stat.st_mode);
}

__libnvme_public bool libnvme_transport_handle_is_ns(
		struct libnvme_transport_handle *hdl)
{
	return S_ISBLK(hdl->stat.st_mode);
}

__libnvme_public bool libnvme_transport_handle_is_direct(
		struct libnvme_transport_handle *hdl)
{
	return hdl->type == LIBNVME_TRANSPORT_HANDLE_TYPE_DIRECT;
}

__libnvme_public bool libnvme_transport_handle_is_mi(
		struct libnvme_transport_handle *hdl)
{
	return hdl->type == LIBNVME_TRANSPORT_HANDLE_TYPE_MI;
}
