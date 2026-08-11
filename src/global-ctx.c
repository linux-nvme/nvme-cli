// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libnvme.h>
#include <libnvme-mi.h>

#include "global-ctx.h"
#include "args.h"
#include "argconfig.h"
#include "cleanup.h"
#include "logging.h"
#include "nvme-print.h"
#include "string-util.h"

static int check_arg_dev(int argc, char **argv)
{
	if (optind >= argc) {
		errno = EINVAL;
		nvme_show_perror(argv[0]);
		return -EINVAL;
	}
	return 0;
}

static int get_transport_handle(struct libnvme_global_ctx *ctx, int argc,
					char **argv, int flags,
					struct libnvme_transport_handle **hdl)
{
	char *devname;
	int ret;

	ret = check_arg_dev(argc, argv);
	if (ret)
		return ret;

	devname = argv[optind];

	ret = libnvme_open(ctx, devname, hdl);
	if (ret)
		nvme_show_err(ret, devname);

	return ret;
}

void put_transport_handle(struct libnvme_transport_handle *hdl)
{
	libnvme_close(hdl);
}

static void setup_transport_handle(struct libnvme_global_ctx *ctx,
		struct libnvme_transport_handle *hdl,
		struct argconfig_commandline_options *opts)
{
	libnvme_transport_handle_set_submit_entry(hdl, nvme_submit_entry);
	libnvme_transport_handle_set_submit_exit(hdl, nvme_submit_exit);
	libnvme_transport_handle_set_decide_retry(hdl, nvme_decide_retry);

#ifdef CONFIG_MI
	if (libnvme_transport_handle_is_mi(hdl)) {
		libnvme_mi_ep_t ep = libnvme_transport_handle_get_mi_ep(hdl);
		if (ep) {
			libnvme_mi_ep_set_submit_entry(ep, nvme_mi_submit_entry);
			libnvme_mi_ep_set_submit_exit(ep, nvme_mi_submit_exit);
		}
	}
#endif

	libnvme_set_dry_run(ctx, nvme_args.dry_run);
	if (nvme_args.timeout != NVME_DEFAULT_IOCTL_TIMEOUT)
		libnvme_transport_handle_set_timeout(hdl, nvme_args.timeout);
}

static bool is_true(const char *val)
{
	return !strcmp(val, "1") ||
		!strcasecmp(val, "true") ||
		!strncasecmp(val, "enable", 6);
}

/*
 * nvme_apply_option() - apply a single "key=value" pair to @ctx.
 *
 * Returns 0 on success, -EINVAL for unknown keys or missing '='.
 */
static int nvme_apply_option(struct libnvme_global_ctx *ctx, const char *kv)
{
	__cleanup_free char *str = NULL;
	char *key, *val;
	int ret = 0;

	str = strdup(kv);
	if (!str)
		return -ENOMEM;

	val = strchr(str, '=');
	if (!val) {
		nvme_show_error("--set-options: missing '=' in '%s'", kv);
		return -EINVAL;
	}
	*val++ = '\0';
	key = str;

	if (!strcmp(key, "force-4k")) {
		libnvme_set_force_4k(ctx, is_true(val));
	} else if (!strcmp(key, "mi-probe-enabled")) {
		libnvme_set_mi_probe_enabled(ctx, is_true(val));
	} else if (!strcmp(key, "test-base-dir")) {
		ret = libnvme_set_test_base_dir(ctx, val);
	} else if (!strcmp(key, "test-sysfs-dir")) {
		ret = libnvme_set_test_sysfs_dir(ctx, val);
	} else {
		nvme_show_error("--set-options: unknown key '%s'", key);
		return -EINVAL;
	}

	if (ret)
		nvme_show_error("--set-options: failed to set '%s=%s': %s",
			key, val, libnvme_strerror(-ret));

	return ret;
}

static int __nvme_create_global_ctx(struct libnvme_global_ctx **pctx)
{
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_free char *buf = NULL;
	const char *opt;
	char *p;
	int err;

	ctx = libnvme_create_global_ctx();
	if (!ctx)
		return -ENOMEM;

	log_level = map_log_level(nvme_args.verbose, nvme_args.quiet);
	libnvme_set_logging_file(ctx, stdout);
	libnvme_set_logging_level(ctx, log_level, false, false);

	if (!nvme_args.set_options)
		goto out;

	buf = strdup(nvme_args.set_options);
	if (!buf)
		return -ENOMEM;

	p = buf;
	while ((opt = strsep(&p, ",")) != NULL) {
		if (!*opt)
			continue;
		err = nvme_apply_option(ctx, opt);
		if (err)
			return err;
	}

out:
	*pctx = ctx;
	ctx = NULL;

	return 0;
}

int nvme_create_global_ctx_hostnqn(struct libnvme_global_ctx **pctx,
				       const char *hostnqn_arg,
				       const char *hostid_arg,
				       char **hostnqn, char **hostid)
{
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_free char *hnqn = NULL;
	__cleanup_free char *hid = NULL;
	int err;

	err = __nvme_create_global_ctx(&ctx);
	if (err)
		return err;

	libnvme_set_ioctl_probing(ctx, !nvme_args.no_ioctl_probing);

#ifdef CONFIG_FABRICS
	err = libnvmf_host_get_ids(ctx, hostnqn_arg, hostid_arg, &hnqn, &hid);
	if (err)
		return err;

	libnvme_set_hostnqn(ctx, hnqn);
	libnvme_set_hostid(ctx, hid);
#endif

	if (hostnqn) {
		*hostnqn = hnqn;
		hnqn = NULL;
	}
	if (hostid) {
		*hostid = hid;
		hid = NULL;
	}

	*pctx = ctx;
	ctx = NULL;

	return 0;
}

int nvme_create_global_ctx(struct libnvme_global_ctx **pctx)
{
	return nvme_create_global_ctx_hostnqn(pctx, NULL, NULL, NULL, NULL);
}

int parse_and_open(struct libnvme_global_ctx **ctx,
		   struct libnvme_transport_handle **hdl, int argc, char **argv,
		   const char *desc, struct argconfig_commandline_options *opts)
{
	struct libnvme_transport_handle *hdl_new;
	struct libnvme_global_ctx *ctx_new;
	int ret;

	ret = parse_args(argc, argv, desc, opts);
	if (ret)
		return ret;

	ret = nvme_create_global_ctx(&ctx_new);
	if (ret)
		return ret;

	ret = get_transport_handle(ctx_new, argc, argv, O_RDONLY, &hdl_new);
	if (ret) {
		libnvme_free_global_ctx(ctx_new);
		argconfig_print_help(desc, opts);
		return -ENXIO;
	}

	setup_transport_handle(ctx_new, hdl_new, opts);

	*ctx = ctx_new;
	*hdl = hdl_new;

	return 0;
}

int open_exclusive(struct libnvme_global_ctx **ctx,
		   struct libnvme_transport_handle **hdl, int argc, char **argv,
		   int ignore_exclusive,
		   struct argconfig_commandline_options *opts)
{
	struct libnvme_transport_handle *hdl_new;
	struct libnvme_global_ctx *ctx_new;
	int flags = O_RDONLY;
	int ret;

	if (!ignore_exclusive)
		flags |= O_EXCL;

	ret = nvme_create_global_ctx(&ctx_new);
	if (ret)
		return ret;

	ret = get_transport_handle(ctx_new, argc, argv, flags, &hdl_new);
	if (ret) {
		libnvme_free_global_ctx(ctx_new);
		return -ENXIO;
	}

	setup_transport_handle(ctx_new, hdl_new, opts);

	*ctx = ctx_new;
	*hdl = hdl_new;

	return 0;
}
