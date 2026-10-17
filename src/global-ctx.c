// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libnvme-mi.h>
#include <libnvme.h>

#include <shared/string-util.h>

#include "argconfig.h"
#include "args.h"
#include "cleanup.h"
#include "global-ctx.h"
#include "logging.h"
#include "nvme-print.h"

static int check_arg_dev(int argc, char **argv)
{
	if (!nvme_args.device) {
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

	devname = nvme_args.device;

	ret = libnvme_open(ctx, devname, flags, hdl);
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
		struct libnvme_mi_ep *ep = libnvme_transport_handle_get_mi_ep(hdl);
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

/*
 * Mirror of libnvme's test sysfs root. libnvme keeps its own copy, set
 * through libnvme_set_test_sysfs_dir(); this one covers the sysfs
 * attributes nvme-cli reads by path rather than through libnvme.
 */
static char *test_sysfs_dir;

static int set_test_sysfs_dir(const char *path)
{
	char *dup = strdup(path);

	if (!dup)
		return -ENOMEM;

	free(test_sysfs_dir);
	test_sysfs_dir = dup;

	return 0;
}

int nvme_sysfs_ctrl_path(const char *ctrl_name, char **path)
{
	if (asprintf(path, "%s/sys/class/nvme/%s",
		     test_sysfs_dir ? test_sysfs_dir : "", ctrl_name) < 0)
		return -ENOMEM;

	return 0;
}

enum set_option_key {
	SET_FORCE_4K,
	SET_MI_PROBE_ENABLED,
	SET_TEST_BASE_DIR,
	SET_TEST_SYSFS_DIR,
	SET_KEYS,
};

static const char * const set_option_keys[] = {
	[SET_FORCE_4K]		= "force-4k",
	[SET_MI_PROBE_ENABLED]	= "mi-probe-enabled",
	[SET_TEST_BASE_DIR]	= "test-base-dir",
	[SET_TEST_SYSFS_DIR]	= "test-sysfs-dir",
};

struct set_option {
	enum set_option_key key;
	char *val;
};

/* --set-options "key=value[,key=value,...]", split in @buf. */
struct set_options {
	char *buf;
	struct set_option *opts;
	unsigned int count;
	/* The first invalid key=value, or its unknown key. */
	char *missing_eq;
	char *unknown_key;
};

static bool is_true(const char *val)
{
	return !strcmp(val, "1") ||
		!strcasecmp(val, "true") ||
		!strncasecmp(val, "enable", 6);
}

/* Splits @so->buf into @so->opts up to the first invalid option. */
static void parse_set_options(struct set_options *so)
{
	char *p = so->buf, *kv, *val;
	int key;

	while ((kv = shr_strsep(&p, ",")) != NULL) {
		if (!*kv)
			continue;

		val = strchr(kv, '=');
		if (!val) {
			so->missing_eq = kv;
			return;
		}
		*val++ = '\0';

		for (key = 0; key < SET_KEYS; key++)
			if (!strcmp(kv, set_option_keys[key]))
				break;
		if (key == SET_KEYS) {
			so->unknown_key = kv;
			return;
		}

		so->opts[so->count].key = key;
		so->opts[so->count].val = val;
		so->count++;
	}
}

static int apply_set_option(struct libnvme_global_ctx *ctx,
			    const struct set_option *opt)
{
	int ret = 0;

	switch (opt->key) {
	case SET_FORCE_4K:
		libnvme_set_force_4k(ctx, is_true(opt->val));
		break;
	case SET_MI_PROBE_ENABLED:
		libnvme_set_mi_probe_enabled(ctx, is_true(opt->val));
		break;
	case SET_TEST_BASE_DIR:
		ret = libnvme_set_test_base_dir(ctx, opt->val);
		break;
	case SET_TEST_SYSFS_DIR:
		ret = libnvme_set_test_sysfs_dir(ctx, opt->val);
		if (!ret)
			ret = set_test_sysfs_dir(opt->val);
		break;
	case SET_KEYS:
		break;
	}

	if (ret)
		nvme_show_error("--set-options: failed to set '%s=%s': %s",
			set_option_keys[opt->key], opt->val,
			libnvme_strerror(-ret));

	return ret;
}

/*
 * nvme_apply_set_options() - apply --set-options to @ctx.
 *
 * Returns 0 on success, -EINVAL for unknown keys or missing '='.
 */
static int nvme_apply_set_options(struct libnvme_global_ctx *ctx,
				  const char *str)
{
	__cleanup_free struct set_option *opts = NULL;
	__cleanup_free char *buf = strdup(str);
	struct set_options so = { .buf = buf };
	unsigned int i, n = 1;
	int ret;

	for (i = 0; str[i]; i++)
		n += str[i] == ',';
	opts = calloc(n, sizeof(*opts));
	if (!buf || !opts)
		return -ENOMEM;
	so.opts = opts;

	parse_set_options(&so);

	for (i = 0; i < so.count; i++) {
		ret = apply_set_option(ctx, &so.opts[i]);
		if (ret)
			return ret;
	}

	if (so.missing_eq) {
		nvme_show_error("--set-options: missing '=' in '%s'",
				so.missing_eq);
		return -EINVAL;
	}
	if (so.unknown_key) {
		nvme_show_error("--set-options: unknown key '%s'",
				so.unknown_key);
		return -EINVAL;
	}

	return 0;
}

static int __nvme_create_global_ctx(struct libnvme_global_ctx **pctx)
{
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	int err;

	ctx = libnvme_create_global_ctx();
	if (!ctx)
		return -ENOMEM;

	log_level = map_log_level(nvme_args.verbose, nvme_args.quiet);
	libnvme_set_logging_file(ctx, stderr);
	libnvme_set_logging_level(ctx, log_level, false, false);
	libnvme_set_dry_run(ctx, nvme_args.dry_run);

	if (nvme_args.set_options) {
		err = nvme_apply_set_options(ctx, nvme_args.set_options);
		if (err)
			return err;
	}

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
		return ret;
	}

	setup_transport_handle(ctx_new, hdl_new, opts);

	*ctx = ctx_new;
	*hdl = hdl_new;

	return 0;
}
