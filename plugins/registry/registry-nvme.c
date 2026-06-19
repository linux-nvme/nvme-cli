// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libnvme.h>

#include "common.h"
#include "nvme.h"
#include "util/cleanup.h"

#define CREATE_CMD
#include "registry-nvme.h"

static void strip_dev_prefix(char **device)
{
	if (!strncmp(*device, "/dev/", 5))
		*device += 5;
}

static void print_attr(const char *attr, const char *value, void *user_data)
{
	printf("  %-12s %s\n", attr, value);
}

static void print_device(const char *device, void *user_data)
{
	struct libnvme_global_ctx *ctx = user_data;
	printf("%s\n", device);
	libnvmf_registry_attr_for_each(ctx, device, print_attr, NULL);
}

static int registry_list(int argc, char **argv, struct command *acmd,
			  struct plugin *plugin)
{
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	const char *desc = "List all live NVMeoF controller ownership registry entries.";

	NVME_ARGS(opts);

	if (argconfig_parse(argc, argv, desc, opts))
		return -EINVAL;

	ctx = libnvme_create_global_ctx(stdout, LIBNVME_DEFAULT_LOGLEVEL);
	return libnvmf_registry_device_for_each(ctx, print_device, ctx);
}

static int registry_retrieve(int argc, char **argv, struct command *acmd,
			      struct plugin *plugin)
{
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	const char *desc = "Read an attribute from a controller's registry entry.";
	const char *device_help = "NVMe device name (e.g. nvme3)";
	const char *attr_help = "attribute name (default: owner)";
	__cleanup_free char *value = NULL;
	int ret;

	struct config {
		char *device;
		char *attr;
	};

	struct config cfg = { .attr = "owner" };

	NVME_ARGS(opts,
		OPT_STRING("device", 'd', "DEV",  &cfg.device, device_help),
		OPT_STRING("attr",   'a', "ATTR", &cfg.attr,   attr_help));

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret)
		return ret;

	if (!cfg.device) {
		fprintf(stderr, "--device required\n");
		return -EINVAL;
	}
	strip_dev_prefix(&cfg.device);

	ctx = libnvme_create_global_ctx(stdout, LIBNVME_DEFAULT_LOGLEVEL);
	ret = libnvmf_registry_retrieve(ctx, cfg.device, cfg.attr, &value);
	if (ret == -ENOENT) {
		fprintf(stderr, "%s: not registered or '%s' not found\n",
			cfg.device, cfg.attr);
		return ret;
	}
	if (ret) {
		fprintf(stderr, "retrieve failed: %s\n", libnvme_strerror(-ret));
		return ret;
	}
	printf("%s\n", value);
	return 0;
}

static int registry_update(int argc, char **argv, struct command *acmd,
			    struct plugin *plugin)
{
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	const char *desc = "Write an attribute to a controller's registry entry. The 'owner' attribute is immutable and cannot be changed.";
	const char *device_help = "NVMe device name (e.g. nvme3)";
	const char *attr_help = "attribute name (e.g. note); 'owner' is not allowed";
	const char *value_help = "new attribute value";
	int ret;

	struct config {
		char *device;
		char *attr;
		char *value;
	};

	struct config cfg = { 0 };

	NVME_ARGS(opts,
		OPT_STRING("device", 'd', "DEV",  &cfg.device, device_help),
		OPT_STRING("attr",   'a', "ATTR", &cfg.attr,   attr_help),
		OPT_STRING("value",  'V', "VAL",  &cfg.value,  value_help));

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret)
		return ret;

	if (!cfg.device || !cfg.attr || !cfg.value) {
		fprintf(stderr, "--device, --attr and --value are required\n");
		return -EINVAL;
	}

	if (!strcmp(cfg.attr, "owner")) {
		fprintf(stderr, "the 'owner' attribute is immutable and cannot be changed via this command\n");
		return -EPERM;
	}

	strip_dev_prefix(&cfg.device);

	ctx = libnvme_create_global_ctx(stdout, LIBNVME_DEFAULT_LOGLEVEL);
	ret = libnvmf_registry_update(ctx, cfg.device, cfg.attr, cfg.value);
	if (ret)
		fprintf(stderr, "update failed: %s\n", libnvme_strerror(-ret));
	return ret;
}

static int registry_delete(int argc, char **argv, struct command *acmd,
			    struct plugin *plugin)
{
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	const char *desc = "Remove a controller's registry entry.";
	const char *device_help = "NVMe device name (e.g. nvme3)";
	int ret;

	struct config {
		char *device;
	};

	struct config cfg = { 0 };

	NVME_ARGS(opts,
		OPT_STRING("device", 'd', "DEV", &cfg.device, device_help));

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret)
		return ret;

	if (!cfg.device) {
		fprintf(stderr, "--device required\n");
		return -EINVAL;
	}
	strip_dev_prefix(&cfg.device);

	ctx = libnvme_create_global_ctx(stdout, LIBNVME_DEFAULT_LOGLEVEL);
	ret = libnvmf_registry_delete(ctx, cfg.device);
	if (ret)
		fprintf(stderr, "%s: %s\n", cfg.device, libnvme_strerror(-ret));
	return ret;
}
