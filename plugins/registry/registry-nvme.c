// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libnvme.h>

#include "common.h"
#include "nvme.h"
#include "nvme-print.h"
#include "util/cleanup.h"

#define CREATE_CMD
#include "registry-nvme.h"

static void strip_dev_prefix(char **device)
{
	if (!strncmp(*device, "/dev/", 5))
		*device += 5;
}

/*
 * The device (a controller name like "nvme3", optionally given as
 * "/dev/nvme3") is passed as a positional argument, consistent with the rest
 * of the nvme CLI.  Returns the bare controller name, or NULL if no positional
 * argument was supplied.
 */
static char *get_device(int argc, char **argv)
{
	char *device;

	if (optind >= argc)
		return NULL;

	device = argv[optind];
	strip_dev_prefix(&device);
	return device;
}

/*
 * Warn before an operation that changes or removes ownership and ask the
 * user to confirm.  Returns true if the operation should proceed.  A
 * non-interactive caller (no controlling terminal) always proceeds --
 * scripting the command is itself the statement of intent.
 */
static bool confirm_owner_change(void)
{
	char ans[8] = { 0 };

	if (!isatty(STDIN_FILENO))
		return true;

	nvme_show_error(
		"Changing or removing the owner may prevent NVMe orchestrators from\n"
		"protecting this controller against accidental removal. Continue? [y/N]: ");

	if (!fgets(ans, sizeof(ans), stdin))
		return false;

	return ans[0] == 'y' || ans[0] == 'Y';
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
	const char *desc = "List all live NVMeoF controller ownership registry entries.";
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	int ret;

	NVME_ARGS(opts);

	if (argconfig_parse(argc, argv, desc, opts))
		return -EINVAL;

	ret = nvme_create_global_ctx(&ctx);
	if (ret)
		return ret;
	libnvme_set_logging_file(ctx, stdout);

	return libnvmf_registry_device_for_each(ctx, print_device, ctx);
}

static int registry_retrieve(int argc, char **argv, struct command *acmd,
			      struct plugin *plugin)
{
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	const char *desc = "Read an attribute from a controller's registry entry.";
	const char *attr_help = "attribute name (e.g. owner, note)";
	__cleanup_free char *value = NULL;
	char *device;
	int ret;

	struct config {
		char *attr;
	};

	struct config cfg = { 0 };

	NVME_ARGS(opts,
		OPT_STRING("attr", 'a', "ATTR", &cfg.attr, attr_help));

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret)
		return ret;

	device = get_device(argc, argv);
	if (!device) {
		nvme_show_error("device required");
		return -EINVAL;
	}
	if (!cfg.attr) {
		nvme_show_error("--attr required");
		return -EINVAL;
	}

	ret = nvme_create_global_ctx(&ctx);
	if (ret)
		return ret;
	libnvme_set_logging_file(ctx, stdout);

	ret = libnvmf_registry_retrieve(ctx, device, cfg.attr, &value);
	if (ret == -ENOENT) {
		nvme_show_error("%s: not registered or '%s' not found",
			device, cfg.attr);
		return ret;
	}
	if (ret) {
		nvme_show_error("retrieve failed: %s", libnvme_strerror(-ret));
		return ret;
	}
	printf("%s\n", value);
	return 0;
}

static int registry_update(int argc, char **argv, struct command *acmd,
			    struct plugin *plugin)
{
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	const char *desc = "Write an attribute to a controller's registry entry.";
	const char *attr_help = "attribute name (e.g. note, owner)";
	const char *value_help = "new attribute value";
	char *device;
	int ret;

	struct config {
		char *attr;
		char *value;
	};

	struct config cfg = { 0 };

	NVME_ARGS(opts,
		OPT_STRING("attr",  'a', "ATTR", &cfg.attr,  attr_help),
		OPT_STRING("value", 'V', "VAL",  &cfg.value, value_help));

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret)
		return ret;

	device = get_device(argc, argv);
	if (!device) {
		nvme_show_error("device required");
		return -EINVAL;
	}
	if (!cfg.attr || !cfg.value) {
		nvme_show_error("--attr and --value are required");
		return -EINVAL;
	}

	if (!strcmp(cfg.attr, "owner") && !confirm_owner_change()) {
		nvme_show_error("Aborted.");
		return 0;
	}

	ret = nvme_create_global_ctx(&ctx);
	if (ret)
		return ret;
	libnvme_set_logging_file(ctx, stdout);

	ret = libnvmf_registry_update(ctx, device, cfg.attr, cfg.value);
	if (ret)
		nvme_show_error("update failed: %s", libnvme_strerror(-ret));
	return ret;
}

static int registry_delete(int argc, char **argv, struct command *acmd,
			    struct plugin *plugin)
{
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	const char *desc = "Remove a controller's registry entry.";
	const char *attr_help = "attribute to remove (default: whole entry)";
	char *device;
	int ret;

	struct config {
		char *attr;
	};

	struct config cfg = { 0 };

	NVME_ARGS(opts,
		OPT_STRING("attr", 'a', "ATTR", &cfg.attr, attr_help));

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret)
		return ret;

	device = get_device(argc, argv);
	if (!device) {
		nvme_show_error("device required");
		return -EINVAL;
	}

	/*
	 * Removing the whole entry, or the owner attribute specifically, drops
	 * ownership -- confirm first.  Removing any other attribute does not
	 * affect ownership and proceeds silently.
	 */
	if ((!cfg.attr || !strcmp(cfg.attr, "owner")) &&
	    !confirm_owner_change()) {
		nvme_show_error("Aborted.");
		return 0;
	}

	ret = nvme_create_global_ctx(&ctx);
	if (ret)
		return ret;
	libnvme_set_logging_file(ctx, stdout);

	if (cfg.attr)
		ret = libnvmf_registry_update(ctx, device, cfg.attr, NULL);
	else
		ret = libnvmf_registry_delete(ctx, device);
	if (ret)
		nvme_show_error("%s: %s", device, libnvme_strerror(-ret));
	return ret;
}
