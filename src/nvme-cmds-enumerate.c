// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * NVM-Express command line utility.
 *
 * Copyright (c) 2014-2015, Intel Corporation.
 *
 * Written by Keith Busch <kbusch@kernel.org>
 */

/**
 * These are nvme-cli's own local device-enumeration commands: they scan the
 * host's sysfs/udev state to list or display attached NVMe devices, rather
 * than sending a specific NVMe command to a controller.
 */
#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <libnvme.h>

#include <shared/compiler-attributes-util.h>
#include <shared/sig-util.h>

#include "argconfig.h"
#include "cleanup.h"
#include "global-ctx.h"
#include "logging.h"
#include "nvme-cmds-common.h"
#include "nvme-print.h"
#include "plugin.h"

static int list_subsys(int argc, char **argv, struct command *acmd,
		struct plugin *plugin)
{
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	nvme_print_flags_t flags;
	const char *desc = "Retrieve information for subsystems";
	libnvme_scan_filter_t filter = NULL;
	char *devname;
	int err;
	int nsid = NVME_NSID_ALL;

	NVME_ARGS(opts);

	err = parse_args(argc, argv, desc, opts);
	if (err)
		return err;

	devname = NULL;
	if (optind < argc)
		devname = basename(argv[optind++]);

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0 || (flags != JSON && flags != NORMAL)) {
		nvme_show_error("Invalid output format");
		return -EINVAL;
	}

	if (nvme_args.verbose)
		flags |= VERBOSE;

	err = nvme_create_global_ctx(&ctx);
	if (err) {
		if (devname)
			nvme_show_error("Failed to scan nvme subsystem for %s", devname);
		else
			nvme_show_error("Failed to scan nvme subsystem");
		return err;
	}

	if (devname) {
		int subsys_num;

		if (sscanf(devname, "nvme%dn%d", &subsys_num, &nsid) < 1 &&
		    sscanf(devname, "ng%dn%d", &subsys_num, &nsid) != 2) {
			nvme_show_error("Invalid device name %s", devname);
			return -EINVAL;
		}
		filter = nvme_match_device_filter;
	}

	err = libnvme_scan_topology(ctx, filter, (void *)devname);
	if (err)
		return handle_scan_topology_error(err);

	nvme_show_subsystem_list(ctx, nsid != NVME_NSID_ALL, flags);

	return 0;
}

static int show_topology_cmd(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Show the topology\n";
	const char *ranking = "Ranking order: namespace|ctrl|multipath";
	nvme_print_flags_t flags;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	char *devname = NULL;
	libnvme_scan_filter_t filter = NULL;
	enum nvme_cli_topo_ranking rank;
	int err;

#ifdef CONFIG_JSONC
	nvme_print_flags_t supported_formats = (NORMAL | JSON | TABULAR);
	const char *supported_formats_desc = "Output format: normal|json|tabular";
#else /* CONFIG_JSONC */
	nvme_print_flags_t supported_formats = (NORMAL | TABULAR);
	const char *supported_formats_desc = "Output format: normal|tabular";
#endif /* CONFIG_JSONC */

	struct config {
		char	*ranking;
	};

	struct config cfg = {
		.ranking	= "namespace",
	};

	NVME_ARGS_OUTPUT_FORMATS(opts, supported_formats, supported_formats_desc,
		  OPT_FMT("ranking",       'r', &cfg.ranking,       ranking));

	err = parse_args(argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (nvme_args.verbose)
		flags |= VERBOSE;

	if (!strcmp(cfg.ranking, "namespace")) {
		rank = NVME_CLI_TOPO_NAMESPACE;
	} else if (!strcmp(cfg.ranking, "ctrl")) {
		rank = NVME_CLI_TOPO_CTRL;
	} else if (!strcmp(cfg.ranking, "multipath")) {
		rank = NVME_CLI_TOPO_MULTIPATH;
	} else {
		nvme_show_error("Invalid ranking argument: %s", cfg.ranking);
		return -EINVAL;
	}

	err = nvme_create_global_ctx(&ctx);
	if (err)
		return err;

	if (optind < argc)
		devname = basename(argv[optind++]);

	if (devname) {
		int subsys_id, nsid;

		if (sscanf(devname, "nvme%dn%d", &subsys_id, &nsid) < 1 &&
		    sscanf(devname, "ng%dn%d", &subsys_id, &nsid) != 2) {
			nvme_show_error("Invalid device name %s\n", devname);
			return -EINVAL;
		}
		filter = nvme_match_device_filter;
	}

	err = libnvme_scan_topology(ctx, filter, (void *)devname);
	if (err < 0)
		return handle_scan_topology_error(err);

	if (flags & TABULAR)
		nvme_show_topology_tabular(ctx, flags);
	else
		nvme_show_topology(ctx, rank, flags);

	return err;
}

#ifdef CONFIG_TOP
static int top(int argc, char **argv, struct command *acmd,
		struct plugin *plugin)
{
	int err;
	nvme_print_flags_t flags = 0;
	const char *desc = "show nvme top output";
	const char *delay = "refresh interval in seconds";

	struct config {
		int delay;
	};

	struct config cfg = {
		.delay = 1,
	};

	NVME_ARGS(opts,
		  OPT_INT("delay", 'd', &cfg.delay, delay));

	err = parse_args(argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0 || flags != NORMAL) {
		nvme_show_error("Invalid output format");
		return -EINVAL;
	}

	if (cfg.delay < 1) {
		nvme_show_error("delay must be greater than or equal to 1");
		return -EINVAL;
	}

	err = shr_install_sigwinch_handler();
	if (err) {
		nvme_show_error("failed to install sig handler for SIGWINCH");
		return err;
	}

	nvme_show_top(flags, cfg.delay);

	return err;
}
#endif

static int list(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Retrieve basic information for all NVMe namespaces";
	nvme_print_flags_t flags;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	int err = 0;

	NVME_ARGS(opts);

	err = parse_args(argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0 || (flags != JSON && flags != NORMAL)) {
		nvme_show_error("Invalid output format");
		return -EINVAL;
	}

	if (nvme_args.verbose)
		flags |= VERBOSE;

	err = nvme_create_global_ctx(&ctx);
	if (err)
		return err;

	err = libnvme_scan_topology(ctx, NULL, NULL);
	if (err < 0)
		return handle_scan_topology_error(err);

	nvme_show_list_items(ctx, flags);

	return err;
}

static struct command list_cmd = {
	.name = "list",
	.help = "List all NVMe devices and namespaces on machine",
	.fn = list,
};

static struct command list_subsys_cmd = {
	.name = "list-subsys",
	.help = "List nvme subsystems",
	.fn = list_subsys,
};

#ifdef CONFIG_TOP

static struct command top_cmd = {
	.name = "top",
	.help = "nvme top",
	.fn = top,
};

#endif /* CONFIG_TOP */

static struct command show_topology_cmd_cmd = {
	.name = "show-topology",
	.help = "Show the topology",
	.fn = show_topology_cmd,
};

static struct command *commands[] = {
	&list_cmd,
	&list_subsys_cmd,
	&show_topology_cmd_cmd,
#ifdef CONFIG_TOP
	&top_cmd,
#endif /* CONFIG_TOP */
	NULL,
};

static void __shr_constructor register_group(void)
{
	plugin_add_group(&builtin, "Device Enumeration", commands);
}
