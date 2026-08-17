// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * NVM-Express command line utility.
 *
 * Copyright (c) 2014-2015, Intel Corporation.
 *
 * Written by Keith Busch <kbusch@kernel.org>
 */

/**
 * This program uses NVMe IOCTLs to run native nvme commands to a device.
 */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <libgen.h>
#include <locale.h>
#include <math.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef NVME_HAVE_MMAP
#include <sys/mman.h>
#endif
#include <sys/stat.h>
#include <sys/types.h>

#include <libnvme-mi.h>
#include <libnvme.h>

#include <ccan/array_size/array_size.h>
#include <ccan/endian/endian.h>
#include <ccan/minmax/minmax.h>
#include <shared/compiler-attributes-util.h>
#include <shared/fs-util.h>
#include <shared/mmio-util.h>
#include <shared/parse-util.h>
#include <shared/sig-util.h>
#include <shared/suffix-util.h>
#include <shared/time-util.h>

#include "argconfig.h"
#include "cleanup.h"
#include "fabrics.h"
#include "global-config.h"
#include "global-ctx.h"
#include "logging.h"
#include "nvme-cmds-common.h"
#include "nvme-cmds.h"
#include "nvme-print.h"
#include "nvme-regs.h"
#include "plugin.h"

static const char *only_ctrl_dev = "Only controller device is allowed";

static int virtual_mgmt(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "The Virtualization Management command is supported by primary controllers "
		"that support the Virtualization Enhancements capability. This command is used for:\n"
		"  1. Modifying Flexible Resource allocation for the primary controller\n"
		"  2. Assigning Flexible Resources for secondary controllers\n"
		"  3. Setting the Online and Offline state for secondary controllers";
	const char *cntlid = "Controller Identifier(CNTLID)";
	const char *rt = "Resource Type(RT): [0,1]\n"
		"0h: VQ Resources\n"
		"1h: VI Resources";
	const char *act = "Action(ACT): [1,7,8,9]\n"
		"1h: Primary Flexible\n"
		"7h: Secondary Offline\n"
		"8h: Secondary Assign\n"
		"9h: Secondary Online";
	const char *nr = "Number of Controller Resources(NR)";

	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	struct libnvme_passthru_cmd cmd;
	int err;

	struct config {
		__u16	cntlid;
		__u8	rt;
		__u8	act;
		__u16	nr;
	};

	struct config cfg = {
		.cntlid	= 0,
		.rt	= 0,
		.act	= 0,
		.nr	= 0,
	};

	NVME_ARGS(opts,
		  OPT_SHRT("cntlid", 'c', &cfg.cntlid, cntlid),
		  OPT_BYTE("rt",     'r', &cfg.rt,     rt),
		  OPT_BYTE("act",    'a', &cfg.act,    act),
		  OPT_SHRT("nr",     'n', &cfg.nr,     nr));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	nvme_init_virtual_mgmt(&cmd, cfg.act, cfg.rt, cfg.cntlid, cfg.nr);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "virt-mgmt");
		return err;
	}

	nvme_show_verbose_result(
		"success, Number of Controller Resources Modified (NRM):%" PRIu64,
		(uint64_t)cmd.result);

	return err;
}

static int subsystem_reset(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Resets the NVMe subsystem";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	int err;

	NVME_ARGS(opts);

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	if (!libnvme_transport_handle_is_ctrl(hdl)) {
		nvme_show_error(only_ctrl_dev);
		return -EINVAL;
	}

	err = libnvme_reset_subsystem(hdl);
	if (err < 0) {
		if (errno == ENOTTY)
			nvme_show_error("Subsystem-reset: NVM Subsystem Reset not supported.");
		else
			nvme_show_error("Subsystem-reset: %s", libnvme_strerror(-err));
	} else {
		nvme_show_verbose_info("resetting subsystem through %s",
				       libnvme_transport_handle_get_name(hdl));
	}

	return err;
}

static int reset(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Resets the NVMe controller\n";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	int err;

	NVME_ARGS(opts);

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	if (!libnvme_transport_handle_is_ctrl(hdl)) {
		nvme_show_error(only_ctrl_dev);
		return -EINVAL;
	}

	err = libnvme_reset_ctrl(hdl);
	if (err < 0)
		nvme_show_error("Reset: %s", libnvme_strerror(-err));
	else
		nvme_show_verbose_info("resetting controller %s",
				       libnvme_transport_handle_get_name(hdl));

	return err;
}

static int ns_rescan(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Rescans the NVMe namespaces\n";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	int err;
	nvme_print_flags_t flags;

	NVME_ARGS(opts);

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	if (!libnvme_transport_handle_is_ctrl(hdl)) {
		nvme_show_error(only_ctrl_dev);
		return -EINVAL;
	}

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	err = libnvme_rescan_ns(hdl);
	if (err < 0)
		nvme_show_error("Namespace Rescan: %s\n", libnvme_strerror(-err));
	else
		nvme_show_verbose_info("rescanning namespaces through %s",
				       libnvme_transport_handle_get_name(hdl));

	return err;
}

/* rpmb_cmd_option is defined in nvme-rpmb.c */
extern int rpmb_cmd_option(int, char **, struct command *, struct plugin *);
static int rpmb_cmd(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return rpmb_cmd_option(argc, argv, acmd, plugin);
}

static int lockdown_cmd(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "The Lockdown command is used to control the\n"
		"Command and Feature Lockdown capability which configures the\n"
		"prohibition or allowance of execution of the specified command\n"
		"or Set Features command targeting a specific Feature Identifier.";
	const char *ofi_desc = "Opcode or Feature Identifier (OFI)\n"
		"specifies the command opcode or Set Features Feature Identifier\n"
		"identified by the Scope field.";
	const char *ifc_desc =
	    "[0-3] Interface (INF) field identifies the interfaces affected by this command.";
	const char *prhbt_desc = "[0-1]Prohibit(PRHBT) bit specifies whether\n"
		"to prohibit or allow the command opcode or Set Features Feature\n"
		"Identifier specified by this command.";
	const char *scp_desc =
	    "[0-15]Scope(SCP) field specifies the contents of the Opcode or Feature Identifier field.";
	const char *uuid_desc = "UUID Index - If this field is set to a non-zero\n"
		"value, then the value of this field is the index of a UUID in the UUID\n"
		"List that is used by the command.If this field is cleared to 0h,\n"
		"then no UUID index is specified";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	struct libnvme_passthru_cmd cmd;
	int err = -1;

	struct config {
		__u8	ofi;
		__u8	ifc;
		__u8	prhbt;
		__u8	scp;
		__u8	uuid;
	};

	struct config cfg = {
		.ofi	= 0,
		.ifc	= 0,
		.prhbt	= 0,
		.scp	= 0,
		.uuid	= 0,
	};

	NVME_ARGS(opts,
		  OPT_BYTE("ofi",	'O', &cfg.ofi,      ofi_desc),
		  OPT_BYTE("ifc",	'f', &cfg.ifc,      ifc_desc),
		  OPT_BYTE("prhbt",	'p', &cfg.prhbt,    prhbt_desc),
		  OPT_BYTE("scp",	's', &cfg.scp,      scp_desc),
		  OPT_BYTE("uuid",	'U', &cfg.uuid,     uuid_desc));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	/* check for input argument limit */
	if (cfg.ifc > 3) {
		nvme_show_error("invalid interface settings:%d", cfg.ifc);
		return -1;
	}
	if (cfg.prhbt > 1) {
		nvme_show_error("invalid prohibit settings:%d", cfg.prhbt);
		return -1;
	}
	if (cfg.scp > 15) {
		nvme_show_error("invalid scope settings:%d", cfg.scp);
		return -1;
	}
	if (cfg.uuid > 127) {
		nvme_show_error("invalid UUID index settings:%d", cfg.uuid);
		return -1;
	}

	nvme_init_lockdown(&cmd, cfg.scp, cfg.prhbt, cfg.ifc, cfg.ofi,
			   cfg.uuid);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "lockdown");
		return err;
	}

	nvme_show_verbose_result("Lockdown Command is Successful");

	return err;
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

static struct command reset_cmd = {
	.name = "reset",
	.help = "Resets the controller",
	.fn = reset,
};

static struct command subsystem_reset_cmd = {
	.name = "subsystem-reset",
	.help = "Resets the subsystem",
	.fn = subsystem_reset,
};

static struct command ns_rescan_cmd = {
	.name = "ns-rescan",
	.help = "Rescans the NVME namespaces",
	.fn = ns_rescan,
};

static struct command virtual_mgmt_cmd = {
	.name = "virt-mgmt",
	.help = "Manage Flexible Resources between Primary and Secondary Controller",
	.fn = virtual_mgmt,
};

static struct command rpmb_cmd_cmd = {
	.name = "rpmb",
	.help = "Replay Protection Memory Block commands",
	.fn = rpmb_cmd,
};

static struct command lockdown_cmd_cmd = {
	.name = "lockdown",
	.help = "Submit a Lockdown command,return result",
	.fn = lockdown_cmd,
};

static struct command show_topology_cmd_cmd = {
	.name = "show-topology",
	.help = "Show the topology",
	.fn = show_topology_cmd,
};

static struct command *commands[] = {
	&reset_cmd,
	&subsystem_reset_cmd,
	&ns_rescan_cmd,
	&virtual_mgmt_cmd,
	&rpmb_cmd_cmd,
	&lockdown_cmd_cmd,
	&show_topology_cmd_cmd,
	NULL,
};

static void __shr_constructor register_group(void)
{
	plugin_add_group(&builtin, "Controller Management", commands);
}
