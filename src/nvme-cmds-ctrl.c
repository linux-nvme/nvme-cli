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
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libnvme.h>

#include <shared/compiler-attributes-util.h>

#include "argconfig.h"
#include "cleanup.h"
#include "global-ctx.h"
#include "logging.h"
#include "nvme-cmds-common.h"
#include "nvme-print.h"
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

static struct command *commands[] = {
	&reset_cmd,
	&subsystem_reset_cmd,
	&ns_rescan_cmd,
	&virtual_mgmt_cmd,
	NULL,
};

static void __shr_constructor register_group(void)
{
	plugin_add_group(&builtin, "Controller Management", commands);
}
