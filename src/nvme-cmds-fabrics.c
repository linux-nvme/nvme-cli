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

#include <libnvme.h>
#include <libnvme-mi.h>

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
#include "nvme-cmds.h"
#include "nvme-print.h"
#include "nvme-regs.h"
#include "plugin.h"
#include "nvme-cmds-common.h"

#ifdef CONFIG_FABRICS

static int gen_hostnqn_cmd(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Generate a hostnqn";

	__cleanup_free char *hostnqn = NULL;
	int err;

	NVME_ARGS(opts);

	err = parse_args(argc, argv, desc, opts);
	if (err)
		return err;

	hostnqn = libnvmf_generate_hostnqn();
	if (!hostnqn) {
		nvme_show_error("\"%s\" not supported. Install lib uuid and rebuild.",
				acmd->name);
		return -ENOTSUP;
	}

	nvme_show_result("%s", hostnqn);

	return 0;
}

static int show_hostnqn_cmd(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Show hostnqn";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_free char *hostnqn = NULL;
	int err;

	NVME_ARGS(opts);

	err = parse_args(argc, argv, desc, opts);
	if (err)
		return err;

	ctx = libnvme_create_global_ctx();
	if (!ctx)
		return -ENOMEM;

	hostnqn = libnvmf_read_hostnqn(ctx);
	if (!hostnqn)
		hostnqn =  libnvmf_generate_hostnqn();

	if (!hostnqn) {
		nvme_show_error("hostnqn is not available -- use nvme gen-hostnqn");
		return -ENOENT;
	}

	nvme_show_result("%s", hostnqn);

	return 0;
}

static int discover_cmd(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Send Get Log Page request to Discovery Controller.";

	return fabrics_discover(desc, argc, argv, false);
}

static int connect_all_cmd(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Discover NVMeoF subsystems and connect to them";

	return fabrics_discover(desc, argc, argv, true);
}

static int connect_cmd(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Connect to NVMeoF subsystem";

	return fabrics_connect(desc, argc, argv);
}

static int disconnect_cmd(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Disconnect from NVMeoF subsystem";

	return fabrics_disconnect(desc, argc, argv);
}

static int disconnect_all_cmd(int argc, char **argv, struct command *acmd,
	struct plugin *plugin)
{
	const char *desc = "Disconnect from all connected NVMeoF subsystems";

	return fabrics_disconnect_all(desc, argc, argv);
}

static int dim_cmd(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc =
	    "Send Discovery Information Management command to a Discovery Controller (DC)";

	return fabrics_dim(desc, argc, argv);
}

static struct command discover_cmd_cmd = {
	.name = "discover",
	.help = "Discover NVMeoF subsystems",
	.fn = discover_cmd,
};

static struct command connect_all_cmd_cmd = {
	.name = "connect-all",
	.help = "Discover and Connect to NVMeoF subsystems",
	.fn = connect_all_cmd,
};

static struct command connect_cmd_cmd = {
	.name = "connect",
	.help = "Connect to NVMeoF subsystem",
	.fn = connect_cmd,
};

static struct command disconnect_cmd_cmd = {
	.name = "disconnect",
	.help = "Disconnect from NVMeoF subsystem",
	.fn = disconnect_cmd,
};

static struct command disconnect_all_cmd_cmd = {
	.name = "disconnect-all",
	.help = "Disconnect from all connected NVMeoF subsystems",
	.fn = disconnect_all_cmd,
};

static struct command dim_cmd_cmd = {
	.name = "dim",
	.help = "Send Discovery Information Management command to a Discovery Controller",
	.fn = dim_cmd,
};

static struct command gen_hostnqn_cmd_cmd = {
	.name = "gen-hostnqn",
	.help = "Generate NVMeoF host NQN",
	.fn = gen_hostnqn_cmd,
};

static struct command show_hostnqn_cmd_cmd = {
	.name = "show-hostnqn",
	.help = "Show NVMeoF host NQN",
	.fn = show_hostnqn_cmd,
};

static struct command *commands[] = {
	&discover_cmd_cmd,
	&connect_all_cmd_cmd,
	&connect_cmd_cmd,
	&disconnect_cmd_cmd,
	&disconnect_all_cmd_cmd,
	&dim_cmd_cmd,
	&gen_hostnqn_cmd_cmd,
	&show_hostnqn_cmd_cmd,
	NULL,
};

static void __shr_constructor register_group(void)
{
	plugin_add_group(&builtin, "Fabrics", commands);
}

#endif /* CONFIG_FABRICS */
