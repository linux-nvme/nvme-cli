// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * NVM-Express command line utility.
 *
 * Copyright (c) 2014-2015, Intel Corporation.
 *
 * Authors: Keith Busch <kbusch@kernel.org>
 *          Daniel Wagner <dwagner@suse.de>
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

#include "malloc.h"

static const char nvme_version_string[] = NVME_VERSION;

struct plugin builtin = {
	.name = NULL,
	.desc = NULL,
	.next = NULL,
	.tail = &builtin,
};

static struct program nvme = {
	.name = "nvme",
	.version = nvme_version_string,
	.usage = "<command> [<device>] [<args>]",
	.desc = "The '<device>' may be either an NVMe controller "
		"device (ex: /dev/nvme0), an nvme namespace device "
		"(ex: /dev/nvme0n1), or a mctp address in the form "
		"mctp:<net>,<eid>[:ctrl-id]",
	.extensions = &builtin,
};

static const char *raw_identify = "show identify in binary format";

int __id_ctrl(int argc, char **argv, struct command *acmd, struct plugin *plugin,
		void (*vs)(__u8 *vs, struct json_object *root))
{
	const char *desc = "Send an Identify Controller command to "
		"the given device and report information about the specified "
		"controller in human-readable or "
		"binary format. May also return vendor-specific "
		"controller attributes in hex-dump if requested.";
	const char *vendor_specific = "dump binary vendor field";

	__cleanup_libnvme_free struct nvme_id_ctrl *ctrl = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	struct libnvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	int err;

	struct config {
		bool	vendor_specific;
		bool	raw_binary;
	};

	struct config cfg = {
		.vendor_specific	= false,
		.raw_binary		= false,
	};

	NVME_ARGS(opts,
		  OPT_FLAG("vendor-specific", 'V', &cfg.vendor_specific, vendor_specific),
		  OPT_FLAG("raw-binary",      'b', &cfg.raw_binary,      raw_identify));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.raw_binary)
		flags = BINARY;

	if (cfg.vendor_specific)
		flags |= VS;

	if (nvme_args.verbose)
		flags |= VERBOSE;

	ctrl = libnvme_alloc(sizeof(*ctrl));
	if (!ctrl)
		return -ENOMEM;

	nvme_init_identify_ctrl(&cmd, ctrl);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "identify controller");
		return err;
	}

	nvme_show_id_ctrl(ctx, hdl, ctrl, flags, vs);

	return err;
}

void register_extension(struct plugin *plugin)
{
	plugin->parent = &nvme;
	nvme.extensions->tail->next = plugin;
	nvme.extensions->tail = plugin;
}

int main(int argc, char **argv)
{
	int err;

#ifdef _WIN32
	/*
	 * Set stdout and stderr to binary mode to prevent Windows text-mode
	 * translation from converting LF to CRLF and corrupting binary output.
	 */
	_setmode(_fileno(stdout), O_BINARY);
	_setmode(_fileno(stderr), O_BINARY);
#endif

	nvme.extensions->parent = &nvme;
	if (argc < 2) {
		general_help(&builtin, NULL);
		return 0;
	}
	setlocale(LC_ALL, "");

	err = nvme_load_global_config();
	if (err)
		return err;

	err = shr_install_sigint_handler();
	if (err)
		return err;

	err = handle_plugin(argc, argv, nvme.extensions);
	if (err == -ENOTTY)
		general_help(&builtin, NULL);

	nvme_show_finish();

	return err ? 1 : 0;
}
