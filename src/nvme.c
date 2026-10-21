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
#include "global-config.h"
#include "global-ctx.h"
#include "nvme-print.h"
#include "plugin.h"
#include "privsep.h"

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
	.desc = "Send NVMe Admin and I/O commands, manage NVMe devices, "
		"and configure NVMe-oF fabrics connections.",
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

	OPT_ARGS(opts) = {
		OPT_FLAG("vendor-specific", 'V', &cfg.vendor_specific,
			 vendor_specific),
		OPT_FLAG("raw-binary",      'b', &cfg.raw_binary, raw_identify),
		OPT_END()
	};

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	flags = nvme_args.output_flags;

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

/*
 * plugin_add_group() runs from constructors, before main(), and its
 * allocations live for the whole process. Release them at exit. A
 * destructor, not atexit(), so main() can run more than once in a
 * process, as the fuzz tests do.
 */
static void __shr_destructor free_plugins(void)
{
	struct plugin *plugin;

	for (plugin = nvme.extensions; plugin; plugin = plugin->next) {
		while (plugin->groups) {
			struct command_group *group = plugin->groups;

			plugin->groups = group->next;
			free(group);
		}
		free(plugin->commands);
		plugin->commands = NULL;
	}
}

/*
 * Open /dev/null on the standard descriptors which are closed. Else the
 * next descriptor nvme-cli opens, e.g. the socket to the privsep helper,
 * becomes one of them, and the output goes there.
 */
static int nvme_reserve_stdio(void)
{
#ifndef _WIN32
	int fd, null;

	for (fd = STDIN_FILENO; fd <= STDERR_FILENO; fd++) {
		if (fcntl(fd, F_GETFD) >= 0 || errno != EBADF)
			continue;
		/* the lowest free descriptor, fd */
		null = open("/dev/null", O_RDWR);
		if (null < 0)
			return -errno;
		if (null != fd) {
			close(null);
			return -EBADF;
		}
	}
#endif
	return 0;
}

int nvme_main(int argc, char **argv)
{
	struct plugin_call call = {};
	int err;

	err = nvme_reserve_stdio();
	if (err) {
		fprintf(stderr, "%s: cannot open /dev/null: %s\n", argv[0],
			strerror(-err));
		return 1;
	}

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
	nvme_args_register();

	/* The command line comes first, nvme-cli.conf does not override it */
	err = plugin_lookup(argc, argv, nvme.extensions, &call);
	if (!err && nvme_privsep_init(&call)) {
		plugin_call_free(&call);
		return 1;
	}
	if (!err) {
		setlocale(LC_ALL, "");
		err = nvme_load_global_config();
	}
	if (!err)
		err = shr_install_sigint_handler();
	if (err) {
		plugin_call_free(&call);
		return err;
	}

	err = plugin_call_run(&call);
	plugin_call_free(&call);

	nvme_show_finish();

	/* the command stopped after printing the help it was asked for */
	if (argconfig_help_requested())
		return 0;

	return err ? 1 : 0;
}
