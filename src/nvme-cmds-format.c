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

#include <cleanup.h>
#include <shared/compiler-attributes-util.h>
#include <shared/fs-util.h>
#include <shared/mmio-util.h>
#include <shared/parse-util.h>
#include <shared/sig-util.h>
#include <shared/suffix-util.h>
#include <shared/time-util.h>

#include "argconfig.h"
#include "fabrics.h"
#include "global-config.h"
#include "global-ctx.h"
#include "logging.h"
#include "nvme-cmds.h"
#include "nvme-print.h"
#include "nvme-regs.h"
#include "plugin.h"
#include "nvme-cmds-common.h"

static const char *ish = "Ignore Shutdown (for NVMe-MI command)";

static void show_relatives(const char *name, nvme_print_flags_t flags)
{
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	int err;

	err = nvme_create_global_ctx(&ctx);
	if (err)
		return;

	err = libnvme_scan_topology(ctx, NULL, NULL);
	if (err < 0) {
		handle_scan_topology_error(err);
		return;
	}

	nvme_show_relatives(ctx, name, flags);
}

static int format_cmd(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Re-format a specified namespace on the\n"
		"given device. Can erase all data in namespace (user\n"
		"data erase) or delete data encryption key if specified.\n"
		"Can also be used to change LBAF to change the namespaces reported physical block format.";
	const char *lbaf = "LBA format to apply (required)";
	const char *ses = "[0-2]: secure erase";
	const char *pil = "[0-1]: protection info location last/first bytes of metadata";
	const char *pi = "[0-3]: protection info off/Type 1/Type 2/Type 3";
	const char *mset = "[0-1]: extended format off/on";
	const char *reset = "Automatically reset the controller after successful format";
	const char *bs = "target block size";
	const char *force = "The \"I know what I'm doing\" flag, skip confirmation before sending command";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_libnvme_free struct nvme_id_ctrl *ctrl = NULL;
	__cleanup_libnvme_free struct nvme_id_ns *ns = NULL;
	nvme_print_flags_t flags = NORMAL;
	struct libnvme_passthru_cmd cmd;
	__u8 prev_lbaf = 0;
	int block_size;
	int err, i;

	struct config {
		bool	ish;
		__u32	namespace_id;
		__u8	lbaf;
		__u8	ses;
		__u8	pi;
		__u8	pil;
		__u8	mset;
		bool	reset;
		bool	force;
		__u64	bs;
	};

	struct config cfg = {
		.ish		= false,
		.namespace_id	= 0,
		.lbaf		= 0xff,
		.ses		= 0,
		.pi		= 0,
		.pil		= 0,
		.mset		= 0,
		.reset		= false,
		.force		= false,
		.bs		= 0,
	};

	NVME_ARGS(opts,
		  OPT_FLAG("ish",         'I', &cfg.ish,          ish),
		  OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id_desired),
		  OPT_BYTE("lbaf",         'l', &cfg.lbaf,         lbaf),
		  OPT_BYTE("ses",          's', &cfg.ses,          ses),
		  OPT_BYTE("pi",           'i', &cfg.pi,           pi),
		  OPT_BYTE("pil",          'p', &cfg.pil,          pil),
		  OPT_BYTE("ms",           'm', &cfg.mset,         mset),
		  OPT_FLAG("reset",        'r', &cfg.reset,        reset),
		  OPT_FLAG("force",          0, &cfg.force,        force),
		  OPT_SUFFIX("block-size", 'b', &cfg.bs,           bs));

	/* set default timeout for format to 60 seconds */
	nvme_args.timeout = 600000;

	err = parse_args(argc, argv, desc, opts);
	if (err)
		return err;

	err = open_exclusive(&ctx, &hdl, argc, argv, cfg.force, opts);
	if (err) {
		if (-err == EBUSY) {
			nvme_show_error("Failed to open %s.", basename(argv[optind]));
			nvme_show_error("Namespace is currently busy.");
			if (!cfg.force)
				nvme_show_error("Use the force [--force] option to ignore that.");
		} else {
			argconfig_print_help(desc, opts);
		}
		return err;
	}

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.lbaf != 0xff && cfg.bs != 0) {
		nvme_show_error(
		    "Invalid specification of both LBAF and Block Size, please specify only one");
		return -EINVAL;
	}
	if (cfg.bs) {
		if ((cfg.bs & (~cfg.bs + 1)) != cfg.bs) {
			nvme_show_error(
			    "Invalid value for block size (%"PRIu64"), must be a power of two",
			    (uint64_t) cfg.bs);
			return -EINVAL;
		}
	}

	ctrl = libnvme_alloc(sizeof(*ctrl));
	if (!ctrl)
		return -ENOMEM;

	nvme_init_identify_ctrl(&cmd, ctrl);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_error("identify-ctrl: %s", libnvme_strerror(err));
		return -errno;
	}

	if (ctrl->fna & NVME_CTRL_FNA_FMT_ALL_NAMESPACES) {
		/*
		 * FNA bit 0 set to 1: all namespaces ... shall be configured with the same
		 * attributes and a format (excluding secure erase) of any namespace results in a
		 * format of all namespaces.
		 */
		cfg.namespace_id = NVME_NSID_ALL;
	} else if (!cfg.namespace_id) {
		err = libnvme_get_nsid(hdl, &cfg.namespace_id);
		if (err < 0) {
			nvme_show_error("get-namespace-id: %s", libnvme_strerror(-err));
			return -errno;
		}
	}

	if (cfg.namespace_id == 0) {
		nvme_show_error(
		    "Invalid namespace ID, specify a namespace to format or use\n"
		    "'-n 0xffffffff' to format all namespaces on this controller.");
		return -EINVAL;
	}

	if (cfg.namespace_id != NVME_NSID_ALL) {
		ns = libnvme_alloc(sizeof(*ns));
		if (!ns)
			return -ENOMEM;

		nvme_init_identify_ns(&cmd, cfg.namespace_id, ns);
		err = libnvme_exec_admin_passthru(hdl, &cmd);
		if (err) {
			if (err > 0)
				nvme_show_error("identify failed");
			nvme_show_err(err, "identify-namespace");
			return err;
		}

		nvme_id_ns_flbas_to_lbaf_inuse(ns->flbas, &prev_lbaf);

		if (cfg.bs) {
			for (i = 0; i <= ns->nlbaf; ++i) {
				if ((1ULL << ns->lbaf[i].ds) == cfg.bs && ns->lbaf[i].ms == 0) {
					cfg.lbaf = i;
					break;
				}
			}
			if (cfg.lbaf == 0xff) {
				nvme_show_error(
				    "LBAF corresponding to given block size %"PRIu64" not found",
				    (uint64_t)cfg.bs);
				nvme_show_error(
					"Please correct block size, or specify LBAF directly");
				return -EINVAL;
			}
		} else  if (cfg.lbaf == 0xff) {
			cfg.lbaf = prev_lbaf;
		}
	} else {
		if (cfg.lbaf == 0xff)
			cfg.lbaf = 0;
	}

	/* ses & pi checks set to 7 for forward-compatibility */
	if (cfg.ses > 7) {
		nvme_show_error("invalid secure erase settings:%d", cfg.ses);
		return -EINVAL;
	}
	if (cfg.lbaf > 63) {
		nvme_show_error("invalid lbaf:%d", cfg.lbaf);
		return -EINVAL;
	}
	if (cfg.pi > 7) {
		nvme_show_error("invalid pi:%d", cfg.pi);
		return -EINVAL;
	}
	if (cfg.pil > 1) {
		nvme_show_error("invalid pil:%d", cfg.pil);
		return -EINVAL;
	}
	if (cfg.mset > 1) {
		nvme_show_error("invalid mset:%d", cfg.mset);
		return -EINVAL;
	}

	if (!cfg.force) {
		nvme_show_error("You are about to format %s, namespace %#x%s.",
			libnvme_transport_handle_get_name(hdl), cfg.namespace_id,
			cfg.namespace_id == NVME_NSID_ALL ? "(ALL namespaces)" : "");
		show_relatives(libnvme_transport_handle_get_name(hdl), flags);
		nvme_show_error(
			"WARNING: Format may irrevocably delete this device's data.\n"
			"You have 10 seconds to press Ctrl-C to cancel this operation.\n\n"
			"Use the force [--force] option to suppress this warning.");
		shr_sigint_received = false;
		sleep(10);
		if (shr_sigint_received)
			return -EINTR;
		nvme_show_verbose_info("Sending format operation ...");
	}

	nvme_init_format_nvm(&cmd, cfg.namespace_id, cfg.lbaf, cfg.mset,
		cfg.pi, cfg.pil, cfg.ses);
	if (cfg.ish) {
		if (libnvme_transport_handle_is_mi(hdl))
			nvme_init_mi_cmd_flags(&cmd, ish);
		else
			nvme_show_error("ISH is supported only for NVMe-MI");
	}
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "format");
		return err;
	}

	nvme_show_verbose_result("Success formatting namespace:%x", cfg.namespace_id);
	if (libnvme_transport_handle_is_direct(hdl) && cfg.lbaf != prev_lbaf) {
		if (libnvme_transport_handle_is_ctrl(hdl)) {
			if (libnvme_rescan_ns(hdl) < 0) {
				nvme_show_error("failed to rescan namespaces");
				return -errno;
			}
		} else if (cfg.namespace_id != NVME_NSID_ALL) {
			block_size = 1 << ns->lbaf[cfg.lbaf].ds;

			/*
			 * If block size has been changed by the format
			 * command up there, we should notify it to
			 * kernel blkdev to update its own block size
			 * to the given one because blkdev will not
			 * update by itself without re-opening fd.
			 */
			err = libnvme_update_block_size(hdl, block_size);
			if (err < 0) {
				nvme_show_error(
				    "failed to set block size to %d",
				    block_size);
				return err;
			}
		}
	}
	if (libnvme_transport_handle_is_direct(hdl) && cfg.reset &&
	    libnvme_transport_handle_is_ctrl(hdl))
		libnvme_reset_ctrl(hdl);

	return err;
}

static struct command format_cmd_cmd = {
	.name = "format",
	.help = "Format namespace with new block format",
	.fn = format_cmd,
};

static struct command *commands[] = {
	&format_cmd_cmd,
	NULL,
};

static void __shr_constructor register_group(void)
{
	plugin_add_group(&builtin, "Format", commands);
}
