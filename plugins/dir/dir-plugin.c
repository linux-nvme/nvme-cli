/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file is part of nvme-cli.
 *
 * Copyright (c) 2014-2015, Intel Corporation.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Keith Busch <kbusch@kernel.org>
 *          Daniel Wagner <dwagner@suse.com>
 */

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>

#include <libnvme.h>

#include <shared/compiler-attributes-util.h>
#include <shared/fs-util.h>

#include "argconfig.h"
#include "cleanup.h"
#include "global-ctx.h"
#include "nvme-print.h"
#include "plugin.h"

static const char *buf_len = "buffer len (if) data is sent or received";
static const char *doper = "directive operation";
static const char *dspec_w_dtype = "directive specification associated with directive type";
static const char *dtype = "directive type";
static const char *raw_directive = "show directive in binary format";

static int dir_send(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Set directive parameters of the specified directive type.";
	const char *endir = "directive enable";
	const char *ttype = "target directive type to be enabled/disabled";
	const char *input = "write/send file (default stdin)";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_libnvme_free void *buf = NULL;
	struct libnvme_passthru_cmd cmd;
	__u32 dw12 = 0;
	__cleanup_fd int ffd = STDIN_FILENO;
	int err;

	struct config {
		__u32	namespace_id;
		__u32	data_len;
		__u8	dtype;
		__u8	ttype;
		__u16	dspec;
		__u8	doper;
		__u16	endir;
		bool	raw_binary;
		char	*file;
	};

	struct config cfg = {
		.namespace_id	= 1,
		.data_len	= 0,
		.dtype		= 0,
		.ttype		= 0,
		.dspec		= 0,
		.doper		= 0,
		.endir		= 1,
		.raw_binary	= false,
		.file		= "",
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id",   'n', &cfg.namespace_id,   namespace_id_desired),
		  OPT_UINT("data-len",       'l', &cfg.data_len,       buf_len),
		  OPT_BYTE("dir-type",       'D', &cfg.dtype,          dtype),
		  OPT_BYTE("target-dir",     'T', &cfg.ttype,          ttype),
		  OPT_SHRT("dir-spec",       'S', &cfg.dspec,          dspec_w_dtype),
		  OPT_BYTE("dir-oper",       'O', &cfg.doper,          doper),
		  OPT_SHRT("endir",          'e', &cfg.endir,          endir),
		  OPT_FLAG("raw-binary",     'b', &cfg.raw_binary,     raw_directive),
		  OPT_FILE("input-file",     'i', &cfg.file,           input));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	switch (cfg.dtype) {
	case NVME_DIRECTIVE_DTYPE_IDENTIFY:
		switch (cfg.doper) {
		case NVME_DIRECTIVE_SEND_IDENTIFY_DOPER_ENDIR:
			if (!cfg.ttype) {
				nvme_show_error("target-dir required param\n");
				return -EINVAL;
			}
			dw12 = cfg.ttype << 8 | cfg.endir;
			break;
		default:
			nvme_show_error("invalid directive operations for Identify Directives");
			return -EINVAL;
		}
		break;
	case NVME_DIRECTIVE_DTYPE_STREAMS:
		switch (cfg.doper) {
		case NVME_DIRECTIVE_SEND_STREAMS_DOPER_RELEASE_IDENTIFIER:
		case NVME_DIRECTIVE_SEND_STREAMS_DOPER_RELEASE_RESOURCE:
			break;
		default:
			nvme_show_error("invalid directive operations for Streams Directives");
			return -EINVAL;
		}
		break;
	default:
		nvme_show_error("invalid directive type");
		return -EINVAL;
	}

	if (cfg.data_len) {
		buf = libnvme_alloc(cfg.data_len);
		if (!buf)
			return -ENOMEM;
	}

	if (buf) {
		if (strlen(cfg.file)) {
			ffd = shr_open_rawdata(cfg.file, O_RDONLY);
			if (ffd <= 0) {
				nvme_show_error("Failed to open file %s: %s",
						cfg.file, libnvme_strerror(errno));
				return -EINVAL;
			}
		}
		err = read(ffd, (void *)buf, cfg.data_len);
		if (err < 0) {
			nvme_show_error(
			    "failed to read data buffer from input file %s",
			    libnvme_strerror(errno));
			return -errno;
		}
	}

	nvme_init_directive_send(&cmd, cfg.namespace_id, cfg.doper, cfg.dtype,
		cfg.dspec, buf, cfg.data_len);
	cmd.cdw12 = dw12;
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "dir-send");
		return err;
	}

	nvme_show_result(
	    "%s: type %#x, operation %#x, spec_val %#x, nsid %#x, result %#"
	    PRIx64, __func__, cfg.dtype, cfg.doper, cfg.dspec,
	    cfg.namespace_id, (uint64_t)cmd.result);

	if (buf) {
		if (!cfg.raw_binary)
			d(buf, cfg.data_len, 16, 1);
		else
			d_raw(buf, cfg.data_len);
	}

	return err;
}

static int dir_receive(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Read directive parameters of the specified directive type.";
	const char *nsr = "namespace stream requested";

	nvme_print_flags_t flags = NORMAL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_libnvme_free void *buf = NULL;
	struct libnvme_passthru_cmd cmd;
	__u32 dw12 = 0;
	int err;

	struct config {
		__u32	namespace_id;
		__u32	data_len;
		bool	raw_binary;
		__u8	dtype;
		__u16	dspec;
		__u8	doper;
		__u16	nsr; /* dw12 for NVME_DIR_ST_RCVOP_STATUS */
	};

	struct config cfg = {
		.namespace_id	= 1,
		.data_len	= 0,
		.raw_binary	= false,
		.dtype		= 0,
		.dspec		= 0,
		.doper		= 0,
		.nsr		= 0,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id",   'n', &cfg.namespace_id,   namespace_id_desired),
		  OPT_UINT("data-len",       'l', &cfg.data_len,       buf_len),
		  OPT_FLAG("raw-binary",     'b', &cfg.raw_binary,     raw_directive),
		  OPT_BYTE("dir-type",       'D', &cfg.dtype,          dtype),
		  OPT_SHRT("dir-spec",       'S', &cfg.dspec,          dspec_w_dtype),
		  OPT_BYTE("dir-oper",       'O', &cfg.doper,          doper),
		  OPT_SHRT("req-resource",   'r', &cfg.nsr,            nsr));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	if (nvme_args.verbose)
		flags |= VERBOSE;
	if (cfg.raw_binary)
		flags = BINARY;

	switch (cfg.dtype) {
	case NVME_DIRECTIVE_DTYPE_IDENTIFY:
		switch (cfg.doper) {
		case NVME_DIRECTIVE_RECEIVE_IDENTIFY_DOPER_PARAM:
			if (!cfg.data_len)
				cfg.data_len = 4096;
			break;
		default:
			nvme_show_error("invalid directive operations for Identify Directives");
			return -EINVAL;
		}
		break;
	case NVME_DIRECTIVE_DTYPE_STREAMS:
		switch (cfg.doper) {
		case NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_PARAM:
			if (!cfg.data_len)
				cfg.data_len = 32;
			break;
		case NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_STATUS:
			if (!cfg.data_len)
				cfg.data_len = 128 * 1024;
			break;
		case NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_RESOURCE:
			dw12 = cfg.nsr;
			break;
		default:
			nvme_show_error("invalid directive operations for Streams Directives");
			return -EINVAL;
		}
		break;
	default:
		nvme_show_error("invalid directive type");
		return -EINVAL;
	}

	if (cfg.data_len) {
		buf = libnvme_alloc(cfg.data_len);
		if (!buf)
			return -ENOMEM;
	}

	nvme_init_directive_recv(&cmd, cfg.namespace_id, cfg.doper, cfg.dtype,
		cfg.dspec, buf, cfg.data_len);
	cmd.cdw12 = dw12;
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "dir-receive");
		return err;
	}

	nvme_directive_show(cfg.dtype, cfg.doper, cfg.dspec, cfg.namespace_id,
			    cmd.result, buf, cfg.data_len, flags);

	return err;
}

static struct command dir_receive_cmd = {
	.name = "receive",
	.help = "Submit a Directive Receive command, return results",
	.fn = dir_receive,
};

static struct command dir_send_cmd = {
	.name = "send",
	.help = "Submit a Directive Send command, return results",
	.fn = dir_send,
};

static struct command *commands[] = {
	&dir_receive_cmd,
	&dir_send_cmd,
	NULL,
};

static struct plugin plugin = {
	.name = "dir",
	.desc = "Submit NVMe Directive commands",
	.version = NVME_VERSION,
	.core = true,
	.group = "I/O Commands",
};

static void __shr_constructor register_plugin(void)
{
	plugin_add_group(&plugin, NULL, commands);
	register_extension(&plugin);
}
