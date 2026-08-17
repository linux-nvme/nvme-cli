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
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <libnvme.h>

#include <shared/compiler-attributes-util.h>
#include <shared/fs-util.h>

#include "argconfig.h"
#include "cleanup.h"
#include "global-ctx.h"
#include "nvme-print.h"
#include "plugin.h"

static const char *ish = "Ignore Shutdown (for NVMe-MI command)";
static const char *namespace_desired = "desired namespace";
static const char *nssf = "NVMe Security Specific Field";
static const char *raw_dump = "dump output in binary format";
static const char *secp = "security protocol (cf. SPC-4)";
static const char *spsp = "security-protocol-specific (cf. SPC-4)";

static int sec_send(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	struct stat sb;
	const char *desc = "Transfer security protocol data to\n"
		"a controller. Security Receives for the same protocol should be\n"
		"performed after Security Sends. The security protocol field\n"
		"associates Security Sends (security-send) and Security Receives (security-recv).";
	const char *file = "transfer payload";
	const char *tl = "transfer length (cf. SPC-4)";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	struct libnvme_passthru_cmd cmd;
	__cleanup_libnvme_free void *sec_buf = NULL;
	__cleanup_fd int sec_fd = -1;
	unsigned int sec_size;
	int err;
	nvme_print_flags_t flags;

	struct config {
		bool	ish;
		__u32	namespace_id;
		char	*file;
		__u8	nssf;
		__u8	secp;
		__u16	spsp;
		__u32	tl;
	};

	struct config cfg = {
		.ish		= false,
		.namespace_id	= 0,
		.file		= "",
		.nssf		= 0,
		.secp		= 0,
		.spsp		= 0,
		.tl		= 0,
	};

	NVME_ARGS(opts,
		  OPT_FLAG("ish",          'I', &cfg.ish,          ish),
		  OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_desired),
		  OPT_FILE("file",         'f', &cfg.file,         file),
		  OPT_BYTE("nssf",         'N', &cfg.nssf,         nssf),
		  OPT_BYTE("secp",         'p', &cfg.secp,         secp),
		  OPT_SHRT("spsp",         's', &cfg.spsp,         spsp),
		  OPT_UINT("tl",           't', &cfg.tl,           tl));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.tl == 0) {
		nvme_show_error("--tl unspecified or zero");
		return -EINVAL;
	}
	if ((cfg.tl & 3) != 0)
		nvme_show_error(
		    "WARNING: --tl not dword aligned; unaligned bytes may be truncated");

	if (strlen(cfg.file) == 0) {
		sec_fd = STDIN_FILENO;
		sec_size = cfg.tl;
	} else {
		sec_fd = shr_open_rawdata(cfg.file, O_RDONLY);
		if (sec_fd < 0) {
			nvme_show_error("Failed to open %s: %s", cfg.file, libnvme_strerror(errno));
			return -EINVAL;
		}

		err = fstat(sec_fd, &sb);
		if (err < 0) {
			nvme_show_perror("fstat");
			return -errno;
		}

		if (sb.st_size < cfg.tl) {
			nvme_show_error("Security payload file %s is smaller than --tl (%u bytes)",
					cfg.file, cfg.tl);
			return -EINVAL;
		}

		sec_size = cfg.tl;
	}

	sec_buf = libnvme_alloc(sec_size);
	if (!sec_buf)
		return -ENOMEM;

	err = read(sec_fd, sec_buf, sec_size);
	if (err < 0) {
		nvme_show_error("Failed to read data from security file %s with %s", cfg.file,
				libnvme_strerror(errno));
		return -errno;
	}
	if ((unsigned int)err != sec_size) {
		nvme_show_error("Short read from %s (got %d bytes, expected %u)", cfg.file, err, sec_size);
		return -EIO;
	}

	nvme_init_security_send(&cmd, cfg.namespace_id, cfg.nssf, cfg.spsp,
		cfg.secp, cfg.tl, sec_buf, cfg.tl);
	if (cfg.ish) {
		if (libnvme_transport_handle_is_mi(hdl))
			nvme_init_mi_cmd_flags(&cmd, ish);
		else
			nvme_show_error("ISH is supported only for NVMe-MI");
	}
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "security-send");
		return err;
	}

	nvme_show_verbose_result("NVME Security Send Command Success");

	return err;
}

static int sec_recv(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Obtain results of one or more\n"
		"previously submitted security-sends. Results, and association\n"
		"between Security Send and Receive, depend on the security\n"
		"protocol field as they are defined by the security protocol\n"
		"used. A Security Receive must follow a Security Send made with\n"
		"the same security protocol.";
	const char *size = "size of buffer (prints to stdout on success)";
	const char *al = "allocation length (cf. SPC-4)";

	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_libnvme_free void *sec_buf = NULL;
	struct libnvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	int err;

	struct config {
		bool	ish;
		__u32	namespace_id;
		__u32	size;
		__u8	nssf;
		__u8	secp;
		__u16	spsp;
		__u32	al;
		bool	raw_binary;
	};

	struct config cfg = {
		.ish		= false,
		.namespace_id	= 0,
		.size		= 0,
		.nssf		= 0,
		.secp		= 0,
		.spsp		= 0,
		.al		= 0,
		.raw_binary	= false,
	};

	NVME_ARGS(opts,
		  OPT_FLAG("ish",          'I', &cfg.ish,          ish),
		  OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_desired),
		  OPT_UINT("size",         'x', &cfg.size,         size),
		  OPT_BYTE("nssf",         'N', &cfg.nssf,         nssf),
		  OPT_BYTE("secp",         'p', &cfg.secp,         secp),
		  OPT_SHRT("spsp",         's', &cfg.spsp,         spsp),
		  OPT_UINT("al",           't', &cfg.al,           al),
		  OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,   raw_dump));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.size) {
		sec_buf = libnvme_alloc(cfg.size);
		if (!sec_buf)
			return -ENOMEM;
	}

	if (cfg.ish) {
		if (libnvme_transport_handle_is_mi(hdl))
			nvme_init_mi_cmd_flags(&cmd, ish);
		else
			nvme_show_error("ISH is supported only for NVMe-MI");
	}

	nvme_init_security_receive(&cmd, cfg.namespace_id, cfg.nssf, cfg.spsp,
				   cfg.secp, cfg.al, sec_buf, cfg.size);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "security receive");
		return err;
	}

	nvme_show_verbose_result("NVME Security Receive Command Success");
	if (!cfg.raw_binary)
		d(sec_buf, cfg.size, 16, 1);
	else if (cfg.size)
		d_raw((unsigned char *)sec_buf, cfg.size);

	return err;
}

static struct command sec_send_cmd = {
	.name = "send",
	.help = "Submit a Security Send command, return results",
	.fn = sec_send,
};

static struct command sec_recv_cmd = {
	.name = "recv",
	.help = "Submit a Security Receive command, return results",
	.fn = sec_recv,
};

static struct command *commands[] = {
	&sec_send_cmd,
	&sec_recv_cmd,
	NULL,
};

static struct plugin plugin = {
	.name = "security",
	.desc = "Submit NVMe Security Send/Receive commands",
	.version = NVME_VERSION,
	.core = true,
	.group = "Security & Access Control",
};

static void __shr_constructor register_plugin(void)
{
	plugin_add_group(&plugin, NULL, commands);
	register_extension(&plugin);
}
