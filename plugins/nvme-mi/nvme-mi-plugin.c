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
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <libnvme-mi.h>
#include <libnvme.h>

#include <shared/compiler-attributes-util.h>
#include <shared/fs-util.h>

#include "argconfig.h"
#include "cleanup.h"
#include "global-ctx.h"
#include "nvme-print.h"
#include "plugin.h"

static const char *namespace_desired = "desired namespace";

static int libnvme_mi(int argc, char **argv, __u8 admin_opcode, const char *desc)
{
	const char *opcode = "opcode (required)";
	const char *data_len = "data I/O length (bytes)";
	const char *nmimt = "nvme-mi message type";
	const char *nmd0 = "nvme management dword 0 value";
	const char *nmd1 = "nvme management dword 1 value";
	const char *input = "data input or output file";

	int mode = 0644;
	void *data = NULL;
	int err = 0;
	bool send;
	__cleanup_fd int fd = -1;
	int flags;
	__cleanup_huge struct libnvme_mem_huge mh = { 0, };
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__u32 result;

	struct config {
		__u8 opcode;
		__u32 namespace_id;
		__u32 data_len;
		__u32 nmimt;
		__u32 nmd0;
		__u32 nmd1;
		char *input_file;
	};

	struct config cfg = {
		.opcode = 0,
		.namespace_id = 0,
		.data_len = 0,
		.nmimt = 0,
		.nmd0 = 0,
		.nmd1 = 0,
		.input_file = "",
	};

	NVME_ARGS(opts,
		  OPT_BYTE("opcode", 'O', &cfg.opcode, opcode),
		  OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_desired),
		  OPT_UINT("data-len", 'l', &cfg.data_len, data_len),
		  OPT_UINT("nmimt", 'm', &cfg.nmimt, nmimt),
		  OPT_UINT("nmd0", '0', &cfg.nmd0, nmd0),
		  OPT_UINT("nmd1", '1', &cfg.nmd1, nmd1),
		  OPT_FILE("input-file", 'i', &cfg.input_file, input));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	if (!argconfig_parse_seen(opts, "opcode")) {
		nvme_show_error("%s: opcode parameter required", *argv);
		return -EINVAL;
	}

	if (admin_opcode == nvme_admin_nvme_mi_send) {
		flags = O_RDONLY;
		fd = STDIN_FILENO;
		send = true;
	} else {
		flags = O_WRONLY | O_CREAT | O_TRUNC;
		fd = STDOUT_FILENO;
		send = false;
	}

	if (strlen(cfg.input_file)) {
		fd = shr_open_rawdata(cfg.input_file, flags, mode);
		if (fd < 0) {
			nvme_show_perror(cfg.input_file);
			return -EINVAL;
		}
	}

	if (cfg.data_len) {
		data = libnvme_alloc_huge(cfg.data_len, &mh);
		if (!data) {
			nvme_show_error("failed to allocate huge memory");
			return -ENOMEM;
		}

		if (send) {
			if (read(fd, data, cfg.data_len) < 0) {
				err = -errno;
				nvme_show_error("failed to read write buffer %s", libnvme_strerror(errno));
				return err;
			}
		}
	}

	struct libnvme_passthru_cmd cmd = {
		.opcode		= admin_opcode,
		.nsid		= cfg.namespace_id,
		.cdw10		= cfg.nmimt << 11 | 4,
		.cdw11		= cfg.opcode,
		.cdw12		= cfg.nmd0,
		.cdw13		= cfg.nmd1,
		.addr		= (__u64)(uintptr_t)data,
		.data_len	= cfg.data_len,
	};

	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "nmi_recv");
		return err;
	}

	result = cmd.result;
	nvme_show_verbose_result(
		"%s Command is Success and result: 0x%08x (status: 0x%02x, response: 0x%06x)",
		nvme_cmd_to_string(true, admin_opcode), result,
		result & 0xff, result >> 8);
	if (result & 0xff)
		nvme_show_verbose_result("status: %s",
					 libnvme_mi_status_to_string(result & 0xff));
	if (!send && strlen(cfg.input_file)) {
 		if (write(fd, (void *)data, cfg.data_len) < 0) {
 			err = -errno;
 			nvme_show_perror("write");
 			return err;
 		}
	} else if (data && !send && !err) {
		d((unsigned char *)data, cfg.data_len, 16, 1);
	}

	return err;
}

static int nmi_recv(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc =
	    "Send a NVMe-MI Receive command to the specified device, return results.";

	return libnvme_mi(argc, argv, nvme_admin_nvme_mi_recv, desc);
}

static int nmi_send(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Send a NVMe-MI Send command to the specified device, return results.";

	return libnvme_mi(argc, argv, nvme_admin_nvme_mi_send, desc);
}

static struct command nmi_recv_cmd = {
	.name = "recv",
	.help = "Submit a NVMe-MI Receive command, return results",
	.fn = nmi_recv,
};

static struct command nmi_send_cmd = {
	.name = "send",
	.help = "Submit a NVMe-MI Send command, return results",
	.fn = nmi_send,
};

static struct command *commands[] = {
	&nmi_recv_cmd,
	&nmi_send_cmd,
	NULL,
};

static struct plugin plugin = {
	.name = "nvme-mi",
	.desc = "Submit NVMe-MI commands",
	.version = NVME_VERSION,
	.core = true,
	.group = "Passthrough",
};

static void __shr_constructor register_plugin(void)
{
	plugin_add_group(&plugin, NULL, commands);
	register_extension(&plugin);
}
