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

static const char *latency = "output latency statistics";
static const char *namespace_desired = "desired namespace";
static const char *raw_dump = "dump output in binary format";

static void passthru_print_read_output(struct passthru_config cfg, void *data, int dfd, void *mdata,
				       int mfd, int err)
{
	if (strlen(cfg.input_file)) {
		if (write(dfd, (void *)data, cfg.data_len) < 0)
			perror("failed to write data buffer");
	} else if (data) {
		if (cfg.raw_binary)
			d_raw((unsigned char *)data, cfg.data_len);
		else if (!err)
			d((unsigned char *)data, cfg.data_len, 16, 1);
	}
	if (cfg.metadata_len && cfg.metadata) {
		if (strlen(cfg.metadata)) {
			if (write(mfd, (void *)mdata, cfg.metadata_len) < 0)
				perror("failed to write metadata buffer");
		} else {
			if (cfg.raw_binary)
				d_raw((unsigned char *)mdata, cfg.metadata_len);
			else if (!err)
				d((unsigned char *)mdata, cfg.metadata_len, 16, 1);
		}
	}
}

static int passthru(int argc, char **argv, bool admin,
		const char *desc, struct command *acmd)
{
	const char *opcode = "opcode (required)";
	const char *cflags = "command flags";
	const char *rsvd = "value for reserved field";
	const char *data_len = "data I/O length (bytes)";
	const char *metadata_len = "metadata seg. length (bytes)";
	const char *metadata = "metadata input or output file";
	const char *cdw2 = "command dword 2 value";
	const char *cdw3 = "command dword 3 value";
	const char *cdw10 = "command dword 10 value";
	const char *cdw11 = "command dword 11 value";
	const char *cdw12 = "command dword 12 value";
	const char *cdw13 = "command dword 13 value";
	const char *cdw14 = "command dword 14 value";
	const char *cdw15 = "command dword 15 value";
	const char *input = "data input or output file";
	const char *show = "print command before sending";
	const char *re = "set dataflow direction to receive";
	const char *wr = "set dataflow direction to send";
	const char *prefill = "prefill buffers with known byte-value, default 0";

	__cleanup_huge struct libnvme_mem_huge mh = { 0, };
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_fd int dfd = -1, mfd = -1;
	int flags = -1;
	int mode = 0644;
	void *data = NULL;
	__cleanup_free void *mdata = NULL;
	int err = 0;
	const char *cmd_name = NULL;
	struct timeval start_time, end_time;
	nvme_print_flags_t flags_t;

	struct passthru_config cfg = {
		.opcode		= 0,
		.flags		= 0,
		.prefill	= 0,
		.rsvd		= 0,
		.namespace_id	= 0,
		.data_len	= 0,
		.metadata_len	= 0,
		.cdw2		= 0,
		.cdw3		= 0,
		.cdw10		= 0,
		.cdw11		= 0,
		.cdw12		= 0,
		.cdw13		= 0,
		.cdw14		= 0,
		.cdw15		= 0,
		.input_file	= "",
		.metadata	= "",
		.raw_binary	= false,
		.show_command	= false,
		.read		= false,
		.write		= false,
		.latency	= false,
	};

	NVME_ARGS(opts,
		  OPT_BYTE("opcode",       'O', &cfg.opcode,       opcode),
		  OPT_BYTE("flags",        'f', &cfg.flags,        cflags),
		  OPT_BYTE("prefill",      'p', &cfg.prefill,      prefill),
		  OPT_SHRT("rsvd",         'R', &cfg.rsvd,         rsvd),
		  OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_desired),
		  OPT_UINT("data-len",     'l', &cfg.data_len,     data_len),
		  OPT_UINT("metadata-len", 'm', &cfg.metadata_len, metadata_len),
		  OPT_UINT("cdw2",         '2', &cfg.cdw2,         cdw2),
		  OPT_UINT("cdw3",         '3', &cfg.cdw3,         cdw3),
		  OPT_UINT("cdw10",        '4', &cfg.cdw10,        cdw10),
		  OPT_UINT("cdw11",        '5', &cfg.cdw11,        cdw11),
		  OPT_UINT("cdw12",        '6', &cfg.cdw12,        cdw12),
		  OPT_UINT("cdw13",        '7', &cfg.cdw13,        cdw13),
		  OPT_UINT("cdw14",        '8', &cfg.cdw14,        cdw14),
		  OPT_UINT("cdw15",        '9', &cfg.cdw15,        cdw15),
		  OPT_FILE("input-file",   'i', &cfg.input_file,   input),
		  OPT_FILE("metadata",     'M', &cfg.metadata,     metadata),
		  OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,   raw_dump),
		  OPT_FLAG("show-command", 's', &cfg.show_command, show),
		  OPT_FLAG("read",         'r', &cfg.read,         re),
		  OPT_FLAG("write",        'w', &cfg.write,        wr),
		  OPT_FLAG("latency",      'T', &cfg.latency,      latency));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags_t);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (!argconfig_parse_seen(opts, "opcode")) {
		nvme_show_error("%s: opcode parameter required", acmd->name);
		return -EINVAL;
	}

	if (cfg.opcode & 0x01) {
		cfg.write = true;
		flags = O_RDONLY;
		dfd = mfd = STDIN_FILENO;
	}

	if (cfg.opcode & 0x02) {
		cfg.read = true;
		flags = O_WRONLY | O_CREAT | O_TRUNC;
		dfd = mfd = STDOUT_FILENO;
	}

	/*
	 * Fallback to user specified data direction in case from opcode
	 * we can't decode direction.
	 */
	if (cfg.write && flags < 0) {
		flags = O_RDONLY;
		dfd = mfd = STDIN_FILENO;
	}

	if (cfg.read && flags < 0) {
		flags = O_WRONLY | O_CREAT | O_TRUNC;
		dfd = mfd = STDOUT_FILENO;
	}
	if (strlen(cfg.input_file)) {
		if (flags < 0) {
			nvme_show_error("input file specified for opcode 0x%x "
				"without a data transfer direction",
					cfg.opcode);
			return -EINVAL;
		}
		dfd = shr_open_rawdata(cfg.input_file, flags, mode);
		if (dfd < 0) {
			nvme_show_perror(cfg.input_file);
			return -EINVAL;
		}
	}

	if (cfg.metadata && strlen(cfg.metadata)) {
		if (flags < 0) {
			nvme_show_error("metadata file specified for opcode 0x%x "
				"without a data transfer direction",
					cfg.opcode);
			return -EINVAL;
		}
		mfd = shr_open_rawdata(cfg.metadata, flags, mode);
		if (mfd < 0) {
			nvme_show_perror(cfg.metadata);
			return -EINVAL;
		}
	}

	if (cfg.metadata_len) {
		mdata = malloc(cfg.metadata_len);
		if (!mdata)
			return -ENOMEM;

		if (cfg.write) {
			if (read(mfd, mdata, cfg.metadata_len) < 0) {
				err = -errno;
				nvme_show_perror("failed to read metadata write buffer");
				return err;
			}
		} else {
			memset(mdata, cfg.prefill, cfg.metadata_len);
		}
	}

	if (cfg.data_len) {
		data = libnvme_alloc_huge(cfg.data_len, &mh);
		if (!data) {
			nvme_show_error("failed to allocate huge memory");
			return -ENOMEM;
		}

		memset(data, cfg.prefill, cfg.data_len);
		if (!cfg.read && !cfg.write) {
			nvme_show_error("data direction not given");
			return -EINVAL;
		} else if (cfg.write) {
			if (read(dfd, data, cfg.data_len) < 0) {
				err = -errno;
				nvme_show_error("failed to read write buffer %s", libnvme_strerror(errno));
				return err;
			}
		}
	}

	if (cfg.show_command || nvme_args.dry_run) {
		nvme_show_result("opcode       : %02x", cfg.opcode);
		nvme_show_result("flags        : %02x", cfg.flags);
		nvme_show_result("rsvd1        : %04x", cfg.rsvd);
		nvme_show_result("nsid         : %08x", cfg.namespace_id);
		nvme_show_result("cdw2         : %08x", cfg.cdw2);
		nvme_show_result("cdw3         : %08x", cfg.cdw3);
		nvme_show_result("data_len     : %08x", cfg.data_len);
		nvme_show_result("metadata_len : %08x", cfg.metadata_len);
		nvme_show_result("addr         : %"PRIx64, (uint64_t)(uintptr_t)data);
		nvme_show_result("metadata     : %"PRIx64, (uint64_t)(uintptr_t)mdata);
		nvme_show_result("cdw10        : %08x", cfg.cdw10);
		nvme_show_result("cdw11        : %08x", cfg.cdw11);
		nvme_show_result("cdw12        : %08x", cfg.cdw12);
		nvme_show_result("cdw13        : %08x", cfg.cdw13);
		nvme_show_result("cdw14        : %08x", cfg.cdw14);
		nvme_show_result("cdw15        : %08x", cfg.cdw15);
		nvme_show_result("timeout_ms   : %08x", nvme_args.timeout);
	}
	if (nvme_args.dry_run)
		return 0;

	gettimeofday(&start_time, NULL);

	struct libnvme_passthru_cmd cmd = {
		.opcode		= cfg.opcode,
		.flags		= cfg.flags,
		.nsid		= cfg.namespace_id,
		.cdw2		= cfg.cdw2,
		.cdw3		= cfg.cdw3,
		.metadata	= (__u64)(uintptr_t)mdata,
		.addr		= (__u64)(uintptr_t)data,
		.metadata_len	= cfg.metadata_len,
		.data_len	= cfg.data_len,
		.cdw10		= cfg.cdw10,
		.cdw11		= cfg.cdw11,
		.cdw12		= cfg.cdw12,
		.cdw13		= cfg.cdw13,
		.cdw14		= cfg.cdw14,
		.cdw15		= cfg.cdw15,
		.timeout_ms 	= nvme_args.timeout,
	};
	if (admin)
		err = libnvme_exec_admin_passthru(hdl, &cmd);
	else
		err = libnvme_exec_io_passthru(hdl, &cmd);

	gettimeofday(&end_time, NULL);
	cmd_name = nvme_cmd_to_string(admin, cfg.opcode);
	if (cfg.latency)
		nvme_show_result("%s Command %s latency: %llu us", admin ? "Admin" : "IO",
		                 strcmp(cmd_name, "Unknown") ? cmd_name : "Vendor Specific",
		                 shr_elapsed_utime(start_time, end_time));

	if (err) {
		nvme_show_err(err, __func__);
		return err;
	}

	nvme_show_verbose_result("%s Command %s is Success and result: 0x%" PRIx64,
				 admin ? "Admin" : "IO",
				 strcmp(cmd_name, "Unknown") ?
				 cmd_name : "Vendor Specific", (uint64_t)cmd.result);
	if (cfg.read)
		passthru_print_read_output(cfg, data, dfd, mdata, mfd, err);

	return err;
}

static int io_passthru(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc =
	    "Send a user-defined IO command to the specified device via IOCTL passthrough, return results.";

	return passthru(argc, argv, false, desc, acmd);
}

static int admin_passthru(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc =
	    "Send a user-defined Admin command to the specified device via IOCTL passthrough, return results.";

	return passthru(argc, argv, true, desc, acmd);
}

static struct command admin_passthru_cmd = {
	.name = "admin-passthru",
	.help = "Submit an arbitrary admin command, return results",
	.fn = admin_passthru,
};

static struct command io_passthru_cmd = {
	.name = "io-passthru",
	.help = "Submit an arbitrary IO command, return results",
	.fn = io_passthru,
};

static struct command *commands[] = {
	&admin_passthru_cmd,
	&io_passthru_cmd,
	NULL,
};

static void __attribute__((constructor)) register_group(void)
{
	plugin_add_group(&builtin, "Passthrough", commands);
}
