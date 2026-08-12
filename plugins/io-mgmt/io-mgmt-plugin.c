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
#include <unistd.h>

#include <libnvme.h>

#include <cleanup.h>
#include <fs-util.h>

#include "argconfig.h"
#include "global-ctx.h"
#include "nvme-print.h"
#include "plugin.h"

#define CREATE_CMD
#include "io-mgmt-plugin.h"

static const char *buf_len = "buffer len (if) data is sent or received";
static const char *mo = "management operation";
static const char *mos = "management operation specific";

static int io_mgmt_send(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "I/O Management Send";
	const char *data = "optional file for data (default stdin)";

	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_fd int dfd = STDIN_FILENO;
	__cleanup_libnvme_free void *buf = NULL;
	struct libnvme_passthru_cmd cmd;
	int err = -1;

	struct config {
		__u32 nsid;
		__u16 mos;
		__u8  mo;
		char  *file;
		__u32 data_len;
	};

	struct config cfg = {
		.mos = 0,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id",  'n', &cfg.nsid,		namespace_id_desired),
		  OPT_SHRT("mos",           's', &cfg.mos,		mos),
		  OPT_BYTE("mo",            'm', &cfg.mo,       mo),
		  OPT_FILE("data",          'd', &cfg.file,     data),
		  OPT_UINT("data-len",      'l', &cfg.data_len, buf_len));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	if (!cfg.nsid) {
		err = libnvme_get_nsid(hdl, &cfg.nsid);
		if (err < 0) {
			nvme_show_err(err, "get-namespace-id");
			return err;
		}
	}

	if (cfg.data_len) {
		buf = libnvme_alloc(cfg.data_len);
		if (!buf)
			return -ENOMEM;
	}

	if (cfg.file) {
		dfd = shr_open_rawdata(cfg.file, O_RDONLY);
		if (dfd < 0) {
			nvme_show_perror(cfg.file);
			return -errno;
		}
	}

	err = read(dfd, buf, cfg.data_len);
	if (err < 0) {
		nvme_show_perror("read");
		return err;
	}

	nvme_init_io_mgmt_send(&cmd, cfg.nsid, cfg.mo, cfg.mos, buf, cfg.data_len);
	err = libnvme_exec_io_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "io-mgmt-send");
		return err;
	}

	nvme_show_verbose_result("io-mgmt-send: Success, mos:%u mo:%u nsid:%d",
				 cfg.mos, cfg.mo, cfg.nsid);

	return err;
}

static int io_mgmt_recv(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "I/O Management Receive";
	const char *data = "optional file for data (default stdout)";

	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_libnvme_free void *buf = NULL;
	struct libnvme_passthru_cmd cmd;
	__cleanup_fd int dfd = -1;
	int err = -1;

	struct config {
		__u16 mos;
		__u8  mo;
		__u32 nsid;
		char  *file;
		__u32 data_len;
	};

	struct config cfg = {
		.mos = 0,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id",  'n', &cfg.nsid,		namespace_id_desired),
		  OPT_SHRT("mos",           's', &cfg.mos,      mos),
		  OPT_BYTE("mo",            'm', &cfg.mo,       mo),
		  OPT_FILE("data",          'd', &cfg.file,     data),
		  OPT_UINT("data-len",      'l', &cfg.data_len, buf_len));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	if (!cfg.nsid) {
		err = libnvme_get_nsid(hdl, &cfg.nsid);
		if (err < 0) {
			nvme_show_err(err, "get-namespace-id");
			return err;
		}
	}

	if (cfg.data_len) {
		buf = libnvme_alloc(cfg.data_len);
		if (!buf)
			return -ENOMEM;
	}

	nvme_init_io_mgmt_recv(&cmd, cfg.nsid, cfg.mo, cfg.mos, buf,
		cfg.data_len);
	err = libnvme_exec_io_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "io-mgmt-recv");
		return err;
	}

	nvme_show_verbose_result("io-mgmt-recv: Success, mos:%u mo:%u nsid:%d",
				 cfg.mos, cfg.mo, cfg.nsid);

	if (cfg.file) {
		dfd = shr_open_rawdata(cfg.file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (dfd < 0) {
			nvme_show_perror(cfg.file);
			return -errno;
		}

		err = write(dfd, buf, cfg.data_len);
		if (err < 0) {
			nvme_show_perror("write");
			return -errno;
		}
	} else {
		d((unsigned char *)buf, cfg.data_len, 16, 1);
	}

	return err;
}
