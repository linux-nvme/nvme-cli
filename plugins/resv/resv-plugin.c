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

#include <libnvme.h>

#include <cleanup.h>

#include "argconfig.h"
#include "global-ctx.h"
#include "nvme-cmds.h"
#include "nvme-print.h"
#include "plugin.h"

#define CREATE_CMD
#include "resv-plugin.h"

static const char *crkey = "current reservation key";
static const char *iekey = "ignore existing res. key";
static const char *namespace_desired = "desired namespace";
static const char *raw_dump = "dump output in binary format";
static const char *rtype = "reservation type";

static int resv_acquire(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Obtain a reservation on a given\n"
		"namespace. Only one reservation is allowed at a time on a\n"
		"given namespace, though multiple controllers may register\n"
		"with that namespace. Namespace reservation will abort with\n"
		"status Reservation Conflict if the given namespace is already reserved.";
	const char *prkey = "pre-empt reservation key";
	const char *racqa = "reservation acquire action";

	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	struct libnvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	__le64 payload[2];
	int err;

	struct config {
		__u32	namespace_id;
		__u64	crkey;
		__u64	prkey;
		__u8	rtype;
		__u8	racqa;
		bool	iekey;
	};

	struct config cfg = {
		.namespace_id	= 0,
		.crkey		= 0,
		.prkey		= 0,
		.rtype		= 0,
		.racqa		= 0,
		.iekey		= false,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id_desired),
		  OPT_SUFFIX("crkey",      'c', &cfg.crkey,        crkey),
		  OPT_SUFFIX("prkey",      'p', &cfg.prkey,        prkey),
		  OPT_BYTE("rtype",        't', &cfg.rtype,        rtype),
		  OPT_BYTE("racqa",        'a', &cfg.racqa,        racqa),
		  OPT_FLAG("iekey",        'i', &cfg.iekey,        iekey));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (!cfg.namespace_id) {
		err = libnvme_get_nsid(hdl, &cfg.namespace_id);
		if (err < 0) {
			nvme_show_error("get-namespace-id: %s", libnvme_strerror(-err));
			return err;
		}
	}
	if (cfg.racqa > 7) {
		nvme_show_error("invalid racqa:%d", cfg.racqa);
		return -EINVAL;
	}

	nvme_init_resv_acquire(&cmd, cfg.namespace_id, cfg.racqa, cfg.iekey,
			       false, cfg.rtype, cfg.crkey, cfg.prkey, payload);
	err = libnvme_exec_io_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "reservation acquire");
		return err;
	}

	nvme_show_verbose_result("NVME Reservation Acquire success");

	return err;
}

static int resv_register(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Register, de-register, or\n"
		"replace a controller's reservation on a given namespace.\n"
		"Only one reservation at a time is allowed on any namespace.";
	const char *nrkey = "new reservation key";
	const char *rrega = "reservation registration action";
	const char *cptpl = "change persistence through power loss setting";

	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	struct libnvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	__le64 payload[2];
	int err;

	struct config {
		__u32	namespace_id;
		__u64	crkey;
		__u64	nrkey;
		__u8	rrega;
		__u8	cptpl;
		bool	iekey;
	};

	struct config cfg = {
		.namespace_id	= 0,
		.crkey		= 0,
		.nrkey		= 0,
		.rrega		= 0,
		.cptpl		= false,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id_desired),
		  OPT_SUFFIX("crkey",      'c', &cfg.crkey,        crkey),
		  OPT_SUFFIX("nrkey",      'k', &cfg.nrkey,        nrkey),
		  OPT_BYTE("rrega",        'r', &cfg.rrega,        rrega),
		  OPT_BYTE("cptpl",        'p', &cfg.cptpl,        cptpl),
		  OPT_FLAG("iekey",        'i', &cfg.iekey,        iekey));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (!cfg.namespace_id) {
		err = libnvme_get_nsid(hdl, &cfg.namespace_id);
		if (err < 0) {
			nvme_show_error("get-namespace-id: %s", libnvme_strerror(-err));
			return err;
		}
	}
	if (cfg.cptpl > 3) {
		nvme_show_error("invalid cptpl:%d", cfg.cptpl);
		return -EINVAL;
	}

	if (cfg.rrega > 7) {
		nvme_show_error("invalid rrega:%d", cfg.rrega);
		return -EINVAL;
	}

	nvme_init_resv_register(&cmd, cfg.namespace_id, cfg.rrega, cfg.iekey,
				false, cfg.cptpl, cfg.crkey, cfg.nrkey,
				payload);
	err = libnvme_exec_io_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "reservation register");
		return err;
	}

	nvme_show_verbose_result("NVME Reservation success");

	return err;
}

static int resv_release(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Releases reservation held on a\n"
		"namespace by the given controller. If rtype != current reservation\n"
		"type, release will fails. If the given controller holds no\n"
		"reservation on the namespace or is not the namespace's current\n"
		"reservation holder, the release command completes with no\n"
		"effect. If the reservation type is not Write Exclusive or\n"
		"Exclusive Access, all registrants on the namespace except\n"
		"the issuing controller are notified.";
	const char *rrela = "reservation release action";

	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	struct libnvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	__le64 payload[1];
	int err;

	struct config {
		__u32	nsid;
		__u64	crkey;
		__u8	rtype;
		__u8	rrela;
		__u8	iekey;
	};

	struct config cfg = {
		.nsid		= 0,
		.crkey		= 0,
		.rtype		= 0,
		.rrela		= 0,
		.iekey		= 0,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id", 'n', &cfg.nsid,		namespace_desired),
		  OPT_SUFFIX("crkey",      'c', &cfg.crkey,     crkey),
		  OPT_BYTE("rtype",        't', &cfg.rtype,     rtype),
		  OPT_BYTE("rrela",        'a', &cfg.rrela,     rrela),
		  OPT_FLAG("iekey",        'i', &cfg.iekey,     iekey));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (!cfg.nsid) {
		err = libnvme_get_nsid(hdl, &cfg.nsid);
		if (err < 0) {
			nvme_show_error("get-namespace-id: %s", libnvme_strerror(-err));
			return err;
		}
	}
	if (cfg.rrela > 7) {
		nvme_show_error("invalid rrela:%d", cfg.rrela);
		return -EINVAL;
	}

	nvme_init_resv_release(&cmd, cfg.nsid, cfg.rrela, cfg.iekey, false,
		cfg.rtype, cfg.crkey, payload);
	err = libnvme_exec_io_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "reservation release");
		return err;
	}

	nvme_show_verbose_result("NVME Reservation Release success");

	return err;
}

static int resv_report(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Returns Reservation Status data\n"
		"structure describing any existing reservations on and the\n"
		"status of a given namespace. Namespace Reservation Status\n"
		"depends on the number of controllers registered for that namespace.";
	const char *numd = "number of dwords to transfer";
	const char *eds = "request extended data structure";

	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_libnvme_free struct nvme_resv_status *status = NULL;
	__cleanup_libnvme_free struct nvme_id_ctrl *ctrl = NULL;
	struct libnvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	int err, size;

	struct config {
		__u32	nsid;
		__u32	numd;
		__u8	eds;
		bool	raw_binary;
	};

	struct config cfg = {
		.nsid		= 0,
		.numd		= 0,
		.eds		= false,
		.raw_binary	= false,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id",  'n', &cfg.nsid,		  namespace_id_desired),
		  OPT_UINT("numd",          'd', &cfg.numd,       numd),
		  OPT_FLAG("eds",           'e', &cfg.eds,        eds),
		  OPT_FLAG("raw-binary",    'b', &cfg.raw_binary, raw_dump));

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

	if (!cfg.nsid) {
		err = libnvme_get_nsid(hdl, &cfg.nsid);
		if (err < 0) {
			nvme_show_error("get-namespace-id: %s", libnvme_strerror(-err));
			return err;
		}
	}

	if (!cfg.numd || cfg.numd >= (0x1000 >> 2))
		cfg.numd = (0x1000 >> 2) - 1;
	if (cfg.numd < 3)
		cfg.numd = 3;

	size = (cfg.numd + 1) << 2;

	ctrl = libnvme_alloc(sizeof(*ctrl));
	if (!ctrl)
		return -ENOMEM;

	nvme_init_identify_ctrl(&cmd, ctrl);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_error("identify-ctrl: %s", libnvme_strerror(err));
		return -errno;
	}

	if (ctrl->ctratt & NVME_CTRL_CTRATT_128_ID)
		cfg.eds = true;

	status = libnvme_alloc(size);
	if (!status)
		return -ENOMEM;

	nvme_init_resv_report(&cmd, cfg.nsid, cfg.eds, false, status, size);
	err = libnvme_exec_io_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "reservation report");
		return err;
	}

	nvme_show_resv_report(status, size, cfg.eds, flags);

	return err;
}
