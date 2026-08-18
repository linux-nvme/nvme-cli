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

#include <ccan/array_size/array_size.h>
#include <shared/compiler-attributes-util.h>

#include "argconfig.h"
#include "cleanup.h"
#include "global-ctx.h"
#include "nvme-print.h"
#include "plugin.h"

static const char *lba_format_index = "The index into the LBA Format list\n"
	"identifying the LBA Format capabilities that are to be returned";
static const char *namespace_id_optional = "optional namespace attached to controller";
static const char *raw_identify = "show identify in binary format";

static int list_ctrl(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Show controller list information for the subsystem the "
		"given device is part of, or optionally controllers attached to a specific namespace.";
	const char *controller = "controller to display";

	__cleanup_libnvme_free struct nvme_ctrl_list *cntlist = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	struct libnvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	int err;

	struct config {
		__u16	cntid;
		__u32	namespace_id;
	};

	struct config cfg = {
		.cntid		= 0,
		.namespace_id	= NVME_NSID_NONE,
	};

	NVME_ARGS(opts,
		  OPT_SHRT("cntid",        'c', &cfg.cntid,         controller),
		  OPT_UINT("namespace-id", 'n', &cfg.namespace_id,  namespace_id_optional));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0 || (flags != JSON && flags != NORMAL)) {
		nvme_show_error("Invalid output format");
		return err;
	}

	cntlist = libnvme_alloc(sizeof(*cntlist));
	if (!cntlist)
		return -ENOMEM;

	if (cfg.namespace_id == NVME_NSID_NONE)
		nvme_init_identify_ctrl_list(&cmd, cfg.cntid, cntlist);
	else
		nvme_init_identify_ns_ctrl_list(&cmd, cfg.namespace_id,
						cfg.cntid, cntlist);

	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "id controller list");
		return err;
	}

	nvme_show_list_ctrl(cntlist, flags);

	return err;
}

static int list_ns(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "For the specified controller handle, show the "
		"namespace list in the associated NVMe subsystem, optionally starting with a given nsid.";
	const char *namespace_id = "first nsid returned list should start from";
	const char *csi = "I/O command set identifier";
	const char *all = "show all namespaces in the subsystem, whether attached or inactive";

	__cleanup_libnvme_free struct nvme_ns_list *ns_list = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	struct libnvme_passthru_cmd cmd;
	enum nvme_identify_cns cns;
	nvme_print_flags_t flags;
	int err;

	struct config {
		__u32	namespace_id;
		int	csi;
		bool	all;
	};

	struct config cfg = {
		.namespace_id	= 1,
		.csi		= -1,
		.all		= false,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id", 'n', &cfg.namespace_id,  namespace_id),
		  OPT_INT("csi",           'y', &cfg.csi,           csi),
		  OPT_FLAG("all",          'a', &cfg.all,           all));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0 || (flags != JSON && flags != NORMAL)) {
		nvme_show_error("Invalid output format");
		return -EINVAL;
	}

	if (!cfg.namespace_id) {
		nvme_show_error("invalid nsid parameter");
		return -EINVAL;
	}

	if (nvme_args.verbose)
		flags |= VERBOSE;

	ns_list = libnvme_alloc(sizeof(*ns_list));
	if (!ns_list)
		return -ENOMEM;

	if (cfg.csi < 0) {
		cns = cfg.all ? NVME_IDENTIFY_CNS_ALLOCATED_NS_LIST :
			NVME_IDENTIFY_CNS_NS_ACTIVE_LIST;
		cfg.csi = 0;
	} else 	{
		cns = cfg.all ? NVME_IDENTIFY_CNS_CSI_ALLOCATED_NS_LIST :
			NVME_IDENTIFY_CNS_CSI_NS_ACTIVE_LIST;
	}

	nvme_init_identify(&cmd, cfg.namespace_id - 1, cfg.csi, cns, ns_list,
			    sizeof(*ns_list));
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "id namespace list");
		return err;
	}

	nvme_show_list_ns(ns_list, flags);

	return err;
}

static int id_ns_lba_format(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Send an Identify Namespace command to the given "
		"device, returns capability field properties of the specified "
		"LBA Format index in  various formats.";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_libnvme_free struct nvme_id_ns *ns = NULL;
	struct libnvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	int err = -1;

	struct config {
		__u16	lba_format_index;
		__u8	uuid_index;
	};

	struct config cfg = {
		.lba_format_index	= 0,
		.uuid_index		= NVME_UUID_NONE,
	};

	NVME_ARGS(opts,
		  OPT_UINT("lba-format-index", 'i', &cfg.lba_format_index, lba_format_index),
		  OPT_BYTE("uuid-index",       'U', &cfg.uuid_index,       uuid_index));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (nvme_args.verbose)
		flags |= VERBOSE;

	ns = libnvme_alloc(sizeof(*ns));
	if (!ns)
		return -ENOMEM;

	nvme_init_identify_csi_ns_user_data_format(&cmd, NVME_CSI_NVM,
						   cfg.lba_format_index,
						   cfg.uuid_index, ns);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err,
			      "identify namespace for specific LBA format");
		return err;
	}

	nvme_show_id_ns(ns, 0, cfg.lba_format_index, true, flags);

	return err;
}

static int id_endurance_grp_list(int argc, char **argv, struct command *acmd,
	struct plugin *plugin)
{
	const char *desc = "Show endurance group list information for the given endurance group id";
	const char *endurance_grp_id = "Endurance Group ID";

	__cleanup_libnvme_free struct nvme_id_endurance_group_list *endgrp_list = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	struct libnvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	int err = -1;

	struct config {
		__u16	endgrp_id;
	};

	struct config cfg = {
		.endgrp_id	= 0,
	};

	NVME_ARGS(opts,
		  OPT_SHRT("endgrp-id",    'i', &cfg.endgrp_id,     endurance_grp_id));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0 || (flags != JSON && flags != NORMAL)) {
		nvme_show_error("invalid output format");
		return -EINVAL;
	}

	endgrp_list = libnvme_alloc(sizeof(*endgrp_list));
	if (!endgrp_list)
		return -ENOMEM;

	nvme_init_identify_endurance_group_id(&cmd, cfg.endgrp_id,
					      endgrp_list);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "Id endurance group list");
		return err;
	}

	nvme_show_endurance_group_list(endgrp_list, flags);

	return err;
}

static int id_ctrl(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return __id_ctrl(argc, argv, acmd, plugin, NULL);
}

static int nvm_id_ctrl(int argc, char **argv, struct command *acmd,
	struct plugin *plugin)
{
	const char *desc = "Send an Identify Controller NVM Command Set "
		"command to the given device and report information about "
		"the specified controller in various formats.";

	__cleanup_libnvme_free struct nvme_id_ctrl_nvm *ctrl_nvm = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	struct libnvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	int err = -1;

	NVME_ARGS(opts);

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (nvme_args.verbose)
		flags |= VERBOSE;

	ctrl_nvm = libnvme_alloc(sizeof(*ctrl_nvm));
	if (!ctrl_nvm)
		return -ENOMEM;

	nvme_init_identify_csi_ctrl(&cmd, NVME_CSI_NVM, ctrl_nvm);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "nvm identify controller");
		return err;
	}

	nvme_show_id_ctrl_nvm(ctrl_nvm, flags);

	return err;
}

static int nvm_id_ns(int argc, char **argv, struct command *acmd,
	struct plugin *plugin)
{
	const char *desc = "Send an Identify Namespace NVM Command Set "
		"command to the given device and report information about "
		"the specified namespace in various formats.";

	__cleanup_libnvme_free struct nvme_nvm_id_ns *id_ns = NULL;
	__cleanup_libnvme_free struct nvme_id_ns *ns = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	struct libnvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	int err = -1;

	struct config {
		__u32	namespace_id;
		__u8	uuid_index;
	};

	struct config cfg = {
		.namespace_id	= 0,
		.uuid_index	= NVME_UUID_NONE,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id", 'n', &cfg.namespace_id,    namespace_id_desired),
		  OPT_BYTE("uuid-index",   'U', &cfg.uuid_index,      uuid_index));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (nvme_args.verbose)
		flags |= VERBOSE;

	if (!cfg.namespace_id) {
		err = libnvme_get_nsid(hdl, &cfg.namespace_id);
		if (err < 0) {
			nvme_show_err(err, "get-namespace-id");
			return err;
		}
	}

	ns = libnvme_alloc(sizeof(*ns));
	if (!ns)
		return -ENOMEM;

	nvme_init_identify_ns(&cmd, cfg.namespace_id, ns);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "nvm identify namespace");
		return err;
	}

	id_ns = libnvme_alloc(sizeof(*id_ns));
	if (!id_ns)
		return -ENOMEM;

	nvme_init_identify_csi_ns(&cmd, cfg.namespace_id, NVME_CSI_NVM,
				  cfg.uuid_index, id_ns);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "nvm identify csi namespace");
		return err;
	}

	nvme_show_nvm_id_ns(id_ns, cfg.namespace_id, ns, 0, false, flags);

	return err;
}

static int nvm_id_ns_lba_format(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Send an NVM Command Set specific Identify Namespace "
		"command to the given device, returns capability field properties of "
		"the specified LBA Format index in the specified namespace in various formats.";

	__cleanup_libnvme_free struct nvme_nvm_id_ns *nvm_ns = NULL;
	__cleanup_libnvme_free struct nvme_id_ns *ns = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	struct libnvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	int err = -1;

	struct config {
		__u16	lba_format_index;
		__u8	uuid_index;
	};

	struct config cfg = {
		.lba_format_index	= 0,
		.uuid_index		= NVME_UUID_NONE,
	};

	NVME_ARGS(opts,
		  OPT_UINT("lba-format-index", 'i', &cfg.lba_format_index, lba_format_index),
		  OPT_BYTE("uuid-index",       'U', &cfg.uuid_index,       uuid_index));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (nvme_args.verbose)
		flags |= VERBOSE;

	ns = libnvme_alloc(sizeof(*ns));
	if (!ns)
		return -ENOMEM;

	nvme_init_identify_ns(&cmd, NVME_NSID_ALL, ns);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		ns->nlbaf = NVME_FEAT_LBA_RANGE_MAX - 1;
		ns->nulbaf = 0;
	}

	nvm_ns = libnvme_alloc(sizeof(*nvm_ns));
	if (!nvm_ns)
		return -ENOMEM;

	nvme_init_identify_csi_ns_user_data_format(&cmd, NVME_CSI_NVM,
						   cfg.lba_format_index,
						   cfg.uuid_index, nvm_ns);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err,
		    "NVM identify namespace for specific LBA format");
		return err;
	}

	nvme_show_nvm_id_ns(nvm_ns, 0, ns, cfg.lba_format_index, true, flags);

	return err;
}

static int ns_descs(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Send Namespace Identification Descriptors command to the "
		"given device, returns the namespace identification descriptors "
		"of the specific namespace in either human-readable or binary format.";
	const char *raw = "show descriptors in binary format";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_libnvme_free void *nsdescs = NULL;
	struct libnvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	int err;

	struct config {
		__u32	namespace_id;
		bool	raw_binary;
	};

	struct config cfg = {
		.namespace_id	= 0,
		.raw_binary	= false,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id",  'n', &cfg.namespace_id,  namespace_id_desired),
		  OPT_FLAG("raw-binary",    'b', &cfg.raw_binary,    raw));

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

	if (nvme_args.verbose)
		flags |= VERBOSE;

	if (!cfg.namespace_id) {
		err = libnvme_get_nsid(hdl, &cfg.namespace_id);
		if (err < 0) {
			nvme_show_error("get-namespace-id: %s", libnvme_strerror(-err));
			return err;
		}
	}

	nsdescs = libnvme_alloc(NVME_IDENTIFY_DATA_SIZE);
	if (!nsdescs)
		return -ENOMEM;

	nvme_init_identify_ns_descs_list(&cmd, cfg.namespace_id, nsdescs);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "identify namespace");
		return err;
	}

	nvme_show_id_ns_descs(nsdescs, cfg.namespace_id, flags);

	return err;
}

static int id_ns(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Send an Identify Namespace command to the "
		"given device, returns properties of the specified namespace "
		"in either human-readable or binary format. Can also return "
		"binary vendor-specific namespace attributes.";
	const char *force = "Return this namespace, even if not attached (1.2 devices only)";
	const char *vendor_specific = "dump binary vendor fields";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_libnvme_free struct nvme_id_ns *ns = NULL;
	struct libnvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	int err;

	struct config {
		__u32	namespace_id;
		bool	force;
		bool	vendor_specific;
		bool	raw_binary;
	};

	struct config cfg = {
		.namespace_id		= 0,
		.force			= false,
		.vendor_specific	= false,
		.raw_binary		= false,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id",    'n', &cfg.namespace_id,    namespace_id_desired),
		  OPT_FLAG("force",             0, &cfg.force,           force),
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

	if (!cfg.namespace_id) {
		err = libnvme_get_nsid(hdl, &cfg.namespace_id);
		if (err < 0) {
			nvme_show_error("get-namespace-id: %s", libnvme_strerror(-err));
			return err;
		}
	}

	ns = libnvme_alloc(sizeof(*ns));
	if (!ns)
		return -ENOMEM;

	if (cfg.force) {
		nvme_init_identify_allocated_ns(&cmd, cfg.namespace_id, ns);
		err = libnvme_exec_admin_passthru(hdl, &cmd);
	} else {
		nvme_init_identify_ns(&cmd, cfg.namespace_id, ns);
		err = libnvme_exec_admin_passthru(hdl, &cmd);
	}

	if (err) {
		nvme_show_err(err, "identify namespace");
		return err;
	}

	nvme_show_id_ns(ns, cfg.namespace_id, 0, false, flags);

	return err;
}

static int cmd_set_independent_id_ns(int argc, char **argv, struct command *acmd,
				     struct plugin *plugin)
{
	const char *desc = "Send an I/O Command Set Independent Identify "
		"Namespace command to the given device, returns properties of the "
		"specified namespace in human-readable or binary or json format.";

	__cleanup_libnvme_free struct nvme_id_independent_id_ns *ns = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	struct libnvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	int err = -1;

	struct config {
		__u32	namespace_id;
		bool	raw_binary;
	};

	struct config cfg = {
		.namespace_id	= 0,
		.raw_binary	= false,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id_desired),
		  OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,   raw_identify));

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

	if (nvme_args.verbose)
		flags |= VERBOSE;

	if (!cfg.namespace_id) {
		err = libnvme_get_nsid(hdl, &cfg.namespace_id);
		if (err < 0) {
			nvme_show_err(err, "get-namespace-id");
			return err;
		}
	}

	ns = libnvme_alloc(sizeof(*ns));
	if (!ns)
		return -ENOMEM;

	nvme_init_identify_csi_independent_identify_id_ns(&cmd,
							  cfg.namespace_id, ns);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err,
			      "I/O command set independent identify namespace");
		return err;
	}

	nvme_show_cmd_set_independent_id_ns(ns, cfg.namespace_id, flags);

	return err;
}

static int id_ns_granularity(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Send an Identify Namespace Granularity List command to the "
		"given device, returns namespace granularity list "
		"in either human-readable or binary format.";

	__cleanup_libnvme_free struct nvme_id_ns_granularity_list *granularity_list = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	struct libnvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	int err;

	NVME_ARGS(opts);

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	granularity_list = libnvme_alloc(NVME_IDENTIFY_DATA_SIZE);
	if (!granularity_list)
		return -ENOMEM;

	nvme_init_identify_ns_granularity(&cmd, granularity_list);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "identify namespace granularity");
		return err;
	}

	nvme_show_id_ns_granularity_list(granularity_list, flags);

	return err;
}

static int id_nvmset(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Send an Identify NVM Set List command to the "
		"given device, returns entries for NVM Set identifiers greater "
		"than or equal to the value specified CDW11.NVMSETID "
		"in either binary format or json format";
	const char *nvmset_id = "NVM Set Identify value";

	__cleanup_libnvme_free struct nvme_id_nvmset_list *nvmset = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	struct libnvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	int err;

	struct config {
		__u16	nvmset_id;
	};

	struct config cfg = {
		.nvmset_id	= 0,
	};

	NVME_ARGS(opts,
		  OPT_SHRT("nvmset_id",    'i', &cfg.nvmset_id,     nvmset_id));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	nvmset = libnvme_alloc(sizeof(*nvmset));
	if (!nvmset)
		return -ENOMEM;

	nvme_init_identify_nvmset_list(&cmd, NVME_NSID_NONE,
				       cfg.nvmset_id, nvmset);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "identify nvm set list");
		return err;
	}

	nvme_show_id_nvmset(nvmset, cfg.nvmset_id, flags);

	return err;
}

static int id_uuid(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Send an Identify UUID List command to the "
		"given device, returns list of supported Vendor Specific UUIDs "
		"in either human-readable or binary format.";
	const char *raw = "show uuid in binary format";

	__cleanup_libnvme_free struct nvme_id_uuid_list *uuid_list = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	struct libnvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	int err;

	struct config {
		bool	raw_binary;
	};

	struct config cfg = {
		.raw_binary	= false,
	};

	NVME_ARGS(opts,
		  OPT_FLAG("raw-binary",     'b', &cfg.raw_binary,     raw));

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

	if (nvme_args.verbose)
		flags |= VERBOSE;

	uuid_list = libnvme_alloc(sizeof(*uuid_list));
	if (!uuid_list)
		return -ENOMEM;

	nvme_init_identify_uuid_list(&cmd, uuid_list);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "identify UUID list");
		return err;
	}

	nvme_show_id_uuid_list(uuid_list, flags);

	return err;
}

static int id_iocs(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Send an Identify Command Set Data command to "
		"the given device, returns properties of the specified controller "
		"in either human-readable or binary format.";
	const char *controller_id = "identifier of desired controller";

	__cleanup_libnvme_free struct nvme_id_iocs *iocs = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	struct libnvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	int err;

	struct config {
		__u16	cntid;
	};

	struct config cfg = {
		.cntid	= 0xffff,
	};

	NVME_ARGS(opts,
		  OPT_SHRT("controller-id", 'c', &cfg.cntid, controller_id));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (nvme_args.verbose)
		flags |= VERBOSE;

	iocs = libnvme_alloc(sizeof(*iocs));
	if (!iocs)
		return -ENOMEM;

	nvme_init_identify_command_set_structure(&cmd, cfg.cntid, iocs);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "NVMe Identify I/O Command Set");
		return err;
	}

	nvme_show_result("NVMe Identify I/O Command Set:");
	nvme_show_id_iocs(iocs, flags);

	return err;
}

static int id_domain(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Send an Identify Domain List command to the "
		"given device, returns properties of the specified domain "
		"in either normal|json|binary format.";
	const char *domain_id = "identifier of desired domain";

	__cleanup_libnvme_free struct nvme_id_domain_list *id_domain = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	struct libnvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	int err;

	struct config {
		__u16	dom_id;
	};

	struct config cfg = {
		.dom_id		= 0xffff,
	};

	NVME_ARGS(opts,
		  OPT_SHRT("dom-id",         'd', &cfg.dom_id,         domain_id));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	id_domain = libnvme_alloc(sizeof(*id_domain));
	if (!id_domain)
		return -ENOMEM;

	nvme_init_identify_domain_list(&cmd, cfg.dom_id, id_domain);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "NVMe Identify Domain List");
		return err;
	}

	nvme_show_verbose_result("NVMe Identify command for Domain List is successful:");
	nvme_show_verbose_result("NVMe Identify Domain List:");
	nvme_show_id_domain_list(id_domain, flags);

	return err;
}

static int primary_ctrl_caps(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *cntlid = "Controller ID";
	const char *desc = "Send an Identify Primary Controller Capabilities "
		"command to the given device and report the information in a "
		"decoded format (default), json or binary.";

	__cleanup_libnvme_free struct nvme_primary_ctrl_cap *caps = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	struct libnvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	int err;

	struct config {
		__u16	cntlid;
	};

	struct config cfg = {
		.cntlid		= 0,
	};

	NVME_ARGS(opts,
		  OPT_UINT("cntlid",         'c', &cfg.cntlid, cntlid));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (nvme_args.verbose)
		flags |= VERBOSE;

	caps = libnvme_alloc(sizeof(*caps));
	if (!caps)
		return -ENOMEM;

	nvme_init_identify_primary_ctrl_cap(&cmd, cfg.cntlid, caps);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "identify primary controller capabilities");
		return err;
	}

	nvme_show_primary_ctrl_cap(caps, flags);

	return err;
}

static int list_secondary_ctrl(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc =
	    "Show secondary controller list associated with the primary controller of the given device.";
	const char *controller = "lowest controller identifier to display";
	const char *num_entries = "number of entries to retrieve";

	__cleanup_libnvme_free struct nvme_secondary_ctrl_list *sc_list = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	struct libnvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	int err;

	struct config {
		__u16	cntid;
		__u32	num_entries;
	};

	struct config cfg = {
		.cntid		= 0,
		.num_entries	= ARRAY_SIZE(sc_list->sc_entry),
	};

	NVME_ARGS(opts,
		  OPT_SHRT("cntid",        'c', &cfg.cntid,         controller),
		  OPT_UINT("num-entries",  'e', &cfg.num_entries,   num_entries));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (!cfg.num_entries) {
		nvme_show_error("non-zero num-entries is required param");
		return -EINVAL;
	}

	sc_list = libnvme_alloc(sizeof(*sc_list));
	if (!sc_list)
		return -ENOMEM;

	nvme_init_identify_secondary_ctrl_list(&cmd, cfg.cntid, sc_list);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "id secondary controller list");
		return err;
	}

	nvme_show_list_secondary_ctrl(sc_list, cfg.num_entries, flags);

	return err;
}

static struct command id_ctrl_cmd = {
	.name = "ctrl",
	.help = "Send NVMe Identify Controller",
	.fn = id_ctrl,
};

static struct command id_ns_cmd = {
	.name = "ns",
	.help = "Send NVMe Identify Namespace, display structure",
	.fn = id_ns,
};

static struct command id_ns_granularity_cmd = {
	.name = "ns-granularity",
	.help = "Send NVMe Identify Namespace Granularity List, display structure",
	.fn = id_ns_granularity,
};

static struct command id_ns_lba_format_cmd = {
	.name = "ns-lba-format",
	.help = "Send NVMe Identify Namespace for the specified LBA Format index, "
		"display structure",
	.fn = id_ns_lba_format,
};

static struct command list_ns_cmd = {
	.name = "ns-list",
	.help = "Send NVMe Identify List, display structure",
	.fn = list_ns,
};

static struct command list_ctrl_cmd = {
	.name = "ctrl-list",
	.help = "Send NVMe Identify Controller List, display structure",
	.fn = list_ctrl,
};

static struct command nvm_id_ctrl_cmd = {
	.name = "nvm-ctrl",
	.help = "Send NVMe Identify Controller NVM Command Set, display structure",
	.fn = nvm_id_ctrl,
};

static struct command nvm_id_ns_cmd = {
	.name = "nvm-ns",
	.help = "Send NVMe Identify Namespace NVM Command Set, display structure",
	.fn = nvm_id_ns,
};

static struct command nvm_id_ns_lba_format_cmd = {
	.name = "nvm-ns-lba-format",
	.help = "Send NVMe Identify Namespace NVM Command Set for the specified LBA "
		"Format index, display structure",
	.fn = nvm_id_ns_lba_format,
};

static struct command primary_ctrl_caps_cmd = {
	.name = "primary-ctrl-caps",
	.help = "Send NVMe Identify Primary Controller Capabilities",
	.fn = primary_ctrl_caps,
};

static struct command list_secondary_ctrl_cmd = {
	.name = "secondary-ctrl-list",
	.help = "List Secondary Controllers associated with a Primary Controller",
	.fn = list_secondary_ctrl,
};

static struct command cmd_set_independent_id_ns_cmd = {
	.name = "ns-ind",
	.help = "I/O Command Set Independent Identify Namespace",
	.fn = cmd_set_independent_id_ns,
};

static struct command ns_descs_cmd = {
	.name = "ns-descs",
	.help = "Send NVMe Namespace Descriptor List, display structure",
	.fn = ns_descs,
};

static struct command id_nvmset_cmd = {
	.name = "nvmset",
	.help = "Send NVMe Identify NVM Set List, display structure",
	.fn = id_nvmset,
};

static struct command id_uuid_cmd = {
	.name = "uuid",
	.help = "Send NVMe Identify UUID List, display structure",
	.fn = id_uuid,
};

static struct command id_iocs_cmd = {
	.name = "iocs",
	.help = "Send NVMe Identify I/O Command Set, display structure",
	.fn = id_iocs,
};

static struct command id_domain_cmd = {
	.name = "domain",
	.help = "Send NVMe Identify Domain List, display structure",
	.fn = id_domain,
};

static struct command id_endurance_grp_list_cmd = {
	.name = "endgrp-list",
	.help = "Send NVMe Identify Endurance Group List, display structure",
	.fn = id_endurance_grp_list,
};

static struct command *commands[] = {
	&id_ctrl_cmd,
	&id_ns_cmd,
	&id_ns_granularity_cmd,
	&id_ns_lba_format_cmd,
	&list_ns_cmd,
	&list_ctrl_cmd,
	&nvm_id_ctrl_cmd,
	&nvm_id_ns_cmd,
	&nvm_id_ns_lba_format_cmd,
	&primary_ctrl_caps_cmd,
	&list_secondary_ctrl_cmd,
	&cmd_set_independent_id_ns_cmd,
	&ns_descs_cmd,
	&id_nvmset_cmd,
	&id_uuid_cmd,
	&id_iocs_cmd,
	&id_domain_cmd,
	&id_endurance_grp_list_cmd,
	NULL,
};

static struct plugin plugin = {
	.name = "id",
	.desc = "Send NVMe Identify commands, show the results",
	.version = NVME_VERSION,
	.core = true,
	.group = "Log Page & Identify",
};

static void __shr_constructor register_plugin(void)
{
	plugin_add_group(&plugin, NULL, commands);
	register_extension(&plugin);
}
