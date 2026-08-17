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
#include <ccan/endian/endian.h>

#include <cleanup.h>
#include <shared/compiler-attributes-util.h>
#include <shared/parse-util.h>
#include <shared/suffix-util.h>

#include "argconfig.h"
#include "global-ctx.h"
#include "logging.h"
#include "nvme-cmds.h"
#include "nvme-print.h"
#include "plugin.h"

static const char *endgid = "Endurance Group Identifier (ENDGID)";
static const char *ish = "Ignore Shutdown (for NVMe-MI command)";

static bool is_ns_mgmt_support(struct libnvme_transport_handle *hdl)
{
	int err;
	struct libnvme_passthru_cmd cmd;

	__cleanup_libnvme_free struct nvme_id_ctrl *ctrl = libnvme_alloc(sizeof(*ctrl));

	if (!ctrl)
		return false;

	nvme_init_identify_ctrl(&cmd, ctrl);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err)
		return false;

	return le16_to_cpu(ctrl->oacs) & NVME_CTRL_OACS_NS_MGMT;
}

static void ns_mgmt_show_status(struct libnvme_transport_handle *hdl, int err, char *cmd, __u32 nsid)
{
	if (err < 0) {
		nvme_show_error("%s: %s", cmd, libnvme_strerror(-err));
		return;
	} else if (err > 0) {
		nvme_show_status(err);
		if (!is_ns_mgmt_support(hdl))
			nvme_show_error("NS management and attachment not supported");
		return;
	}

	nvme_show_verbose_key_value(cmd, "success");
	nvme_show_verbose_key_value("nsid", "%d", nsid);
}

static int delete_ns(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Delete the given namespace by "
		"sending a namespace management command to "
		"the provided device. All controllers should be detached from "
		"the namespace prior to namespace deletion. A namespace ID "
		"becomes inactive when that namespace is detached or, if "
		"the namespace is not already inactive, once deleted.";
	const char *namespace_id = "namespace to delete";

	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	struct libnvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	int err;

	struct config {
		bool	ish;
		__u32	namespace_id;
	};

	struct config cfg = {
		.ish		= false,
		.namespace_id	= 0,
	};

	NVME_ARGS(opts,
		  OPT_FLAG("ish",          'I', &cfg.ish,          ish),
		  OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id));

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

	nvme_init_ns_mgmt_delete(&cmd, cfg.namespace_id);
	if (cfg.ish) {
		if (libnvme_transport_handle_is_mi(hdl))
			nvme_init_mi_cmd_flags(&cmd, ish);
		else
			nvme_show_error("ISH is supported only for NVMe-MI");
	}
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	ns_mgmt_show_status(hdl, err, acmd->name, cfg.namespace_id);

	return err;
}

static int nvme_attach_ns(int argc, char **argv, int attach, const char *desc, struct command *acmd)
{
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;

	__cleanup_libnvme_free struct nvme_ctrl_list *cntlist = NULL;
	__u16 list[NVME_ID_CTRL_LIST_MAX];
	struct libnvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	int err, num;

	const char *namespace_id = "namespace to attach";
	const char *cont = "optional comma-sep controller id list";

	struct config {
		bool	ish;
		__u32	nsid;
		char	*cntlist;
	};

	struct config cfg = {
		.ish		= false,
		.nsid		= 0,
		.cntlist	= "",
	};

	NVME_ARGS(opts,
		  OPT_FLAG("ish",          'I', &cfg.ish,     ish),
		  OPT_UINT("namespace-id", 'n', &cfg.nsid,    namespace_id),
		  OPT_LIST("controllers",  'c', &cfg.cntlist, cont));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (libnvme_transport_handle_is_ns(hdl)) {
		nvme_show_error("%s: a namespace device opened (dev: %s, nsid: %d)", acmd->name,
				libnvme_transport_handle_get_name(hdl), cfg.nsid);
		return -EINVAL;
	}

	if (!cfg.nsid) {
		nvme_show_error("%s: namespace-id parameter required", acmd->name);
		return -EINVAL;
	}

	num = shr_parse_csv_u16(cfg.cntlist, list, ARRAY_SIZE(list));
	if (num == -1) {
		nvme_show_error("%s: controller id list is malformed", acmd->name);
		return -EINVAL;
	}

	cntlist = libnvme_alloc(sizeof(*cntlist));
	if (!cntlist)
		return -ENOMEM;

	if (argconfig_parse_seen(opts, "controllers")) {
		nvme_init_ctrl_list(cntlist, num, list);
	} else {
		struct nvme_id_ctrl ctrl = { 0 };

		nvme_init_identify_ctrl(&cmd, &ctrl);
		err = libnvme_exec_admin_passthru(hdl, &cmd);
		if (err) {
			nvme_show_error("identify-ctrl %s", libnvme_strerror(-err));
			return err;
		}
		cntlist->num = cpu_to_le16(1);
		cntlist->identifier[0] = ctrl.cntlid;
	}

	if (attach)
		nvme_init_ns_attach_ctrls(&cmd, cfg.nsid, cntlist);
	else
		nvme_init_ns_detach_ctrls(&cmd, cfg.nsid, cntlist);

	if (cfg.ish) {
		if (libnvme_transport_handle_is_mi(hdl))
			nvme_init_mi_cmd_flags(&cmd, ish);
		else
			nvme_show_error("ISH is supported only for NVMe-MI");
	}
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	ns_mgmt_show_status(hdl, err, acmd->name, cfg.nsid);

	return err;
}

static int attach_ns(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Attach the given namespace to the "
		"given controller or comma-sep list of controllers. ID of the "
		"given namespace becomes active upon attachment to a "
		"controller. A namespace must be attached to a controller "
		"before IO commands may be directed to that namespace.";

	return nvme_attach_ns(argc, argv, 1, desc, acmd);
}

static int detach_ns(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Detach the given namespace from the "
		"given controller; de-activates the given namespace's ID. A "
		"namespace must be attached to a controller before IO "
		"commands may be directed to that namespace.";

	return nvme_attach_ns(argc, argv, 0, desc, acmd);
}

static int parse_lba_num_si(struct libnvme_transport_handle *hdl, const char *opt,
			    const char *val, __u8 flbas, __u64 *num, __u64 align)
{
	__cleanup_libnvme_free struct nvme_ns_list *ns_list = NULL;
	__cleanup_libnvme_free struct nvme_id_ctrl *ctrl = NULL;
	__cleanup_libnvme_free struct nvme_id_ns *ns = NULL;
	struct libnvme_passthru_cmd cmd;
	__u32 nsid = 1;
	__u8 lbaf;
	unsigned int remainder;
	char *endptr;
	int err = -EINVAL;
	int lbas;

	if (!val)
		return 0;

	if (*num) {
		nvme_show_error(
		    "Invalid specification of both %s and its SI argument, please specify only one",
		    opt);
		return err;
	}

	ctrl = libnvme_alloc(sizeof(*ctrl));
	if (!ctrl)
		return -ENOMEM;

	nvme_init_identify_ctrl(&cmd, ctrl);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "identify controller");
		return err;
	}

	ns_list = libnvme_alloc(sizeof(*ns_list));
	if (!ns_list)
		return -ENOMEM;

	if ((ctrl->oacs & 0x8) >> 3) {
		nsid = NVME_NSID_ALL;
	} else {
		nvme_init_identify_active_ns_list(&cmd, nsid - 1, ns_list);
		err = libnvme_exec_admin_passthru(hdl, &cmd);
		if (err) {
			nvme_show_err(err, "identify namespace list");
			return err;
		}
		nsid = le32_to_cpu(ns_list->ns[0]);
	}

	ns = libnvme_alloc(sizeof(*ns));
	if (!ns)
		return -ENOMEM;

	nvme_init_identify_ns(&cmd, nsid, ns);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "identify namespace");
		return err;
	}

	nvme_id_ns_flbas_to_lbaf_inuse(flbas, &lbaf);
	lbas = (1 << ns->lbaf[lbaf].ds) + le16_to_cpu(ns->lbaf[lbaf].ms);

	err = shr_suffix_si_parse(val, &endptr, (uint64_t *)num);
	if (err) {
		nvme_show_error("Expected long suffixed integer argument for '%s-si' but got '%s'!",
				opt, val);
		return -err;
	}

	if (endptr[0]) {
		remainder = *num % align;
		if (remainder)
			*num += align - remainder;
	}

	if (endptr[0] != '\0')
		*num /= lbas;

	return 0;
}

static int create_ns(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Send a namespace management command "
		"to the specified device to create a namespace with the given "
		"parameters. The next available namespace ID is used for the "
		"create operation. Note that create-ns does not attach the "
		"namespace to a controller, the attach-ns command is needed.";
	const char *nsze = "size of ns (NSZE)";
	const char *ncap = "capacity of ns (NCAP)";
	const char *flbas =
	    "Formatted LBA size (FLBAS), if entering this value ignore \'block-size\' field";
	const char *dps = "data protection settings (DPS)";
	const char *nmic = "multipath and sharing capabilities (NMIC)";
	const char *anagrpid = "ANA Group Identifier (ANAGRPID)";
	const char *nvmsetid = "NVM Set Identifier (NVMSETID)";
	const char *csi = "command set identifier (CSI)";
	const char *lbstm = "logical block storage tag mask (LBSTM)";
	const char *nphndls = "Number of Placement Handles (NPHNDLS)";
	const char *bs = "target block size, specify only if \'FLBAS\' value not entered";
	const char *nsze_si = "size of ns (NSZE) in standard SI units";
	const char *ncap_si = "capacity of ns (NCAP) in standard SI units";
	const char *azr = "Allocate ZRWA Resources (AZR) for Zoned Namespace Command Set";
	const char *rar = "Requested Active Resources (RAR) for Zoned Namespace Command Set";
	const char *ror = "Requested Open Resources (ROR) for Zoned Namespace Command Set";
	const char *rnumzrwa =
	    "Requested Number of ZRWA Resources (RNUMZRWA) for Zoned Namespace Command Set";
	const char *phndls = "Comma separated list of Placement Handle Associated RUH";

	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_libnvme_free struct nvme_ns_mgmt_host_sw_specified *data = NULL;
	__cleanup_libnvme_free struct nvme_id_ns_granularity_list *gr_list = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_libnvme_free struct nvme_id_ctrl *id = NULL;
	__cleanup_libnvme_free struct nvme_id_ns *ns = NULL;
	__u64 align_nsze = 1 << 20; /* Default 1 MiB */
	__u64 align_ncap = align_nsze;
	struct libnvme_passthru_cmd cmd;
	uint16_t phndl[128] = { 0, };
	nvme_print_flags_t flags;
	uint16_t num_phandle;
	int err = 0, i;
	__u32 nsid;

	struct config {
		bool	ish;
		__u64	nsze;
		__u64	ncap;
		__u8	flbas;
		__u8	dps;
		__u8	nmic;
		__u32	anagrpid;
		__u16	nvmsetid;
		__u16	endgid;
		__u64	bs;
		__u8	csi;
		__u64	lbstm;
		__u16	nphndls;
		char	*nsze_si;
		char	*ncap_si;
		bool	azr;
		__u32	rar;
		__u32	ror;
		__u32	rnumzrwa;
		char	*phndls;
	};

	struct config cfg = {
		.ish		= false,
		.nsze		= 0,
		.ncap		= 0,
		.flbas		= 0xff,
		.dps		= 0,
		.nmic		= 0,
		.anagrpid	= 0,
		.nvmsetid	= 0,
		.endgid		= 0,
		.bs		= 0x00,
		.csi		= 0,
		.lbstm		= 0,
		.nphndls	= 0,
		.nsze_si	= NULL,
		.ncap_si	= NULL,
		.azr		= false,
		.rar		= 0,
		.ror		= 0,
		.rnumzrwa	= 0,
		.phndls		= "",
	};

	NVME_ARGS(opts,
		  OPT_FLAG("ish",          'I', &cfg.ish,      ish),
		  OPT_SUFFIX("nsze",       's', &cfg.nsze,     nsze),
		  OPT_SUFFIX("ncap",       'c', &cfg.ncap,     ncap),
		  OPT_BYTE("flbas",        'f', &cfg.flbas,    flbas),
		  OPT_BYTE("dps",          'd', &cfg.dps,      dps),
		  OPT_BYTE("nmic",         'm', &cfg.nmic,     nmic),
		  OPT_UINT("anagrp-id",    'a', &cfg.anagrpid, anagrpid),
		  OPT_SHRT("nvmset-id",    'i', &cfg.nvmsetid, nvmsetid),
		  OPT_SHRT("endg-id",      'e', &cfg.endgid,   endgid),
		  OPT_SUFFIX("block-size", 'b', &cfg.bs,       bs),
		  OPT_BYTE("csi",          'y', &cfg.csi,      csi),
		  OPT_SUFFIX("lbstm",      'l', &cfg.lbstm,    lbstm),
		  OPT_SHRT("nphndls",      'n', &cfg.nphndls,  nphndls),
		  OPT_STR("nsze-si",       'S', &cfg.nsze_si,  nsze_si),
		  OPT_STR("ncap-si",       'C', &cfg.ncap_si,  ncap_si),
		  OPT_FLAG("azr",          'z', &cfg.azr,      azr),
		  OPT_UINT("rar",          'r', &cfg.rar,      rar),
		  OPT_UINT("ror",          'O', &cfg.ror,      ror),
		  OPT_UINT("rnumzrwa",     'u', &cfg.rnumzrwa, rnumzrwa),
		  OPT_LIST("phndls",       'p', &cfg.phndls,   phndls));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.flbas != 0xff && cfg.bs != 0x00) {
		nvme_show_error(
		    "Invalid specification of both FLBAS and Block Size, please specify only one");
		return -EINVAL;
	}
	if (cfg.bs) {
		if ((cfg.bs & (~cfg.bs + 1)) != cfg.bs) {
			nvme_show_error(
			    "Invalid value for block size (%"PRIu64"). Block size must be a power of two",
			    (uint64_t)cfg.bs);
			return -EINVAL;
		}

		ns = libnvme_alloc(sizeof(*ns));
		if (!ns)
			return -ENOMEM;

		nvme_init_identify_ns(&cmd, NVME_NSID_ALL, ns);
		err = libnvme_exec_admin_passthru(hdl, &cmd);
		if (err) {
			if (err > 0)
				nvme_show_error("identify failed");
			nvme_show_err(err, "identify-namespace");
			return err;
		}
		for (i = 0; i <= ns->nlbaf; ++i) {
			if ((1 << ns->lbaf[i].ds) == cfg.bs && ns->lbaf[i].ms == 0) {
				cfg.flbas = i;
				break;
			}
		}

	}
	if (cfg.flbas == 0xff) {
		nvme_show_error("FLBAS corresponding to block size %"PRIu64" not found",
			(uint64_t)cfg.bs);
		nvme_show_error("Please correct block size, or specify FLBAS directly");

		return -EINVAL;
	}

	id = libnvme_alloc(sizeof(*id));
	if (!id)
		return -ENOMEM;

	nvme_init_identify_ctrl(&cmd, id);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		if (err > 0)
			nvme_show_error("identify controller failed");
		nvme_show_err(err, "identify-controller");
		return err;
	}

	if (id->ctratt & NVME_CTRL_CTRATT_NAMESPACE_GRANULARITY) {
		gr_list = libnvme_alloc(sizeof(*gr_list));
		if (!gr_list)
			return -ENOMEM;

		nvme_init_identify_ns_granularity(&cmd, gr_list);
		if (!libnvme_exec_admin_passthru(hdl, &cmd)) {
			struct nvme_id_ns_granularity_desc *desc;
			int index = cfg.flbas;

			/* FIXME: add a proper bitmask to libnvme */
			if (!(le32_to_cpu(gr_list->attributes) & 1)) {
				/* Only the first descriptor is valid */
				index = 0;
			} else if (index > gr_list->num_descriptors) {
				/*
				 * The descriptor will contain only zeroes
				 * so we don't need to read it.
				 */
				goto parse_lba;
			}
			desc = &gr_list->entry[index];

			if (desc->nszegran) {
				print_info("enforce nsze alignment to %"PRIx64
					   " because of namespace granularity requirements\n",
					   le64_to_cpu(desc->nszegran));
				align_nsze = le64_to_cpu(desc->nszegran);
			}
			if (desc->ncapgran) {
				print_info("enforce ncap alignment to %"PRIx64
					   " because of namespace granularity requirements\n",
					   le64_to_cpu(desc->ncapgran));
				align_ncap = le64_to_cpu(desc->ncapgran);
			}
		}
	}

parse_lba:
	err = parse_lba_num_si(hdl, "nsze", cfg.nsze_si, cfg.flbas, &cfg.nsze, align_nsze);
	if (err)
		return err;

	err = parse_lba_num_si(hdl, "ncap", cfg.ncap_si, cfg.flbas, &cfg.ncap, align_ncap);
	if (err)
		return err;

	if (cfg.csi != NVME_CSI_ZNS && (cfg.azr || cfg.rar || cfg.ror || cfg.rnumzrwa)) {
		nvme_show_error("Invalid ZNS argument is given (CSI:%#x)", cfg.csi);
		return -EINVAL;
	}

	data = libnvme_alloc(sizeof(*data));
	if (!data)
		return -ENOMEM;

	data->nsze = cpu_to_le64(cfg.nsze);
	data->ncap = cpu_to_le64(cfg.ncap);
	data->flbas = cfg.flbas;
	data->dps = cfg.dps;
	data->nmic = cfg.nmic;
	data->anagrpid = cpu_to_le32(cfg.anagrpid);
	data->nvmsetid = cpu_to_le16(cfg.nvmsetid);
	data->endgid = cpu_to_le16(cfg.endgid);
	data->lbstm = cpu_to_le64(cfg.lbstm);
	data->zns.znsco = cfg.azr;
	data->zns.rar = cpu_to_le32(cfg.rar);
	data->zns.ror = cpu_to_le32(cfg.ror);
	data->zns.rnumzrwa = cpu_to_le32(cfg.rnumzrwa);
	data->nphndls = cpu_to_le16(cfg.nphndls);

	num_phandle = shr_parse_csv_ushort(cfg.phndls, phndl, ARRAY_SIZE(phndl));
	if (cfg.nphndls != num_phandle) {
		nvme_show_error("Invalid Placement handle list");
		return -EINVAL;
	}

	for (i = 0; i < num_phandle; i++)
		data->phndl[i] = cpu_to_le16(phndl[i]);

	nvme_init_ns_mgmt_create(&cmd, cfg.csi, data);
	if (cfg.ish) {
		if (libnvme_transport_handle_is_mi(hdl))
			nvme_init_mi_cmd_flags(&cmd, ish);
		else
			nvme_show_error("ISH is supported only for NVMe-MI");
	}
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	nsid = cmd.result;
	ns_mgmt_show_status(hdl, err, acmd->name, nsid);

	return err;
}

static int get_ns_id(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Get namespace ID of a the block device.";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	unsigned int nsid;
	int err;
	nvme_print_flags_t flags;

	NVME_ARGS(opts);

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	err = libnvme_get_nsid(hdl, &nsid);
	if (err < 0) {
		nvme_show_error("get namespace ID: %s", libnvme_strerror(-err));
		return -errno;
	}

	nvme_show_result("%s: namespace-id:%d", libnvme_transport_handle_get_name(hdl), nsid);

	return 0;
}

static struct command create_ns_cmd = {
	.name = "create",
	.help = "Creates a namespace with the provided parameters",
	.fn = create_ns,
};

static struct command delete_ns_cmd = {
	.name = "delete",
	.help = "Deletes a namespace from the controller",
	.fn = delete_ns,
};

static struct command attach_ns_cmd = {
	.name = "attach",
	.help = "Attaches a namespace to requested controller(s)",
	.fn = attach_ns,
};

static struct command detach_ns_cmd = {
	.name = "detach",
	.help = "Detaches a namespace from requested controller(s)",
	.fn = detach_ns,
};

static struct command get_ns_id_cmd = {
	.name = "get-id",
	.help = "Retrieve the namespace ID of opened block device",
	.fn = get_ns_id,
};

static struct command *commands[] = {
	&create_ns_cmd,
	&delete_ns_cmd,
	&attach_ns_cmd,
	&detach_ns_cmd,
	&get_ns_id_cmd,
	NULL,
};

static struct plugin plugin = {
	.name = "ns",
	.desc = "Manage NVMe namespaces",
	.version = NVME_VERSION,
	.core = true,
};

static void __shr_constructor register_plugin(void)
{
	plugin_add_group(&plugin, NULL, commands);
	register_extension(&plugin);
}
