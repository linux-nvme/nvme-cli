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
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libnvme.h>

#include <shared/compiler-attributes-util.h>

#include "argconfig.h"
#include "cleanup.h"
#include "global-ctx.h"
#include "logging.h"
#include "nvme-cmds-common.h"
#include "nvme-print.h"
#include "plugin.h"

static const char *rae = "Retain an Asynchronous Event";
static const char *lsp = "log specific field";
static const char *csi = "command set identifier";
static const char *namespace_desired = "desired namespace";
static const char *ish = "Ignore Shutdown (for NVMe-MI command)";

static int get_supported_log_pages(int argc, char **argv, struct command *acmd,
	struct plugin *plugin)
{
	const char *desc = "Retrieve supported logs and print the table.";

	__cleanup_libnvme_free struct nvme_supported_log_pages *supports = NULL;
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

	supports = libnvme_alloc(sizeof(*supports));
	if (!supports)
		return -ENOMEM;

	nvme_init_get_log(&cmd, NVME_NSID_ALL, NVME_LOG_LID_SUPPORTED_LOG_PAGES,
		NVME_CSI_NVM, supports, sizeof(*supports));
	err = libnvme_get_log(hdl, &cmd, false, sizeof(*supports));
	if (err) {
		nvme_show_err(err, "supported log pages");
		return err;
	}

	nvme_show_supported_log(supports, libnvme_transport_handle_get_name(hdl),
				flags);

	return err;
}

static int get_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Retrieve desired number of bytes "
		"from a given log on a specified device in either "
		"hex-dump (default) or binary format";
	const char *log_id = "identifier of log to retrieve";
	const char *log_len = "how many bytes to retrieve";
	const char *aen = "result of the aen, use to override log id";
	const char *lpo = "log page offset specifies the location within a log page from where to start returning data";
	const char *lsi = "log specific identifier specifies an identifier that is required for a particular log page";
	const char *raw = "output in raw format";
	const char *offset_type = "offset type";
	const char *xfer_len = "read chunk size (default 4k)";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_libnvme_free unsigned char *log = NULL;
	struct libnvme_passthru_cmd cmd;
	int err;
	nvme_print_flags_t flags;

	struct config {
		bool	ish;
		__u32	namespace_id;
		__u8	log_id;
		__u32	log_len;
		__u32	aen;
		__u64	lpo;
		__u8	lsp;
		__u16	lsi;
		bool	rae;
		__u8	uuid_index;
		bool	raw_binary;
		__u8	csi;
		bool	ot;
		__u32	xfer_len;
	};

	struct config cfg = {
		.ish		= false,
		.namespace_id	= NVME_NSID_ALL,
		.log_id		= 0xff,
		.log_len	= 0,
		.aen		= 0,
		.lpo		= NVME_LOG_LPO_NONE,
		.lsp		= NVME_LOG_LSP_NONE,
		.lsi		= NVME_LOG_LSI_NONE,
		.rae		= false,
		.uuid_index	= NVME_UUID_NONE,
		.raw_binary	= false,
		.csi		= NVME_CSI_NVM,
		.ot		= false,
		.xfer_len	= NVME_LOG_PAGE_PDU_SIZE,
	};

	OPT_VALS(log_name) = {
		VAL_BYTE("supported-log-pages", NVME_LOG_LID_SUPPORTED_LOG_PAGES),
		VAL_BYTE("error", NVME_LOG_LID_ERROR),
		VAL_BYTE("smart", NVME_LOG_LID_SMART),
		VAL_BYTE("fw-slot", NVME_LOG_LID_FW_SLOT),
		VAL_BYTE("changed-attached-ns", NVME_LOG_LID_CHANGED_ATTACHED_NS),
		VAL_BYTE("changed-ns", NVME_LOG_LID_CHANGED_ATTACHED_NS),
		VAL_BYTE("cmd-effects", NVME_LOG_LID_CMD_EFFECTS),
		VAL_BYTE("device-self-test", NVME_LOG_LID_DEVICE_SELF_TEST),
		VAL_BYTE("telemetry-host", NVME_LOG_LID_TELEMETRY_HOST),
		VAL_BYTE("telemetry-ctrl", NVME_LOG_LID_TELEMETRY_CTRL),
		VAL_BYTE("endurance-group", NVME_LOG_LID_ENDURANCE_GROUP),
		VAL_BYTE("predictable-lat-nvmset", NVME_LOG_LID_PREDICTABLE_LAT_NVMSET),
		VAL_BYTE("predictable-lat-agg", NVME_LOG_LID_PREDICTABLE_LAT_AGG),
		VAL_BYTE("ana", NVME_LOG_LID_ANA),
		VAL_BYTE("persistent-event", NVME_LOG_LID_PERSISTENT_EVENT),
		VAL_BYTE("lba-status", NVME_LOG_LID_LBA_STATUS),
		VAL_BYTE("endurance-grp-evt", NVME_LOG_LID_ENDURANCE_GRP_EVT),
		VAL_BYTE("media-unit-status", NVME_LOG_LID_MEDIA_UNIT_STATUS),
		VAL_BYTE("supported-cap-config-list", NVME_LOG_LID_SUPPORTED_CAP_CONFIG_LIST),
		VAL_BYTE("fid-supported-effects", NVME_LOG_LID_FID_SUPPORTED_EFFECTS),
		VAL_BYTE("mi-cmd-supported-effects", NVME_LOG_LID_MI_CMD_SUPPORTED_EFFECTS),
		VAL_BYTE("cmd-and-feat-lockdown", NVME_LOG_LID_CMD_AND_FEAT_LOCKDOWN),
		VAL_BYTE("boot-partition", NVME_LOG_LID_BOOT_PARTITION),
		VAL_BYTE("rotational-media-info",
			 NVME_LOG_LID_ROTATIONAL_MEDIA_INFO),
		VAL_BYTE("dispersed-ns-participating-ns",
			 NVME_LOG_LID_DISPERSED_NS_PARTICIPATING_NSS),
		VAL_BYTE("mgmt-addr-list", NVME_LOG_LID_MGMT_ADDR_LIST),
		VAL_BYTE("phy-rx-eom", NVME_LOG_LID_PHY_RX_EOM),
		VAL_BYTE("reachability-groups", NVME_LOG_LID_REACHABILITY_GROUPS),
		VAL_BYTE("reachability-associations", NVME_LOG_LID_REACHABILITY_ASSOCIATIONS),
		VAL_BYTE("changed-alloc-ns-list", NVME_LOG_LID_CHANGED_ALLOC_NS),
		VAL_BYTE("fdp-configs", NVME_LOG_LID_FDP_CONFIGS),
		VAL_BYTE("fdp-ruh-usage", NVME_LOG_LID_FDP_RUH_USAGE),
		VAL_BYTE("fdp-stats", NVME_LOG_LID_FDP_STATS),
		VAL_BYTE("fdp-events", NVME_LOG_LID_FDP_EVENTS),
		VAL_BYTE("discover", NVME_LOG_LID_DISCOVERY),
		VAL_BYTE("host-discover", NVME_LOG_LID_HOST_DISCOVERY),
		VAL_BYTE("ave-discover", NVME_LOG_LID_AVE_DISCOVERY),
		VAL_BYTE("pull-model-ddc-req", NVME_LOG_LID_PULL_MODEL_DDC_REQ),
		VAL_BYTE("reservation", NVME_LOG_LID_RESERVATION),
		VAL_BYTE("sanitize", NVME_LOG_LID_SANITIZE),
		VAL_BYTE("zns-changed-zones", NVME_LOG_LID_ZNS_CHANGED_ZONES),
		VAL_END()
	};

	NVME_ARGS(opts,
		  OPT_FLAG("ish",          'I', &cfg.ish,          ish),
		  OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_desired),
		  OPT_BYTE("log-id",       'i', &cfg.log_id,       log_id, log_name),
		  OPT_UINT("log-len",      'l', &cfg.log_len,      log_len),
		  OPT_UINT("aen",          'a', &cfg.aen,          aen),
		  OPT_SUFFIX("lpo",        'L', &cfg.lpo,          lpo),
		  OPT_BYTE("lsp",          's', &cfg.lsp,          lsp),
		  OPT_SHRT("lsi",          'S', &cfg.lsi,          lsi),
		  OPT_FLAG("rae",          'r', &cfg.rae,          rae),
		  OPT_BYTE("uuid-index",   'U', &cfg.uuid_index,   uuid_index),
		  OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,   raw),
		  OPT_BYTE("csi",          'y', &cfg.csi,          csi),
		  OPT_FLAG("ot",           'O', &cfg.ot,           offset_type),
		  OPT_UINT("xfer-len",     'x', &cfg.xfer_len,     xfer_len));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.aen) {
		cfg.log_len = 4096;
		cfg.log_id = (cfg.aen >> 16) & 0xff;
	}

	if (!cfg.log_len || cfg.log_len & 0x3) {
		nvme_show_error("non-zero or non-dw alignment log-len is required param");
		return -EINVAL;
	}

	if (cfg.lsp > 127) {
		nvme_show_error("invalid lsp param");
		return -EINVAL;
	}

	if (cfg.uuid_index > 127) {
		nvme_show_error("invalid uuid index param");
		return -EINVAL;
	}

	if (cfg.xfer_len == 0 || cfg.xfer_len % 4096) {
		nvme_show_error("xfer-len argument invalid. It needs to be multiple of 4k");
		return -EINVAL;
	}

	log = libnvme_alloc(cfg.log_len);
	if (!log)
		return -ENOMEM;

	struct nvme_get_log_args args = {
		.nsid		= cfg.namespace_id,
		.rae		= cfg.rae,
		.lsp		= cfg.lsp,
		.lid		= cfg.log_id,
		.lsi		= cfg.lsi,
		.csi		= cfg.csi,
		.ot		= cfg.ot,
		.uidx		= cfg.uuid_index,
		.lpo		= cfg.lpo,
		.log		= log,
		.len		= cfg.log_len,
		.result		= NULL,
	};
	nvme_init_get_log(&cmd, cfg.namespace_id, cfg.log_id,
			  cfg.csi, log, cfg.log_len);
	if (cfg.ish) {
		if (libnvme_transport_handle_is_mi(hdl))
			nvme_init_mi_cmd_flags(&cmd, ish);
		else
			nvme_show_error("ISH is supported only for NVMe-MI");
	}
	cmd.cdw10 |= NVME_FIELD_ENCODE(cfg.lsp,
			NVME_LOG_CDW10_LSP_SHIFT,
			NVME_LOG_CDW10_LSP_MASK);
	cmd.cdw11 |= NVME_FIELD_ENCODE(cfg.lsi,
			NVME_LOG_CDW11_LSI_SHIFT,
			NVME_LOG_CDW11_LSI_MASK);
	cmd.cdw12 = cfg.lpo & 0xffffffff;
	cmd.cdw13 = cfg.lpo >> 32;
	cmd.cdw14 |= NVME_FIELD_ENCODE(cfg.uuid_index,
			NVME_LOG_CDW14_UUID_SHIFT,
			NVME_LOG_CDW14_UUID_MASK) |
		     NVME_FIELD_ENCODE(cfg.ot,
			NVME_LOG_CDW14_OT_SHIFT,
			NVME_LOG_CDW14_OT_MASK);

	err = libnvme_get_log(hdl, &cmd, cfg.rae, cfg.xfer_len);
	if (err) {
		nvme_show_err(err, "log page");
		return err;
	}

	if (!cfg.raw_binary) {
		nvme_show_result("Device:%s log-id:%d namespace-id:%#x",
		                 libnvme_transport_handle_get_name(hdl), cfg.log_id,
		                 cfg.namespace_id);
		d(log, cfg.log_len, 16, 1);
		if (nvme_args.verbose)
			nvme_show_log(libnvme_transport_handle_get_name(hdl), args.lid,
				      args.nsid, args.lsi, args.lsp, args.log, args.len,
				      VERBOSE);
	} else {
		d_raw((unsigned char *)log, cfg.log_len);
	}

	return err;
}

static struct command get_log_cmd = {
	.name = "get-log",
	.help = "Generic NVMe get log, returns log in raw format",
	.fn = get_log,
};

static struct command get_supported_log_pages_cmd = {
	.name = "supported-log-pages",
	.help = "Retrieve the Supported Log pages details, show it",
	.fn = get_supported_log_pages,
};

static struct command *commands[] = {
	&get_log_cmd,
	&get_supported_log_pages_cmd,
	NULL,
};

static void __shr_constructor register_group(void)
{
	plugin_add_group(&builtin, "Discovery & Logging", commands);
}
