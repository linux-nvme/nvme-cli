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

#include <libnvme-mi.h>
#include <libnvme.h>

#include <ccan/array_size/array_size.h>
#include <ccan/endian/endian.h>
#include <ccan/minmax/minmax.h>
#include <shared/compiler-attributes-util.h>
#include <shared/fs-util.h>
#include <shared/mmio-util.h>
#include <shared/parse-util.h>
#include <shared/sig-util.h>
#include <shared/suffix-util.h>
#include <shared/time-util.h>

#include "argconfig.h"
#include "cleanup.h"
#include "fabrics.h"
#include "global-config.h"
#include "global-ctx.h"
#include "logging.h"
#include "nvme-cmds-common.h"
#include "nvme-cmds.h"
#include "nvme-print.h"
#include "nvme-regs.h"
#include "plugin.h"

static const char *buf_len = "buffer len (if) data is sent or received";
static const char *namespace_desired = "desired namespace";
static const char *uuid_index_specify = "specify uuid index";

static OPT_VALS(feature_name) = {
	VAL_BYTE("arbitration", NVME_FEAT_FID_ARBITRATION),
	VAL_BYTE("power-mgmt", NVME_FEAT_FID_POWER_MGMT),
	VAL_BYTE("lba-range", NVME_FEAT_FID_LBA_RANGE),
	VAL_BYTE("temp-thresh", NVME_FEAT_FID_TEMP_THRESH),
	VAL_BYTE("err-recovery", NVME_FEAT_FID_ERR_RECOVERY),
	VAL_BYTE("volatile-wc", NVME_FEAT_FID_VOLATILE_WC),
	VAL_BYTE("num-queues", NVME_FEAT_FID_NUM_QUEUES),
	VAL_BYTE("irq-coalesce", NVME_FEAT_FID_IRQ_COALESCE),
	VAL_BYTE("irq-config", NVME_FEAT_FID_IRQ_CONFIG),
	VAL_BYTE("write-atomic", NVME_FEAT_FID_WRITE_ATOMIC),
	VAL_BYTE("async-event", NVME_FEAT_FID_ASYNC_EVENT),
	VAL_BYTE("auto-pst", NVME_FEAT_FID_AUTO_PST),
	VAL_BYTE("host-mem-buf", NVME_FEAT_FID_HOST_MEM_BUF),
	VAL_BYTE("timestamp", NVME_FEAT_FID_TIMESTAMP),
	VAL_BYTE("kato", NVME_FEAT_FID_KATO),
	VAL_BYTE("hctm", NVME_FEAT_FID_HCTM),
	VAL_BYTE("nopsc", NVME_FEAT_FID_NOPSC),
	VAL_BYTE("rrl", NVME_FEAT_FID_RRL),
	VAL_BYTE("plm-config", NVME_FEAT_FID_PLM_CONFIG),
	VAL_BYTE("plm-window", NVME_FEAT_FID_PLM_WINDOW),
	VAL_BYTE("lba-sts-interval", NVME_FEAT_FID_LBA_STS_INTERVAL),
	VAL_BYTE("host-behavior", NVME_FEAT_FID_HOST_BEHAVIOR),
	VAL_BYTE("sanitize", NVME_FEAT_FID_SANITIZE),
	VAL_BYTE("endurance-evt-cfg", NVME_FEAT_FID_ENDURANCE_EVT_CFG),
	VAL_BYTE("iocs-profile", NVME_FEAT_FID_IOCS_PROFILE),
	VAL_BYTE("spinup-control", NVME_FEAT_FID_SPINUP_CONTROL),
	VAL_BYTE("power-loss-signal", NVME_FEAT_FID_POWER_LOSS_SIGNAL),
	VAL_BYTE("perf-characteristics", NVME_FEAT_FID_PERF_CHARACTERISTICS),
	VAL_BYTE("fdp", NVME_FEAT_FID_FDP),
	VAL_BYTE("fdp-events", NVME_FEAT_FID_FDP_EVENTS),
	VAL_BYTE("ns-admin-label", NVME_FEAT_FID_NS_ADMIN_LABEL),
	VAL_BYTE("key-value", NVME_FEAT_FID_KEY_VALUE),
	VAL_BYTE("ctrl-data-queue", NVME_FEAT_FID_CTRL_DATA_QUEUE),
	VAL_BYTE("emb-mgmt-ctrl-addr", NVME_FEAT_FID_EMB_MGMT_CTRL_ADDR),
	VAL_BYTE("host-mgmt-agent-addr", NVME_FEAT_FID_HOST_MGMT_AGENT_ADDR),
	VAL_BYTE("enh-ctrl-metadata", NVME_FEAT_FID_ENH_CTRL_METADATA),
	VAL_BYTE("ctrl-metadata", NVME_FEAT_FID_CTRL_METADATA),
	VAL_BYTE("ns-metadata", NVME_FEAT_FID_NS_METADATA),
	VAL_BYTE("sw-progress", NVME_FEAT_FID_SW_PROGRESS),
	VAL_BYTE("host-id", NVME_FEAT_FID_HOST_ID),
	VAL_BYTE("resv-nf-mask", NVME_FEAT_FID_RESV_NF_MASK),
	VAL_BYTE("resv-persist", NVME_FEAT_FID_RESV_PERSIST),
	VAL_BYTE("write-protect", NVME_FEAT_FID_WRITE_PROTECT),
	VAL_BYTE("bp-write-protect", NVME_FEAT_FID_BP_WRITE_PROTECT),
	VAL_END()
};

static int get_feature_id(struct libnvme_transport_handle *hdl, struct feat_cfg *cfg,
			  void **buf, __u64 *result)
{
	if (!cfg->data_len)
		libnvme_get_feature_length(cfg->feature_id, cfg->cdw11,
					NVME_DATA_TFR_CTRL_TO_HOST,	
					&cfg->data_len);

	if (cfg->feature_id == NVME_FEAT_FID_FDP_EVENTS) {
		cfg->data_len = 0xff * sizeof(__u16);
		cfg->cdw11 |= 0xff << 16;
	}

	if (NVME_CHECK(cfg->sel, GET_FEATURES_SEL, SUPPORTED))
		cfg->data_len = 0;

	if (cfg->data_len) {
		*buf = libnvme_alloc(cfg->data_len - 1);
		if (!*buf)
			return -1;
	}

	return nvme_get_features(hdl, cfg->namespace_id, cfg->feature_id, cfg->sel,
			cfg->cdw11, cfg->uuid_index, *buf, cfg->data_len, result);
}

static int filter_out_flags(int status)
{
	return status & (NVME_VAL(SCT) | NVME_VAL(SC));
}

static void get_feature_id_print(struct feat_cfg cfg, int err, __u64 result,
		void *buf, nvme_print_flags_t flags)
{
	int status = err > 0 ? filter_out_flags(err) : err;
	enum nvme_status_type type = NVME_STATUS_TYPE_NVME;

	if (err) {
		if (nvme_status_equals(status, type, NVME_SC_INVALID_FIELD) ||
		    nvme_status_equals(status, type, NVME_SC_INVALID_NS))
			return;
		nvme_show_err(err, "get-feature");
		return;
	}

	nvme_show_feature(cfg.feature_id, cfg.sel, result, buf, cfg.data_len,
			  flags);
}

static bool is_get_feature_result_set(enum nvme_features_id feature_id)
{
	switch (feature_id) {
	case NVME_FEAT_FID_PERF_CHARACTERISTICS:
	case NVME_FEAT_FID_HOST_ID:
		return false;
	default:
		break;
	}

	return true;
}

static int get_feature_id_changed(struct libnvme_transport_handle *hdl, struct feat_cfg cfg,
		nvme_print_flags_t flags)
{
	__cleanup_libnvme_free void *buf_def = NULL;
	__cleanup_libnvme_free void *buf = NULL;
	__u64 result_def = 0;
	__u64 result = 0;
	int err_def = 0;
	int err;

	if (cfg.changed)
		cfg.sel = NVME_GET_FEATURES_SEL_CURRENT;

	err = get_feature_id(hdl, &cfg, &buf, &result);

	if (!err && cfg.changed) {
		cfg.sel = NVME_GET_FEATURES_SEL_DEFAULT;
		err_def = get_feature_id(hdl, &cfg, &buf_def, &result_def);
	}

	if (!err && !is_get_feature_result_set(cfg.feature_id))
		result = cfg.cdw11;

	if (err || !cfg.changed || err_def || result != result_def ||
	    (buf && buf_def && !strcmp(buf, buf_def)))
		get_feature_id_print(cfg, err, result, buf, flags);

	return err;
}

static int get_feature_ids(struct libnvme_transport_handle *hdl, struct feat_cfg cfg,
		nvme_print_flags_t flags)
{
	int err = 0;
	int i;
	int feat_max = 0x100;
	int feat_num = 0;
	int status = 0;
	enum nvme_status_type type = NVME_STATUS_TYPE_NVME;

	if (cfg.feature_id)
		feat_max = cfg.feature_id + 1;

	for (i = cfg.feature_id; i < feat_max; i++, feat_num++) {
		cfg.feature_id = i;
		err = get_feature_id_changed(hdl, cfg, flags);
		if (!err)
			continue;
		status = filter_out_flags(err);
		if (nvme_status_equals(status, type, NVME_SC_INVALID_FIELD))
			continue;
		if (!nvme_status_equals(status, type, NVME_SC_INVALID_NS))
			break;
		nvme_show_error_status(err, "get-feature:%#0*x (%s)", cfg.feature_id ? 4 : 2,
				       cfg.feature_id, nvme_feature_to_string(cfg.feature_id));
	}

	if (feat_num == 1 && nvme_status_equals(status, type, NVME_SC_INVALID_FIELD))
		nvme_show_status(err);

	return err;
}

static int get_feature(int argc, char **argv, struct command *acmd,
		       struct plugin *plugin)
{
	const char *desc = "Read operating parameters of the "
		"specified controller. Operating parameters are grouped "
		"and identified by Feature Identifiers; each Feature "
		"Identifier contains one or more attributes that may affect "
		"behavior of the feature. Each Feature has three possible "
		"settings: default, saveable, and current. If a Feature is "
		"saveable, it may be modified by set-feature. Default values "
		"are vendor-specific and not changeable. Use set-feature to "
		"change saveable Features.";
	const char *raw = "show feature in binary format";
	const char *feature_id = "feature identifier";
	const char *sel = "[0-3]: current/default/saved/supported";
	const char *cdw11 = "feature specific dword 11";
	const char *changed = "show feature changed";
	nvme_print_flags_t flags = NORMAL;

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	int err;

	struct feat_cfg cfg = {
		.feature_id	= 0,
		.namespace_id	= 0,
		.sel		= NVME_GET_FEATURES_SEL_CURRENT,
		.data_len	= 0,
		.raw_binary	= false,
		.cdw11		= 0,
		.uuid_index	= 0,
	};

	NVME_ARGS(opts,
		  OPT_BYTE("feature-id",     'f', &cfg.feature_id,     feature_id, feature_name),
		  OPT_UINT("namespace-id",   'n', &cfg.namespace_id,   namespace_id_desired),
		  OPT_BYTE("sel",            's', &cfg.sel,            sel),
		  OPT_UINT("data-len",       'l', &cfg.data_len,       buf_len),
		  OPT_FLAG("raw-binary",     'b', &cfg.raw_binary,     raw),
		  OPT_UINT("cdw11",          'c', &cfg.cdw11,          cdw11),
		  OPT_BYTE("uuid-index",     'U', &cfg.uuid_index,     uuid_index_specify),
		  OPT_FLAG("changed",        'C', &cfg.changed,        changed));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (!argconfig_parse_seen(opts, "namespace-id")) {
		err = libnvme_get_nsid(hdl, &cfg.namespace_id);
		if (err < 0) {
			if (errno != ENOTTY) {
				nvme_show_error("get-namespace-id: %s", libnvme_strerror(-err));
				return err;
			}
			cfg.namespace_id = NVME_NSID_ALL;
		}
	}

	if (cfg.sel > NVME_GET_FEATURES_SEL_SUPPORTED) {
		nvme_show_error("invalid 'select' param:%d", cfg.sel);
		return -EINVAL;
	}

	if (cfg.uuid_index > 127) {
		nvme_show_error("invalid uuid index param: %u", cfg.uuid_index);
		return -1;
	}

	if (nvme_args.verbose)
		flags |= VERBOSE;

	err = get_feature_ids(hdl, cfg, flags);

	return err;
}

#define STRTOUL_AUTO_BASE              (0)
#define NVME_FEAT_TIMESTAMP_DATA_SIZE  (6)

static int set_feature(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Modify the saveable or changeable "
		"current operating parameters of the controller. "
		"Operating parameters are grouped and identified by Feature"
		"Identifiers. Feature settings can be applied to the entire"
		"controller and all associated namespaces, or to only a few"
		"namespace(s) associated with the controller. Default values"
		"for each Feature are vendor-specific and may not be modified."
		"Use get-feature to determine which Features are supported by"
		"the controller and are saveable/changeable.";
	const char *fid = "feature identifier (required)";
	const char *data = "optional file for feature data (default stdin)";
	const char *value = "new value of feature (required)";
	const char *cdw12 = "feature cdw12, if used";
	const char *sv = "specifies that the controller shall save the attribute";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_libnvme_free void *buf = NULL;
	__cleanup_fd int ffd = STDIN_FILENO;
	int err;
	__u64 result;
	nvme_print_flags_t flags;

	struct config {
		__u32	nsid;
		__u8	fid;
		__u64	value;
		__u32	cdw12;
		__u8	uidx;
		__u32	data_len;
		char	*file;
		bool	sv;
	};

	struct config cfg = {
		.nsid		= 0,
		.fid		= 0,
		.value		= 0,
		.uidx		= 0,
		.data_len	= 0,
		.file		= "",
		.sv			= false,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id", 'n', &cfg.nsid,     namespace_desired),
		  OPT_BYTE("feature-id",   'f', &cfg.fid,      fid, feature_name),
		  OPT_SUFFIX("value",      'V', &cfg.value,    value),
		  OPT_UINT("cdw12",        'c', &cfg.cdw12,    cdw12),
		  OPT_BYTE("uuid-index",   'U', &cfg.uidx,     uuid_index_specify),
		  OPT_UINT("data-len",     'l', &cfg.data_len, buf_len),
		  OPT_FILE("data",         'd', &cfg.file,     data),
		  OPT_FLAG("save",         's', &cfg.sv,       sv));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (!argconfig_parse_seen(opts, "namespace-id")) {
		err = libnvme_get_nsid(hdl, &cfg.nsid);
		if (err < 0) {
			if (errno != ENOTTY) {
				nvme_show_error("get-namespace-id: %s", libnvme_strerror(-err));
				return -errno;
			}
			cfg.nsid = NVME_NSID_ALL;
		}
	}

	if (!cfg.fid) {
		nvme_show_error("feature-id required param");
		return -EINVAL;
	}

	if (cfg.uidx > 127) {
		nvme_show_error("invalid uuid index param: %u", cfg.uidx);
		return -1;
	}

	if (!cfg.data_len)
		libnvme_get_feature_length(cfg.fid, cfg.value,
					 NVME_DATA_TFR_HOST_TO_CTRL,
					 &cfg.data_len);

	if (cfg.data_len) {
		buf = libnvme_alloc(cfg.data_len);
		if (!buf)
			return -ENOMEM;
	}

	if (buf) {
		/*
		 * Use the '-v' value for the timestamp feature if provided as
		 * a convenience since it can often fit in 4-bytes. The user
		 * should use the buffer method if the value exceeds this
		 * length.
		 */
		if (cfg.fid == NVME_FEAT_FID_TIMESTAMP &&
		    argconfig_parse_seen(opts, "value")) {
			memcpy(buf, &cfg.value, NVME_FEAT_TIMESTAMP_DATA_SIZE);
		} else {
			if (strlen(cfg.file))
				ffd = shr_open_rawdata(cfg.file, O_RDONLY);

			if (ffd < 0) {
				nvme_show_error("Failed to open file %s: %s",
						cfg.file, libnvme_strerror(errno));
				return -EINVAL;
			}

			err = read(ffd, buf, cfg.data_len);
			if (err < 0) {
				nvme_show_error("failed to read data buffer from input file: %s",
						libnvme_strerror(errno));
				return -errno;
			}
		}
	}

	err = nvme_set_features(hdl, cfg.nsid, cfg.fid, cfg.sv, cfg.value, cfg.cdw12,
			0, cfg.uidx, 0, buf, cfg.data_len, &result);
	if (err) {
		nvme_show_admin_cmd_err("set-feature", nvme_admin_set_features,
					err);
		return err;
	}

	nvme_show_result("set-feature:%#0*x (%s), value:%#0*" PRIx64
	                 ", cdw12:%#0*x, save:%#x", cfg.fid ? 4 : 2, cfg.fid,
	                 nvme_feature_to_string(cfg.fid), cfg.value ? 10 : 8,
	                 (uint64_t)cfg.value, cfg.cdw12 ? 10 : 8, cfg.cdw12, cfg.sv);
	if (cfg.fid == NVME_FEAT_FID_LBA_STS_INTERVAL)
		nvme_show_lba_status_info(result);
	if (buf) {
		if (cfg.fid == NVME_FEAT_FID_LBA_RANGE)
			nvme_show_lba_range((struct nvme_lba_range_type *)buf,
					    result, 0);
		else
			d(buf, cfg.data_len, 16, 1);
	}

	return err;
}

static struct command get_feature_cmd = {
	.name = "get-feature",
	.help = "Get feature and show the resulting value",
	.fn = get_feature,
};

static struct command set_feature_cmd = {
	.name = "set-feature",
	.help = "Set a feature and show the resulting value",
	.fn = set_feature,
};

static struct command *commands[] = {
	&get_feature_cmd,
	&set_feature_cmd,
	NULL,
};

static void __shr_constructor register_group(void)
{
	plugin_add_group(&builtin, "Features & Properties", commands);
}
