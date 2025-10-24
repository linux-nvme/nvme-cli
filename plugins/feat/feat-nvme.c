// SPDX-License-Identifier: GPL-2.0-or-later
#include <errno.h>
#include <fcntl.h>
#include "nvme.h"
#include "plugin.h"
#include "nvme-print.h"
#include "common.h"

#define CREATE_CMD
#include "feat-nvme.h"

#define STR(x) #x
#define TMT(n) "thermal management temperature " STR(n)

struct perfc_config {
	__u32 namespace_id;
	__u8 attri;
	bool rvspa;
	__u8 r4karl;
	char *paid;
	__u16 attrl;
	char *vs_data;
	__u8 sel;
};

struct temp_thresh_config {
	__u16 tmpth;
	__u8 tmpsel;
	__u8 thsel;
	__u8 tmpthh;
	__u8 sel;
};

struct arbitration_config {
	__u8 ab;
	__u8 lpw;
	__u8 mpw;
	__u8 hpw;
	__u8 sel;
};

static const char *power_mgmt_feat = "power management feature";
static const char *sel = "[0-3]: current/default/saved/supported";
static const char *save = "Specifies that the controller shall save the attribute";
static const char *perfc_feat = "performance characteristics feature";
static const char *hctm_feat = "host controlled thermal management feature";
static const char *timestamp_feat = "timestamp feature";
static const char *temp_thresh_feat = "temperature threshold feature";
static const char *arbitration_feat = "arbitration feature";
static const char *volatile_wc_feat = "volatile write cache feature";

static int feat_get(struct nvme_transport_handle *hdl, const __u8 fid,
		    __u32 cdw11, __u8 sel, const char *feat)
{
	__u32 result;
	int err;
	__u32 len = 0;

	_cleanup_free_ void *buf = NULL;

	if (!NVME_CHECK(sel, GET_FEATURES_SEL, SUPPORTED))
		nvme_get_feature_length(fid, cdw11, NVME_DATA_TFR_CTRL_TO_HOST, &len);

	if (len) {
		buf = nvme_alloc(len - 1);
		if (!buf)
			return -ENOMEM;
	}

	struct nvme_get_features_args args = {
		.args_size = sizeof(args),
		.fid = fid,
		.sel = sel,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result = &result,
		.cdw11 = cdw11,
		.data = buf,
		.data_len = len,
	};

	err = nvme_get_features(hdl, &args);

	nvme_show_init();

	if (!err) {
		nvme_feature_show(fid, sel, result);
		if (NVME_CHECK(sel, GET_FEATURES_SEL, SUPPORTED))
			nvme_show_select_result(fid, result);
		else
			nvme_feature_show_fields(fid, result, buf);
	} else if (err > 0) {
		nvme_show_status(err);
	} else {
		nvme_show_error("Get %s: %s", feat, nvme_strerror(errno));
	}

	nvme_show_finish();

	return err;
}

static int power_mgmt_set(struct nvme_transport_handle *hdl, const __u8 fid,
			  __u8 ps, __u8 wh, bool save)
{
	__u32 result;
	int err;

	struct nvme_set_features_args args = {
		.args_size = sizeof(args),
		.fid = fid,
		.cdw11 = NVME_SET(ps, FEAT_PWRMGMT_PS) | NVME_SET(wh, FEAT_PWRMGMT_WH),
		.save = save,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result = &result,
	};

	err = nvme_set_features(hdl, &args);

	nvme_show_init();

	if (err > 0) {
		nvme_show_status(err);
	} else if (err < 0) {
		nvme_show_perror("Set %s", power_mgmt_feat);
	} else {
		nvme_show_result("Set %s: 0x%04x (%s)", power_mgmt_feat, args.cdw11,
				 save ? "Save" : "Not save");
		nvme_feature_show_fields(fid, args.cdw11, NULL);
	}

	nvme_show_finish();

	return err;
}

static int feat_power_mgmt(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *ps = "power state";
	const char *wh = "workload hint";
	const __u8 fid = NVME_FEAT_FID_POWER_MGMT;

	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	int err;

	struct config {
		__u8 ps;
		__u8 wh;
		__u8 sel;
	};

	struct config cfg = { 0 };

	FEAT_ARGS(opts,
		  OPT_BYTE("ps", 'p', &cfg.ps, ps),
		  OPT_BYTE("wh", 'w', &cfg.wh, wh));

	err = parse_and_open(&ctx, &hdl, argc, argv, POWER_MGMT_DESC, opts);
	if (err)
		return err;

	if (argconfig_parse_seen(opts, "ps"))
		err = power_mgmt_set(hdl, fid, cfg.ps, cfg.wh, argconfig_parse_seen(opts, "save"));
	else
		err = feat_get(hdl, fid, 0, cfg.sel, power_mgmt_feat);

	return err;
}

static int perfc_set(struct nvme_transport_handle *hdl, __u8 fid, __u32 cdw11,
		     struct perfc_config *cfg, bool save)
{
	__u32 result;
	int err;

	_cleanup_fd_ int ffd = STDIN_FILENO;

	struct nvme_perf_characteristics data = {
		.attr_buf = { 0 },
	};

	struct nvme_set_features_args args = {
		.args_size = sizeof(args),
		.fid = fid,
		.cdw11 = cdw11,
		.save = save,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result = &result,
		.data = &data,
		.data_len = sizeof(data),
	};

	switch (cfg->attri) {
	case NVME_FEAT_PERFC_ATTRI_STD:
		data.std_perf->r4karl = cfg->r4karl;
		break;
	case NVME_FEAT_PERFC_ATTRI_VS_MIN ... NVME_FEAT_PERFC_ATTRI_VS_MAX:
		nvme_uuid_from_string(cfg->paid, data.vs_perf->paid);
		data.vs_perf->attrl = cfg->attrl;
		if (data.vs_perf->attrl && strlen(cfg->vs_data)) {
			ffd = open(cfg->vs_data, O_RDONLY);
			if (ffd < 0) {
				nvme_show_error("Failed to open file %s: %s", cfg->vs_data,
						strerror(errno));
				return -EINVAL;
			}
			err = read(ffd, data.vs_perf->vs, data.vs_perf->attrl);
			if (err < 0) {
				nvme_show_error("failed to read data buffer from input file: %s",
						strerror(errno));
				return -errno;
			}
		}
		break;
	default:
		break;
	}

	err = nvme_set_features(hdl, &args);

	nvme_show_init();

	if (err > 0) {
		nvme_show_status(err);
	} else if (err < 0) {
		nvme_show_perror("Set %s", perfc_feat);
	} else {
		nvme_show_result("Set %s: 0x%04x (%s)", perfc_feat, args.cdw11,
				 save ? "Save" : "Not save");
		nvme_feature_show_fields(args.fid, args.cdw11, NULL);
	}

	nvme_show_finish();

	return err;
}

static int feat_perfc(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *namespace_id_optional = "optional namespace attached to controller";
	const char *attri = "attribute index";
	const char *rvspa = "revert vendor specific performance attribute";
	const char *r4karl = "random 4 kib average read latency";
	const char *paid = "performance attribute identifier";
	const char *attrl = "attribute length";
	const char *vs_data = "vendor specific data";

	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	int err;
	__u8 fid = NVME_FEAT_FID_PERF_CHARACTERISTICS;
	__u32 cdw11;

	struct perfc_config cfg = { 0 };

	FEAT_ARGS(opts,
		  OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id_optional),
		  OPT_BYTE("attri", 'a', &cfg.attri, attri),
		  OPT_FLAG("rvspa", 'r', &cfg.rvspa, rvspa),
		  OPT_BYTE("r4karl", 'R', &cfg.r4karl, r4karl),
		  OPT_STR("paid", 'p', &cfg.paid, paid),
		  OPT_SHRT("attrl", 'A', &cfg.attrl, attrl),
		  OPT_FILE("vs-data", 'V', &cfg.vs_data, vs_data));

	err = parse_and_open(&ctx, &hdl, argc, argv, PERFC_DESC, opts);
	if (err)
		return err;

	cdw11 = NVME_SET(cfg.attri, FEAT_PERFC_ATTRI) | NVME_SET(cfg.rvspa, FEAT_PERFC_RVSPA);

	if (argconfig_parse_seen(opts, "rvspa") || argconfig_parse_seen(opts, "r4karl") ||
	    argconfig_parse_seen(opts, "paid"))
		err = perfc_set(hdl, fid, cdw11, &cfg, argconfig_parse_seen(opts, "save"));
	else
		err = feat_get(hdl, fid, cdw11, cfg.sel, perfc_feat);

	return err;
}

static int hctm_set(struct nvme_transport_handle *hdl, const __u8 fid,
		    __u16 tmt1, __u16 tmt2, bool save)
{
	__u32 result;
	int err;

	struct nvme_set_features_args args = {
		.args_size = sizeof(args),
		.fid = fid,
		.cdw11 = NVME_SET(tmt1, FEAT_HCTM_TMT1) | NVME_SET(tmt2, FEAT_HCTM_TMT2),
		.save = save,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result = &result,
	};

	err = nvme_set_features(hdl, &args);

	nvme_show_init();

	if (err > 0) {
		nvme_show_status(err);
	} else if (err < 0) {
		nvme_show_perror("Set %s", hctm_feat);
	} else {
		nvme_show_result("Set %s: 0x%04x (%s)", hctm_feat, args.cdw11,
				 save ? "Save" : "Not save");
		nvme_feature_show_fields(fid, args.cdw11, NULL);
	}

	nvme_show_finish();

	return err;
}

static int feat_hctm(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const __u8 fid = NVME_FEAT_FID_HCTM;

	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	int err;

	struct config {
		__u16 tmt1;
		__u16 tmt2;
		__u8 sel;
	};

	struct config cfg = { 0 };

	FEAT_ARGS(opts,
		  OPT_SHRT("tmt1", 't', &cfg.tmt1, TMT(1)),
		  OPT_SHRT("tmt2", 'T', &cfg.tmt2, TMT(2)));

	err = parse_and_open(&ctx, &hdl, argc, argv, HCTM_DESC, opts);
	if (err)
		return err;

	if (argconfig_parse_seen(opts, "tmt1") || argconfig_parse_seen(opts, "tmt2"))
		err = hctm_set(hdl, fid, cfg.tmt1, cfg.tmt2, argconfig_parse_seen(opts, "save"));
	else
		err = feat_get(hdl, fid, 0, cfg.sel, hctm_feat);

	return err;
}

static int timestamp_set(struct nvme_transport_handle *hdl, const __u8 fid,
			 __u64 tstmp, bool save)
{
	__u32 result;
	int err;
	struct nvme_timestamp ts;
	__le64 timestamp = cpu_to_le64(tstmp);

	struct nvme_set_features_args args = {
		.args_size = sizeof(args),
		.fid = fid,
		.save = save,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result = &result,
		.data = &ts,
		.data_len = sizeof(ts),
	};

	memcpy(ts.timestamp, &timestamp, sizeof(ts.timestamp));

	err = nvme_set_features(hdl, &args);

	nvme_show_init();

	if (err > 0) {
		nvme_show_status(err);
	} else if (err < 0) {
		nvme_show_perror("Set %s", timestamp_feat);
	} else {
		nvme_show_result("Set %s: (%s)", timestamp_feat, save ? "Save" : "Not save");
		nvme_feature_show_fields(fid, args.cdw11, args.data);
	}

	nvme_show_finish();

	return err;
}

static int feat_timestamp(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const __u8 fid = NVME_FEAT_FID_TIMESTAMP;
	const char *tstmp = "timestamp";

	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	int err;

	struct config {
		__u64 tstmp;
		__u8 sel;
	};

	struct config cfg = { 0 };

	FEAT_ARGS(opts, OPT_LONG("tstmp", 't', &cfg.tstmp, tstmp));

	err = parse_and_open(&ctx, &hdl, argc, argv, TIMESTAMP_DESC, opts);
	if (err)
		return err;

	if (argconfig_parse_seen(opts, "tstmp"))
		err = timestamp_set(hdl, fid, cfg.tstmp, argconfig_parse_seen(opts, "save"));
	else
		err = feat_get(hdl, fid, 0, cfg.sel, timestamp_feat);

	return err;
}

static int temp_thresh_set(struct nvme_transport_handle *hdl, const __u8 fid,
			   struct argconfig_commandline_options *opts,
			   struct temp_thresh_config *cfg)
{
	__u32 result;
	int err;
	enum nvme_get_features_sel sel = NVME_GET_FEATURES_SEL_CURRENT;
	__u16 tmpth;
	__u8 tmpsel;
	__u8 thsel;
	__u8 tmpthh;
	bool save = argconfig_parse_seen(opts, "save");

	if (save)
		sel = NVME_GET_FEATURES_SEL_SAVED;

	err = nvme_get_features_temp_thresh(hdl, sel, cfg->tmpsel, cfg->thsel, &result);
	if (!err) {
		nvme_feature_decode_temp_threshold(result, &tmpth, &tmpsel, &thsel, &tmpthh);
		if (!argconfig_parse_seen(opts, "tmpth"))
			cfg->tmpth = tmpth;
		if (!argconfig_parse_seen(opts, "tmpthh"))
			cfg->tmpthh = tmpthh;
	}

	err = nvme_set_features_temp_thresh(hdl, cfg->tmpth, cfg->tmpsel, cfg->thsel, cfg->tmpthh,
					    save, &result);

	nvme_show_init();

	if (err > 0) {
		nvme_show_status(err);
	} else if (err < 0) {
		nvme_show_perror("Set %s", temp_thresh_feat);
	} else {
		nvme_show_result("Set %s: (%s)", temp_thresh_feat, save ? "Save" : "Not save");
		nvme_feature_show_fields(fid, NVME_SET(cfg->tmpth, FEAT_TT_TMPTH) |
					 NVME_SET(cfg->tmpsel, FEAT_TT_TMPSEL) |
					 NVME_SET(cfg->thsel, FEAT_TT_THSEL) |
					 NVME_SET(cfg->tmpthh, FEAT_TT_TMPTHH), NULL);
	}

	nvme_show_finish();

	return err;
}

static int feat_temp_thresh(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const __u8 fid = NVME_FEAT_FID_TEMP_THRESH;
	const char *tmpth = "temperature threshold";
	const char *tmpsel = "threshold temperature select";
	const char *thsel = "threshold type select";
	const char *tmpthh = "temperature threshold hysteresis";

	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	int err;

	struct temp_thresh_config cfg = { 0 };

	FEAT_ARGS(opts,
		  OPT_SHRT("tmpth", 'T', &cfg.tmpth, tmpth),
		  OPT_BYTE("tmpsel", 'm', &cfg.tmpsel, tmpsel),
		  OPT_BYTE("thsel", 'H', &cfg.thsel, thsel),
		  OPT_BYTE("tmpthh", 'M', &cfg.tmpthh, tmpthh));

	err = parse_and_open(&ctx, &hdl, argc, argv, TEMP_THRESH_DESC, opts);
	if (err)
		return err;

	if (argconfig_parse_seen(opts, "tmpth") || argconfig_parse_seen(opts, "tmpthh"))
		err = temp_thresh_set(hdl, fid, opts, &cfg);
	else
		err = feat_get(hdl, fid, NVME_SET(cfg.tmpsel, FEAT_TT_TMPSEL) |
			       NVME_SET(cfg.thsel, FEAT_TT_THSEL), cfg.sel, temp_thresh_feat);

	return err;
}

static int arbitration_set(struct nvme_transport_handle *hdl, const __u8 fid,
			   struct argconfig_commandline_options *opts,
			   struct arbitration_config *cfg)
{
	enum nvme_get_features_sel sel = NVME_GET_FEATURES_SEL_CURRENT;
	bool save = argconfig_parse_seen(opts, "save");
	__u8 ab, lpw, mpw, hpw;
	__u32 result;
	int err;

	if (save)
		sel = NVME_GET_FEATURES_SEL_SAVED;

	err = nvme_get_features_arbitration(hdl, sel, &result);
	if (!err) {
		nvme_feature_decode_arbitration(result, &ab, &lpw, &mpw, &hpw);
		if (!argconfig_parse_seen(opts, "ab"))
			cfg->ab = ab;
		if (!argconfig_parse_seen(opts, "lpw"))
			cfg->lpw = lpw;
		if (!argconfig_parse_seen(opts, "mpw"))
			cfg->mpw = mpw;
		if (!argconfig_parse_seen(opts, "hpw"))
			cfg->hpw = hpw;
	}

	err = nvme_set_features_arbitration(hdl, cfg->ab, cfg->lpw, cfg->mpw, cfg->hpw,
					    save, &result);

	nvme_show_init();

	if (err > 0) {
		nvme_show_status(err);
	} else if (err < 0) {
		nvme_show_perror("Set %s", temp_thresh_feat);
	} else {
		nvme_show_result("Set %s: (%s)", arbitration_feat, save ? "Save" : "Not save");
		nvme_feature_show_fields(fid, NVME_SET(cfg->ab, FEAT_ARBITRATION_BURST) |
					 NVME_SET(cfg->lpw, FEAT_ARBITRATION_LPW) |
					 NVME_SET(cfg->mpw, FEAT_ARBITRATION_MPW) |
					 NVME_SET(cfg->hpw, FEAT_ARBITRATION_HPW), NULL);
	}

	nvme_show_finish();

	return err;
}

static int feat_arbitration(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const __u8 fid = NVME_FEAT_FID_ARBITRATION;
	const char *ab = "arbitration burst";
	const char *lpw = "low priority weight";
	const char *mpw = "medium priority weight";
	const char *hpw = "high priority weight";

	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	int err;

	struct arbitration_config cfg = { 0 };

	FEAT_ARGS(opts,
		  OPT_BYTE("ab", 'a', &cfg.ab, ab),
		  OPT_BYTE("lpw", 'l', &cfg.lpw, lpw),
		  OPT_BYTE("mpw", 'm', &cfg.mpw, mpw),
		  OPT_BYTE("hpw", 'H', &cfg.hpw, hpw));

	err = parse_and_open(&ctx, &hdl, argc, argv, TEMP_THRESH_DESC, opts);
	if (err)
		return err;

	if (argc == 2 || argconfig_parse_seen(opts, "sel"))
		return feat_get(hdl, fid, 0, cfg.sel, "arbitration feature");

	return arbitration_set(hdl, fid, opts, &cfg);
}

static int volatile_wc_set(struct nvme_transport_handle *hdl, const __u8 fid,
			   bool wce, bool save)
{
	__u32 result;
	int err;

	struct nvme_set_features_args args = {
		.args_size = sizeof(args),
		.fid = fid,
		.cdw11 = NVME_SET(wce, FEAT_VWC_WCE),
		.save = save,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result = &result,
	};

	err = nvme_set_features(hdl, &args);

	nvme_show_init();

	if (err > 0) {
		nvme_show_status(err);
	} else if (err < 0) {
		nvme_show_perror("Set %s", volatile_wc_feat);
	} else {
		nvme_show_result("Set %s: 0x%04x (%s)", volatile_wc_feat, args.cdw11,
				 save ? "Save" : "Not save");
		nvme_feature_show_fields(fid, args.cdw11, NULL);
	}

	nvme_show_finish();

	return err;
}

static int feat_volatile_wc(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const __u8 fid = NVME_FEAT_FID_VOLATILE_WC;
	const char *wce = "volatile write cache enable";

	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	int err;

	struct config {
		bool wce;
		__u8 sel;
	};

	struct config cfg = { 0 };

	FEAT_ARGS(opts, OPT_FLAG("wce", 'w', &cfg.wce, wce));

	err = parse_and_open(&ctx, &hdl, argc, argv, VOLATILE_WC_DESC, opts);
	if (err)
		return err;

	if (argconfig_parse_seen(opts, "wce"))
		err = volatile_wc_set(hdl, fid, cfg.wce, argconfig_parse_seen(opts, "save"));
	else
		err = feat_get(hdl, fid, 0, cfg.sel, volatile_wc_feat);

	return err;
}
