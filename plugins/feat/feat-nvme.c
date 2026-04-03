// SPDX-License-Identifier: GPL-2.0-or-later
#include <errno.h>
#include <fcntl.h>

#include "common.h"
#include "nvme-cmds.h"
#include "nvme-print.h"
#include "nvme.h"
#include "plugin.h"

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

struct err_recovery_config {
	__u8 tler;
	__u8 dulbe;
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
static const char *power_limit_feat = "power limit feature";
static const char *power_thresh_feat = "power threshold feature";
static const char *power_meas_feat = "power measurement feature";
static const char *err_recovery_feat = "error recovery feature";
static const char *num_queues_feat = "number of queues feature";

static int feat_get_nsid(struct libnvme_transport_handle *hdl, __u32 nsid,
			 const __u8 fid, __u32 cdw11, __u8 sel, __u8 uidx,
			 const char *feat)
{
	__u64 result;
	int err;
	__u32 len = 0;

	_cleanup_free_ void *buf = NULL;

	if (!NVME_CHECK(sel, GET_FEATURES_SEL, SUPPORTED))
		libnvme_get_feature_length(fid, cdw11, NVME_DATA_TFR_CTRL_TO_HOST, &len);

	if (len) {
		buf = nvme_alloc(len - 1);
		if (!buf)
			return -ENOMEM;
	}

	err = nvme_get_features(hdl, nsid, fid, sel, cdw11, uidx, buf, len,
				&result);
	if (err) {
		nvme_show_err(err, "Get %s", feat);
		return err;
	}

	nvme_show_init();

	nvme_feature_show(fid, sel, result);
	if (NVME_CHECK(sel, GET_FEATURES_SEL, SUPPORTED))
		nvme_show_select_result(fid, result);
	else
		nvme_feature_show_fields(fid, result, buf);

	nvme_show_finish();

	return err;
}

static int feat_get(struct libnvme_transport_handle *hdl, const __u8 fid,
		    __u32 cdw11, __u8 sel, __u8 uidx, const char *feat)
{
	return feat_get_nsid(hdl, 0, fid, cdw11, sel, uidx, feat);
}

static int power_mgmt_set(struct libnvme_transport_handle *hdl, const __u8 fid,
			  __u8 ps, __u8 wh, bool sv)
{
	__u32 cdw11 = NVME_SET(ps, FEAT_PWRMGMT_PS) | NVME_SET(wh, FEAT_PWRMGMT_WH);
	__u64 result;
	int err;

	err = nvme_set_features(hdl, 0, fid, sv, cdw11, 0, 0, 0, 0, NULL, 0,
			&result);

	if (err) {
		nvme_show_err(err, "Set %s", power_mgmt_feat);
		return err;
	}

	nvme_show_init();

	nvme_show_result("Set %s: 0x%04x (%s)", power_mgmt_feat, cdw11,
			 sv ? "Save" : "Not save");
	nvme_feature_show_fields(fid, cdw11, NULL);

	nvme_show_finish();

	return err;
}

static int feat_power_mgmt(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *ps = "power state";
	const char *wh = "workload hint";
	const __u8 fid = NVME_FEAT_FID_POWER_MGMT;

	_cleanup_nvme_global_ctx_ struct libnvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct libnvme_transport_handle *hdl = NULL;
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
		err = power_mgmt_set(hdl, fid, cfg.ps, cfg.wh,
				     argconfig_parse_seen(opts, "save"));
	else
		err = feat_get(hdl, fid, 0, cfg.sel, 0, power_mgmt_feat);

	return err;
}

static int perfc_set(struct libnvme_transport_handle *hdl, __u8 fid, __u32 cdw11,
		     struct perfc_config *cfg, bool sv)
{
	__u64 result;
	int err;

	_cleanup_fd_ int ffd = STDIN_FILENO;

	struct nvme_perf_characteristics data = {
		.attr_buf = { 0 },
	};

	switch (cfg->attri) {
	case NVME_FEAT_PERFC_ATTRI_STD:
		data.std_perf->r4karl = cfg->r4karl;
		break;
	case NVME_FEAT_PERFC_ATTRI_VS_MIN ... NVME_FEAT_PERFC_ATTRI_VS_MAX:
		libnvme_uuid_from_string(cfg->paid, data.vs_perf->paid);
		data.vs_perf->attrl = cfg->attrl;
		if (data.vs_perf->attrl && strlen(cfg->vs_data)) {
			ffd = open(cfg->vs_data, O_RDONLY);
			if (ffd < 0) {
				nvme_show_error("Failed to open file %s: %s", cfg->vs_data,
						libnvme_strerror(errno));
				return -EINVAL;
			}
			err = read(ffd, data.vs_perf->vs, data.vs_perf->attrl);
			if (err < 0) {
				nvme_show_error("failed to read data buffer from input file: %s",
						libnvme_strerror(errno));
				return -errno;
			}
		}
		break;
	default:
		break;
	}

	err = nvme_set_features(hdl, 0, fid, sv, cdw11, 0, 0, 0, 0, &data,
			sizeof(data), &result);
	if (err) {
		nvme_show_err(err, "Set %s", perfc_feat);
		return err;
	}

	nvme_show_init();

	nvme_show_result("Set %s: 0x%04x (%s)", perfc_feat, cdw11,
			 sv ? "Save" : "Not save");
	nvme_feature_show_fields(fid, cdw11, NULL);

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

	_cleanup_nvme_global_ctx_ struct libnvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct libnvme_transport_handle *hdl = NULL;
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

	if (argconfig_parse_seen(opts, "rvspa") ||
	    argconfig_parse_seen(opts, "r4karl") ||
	    argconfig_parse_seen(opts, "paid"))
		err = perfc_set(hdl, fid, cdw11, &cfg,
				argconfig_parse_seen(opts, "save"));
	else
		err = feat_get(hdl, fid, cdw11, cfg.sel, 0, perfc_feat);

	return err;
}

static int hctm_set(struct libnvme_transport_handle *hdl, const __u8 fid,
		    __u16 tmt1, __u16 tmt2, bool sv)
{
	__u32 cdw11 = NVME_SET(tmt1, FEAT_HCTM_TMT1)
		| NVME_SET(tmt2, FEAT_HCTM_TMT2);
	__u64 result;
	int err;

	err = nvme_set_features(hdl, 0, fid, sv, cdw11, 0, 0, 0, 0, NULL, 0,
			&result);
	if (err) {
		nvme_show_err(err, "Set %s", hctm_feat);
		return err;
	}

	nvme_show_init();

	nvme_show_result("Set %s: 0x%04x (%s)", hctm_feat, cdw11,
			 sv ? "Save" : "Not save");
	nvme_feature_show_fields(fid, cdw11, NULL);

	nvme_show_finish();

	return err;
}

static int feat_hctm(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const __u8 fid = NVME_FEAT_FID_HCTM;

	_cleanup_nvme_global_ctx_ struct libnvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct libnvme_transport_handle *hdl = NULL;
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

	if (argconfig_parse_seen(opts, "tmt1") ||
	    argconfig_parse_seen(opts, "tmt2"))
		err = hctm_set(hdl, fid, cfg.tmt1, cfg.tmt2,
			       argconfig_parse_seen(opts, "save"));
	else
		err = feat_get(hdl, fid, 0, cfg.sel, 0, hctm_feat);

	return err;
}

static int timestamp_set(struct libnvme_transport_handle *hdl, const __u8 fid,
			 __u64 tstmp, bool sv)
{
	__u64 result;
	int err;
	struct nvme_timestamp ts;
	__le64 timestamp = cpu_to_le64(tstmp);

	memcpy(ts.timestamp, &timestamp, sizeof(ts.timestamp));

	err = nvme_set_features(hdl, 0, fid, sv, 0, 0, 0, 0, 0, &ts, sizeof(ts),
			&result);
	if (err) {
		nvme_show_err(err, "Set %s", timestamp_feat);
		return err;
	}

	nvme_show_init();

	nvme_show_result("Set %s: (%s)", timestamp_feat,
			 sv ? "Save" : "Not save");
	nvme_feature_show_fields(fid, 0, (unsigned char *)&ts);

	nvme_show_finish();

	return err;
}

static int feat_timestamp(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const __u8 fid = NVME_FEAT_FID_TIMESTAMP;
	const char *tstmp = "timestamp";

	_cleanup_nvme_global_ctx_ struct libnvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct libnvme_transport_handle *hdl = NULL;
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
		err = timestamp_set(hdl, fid, cfg.tstmp,
				    argconfig_parse_seen(opts, "save"));
	else
		err = feat_get(hdl, fid, 0, cfg.sel, 0, timestamp_feat);

	return err;
}

static int temp_thresh_set(struct libnvme_transport_handle *hdl, const __u8 fid,
			   struct argconfig_commandline_options *opts,
			   struct temp_thresh_config *cfg)
{
	enum nvme_get_features_sel sel = NVME_GET_FEATURES_SEL_CURRENT;
	struct libnvme_passthru_cmd cmd;
	__u16 tmpth;
	__u8 tmpsel;
	__u8 thsel;
	__u8 tmpthh;
	int err;
	bool sv;

	sv = argconfig_parse_seen(opts, "save");
	if (sv)
		sel = NVME_GET_FEATURES_SEL_SAVED;

	nvme_init_get_features_temp_thresh(&cmd, sel, cfg->tmpsel, cfg->thsel);
	err = libnvme_submit_admin_passthru(hdl, &cmd);
	if (!err) {
		nvme_feature_decode_temp_threshold(cmd.result, &tmpth,
						   &tmpsel, &thsel, &tmpthh);
		if (!argconfig_parse_seen(opts, "tmpth"))
			cfg->tmpth = tmpth;
		if (!argconfig_parse_seen(opts, "tmpthh"))
			cfg->tmpthh = tmpthh;
	}

	nvme_init_set_features_temp_thresh(&cmd, sv, cfg->tmpth, cfg->tmpsel,
					   cfg->thsel, cfg->tmpthh);
	err = libnvme_submit_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "Set %s", temp_thresh_feat);
		return err;
	}

	nvme_show_init();

	nvme_show_result("Set %s: (%s)", temp_thresh_feat,
			 sv ? "Save" : "Not save");
	nvme_feature_show_fields(fid, NVME_SET(cfg->tmpth, FEAT_TT_TMPTH) |
				 NVME_SET(cfg->tmpsel, FEAT_TT_TMPSEL) |
				 NVME_SET(cfg->thsel, FEAT_TT_THSEL) |
				 NVME_SET(cfg->tmpthh, FEAT_TT_TMPTHH), NULL);

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

	_cleanup_nvme_global_ctx_ struct libnvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct libnvme_transport_handle *hdl = NULL;
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

	if (argconfig_parse_seen(opts, "tmpth") ||
	    argconfig_parse_seen(opts, "tmpthh"))
		err = temp_thresh_set(hdl, fid, opts, &cfg);
	else
		err = feat_get(hdl, fid, NVME_SET(cfg.tmpsel, FEAT_TT_TMPSEL) |
			       NVME_SET(cfg.thsel, FEAT_TT_THSEL), cfg.sel, 0,
			       temp_thresh_feat);

	return err;
}

static int arbitration_set(struct libnvme_transport_handle *hdl, const __u8 fid,
			   struct argconfig_commandline_options *opts,
			   struct arbitration_config *cfg)
{
	enum nvme_get_features_sel sel = NVME_GET_FEATURES_SEL_CURRENT;
	struct libnvme_passthru_cmd cmd;
	__u8 ab, lpw, mpw, hpw;
	bool sv;
	int err;

	sv = argconfig_parse_seen(opts, "save");
	if (sv)
		sel = NVME_GET_FEATURES_SEL_SAVED;

	nvme_init_get_features_arbitration(&cmd, sel);
	err = libnvme_submit_admin_passthru(hdl, &cmd);
	if (!err) {
		nvme_feature_decode_arbitration(cmd.result, &ab,
						&lpw, &mpw, &hpw);
		if (!argconfig_parse_seen(opts, "ab"))
			cfg->ab = ab;
		if (!argconfig_parse_seen(opts, "lpw"))
			cfg->lpw = lpw;
		if (!argconfig_parse_seen(opts, "mpw"))
			cfg->mpw = mpw;
		if (!argconfig_parse_seen(opts, "hpw"))
			cfg->hpw = hpw;
	}

	nvme_init_set_features_arbitration(&cmd, sv, cfg->ab, cfg->lpw,
					   cfg->mpw, cfg->hpw);
	err = libnvme_submit_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "Set %s", arbitration_feat);
		return err;
	}

	nvme_show_init();

	nvme_show_result("Set %s: (%s)", arbitration_feat,
			 sv ? "Save" : "Not save");
	nvme_feature_show_fields(fid,
				 NVME_SET(cfg->ab, FEAT_ARBITRATION_BURST) |
				 NVME_SET(cfg->lpw, FEAT_ARBITRATION_LPW) |
				 NVME_SET(cfg->mpw, FEAT_ARBITRATION_MPW) |
				 NVME_SET(cfg->hpw, FEAT_ARBITRATION_HPW),
				 NULL);

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

	_cleanup_nvme_global_ctx_ struct libnvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct libnvme_transport_handle *hdl = NULL;
	int err;

	struct arbitration_config cfg = { 0 };

	FEAT_ARGS(opts,
		  OPT_BYTE("ab", 'a', &cfg.ab, ab),
		  OPT_BYTE("lpw", 'l', &cfg.lpw, lpw),
		  OPT_BYTE("mpw", 'm', &cfg.mpw, mpw),
		  OPT_BYTE("hpw", 'H', &cfg.hpw, hpw));

	err = parse_and_open(&ctx, &hdl, argc, argv, ARBITRATION_DESC, opts);
	if (err)
		return err;

	if (argc == 2 || argconfig_parse_seen(opts, "sel"))
		return feat_get(hdl, fid, 0, cfg.sel, 0, "arbitration feature");

	return arbitration_set(hdl, fid, opts, &cfg);
}

static int volatile_wc_set(struct libnvme_transport_handle *hdl, const __u8 fid,
			   bool wce, bool sv)
{
	__u32 cdw11 = NVME_SET(wce, FEAT_VWC_WCE);
	__u64 result;
	int err;

	err = nvme_set_features(hdl, 0, fid, sv, cdw11, 0, 0, 0, 0, NULL, 0,
			&result);
	if (err) {
		nvme_show_err(err, "Set %s", volatile_wc_feat);
		return err;
	}

	nvme_show_init();

	nvme_show_result("Set %s: 0x%04x (%s)", volatile_wc_feat, cdw11,
			 sv ? "Save" : "Not save");
	nvme_feature_show_fields(fid, cdw11, NULL);

	nvme_show_finish();

	return err;
}

static int feat_volatile_wc(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const __u8 fid = NVME_FEAT_FID_VOLATILE_WC;
	const char *wce = "volatile write cache enable";

	_cleanup_nvme_global_ctx_ struct libnvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct libnvme_transport_handle *hdl = NULL;
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
		err = volatile_wc_set(hdl, fid, cfg.wce,
				      argconfig_parse_seen(opts, "save"));
	else
		err = feat_get(hdl, fid, 0, cfg.sel, 0, volatile_wc_feat);

	return err;
}

static int power_limit_set(struct libnvme_transport_handle *hdl, const __u8 fid,
			   __u8 plv, __u8 pls, __u8 uidx, bool sv)
{
	__u32 cdw13 = NVME_SET(plv, FEAT_POWER_LIMIT_PLV) |
		      NVME_SET(pls, FEAT_POWER_LIMIT_PLS);
	__u64 result;
	int err;

	err = nvme_set_features(hdl, 0, fid, sv, 0, 0, cdw13, uidx, 0, NULL, 0,
				&result);
	if (err) {
		nvme_show_err(err, "Set %s", power_limit_feat);
		return err;
	}

	nvme_show_init();

	nvme_show_result("Set %s: 0x%04x (%s)", power_limit_feat, cdw13,
			 sv ? "Save" : "Not save");
	nvme_feature_show_fields(fid, cdw13, NULL);

	nvme_show_finish();

	return err;
}

static int feat_power_limit(int argc, char **argv, struct command *acmd,
			    struct plugin *plugin)
{
	const char *plv = "power limit value";
	const char *pls = "power limit scale";
	const __u8 fid = NVME_FEAT_FID_POWER_LIMIT;

	_cleanup_nvme_global_ctx_ struct libnvme_global_ctx *ctx = NULL;

	_cleanup_nvme_transport_handle_ struct libnvme_transport_handle *hdl =
	    NULL;
	int err;

	struct config {
		__u8 plv;
		__u8 pls;
		__u8 uidx;
		__u8 sel;
	};

	struct config cfg = { 0 };

	FEAT_ARGS(opts,
		  OPT_BYTE("plv", 'p', &cfg.plv, plv),
		  OPT_BYTE("pls", 'l', &cfg.pls, pls),
		  OPT_BYTE("uuid-index", 'u', &cfg.uidx, uuid_index));

	err = parse_and_open(&ctx, &hdl, argc, argv, POWER_LIMIT_DESC, opts);
	if (err)
		return err;

	if (argconfig_parse_seen(opts, "plv"))
		err = power_limit_set(hdl, fid, cfg.plv, cfg.pls, cfg.uidx,
				      argconfig_parse_seen(opts, "save"));
	else
		err = feat_get(hdl, fid, 0, cfg.sel, cfg.uidx,
			       power_limit_feat);

	return err;
}

static int power_thresh_set(struct libnvme_transport_handle *hdl, const __u8 fid,
			    __u16 ptv, __u8 pts, __u8 pmts, __u8 ept, __u8 uidx,
			    bool sv)
{
	__u32 cdw11 = NVME_SET(ptv, FEAT_POWER_THRESH_PTV) |
		      NVME_SET(pmts, FEAT_POWER_THRESH_PMTS) |
		      NVME_SET(pts, FEAT_POWER_THRESH_PTS) |
		      NVME_SET(ept, FEAT_POWER_THRESH_EPT);
	__u64 result;
	int err;

	err = nvme_set_features(hdl, 0, fid, sv, cdw11, 0, 0, uidx, 0, NULL, 0,
				&result);
	if (err) {
		nvme_show_err(err, "Set %s", power_thresh_feat);
		return err;
	}

	nvme_show_init();

	nvme_show_result("Set %s: 0x%04x (%s)", power_thresh_feat,
			 cdw11, sv ? "Save" : "Not save");
	nvme_feature_show_fields(fid, cdw11, NULL);

	nvme_show_finish();

	return err;
}

static int feat_power_thresh(int argc, char **argv, struct command *acmd,
			     struct plugin *plugin)
{
	const char *ptv = "power threshold value";
	const char *pts = "power threshold scale";
	const char *pmts = "power measurement type select";
	const char *ept = "enable power threshold";
	const __u8 fid = NVME_FEAT_FID_POWER_THRESH;

	_cleanup_nvme_global_ctx_ struct libnvme_global_ctx *ctx = NULL;

	_cleanup_nvme_transport_handle_ struct libnvme_transport_handle *hdl =
	    NULL;
	int err;

	struct config {
		__u16 ptv;
		__u8 pts;
		__u8 pmts;
		__u8 ept;
		__u8 uidx;
		__u8 sel;
	};

	struct config cfg = { 0 };

	FEAT_ARGS(opts,
		  OPT_SHRT("ptv", 'p', &cfg.ptv, ptv),
		  OPT_BYTE("pts", 't', &cfg.pts, pts),
		  OPT_BYTE("pmts", 'm', &cfg.pmts, pmts),
		  OPT_BYTE("ept", 'e', &cfg.ept, ept),
		  OPT_BYTE("uuid-index", 'u', &cfg.uidx, uuid_index));

	err = parse_and_open(&ctx, &hdl, argc, argv, POWER_THRESH_DESC, opts);
	if (err)
		return err;

	if (argconfig_parse_seen(opts, "ptv") ||
	    argconfig_parse_seen(opts, "pts") ||
	    argconfig_parse_seen(opts, "pmts") ||
	    argconfig_parse_seen(opts, "ept"))
		err = power_thresh_set(hdl, fid, cfg.ptv, cfg.pts, cfg.pmts,
				       cfg.ept, cfg.uidx,
				       argconfig_parse_seen(opts, "save"));
	else
		err = feat_get(hdl, fid, 0, cfg.sel, cfg.uidx,
			       power_thresh_feat);

	return err;
}

static int power_meas_set(struct libnvme_transport_handle *hdl, const __u8 fid,
			  __u8 action, __u8 pmts, __u16 smt, __u8 uidx, bool sv)
{
	__u32 cdw11 = NVME_SET(action, FEAT_POWER_MEAS_ACT) |
		      NVME_SET(pmts, FEAT_POWER_MEAS_PMTS) |
		      NVME_SET(smt, FEAT_POWER_MEAS_SMT);
	__u64 result;
	int err;

	err = nvme_set_features(hdl, 0, fid, sv, cdw11, 0, 0, uidx, 0, NULL, 0,
			&result);
	if (err) {
		nvme_show_err(err, "Set %s", power_meas_feat);
		return err;
	}

	nvme_show_init();

	nvme_show_result("Set %s: 0x%04x (%s)", power_meas_feat, cdw11,
			 sv ? "Save" : "Not save");
	nvme_feature_show_fields(fid, cdw11, NULL);

	nvme_show_finish();

	return err;
}

static int feat_power_meas(int argc, char **argv, struct command *cmd,
			   struct plugin *plugin)
{
	const char *action = "action [0-1]: stop|start";
	const char *pmts = "power measurement type select";
	const char *smt = "stop measurement time";
	const __u8 fid = NVME_FEAT_FID_POWER_MEASUREMENT;

	_cleanup_nvme_global_ctx_ struct libnvme_global_ctx *ctx = NULL;

	_cleanup_nvme_transport_handle_ struct libnvme_transport_handle *hdl =
	    NULL;
	int err;

	struct config {
		__u8 act;
		__u8 pmts;
		__u16 smt;
		__u8 uidx;
		__u8 sel;
	};

	struct config cfg = { 0 };

	FEAT_ARGS(opts,
		  OPT_BYTE("act", 0, &cfg.act, action),
		  OPT_BYTE("pmts", 0, &cfg.pmts, pmts),
		  OPT_SHRT("smt", 0, &cfg.smt, smt),
		  OPT_BYTE("uuid-index", 'u', &cfg.uidx, uuid_index));

	err = parse_and_open(&ctx, &hdl, argc, argv, POWER_MEAS_DESC, opts);
	if (err)
		return err;

	if (argconfig_parse_seen(opts, "act") ||
	    argconfig_parse_seen(opts, "pmts") ||
	    argconfig_parse_seen(opts, "smt"))
		err = power_meas_set(hdl, fid, cfg.act, cfg.pmts, cfg.smt,
				     cfg.uidx,
				     argconfig_parse_seen(opts, "save"));
	else
		err = feat_get(hdl, fid, 0, cfg.sel, 0, power_meas_feat);

	return err;
}

static int err_recovery_set(struct libnvme_transport_handle *hdl, const __u8 fid,
			    __u32 nsid, __u16 tler, bool dulbe, bool sv)
{
	__u32 cdw11 = NVME_SET(tler, FEAT_ERROR_RECOVERY_TLER) |
		      NVME_SET(dulbe, FEAT_ERROR_RECOVERY_DULBE);
	__u64 result;
	int err;

	err = nvme_set_features(hdl, nsid, fid, sv, cdw11, 0, 0, 0, 0, NULL, 0,
				&result);
	if (err) {
		nvme_show_err(err, "Set %s", err_recovery_feat);
		return err;
	}

	nvme_show_init();

	nvme_show_result("Set %s: 0x%04x (%s)", err_recovery_feat, cdw11,
			 sv ? "Save" : "Not save");
	nvme_feature_show_fields(fid, cdw11, NULL);

	nvme_show_finish();

	return err;
}

static int feat_err_recovery(int argc, char **argv, struct command *acmd,
			     struct plugin *plugin)
{
	_cleanup_nvme_transport_handle_ struct libnvme_transport_handle *hdl =
	    NULL;
	_cleanup_nvme_global_ctx_ struct libnvme_global_ctx *ctx = NULL;

	const char *dulbe =
	    "deallocated or unwritten logical block error enable";
	const char *tler = "time limited error recovery";
	const __u8 fid = NVME_FEAT_FID_ERR_RECOVERY;

	int err;

	struct config {
		__u32 nsid;
		__u16 tler;
		bool dulbe;
		__u8 sel;
	};

	struct config cfg = { 0 };

	FEAT_ARGS(opts,
		  OPT_UINT("nsid", 'n', &cfg.nsid, namespace_id_desired),
		  OPT_SHRT("tler", 't', &cfg.tler, tler),
		  OPT_FLAG("dulbe", 'd', &cfg.dulbe, dulbe));

	err = parse_and_open(&ctx, &hdl, argc, argv, ERR_RECOVERY_DESC, opts);
	if (err)
		return err;

	if (argconfig_parse_seen(opts, "tler") ||
	    argconfig_parse_seen(opts, "dulbe"))
		err = err_recovery_set(hdl, fid, cfg.nsid, cfg.tler, cfg.dulbe,
				       argconfig_parse_seen(opts, "save"));
	else
		err = feat_get_nsid(hdl, cfg.nsid, fid, 0, cfg.sel, 0,
				    err_recovery_feat);

	return err;
}

static int num_queues_set(struct libnvme_transport_handle *hdl, const __u8 fid,
			  __u16 nsqr, __u16 ncqr, bool sv,
			  struct argconfig_commandline_options *opts)
{
	enum nvme_get_features_sel sel = NVME_GET_FEATURES_SEL_CURRENT;
	__u32 cdw11 = NVME_SET(nsqr, FEAT_NRQS_NSQR) |
		      NVME_SET(ncqr, FEAT_NRQS_NCQR);
	struct libnvme_passthru_cmd cmd;
	__u64 result;
	int err;

	if (sv)
		sel = NVME_GET_FEATURES_SEL_SAVED;

	nvme_init_get_features_num_queues(&cmd, sel);
	err = libnvme_submit_admin_passthru(hdl, &cmd);
	if (!err) {
		nvme_feature_decode_number_of_queues(cmd.result, &nsqr, &ncqr);
		if (!argconfig_parse_seen(opts, "nsqr"))
			cdw11 |= NVME_SET(nsqr, FEAT_NRQS_NSQR);
		if (!argconfig_parse_seen(opts, "ncqr"))
			cdw11 |= NVME_SET(ncqr, FEAT_NRQS_NSQR);
	}

	err = nvme_set_features(hdl, 0, fid, sv, cdw11, 0, 0, 0, 0, NULL, 0,
				&result);
	if (err) {
		nvme_show_err(err, "Set %s", num_queues_feat);
		return err;
	}

	nvme_show_init();

	nvme_show_result("Set %s: 0x%04x (%s)", num_queues_feat, cdw11,
			 sv ? "Save" : "Not save");
	nvme_feature_show_fields(fid, cdw11, NULL);

	nvme_show_finish();

	return err;
}

static int feat_num_queues(int argc, char **argv, struct command *acmd,
			     struct plugin *plugin)
{
	_cleanup_nvme_transport_handle_ struct libnvme_transport_handle *hdl =
	    NULL;
	_cleanup_nvme_global_ctx_ struct libnvme_global_ctx *ctx = NULL;

	const char *ncqr = "number of I/O completion queues requested";
	const char *nsqr = "number of I/O submission queues requested";
	const __u8 fid = NVME_FEAT_FID_NUM_QUEUES;
	int err;

	struct config {
		__u16 nsqr;
		__u16 ncqr;
		__u8 sel;
	};

	struct config cfg = { 0 };

	FEAT_ARGS(opts,
		  OPT_SHRT("nsqr", 'n', &cfg.nsqr, nsqr),
		  OPT_SHRT("ncqr", 'c', &cfg.ncqr, ncqr));

	err = parse_and_open(&ctx, &hdl, argc, argv, NUM_QUEUES_DESC, opts);
	if (err)
		return err;

	if (argconfig_parse_seen(opts, "nsqr") ||
	    argconfig_parse_seen(opts, "ncqr"))
		err = num_queues_set(hdl, fid, cfg.nsqr, cfg.ncqr,
				     argconfig_parse_seen(opts, "save"), opts);
	else
		err = feat_get(hdl, fid, 0, cfg.sel, 0, num_queues_feat);

	return err;
}
