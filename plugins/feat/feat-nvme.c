// SPDX-License-Identifier: GPL-2.0-or-later
#include "nvme.h"
#include "plugin.h"
#include "nvme-print.h"

#define CREATE_CMD
#include "feat-nvme.h"

static const char *power_mgmt_feat = "power management feature";
static const char *sel = "[0-3]: current/default/saved/supported";
static const char *save = "Specifies that the controller shall save the attribute";

static int power_mgmt_get(struct nvme_dev *dev, const __u8 fid, __u8 sel)
{
	__u32 result;
	int err;

	struct nvme_get_features_args args = {
		.args_size	= sizeof(args),
		.fd		= dev_fd(dev),
		.fid		= fid,
		.sel		= sel,
		.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
		.result		= &result,
	};

	err = nvme_get_features(&args);
	if (!err) {
		if (NVME_CHECK(sel, GET_FEATURES_SEL, SUPPORTED))
			nvme_show_select_result(fid, result);
		else
			nvme_feature_show_fields(fid, result, NULL);
	} else {
		nvme_show_error("Get %s", power_mgmt_feat);
	}

	return err;
}

static int power_mgmt_set(struct nvme_dev *dev, const __u8 fid, __u8 ps, __u8 wh, bool save)
{
	__u32 result;
	int err;

	struct nvme_set_features_args args = {
		.args_size = sizeof(args),
		.fd = dev_fd(dev),
		.fid = fid,
		.cdw11 = NVME_SET(ps, FEAT_PWRMGMT_PS) | NVME_SET(wh, FEAT_PWRMGMT_WH),
		.save = save,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result = &result,
	};

	err = nvme_set_features(&args);

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

static int feat_power_mgmt(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *ps = "power state";
	const char *wh = "workload hint";
	const __u8 fid = NVME_FEAT_FID_POWER_MGMT;

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	int err;

	struct config {
		__u8 ps;
		__u8 wh;
		bool save;
		__u8 sel;
	};

	struct config cfg = { 0 };

	NVME_ARGS(opts,
		  OPT_BYTE("ps", 'p', &cfg.ps, ps),
		  OPT_BYTE("wh", 'w', &cfg.wh, wh),
		  OPT_FLAG("save", 's', &cfg.save, save),
		  OPT_BYTE("sel", 'S', &cfg.sel, sel));

	err = parse_and_open(&dev, argc, argv, POWER_MGMT_DESC, opts);
	if (err)
		return err;

	if (argconfig_parse_seen(opts, "ps"))
		err = power_mgmt_set(dev, fid, cfg.ps, cfg.wh, cfg.save);
	else
		err = power_mgmt_get(dev, fid, cfg.sel);

	return err;
}
