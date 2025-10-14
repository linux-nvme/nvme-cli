// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2022 Solidigm.
 *
 * Authors: haro.panosyan@solidigm.com
 *          leonardo.da.cunha@solidigm.com
 */

#include <unistd.h>
#include "util/types.h"
#include "ocp-nvme.h"
#include "ocp-utils.h"
#include "nvme-print.h"

static int ocp_clear_feature(int argc, char **argv, const char *desc, const __u8 fid)
{
	__u32 result = 0;
	__u32 clear = 1 << 31;
	struct nvme_dev *dev;
	__u8 uuid_index = 0;
	bool uuid = true;
	int err;

	OPT_ARGS(opts) = {
		OPT_FLAG("no-uuid", 'n', NULL,
			 "Skip UUID index search (UUID index not required for OCP 1.0)"),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	if (opts[0].seen)
		uuid = false;

	if (uuid) {
		/* OCP 2.0 requires UUID index support */
		err = ocp_get_uuid_index(dev, &uuid_index);
		if (err || !uuid_index) {
			fprintf(stderr, "ERROR: No OCP UUID index found\n");
			goto close_dev;
		}
	}

	struct nvme_set_features_args args = {
		.result = &result,
		.data = NULL,
		.args_size = sizeof(args),
		.fd = dev_fd(dev),
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.nsid = 0,
		.cdw11 = clear,
		.cdw12 = 0,
		.cdw13 = 0,
		.cdw15 = 0,
		.data_len = 0,
		.save = 0,
		.uuidx = uuid_index,
		.fid = fid,
	};

	err = nvme_set_features(&args);

	if (err == 0)
		printf("Success : %s\n", desc);
	else if (err > 0)
		nvme_show_status(err);
	else
		printf("Fail : %s\n", desc);
close_dev:
	/* Redundant close() to make static code analysis happy */
	close(dev->direct.fd);
	dev_close(dev);
	return err;
}

int get_ocp_error_counters(int argc, char **argv, struct command *cmd,
			   struct plugin *plugin)
{
	const char *desc = "Define Issue Get Feature cmd (FID: 0xC3) Clear PCIe Corr Err Counters";
	const char *sel = "[0-3]: current/default/saved/supported/";
	const char *nsid = "Byte[04-07]: Namespace Identifier Valid/Invalid/Inactive";
	const char *no_uuid = "Do not try to automatically detect UUID index";

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;

	__u32 result;
	int err;
	bool uuid;
	__u8 uuid_index = 0;

	struct config {
		__u8 sel;
		__u32 nsid;
	};

	struct config cfg = {
		.sel = 0,
		.nsid = 0,
	};

	OPT_ARGS(opts) = {
		OPT_BYTE("sel", 's', &cfg.sel, sel),
		OPT_UINT("namespace-id", 'n', &cfg.nsid, nsid),
		OPT_FLAG("no-uuid", 'u', NULL, no_uuid),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	uuid = !argconfig_parse_seen(opts, "no-uuid");

	if (uuid) {
		/* OCP 2.0 requires UUID index support */
		err = ocp_get_uuid_index(dev, &uuid_index);
		if (err || !uuid_index) {
			nvme_show_error("ERROR: No OCP UUID index found");
			return err;
		}
	}

	struct nvme_get_features_args args = {
		.args_size  = sizeof(args),
		.fd         = dev_fd(dev),
		.fid        = OCP_FID_CPCIE,
		.nsid       = cfg.nsid,
		.sel        = cfg.sel,
		.cdw11      = 0,
		.uuidx      = uuid_index,
		.data_len   = 0,
		.data       = NULL,
		.timeout    = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result     = &result,
	};

	err = nvme_get_features(&args);
	if (!err) {
		printf("get-feature:0xC3 %s value: %#08x\n",
		nvme_select_to_string(cfg.sel), result);

		if (cfg.sel == NVME_GET_FEATURES_SEL_SUPPORTED)
			nvme_show_select_result(0xC3, result);
	} else {
		nvme_show_error("Could not get feature: 0xC3");
	}

	return err;
}

int ocp_clear_fw_update_history(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "OCP Clear Firmware Update History";

	return ocp_clear_feature(argc, argv, desc, OCP_FID_CFUH);
}

int ocp_clear_pcie_correctable_errors(int argc, char **argv, struct command *cmd,
				      struct plugin *plugin)
{
	const char *desc = "OCP Clear PCIe Correctable Error Counters";

	return ocp_clear_feature(argc, argv, desc, OCP_FID_CPCIE);
}
