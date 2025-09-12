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
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	__u32 result = 0;
	__u32 clear = 1 << 31;
	__u8 uuid_index = 0;
	bool uuid = true;
	int err;

	OPT_ARGS(opts) = {
		OPT_FLAG("no-uuid", 'n', NULL,
			 "Skip UUID index search (UUID index not required for OCP 1.0)"),
		OPT_END()
	};

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	if (opts[0].seen)
		uuid = false;

	if (uuid) {
		/* OCP 2.0 requires UUID index support */
		err = ocp_get_uuid_index(hdl, &uuid_index);
		if (err || !uuid_index) {
			fprintf(stderr, "ERROR: No OCP UUID index found\n");
			return err;
		}
	}

	err = nvme_set_features(hdl, 0, fid, 0, clear, 0, 0, uuid_index, 0, NULL, 0,
			&result);

	if (err == 0)
		printf("Success : %s\n", desc);
	else if (err > 0)
		nvme_show_status(err);
	else
		printf("Fail : %s\n", desc);

	return err;
}

int get_ocp_error_counters(int argc, char **argv, struct command *acmd,
			   struct plugin *plugin)
{
	const char *desc = "Define Issue Get Feature cmd (FID: 0xC3) Clear PCIe Corr Err Counters";
	const char *sel = "[0-3]: current/default/saved/supported/";
	const char *nsid = "Byte[04-07]: Namespace Identifier Valid/Invalid/Inactive";
	const char *no_uuid = "Do not try to automatically detect UUID index";

	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
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

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	uuid = !argconfig_parse_seen(opts, "no-uuid");

	if (uuid) {
		/* OCP 2.0 requires UUID index support */
		err = ocp_get_uuid_index(hdl, &uuid_index);
		if (err || !uuid_index) {
			nvme_show_error("ERROR: No OCP UUID index found");
			return err;
		}
	}

	struct nvme_get_features_args args = {
		.args_size  = sizeof(args),
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

	err = nvme_get_features(hdl, &args);
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

int ocp_clear_fw_update_history(int argc, char **argv, struct command *acmd,
				struct plugin *plugin)
{
	const char *desc = "OCP Clear Firmware Update History";

	return ocp_clear_feature(argc, argv, desc, OCP_FID_CFUH);
}

int ocp_clear_pcie_correctable_errors(int argc, char **argv,
				      struct command *command,
				      struct plugin *plugin)
{
	const char *desc = "OCP Clear PCIe Correctable Error Counters";

	return ocp_clear_feature(argc, argv, desc, OCP_FID_CPCIE);
}
