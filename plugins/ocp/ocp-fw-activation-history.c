// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2022 Solidigm.
 *
 * Author: karl.dedow@solidigm.com
 */

#include "ocp-fw-activation-history.h"

#include <errno.h>
#include <stdio.h>

#include "common.h"
#include "nvme-print.h"

#include "ocp-nvme.h"
#include "ocp-utils.h"
#include "ocp-print.h"

static const unsigned char ocp_fw_activation_history_guid[GUID_LEN] = {
	0x6D, 0x79, 0x9a, 0x76,
	0xb4, 0xda, 0xf6, 0xa3,
	0xe2, 0x4d, 0xb2, 0x8a,
	0xac, 0xf3, 0x1c, 0xd1
};

int ocp_fw_activation_history_log(int argc, char **argv, struct command *cmd,
				  struct plugin *plugin)
{
	const char *desc = "Retrieves the OCP firmware activation history log.";

	char *format = "normal";

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &format, "output format : normal | json"),
		OPT_END()
	};

	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	int err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);

	if (err)
		return err;

	__u8 uuid_index = 0;

	/*
	 * Best effort attempt at uuid. Otherwise, assume no index (i.e. 0)
	 * Log GUID check will ensure correctness of returned data
	 */
	ocp_get_uuid_index(hdl, &uuid_index);

	struct fw_activation_history fw_history = { 0 };

	struct nvme_get_log_args args = {
		.lpo = 0,
		.result = NULL,
		.log = &fw_history,
		.args_size = sizeof(args),
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.lid = (enum nvme_cmd_get_log_lid)OCP_LID_FAHL_OBSOLETE,
		.len = sizeof(fw_history),
		.nsid = NVME_NSID_ALL,
		.csi = NVME_CSI_NVM,
		.lsi = NVME_LOG_LSI_NONE,
		.lsp = 0,
		.uuidx = uuid_index,
		.rae = false,
		.ot = false,
	};

	err = nvme_get_log(hdl, &args);

	if (err)
		nvme_show_status(err);

	int guid_cmp_res = memcmp(fw_history.log_page_guid, ocp_fw_activation_history_guid,
				  sizeof(ocp_fw_activation_history_guid));

	if (!err && guid_cmp_res) {
		fprintf(stderr,
			"Error: Unexpected data. Log page guid does not match with expected.\n");
		err = -EINVAL;
	}

	if (!err) {
		nvme_print_flags_t print_flag;

		err = validate_output_format(format, &print_flag);
		if (err < 0) {
			fprintf(stderr, "Error: Invalid output format.\n");
			return err;
		}

		ocp_fw_act_history(&fw_history, print_flag);
	}

	return err;
}
