// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2022 Solidigm.
 *
 * Authors: haro.panosyan@solidigm.com
 *          leonardo.da.cunha@solidigm.com
 */

#include <unistd.h>
#include "ocp-utils.h"
#include "nvme-print.h"

static const __u8 OCP_FID_CLEAR_FW_ACTIVATION_HISTORY = 0xC1;

int ocp_clear_fw_update_history(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "OCP Clear Firmware Update History";
	__u32 result = 0;
	__u32 clear_fw_history = 1 << 31;
	struct nvme_dev *dev;
	int uuid_index = 0;
	bool no_uuid = false;
	int err;

	OPT_ARGS(opts) = {
		OPT_FLAG("no-uuid", 'n', &no_uuid,
			 "Skip UUID index search (UUID index not required for OCP 1.0)"),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;
	if (no_uuid == false) {
		// OCP 2.0 requires UUID index support
		err = ocp_get_uuid_index(dev, &uuid_index);
		if (err || uuid_index == 0) {
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
		.cdw11 = clear_fw_history,
		.cdw12 = 0,
		.cdw13 = 0,
		.cdw15 = 0,
		.data_len = 0,
		.save = 0,
		.uuidx = uuid_index,
		.fid = OCP_FID_CLEAR_FW_ACTIVATION_HISTORY,
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
