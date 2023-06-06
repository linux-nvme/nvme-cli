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

	return ocp_clear_feature(argc, argv, desc, OCP_FID_CLEAR_FW_ACTIVATION_HISTORY);
}
