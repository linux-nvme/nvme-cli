/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "cmd.h"

#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/feat/feat-nvme

#include "define_cmd.h"

#if !defined(FEAT_NVME) || defined(CMD_HEADER_MULTI_READ)
#define FEAT_NVME

#define FEAT_PLUGIN_VERSION "1.0"
#define POWER_MGMT_DESC "Get and set power management feature"

PLUGIN(NAME("feat", "NVMe feature extensions", FEAT_PLUGIN_VERSION),
	COMMAND_LIST(
		ENTRY("power-mgmt", POWER_MGMT_DESC, feat_power_mgmt)
	)
);
#endif /* !FEAT_NVME || CMD_HEADER_MULTI_READ */

#ifndef FEAT_NVME_H
#define FEAT_NVME_H

#endif /* FEAT_NVME_H */
