/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "cmd.h"

#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/feat/feat-nvme

#include "define_cmd.h"

#if !defined(FEAT_NVME) || defined(CMD_HEADER_MULTI_READ)
#define FEAT_NVME

#define FEAT_PLUGIN_VERSION "1.0"
#define POWER_MGMT_DESC "Get and set power management feature"
#define PERFC_DESC "Get and set perf characteristics feature"
#define HCTM_DESC "Get and set host controlled thermal management feature"
#define TIMESTAMP_DESC "Get and set timestamp feature"
#define TEMP_THRESH_DESC "Get and set temperature threshold feature"
#define ARBITRATION_DESC "Get and set arbitration feature"
#define VOLATILE_WC_DESC "Get and set volatile write cache feature"

#define FEAT_ARGS(n, ...)                                              \
	NVME_ARGS(n, ##__VA_ARGS__, OPT_FLAG("save", 's', NULL, save), \
		  OPT_BYTE("sel", 'S', &cfg.sel, sel))

PLUGIN(NAME("feat", "NVMe feature extensions", FEAT_PLUGIN_VERSION),
	COMMAND_LIST(
		ENTRY("power-mgmt", POWER_MGMT_DESC, feat_power_mgmt)
		ENTRY("perf-characteristics", PERFC_DESC, feat_perfc)
		ENTRY("hctm", HCTM_DESC, feat_hctm)
		ENTRY("timestamp", TIMESTAMP_DESC, feat_timestamp)
		ENTRY("temp-thresh", TEMP_THRESH_DESC, feat_temp_thresh)
		ENTRY("arbitration", ARBITRATION_DESC, feat_arbitration)
		ENTRY("volatile-wc", VOLATILE_WC_DESC, feat_volatile_wc)
	)
);
#endif /* !FEAT_NVME || CMD_HEADER_MULTI_READ */

#ifndef FEAT_NVME_H
#define FEAT_NVME_H

#endif /* FEAT_NVME_H */
