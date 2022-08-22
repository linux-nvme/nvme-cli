/* SPDX-License-Identifier: GPL-2.0-or-later */
#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/shannon/shannon-nvme

#if !defined(SHANNON_NVME) || defined(CMD_HEADER_MULTI_READ)
#define SHANNON_NVME

#include "cmd.h"

PLUGIN(NAME("shannon", "Shannon vendor specific extensions", NVME_VERSION),
	COMMAND_LIST(
		ENTRY("smart-log-add", "Retrieve Shannon SMART Log, show it", get_additional_smart_log)
		ENTRY("set-additioal-feature", "Set additional Shannon feature", set_additional_feature)
		ENTRY("get-additional-feature", "Get additional Shannon feature", get_additional_feature)
		ENTRY("id-ctrl", "Retrieve Shannon ctrl id, show it", shannon_id_ctrl)
		     )
);

#endif

#include "define_cmd.h"
