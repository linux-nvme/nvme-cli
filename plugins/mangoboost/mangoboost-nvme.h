// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2025 MangoBoost Inc.
 *
 * Author: Jonghyeon Kim <jonghyeon.kim@mangoboost.io>
 */

#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/mangoboost/mangoboost-nvme

#if !defined(MANGOBOOST_NVME) || defined(CMD_HEADER_MULTI_READ)
#define MANGOBOOST_NVME

#include "cmd.h"

PLUGIN(NAME("mangoboost", "MangoBoost vendor specific extensions", NVME_VERSION),
	COMMAND_LIST(
		ENTRY("id-ctrl", "Send NVMe Identify Controller", id_ctrl)
	)
);

#endif

#include "define_cmd.h"
