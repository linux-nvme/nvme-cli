/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2026 Micron Technology, Inc.
 */
#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/utils/utils

#if !defined(UTILS_NVME) || defined(CMD_HEADER_MULTI_READ)
#define UTILS_NVME

#include "cmd.h"

PLUGIN(NAME("utils", "General purpose utilities", NVME_VERSION),
	COMMAND_LIST(
	)
);

#endif

#include "define_cmd.h"
