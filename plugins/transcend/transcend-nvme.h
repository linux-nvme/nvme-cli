/* SPDX-License-Identifier: GPL-2.0-or-later */
#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/transcend/transcend-nvme

#if !defined(TRANSCEND_NVME) || defined(CMD_HEADER_MULTI_READ)
#define TRANSCEND_NVME
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#include "cmd.h"
 

PLUGIN(NAME("transcend", "Transcend vendor specific extensions", NVME_VERSION),
    COMMAND_LIST(
			ENTRY("healthvalue", "NVME health percentage", getHealthValue)
			ENTRY("badblock", "Get NVME bad block number", getBadblock)
			ENTRY("plphealthvalue", "Get NVME PLP Health.", getPLPHealth)
    )
);

#endif

#include "define_cmd.h"
