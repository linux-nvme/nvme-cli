#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/transcend/transcend-nvme

#if !defined(TRANSCEND_NVME) || defined(CMD_HEADER_MULTI_READ)
#define TRANSCEND_NVME

#include "cmd.h"
 

PLUGIN(NAME("transcend", "Transcend vendor specific extensions", NVME_VERSION),
    COMMAND_LIST(
			ENTRY("healthvalue", "NVME health percentage", getHealthValue)
			ENTRY("badblock", "Get NVME bad block number", getBadblock)
 
    )
);

#endif

#include "define_cmd.h"
