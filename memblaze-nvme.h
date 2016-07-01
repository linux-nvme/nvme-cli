#undef CMD_INC_FILE
#define CMD_INC_FILE memblaze-nvme

#if !defined(MEMBLAZE_NVME) || defined(CMD_HEADER_MULTI_READ)
#define MEMBLAZE_NVME

#include "cmd.h"

PLUGIN(NAME("memblaze", "Memblaze vendor specific extensions"),
	COMMAND_LIST(
		ENTRY("smart-log-add", "Retrieve Memblaze SMART Log, show it", get_additional_smart_log)
	)
);

#endif

#include "define_cmd.h"
