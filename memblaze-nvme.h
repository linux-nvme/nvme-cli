#undef CMD_INC_FILE
#define CMD_INC_FILE memblaze-nvme

#if !defined(MEMBLAZE_NVME) || defined(CMD_HEADER_MULTI_READ)
#define MEMBLAZE_NVME

#include "cmd.h"

PLUGIN(NAME("memblaze", "Memblaze vendor specific extensions"),
	COMMAND_LIST(
		ENTRY("smart-log-add", "Retrieve Memblaze SMART Log, show it", get_additional_smart_log)
		ENTRY("get-feature-add", "Get Memblaze feature and show the resulting value", get_additional_feature)
		ENTRY("set-feature-add", "Set a Memblaze feature and show the resulting value", set_additional_feature)
	)
);

#endif

#include "define_cmd.h"
