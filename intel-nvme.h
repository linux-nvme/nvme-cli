#undef CMD_INC_FILE
#define CMD_INC_FILE intel-nvme

#if !defined(INTEL_NVME) || defined(CMD_HEADER_MULTI_READ)
#define INTEL_NVME

#include "cmd.h"

COMMAND_LIST(
	ENTRY("smart-log-add", "Retrieve Intel SMART Log, show it", get_additional_smart_log)
);

#endif

#include "define_cmd.h"
