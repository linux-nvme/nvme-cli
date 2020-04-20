#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/dera/dera-nvme

#if !defined(DERA_NVME) || defined(CMD_HEADER_MULTI_READ)
#define DERA_NVME

#include "cmd.h"

PLUGIN(NAME("dera", "Dera vendor specific extensions"),
	COMMAND_LIST(
		ENTRY("smart-log-add", "Retrieve Dera SMART Log, show it", get_additional_smart_log)
		ENTRY("stat", "Retrieve Dera device status, show it", get_status)
	)
);

#endif

#include "define_cmd.h"
