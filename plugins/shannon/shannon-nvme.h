#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/shannon/shannon-nvme

#if !defined(SHANNON_NVME) || defined(CMD_HEADER_MULTI_READ)
#define SHANNON_NVME

#include "cmd.h"

PLUGIN(NAME("shannon", "Shannon vendor specific extensions", NVME_VERSION),
	COMMAND_LIST(
		ENTRY("smart-log-add", "Retrieve Shannon SMART Log, show it", get_additional_smart_log)
		ENTRY("get-feature-add", "Get Shannon feature and show the resulting value", get_additional_feature)
		ENTRY("set-feature-add", "Set a Shannon feature and show the resulting value", set_additional_feature)
		ENTRY("id-ctrl", "Shannon NVMe Identify Controller", shannon_id_ctrl)
	)
);

#endif

#include "define_cmd.h"
