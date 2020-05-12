#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/memblaze/memblaze-nvme

#if !defined(MEMBLAZE_NVME) || defined(CMD_HEADER_MULTI_READ)
#define MEMBLAZE_NVME

#include "cmd.h"
#include "common.h"

#include <ctype.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

PLUGIN(NAME("memblaze", "Memblaze vendor specific extensions"),
	COMMAND_LIST(
		ENTRY("smart-log-add", "Retrieve Memblaze SMART Log, show it", get_additional_smart_log)
		ENTRY("get-feature-add", "Get Memblaze feature and show the resulting value", get_additional_feature)
		ENTRY("set-feature-add", "Set a Memblaze feature and show the resulting value", set_additional_feature)
		ENTRY("select-download", "Selective Firmware Download", memblaze_selective_download)
	)
);

#endif

#include "define_cmd.h"

