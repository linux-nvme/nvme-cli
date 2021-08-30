#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/ymtc/ymtc-nvme

#if !defined(YMTC_NVME) || defined(CMD_HEADER_MULTI_READ)
#define YMTC_NVME

#include "cmd.h"
#include "common.h"

#include <ctype.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

PLUGIN(NAME("ymtc", "Ymtc vendor specific extensions"),
    COMMAND_LIST(
        ENTRY("smart-log-add", "Retrieve Ymtc SMART Log, show it", get_additional_smart_log)
    )
);

#endif

#include "define_cmd.h"

