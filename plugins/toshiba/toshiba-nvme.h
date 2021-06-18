#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/toshiba/toshiba-nvme

#if !defined(TOSHIBA_NVME) || defined(CMD_HEADER_MULTI_READ)
#define TOSHIBA_NVME

#include "cmd.h"
#include "plugin.h"

PLUGIN(NAME("toshiba", "Toshiba NVME plugin", NVME_VERSION),
    COMMAND_LIST(
			ENTRY("vs-smart-add-log", "Extended SMART information", vendor_log)
			ENTRY("vs-internal-log", "Get Internal Log", internal_log)
			ENTRY("clear-pcie-correctable-errors", "Clear PCIe correctable error count", clear_correctable_errors)
    )
);

#endif

#include "define_cmd.h"
