//NGD add  by command line
#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/ngd/ngd-nvme

#if !defined(NGD_NVME) || defined(CMD_HEADER_MULTI_READ)
#define NGD_NVME

#include "cmd.h"

PLUGIN(NAME("ngd", "NGDSysytems vendor specific extensions", NVME_VERSION),
	COMMAND_LIST(
		ENTRY("internal-log", "Retrieve Ngd internal firmware log, save it", get_internal_log_old)
	)
);

#endif

#include "define_cmd.h"
