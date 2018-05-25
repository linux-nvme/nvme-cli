#undef CMD_INC_FILE
#define CMD_INC_FILE micron-nvme

#if !defined(MICRON_NVME) || defined(CMD_HEADER_MULTI_READ)
#define MICRON_NVME

#include "cmd.h"

PLUGIN(NAME("micron", "Micron vendor specific extensions"),
	COMMAND_LIST(
		ENTRY("select-download", "Selective Firmware Download", micron_selective_download)
	)
);

#endif

#include "define_cmd.h"
