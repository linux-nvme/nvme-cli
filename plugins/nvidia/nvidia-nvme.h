#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/nvidia/nvidia-nvme

#if !defined(NVIDIA_NVME) || defined(CMD_HEADER_MULTI_READ)
#define NVIDIA_NVME

#include "cmd.h"

PLUGIN(NAME("nvidia", "NVIDIA vendor specific extensions"),
	COMMAND_LIST(
		ENTRY("id-ctrl", "Send NVMe Identify Controller", id_ctrl)
	)
);

#endif

#include "define_cmd.h"
