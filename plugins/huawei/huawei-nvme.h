#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/huawei/huawei-nvme

#if !defined(HUAWEI_NVME) || defined(CMD_HEADER_MULTI_READ)
#define HUAWEI_NVME

#include "cmd.h"

PLUGIN(NAME("huawei", "Huawei vendor specific extensions", NVME_VERSION),
	COMMAND_LIST(
		ENTRY("list", "List all Huawei NVMe devices and namespaces on machine", huawei_list)
		ENTRY("id-ctrl", "Huawei identify controller", huawei_id_ctrl)
	)
);

#endif

#include "define_cmd.h"
