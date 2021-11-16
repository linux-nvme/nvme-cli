#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/netapp/netapp-nvme

#if !defined(NETAPP_NVME) || defined(CMD_HEADER_MULTI_READ)
#define NETAPP_NVME

#include "cmd.h"

PLUGIN(NAME("netapp", "NetApp vendor specific extensions", NVME_VERSION),
	COMMAND_LIST(
		ENTRY("smdevices", "NetApp SMdevices", netapp_smdevices)
		ENTRY("ontapdevices", "NetApp ONTAPdevices", netapp_ontapdevices)
	)
);

#endif

#include "define_cmd.h"
