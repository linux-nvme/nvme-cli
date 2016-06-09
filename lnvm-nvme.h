
#undef CMD_INC_FILE
#define CMD_INC_FILE lnvm-nvme

#if !defined(LNVM_NVME) || defined(CMD_HEADER_MULTI_READ)
#define LNVM_NVME

#include "cmd.h"

PLUGIN(NAME("lnvm", "LightNVM specific extensions"),
	COMMAND_LIST(
		ENTRY("list", "List available LightNVM devices", lnvm_list)
		ENTRY("info", "List general information and available target engines", lnvm_info)
		ENTRY("id-ns", "List geometry for LightNVM device", lnvm_id_ns)
		ENTRY("init", "Initialize media manager on LightNVM device", lnvm_init)
		ENTRY("create", "Create target on top of a LightNVM device", lnvm_create_tgt)
		ENTRY("remove", "Remove target from device", lnvm_remove_tgt)
		ENTRY("factory", "Reset device to factory state", lnvm_factory_init)
		ENTRY("diag-bbtbl", "Diagnose bad block table", lnvm_get_bbtbl)
		ENTRY("diag-set-bbtbl", "Update bad block table", lnvm_set_bbtbl)
	)
);

#endif

#include "define_cmd.h"
