#undef CMD_INC_FILE
#define CMD_INC_FILE eid-nvme

#if !defined(EIDETICOM_NVME) || defined(CMD_HEADER_MULTI_READ)
#define EIDETICOM_NVME

#include "cmd.h"

PLUGIN(NAME("eid", "Eideticom vendor specific extensions"),
	COMMAND_LIST(
		ENTRY("list", "Eideticom NoLoad list accelerator namespaces", eid_list)
		ENTRY("id-ns", "Eideticom NoLoad print namespace VS info", eid_id_ns)
	)
);

#endif

#include "define_cmd.h"
