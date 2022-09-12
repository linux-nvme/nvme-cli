/* SPDX-License-Identifier: GPL-2.0-or-later */

#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/spdk/spdk-nvme

#if !defined(SPDK_NVME) || defined(CMD_HEADER_MULTI_READ)
#define SPDK_NVME

#include "cmd.h"

PLUGIN(NAME("spdk", "SPDK specific extensions", NVME_VERSION),
	COMMAND_LIST(
		ENTRY("list", "List all SPDK NVMe devices and namespaces on machine", spdk_list)
		ENTRY("list-subsys", "Retrieve all information for SPDK subsystems",
		      spdk_list_subsys)
	)
);

#endif

#include "define_cmd.h"
