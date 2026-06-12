/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */
#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/registry/registry-nvme

#if !defined(REGISTRY_NVME) || defined(CMD_HEADER_MULTI_READ)
#define REGISTRY_NVME

#include "cmd.h"

PLUGIN(NAME("registry", "NVMeoF controller ownership registry", NVME_VERSION),
	COMMAND_LIST(
		ENTRY("list",     "List live registry entries",                       registry_list)
		ENTRY("retrieve", "Read an attribute from a controller's entry",      registry_retrieve)
		ENTRY("update",   "Write an attribute to a controller's entry",       registry_update)
		ENTRY("delete",   "Remove a controller's registry entry",             registry_delete)
	)
);

#endif

#include "define_cmd.h"
