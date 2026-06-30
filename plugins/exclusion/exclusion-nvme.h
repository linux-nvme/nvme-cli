/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */
#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/exclusion/exclusion-nvme

#if !defined(EXCLUSION_NVME) || defined(CMD_HEADER_MULTI_READ)
#define EXCLUSION_NVME

#include "cmd.h"

PLUGIN(NAME("exclusion", "NVMeoF system-wide exclusion list", NVME_VERSION),
	COMMAND_LIST(
		ENTRY("create", "Create an exclusion list",             excl_create)
		ENTRY("delete", "Delete an exclusion list",             excl_delete)
		ENTRY("edit",   "Edit an exclusion list interactively", excl_edit)
		ENTRY("list",   "List exclusion lists or entries",      excl_list)
		ENTRY("add",    "Add an entry to an exclusion list",    excl_add)
		ENTRY("remove", "Remove an entry from an exclusion list", excl_remove)
	)
);

#endif

#include "define_cmd.h"
