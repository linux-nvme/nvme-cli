/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */
#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/config/config-nvme

#if !defined(CONFIG_NVME) || defined(CMD_HEADER_MULTI_READ)
#define CONFIG_NVME

#include "cmd.h"

PLUGIN(NAME("config", "NVMeoF connection configuration", NVME_VERSION),
	COMMAND_LIST(
		ENTRY("validate", "Validate an NVMeoF connection configuration", config_validate_cmd)
		ENTRY("show",     "Show the resolved NVMeoF connection configuration", config_show_cmd)
		ENTRY("convert",  "Convert config.json/discovery.conf to INI", config_convert_cmd)
	)
);

#endif

#include "define_cmd.h"
