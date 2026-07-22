// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */
#include "common.h"
#include "config-convert.h"
#include "fabrics.h"
#include "nvme.h"

#define CREATE_CMD
#include "config-nvme.h"

static int config_validate_cmd(int argc, char **argv, struct command *cmd,
		struct plugin *plugin)
{
	const char *desc = "Validate an NVMeoF connection configuration";

	return fabrics_config_validate(desc, argc, argv);
}

static int config_show_cmd(int argc, char **argv, struct command *cmd,
		struct plugin *plugin)
{
	const char *desc = "Show the resolved NVMeoF connection configuration";

	return fabrics_config_show(desc, argc, argv);
}

static int config_convert_cmd(int argc, char **argv, struct command *cmd,
		struct plugin *plugin)
{
	const char *desc = "Convert config.json/discovery.conf to INI";

	return nvme_config_convert(desc, argc, argv);
}
