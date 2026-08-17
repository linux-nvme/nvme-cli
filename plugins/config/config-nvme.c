// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */
#include <shared/compiler-attributes-util.h>

#include "config-convert.h"
#include "config-create.h"
#include "fabrics.h"
#include "plugin.h"

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

static int config_status_cmd(int argc, char **argv, struct command *cmd,
		struct plugin *plugin)
{
	const char *desc = "Report legacy config.json/discovery.conf status";

	return nvme_config_status(desc, argc, argv);
}

static int config_convert_cmd(int argc, char **argv, struct command *cmd,
		struct plugin *plugin)
{
	const char *desc = "Convert config.json/discovery.conf to INI";

	return nvme_config_convert(desc, argc, argv);
}

static int config_create_cmd(int argc, char **argv, struct command *cmd,
		struct plugin *plugin)
{
	const char *desc = "Create an NVMeoF connection entry in the INI configuration";

	return nvme_config_create(desc, argc, argv);
}

static struct command config_validate_cmd_cmd = {
	.name = "validate",
	.help = "Validate an NVMeoF connection configuration",
	.fn = config_validate_cmd,
};

static struct command config_show_cmd_cmd = {
	.name = "show",
	.help = "Show the resolved NVMeoF connection configuration",
	.fn = config_show_cmd,
};

static struct command config_status_cmd_cmd = {
	.name = "status",
	.help = "Report config status",
	.fn = config_status_cmd,
};

static struct command config_convert_cmd_cmd = {
	.name = "convert",
	.help = "Convert config.json/discovery.conf to INI",
	.fn = config_convert_cmd,
};

static struct command config_create_cmd_cmd = {
	.name = "create",
	.help = "Create an NVMeoF connection entry in the INI configuration",
	.fn = config_create_cmd,
};

static struct command *commands[] = {
	&config_validate_cmd_cmd,
	&config_show_cmd_cmd,
	&config_status_cmd_cmd,
	&config_convert_cmd_cmd,
	&config_create_cmd_cmd,
	NULL,
};

static struct plugin plugin = {
	.name = "config",
	.desc = "NVMeoF connection configuration",
	.version = NVME_VERSION,
	.core = true,
};

static void __shr_constructor register_plugin(void)
{
	plugin_add_group(&plugin, NULL, commands);
	register_extension(&plugin);
}
