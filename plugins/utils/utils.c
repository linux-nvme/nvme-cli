// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2026 Micron Technology, Inc.
 */
#include <shared/compiler-attributes-util.h>

#include "command-metadata.h"
#include "plugin.h"

#ifdef CONFIG_JSONC
static int dump_command_metadata_cmd(int argc, char **argv, struct command *acmd,
				     struct plugin *plugin)
{
	(void)argc;
	(void)argv;
	(void)acmd;

	return dump_command_metadata(plugin->parent);
}

static struct command dump_command_metadata_cmd_cmd = {
	.name = "dump-command-metadata",
	.help = "Dump all commands and their options as JSON",
	.fn = dump_command_metadata_cmd,
	.no_device = true,
};
#endif /* CONFIG_JSONC */

static struct command *commands[] = {
#ifdef CONFIG_JSONC
	&dump_command_metadata_cmd_cmd,
#endif
	NULL,
};

static struct plugin plugin = {
	.name = "utils",
	.desc = "General purpose utilities",
	.version = NVME_VERSION,
	.core = true,
};

static void __shr_constructor register_plugin(void)
{
	plugin_add_group(&plugin, NULL, commands);
	register_extension(&plugin);
}
