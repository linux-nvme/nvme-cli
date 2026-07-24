// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2026 Micron Technology, Inc.
 */
#include "command-metadata.h"
#include "common.h"
#include "nvme.h"

#define CREATE_CMD
#include "utils.h"

#ifdef CONFIG_JSONC
static int dump_command_metadata_cmd(int argc, char **argv, struct command *acmd,
				     struct plugin *plugin)
{
	(void)argc;
	(void)argv;
	(void)acmd;

	return dump_command_metadata(plugin->parent);
}
#endif /* CONFIG_JSONC */
