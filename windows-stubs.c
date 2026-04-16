/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Windows compatibility implementation for nvme-cli application.
 * 
 * This file contains nvme-cli-specific Windows stubs for functionality
 * not currently supported on Windows.
 */

#ifdef _WIN32

#include <stdio.h>

/* ========== NVMe RPMB Command Stubs ========== */
/*
 * NVMe RPMB (Replay Protected Memory Block) operations are not currently
 * supported on Windows. This stub provides an error message.
 */

struct command;
struct plugin;

int rpmb_cmd_option(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	(void)argc; (void)argv; (void)cmd; (void)plugin;
	fprintf(stderr, "NVMe RPMB commands are not supported on Windows\n");
	return -1;
}

#endif /* _WIN32 */
