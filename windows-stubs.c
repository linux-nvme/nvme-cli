/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Windows compatibility implementation for nvme-cli application.
 * 
 * This file contains nvme-cli-specific Windows stubs for functionality
 * not currently supported on Windows.
 */

#ifdef _WIN32

#include <stdio.h>
#include <stdbool.h>

/* ========== NVMe Fabrics Command Stubs ========== */
/*
 * NVMe over Fabrics is not currently supported on Windows.
 * These stubs provide error messages when users attempt to use fabrics commands.
 */

int fabrics_discovery(const char *desc, int argc, char **argv, bool connect)
{
	(void)desc; (void)argc; (void)argv; (void)connect;
	fprintf(stderr, "NVMe fabrics discovery is not supported on Windows\n");
	return -1;
}

int fabrics_connect(const char *desc, int argc, char **argv)
{
	(void)desc; (void)argc; (void)argv;
	fprintf(stderr, "NVMe fabrics connect is not supported on Windows\n");
	return -1;
}

int fabrics_disconnect(const char *desc, int argc, char **argv)
{
	(void)desc; (void)argc; (void)argv;
	fprintf(stderr, "NVMe fabrics disconnect is not supported on Windows\n");
	return -1;
}

int fabrics_disconnect_all(const char *desc, int argc, char **argv)
{
	(void)desc; (void)argc; (void)argv;
	fprintf(stderr, "NVMe fabrics disconnect-all is not supported on Windows\n");
	return -1;
}

int fabrics_config(const char *desc, int argc, char **argv)
{
	(void)desc; (void)argc; (void)argv;
	fprintf(stderr, "NVMe fabrics config is not supported on Windows\n");
	return -1;
}

int fabrics_dim(const char *desc, int argc, char **argv)
{
	(void)desc; (void)argc; (void)argv;
	fprintf(stderr, "NVMe fabrics DIM is not supported on Windows\n");
	return -1;
}

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
