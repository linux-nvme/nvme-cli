/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2022 Solidigm.
 *
 * Authors: karl.dedow@solidigm.com
 */

#ifndef OCP_FIRMWARE_ACTIVATION_HISTORY_H
#define OCP_FIRMWARE_ACTIVATION_HISTORY_H

struct command;
struct plugin;

int ocp_fw_activation_history_log(int argc, char **argv,
	struct command *cmd, struct plugin *plugin);

#endif
