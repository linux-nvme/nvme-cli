/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (c) 2022 Meta Platforms, Inc.
 *
 * Authors: Arthur Shau <arthurshau@fb.com>,
 *          Wei Zhang <wzhang@fb.com>,
 *          Venkat Ramesh <venkatraghavan@fb.com>
 */

#ifndef OCP_SMART_EXTENDED_LOG_H
#define OCP_SMART_EXTENDED_LOG_H

struct command;
struct plugin;

int ocp_smart_add_log(int argc, char **argv, struct command *cmd,
	struct plugin *plugin);

#endif

