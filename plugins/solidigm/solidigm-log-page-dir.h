/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2023 Solidigm.
 *
 * Authors: karl.dedow@solidigm.com
 */
#pragma once

struct command;
struct plugin;

int solidigm_get_log_page_directory_log(int argc, char **argv, struct command *acmd,
					struct plugin *plugin);
