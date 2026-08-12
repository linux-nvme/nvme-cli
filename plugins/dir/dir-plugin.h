/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file is part of nvme-cli.
 *
 * Copyright (c) 2014-2015, Intel Corporation.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Keith Busch <kbusch@kernel.org>
 *          Daniel Wagner <dwagner@suse.com>
 */

#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/dir/dir-plugin

#if !defined(DIR_PLUGIN) || defined(CMD_HEADER_MULTI_READ)
#define DIR_PLUGIN

#include "cmd.h"

PLUGIN(NAME_CORE("dir", "Submit NVMe Directive commands", NVME_VERSION),
	COMMAND_LIST(
		ENTRY("receive", "Submit a Directive Receive command, return results", dir_receive)
		ENTRY("send", "Submit a Directive Send command, return results", dir_send)
	)
);

#endif

#include "define_cmd.h"
