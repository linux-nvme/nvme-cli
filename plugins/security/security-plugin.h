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
#define CMD_INC_FILE plugins/security/security-plugin

#if !defined(SECURITY_PLUGIN) || defined(CMD_HEADER_MULTI_READ)
#define SECURITY_PLUGIN

#include "cmd.h"

PLUGIN(NAME_CORE("security", "Submit NVMe Security Send/Receive commands", NVME_VERSION),
	COMMAND_LIST(
		ENTRY("send", "Submit a Security Send command, return results", sec_send)
		ENTRY("recv", "Submit a Security Receive command, return results", sec_recv)
	)
);

#endif

#include "define_cmd.h"
