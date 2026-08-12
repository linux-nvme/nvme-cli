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
#define CMD_INC_FILE plugins/io-mgmt/io-mgmt-plugin

#if !defined(IO_MGMT_PLUGIN) || defined(CMD_HEADER_MULTI_READ)
#define IO_MGMT_PLUGIN

#include "cmd.h"

PLUGIN(NAME_CORE("io-mgmt", "Submit NVMe I/O Management commands", NVME_VERSION),
	COMMAND_LIST(
		ENTRY("recv", "I/O Management Receive", io_mgmt_recv)
		ENTRY("send", "I/O Management Send", io_mgmt_send)
	)
);

#endif

#include "define_cmd.h"
