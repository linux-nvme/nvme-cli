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
#define CMD_INC_FILE plugins/nvme-mi/nvme-mi-plugin

#if !defined(NVME_MI_PLUGIN) || defined(CMD_HEADER_MULTI_READ)
#define NVME_MI_PLUGIN

#include "cmd.h"

PLUGIN(NAME_CORE("nvme-mi", "Submit NVMe-MI commands", NVME_VERSION),
	COMMAND_LIST(
		ENTRY("recv", "Submit a NVMe-MI Receive command, return results", nmi_recv)
		ENTRY("send", "Submit a NVMe-MI Send command, return results", nmi_send)
	)
);

#endif

#include "define_cmd.h"
