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
#define CMD_INC_FILE plugins/fw/fw-plugin

#if !defined(FW_PLUGIN) || defined(CMD_HEADER_MULTI_READ)
#define FW_PLUGIN

#include "cmd.h"

PLUGIN(NAME_CORE("fw", "Manage NVMe controller firmware", NVME_VERSION),
	COMMAND_LIST(
		ENTRY("download", "Download new firmware", fw_download)
		ENTRY("commit", "Verify and commit firmware to a specific slot (fw-activate in old version < 1.2)",
		      fw_commit, "activate")
	)
);

#endif

#include "define_cmd.h"
