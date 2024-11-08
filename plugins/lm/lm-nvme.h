/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2024 Samsung Electronics Co., LTD.
 *
 * Authors: Nate Thornton <n.thornton@samsung.com>
 */

#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/lm/lm-nvme

#if !defined(LIVE_MIGRATION_NVME) || defined(CMD_HEADER_MULTI_READ)
#define LIVE_MIGRATION_NVME

#include "cmd.h"

PLUGIN(NAME("lm", "Live Migration NVMe extensions", NVME_VERSION),
	COMMAND_LIST(
		ENTRY("create-cdq",	"Create Controller Data Queue", lm_create_cdq)
		ENTRY("delete-cdq",	"Delete Controller Data Queue", lm_delete_cdq)
		ENTRY("track-send",	"Track Send Command", lm_track_send)
		ENTRY("migration-send",	"Migration Send", lm_migration_send)
		ENTRY("migration-recv",	"Migration Receive", lm_migration_recv)
		ENTRY("set-cdq",	"Set Feature - Controller Data Queue (FID 21h)", lm_set_cdq)
		ENTRY("get-cdq",	"Get Feature - Controller Data Queue (FID 21h)", lm_get_cdq)
	)
);

#endif

#include "define_cmd.h"
