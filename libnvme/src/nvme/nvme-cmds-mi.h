/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 *	    Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 *	    Daniel Wagner <dwagner@suse.de>
 */

#pragma once

/**
 * DOC: nvme-cmds-mi.h
 *
 * NVMe Management Interface Command Definitions
 */

#include <nvme/ioctl.h>
#include <nvme/nvme-cmds-base.h>
#include <nvme/nvme-types-mi.h>

/**
 * nvme_init_get_log_mi_cmd_supported_effects() - Initialize passthru command
 * for MI Commands Supported by the controller
 * @cmd:	Passthru command to use
 * @log:	MI Command Supported and Effects data structure
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_MI_CMD_SUPPORTED_EFFECTS
 */
static inline void
nvme_init_get_log_mi_cmd_supported_effects(struct libnvme_passthru_cmd *cmd,
		struct nvme_mi_cmd_supported_effects_log *log)
{
	nvme_init_get_log(cmd, NVME_NSID_NONE,
		NVME_LOG_LID_MI_CMD_SUPPORTED_EFFECTS, NVME_CSI_NVM,
		log, sizeof(*log));
}

/*
 * Helper Functions
 */

/**
 * nvme_init_mi_cmd_flags() - Initialize command flags for NVMe-MI
 * @cmd:	Passthru command to use
 * @ish:	Ignore Shutdown (for NVMe-MI command)
 *
 * Initializes the passthru command flags
 */
static inline void
nvme_init_mi_cmd_flags(struct libnvme_passthru_cmd *cmd, bool ish)
{
	cmd->flags = NVME_FIELD_ENCODE(ish,
			NVME_MI_ADMIN_CFLAGS_ISH_SHIFT,
			NVME_MI_ADMIN_CFLAGS_ISH_MASK);
}
