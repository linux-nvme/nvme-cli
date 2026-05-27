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
 * DOC: nvme-fabrics-cmds.h
 *
 * NVMe over Fabrics Specific Commands
 */

#include <nvme/ioctl.h>
#include <nvme/nvme-cmds-base.h>
#include <nvme/nvme-types-fabrics.h>

/**
 * nvme_init_get_log_discovery() - Initialize passthru command for Discovery
 * @cmd:	Passthru command to use
 * @lpo:	Offset of this log to retrieve
 * @log:	User address to store the discovery log
 * @len:	The allocated size for this portion of the log
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_DISCOVERY
 */
static inline void
nvme_init_get_log_discovery(struct libnvme_passthru_cmd *cmd,
			__u64 lpo, void *log, __u32 len)
{
	nvme_init_get_log(cmd, NVME_NSID_NONE,
		NVME_LOG_LID_DISCOVERY, NVME_CSI_NVM,
		log, len);
	nvme_init_get_log_lpo(cmd, lpo);
}

/**
 * nvme_init_get_log_host_discovery() - Initialize passthru command for
 * Host Discover
 * @cmd:	Passthru command to use
 * @allhoste:	All host entries
 * @log:	User address to store the log page
 * @len:	The allocated length of the log page
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_HOST_DISCOVERY
 */
static inline void
nvme_init_get_log_host_discovery(struct libnvme_passthru_cmd *cmd,
		bool allhoste, struct nvme_host_discover_log *log, __u32 len)
{
	nvme_init_get_log(cmd, NVME_NSID_ALL,
		NVME_LOG_LID_HOST_DISCOVERY, NVME_CSI_NVM,
		log, len);
	cmd->cdw10 |= NVME_FIELD_ENCODE((__u8)allhoste,
			NVME_LOG_CDW10_LSP_SHIFT,
			NVME_LOG_CDW10_LSP_MASK);
}

/**
 * nvme_init_get_log_ave_discovery() - Initialize passthru command for
 * AVE Discovery
 * @cmd:	Passthru command to use
 * @log:	User address to store the log page
 * @len:	The allocated length of the log page
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_AVE_DISCOVERY
 */
static inline void
nvme_init_get_log_ave_discovery(struct libnvme_passthru_cmd *cmd,
		struct nvme_ave_discover_log *log, __u32 len)
{
	nvme_init_get_log(cmd, NVME_NSID_ALL,
		NVME_LOG_LID_AVE_DISCOVERY, NVME_CSI_NVM,
		log, len);
}

/**
 * nvme_init_get_log_pull_model_ddc_req() - Initialize passthru command for
 * Pull Model DDC Request
 * @cmd:	Passthru command to use
 * @log:	User address to store the log page
 * @len:	The allocated length of the log page
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_PULL_MODEL_DDC_REQ
 */
static inline void
nvme_init_get_log_pull_model_ddc_req(struct libnvme_passthru_cmd *cmd,
		struct nvme_pull_model_ddc_req_log *log, __u32 len)
{
	nvme_init_get_log(cmd, NVME_NSID_ALL,
		NVME_LOG_LID_PULL_MODEL_DDC_REQ, NVME_CSI_NVM,
		log, len);
}

/**
 * nvme_init_set_property() - Initialize passthru command to set
 * controller property
 * @cmd:	Passthru command to use
 * @offset:	Property offset from the base to set
 * @value:	The value to set the property
 *
 * Initializes the passthru command buffer for the Fabrics Set Property command.
 * This is an NVMe-over-Fabrics specific command.
 */
static inline void
nvme_init_set_property(struct libnvme_passthru_cmd *cmd, __u32 offset,
		__u64 value)
{
	memset(cmd, 0, sizeof(*cmd));

	cmd->opcode = nvme_admin_fabrics;
	cmd->nsid = nvme_fabrics_type_property_set;
	cmd->cdw10 = nvme_is_64bit_reg(offset);
	cmd->cdw11 = (__u32)offset;
	cmd->cdw12 = (__u32)(value & 0xffffffff);
	cmd->cdw13 = (__u32)(value >> 32);
}

/**
 * nvme_init_get_property() - Initialize passthru command to get
 * a controller property
 * @cmd:	Passthru command to use
 * @offset:	Property offset from the base to retrieve
 *
 * Initializes the passthru command buffer for the Fabrics Get Property command.
 * This is an NVMe-over-Fabrics specific command.
 */
static inline void
nvme_init_get_property(struct libnvme_passthru_cmd *cmd, __u32 offset)
{

	memset(cmd, 0, sizeof(*cmd));

	cmd->opcode = nvme_admin_fabrics;
	cmd->nsid = nvme_fabrics_type_property_get;
	cmd->cdw10 = nvme_is_64bit_reg(offset);
	cmd->cdw11 = (__u32)offset;
}

