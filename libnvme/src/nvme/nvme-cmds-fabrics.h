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
		bool allhoste, struct nvme_host_discovery_log *log, __u32 len)
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
		struct nvme_ave_discovery_log *log, __u32 len)
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
 * nvme_init_get_log_cross_ctrl_reset() - Initialize passthru command for
 * Cross-Controller Reset
 * @cmd:	Passthru command to use
 * @rmc:	Remove Completed (RMC), see &enum nvme_cross_ctrl_reset_lsp
 * @log:	User address to store the log page
 * @len:	The allocated length of the log page
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_CROSS_CTRL_RESET
 */
static inline void
nvme_init_get_log_cross_ctrl_reset(struct libnvme_passthru_cmd *cmd,
		bool rmc, struct nvme_cross_ctrl_reset_log *log, __u32 len)
{
	nvme_init_get_log(cmd, NVME_NSID_ALL,
		NVME_LOG_LID_CROSS_CTRL_RESET, NVME_CSI_NVM,
		log, len);
	if (rmc)
		cmd->cdw10 |= NVME_FIELD_ENCODE(NVME_CROSS_CTRL_RESET_LSP_RMC,
				NVME_LOG_CDW10_LSP_SHIFT,
				NVME_LOG_CDW10_LSP_MASK);
}

/**
 * nvme_init_get_log_lost_host_comm() - Initialize passthru command for
 * Lost Host Communication
 * @cmd:	Passthru command to use
 * @rae:	Retain Asynchronous Event
 * @log:	User address to store the log page
 * @len:	The allocated length of the log page
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_LOST_HOST_COMMUNICATION
 */
static inline void
nvme_init_get_log_lost_host_comm(struct libnvme_passthru_cmd *cmd,
		bool rae, struct nvme_lost_host_comm_log *log, __u32 len)
{
	nvme_init_get_log(cmd, NVME_NSID_ALL,
		NVME_LOG_LID_LOST_HOST_COMMUNICATION, NVME_CSI_NVM,
		log, len);
	cmd->cdw10 |= NVME_FIELD_ENCODE(rae,
			NVME_LOG_CDW10_RAE_SHIFT,
			NVME_LOG_CDW10_RAE_MASK);
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

/**
 * nvme_init_auth_send() - Initialize passthru command for Authentication Send
 * @cmd:	Passthru command to use
 * @spsp:	Security Protocol Specific field
 * @secp:	Security Protocol
 * @tl:		Protocol specific transfer length
 * @data:	Authentication message payload buffer to send
 * @len:	Data length of the payload in bytes
 *
 * Initializes the passthru command buffer for the Fabrics Authentication
 * Send command, used to send a KX-HMAC-CHAP authentication message (e.g.
 * &struct nvmf_auth_kxchap_reply) to a controller. This is an
 * NVMe-over-Fabrics specific command that reuses the SECP/SPSP0/SPSP1/TL
 * field encoding of the Security Send command.
 */
static inline void
nvme_init_auth_send(struct libnvme_passthru_cmd *cmd, __u16 spsp, __u8 secp,
		__u32 tl, void *data, __u32 len)
{
	memset(cmd, 0, sizeof(*cmd));

	cmd->opcode = nvme_admin_fabrics;
	cmd->nsid = nvme_fabrics_type_auth_send;
	cmd->data_len = len;
	cmd->addr = (__u64)(uintptr_t)data;
	cmd->cdw10 = NVME_FIELD_ENCODE(secp,
			NVME_SECURITY_SECP_SHIFT,
			NVME_SECURITY_SECP_MASK) |
		      NVME_FIELD_ENCODE(spsp,
			NVME_SECURITY_SPSP0_SHIFT,
			NVME_SECURITY_SPSP0_MASK) |
		      NVME_FIELD_ENCODE(spsp >> 8,
			NVME_SECURITY_SPSP1_SHIFT,
			NVME_SECURITY_SPSP1_MASK);
	cmd->cdw11 = tl;
}

/**
 * nvme_init_auth_receive() - Initialize passthru command for
 * Authentication Receive
 * @cmd:	Passthru command to use
 * @spsp:	Security Protocol Specific field
 * @secp:	Security Protocol
 * @al:		Protocol specific allocation length
 * @data:	Authentication message payload buffer to receive data into
 * @len:	Data length of the payload in bytes (must match @al)
 *
 * Initializes the passthru command buffer for the Fabrics Authentication
 * Receive command, used to receive a KX-HMAC-CHAP authentication message
 * (e.g. &struct nvmf_auth_kxchap_challenge) from a controller. This is an
 * NVMe-over-Fabrics specific command that reuses the SECP/SPSP0/SPSP1/AL
 * field encoding of the Security Receive command.
 */
static inline void
nvme_init_auth_receive(struct libnvme_passthru_cmd *cmd, __u16 spsp,
		__u8 secp, __u32 al, void *data, __u32 len)
{
	memset(cmd, 0, sizeof(*cmd));

	cmd->opcode = nvme_admin_fabrics;
	cmd->nsid = nvme_fabrics_type_auth_receive;
	cmd->data_len = len;
	cmd->addr = (__u64)(uintptr_t)data;
	cmd->cdw10 = NVME_FIELD_ENCODE(secp,
			NVME_SECURITY_SECP_SHIFT,
			NVME_SECURITY_SECP_MASK) |
		     NVME_FIELD_ENCODE(spsp,
			NVME_SECURITY_SPSP0_SHIFT,
			NVME_SECURITY_SPSP0_MASK) |
		     NVME_FIELD_ENCODE(spsp >> 8,
			NVME_SECURITY_SPSP1_SHIFT,
			NVME_SECURITY_SPSP1_MASK);
	cmd->cdw11 = al;
}

