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
 * nvme_init_cross_ctrl_reset() - Initialize passthru command for
 * Cross-Controller Reset
 * @cmd:	Passthru command to use
 * @icid:	Impacted Controller ID (ICID)
 * @ciu:	Controller Instance Uniquifier (CIU) of the Impacted Controller
 * @cirn:	Controller Instance Random Number (CIRN) of the Impacted
 *		Controller
 *
 * Initializes the passthru command buffer for the Cross-Controller Reset
 * command.
 */
static inline void
nvme_init_cross_ctrl_reset(struct libnvme_passthru_cmd *cmd,
		__u16 icid, __u8 ciu, __u64 cirn)
{
	memset(cmd, 0, sizeof(*cmd));
	cmd->opcode = nvme_admin_cross_ctrl_reset;
	cmd->cdw10 = NVME_FIELD_ENCODE(icid,
			NVME_CROSS_CTRL_RESET_CDW10_ICID_SHIFT,
			NVME_CROSS_CTRL_RESET_CDW10_ICID_MASK) |
		     NVME_FIELD_ENCODE(ciu,
			NVME_CROSS_CTRL_RESET_CDW10_CIU_SHIFT,
			NVME_CROSS_CTRL_RESET_CDW10_CIU_MASK);
	cmd->cdw12 = (__u32)cirn;
	cmd->cdw13 = (__u32)(cirn >> 32);
}

/**
 * nvme_init_fabric_zoning_lookup() - Initialize passthru command for
 * Fabric Zoning Lookup
 * @cmd:	Passthru command to use
 * @data:	Fabric Zoning Lookup data buffer
 * @len:	Length of @data
 *
 * Initializes the passthru command buffer for the Fabric Zoning Lookup
 * command. The returned Zoning Data Key is available in the completion
 * result, see &enum nvme_fabric_zoning_recv_cqe_dw0 for related fields.
 */
static inline void
nvme_init_fabric_zoning_lookup(struct libnvme_passthru_cmd *cmd,
		void *data, __u32 len)
{
	memset(cmd, 0, sizeof(*cmd));
	cmd->opcode = nvme_admin_fabric_zoning_lookup;
	cmd->data_len = len;
	cmd->addr = (__u64)(uintptr_t)data;
}

/**
 * nvme_init_fabric_zoning_receive() - Initialize passthru command for
 * Fabric Zoning Receive
 * @cmd:	Passthru command to use
 * @zdk:	Zoning Data Key (ZDK), or Transaction ID if @zdkc is set
 * @zdo:	Zoning Data Offset (ZDO)
 * @zdkc:	ZDK Context (ZDKC): if set, @zdk contains a Transaction ID
 *		instead of a Zoning Data Key
 * @numd:	Number of Dwords (NUMD) to transfer
 * @data:	Zoning data buffer
 * @len:	Length of @data
 *
 * Initializes the passthru command buffer for the Fabric Zoning Receive
 * command.
 */
static inline void
nvme_init_fabric_zoning_receive(struct libnvme_passthru_cmd *cmd,
		__u32 zdk, __u32 zdo, bool zdkc, __u32 numd,
		void *data, __u32 len)
{
	memset(cmd, 0, sizeof(*cmd));
	cmd->opcode = nvme_admin_fabric_zoning_recv;
	cmd->data_len = len;
	cmd->addr = (__u64)(uintptr_t)data;
	cmd->cdw10 = zdk;
	cmd->cdw11 = zdo;
	cmd->cdw12 = NVME_FIELD_ENCODE(numd,
			NVME_FABRIC_ZONING_RECV_CDW12_NUMD_SHIFT,
			NVME_FABRIC_ZONING_RECV_CDW12_NUMD_MASK) |
		     (zdkc ? NVME_FABRIC_ZONING_RECV_CDW12_ZDKC : 0);
}

/**
 * nvme_init_fabric_zoning_send() - Initialize passthru command for
 * Fabric Zoning Send
 * @cmd:	Passthru command to use
 * @zdk:	Zoning Data Key (ZDK), or Transaction ID if @zdkc is set
 * @zdo:	Zoning Data Offset (ZDO)
 * @lf:		Last Fragment (LF): set if @data contains the last fragment
 *		of the Zoning data structure
 * @zdkc:	ZDK Context (ZDKC): if set, @zdk contains a Transaction ID
 *		instead of a Zoning Data Key
 * @numd:	Number of Dwords (NUMD) to transfer
 * @data:	Zoning data buffer
 * @len:	Length of @data
 *
 * Initializes the passthru command buffer for the Fabric Zoning Send
 * command.
 */
static inline void
nvme_init_fabric_zoning_send(struct libnvme_passthru_cmd *cmd,
		__u32 zdk, __u32 zdo, bool lf, bool zdkc, __u32 numd,
		void *data, __u32 len)
{
	memset(cmd, 0, sizeof(*cmd));
	cmd->opcode = nvme_admin_fabric_zoning_send;
	cmd->data_len = len;
	cmd->addr = (__u64)(uintptr_t)data;
	cmd->cdw10 = zdk;
	cmd->cdw11 = zdo;
	cmd->cdw12 = NVME_FIELD_ENCODE(numd,
			NVME_FABRIC_ZONING_SEND_CDW12_NUMD_SHIFT,
			NVME_FABRIC_ZONING_SEND_CDW12_NUMD_MASK) |
		     (zdkc ? NVME_FABRIC_ZONING_SEND_CDW12_ZDKC : 0) |
		     (lf ? NVME_FABRIC_ZONING_SEND_CDW12_LF : 0);
}

/**
 * nvme_init_send_discovery_log_page() - Initialize passthru command for
 * Send Discovery Log Page
 * @cmd:	Passthru command to use
 * @rlps:	Requested Log Page Status (RLPS), see &enum
 *		nvme_send_discovery_log_page_rlps
 * @sct:	Status Code Type (SCT), used if @rlps is
 *		%NVME_SDLP_RLPS_NOT_SUCCESSFUL
 * @sc:		Status Code (SC), used if @rlps is
 *		%NVME_SDLP_RLPS_NOT_SUCCESSFUL
 * @tlsp:	Transferred Log Specific Parameter (TLSP)
 * @tlid:	Transferred Log Page Identifier (TLID)
 * @ndws:	Number of Dwords (NDWS) transferred
 * @tlpo:	Transferred Log Page Offset (TLPO)
 * @data:	Transferred log page data buffer
 * @len:	Length of @data
 *
 * Initializes the passthru command buffer for the Send Discovery Log Page
 * command.
 */
static inline void
nvme_init_send_discovery_log_page(struct libnvme_passthru_cmd *cmd,
		__u8 rlps, __u8 sct, __u8 sc, __u8 tlsp, __u8 tlid,
		__u32 ndws, __u64 tlpo, void *data, __u32 len)
{
	memset(cmd, 0, sizeof(*cmd));
	cmd->opcode = nvme_admin_send_disc_log_page;
	cmd->data_len = len;
	cmd->addr = (__u64)(uintptr_t)data;
	cmd->cdw10 = NVME_FIELD_ENCODE(rlps,
			NVME_SDLP_CDW10_RLPS_SHIFT,
			NVME_SDLP_CDW10_RLPS_MASK) |
		     NVME_FIELD_ENCODE(sct,
			NVME_SDLP_CDW10_SCT_SHIFT,
			NVME_SDLP_CDW10_SCT_MASK) |
		     NVME_FIELD_ENCODE(sc,
			NVME_SDLP_CDW10_SC_SHIFT,
			NVME_SDLP_CDW10_SC_MASK) |
		     NVME_FIELD_ENCODE(tlsp,
			NVME_SDLP_CDW10_TLSP_SHIFT,
			NVME_SDLP_CDW10_TLSP_MASK) |
		     NVME_FIELD_ENCODE(tlid,
			NVME_SDLP_CDW10_TLID_SHIFT,
			NVME_SDLP_CDW10_TLID_MASK);
	cmd->cdw11 = ndws;
	cmd->cdw12 = (__u32)tlpo;
	cmd->cdw13 = (__u32)(tlpo >> 32);
}

/**
 * nvme_init_manage_export_port() - Initialize passthru command for
 * Manage Exported Port
 * @cmd:	Passthru command to use
 * @sel:	Select (SEL): management operation to perform, see &enum
 *		nvme_manage_export_port_sel
 * @mos:	Management Operation Specific (MOS): specific to @sel
 * @data:	Pointer to data buffer
 * @len:	Length of @data
 *
 * Initializes the passthru command buffer for the Manage Exported Port
 * command.
 */
static inline void
nvme_init_manage_export_port(struct libnvme_passthru_cmd *cmd,
		__u8 sel, __u8 mos, void *data, __u32 len)
{
	memset(cmd, 0, sizeof(*cmd));
	cmd->opcode = nvme_admin_manage_export_port;
	cmd->data_len = len;
	cmd->addr = (__u64)(uintptr_t)data;
	cmd->cdw10 = NVME_FIELD_ENCODE(sel,
			NVME_MANAGE_EXPORT_PORT_CDW10_SEL_SHIFT,
			NVME_MANAGE_EXPORT_PORT_CDW10_SEL_MASK) |
		     NVME_FIELD_ENCODE(mos,
			NVME_MANAGE_EXPORT_PORT_CDW10_MOS_SHIFT,
			NVME_MANAGE_EXPORT_PORT_CDW10_MOS_MASK);
}

/**
 * nvme_init_manage_export_port_create() - Initialize passthru command for
 * Manage Exported Port - Create
 * @cmd:	Passthru command to use
 * @gepid:	Generate Exported Port ID (GEPID): if set, the controller
 *		generates the Exported Port ID (returned in the CQE result,
 *		see &enum nvme_export_port_create_cqe_dw0); if clear, the
 *		EPID field in @data specifies it
 * @data:	Create data buffer, see &struct nvme_exported_port_create_data
 *
 * Initializes the passthru command buffer for the Manage Exported Port
 * command with SEL value %NVME_MANAGE_EXPORT_PORT_SEL_CREATE.
 */
static inline void
nvme_init_manage_export_port_create(struct libnvme_passthru_cmd *cmd,
		bool gepid, struct nvme_exported_port_create_data *data)
{
	__u8 mos = gepid ? NVME_EXPORT_PORT_CREATE_MOS_GEPID : 0;

	nvme_init_manage_export_port(cmd, NVME_MANAGE_EXPORT_PORT_SEL_CREATE,
		mos, data, sizeof(*data));
}

/**
 * nvme_init_manage_export_port_delete() - Initialize passthru command for
 * Manage Exported Port - Delete
 * @cmd:	Passthru command to use
 * @data:	Delete data buffer, see &struct nvme_exported_port_delete_data
 *
 * Initializes the passthru command buffer for the Manage Exported Port
 * command with SEL value %NVME_MANAGE_EXPORT_PORT_SEL_DELETE.
 */
static inline void
nvme_init_manage_export_port_delete(struct libnvme_passthru_cmd *cmd,
		struct nvme_exported_port_delete_data *data)
{
	nvme_init_manage_export_port(cmd, NVME_MANAGE_EXPORT_PORT_SEL_DELETE,
		0, data, sizeof(*data));
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

