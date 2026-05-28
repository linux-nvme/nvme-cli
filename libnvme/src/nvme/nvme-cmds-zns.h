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
 * DOC: nvme-cmds-zns.h
 *
 * Zoned Namespace Command Set Commands
 */

#include <nvme/ioctl.h>
#include <nvme/nvme-cmds-base.h>
#include <nvme/nvme-types-zns.h>

/**
 * nvme_init_get_log_zns_changed_zones() - Initialize passthru command for
 * list of zones that have changed
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID
 * @log:	User address to store the changed zone log
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_ZNS_CHANGED_ZONES
 */
static inline void
nvme_init_get_log_zns_changed_zones(struct libnvme_passthru_cmd *cmd,
		__u32 nsid, struct nvme_zns_changed_zone_log *log)
{
	nvme_init_get_log(cmd, nsid,
		NVME_LOG_LID_ZNS_CHANGED_ZONES, NVME_CSI_ZNS,
		log, sizeof(*log));
}


/**
 * nvme_init_zns_identify_ns() - Initialize passthru command for
 * ZNS identify namespace data
 * @cmd:	Command data structure to initialize
 * @nsid:	Namespace to identify
 * @data:	User space destination address to transfer the data
 */
static inline void
nvme_init_zns_identify_ns(struct libnvme_passthru_cmd *cmd,
		__u32 nsid, struct nvme_zns_id_ns *data)
{
	nvme_init_identify(cmd, nsid, NVME_CSI_ZNS,
			   NVME_IDENTIFY_CNS_CSI_NS,
			   data, sizeof(*data));
}

/**
 * nvme_init_zns_identify_ctrl() - Initialize passthru command for
 * ZNS identify controller data
 * @cmd:	Command data structure to initialize
 * @id:	User space destination address to transfer the data
 */
static inline void
nvme_init_zns_identify_ctrl(struct libnvme_passthru_cmd *cmd,
		struct nvme_zns_id_ctrl *id)
{
	nvme_init_identify(cmd, NVME_NSID_NONE, NVME_CSI_ZNS,
			   NVME_IDENTIFY_CNS_CSI_CTRL,
			   id, sizeof(*id));
}

/**
 * nvme_init_zns_mgmt_send() - Initialize passthru command for
 * ZNS management send command
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID
 * @slba:	Starting logical block address
 * @zsa:	Zone send action
 * @selall:	Select all flag
 * @zsaso:	Zone Send Action Specific Option
 * @zm:		Zone Management
 * @data:	Userspace address of the data buffer
 * @len:	Length of @data
 *
 * Initializes the passthru command buffer for the ZNS Management Send command.
 */
static inline void
nvme_init_zns_mgmt_send(struct libnvme_passthru_cmd *cmd, __u32 nsid,
		__u64 slba, enum nvme_zns_send_action zsa, bool selall,
		__u8 zsaso, __u8 zm, void *data, __u32 len)
{
	memset(cmd, 0, sizeof(*cmd));

	cmd->opcode = nvme_zns_cmd_mgmt_send;
	cmd->nsid = nsid;
	cmd->data_len = len;
	cmd->addr = (__u64)(uintptr_t)data;
	cmd->cdw10 = slba & 0xffffffff;
	cmd->cdw11 = slba >> 32;
	cmd->cdw13 = NVME_FIELD_ENCODE(zsa,
			NVME_ZNS_MGMT_SEND_ZSA_SHIFT,
			NVME_ZNS_MGMT_SEND_ZSA_MASK) |
		      NVME_FIELD_ENCODE(selall,
			NVME_ZNS_MGMT_SEND_SEL_SHIFT,
			NVME_ZNS_MGMT_SEND_SEL_MASK) |
		      NVME_FIELD_ENCODE(zsaso,
			NVME_ZNS_MGMT_SEND_ZSASO_SHIFT,
			NVME_ZNS_MGMT_SEND_ZSASO_MASK) |
		      NVME_FIELD_ENCODE(zm,
			NVME_ZNS_MGMT_SEND_ZM_SHIFT,
			NVME_ZNS_MGMT_SEND_ZM_MASK);
}

/**
 * nvme_init_zns_mgmt_recv() - Initialize passthru command for
 * ZNS management receive command
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID
 * @slba:	Starting logical block address
 * @zra:	zone receive action
 * @zras:	Zone receive action specific field
 * @zraspf:	Zone receive action specific features
 * @data:	Userspace address of the data buffer
 * @len:	Length of @data
 *
 * Initializes the passthru command buffer for the ZNS Management
 * Receive command.
 */
static inline void
nvme_init_zns_mgmt_recv(struct libnvme_passthru_cmd *cmd, __u32 nsid,
		__u64 slba, enum nvme_zns_recv_action zra, __u16 zras,
		bool zraspf, void *data, __u32 len)
{
	memset(cmd, 0, sizeof(*cmd));

	cmd->opcode = nvme_zns_cmd_mgmt_recv;
	cmd->nsid = nsid;
	cmd->data_len = len;
	cmd->addr = (__u64)(uintptr_t)data;
	cmd->cdw10 = slba & 0xffffffff;
	cmd->cdw11 = slba >> 32;
	cmd->cdw12 = (len >> 2) - 1;
	cmd->cdw13 = NVME_FIELD_ENCODE(zra,
			NVME_ZNS_MGMT_RECV_ZRA_SHIFT,
			NVME_ZNS_MGMT_RECV_ZRA_MASK) |
		     NVME_FIELD_ENCODE(zras,
			NVME_ZNS_MGMT_RECV_ZRAS_SHIFT,
			NVME_ZNS_MGMT_RECV_ZRAS_MASK) |
		     NVME_FIELD_ENCODE(zraspf,
			NVME_ZNS_MGMT_RECV_ZRASPF_SHIFT,
			NVME_ZNS_MGMT_RECV_ZRASPF_MASK);
}

/**
 * nvme_init_zns_report_zones() - Initialize passthru command to return
 * the list of zones
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID
 * @slba:	Starting LBA
 * @opts:	Reporting options
 * @extended:	Extended report
 * @partial:	Partial report requested
 * @data:	Userspace address of the report zones data buffer
 * @len:	Length of the data buffer
 *
 * Initializes the passthru command buffer for the ZNS Management Receive -
 * Report Zones command.
 */
static inline void
nvme_init_zns_report_zones(struct libnvme_passthru_cmd *cmd, __u32 nsid,
		__u64 slba, enum nvme_zns_report_options opts,
		bool extended, bool partial,
		void *data, __u32 len)
{
	enum nvme_zns_recv_action zra = extended ?
		NVME_ZNS_ZRA_EXTENDED_REPORT_ZONES : NVME_ZNS_ZRA_REPORT_ZONES;
	__u16 zras = (__u16)opts;
	bool zraspf = partial; /* ZRASPF is Partial Report Requested */

	nvme_init_zns_mgmt_recv(cmd, nsid, slba, zra, zras, zraspf, data, len);
}

/**
 * nvme_init_zns_append() - Initialize passthru command to append data to a zone
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID
 * @zslba:	Zone start logical block address
 * @nlb:	Number of logical blocks
 * @control:	Upper 16 bits of cdw12
 * @cev:	Command Extension Value
 * @dspec:	Directive Specific
 * @data:	Userspace address of the data buffer
 * @data_len:	Length of @data
 * @metadata:	Userspace address of the metadata buffer
 * @metadata_len: Length of @metadata
 *
 * Initializes the passthru command buffer for the ZNS Append command.
 */
static inline void
nvme_init_zns_append(struct libnvme_passthru_cmd *cmd, __u32 nsid,
		__u64 zslba, __u16 nlb, __u16 control, __u16 cev, __u16 dspec,
		void *data, __u32 data_len, void *metadata, __u32 metadata_len)
{
	memset(cmd, 0, sizeof(*cmd));

	cmd->opcode = nvme_zns_cmd_append;
	cmd->nsid = nsid;
	cmd->metadata = (__u64)(uintptr_t)metadata;
	cmd->addr = (__u64)(uintptr_t)data;
	cmd->metadata_len = metadata_len;
	cmd->data_len = data_len;
	cmd->cdw10 = NVME_FIELD_ENCODE(zslba,
			NVME_IOCS_COMMON_CDW10_SLBAL_SHIFT,
			NVME_IOCS_COMMON_CDW10_SLBAL_MASK);
	cmd->cdw11 = NVME_FIELD_ENCODE(zslba >> 32,
			NVME_IOCS_COMMON_CDW11_SLBAU_SHIFT,
			NVME_IOCS_COMMON_CDW11_SLBAU_MASK);
	cmd->cdw12 = NVME_FIELD_ENCODE(nlb,
			NVME_IOCS_COMMON_CDW12_NLB_SHIFT,
			NVME_IOCS_COMMON_CDW12_NLB_MASK) |
		     NVME_FIELD_ENCODE(control,
			NVME_IOCS_COMMON_CDW12_CONTROL_SHIFT,
			NVME_IOCS_COMMON_CDW12_CONTROL_MASK);
	cmd->cdw13 = NVME_FIELD_ENCODE(dspec,
			NVME_IOCS_COMMON_CDW13_DSPEC_SHIFT,
			NVME_IOCS_COMMON_CDW13_DSPEC_MASK);
	if (control & NVME_IOCS_COMMON_CDW12_CETYPE_MASK)
		cmd->cdw13 |= NVME_FIELD_ENCODE(cev,
			NVME_IOCS_COMMON_CDW13_CEV_SHIFT,
			NVME_IOCS_COMMON_CDW13_CEV_MASK);
}

