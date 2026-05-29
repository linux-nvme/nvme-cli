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
 * DOC: nvme-csi-cmds.h
 *
 * NVM Command Set I/O Commands
 */
#include <errno.h>
#include <string.h>

#include <nvme/endian.h>
#include <nvme/ioctl.h>
#include <nvme/nvme-types-nvm.h>
#include <nvme/nvme-cmds-base.h>

/**
 * nvme_init_flush() - Initialize passthru command for Flush command
 * @cmd:	Passthru command to use
 * @nsid:	Namespace identifier
 *
 * The Flush command requests that the contents of volatile write cache be made
 * non-volatile.
 *
 * Initializes the passthru command buffer for the Flush command.
 */
static inline void
nvme_init_flush(struct libnvme_passthru_cmd *cmd, __u32 nsid)
{
	memset(cmd, 0, sizeof(*cmd));
	cmd->opcode = nvme_cmd_flush;
	cmd->nsid = nsid;
}

/**
 * nvme_init_io() - Initialize passthru command for a generic user I/O command
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID
 * @opcode:	Opcode to execute
 * @slba:	Starting logical block
 * @data:	Pointer to user address of the data buffer
 * @data_len:	Length of user buffer, @data, in bytes
 * @metadata:	Pointer to user address of the metadata buffer
 * @metadata_len:Length of user buffer, @metadata, in bytes
 *
 * Initializes the passthru command buffer for a generic NVM I/O command.
 * Note: If @elbas is true, the caller must ensure the definition/logic for
 * nvme_init_set_var_size_tags is available and that the return value from
 * that function is checked for error.
 */
static inline void
nvme_init_io(struct libnvme_passthru_cmd *cmd, __u8 opcode,
		__u32 nsid, __u64 slba,
		void *data, __u32 data_len, void *metadata, __u32 metadata_len)
{
	memset(cmd, 0, sizeof(*cmd));

	cmd->opcode = opcode;
	cmd->nsid = nsid;
	cmd->metadata = (__u64)(uintptr_t)metadata;
	cmd->addr = (__u64)(uintptr_t)data;
	cmd->metadata_len = metadata_len;
	cmd->data_len = data_len;
	cmd->cdw10 = NVME_FIELD_ENCODE(slba,
			NVME_IOCS_COMMON_CDW10_SLBAL_SHIFT,
			NVME_IOCS_COMMON_CDW10_SLBAL_MASK);
	cmd->cdw11 = NVME_FIELD_ENCODE(slba >> 32,
			NVME_IOCS_COMMON_CDW11_SLBAU_SHIFT,
			NVME_IOCS_COMMON_CDW11_SLBAU_MASK);
}

/**
 * nvme_init_write() - Initialize passthru command for a user write command
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID
 * @slba:	Starting logical block
 * @nlb:	Number of logical blocks (0-based)
 * @control:	Upper 16 bits of cdw12
 * @dspec:	Directive specific value
 * @dsm:	Data set management attributes (CETYPE is zero),
 *		see &enum nvme_io_dsm_flags
 * @cev:	Command Extension Value (CETYPE is non-zero)
 * @data:	Pointer to user address of the data buffer
 * @data_len:	Length of user buffer, @data, in bytes
 * @metadata:	Pointer to user address of the metadata buffer
 * @metadata_len:Length of user buffer, @metadata, in bytes
 *
 * Initializes the passthru command buffer for the Write command.
 */
static inline void
nvme_init_write(struct libnvme_passthru_cmd *cmd,
		__u32 nsid, __u64 slba,
		__u16 nlb, __u16 control, __u16 dspec, __u8 dsm, __u8 cev,
		void *data, __u32 data_len, void *metadata, __u32 metadata_len)
{
	nvme_init_io(cmd, nvme_cmd_write, nsid, slba,
		data, data_len, metadata, metadata_len);
	cmd->cdw12 = NVME_FIELD_ENCODE(nlb,
			NVME_IOCS_COMMON_CDW12_NLB_SHIFT,
			NVME_IOCS_COMMON_CDW12_NLB_MASK) |
		      NVME_FIELD_ENCODE(control,
			NVME_IOCS_COMMON_CDW12_CONTROL_SHIFT,
			NVME_IOCS_COMMON_CDW12_CONTROL_MASK);
	cmd->cdw13 = NVME_FIELD_ENCODE(dspec,
			NVME_IOCS_COMMON_CDW13_DSPEC_SHIFT,
			NVME_IOCS_COMMON_CDW13_DSPEC_MASK) |
		     NVME_FIELD_ENCODE(dsm,
			NVME_IOCS_COMMON_CDW13_DSM_SHIFT,
			NVME_IOCS_COMMON_CDW13_DSM_MASK) |
		     NVME_FIELD_ENCODE(cev,
			NVME_IOCS_COMMON_CDW13_CEV_SHIFT,
			NVME_IOCS_COMMON_CDW13_CEV_MASK);
}

/**
 * nvme_init_read() - Initialize passthru command for a user read command
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID
 * @slba:	Starting logical block
 * @nlb:	Number of logical blocks (0-based)
 * @control:	Upper 16 bits of cdw12
 * @dsm:	Data set management attributes (CETYPE is zero),
 *		see &enum nvme_io_dsm_flags
 * @cev:	Command Extension Value (CETYPE is non-zero)
 * @data:	Pointer to user address of the data buffer
 * @data_len:	Length of user buffer, @data, in bytes
 * @metadata:	Pointer to user address of the metadata buffer
 * @metadata_len:Length of user buffer, @metadata, in bytes
 *
 * Initializes the passthru command buffer for the Read command.
 * Note: Assumes a macro or separate function exists to translate the combined
 * NLB/control/prinfo fields into cdw12/cdw13. This transformation assumes
 * the parameters are used for a generic nvme_init_io wrapper.
 */
static inline void
nvme_init_read(struct libnvme_passthru_cmd *cmd,
		__u32 nsid, __u64 slba,
		__u16 nlb, __u16 control, __u8 dsm, __u16 cev,
		void *data, __u32 data_len, void *metadata, __u32 metadata_len)
{
	nvme_init_io(cmd, nvme_cmd_read, nsid, slba,
		data, data_len, metadata, metadata_len);
	cmd->cdw12 = NVME_FIELD_ENCODE(nlb,
			NVME_IOCS_COMMON_CDW12_NLB_SHIFT,
			NVME_IOCS_COMMON_CDW12_NLB_MASK) |
		      NVME_FIELD_ENCODE(control,
			NVME_IOCS_COMMON_CDW12_CONTROL_SHIFT,
			NVME_IOCS_COMMON_CDW12_CONTROL_MASK);
	cmd->cdw13 = NVME_FIELD_ENCODE(dsm,
			NVME_IOCS_COMMON_CDW13_DSM_SHIFT,
			NVME_IOCS_COMMON_CDW13_DSM_MASK) |
		     NVME_FIELD_ENCODE(cev,
			NVME_IOCS_COMMON_CDW13_CEV_SHIFT,
			NVME_IOCS_COMMON_CDW13_CEV_MASK);
}

/**
 * nvme_init_write_uncorrectable() - Initialize passthru command for a
 * write uncorrectable command
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID
 * @slba:	Starting logical block
 * @nlb:	Number of logical blocks (0-based)
 * @control:	Upper 16 bits of cdw12
 * @dspec:	Directive specific value
 *
 * Initializes the passthru command buffer for the Write Uncorrectable command.
 * Note: This command transfers no data or metadata.
 */
static inline void
nvme_init_write_uncorrectable(struct libnvme_passthru_cmd *cmd,
		__u32 nsid, __u64 slba, __u16 nlb, __u16 control, __u16 dspec)
{
	nvme_init_io(cmd, nvme_cmd_write_uncor, nsid, slba, NULL, 0, NULL, 0);
	cmd->cdw12 = NVME_FIELD_ENCODE(nlb,
			NVME_IOCS_COMMON_CDW12_NLB_SHIFT,
			NVME_IOCS_COMMON_CDW12_NLB_MASK) |
		      NVME_FIELD_ENCODE(control,
			NVME_IOCS_COMMON_CDW12_CONTROL_SHIFT,
			NVME_IOCS_COMMON_CDW12_CONTROL_MASK);
	cmd->cdw13 = NVME_FIELD_ENCODE(dspec,
			NVME_IOCS_COMMON_CDW13_DSPEC_SHIFT,
			NVME_IOCS_COMMON_CDW13_DSPEC_MASK);
}

/**
 * nvme_init_compare() - Initialize passthru command for a user compare command
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID
 * @slba:	Starting logical block
 * @nlb:	Number of logical blocks (0-based)
 * @control:	Command control flags, see &enum nvme_io_control_flags.
 * @cev:	Command Extension Value (CETYPE is non-zero)
 * @data:	Pointer to user address of the data buffer
 * @data_len:	Length of user buffer, @data, in bytes
 * @metadata:	Pointer to user address of the metadata buffer
 * @metadata_len:Length of user buffer, @metadata, in bytes
 *
 * Initializes the passthru command buffer for the Compare command.
 */
static inline void
nvme_init_compare(struct libnvme_passthru_cmd *cmd,
		__u32 nsid, __u64 slba,
		__u16 nlb, __u16 control, __u8 cev,
		void *data, __u32 data_len, void *metadata, __u32 metadata_len)
{
	nvme_init_io(cmd, nvme_cmd_compare, nsid, slba,
		data, data_len, metadata, metadata_len);
	cmd->cdw12 = NVME_FIELD_ENCODE(nlb,
			NVME_IOCS_COMMON_CDW12_NLB_SHIFT,
			NVME_IOCS_COMMON_CDW12_NLB_MASK) |
		     NVME_FIELD_ENCODE(control,
			NVME_IOCS_COMMON_CDW12_CONTROL_SHIFT,
			NVME_IOCS_COMMON_CDW12_CONTROL_MASK);
	cmd->cdw13 = NVME_FIELD_ENCODE(cev,
			NVME_IOCS_COMMON_CDW13_CEV_SHIFT,
			NVME_IOCS_COMMON_CDW13_CEV_MASK);
}

/**
 * nvme_init_write_zeros() - Initialize passthru command for a
 * write zeroes command
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID
 * @slba:	Starting logical block
 * @nlb:	Number of logical blocks (0-based)
 * @control:	Upper 16 bits of cdw12
 * @dspec:	Directive specific value
 * @dsm:	Data set management attributes (CETYPE is zero),
 *		see &enum nvme_io_dsm_flags
 * @cev:	Command Extension Value (CETYPE is non-zero)
 *
 * Initializes the passthru command buffer for the Write Zeroes command.
 * Note: Write Zeroes command does not transfer data or metadata.
 */
static inline void
nvme_init_write_zeros(struct libnvme_passthru_cmd *cmd,
		__u32 nsid, __u64 slba,
		__u16 nlb, __u16 control, __u16 dspec, __u8 dsm, __u8 cev)
{
	nvme_init_io(cmd, nvme_cmd_write_zeroes, nsid, slba, NULL, 0, NULL, 0);
	cmd->cdw12 = NVME_FIELD_ENCODE(nlb,
			NVME_IOCS_COMMON_CDW12_NLB_SHIFT,
			NVME_IOCS_COMMON_CDW12_NLB_MASK) |
		      NVME_FIELD_ENCODE(control,
			NVME_IOCS_COMMON_CDW12_CONTROL_SHIFT,
			NVME_IOCS_COMMON_CDW12_CONTROL_MASK);
	cmd->cdw13 = NVME_FIELD_ENCODE(dspec,
			NVME_IOCS_COMMON_CDW13_DSPEC_SHIFT,
			NVME_IOCS_COMMON_CDW13_DSPEC_MASK) |
		     NVME_FIELD_ENCODE(dsm,
			NVME_IOCS_COMMON_CDW13_DSM_SHIFT,
			NVME_IOCS_COMMON_CDW13_DSM_MASK) |
		     NVME_FIELD_ENCODE(cev,
			NVME_IOCS_COMMON_CDW13_CEV_SHIFT,
			NVME_IOCS_COMMON_CDW13_CEV_MASK);
}

/**
 * nvme_init_dsm() - Initialize passthru command for
 * NVMe I/O Data Set Management
 * @cmd:	Passthru command to use
 * @nsid:	Namespace identifier
 * @nr:		Number of block ranges in the data set management attributes
 * @idr:	DSM Integral Dataset for Read attribute
 * @idw:	DSM Integral Dataset for Write attribute
 * @ad:		DSM Deallocate attribute
 * @data:	User space destination address to transfer the data
 * @len:	Length of provided user buffer to hold the log data in bytes
 */
static inline void
nvme_init_dsm(struct libnvme_passthru_cmd *cmd,
		__u32 nsid, __u16 nr, __u8 idr, __u8 idw, __u8 ad, void *data,
		__u32 len)
{
	memset(cmd, 0, sizeof(*cmd));

	cmd->opcode	= nvme_cmd_dsm;
	cmd->nsid	= nsid;
	cmd->data_len	= len;
	cmd->addr	= (__u64)(uintptr_t)data;
	cmd->cdw10 = NVME_FIELD_ENCODE(nr - 1,
			NVME_DSM_CDW10_NR_SHIFT,
			NVME_DSM_CDW10_NR_MASK);
	cmd->cdw11 = NVME_FIELD_ENCODE(idr,
			NVME_DSM_CDW11_IDR_SHIFT,
			NVME_DSM_CDW11_IDR_MASK) |
		      NVME_FIELD_ENCODE(idw,
			NVME_DSM_CDW11_IDW_SHIFT,
			NVME_DSM_CDW11_IDW_MASK) |
		      NVME_FIELD_ENCODE(ad,
			NVME_DSM_CDW11_AD_SHIFT,
			NVME_DSM_CDW11_AD_MASK);
}

/**
 * nvme_init_verify() - Initialize passthru command for a verify command
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID
 * @slba:	Starting logical block
 * @nlb:	Number of logical blocks (0-based)
 * @control:	Upper 16 bits of cdw12
 * @cev:	Command Extension Value (CETYPE is non-zero)
 * @data:	Pointer to user address of the data buffer
 * @data_len:	Length of user buffer, @data, in bytes
 * @metadata:	Pointer to user address of the metadata buffer
 * @metadata_len:Length of user buffer, @metadata, in bytes
 *
 * Initializes the passthru command buffer for the Verify command.
 * Note: Verify command transfers data or metadata to the controller to perform
 * the verification but not back to the host.
 */
static inline void
nvme_init_verify(struct libnvme_passthru_cmd *cmd,
		__u32 nsid, __u64 slba,
		__u16 nlb, __u16 control, __u8 cev,
		void *data, __u32 data_len, void *metadata, __u32 metadata_len)
{
	nvme_init_io(cmd, nvme_cmd_verify, nsid, slba,
		data, data_len, metadata, metadata_len);
	cmd->cdw12 = NVME_FIELD_ENCODE(nlb,
			NVME_IOCS_COMMON_CDW12_NLB_SHIFT,
			NVME_IOCS_COMMON_CDW12_NLB_MASK) |
		     NVME_FIELD_ENCODE(control,
			NVME_IOCS_COMMON_CDW12_CONTROL_SHIFT,
			NVME_IOCS_COMMON_CDW12_CONTROL_MASK);
	cmd->cdw13 = NVME_FIELD_ENCODE(cev,
			NVME_IOCS_COMMON_CDW13_CEV_SHIFT,
			NVME_IOCS_COMMON_CDW13_CEV_MASK);
}

/**
 * nvme_init_resv_register() - Initialize passthru command for
 * Reservation Register
 * @cmd:	Passthru command to use
 * @nsid:	Namespace identifier
 * @rrega:	The registration action, see &enum nvme_resv_rrega
 * @iekey:	Set to ignore the existing key
 * @disnsrs:	Disperse Namespace Reservation Support
 * @cptpl:	Change persist through power loss, see &enum nvme_resv_cptpl
 * @crkey:	The current reservation key associated with the host
 * @nrkey:	The new reservation key to be register if action is register or
 *		replace
 * @payload:	Data payload buffer to hold crkey and nrkey
 *
 * Initializes the passthru command buffer for the Reservation Register command.
 */
static inline void
nvme_init_resv_register(struct libnvme_passthru_cmd *cmd, __u32 nsid,
		enum nvme_resv_rrega rrega, bool iekey, bool disnsrs,
		enum nvme_resv_cptpl cptpl, __u64 crkey, __u64 nrkey,
		__le64 *payload)
{
	memset(cmd, 0, sizeof(*cmd));

	payload[0] = htole64(crkey);
	payload[1] = htole64(nrkey);

	cmd->opcode = nvme_cmd_resv_register;
	cmd->nsid = nsid;
	cmd->data_len = 2 * sizeof(__le64);
	cmd->addr = (__u64)(uintptr_t)payload;
	cmd->cdw10 = NVME_FIELD_ENCODE(rrega,
			NVME_RESV_REGISTER_CDW10_RREGA_SHIFT,
			NVME_RESV_REGISTER_CDW10_RREGA_MASK) |
		     NVME_FIELD_ENCODE(iekey,
			NVME_RESV_REGISTER_CDW10_IEKEY_SHIFT,
			NVME_RESV_REGISTER_CDW10_IEKEY_MASK) |
		     NVME_FIELD_ENCODE(disnsrs,
			NVME_RESV_REGISTER_CDW10_DISNSRS_SHIFT,
			NVME_RESV_REGISTER_CDW10_DISNSRS_MASK) |
		     NVME_FIELD_ENCODE(cptpl,
			NVME_RESV_REGISTER_CDW10_CPTPL_SHIFT,
			NVME_RESV_REGISTER_CDW10_CPTPL_MASK);
}

/**
 * nvme_init_resv_report() - Initialize passthru command for
 * Reservation Report
 * @cmd:	Passthru command to use
 * @nsid:	Namespace identifier
 * @eds:	Request extended Data Structure
 * @disnsrs:	Disperse Namespace Reservation Support
 * @report:	The user space destination address to store the reservation
 *		report buffer
 * @len:	Number of bytes to request transferred with this command
 *
 * Initializes the passthru command buffer for the Reservation Report command.
 */
static inline void
nvme_init_resv_report(struct libnvme_passthru_cmd *cmd, __u32 nsid,
		bool eds, bool disnsrs, struct nvme_resv_status *report,
		__u32 len)
{
	memset(cmd, 0, sizeof(*cmd));

	cmd->opcode = nvme_cmd_resv_report;
	cmd->nsid = nsid;
	cmd->data_len = len;
	cmd->addr = (__u64)(uintptr_t)report;
	cmd->cdw10 = (len >> 2) - 1;
	cmd->cdw11 = NVME_FIELD_ENCODE(eds,
			NVME_RESV_REPORT_CDW11_EDS_SHIFT,
			NVME_RESV_REPORT_CDW11_EDS_MASK) |
		     NVME_FIELD_ENCODE(disnsrs,
			NVME_RESV_REPORT_CDW11_DISNSRS_SHIFT,
			NVME_RESV_REPORT_CDW11_DISNSRS_MASK);
}

/**
 * nvme_init_resv_acquire() - Initialize passthru command for
 * Reservation Acquire
 * @cmd:	Passthru command to use
 * @nsid:	Namespace identifier
 * @racqa:	The action that is performed by the command,
 *		see &enum nvme_resv_racqa
 * @iekey:	Set to ignore the existing key
 * @disnsrs:	Disperse Namespace Reservation Support
 * @rtype:	The type of reservation to be create, see &enum nvme_resv_rtype
 * @crkey:	The current reservation key associated with the host
 * @prkey:	Preempt Reservation Key
 * @payload:	Data payload buffer to hold crkey and prkey
 *
 * Initializes the passthru command buffer for the Reservation Acquire command.
 */
static inline void
nvme_init_resv_acquire(struct libnvme_passthru_cmd *cmd, __u32 nsid,
		enum nvme_resv_racqa racqa, bool iekey, bool disnsrs,
		enum nvme_resv_rtype rtype, __u64 crkey, __u64 prkey,
		__le64 *payload)
{
	memset(cmd, 0, sizeof(*cmd));

	payload[0] = htole64(crkey);
	payload[1] = htole64(prkey);

	cmd->opcode = nvme_cmd_resv_acquire;
	cmd->nsid = nsid;
	cmd->data_len = 2 * sizeof(__le64);
	cmd->addr = (__u64)(uintptr_t)payload;
	cmd->cdw10 = NVME_FIELD_ENCODE(racqa,
			NVME_RESV_ACQUIRE_CDW10_RACQA_SHIFT,
			NVME_RESV_ACQUIRE_CDW10_RACQA_MASK) |
		     NVME_FIELD_ENCODE(iekey,
			NVME_RESV_ACQUIRE_CDW10_IEKEY_SHIFT,
			NVME_RESV_ACQUIRE_CDW10_IEKEY_MASK) |
		     NVME_FIELD_ENCODE(disnsrs,
			NVME_RESV_ACQUIRE_CDW10_DISNSRS_SHIFT,
			NVME_RESV_ACQUIRE_CDW10_DISNSRS_MASK) |
		     NVME_FIELD_ENCODE(rtype,
			NVME_RESV_ACQUIRE_CDW10_RTYPE_SHIFT,
			NVME_RESV_ACQUIRE_CDW10_RTYPE_MASK);
}

/**
 * nvme_init_io_mgmt_recv() - Initialize passthru command for
 * I/O Management Receive command
 * @cmd:	Passthru command to use
 * @nsid:	Namespace identifier
 * @mo:		Management Operation
 * @mos:	Management Operation Specific
 * @data:	Userspace address of the data buffer
 * @len:	Length of @data
 *
 * Initializes the passthru command buffer for the I/O Management
 * Receive command.
 */
static inline void
nvme_init_io_mgmt_recv(struct libnvme_passthru_cmd *cmd, __u32 nsid,
		__u8 mo, __u16 mos, void *data, __u32 len)
{
	memset(cmd, 0, sizeof(*cmd));

	cmd->opcode = nvme_cmd_io_mgmt_recv;
	cmd->nsid = nsid;
	cmd->data_len = len;
	cmd->addr = (__u64)(uintptr_t)data;
	cmd->cdw10 = NVME_FIELD_ENCODE(mo,
			NVME_IO_MGMT_RECV_CDW10_MO_SHIFT,
			NVME_IO_MGMT_RECV_CDW10_MO_MASK) |
		     NVME_FIELD_ENCODE(mos,
			NVME_IO_MGMT_RECV_CDW10_MOS_SHIFT,
			NVME_IO_MGMT_RECV_CDW10_MOS_MASK);
	cmd->cdw11 = (len >> 2) - 1;
}

/**
 * nvme_init_fdp_reclaim_unit_handle_status() - Initialize passthru command
 * to get reclaim unit handle status
 * @cmd:	Passthru command to use
 * @nsid:	Namespace identifier
 * @data:	Response buffer
 * @len:	Length of response buffer
 *
 * Initializes the passthru command buffer for the I/O Management Receive -
 * Reclaim Unit Handle Status command.
 */
static inline void
nvme_init_fdp_reclaim_unit_handle_status(struct libnvme_passthru_cmd *cmd,
		__u32 nsid, void *data, __u32 len)
{
	nvme_init_io_mgmt_recv(cmd, nsid, NVME_IO_MGMT_RECV_RUH_STATUS, 0,
		data, len);
}

/**
 * nvme_init_resv_release() - Initialize passthru command for
 * Reservation Release
 * @cmd:	Passthru command to use
 * @nsid:	Namespace identifier
 * @rrela:	Reservation release action, see &enum nvme_resv_rrela
 * @iekey:	Set to ignore the existing key
 * @disnsrs:	Disperse Namespace Reservation Support
 * @rtype:	The type of reservation to be create, see &enum nvme_resv_rtype
 * @crkey:	The current reservation key to release
 * @payload:	Data payload buffer to hold crkey
 *
 * Initializes the passthru command buffer for the Reservation Release command.
 */
static inline void
nvme_init_resv_release(struct libnvme_passthru_cmd *cmd, __u32 nsid,
		enum nvme_resv_rrela rrela, bool iekey, bool disnsrs,
		enum nvme_resv_rtype rtype, __u64 crkey, __le64 *payload)
{
	memset(cmd, 0, sizeof(*cmd));

	payload[0] = htole64(crkey);

	cmd->opcode = nvme_cmd_resv_release;
	cmd->nsid = nsid;
	cmd->data_len = sizeof(__le64);
	cmd->addr = (__u64)(uintptr_t)payload;
	cmd->cdw10 = NVME_FIELD_ENCODE(rrela,
			NVME_RESV_RELEASE_CDW10_RRELA_SHIFT,
			NVME_RESV_RELEASE_CDW10_RRELA_MASK) |
		     NVME_FIELD_ENCODE(iekey,
			NVME_RESV_RELEASE_CDW10_IEKEY_SHIFT,
			NVME_RESV_RELEASE_CDW10_IEKEY_MASK) |
		     NVME_FIELD_ENCODE(disnsrs,
			NVME_RESV_RELEASE_CDW10_DISNSRS_SHIFT,
			NVME_RESV_RELEASE_CDW10_DISNSRS_MASK) |
		     NVME_FIELD_ENCODE(rtype,
			NVME_RESV_RELEASE_CDW10_RTYPE_SHIFT,
			NVME_RESV_RELEASE_CDW10_RTYPE_MASK);
}

/**
 * nvme_init_copy() - Initialize passthru command for Copy command
 * @cmd:	Passthru command to use
 * @nsid:	Namespace identifier
 * @sdlba:	Start destination LBA
 * @nr:		Number of ranges (1-based, 0-based in command)
 * @desfmt:	Descriptor format
 * @prinfor:	Protection information field for read
 * @prinfow:	Protection information field for write
 * @cetype:	Command Extension Type
 * @dtype:	Directive Type
 * @stcw:	Storage Tag Check Write
 * @stcr:	Storage Tag Check Read
 * @fua:	Force unit access
 * @lr:		Limited retry
 * @cev:	Command Extension Value
 * @dspec:	Directive specific value
 * @cpydsc:	Range description buffer
 *
 * Initializes the passthru command buffer for the Copy command by calculating
 * the data length and calling the generic I/O initializer.
 */
static inline void
nvme_init_copy(struct libnvme_passthru_cmd *cmd, __u32 nsid, __u64 sdlba,
		__u16 nr, __u8 desfmt, __u8 prinfor, __u8 prinfow,
		__u8 cetype, __u8 dtype, bool stcw, bool stcr, bool fua,
		bool lr, __u16 cev, __u16 dspec, void *cpydsc)
{
	__u32 data_len;

	switch (desfmt) {
	case 1:
		data_len = nr * sizeof(struct nvme_copy_range_f1);
		break;
	case 2:
		data_len = nr * sizeof(struct nvme_copy_range_f2);
		break;
	case 3:
		data_len = nr * sizeof(struct nvme_copy_range_f3);
		break;
	default:
		data_len = nr * sizeof(struct nvme_copy_range_f0);
		break;
	}

	nvme_init_io(cmd, nvme_cmd_copy, nsid, sdlba, cpydsc,
		data_len, NULL, 0);
	cmd->cdw12 = NVME_FIELD_ENCODE(nr - 1,
			NVME_COPY_CDW12_NR_SHIFT,
			NVME_COPY_CDW12_NR_MASK) |
		     NVME_FIELD_ENCODE(desfmt,
			NVME_COPY_CDW12_DESFMT_SHIFT,
			NVME_COPY_CDW12_DESFMT_MASK) |
		     NVME_FIELD_ENCODE(prinfor,
			NVME_COPY_CDW12_PRINFOR_SHIFT,
			NVME_COPY_CDW12_PRINFOR_MASK) |
		     NVME_FIELD_ENCODE(cetype,
			NVME_COPY_CDW12_CETYPE_SHIFT,
			NVME_COPY_CDW12_CETYPE_MASK) |
		     NVME_FIELD_ENCODE(dtype,
			NVME_COPY_CDW12_DTYPE_SHIFT,
			NVME_COPY_CDW12_DTYPE_MASK) |
		     NVME_FIELD_ENCODE(stcw,
			NVME_COPY_CDW12_STCW_SHIFT,
			NVME_COPY_CDW12_STCW_MASK) |
		     NVME_FIELD_ENCODE(stcr,
			NVME_COPY_CDW12_STCR_SHIFT,
			NVME_COPY_CDW12_STCR_MASK) |
		     NVME_FIELD_ENCODE(prinfow,
			NVME_COPY_CDW12_PRINFOW_SHIFT,
			NVME_COPY_CDW12_PRINFOW_MASK) |
		     NVME_FIELD_ENCODE(fua,
			NVME_COPY_CDW12_FUA_SHIFT,
			NVME_COPY_CDW12_FUA_MASK) |
		     NVME_FIELD_ENCODE(lr,
			NVME_COPY_CDW12_LR_SHIFT,
			NVME_COPY_CDW12_LR_MASK);
	cmd->cdw13 = NVME_FIELD_ENCODE(cev,
			NVME_IOCS_COMMON_CDW13_CEV_SHIFT,
			NVME_IOCS_COMMON_CDW13_CEV_MASK) |
		     NVME_FIELD_ENCODE(dspec,
			NVME_IOCS_COMMON_CDW13_DSPEC_SHIFT,
			NVME_IOCS_COMMON_CDW13_DSPEC_MASK);
}

/**
 * nvme_init_io_mgmt_send() - Initialize passthru command for
 * I/O Management Send command
 * @cmd:	Passthru command to use
 * @nsid:	Namespace identifier
 * @mo:		Management Operation
 * @mos:	Management Operation Specific
 * @data:	Userspace address of the data buffer
 * @len:	Length of @data
 *
 * Initializes the passthru command buffer for the I/O Management Send command.
 */
static inline void
nvme_init_io_mgmt_send(struct libnvme_passthru_cmd *cmd, __u32 nsid,
		__u8 mo, __u16 mos, void *data, __u32 len)
{
	memset(cmd, 0, sizeof(*cmd));

	cmd->opcode = nvme_cmd_io_mgmt_send;
	cmd->nsid = nsid;
	cmd->data_len = len;
	cmd->addr = (__u64)(uintptr_t)data;
	cmd->cdw10 = NVME_FIELD_ENCODE(mo,
			NVME_IO_MGMT_SEND_CDW10_MO_SHIFT,
			NVME_IO_MGMT_SEND_CDW10_MO_MASK) |
		     NVME_FIELD_ENCODE(mos,
			NVME_IO_MGMT_SEND_CDW10_MOS_SHIFT,
			NVME_IO_MGMT_SEND_CDW10_MOS_MASK);
}

/**
 * nvme_init_fdp_reclaim_unit_handle_update() - Initialize passthru command to
 * update a list of reclaim unit handles
 * @cmd:	Passthru command to use
 * @nsid:	Namespace identifier
 * @pids:	List of placement identifiers buffer
 * @npids:	Number of placement identifiers
 *
 * Initializes the passthru command buffer for the I/O Management Send -
 * Reclaim Unit Handle Update command.
 */
static inline void
nvme_init_fdp_reclaim_unit_handle_update(struct libnvme_passthru_cmd *cmd,
		__u32 nsid, void *pids, unsigned int npids)
{
	__u16 mos = npids - 1; /* MOS = NPI - 1 */
	__u32 len = npids * sizeof(__u16);

	nvme_init_io_mgmt_send(cmd, nsid, NVME_IO_MGMT_SEND_RUH_UPDATE,
		mos, pids, len);
}

/*
 * Helper Functions
 */

/**
 * nvme_init_app_tag() - Initialize Command Dword fields for
 * Logical Block Application Tag/Mask
 * @cmd:	Passthru command to use
 * @lbat:	Logical block application tag
 * @lbatm:	Logical block application tag mask
 */
static inline void
nvme_init_app_tag(struct libnvme_passthru_cmd *cmd,
	__u16 lbat, __u16 lbatm)
{
	cmd->cdw15 = NVME_FIELD_ENCODE(lbat,
			NVME_IOCS_COMMON_CDW15_ELBAT_SHIFT,
			NVME_IOCS_COMMON_CDW15_ELBAT_MASK) |
		     NVME_FIELD_ENCODE(lbatm,
			NVME_IOCS_COMMON_CDW15_ELBATM_SHIFT,
			NVME_IOCS_COMMON_CDW15_ELBATM_MASK);
}


/**
 * nvme_init_dsm_range() - Constructs a data set range structure
 * @dsm:	DSM range array
 * @ctx_attrs:	Array of context attributes
 * @llbas:	Array of length in logical blocks
 * @slbas:	Array of starting logical blocks
 * @nr_ranges:	The size of the dsm arrays
 *
 * Each array must be the same size of size 'nr_ranges'. This is intended to be
 * used with constructing a payload for nvme_dsm().
 */
static inline void
nvme_init_dsm_range(struct nvme_dsm_range *dsm, __u32 *ctx_attrs,
		__u32 *llbas, __u64 *slbas, __u16 nr_ranges)
{
	int i;

	for (i = 0; i < nr_ranges; i++) {
		dsm[i].cattr = htole32(ctx_attrs[i]);
		dsm[i].nlb = htole32(llbas[i]);
		dsm[i].slba = htole64(slbas[i]);
	}
}

/**
 * nvme_init_copy_range_f0() - Constructs a copy range structure
 * @copy:	Copy range array
 * @nlbs:	Number of logical blocks
 * @slbas:	Starting LBA
 * @elbts:	Expected initial logical block reference tag
 * @elbatms:	Expected logical block application tag mask
 * @elbats:	Expected logical block application tag
 * @nr:		Number of descriptors to construct
 */
static inline void
nvme_init_copy_range_f0(struct nvme_copy_range_f0 *copy, __u16 *nlbs,
		__u64 *slbas, __u32 *elbts, __u16 *elbatms,
		__u16 *elbats, __u16 nr)
{
	int i;

	for (i = 0; i < nr; i++) {
		copy[i].nlb = htole16(nlbs[i]);
		copy[i].slba = htole64(slbas[i]);
		copy[i].elbt = htobe32(elbts[i]);
		copy[i].elbatm = htobe16(elbatms[i]);
		copy[i].elbat = htobe16(elbats[i]);
	}
}

/**
 * nvme_init_copy_range_f1() - Constructs a copy range f1 structure
 * @copy:	Copy range array
 * @nlbs:	Number of logical blocks
 * @slbas:	Starting LBA
 * @eilbrts:	Expected initial logical block reference tag
 * @elbatms:	Expected logical block application tag mask
 * @elbats:	Expected logical block application tag
 * @nr:		Number of descriptors to construct
 */
static inline void
nvme_init_copy_range_f1(struct nvme_copy_range_f1 *copy, __u16 *nlbs,
		__u64 *slbas, __u64 *eilbrts, __u16 *elbatms,
		__u16 *elbats, __u16 nr)
{
	int i;

	memset(copy, 0, sizeof(*copy) * nr);

	for (i = 0; i < nr; i++) {
		copy[i].nlb = htole16(nlbs[i]);
		copy[i].slba = htole64(slbas[i]);
		*(__be64 *)&copy[i].elbt[2] = htobe64(eilbrts[i]);
		copy[i].elbatm = htobe16(elbatms[i]);
		copy[i].elbat = htobe16(elbats[i]);
	}
}

/**
 * nvme_init_copy_range_f2() - Constructs a copy range f2 structure
 * @copy:	Copy range array
 * @snsids:	Source namespace identifier
 * @nlbs:	Number of logical blocks
 * @slbas:	Starting LBA
 * @sopts:	Source options
 * @elbts:	Expected initial logical block reference tag
 * @elbatms:	Expected logical block application tag mask
 * @elbats:	Expected logical block application tag
 * @nr:		Number of descriptors to construct
 */
static inline void
nvme_init_copy_range_f2(struct nvme_copy_range_f2 *copy,
		__u32 *snsids, __u16 *nlbs, __u64 *slbas, __u16 *sopts,
		__u32 *elbts, __u16 *elbatms, __u16 *elbats,
		__u16 nr)
{
	int i;

	for (i = 0; i < nr; i++) {
		copy[i].snsid = htole32(snsids[i]);
		copy[i].nlb = htole16(nlbs[i]);
		copy[i].slba = htole64(slbas[i]);
		copy[i].sopt = htole16(sopts[i]);
		copy[i].elbt = htobe32(elbts[i]);
		copy[i].elbatm = htobe16(elbatms[i]);
		copy[i].elbat = htobe16(elbats[i]);
	}
}

/**
 * nvme_init_copy_range_f3() - Constructs a copy range f3 structure
 * @copy:	Copy range array
 * @snsids:	Source namespace identifier
 * @nlbs:	Number of logical blocks
 * @slbas:	Starting LBA
 * @sopts:	Source options
 * @eilbrts:	Expected initial logical block reference tag
 * @elbatms:	Expected logical block application tag mask
 * @elbats:	Expected logical block application tag
 * @nr:		Number of descriptors to construct
 */
static inline void
nvme_init_copy_range_f3(struct nvme_copy_range_f3 *copy, __u32 *snsids,
		__u16 *nlbs, __u64 *slbas, __u16 *sopts,
		__u64 *eilbrts, __u16 *elbatms, __u16 *elbats,
		__u16 nr)
{
	int i;

	memset(copy, 0, sizeof(*copy) * nr);

	for (i = 0; i < nr; i++) {
		copy[i].snsid = htole32(snsids[i]);
		copy[i].nlb = htole16(nlbs[i]);
		copy[i].slba = htole64(slbas[i]);
		copy[i].sopt = htole16(sopts[i]);
		*(__be64 *)&copy[i].elbt[2] = htobe64(eilbrts[i]);
		copy[i].elbatm = htobe16(elbatms[i]);
		copy[i].elbat = htobe16(elbats[i]);
	}
}

/**
 * nvme_init_var_size_tags() - Initialize Command Dword fields
 * for Extended LBA based on Variable Sized Tags
 * @cmd:	Passthru command to use
 * @pif:	Protection information format, determines tag placement
 * @sts:	Storage tag size in bits
 * @reftag:	Expected Initial Logical Block Reference Tag (EILBRT)
 * @storage_tag: Expected Logical Block Storage Tag (ELBST)
 *
 * Initializes the passthru command buffer fields cdw2, cdw3, and cdw14
 * for commands supporting Extended LBA. This logic is usually called from
 * the command-specific init function (like nvme_init_zns_append).
 *
 * Return: 0 on success, -EINVAL otherwise.
 */
static inline int
nvme_init_var_size_tags(struct libnvme_passthru_cmd *cmd,
		__u8 pif, __u8 sts, __u64 reftag, __u64 storage_tag)
{
	__u32 cdw2 = 0, cdw3 = 0, cdw14 = 0;

	switch (pif) {
	case NVME_NVM_PIF_16B_GUARD:
		cdw14 = NVME_FIELD_ENCODE(reftag,
				NVME_IOCS_COMMON_CDW14_ELBTL_SHIFT,
				NVME_IOCS_COMMON_CDW14_ELBTL_MASK);
		cdw14 |= NVME_FIELD_ENCODE(storage_tag << (32 - sts),
				NVME_IOCS_COMMON_CDW14_ELBTL_SHIFT,
				NVME_IOCS_COMMON_CDW14_ELBTL_MASK);
		break;
	case NVME_NVM_PIF_32B_GUARD:
		cdw14 = NVME_FIELD_ENCODE(reftag,
				NVME_IOCS_COMMON_CDW14_ELBTL_SHIFT,
				NVME_IOCS_COMMON_CDW14_ELBTL_MASK);
		cdw3 = NVME_FIELD_ENCODE(reftag >> 32,
				NVME_IOCS_COMMON_CDW3_ELBTU_SHIFT,
				NVME_IOCS_COMMON_CDW3_ELBTU_MASK);
		cdw14 |= NVME_FIELD_ENCODE(
				(storage_tag << (80 - sts)) & 0xffff0000,
				NVME_IOCS_COMMON_CDW14_ELBTL_SHIFT,
				NVME_IOCS_COMMON_CDW14_ELBTL_MASK);
		if (sts >= 48)
			cdw3 |= NVME_FIELD_ENCODE(storage_tag >> (sts - 48),
					NVME_IOCS_COMMON_CDW3_ELBTU_SHIFT,
					NVME_IOCS_COMMON_CDW3_ELBTU_MASK);
		else
			cdw3 |= NVME_FIELD_ENCODE(storage_tag << (48 - sts),
					NVME_IOCS_COMMON_CDW3_ELBTU_SHIFT,
					NVME_IOCS_COMMON_CDW3_ELBTU_MASK);
		cdw2 = NVME_FIELD_ENCODE(storage_tag >> (sts - 16),
			NVME_IOCS_COMMON_CDW2_ELBTU_SHIFT,
			NVME_IOCS_COMMON_CDW2_ELBTU_MASK);
		break;
	case NVME_NVM_PIF_64B_GUARD:
		cdw14 = NVME_FIELD_ENCODE(reftag,
				NVME_IOCS_COMMON_CDW14_ELBTL_SHIFT,
				NVME_IOCS_COMMON_CDW14_ELBTL_MASK);
		cdw3 = NVME_FIELD_ENCODE((reftag >> 32) & 0xffff,
				NVME_IOCS_COMMON_CDW3_ELBTU_SHIFT,
				NVME_IOCS_COMMON_CDW3_ELBTU_MASK);
		cdw14 |= NVME_FIELD_ENCODE(storage_tag << (48 - sts),
				NVME_IOCS_COMMON_CDW14_ELBTL_SHIFT,
				NVME_IOCS_COMMON_CDW14_ELBTL_MASK);
		if (sts >= 16)
			cdw3 |= NVME_FIELD_ENCODE(
					(storage_tag >> (sts - 16)) & 0xffff,
					NVME_IOCS_COMMON_CDW3_ELBTU_SHIFT,
					NVME_IOCS_COMMON_CDW3_ELBTU_MASK);
		else
			cdw3 |= NVME_FIELD_ENCODE(
					(storage_tag << (16 - sts)) & 0xffff,
					NVME_IOCS_COMMON_CDW3_ELBTU_SHIFT,
					NVME_IOCS_COMMON_CDW3_ELBTU_MASK);
		break;
	default:
		return -EINVAL;
	}

	cmd->cdw2 = cdw2;
	cmd->cdw3 = cdw3;
	cmd->cdw14 = cdw14;

	return 0;
}

