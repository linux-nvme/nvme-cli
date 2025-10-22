// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * Types used as part of the libnvme/libnvme-mi API, rather than specified
 * by the NVM Express specification.
 *
 * These are shared across both libnvme and libnvme-mi interfaces.
 *
 * This file is part of libnvme.
 * Copyright (c) 2022 Code Construct
 *
 * Authors: Jeremy Kerr <jk@codeconstruct.com.au>
 */
#ifndef _LIBNVME_API_TYPES_H
#define _LIBNVME_API_TYPES_H

#include <stdio.h>
#include <stdbool.h>

#include <nvme/types.h>

struct nvme_global_ctx;
struct nvme_transport_handle;

/**
 * nvme_create_global_ctx() - Initialize global context object
 * @fp:		File descriptor for logging messages
 * @log_level:	Logging level to use
 *
 * Return: Initialized &struct nvme_global_ctx object
 */
struct nvme_global_ctx *nvme_create_global_ctx(FILE *fp, int log_level);

/**
 * nvme_free_global_ctx() - Free global context object
 * @ctx:	&struct nvme_global_ctx object
 *
 * Free an &struct nvme_global_ctx object and all attached objects
 */
void nvme_free_global_ctx(struct nvme_global_ctx *ctx);

/**
 * struct nvme_io_args - Arguments for NVMe I/O commands
 * @slba:	Starting logical block
 * @storage_tag: This filed specifies Variable Sized Expected Logical Block
 *		Storage Tag (ELBST) or Logical Block Storage Tag (LBST)
 * @result:	The command completion result from CQE dword0
 * @data:	Pointer to user address of the data buffer
 * @metadata:	Pointer to user address of the metadata buffer
 * @args_size:	Size of &struct nvme_io_args
 * @timeout:	Timeout in ms
 * @nsid:	Namespace ID
 * @data_len:	Length of user buffer, @data, in bytes
 * @metadata_len:Length of user buffer, @metadata, in bytes
 * @nlb:	Number of logical blocks to send (0's based value)
 * @control:	Command control flags, see &enum nvme_io_control_flags.
 * @apptag:	This field specifies the Application Tag Mask expected value.
 *		Used only if the namespace is formatted to use end-to-end
 *		protection information.
 * @appmask:	This field specifies the Application Tag expected value. Used
 *		only if the namespace is formatted to use end-to-end protection
 *		information.
 * @reftag:	This field specifies the variable sized Expected Initial
 *		Logical Block Reference Tag (EILBRT) or Initial Logical Block
 *		Reference Tag (ILBRT). Used only if the namespace is formatted
 *		to use end-to-end protection information.
 * @dspec:	Directive specific value
 * @dsm:	Data set management attributes, see &enum nvme_io_dsm_flags
 * @rsvd1:	Reserved
 * @reftag_u64:	This field specifies the variable sized Expected Initial
 *		Logical Block Reference Tag (EILBRT) or Initial Logical Block
 *		Reference Tag (ILBRT). It is the 8 byte version required for
 *		enhanced protection information.  Used only if the namespace is
 *		formatted to use end-to-end protection information.
 * @sts:	Storage tag size in bits, set by namespace Extended LBA Format
 * @pif:	Protection information format, determines how variable sized
 *		storage_tag and reftag are put into dwords 2, 3, and 14. Set by
 *		namespace Extended LBA Format.
 */
struct nvme_io_args {
	__u64 slba;
	__u64 storage_tag;
	__u32 *result;
	void *data;
	void *metadata;
	int args_size;
	__u32 timeout;
	__u32 nsid;
	__u32 reftag;
	__u32 data_len;
	__u32 metadata_len;
	__u16 nlb;
	__u16 control;
	__u16 apptag;
	__u16 appmask;
	__u16 dspec;
	__u8 dsm;
	__u8 rsvd1[1];
	__u64 reftag_u64;
	__u8 sts;
	__u8 pif;
};

/**
 * struct nvme_copy_args - Arguments for the NVMe Copy command
 * @sdlba:	Start destination LBA
 * @result:	The command completion result from CQE dword0
 * @copy:	Range description
 * @args_size:	Size of &struct nvme_copy_args
 * @timeout:	Timeout in ms
 * @nsid:	Namespace identifier
 * @ilbrt:	Initial logical block reference tag
 * @lr:		Limited retry
 * @fua:	Force unit access
 * @nr:		Number of ranges
 * @dspec:	Directive specific value
 * @lbatm:	Logical block application tag mask
 * @lbat:	Logical block application tag
 * @prinfor:	Protection information field for read
 * @prinfow:	Protection information field for write
 * @dtype:	Directive type
 * @format:	Descriptor format
 * @ilbrt_u64:	Initial logical block reference tag - 8 byte
 *              version required for enhanced protection info
 */
struct nvme_copy_args {
	__u64 sdlba;
	__u32 *result;
	struct nvme_copy_range *copy;
	int args_size;
	__u32 timeout;
	__u32 nsid;
	__u32 ilbrt;
	int lr;
	int fua;
	__u16 nr;
	__u16 dspec;
	__u16 lbatm;
	__u16 lbat;
	__u8 prinfor;
	__u8 prinfow;
	__u8 dtype;
	__u8 format;
	__u64 ilbrt_u64;
};

/**
 * struct nvme_dim_args - Arguments for the Discovery Information Management (DIM) command
 * @result:	Set on completion to the command's CQE DWORD 0 controller response.
 * @data:	Pointer to the DIM data
 * @args_size:	Length of the structure
 * @timeout:	Timeout in ms
 * @data_len:	Length of @data
 * @tas:	Task field of the Command Dword 10 (cdw10)
 */
struct nvme_dim_args {
	__u32	*result;
	void	*data;
	int	args_size;
	__u32	timeout;
	__u32	data_len;
	__u8	tas;
};

/**
 * struct nvme_lm_cdq_args - Arguments for Controller Data Queue (CDQ) command
 * @result:	Set on completion to the command's CQE DWORD 0 controller response
 * @data:	Pointer to data
 * @args_size:	Length of structure
 * @timeout:	Timeout in ms
 * @mos:	Management Operation Specific (MOS): This field is specific to the SEL type
 * @cntlid:	Controller ID: For Create CDQ, specifies the target migratable controller
 * @cdqid:	Controller Data Queue ID (CDQID): For Create CDQ, this field is the CDQID created
 *		by the controller if no error is present. For Delete CDQ, this field is the CDQID
 *		to delete.
 * @sel:	Select (SEL): This field specifies the type of management operation to perform.
 * @sz_u8:	For Create CDQ, specifies the size of CDQ, in dwords - 1 byte
 * @rsvd1:	Reserved
 * @sz:		For Create CDQ, specifies the size of CDQ, in dwords - 4 byte
 */
struct nvme_lm_cdq_args {
	__u32	*result;
	void	*data;
	int	args_size;
	__u32	timeout;
	__u16	mos;
	__u16	cntlid;
	__u16	cdqid;
	__u8	sel;
	__u8	sz_u8;
	__u8	rsvd1[4];
	__u32	sz;
};

/**
 * struct nvme_lm_track_send_args - Arguments for the Track Send command
 * @result:	Set on completion to the command's CQE DWORD 0 controller response
 * @args_size:	Length of structure
 * @timeout:	Timeout in ms
 * @mos:	Management Operation Specific (MOS): This field is specific to the SEL type
 * @cdqid:	Controller Data Queue ID (CDQID)
 * @sel:	Select (SEL): This field specifies the type of management operation to perform
 */
struct nvme_lm_track_send_args {
	__u32	*result;
	int	args_size;
	__u32	timeout;
	__u16	mos;
	__u16	cdqid;
	__u8	sel;
};

/**
 * struct nvme_lm_migration_send_args - Arguments for the Migration Send command
 * @offset:	Offset: This field specifies the offset, in bytes, within the data available to be
 *		returned and specifies the starting point for that data for what is actually
 *		returned to the host.
 * @result:	Set on completion to the command's CQE DWORD 0 controller response
 * @data:	Pointer to data
 * @args_size:	Length of structure
 * @timeout:	Timeout in ms
 * @numd:	Number of Dwords (NUMD): This field specifies the number of dwords being transferred
 * @mos:	Management Operation Specific (MOS): This field is specific to the SEL type
 * @cntlid:	Controller ID: This field specifies the identifier of the controller to which the
 *		operation is performed.
 * @csuuidi:	Controller State UUID Index (CSUUIDI): A non-zero value in this field specifies the
 *		index to a specific entry in the Vendor Specific Controller State UUID Supported.
 *		list of the Supported Controller State Formats data structure.
 * @sel:	Select (SEL): This field specifies the type of management operation to perform.
 * @uidx:	UUID Index (UIDX): If this field is set to a non-zero value, then the value of this
 *		field is the index of a UUID in the UUID List (refer to Figure 320) that is used by
 *		the command.
 * @stype:	Suspend Type (STYPE): This field specifies the type of suspend.
 * @seqind:	Sequence Identifier (SEQIND): This field identified the sequences of this Migration
 *		Send command in relation to other Migration Send commands.
 * @csvi:	Controller State Version Index (CSVI): A non-zero value in this field specifies the
 *		index to a specific entry in the NVMe Controller State Version list of the Supported
 *		Controller State Formats data structure.
 * @dudmq:	Delete User Data Migration Queue (DUDMQ): If set, the migration queue is deleted
 *		is deleted as part of the Suspend operation. If cleared, it is retained.
 */
struct nvme_lm_migration_send_args {
	__u64	offset;
	__u32	*result;
	void	*data;
	int	args_size;
	__u32	timeout;
	__u32	numd;
	__u16	mos;
	__u16	cntlid;
	__u16	csuuidi;
	__u8	sel;
	__u8	uidx;
	__u8	stype;
	__u8	seqind;
	__u8	csvi;
	bool	dudmq;
};

/**
 * struct nvme_lm_migration_recv_args - Arguments for the Migration Receive command
 * @offset:	Offset: This field specifies the offset, in bytes, within the data available to be
 *		returned and specifies the starting point for that data for what is actually
 *		returned to the host.
 * @result:	Set on completion to the command's CQE DWORD 0 controller response
 * @data:	Pointer to data
 * @args_size:	Length of structure
 * @fd:		File descriptor of nvme device
 * @timeout:	Timeout in ms
 * @numd:	Number of Dwords (NUMD): This field specifies the number of dwords to return. This
 *		is a 0's based value.
 * @mos:	Management Operation Specific (MOS): This field is specific to the SEL type
 * @cntlid:	Controller ID: This field specifies the identifier of the controller to which the
 *		operation is performed.
 * @csuuidi:	Controller State UUID Index (CSUUIDI): A non-zero value in this field specifies the
 *		index to a specific entry in the Vendor Specific Controller State UUID Supported.
 *		list of the Supported Controller State Formats data structure.
 * @sel:	Select (SEL): This field specifies the type of management operation to perform
 * @uidx:	UUID Index (UIDX): If this field is set to a non-zero value, then the value of this
 *		field is the index of a UUID in the UUID List (refer to Figure 320) that is used by
 *		the command.
 * @csuidxp:	Controller State UUID Index Parameter (CSUIDXP): This field is vendor specific.
 */
struct nvme_lm_migration_recv_args {
	__u64	offset;
	__u32	*result;
	void	*data;
	int	args_size;
	int	fd;
	__u32	timeout;
	__u32	numd;
	__u16	mos;
	__u16	cntlid;
	__u16	csuuidi;
	__u8	sel;
	__u8	uidx;
	__u8	csuidxp;
};

#endif /* _LIBNVME_API_TYPES_H */
