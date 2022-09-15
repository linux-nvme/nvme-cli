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

#include <stdbool.h>
#include "types.h"

/*
 * _args struct definitions. These are used by both the ioctl-based and
 * MI-based interfaces, as the call interface for (admin/io/etc) NVMe commands,
 * passed to the nvme_*() and nvme_mi_*() functions.
 *
 * On MI-based interfaces, the fd and timeout members are unused, and should
 * be set to zero.
 */

/**
 * struct nvme_identify_args - Arguments for the NVMe Identify command
 * @result:		The command completion result from CQE dword0
 * @data:		User space destination address to transfer the data
 * @args_size:		Size of &struct nvme_identify_args
 * @fd:			File descriptor of nvme device
 * @timeout:		Timeout in ms (0 for default timeout)
 * @cns:		The Controller or Namespace structure, see @enum nvme_identify_cns
 * @csi:		Command Set Identifier
 * @nsid:		Namespace identifier, if applicable
 * @cntid:		The Controller Identifier, if applicable
 * @cns_specific_id:	Identifier that is required for a particular CNS value
 * @uuidx:		UUID Index if controller supports this id selection method
 */
struct nvme_identify_args {
	__u32 *result;
	void *data;
	int args_size;
	int fd;
	__u32 timeout;
	enum nvme_identify_cns cns;
	enum nvme_csi csi;
	__u32 nsid;
	__u16 cntid;
	__u16 cns_specific_id;
	__u8 uuidx;
};

/**
 * struct nvme_get_log_args - Arguments for the NVMe Admin Get Log command
 * @lpo:	Log page offset for partial log transfers
 * @result:	The command completion result from CQE dword0
 * @log:	User space destination address to transfer the data
 * @args_size:	Length of the structure
 * @fd:		File descriptor of nvme device
 * @timeout:	Timeout in ms
 * @lid:	Log page identifier, see &enum nvme_cmd_get_log_lid for known
 *		values
 * @len:	Length of provided user buffer to hold the log data in bytes
 * @nsid:	Namespace identifier, if applicable
 * @csi:	Command set identifier, see &enum nvme_csi for known values
 * @lsi:	Log Specific Identifier
 * @lsp:	Log specific field
 * @uuidx:	UUID selection, if supported
 * @rae:	Retain asynchronous events
 * @ot:		Offset Type; if set @lpo specifies the index into the list
 *		of data structures, otherwise @lpo specifies the byte offset
 *		into the log page.
 */
struct nvme_get_log_args {
	__u64 lpo;
	__u32 *result;
	void *log;
	int args_size;
	int fd;
	__u32 timeout;
	enum nvme_cmd_get_log_lid lid;
	__u32 len;
	__u32 nsid;
	enum nvme_csi csi;
	__u16 lsi;
	__u8 lsp;
	__u8 uuidx;
	bool rae;
	bool ot;
};

/**
 * struct nvme_set_features_args - Arguments for the NVMe Admin Set Feature command
 * @result:	The command completion result from CQE dword0
 * @data:	User address of feature data, if applicable
 * @args_size:	Size of &struct nvme_set_features_args
 * @fd:		File descriptor of nvme device
 * @timeout:	Timeout in ms
 * @nsid:	Namespace ID, if applicable
 * @cdw11:	Value to set the feature to
 * @cdw12:	Feature specific command dword12 field
 * @cdw13:	Feature specific command dword13 field
 * @cdw15:	Feature specific command dword15 field
 * @data_len:	Length of feature data, if applicable, in bytes
 * @save:	Save value across power states
 * @uuidx:	UUID Index for differentiating vendor specific encoding
 * @fid:	Feature identifier
 */
struct nvme_set_features_args {
	__u32 *result;
	void *data;
	int args_size;
	int fd;
	__u32 timeout;
	__u32 nsid;
	__u32 cdw11;
	__u32 cdw12;
	__u32 cdw13;
	__u32 cdw15;
	__u32 data_len;
	bool save;
	__u8 uuidx;
	__u8 fid;
};

/**
 * struct nvme_get_features_args - Arguments for the NVMe Admin Get Feature command
 * @args_size:	Size of &struct nvme_get_features_args
 * @fd:		File descriptor of nvme device
 * @result:	The command completion result from CQE dword0
 * @timeout:	Timeout in ms
 * @nsid:	Namespace ID, if applicable
 * @sel:	Select which type of attribute to return,
 *		see &enum nvme_get_features_sel
 * @cdw11:	Feature specific command dword11 field
 * @data_len:	Length of feature data, if applicable, in bytes
 * @data:	User address of feature data, if applicable
 * @fid:	Feature identifier, see &enum nvme_features_id
 * @uuidx:	UUID Index for differentiating vendor specific encoding
 */
struct nvme_get_features_args {
	__u32 *result;
	void *data;
	int args_size;
	int fd;
	__u32 timeout;
	__u32 nsid;
	enum nvme_get_features_sel sel;
	__u32 cdw11;
	__u32 data_len;
	__u8 fid;
	__u8 uuidx;
};

/**
 * struct nvme_format_nvm_args - Arguments for the Format Nvme Namespace command
 * @result:	The command completion result from CQE dword0
 * @args_size:	Size of &struct nvme_format_nvm_args
 * @fd:		File descriptor of nvme device
 * @timeout:	Set to override default timeout to this value in milliseconds;
 *		useful for long running formats. 0 will use system default.
 * @nsid:	Namespace ID to format
 * @mset:	Metadata settings (extended or separated), true if extended
 * @pi:		Protection information type
 * @pil:	Protection information location (beginning or end), true if end
 * @ses:	Secure erase settings
 * @lbaf:	Logical block address format least significant 4 bits
 * @rsvd1:	Reserved
 * @lbafu:	Logical block address format most significant 2 bits
 */
struct nvme_format_nvm_args {
	__u32 *result;
	int args_size;
	int fd;
	__u32 timeout;
	__u32 nsid;
	enum nvme_cmd_format_mset mset;
	enum nvme_cmd_format_pi pi;
	enum nvme_cmd_format_pil pil;
	enum nvme_cmd_format_ses ses;
	__u8 lbaf;
	__u8 rsvd1[7];
	__u8 lbafu;
};

/**
 * struct nvme_ns_mgmt_args - Arguments for NVMe Namespace Management command
 * @result:	NVMe command result
 * @ns:		Namespace identification descriptors
 * @args_size:	Size of &struct nvme_ns_mgmt_args
 * @fd:		File descriptor of nvme device
 * @timeout:	Timeout in ms
 * @nsid:	Namespace identifier
 * @sel:	Type of management operation to perform
 * @csi:	Command Set Identifier
 */
struct nvme_ns_mgmt_args {
	__u32 *result;
	struct nvme_id_ns *ns;
	int args_size;
	int fd;
	__u32 timeout;
	__u32 nsid;
	enum nvme_ns_mgmt_sel sel;
	__u8 csi;
};

/**
 * struct nvme_ns_attach_args - Arguments for Nvme Namespace Management command
 * @result:	NVMe command result
 * @ctrlist:	Controller list to modify attachment state of nsid
 * @args_size:	Size of &struct nvme_ns_attach_args
 * @fd:		File descriptor of nvme device
 * @timeout:	Timeout in ms
 * @nsid:	Namespace ID to execute attach selection
 * @sel:	Attachment selection, see &enum nvme_ns_attach_sel
 */
struct nvme_ns_attach_args {
	__u32 *result;
	struct nvme_ctrl_list *ctrlist;
	int args_size;
	int fd;
	__u32 timeout;
	__u32 nsid;
	enum nvme_ns_attach_sel sel;
};

/**
 * struct nvme_fw_download_args - Arguments for the NVMe Firmware Download command
 * @args_size:	Size of &struct nvme_fw_download_args
 * @fd:		File descriptor of nvme device
 * @result:	The command completion result from CQE dword0
 * @timeout:	Timeout in ms
 * @offset:	Offset in the firmware data
 * @data:	Userspace address of the firmware data
 * @data_len:	Length of data in this command in bytes
 */
struct nvme_fw_download_args {
	__u32 *result;
	void *data;
	int args_size;
	int fd;
	__u32 timeout;
	__u32 offset;
	__u32 data_len;
};

/**
 * struct nvme_fw_commit_args - Arguments for the NVMe Firmware Commit command
 * @args_size:	Size of &struct nvme_fw_commit_args
 * @fd:		File descriptor of nvme device
 * @action:	Action to use for the firmware image, see &enum nvme_fw_commit_ca
 * @timeout:	Timeout in ms
 * @result:	The command completion result from CQE dword0
 * @slot:	Firmware slot to commit the downloaded image
 * @bpid:	Set to true to select the boot partition id
 */
struct nvme_fw_commit_args {
	__u32 *result;
	int args_size;
	int fd;
	__u32 timeout;
	enum nvme_fw_commit_ca action;
	__u8 slot;
	bool bpid;
};

/**
 * struct nvme_security_send_args - Arguments for the NVMe Security Send command
 * @result:	The command completion result from CQE dword0
 * @data:	Security data payload to send
 * @args_size:	Size of &struct nvme_security_send_args
 * @fd:		File descriptor of nvme device
 * @timeout:	Timeout in ms
 * @nsid:	Namespace ID to issue security command on
 * @tl:		Protocol specific transfer length
 * @data_len:	Data length of the payload in bytes
 * @nssf:	NVMe Security Specific field
 * @spsp0:	Security Protocol Specific field
 * @spsp1:	Security Protocol Specific field
 * @secp:	Security Protocol
 */
struct nvme_security_send_args {
	__u32 *result;
	void *data;
	int args_size;
	int fd;
	__u32 timeout;
	__u32 nsid;
	__u32 tl;
	__u32 data_len;
	__u8 nssf;
	__u8 spsp0;
	__u8 spsp1;
	__u8 secp;
};

/**
 * struct nvme_security_receive_args - Arguments for the NVMe Security Receive command
 * @result:	The command completion result from CQE dword0
 * @data:	Security data payload to send
 * @args_size:	Size of &struct nvme_security_receive_args
 * @fd:		File descriptor of nvme device
 * @timeout:	Timeout in ms
 * @nsid:	Namespace ID to issue security command on
 * @al:		Protocol specific allocation length
 * @data_len:	Data length of the payload in bytes
 * @nssf:	NVMe Security Specific field
 * @spsp0:	Security Protocol Specific field
 * @spsp1:	Security Protocol Specific field
 * @secp:	Security Protocol
 */
struct nvme_security_receive_args {
	__u32 *result;
	void *data;
	int args_size;
	int fd;
	__u32 timeout;
	__u32 nsid;
	__u32 al;
	__u32 data_len;
	__u8 nssf;
	__u8 spsp0;
	__u8 spsp1;
	__u8 secp;
};

/**
 * struct nvme_get_lba_status_args - Arguments for the NVMe Get LBA Status command
 * @lbas:	Data payload to return status descriptors
 * @result:	The command completion result from CQE dword0
 * @slba:	Starting logical block address to check statuses
 * @args_size:	Size of &struct nvme_get_lba_status_args
 * @fd:		File descriptor of nvme device
 * @timeout:	Timeout in ms
 * @nsid:	Namespace ID to retrieve LBA status
 * @mndw:	Maximum number of dwords to return
 * @atype:	Action type mechanism to determine LBA status descriptors to
 *		return, see &enum nvme_lba_status_atype
 * @rl:		Range length from slba to perform the action
 */
struct nvme_get_lba_status_args {
	__u64 slba;
	__u32 *result;
	struct nvme_lba_status *lbas;
	int args_size;
	int fd;
	__u32 timeout;
	__u32 nsid;
	__u32 mndw;
	enum nvme_lba_status_atype atype;
	__u16 rl;
};

/**
 * struct nvme_directive_send_args - Arguments for the NVMe Directive Send command
 * @result:	If successful, the CQE dword0 value
 * @data:	Data payload to be send
 * @args_size:	Size of &struct nvme_directive_send_args
 * @fd:		File descriptor of nvme device
 * @timeout:	Timeout in ms
 * @nsid:	Namespace ID, if applicable
 * @doper:	Directive send operation, see &enum nvme_directive_send_doper
 * @dtype:	Directive type, see &enum nvme_directive_dtype
 * @cdw12:	Directive specific command dword12
 * @data_len:	Length of data payload in bytes
 * @dspec:	Directive specific field
 */
struct nvme_directive_send_args {
	__u32 *result;
	void *data;
	int args_size;
	int fd;
	__u32 timeout;
	__u32 nsid;
	enum nvme_directive_send_doper doper;
	enum nvme_directive_dtype dtype;
	__u32 cdw12;
	__u32 data_len;
	__u16 dspec;
};

/**
 * struct nvme_directive_recv_args - Arguments for the NVMe Directive Receive command
 * @result:	If successful, the CQE dword0 value
 * @data:	Userspace address of data payload
 * @args_size:	Size of &struct nvme_directive_recv_args
 * @fd:		File descriptor of nvme device
 * @timeout:	Timeout in ms
 * @nsid:	Namespace ID, if applicable
 * @doper:	Directive send operation, see &enum nvme_directive_send_doper
 * @dtype:	Directive type, see &enum nvme_directive_dtype
 * @cdw12:	Directive specific command dword12
 * @data_len:	Length of data payload in bytes
 * @dspec:	Directive specific field
 */
struct nvme_directive_recv_args {
	__u32 *result;
	void *data;
	int args_size;
	int fd;
	__u32 timeout;
	__u32 nsid;
	enum nvme_directive_receive_doper doper;
	enum nvme_directive_dtype dtype;
	__u32 cdw12;
	__u32 data_len;
	__u16 dspec;
};

/**
 * struct nvme_capacity_mgmt_args - Arguments for the NVMe Capacity Management command
 * @result:	If successful, the CQE dword0 value
 * @args_size:	Size of &struct nvme_capacity_mgmt_args
 * @fd:		File descriptor of nvme device
 * @cdw11:	Least significant 32 bits of the capacity in bytes of the
 *		Endurance Group or NVM Set to be created
 * @cdw12:	Most significant 32 bits of the capacity in bytes of the
 *		Endurance Group or NVM Set to be created
 * @timeout:	Timeout in ms
 * @element_id:	Value specific to the value of the Operation field
 * @op:		Operation to be performed by the controller
 */
struct nvme_capacity_mgmt_args {
	__u32 *result;
	int args_size;
	int fd;
	__u32 timeout;
	__u32 cdw11;
	__u32 cdw12;
	__u16 element_id;
	__u8 op;
};

/**
 * struct nvme_lockdown_args - Arguments for the NVME Lockdown command
 * @args_size:	Size of &struct nvme_lockdown_args
 * @fd:		File descriptor of nvme device
 * @result:	The command completion result from CQE dword0
 * @timeout:	Timeout in ms (0 for default timeout)
 * @scp:	Scope of the command
 * @prhbt:	Prohibit or allow the command opcode or Set Features command
 * @ifc:	Affected interface
 * @ofi:	Opcode or Feature Identifier
 * @uuidx:	UUID Index if controller supports this id selection method
 */
struct nvme_lockdown_args {
	__u32 *result;
	int args_size;
	int fd;
	__u32 timeout;
	__u8 scp;
	__u8 prhbt;
	__u8 ifc;
	__u8 ofi;
	__u8 uuidx;
};

/**
 * struct nvme_set_property_args - Arguments for NVMe Set Property command
 * @args_size:	Size of &struct nvme_set_property_args
 * @fd:		File descriptor of nvme device
 * @result:	The command completion result from CQE dword0
 * @timeout:	Timeout in ms
 * @offset:	Property offset from the base to set
 * @value:	The value to set the property
 */
struct nvme_set_property_args {
	__u64 value;
	__u32 *result;
	int args_size;
	int fd;
	__u32 timeout;
	int offset;
};

/**
 * struct nvme_get_property_args - Arguments for NVMe Get Property command
 * @value:	Where the property's value will be stored on success
 * @args_size:	Size of &struct nvme_get_property_args
 * @fd:		File descriptor of nvme device
 * @offset:	Property offset from the base to retrieve
 * @timeout:	Timeout in ms
 */
struct nvme_get_property_args {
	__u64 *value;
	int args_size;
	int fd;
	__u32 timeout;
	int offset;
};

/**
 * struct nvme_sanitize_nvm_args - Arguments for the NVMe Sanitize NVM command
 * @result:	The command completion result from CQE dword0
 * @args_size:	Size of &struct nvme_sanitize_nvm_args
 * @fd:		File descriptor of nvme device
 * @timeout:	Timeout in ms
 * @ovrpat:	Overwrite pattern
 * @sanact:	Sanitize action, see &enum nvme_sanitize_sanact
 * @ause:	Set to allow unrestricted sanitize exit
 * @owpass:	Overwrite pass count
 * @oipbp:	Set to overwrite invert pattern between passes
 * @nodas:	Set to not deallocate blocks after sanitizing
 */
struct nvme_sanitize_nvm_args {
	__u32 *result;
	int args_size;
	int fd;
	__u32 timeout;
	enum nvme_sanitize_sanact sanact;
	__u32 ovrpat;
	bool ause;
	__u8 owpass;
	bool oipbp;
	bool nodas;
};

/**
 * struct nvme_dev_self_test_args - Arguments for the NVMe Device Self Test command
 * @result:	The command completion result from CQE dword0
 * @args_size:	Size of &struct nvme_dev_self_test_args
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace ID to test
 * @stc:	Self test code, see &enum nvme_dst_stc
 * @timeout:	Timeout in ms
 */
struct nvme_dev_self_test_args {
	__u32 *result;
	int args_size;
	int fd;
	__u32 timeout;
	__u32 nsid;
	enum nvme_dst_stc stc;
};

/**
 * struct nvme_virtual_mgmt_args - Arguments for the NVMe Virtualization
 *			    resource management command
 * @args_size:	Size of &struct nvme_virtual_mgmt_args
 * @fd:		File descriptor of nvme device
 * @result:	If successful, the CQE dword0
 * @timeout:	Timeout in ms
 * @act:	Virtual resource action, see &enum nvme_virt_mgmt_act
 * @rt:		Resource type to modify, see &enum nvme_virt_mgmt_rt
 * @cntlid:	Controller id for which resources are bing modified
 * @nr:		Number of resources being allocated or assigned
 */
struct nvme_virtual_mgmt_args {
	__u32 *result;
	int args_size;
	int fd;
	__u32 timeout;
	enum nvme_virt_mgmt_act act;
	enum nvme_virt_mgmt_rt rt;
	__u16 cntlid;
	__u16 nr;
};

/**
 * struct nvme_io_args - Arguments for NVMe I/O commands
 * @slba:	Starting logical block
 * @storage_tag: This filed specifies Variable Sized Expected Logical Block
 *		Storage Tag (ELBST) or Logical Block Storage Tag (LBST)
 * @result:	The command completion result from CQE dword0
 * @data:	Pointer to user address of the data buffer
 * @metadata:	Pointer to user address of the metadata buffer
 * @args_size:	Size of &struct nvme_io_args
 * @fd:		File descriptor of nvme device
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
	int fd;
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
 * struct nvme_dsm_args - Arguments for the NVMe Dataset Management command
 * @result:	The command completion result from CQE dword0
 * @dsm:	The data set management attributes
 * @args_size:	Size of &struct nvme_dsm_args
 * @fd:		File descriptor of nvme device
 * @timeout:	Timeout in ms
 * @nsid:	Namespace identifier
 * @attrs:	DSM attributes, see &enum nvme_dsm_attributes
 * @nr_ranges:	Number of block ranges in the data set management attributes
 */
struct nvme_dsm_args {
	__u32 *result;
	struct nvme_dsm_range *dsm;
	int args_size;
	int fd;
	__u32 timeout;
	__u32 nsid;
	__u32 attrs;
	__u16 nr_ranges;
};

/**
 * struct nvme_copy_args - Arguments for the NVMe Copy command
 * @sdlba:	Start destination LBA
 * @result:	The command completion result from CQE dword0
 * @copy:	Range description
 * @args_size:	Size of &struct nvme_copy_args
 * @fd:		File descriptor of the nvme device
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
	int fd;
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
 * struct nvme_resv_acquire_args - Arguments for the NVMe Reservation Acquire Command
 * @nrkey:	The reservation key to be unregistered from the namespace if
 *		the action is preempt
 * @iekey:	Set to ignore the existing key
 * @result:	The command completion result from CQE dword0
 * @args_size:	Size of &struct nvme_resv_acquire_args
 * @fd:		File descriptor of nvme device
 * @timeout:	Timeout in ms
 * @nsid:	Namespace identifier
 * @rtype:	The type of reservation to be create, see &enum nvme_resv_rtype
 * @racqa:	The action that is performed by the command, see &enum nvme_resv_racqa
 * @crkey:	The current reservation key associated with the host
 */
struct nvme_resv_acquire_args {
	__u64 crkey;
	__u64 nrkey;
	__u32 *result;
	int args_size;
	int fd;
	__u32 timeout;
	__u32 nsid;
	enum nvme_resv_rtype rtype;
	enum nvme_resv_racqa racqa;
	bool iekey;
};

/**
 * struct nvme_resv_register_args - Arguments for the NVMe Reservation Register command
 * @crkey:	The current reservation key associated with the host
 * @nrkey:	The new reservation key to be register if action is register or
 *		replace
 * @result:	The command completion result from CQE dword0
 * @args_size:	Size of &struct nvme_resv_register_args
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace identifier
 * @rrega:	The registration action, see &enum nvme_resv_rrega
 * @cptpl:	Change persist through power loss, see &enum nvme_resv_cptpl
 * @iekey:	Set to ignore the existing key
 * @timeout:	Timeout in ms
 */
struct nvme_resv_register_args {
	__u64 crkey;
	__u64 nrkey;
	__u32 *result;
	int args_size;
	int fd;
	__u32 timeout;
	__u32 nsid;
	enum nvme_resv_rrega rrega;
	enum nvme_resv_cptpl cptpl;
	bool iekey;
};

/**
 * struct nvme_resv_release_args - Arguments for the NVMe Reservation Release Command
 * @crkey:	The current reservation key to release
 * @result:	The command completion result from CQE dword0
 * @args_size:	Size of &struct nvme_resv_release_args
 * @fd:		File descriptor of nvme device
 * @timeout:	Timeout in ms
 * @nsid:	Namespace identifier
 * @rtype:	The type of reservation to be create, see &enum nvme_resv_rtype
 * @rrela:	Reservation release action, see &enum nvme_resv_rrela
 * @iekey:	Set to ignore the existing key
 */
struct nvme_resv_release_args {
	__u64 crkey;
	__u32 *result;
	int args_size;
	int fd;
	__u32 timeout;
	__u32 nsid;
	enum nvme_resv_rtype rtype;
	enum nvme_resv_rrela rrela;
	bool iekey;
};

/**
 * struct nvme_resv_report_args - Arguments for the NVMe Reservation Report command
 * @result:	The command completion result from CQE dword0
 * @report:	The user space destination address to store the reservation
 *		report
 * @args_size:	Size of &struct nvme_resv_report_args
 * @fd:		File descriptor of nvme device
 * @timeout:	Timeout in ms
 * @nsid:	Namespace identifier
 * @len:	Number of bytes to request transferred with this command
 * @eds:	Request extended Data Structure
 */
struct nvme_resv_report_args {
	__u32 *result;
	struct nvme_resv_status *report;
	int args_size;
	int fd;
	__u32 timeout;
	__u32 nsid;
	__u32 len;
	bool eds;
};

/**
 * struct nvme_io_mgmt_recv_args - Arguments for the NVMe I/O Management Receive command
 * @data:	Userspace address of the data
 * @args_size:	Size of &struct nvme_io_mgmt_recv_args
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace identifier
 * @data_len:	Length of @data
 * @timeout:	Timeout in ms
 * @mos		Management Operation Specific
 * @mo		Management Operation
 */
struct nvme_io_mgmt_recv_args {
	void *data;
	int args_size;
	int fd;
	__u32 nsid;
	__u32 data_len;
	__u32 timeout;
	__u16 mos;
	__u8 mo;
};

/**
 * struct nvme_io_mgmt_send_args - Arguments for the NVMe I/O Management Send command
 * @data:	Userspace address of the data
 * @args_size:	Size of &struct nvme_io_mgmt_send_args
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace identifier
 * @data_len:	Length of @data
 * @timeout:	Timeout in ms
 * @mos		Management Operation Specific
 * @mo		Management Operation
 */
struct nvme_io_mgmt_send_args {
	void *data;
	int args_size;
	int fd;
	__u32 nsid;
	__u32 data_len;
	__u32 timeout;
	__u16 mos;
	__u8 mo;
};

/**
 * struct nvme_zns_mgmt_send_args - Arguments for the NVMe ZNS Management Send command
 * @slba:	Starting logical block address
 * @result:	The command completion result from CQE dword0
 * @data:	Userspace address of the data
 * @args_size:	Size of &struct nvme_zns_mgmt_send_args
 * @fd:		File descriptor of nvme device
 * @timeout:	timeout in ms
 * @nsid:	Namespace ID
 * @zsa:	Zone send action
 * @data_len:	Length of @data
 * @select_all:	Select all flag
 * @zsaso:	Zone Send Action Specific Option
 */
struct nvme_zns_mgmt_send_args {
	__u64 slba;
	__u32 *result;
	void *data;
	int args_size;
	int fd;
	__u32 timeout;
	__u32 nsid;
	enum nvme_zns_send_action zsa;
	__u32 data_len;
	bool select_all;
	__u8 zsaso;
};

/**
 * struct nvme_zns_mgmt_recv_args - Arguments for the NVMe ZNS Management Receive command
 * @slba:	Starting logical block address
 * @result:	The command completion result from CQE dword0
 * @data:	Userspace address of the data
 * @args_size:	Size of &struct nvme_zns_mgmt_recv_args
 * @fd:		File descriptor of nvme device
 * @timeout:	timeout in ms
 * @nsid:	Namespace ID
 * @zra:	zone receive action
 * @data_len:	Length of @data
 * @zrasf:	Zone receive action specific field
 * @zras_feat:	Zone receive action specific features
 */
struct nvme_zns_mgmt_recv_args {
	__u64 slba;
	__u32 *result;
	void *data;
	int args_size;
	int fd;
	__u32 timeout;
	__u32 nsid;
	enum nvme_zns_recv_action zra;
	__u32 data_len;
	__u16 zrasf;
	bool zras_feat;
};

/**
 * struct nvme_zns_append_args - Arguments for the NVMe ZNS Append command
 * @zslba:	Zone start logical block address
 * @result:	The command completion result from CQE dword0
 * @data:	Userspace address of the data
 * @metadata:	Userspace address of the metadata
 * @args_size:	Size of &struct nvme_zns_append_args
 * @fd:		File descriptor of nvme device
 * @timeout:	Timeout in ms
 * @nsid:	Namespace ID
 * @ilbrt:	Initial logical block reference tag
 * @data_len:	Length of @data
 * @metadata_len: Length of @metadata
 * @nlb:	Number of logical blocks
 * @control:
 * @lbat:	Logical block application tag
 * @lbatm:	Logical block application tag mask
 * @rsvd1:	Reserved
 * @ilbrt_u64:	Initial logical block reference tag - 8 byte
 *              version required for enhanced protection info
 *
 */
struct nvme_zns_append_args {
	__u64 zslba;
	__u64 *result;
	void *data;
	void *metadata;
	int args_size;
	int fd;
	__u32 timeout;
	__u32 nsid;
	__u32 ilbrt;
	__u32 data_len;
	__u32 metadata_len;
	__u16 nlb;
	__u16 control;
	__u16 lbat;
	__u16 lbatm;
	__u8  rsvd1[4];
	__u64 ilbrt_u64;
};

/**
 * struct nvme_dim_args - Arguments for the Discovery Information Management (DIM) command
 * @result:	Set on completion to the command's CQE DWORD 0 controller response.
 * @data:	Pointer to the DIM data
 * @args_size:	Length of the structure
 * @fd:		File descriptor of nvme device
 * @timeout:	Timeout in ms
 * @data_len:	Length of @data
 * @tas:	Task field of the Command Dword 10 (cdw10)
 */
struct nvme_dim_args {
	__u32	*result;
	void	*data;
	int	args_size;
	int	fd;
	__u32	timeout;
	__u32	data_len;
	__u8	tas;
};

#endif /* _LIBNVME_API_TYPES_H */
