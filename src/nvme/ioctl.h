// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 * 	    Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 */

#ifndef _LIBNVME_IOCTL_H
#define _LIBNVME_IOCTL_H

#include <stddef.h>
#include <sys/ioctl.h>
#include "types.h"

/*
 * We can not always count on the kernel UAPI being installed. Use the same
 * 'ifdef' guard to avoid double definitions just in case.
 */
#ifndef _UAPI_LINUX_NVME_IOCTL_H
#define _UAPI_LINUX_NVME_IOCTL_H

#ifndef _LINUX_NVME_IOCTL_H
#define _LINUX_NVME_IOCTL_H

/**
 * struct nvme_passthru_cmd -
 * @opcode:	Operation code, see &enum nvme_io_opcodes and &enum nvme_admin_opcodes
 * @flags:	Not supported: intended for command flags (eg: SGL, FUSE)
 * @rsvd1:	Reserved for future use
 * @nsid:	Namespace Identifier, or Fabrics type
 * @cdw2:	Command Dword 2 (no spec defined use)
 * @cdw3:	Command Dword 3 (no spec defined use)
 * @metadata:	User space address to metadata buffer (NULL if not used)
 * @addr:	User space address to data buffer (NULL if not used)
 * @metadata_len: Metadata buffer transfer length
 * @data_len:	Data buffer transfer length
 * @cdw10:	Command Dword 10 (command specific)
 * @cdw11:	Command Dword 11 (command specific)
 * @cdw12:	Command Dword 12 (command specific)
 * @cdw13:	Command Dword 13 (command specific)
 * @cdw14:	Command Dword 14 (command specific)
 * @cdw15:	Command Dword 15 (command specific)
 * @timeout_ms:	If non-zero, overrides system default timeout in milliseconds
 * @result:	Set on completion to the command's CQE DWORD 0 controller response
 */
struct nvme_passthru_cmd {
	__u8	opcode;
	__u8	flags;
	__u16	rsvd1;
	__u32	nsid;
	__u32	cdw2;
	__u32	cdw3;
	__u64	metadata;
	__u64	addr;
	__u32	metadata_len;
	__u32	data_len;
	__u32	cdw10;
	__u32	cdw11;
	__u32	cdw12;
	__u32	cdw13;
	__u32	cdw14;
	__u32	cdw15;
	__u32	timeout_ms;
	__u32	result;
};

/**
 * struct nvme_passthru_cmd64 -
 * @opcode:	Operation code, see &enum nvme_io_opcodes and &enum nvme_admin_opcodes
 * @flags:	Not supported: intended for command flags (eg: SGL, FUSE)
 * @rsvd1:	Reserved for future use
 * @nsid:	Namespace Identifier, or Fabrics type
 * @cdw2:	Command Dword 2 (no spec defined use)
 * @cdw3:	Command Dword 3 (no spec defined use)
 * @metadata:	User space address to metadata buffer (NULL if not used)
 * @addr:	User space address to data buffer (NULL if not used)
 * @metadata_len: Metadata buffer transfer length
 * @data_len:	Data buffer transfer length
 * @cdw10:	Command Dword 10 (command specific)
 * @cdw11:	Command Dword 11 (command specific)
 * @cdw12:	Command Dword 12 (command specific)
 * @cdw13:	Command Dword 13 (command specific)
 * @cdw14:	Command Dword 14 (command specific)
 * @cdw15:	Command Dword 15 (command specific)
 * @timeout_ms:	If non-zero, overrides system default timeout in milliseconds
 * @rsvd2:	Reserved for future use (and fills an impicit struct pad
 * @result:	Set on completion to the command's CQE DWORD 0-1 controller response
 */
struct nvme_passthru_cmd64 {
        __u8    opcode;
        __u8    flags;
        __u16   rsvd1;
        __u32   nsid;
        __u32   cdw2;
        __u32   cdw3;
        __u64   metadata;
        __u64   addr;
        __u32   metadata_len;
        __u32   data_len;
        __u32   cdw10;
        __u32   cdw11;
        __u32   cdw12;
        __u32   cdw13;
        __u32   cdw14;
        __u32   cdw15;
        __u32   timeout_ms;
        __u32   rsvd2;
        __u64   result;
};

#define NVME_IOCTL_ID		_IO('N', 0x40)
#define NVME_IOCTL_RESET	_IO('N', 0x44)
#define NVME_IOCTL_SUBSYS_RESET	_IO('N', 0x45)
#define NVME_IOCTL_RESCAN	_IO('N', 0x46)
#define NVME_IOCTL_ADMIN_CMD	_IOWR('N', 0x41, struct nvme_passthru_cmd)
#define NVME_IOCTL_IO_CMD	_IOWR('N', 0x43, struct nvme_passthru_cmd)
#define NVME_IOCTL_ADMIN64_CMD  _IOWR('N', 0x47, struct nvme_passthru_cmd64)
#define NVME_IOCTL_IO64_CMD     _IOWR('N', 0x48, struct nvme_passthru_cmd64)

#endif /* _UAPI_LINUX_NVME_IOCTL_H */

#endif /* _LINUX_NVME_IOCTL_H */

/**
 * nvme_submit_admin_passthru64() - Submit a 64-bit nvme passthrough admin
 * 				    command
 * @fd:		File descriptor of nvme device
 * @cmd:	The nvme admin command to send
 * @result:	Optional field to return the result from the CQE DW0-1
 *
 * Uses NVME_IOCTL_ADMIN64_CMD for the ioctl request.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_submit_admin_passthru64(int fd, struct nvme_passthru_cmd64 *cmd,
				 __u64 *result);

/**
 * nvme_admin_passthru64() - Submit an nvme passthrough command
 * @fd:		File descriptor of nvme device
 * @opcode:	The nvme io command to send
 * @flags:	NVMe command flags (not used)
 * @rsvd:	Reserevd for future use
 * @nsid:	Namespace identifier
 * @cdw2:	Command dword 2
 * @cdw3:	Command dword 3
 * @cdw10:	Command dword 10
 * @cdw11:	Command dword 11
 * @cdw12:	Command dword 12
 * @cdw13:	Command dword 13
 * @cdw14:	Command dword 14
 * @cdw15:	Command dword 15
 * @data_len:	Length of the data transfered in this command in bytes
 * @data:	Pointer to user address of the data buffer
 * @metadata_len:Length of metadata transfered in this command
 * @metadata:	Pointer to user address of the metadata buffer
 * @timeout_ms:	How long the kernel waits for the command to complete
 * @result:	Optional field to return the result from the CQE dword 0
 *
 * Parameterized form of nvme_submit_admin_passthru64(). This sets up and
 * submits a &struct nvme_passthru_cmd64.
 *
 * Known values for @opcode are defined in &enum nvme_admin_opcode.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_admin_passthru64(int fd, __u8 opcode, __u8 flags, __u16 rsvd,
		__u32 nsid, __u32 cdw2, __u32 cdw3, __u32 cdw10, __u32 cdw11,
		__u32 cdw12, __u32 cdw13, __u32 cdw14, __u32 cdw15,
		__u32 data_len, void *data, __u32 metadata_len, void *metadata,
		__u32 timeout_ms, __u64 *result);

/**
 * nvme_submit_admin_passthru() - Submit an nvme passthrough admin command
 * @fd:		File descriptor of nvme device
 * @cmd:	The nvme admin command to send
 * @result:	Optional field to return the result from the CQE DW0
 *
 * Uses NVME_IOCTL_ADMIN_CMD for the ioctl request.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_submit_admin_passthru(int fd, struct nvme_passthru_cmd *cmd,
			       __u32 *result);

/**
 * nvme_admin_passthru() - Submit an nvme passthrough command
 * @fd:		File descriptor of nvme device
 * @opcode:	The nvme io command to send
 * @flags:	NVMe command flags (not used)
 * @rsvd:	Reserevd for future use
 * @nsid:	Namespace identifier
 * @cdw2:	Command dword 2
 * @cdw3:	Command dword 3
 * @cdw10:	Command dword 10
 * @cdw11:	Command dword 11
 * @cdw12:	Command dword 12
 * @cdw13:	Command dword 13
 * @cdw14:	Command dword 14
 * @cdw15:	Command dword 15
 * @data_len:	Length of the data transfered in this command in bytes
 * @data:	Pointer to user address of the data buffer
 * @metadata_len:Length of metadata transfered in this command
 * @metadata:	Pointer to user address of the metadata buffer
 * @timeout_ms:	How long the kernel waits for the command to complete
 * @result:	Optional field to return the result from the CQE dword 0
 *
 * Parameterized form of nvme_submit_admin_passthru(). This sets up and
 * submits a &struct nvme_passthru_cmd.
 *
 * Known values for @opcode are defined in &enum nvme_admin_opcode.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_admin_passthru(int fd, __u8 opcode, __u8 flags, __u16 rsvd,
		__u32 nsid, __u32 cdw2, __u32 cdw3, __u32 cdw10, __u32 cdw11,
		__u32 cdw12, __u32 cdw13, __u32 cdw14, __u32 cdw15,
		__u32 data_len, void *data, __u32 metadata_len, void *metadata,
		__u32 timeout_ms, __u32 *result);

/**
 * nvme_submit_io_passthru64() - Submit a 64-bit nvme passthrough command
 * @fd:		File descriptor of nvme device
 * @cmd:	The nvme io command to send
 * @result:	Optional field to return the result from the CQE DW0-1
 *
 * Uses NVME_IOCTL_IO64_CMD for the ioctl request.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_submit_io_passthru64(int fd, struct nvme_passthru_cmd64 *cmd,
			    __u64 *result);

/**
 * nvme_io_passthru64() - Submit an nvme io passthrough command
 * @fd:		File descriptor of nvme device
 * @opcode:	The nvme io command to send
 * @flags:	NVMe command flags (not used)
 * @rsvd:	Reserevd for future use
 * @nsid:	Namespace identifier
 * @cdw2:	Command dword 2
 * @cdw3:	Command dword 3
 * @cdw10:	Command dword 10
 * @cdw11:	Command dword 11
 * @cdw12:	Command dword 12
 * @cdw13:	Command dword 13
 * @cdw14:	Command dword 14
 * @cdw15:	Command dword 15
 * @data_len:	Length of the data transfered in this command in bytes
 * @data:	Pointer to user address of the data buffer
 * @metadata_len:Length of metadata transfered in this command
 * @metadata:	Pointer to user address of the metadata buffer
 * @timeout_ms:	How long the kernel waits for the command to complete
 * @result:	Optional field to return the result from the CQE dword 0
 *
 * Parameterized form of nvme_submit_io_passthru64(). This sets up and submits
 * a &struct nvme_passthru_cmd64.
 *
 * Known values for @opcode are defined in &enum nvme_io_opcode.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_io_passthru64(int fd, __u8 opcode, __u8 flags, __u16 rsvd,
		__u32 nsid, __u32 cdw2, __u32 cdw3, __u32 cdw10, __u32 cdw11,
		__u32 cdw12, __u32 cdw13, __u32 cdw14, __u32 cdw15,
		__u32 data_len, void *data, __u32 metadata_len, void *metadata,
		__u32 timeout_ms, __u64 *result);

/**
 * nvme_submit_io_passthru() - Submit an nvme passthrough command
 * @fd:		File descriptor of nvme device
 * @cmd:	The nvme io command to send
 * @result:	Optional field to return the result from the CQE dword 0
 * @result:	Optional field to return the result from the CQE DW0
 *
 * Uses NVME_IOCTL_IO_CMD for the ioctl request.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_submit_io_passthru(int fd, struct nvme_passthru_cmd *cmd,
			    __u32 *result);

/**
 * nvme_io_passthru() - Submit an nvme io passthrough command
 * @fd:		File descriptor of nvme device
 * @opcode:	The nvme io command to send
 * @flags:	NVMe command flags (not used)
 * @rsvd:	Reserevd for future use
 * @nsid:	Namespace identifier
 * @cdw2:	Command dword 2
 * @cdw3:	Command dword 3
 * @cdw10:	Command dword 10
 * @cdw11:	Command dword 11
 * @cdw12:	Command dword 12
 * @cdw13:	Command dword 13
 * @cdw14:	Command dword 14
 * @cdw15:	Command dword 15
 * @data_len:	Length of the data transfered in this command in bytes
 * @data:	Pointer to user address of the data buffer
 * @metadata_len:Length of metadata transfered in this command
 * @metadata:	Pointer to user address of the metadata buffer
 * @timeout_ms:	How long the kernel waits for the command to complete
 * @result:	Optional field to return the result from the CQE dword 0
 *
 * Parameterized form of nvme_submit_io_passthru(). This sets up and submits
 * a &struct nvme_passthru_cmd.
 *
 * Known values for @opcode are defined in &enum nvme_io_opcode.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_io_passthru(int fd, __u8 opcode, __u8 flags, __u16 rsvd,
		__u32 nsid, __u32 cdw2, __u32 cdw3, __u32 cdw10, __u32 cdw11,
		__u32 cdw12, __u32 cdw13, __u32 cdw14, __u32 cdw15,
		__u32 data_len, void *data, __u32 metadata_len, void *metadata,
		__u32 timeout_ms, __u32 *result);

/**
 * nvme_subsystem_reset() - Initiate a subsystem reset
 * @fd:		File descriptor of nvme device
 *
 * This should only be sent to controller handles, not to namespaces.
 *
 * Return: Zero if a subsystem reset was initiated or -1 with errno set
 * otherwise.
 */
int nvme_subsystem_reset(int fd);

/**
 * nvme_ctrl_reset() - Initiate a controller reset
 * @fd:		File descriptor of nvme device
 *
 * This should only be sent to controller handles, not to namespaces.
 *
 * Return: 0 if a reset was initiated or -1 with errno set otherwise.
 */
int nvme_ctrl_reset(int fd);

/**
 * nvme_ns_rescan() - Initiate a controller rescan
 * @fd:		File descriptor of nvme device
 *
 * This should only be sent to controller handles, not to namespaces.
 *
 * Return: 0 if a rescan was initiated or -1 with errno set otherwise.
 */
int nvme_ns_rescan(int fd);

/**
 * nvme_get_nsid() - Retrieve the NSID from a namespace file descriptor
 * @fd:		File descriptor of nvme namespace
 * @nsid:	User pointer to namespace id
 *
 * This should only be sent to namespace handles, not to controllers. The
 * kernel's interface returns the nsid as the return value. This is unfortunate
 * for many architectures that are incapable of allowing distinguishing a
 * namespace id > 0x80000000 from a negative error number.
 *
 * Return: 0 if @nsid was set successfully or -1 with errno set otherwise.
 */
int nvme_get_nsid(int fd, __u32 *nsid);

/**
 * enum nvme_admin_opcode - Known NVMe admin opcodes
 * @nvme_admin_delete_sq:
 * @nvme_admin_create_sq:
 * @nvme_admin_get_log_page:
 * @nvme_admin_delete_cq:
 * @nvme_admin_create_cq:
 * @nvme_admin_identify:
 * @nvme_admin_abort_cmd:
 * @nvme_admin_set_features:
 * @nvme_admin_get_features:
 * @nvme_admin_async_event:
 * @nvme_admin_ns_mgmt:
 * @nvme_admin_fw_commit:
 * @nvme_admin_fw_download:
 * @nvme_admin_dev_self_test:
 * @nvme_admin_ns_attach:
 * @nvme_admin_keep_alive:
 * @nvme_admin_directive_send:
 * @nvme_admin_directive_recv:
 * @nvme_admin_virtual_mgmt:
 * @nvme_admin_nvme_mi_send:
 * @nvme_admin_nvme_mi_recv:
 * @nvme_admin_dbbuf:
 * @nvme_admin_fabrics:
 * @nvme_admin_format_nvm:
 * @nvme_admin_security_send:
 * @nvme_admin_security_recv:
 * @nvme_admin_sanitize_nvm:
 * @nvme_admin_get_lba_status:
 */
enum nvme_admin_opcode {
	nvme_admin_delete_sq		= 0x00,
	nvme_admin_create_sq		= 0x01,
	nvme_admin_get_log_page		= 0x02,
	nvme_admin_delete_cq		= 0x04,
	nvme_admin_create_cq		= 0x05,
	nvme_admin_identify		= 0x06,
	nvme_admin_abort_cmd		= 0x08,
	nvme_admin_set_features		= 0x09,
	nvme_admin_get_features		= 0x0a,
	nvme_admin_async_event		= 0x0c,
	nvme_admin_ns_mgmt		= 0x0d,
	nvme_admin_fw_commit		= 0x10,
	nvme_admin_fw_activate		= nvme_admin_fw_commit,
	nvme_admin_fw_download		= 0x11,
	nvme_admin_dev_self_test	= 0x14,
	nvme_admin_ns_attach		= 0x15,
	nvme_admin_keep_alive		= 0x18,
	nvme_admin_directive_send	= 0x19,
	nvme_admin_directive_recv	= 0x1a,
	nvme_admin_virtual_mgmt		= 0x1c,
	nvme_admin_nvme_mi_send		= 0x1d,
	nvme_admin_nvme_mi_recv		= 0x1e,
	nvme_admin_dbbuf		= 0x7c,
	nvme_admin_fabrics		= 0x7f,
	nvme_admin_format_nvm		= 0x80,
	nvme_admin_security_send	= 0x81,
	nvme_admin_security_recv	= 0x82,
	nvme_admin_sanitize_nvm		= 0x84,
	nvme_admin_get_lba_status	= 0x86,
};

/**
 * enum nvme_identify_cns -
 * @NVME_IDENTIFY_CNS_NS:
 * @NVME_IDENTIFY_CNS_CTRL:
 * @NVME_IDENTIFY_CNS_NS_ACTIVE_LIST:
 * @NVME_IDENTIFY_CNS_NS_DESC_LIST:
 * @NVME_IDENTIFY_CNS_NVMSET_LIST:
 * @NVME_IDENTIFY_CNS_CSI_NS:
 * @NVME_IDENTIFY_CNS_CSI_CTRL:
 * @NVME_IDENTIFY_CNS_ALLOCATED_NS_LIST:
 * @NVME_IDENTIFY_CNS_ALLOCATED_NS:
 * @NVME_IDENTIFY_CNS_NS_CTRL_LIST:
 * @NVME_IDENTIFY_CNS_CTRL_LIST:
 * @NVME_IDENTIFY_CNS_PRIMARY_CTRL_CAP:
 * @NVME_IDENTIFY_CNS_SECONDARY_CTRL_LIST:
 * @NVME_IDENTIFY_CNS_NS_GRANULARITY:
 * @NVME_IDENTIFY_CNS_UUID_LIST:
 * @NVME_IDENTIFY_CNS_CSI_ALLOCATED_NS:
 */
enum nvme_identify_cns {
	NVME_IDENTIFY_CNS_NS					= 0x00,
	NVME_IDENTIFY_CNS_CTRL					= 0x01,
	NVME_IDENTIFY_CNS_NS_ACTIVE_LIST			= 0x02,
	NVME_IDENTIFY_CNS_NS_DESC_LIST				= 0x03,
	NVME_IDENTIFY_CNS_NVMSET_LIST				= 0x04,
	NVME_IDENTIFY_CNS_CSI_NS				= 0x05, /* XXX: Placeholder until assigned */
	NVME_IDENTIFY_CNS_CSI_CTRL				= 0x06, /* XXX: Placeholder until assigned */
	NVME_IDENTIFY_CNS_ALLOCATED_NS_LIST			= 0x10,
	NVME_IDENTIFY_CNS_ALLOCATED_NS				= 0x11,
	NVME_IDENTIFY_CNS_NS_CTRL_LIST				= 0x12,
	NVME_IDENTIFY_CNS_CTRL_LIST				= 0x13,
	NVME_IDENTIFY_CNS_PRIMARY_CTRL_CAP			= 0x14,
	NVME_IDENTIFY_CNS_SECONDARY_CTRL_LIST			= 0x15,
	NVME_IDENTIFY_CNS_NS_GRANULARITY			= 0x16,
	NVME_IDENTIFY_CNS_UUID_LIST				= 0x17,
	NVME_IDENTIFY_CNS_CSI_ALLOCATED_NS			= 0x18, /* XXX: Placeholder until assigned */
};

/**
 * enum nvme_cmd_get_log_lid -
 * @NVME_LOG_LID_ERROR:
 * @NVME_LOG_LID_SMART:
 * @NVME_LOG_LID_FW_SLOT:
 * @NVME_LOG_LID_CHANGED_NS:
 * @NVME_LOG_LID_CMD_EFFECTS:
 * @NVME_LOG_LID_DEVICE_SELF_TEST:
 * @NVME_LOG_LID_TELEMETRY_HOST:
 * @NVME_LOG_LID_TELEMETRY_CTRL:
 * @NVME_LOG_LID_ENDURANCE_GROUP:
 * @NVME_LOG_LID_PREDICTABLE_LAT_NVMSET:
 * @NVME_LOG_LID_PREDICTABLE_LAT_AGG:
 * @NVME_LOG_LID_ANA:
 * @NVME_LOG_LID_PERSISTENT_EVENT:
 * @NVME_LOG_LID_LBA_STATUS:
 * @NVME_LOG_LID_ENDURANCE_GRP_EVT:
 * @NVME_LOG_LID_DISCOVER:
 * @NVME_LOG_LID_RESERVATION:
 * @NVME_LOG_LID_SANITIZE:
 * @NVME_LOG_LID_ZNS_CHANGED_ZONES:
 */
enum nvme_cmd_get_log_lid {
	NVME_LOG_LID_ERROR					= 0x01,
	NVME_LOG_LID_SMART					= 0x02,
	NVME_LOG_LID_FW_SLOT					= 0x03,
	NVME_LOG_LID_CHANGED_NS					= 0x04,
	NVME_LOG_LID_CMD_EFFECTS				= 0x05,
	NVME_LOG_LID_DEVICE_SELF_TEST				= 0x06,
	NVME_LOG_LID_TELEMETRY_HOST				= 0x07,
	NVME_LOG_LID_TELEMETRY_CTRL				= 0x08,
	NVME_LOG_LID_ENDURANCE_GROUP				= 0x09,
	NVME_LOG_LID_PREDICTABLE_LAT_NVMSET			= 0x0a,
	NVME_LOG_LID_PREDICTABLE_LAT_AGG			= 0x0b,
	NVME_LOG_LID_ANA					= 0x0c,
	NVME_LOG_LID_PERSISTENT_EVENT				= 0x0d,
	NVME_LOG_LID_LBA_STATUS					= 0x0e,
	NVME_LOG_LID_ENDURANCE_GRP_EVT				= 0x0f,
	NVME_LOG_LID_DISCOVER					= 0x70,
	NVME_LOG_LID_RESERVATION				= 0x80,
	NVME_LOG_LID_SANITIZE					= 0x81,
	NVME_LOG_LID_ZNS_CHANGED_ZONES				= 0xbf,
};

/**
 * enum nvme_features_id -
 * @NVME_FEAT_FID_ARBITRATION:
 * @NVME_FEAT_FID_POWER_MGMT:
 * @NVME_FEAT_FID_LBA_RANGE:
 * @NVME_FEAT_FID_TEMP_THRESH:
 * @NVME_FEAT_FID_ERR_RECOVERY:
 * @NVME_FEAT_FID_VOLATILE_WC:
 * @NVME_FEAT_FID_NUM_QUEUES:
 * @NVME_FEAT_FID_IRQ_COALESCE:
 * @NVME_FEAT_FID_IRQ_CONFIG:
 * @NVME_FEAT_FID_WRITE_ATOMIC:
 * @NVME_FEAT_FID_ASYNC_EVENT:
 * @NVME_FEAT_FID_AUTO_PST:
 * @NVME_FEAT_FID_HOST_MEM_BUF:
 * @NVME_FEAT_FID_TIMESTAMP:
 * @NVME_FEAT_FID_KATO:
 * @NVME_FEAT_FID_HCTM:
 * @NVME_FEAT_FID_NOPSC:
 * @NVME_FEAT_FID_RRL:
 * @NVME_FEAT_FID_PLM_CONFIG:
 * @NVME_FEAT_FID_PLM_WINDOW:
 * @NVME_FEAT_FID_LBA_STS_INTERVAL:
 * @NVME_FEAT_FID_HOST_BEHAVIOR:
 * @NVME_FEAT_FID_SANITIZE:
 * @NVME_FEAT_FID_ENDURANCE_EVT_CFG:
 * @NVME_FEAT_FID_IOCS_PROFILE:
 * @NVME_FEAT_FID_SW_PROGRESS:
 * @NVME_FEAT_FID_HOST_ID:
 * @NVME_FEAT_FID_RESV_MASK:
 * @NVME_FEAT_FID_RESV_PERSIST:
 * @NVME_FEAT_FID_WRITE_PROTECT:
 */
enum nvme_features_id {
	NVME_FEAT_FID_ARBITRATION				= 0x01,
	NVME_FEAT_FID_POWER_MGMT				= 0x02,
	NVME_FEAT_FID_LBA_RANGE					= 0x03,
	NVME_FEAT_FID_TEMP_THRESH				= 0x04,
	NVME_FEAT_FID_ERR_RECOVERY				= 0x05,
	NVME_FEAT_FID_VOLATILE_WC				= 0x06,
	NVME_FEAT_FID_NUM_QUEUES				= 0x07,
	NVME_FEAT_FID_IRQ_COALESCE				= 0x08,
	NVME_FEAT_FID_IRQ_CONFIG				= 0x09,
	NVME_FEAT_FID_WRITE_ATOMIC				= 0x0a,
	NVME_FEAT_FID_ASYNC_EVENT				= 0x0b,
	NVME_FEAT_FID_AUTO_PST					= 0x0c,
	NVME_FEAT_FID_HOST_MEM_BUF				= 0x0d,
	NVME_FEAT_FID_TIMESTAMP					= 0x0e,
	NVME_FEAT_FID_KATO					= 0x0f,
	NVME_FEAT_FID_HCTM					= 0x10,
	NVME_FEAT_FID_NOPSC					= 0x11,
	NVME_FEAT_FID_RRL					= 0x12,
	NVME_FEAT_FID_PLM_CONFIG				= 0x13,
	NVME_FEAT_FID_PLM_WINDOW				= 0x14,
	NVME_FEAT_FID_LBA_STS_INTERVAL				= 0x15,
	NVME_FEAT_FID_HOST_BEHAVIOR				= 0x16,
	NVME_FEAT_FID_SANITIZE					= 0x17,
	NVME_FEAT_FID_ENDURANCE_EVT_CFG				= 0x18,
	NVME_FEAT_FID_IOCS_PROFILE				= 0x19, /* XXX: Placeholder until assigned */
	NVME_FEAT_FID_SW_PROGRESS				= 0x80,
	NVME_FEAT_FID_HOST_ID					= 0x81,
	NVME_FEAT_FID_RESV_MASK					= 0x82,
	NVME_FEAT_FID_RESV_PERSIST				= 0x83,
	NVME_FEAT_FID_WRITE_PROTECT				= 0x84,
};

/**
 * enum nvme_get_features_sel -
 * @NVME_GET_FEATURES_SEL_CURRENT:
 * @NVME_GET_FEATURES_SEL_DEFAULT:
 * @NVME_GET_FEATURES_SEL_SAVED:
 */
enum nvme_get_features_sel {
	NVME_GET_FEATURES_SEL_CURRENT				= 0,
	NVME_GET_FEATURES_SEL_DEFAULT				= 1,
	NVME_GET_FEATURES_SEL_SAVED				= 2,
	NVME_GET_FEATURES_SEL_SUPPORTED				= 3,
};

/**
 * enum nvme_cmd_format_mset -
 * @NVME_FORMAT_MSET_SEPARATE:
 * @NVME_FORMAT_MSET_EXTENEDED:
 */
enum nvme_cmd_format_mset {
	NVME_FORMAT_MSET_SEPARATE				= 0,
	NVME_FORMAT_MSET_EXTENEDED				= 1,
};

/**
 * enum nvme_cmd_format_pi -
 * @NVME_FORMAT_PI_DISABLE:
 * @NVME_FORMAT_PI_TYPE1:
 * @NVME_FORMAT_PI_TYPE2:
 * @NVME_FORMAT_PI_TYPE3:
 */
enum nvme_cmd_format_pi {
	NVME_FORMAT_PI_DISABLE					= 0,
	NVME_FORMAT_PI_TYPE1					= 1,
	NVME_FORMAT_PI_TYPE2					= 2,
	NVME_FORMAT_PI_TYPE3					= 3,
};

/**
 * @enum nvme_cmd_format_pil -
 * @NVME_FORMAT_PIL_LAST:
 * @NVME_FORMAT_PIL_FIRST:
 */
enum nvme_cmd_format_pil {
	NVME_FORMAT_PIL_LAST					= 0,
	NVME_FORMAT_PIL_FIRST					= 1,
};

/**
 * enum nvme_cmd_format_ses -
 * @NVME_FORMAT_SES_NONE:
 * @NVME_FORMAT_SES_USER_DATA_ERASE:
 * @NVME_FORMAT_SES_CRYPTO_ERASE:
 */
enum nvme_cmd_format_ses {
	NVME_FORMAT_SES_NONE					= 0,
	NVME_FORMAT_SES_USER_DATA_ERASE				= 1,
	NVME_FORMAT_SES_CRYPTO_ERASE				= 2,
};

/**
 * enum nvme_ns_mgmt_sel -
 * @NVME_NAMESPACE_MGMT_SEL_CREATE:
 * @NVME_NAMESPACE_MGMT_SEL_DELETE:
 */
enum nvme_ns_mgmt_sel {
	NVME_NS_MGMT_SEL_CREATE					= 0,
	NVME_NS_MGMT_SEL_DELETE					= 1,
};

/**
 * enum nvme_ns_attach_sel -
 * NVME_NS_ATTACH_SEL_CTRL_ATTACH:
 * NVME_NP_ATTACH_SEL_CTRL_DEATTACH:
 */
enum nvme_ns_attach_sel {
	NVME_NS_ATTACH_SEL_CTRL_ATTACH				= 0,
	NVME_NS_ATTACH_SEL_CTRL_DEATTACH			= 1,
};

/**
 * enum nvme_fw_commit_ca -
 * @NVME_FW_COMMIT_CA_REPLACE:
 * @NVME_FW_COMMIT_CA_REPLACE_AND_ACTIVATE:
 * @NVME_FW_COMMIT_CA_SET_ACTIVE:
 * @NVME_FW_COMMIT_CA_REPLACE_AND_ACTIVATE_IMMEDIATE:
 * @NVME_FW_COMMIT_CA_REPLACE_BOOT_PARTITION:
 * @NVME_FW_COMMIT_CA_ACTIVATE_BOOT_PARTITION:
 */
enum nvme_fw_commit_ca {
	NVME_FW_COMMIT_CA_REPLACE				= 0,
	NVME_FW_COMMIT_CA_REPLACE_AND_ACTIVATE			= 1,
	NVME_FW_COMMIT_CA_SET_ACTIVE				= 2,
	NVME_FW_COMMIT_CA_REPLACE_AND_ACTIVATE_IMMEDIATE	= 3,
	NVME_FW_COMMIT_CA_REPLACE_BOOT_PARTITION		= 6,
	NVME_FW_COMMIT_CA_ACTIVATE_BOOT_PARTITION		= 7,
};

/**
 * enum nvme_directive_dtype -
 * @NVME_DIRECTIVE_DTYPE_IDENTIFY:
 * @NVME_DIRECTIVE_DTYPE_STREAMS:
 */
enum nvme_directive_dtype {
	NVME_DIRECTIVE_DTYPE_IDENTIFY				= 0,
	NVME_DIRECTIVE_DTYPE_STREAMS				= 1,
};

/**
 * enum nvme_directive_receive_doper -
 * @NVME_DIRECTIVE_RECEIVE_IDENTIFY_DOPER_PARAM:
 * @NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_PARAM:
 * @NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_STATUS:
 * @NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_RESOURCE:
 */
enum nvme_directive_receive_doper {
	NVME_DIRECTIVE_RECEIVE_IDENTIFY_DOPER_PARAM		= 0x01,
	NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_PARAM		= 0x01,
	NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_STATUS		= 0x02,
	NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_RESOURCE		= 0x03,
};

/**
 * enum nvme_directive_send_doper -
 * @NVME_DIRECTIVE_SEND_IDENTIFY_DOPER_ENDIR:
 * @NVME_DIRECTIVE_SEND_STREAMS_DOPER_RELEASE_IDENTIFIER:
 * @NVME_DIRECTIVE_SEND_STREAMS_DOPER_RELEASE_RESOURCE:
 */
enum nvme_directive_send_doper {
	NVME_DIRECTIVE_SEND_IDENTIFY_DOPER_ENDIR		= 0x01,
	NVME_DIRECTIVE_SEND_STREAMS_DOPER_RELEASE_IDENTIFIER	= 0x01,
	NVME_DIRECTIVE_SEND_STREAMS_DOPER_RELEASE_RESOURCE	= 0x02,
};

/**
 * enum nvme_directive_send_identify_endir -
 */
enum nvme_directive_send_identify_endir {
	NVME_DIRECTIVE_SEND_IDENTIFY_ENDIR_DISABLE		= 0,
	NVME_DIRECTIVE_SEND_IDENTIFY_ENDIR_ENABLE		= 1,
};

/**
 * enum nvme_sanitize_sanact -
 * @NVME_SANITIZE_SANACT_EXIT_FAILURE:
 * @NVME_SANITIZE_SANACT_START_BLOCK_ERASE:
 * @NVME_SANITIZE_SANACT_START_OVERWRITE:
 * @NVME_SANITIZE_SANACT_START_CRYPTO_ERASE:
 */
enum nvme_sanitize_sanact {
	NVME_SANITIZE_SANACT_EXIT_FAILURE			= 1,
	NVME_SANITIZE_SANACT_START_BLOCK_ERASE			= 2,
	NVME_SANITIZE_SANACT_START_OVERWRITE			= 3,
	NVME_SANITIZE_SANACT_START_CRYPTO_ERASE			= 4,
};

/**
 * enum nvme_dst_stc - Action taken by the Device Self-test command
 * @NVME_DST_STC_SHORT:	 Start a short device self-test operation
 * @NVME_DST_STC_LONG:	 Start an extended device self-test operation
 * @NVME_DST_STC_VS:	 Start a vendor specific device self-test operation
 * @NVME_DST_STC_ABORT:	 Abort device self-test operation
 */
enum nvme_dst_stc {
	NVME_DST_STC_SHORT					= 0x1,
	NVME_DST_STC_LONG					= 0x2,
	NVME_DST_STC_VS						= 0xe,
	NVME_DST_STC_ABORT					= 0xf,
};

/**
 * enum nvme_virt_mgmt_act -
 * @NVME_VIRT_MGMT_ACT_PRIM_CTRL_FLEX_ALLOC:
 * @NVME_VIRT_MGMT_ACT_OFFLINE_SEC_CTRL:
 * @NVME_VIRT_MGMT_ACT_ASSIGN_SEC_CTRL:
 * @NVME_VIRT_MGMT_ACT_ONLINE_SEC_CTRL:
 */
enum nvme_virt_mgmt_act {
	NVME_VIRT_MGMT_ACT_PRIM_CTRL_FLEX_ALLOC			= 1,
	NVME_VIRT_MGMT_ACT_OFFLINE_SEC_CTRL			= 7,
	NVME_VIRT_MGMT_ACT_ASSIGN_SEC_CTRL			= 8,
	NVME_VIRT_MGMT_ACT_ONLINE_SEC_CTRL			= 9,
};

/**
 * enum nvme_virt_mgmt_rt -
 * @NVME_VIRT_MGMT_RT_VQ_RESOURCE:
 * @NVME_VIRT_MGMT_RT_VI_RESOURCE:
 */
enum nvme_virt_mgmt_rt {
	NVME_VIRT_MGMT_RT_VQ_RESOURCE				= 0,
	NVME_VIRT_MGMT_RT_VI_RESOURCE				= 1,
};

/**
 * enum nvme_ns_write_protect -
 * @NVME_NS_WP_CFG_NONE
 * @NVME_NS_WP_CFG_PROTECT
 * @NVME_NS_WP_CFG_PROTECT_POWER_CYCLE
 * @NVME_NS_WP_CFG_PROTECT_PERMANENT
 */
enum nvme_ns_write_protect_cfg {
	NVME_NS_WP_CFG_NONE					= 0,
	NVME_NS_WP_CFG_PROTECT					= 1,
	NVME_NS_WP_CFG_PROTECT_POWER_CYCLE			= 2,
	NVME_NS_WP_CFG_PROTECT_PERMANENT			= 3,
};

/**
 * nvme_identify() - Send the NVMe Identify command
 * @fd:		File descriptor of nvme device
 * @cns:	The Controller or Namespace structure, see @enum nvme_identify_cns
 * @nsid:	Namespace identifier, if applicable
 * @cntid:	The Controller Identifier, if applicable
 * @nvmsetid:	The NVMe Set ID if CNS is 04h
 * @uuidx:	UUID Index if controller supports this id selection method
 * @csi:	Command Set Identifier
 * @data:	User space destination address to transfer the data
 *
 * The Identify command returns a data buffer that describes information about
 * the NVM subsystem, the controller or the namespace(s).
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_identify(int fd, enum nvme_identify_cns cns, __u32 nsid,
		  __u16 cntid, __u16 nvmsetid, __u8 uuidx, __u8 csi,
		  void *data);

/**
 * nvme_identify_ctrl() - Retrieves nvme identify controller
 * @fd:		File descriptor of nvme device
 * id:		User space destination address to transfer the data,
 *
 * Sends nvme identify with CNS value %NVME_IDENTIFY_CNS_CTRL.
 *
 * See &struct nvme_id_ctrl for details on the data returned.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_identify_ctrl(int fd, struct nvme_id_ctrl *id);

/**
 * nvme_identify_ns() - Retrieves nvme identify namespace
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace to identify
 * @ns:		User space destination address to transfer the data
 *
 * If the Namespace Identifier (NSID) field specifies an active NSID, then the
 * Identify Namespace data structure is returned to the host for that specified
 * namespace.
 *
 * If the controller supports the Namespace Management capability and the NSID
 * field is set to %NVME_NSID_ALL, then the controller returns an Identify Namespace
 * data structure that specifies capabilities that are common across namespaces
 * for this controller.
 *
 * See &struct nvme_id_ns for details on the structure returned.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_identify_ns(int fd, __u32 nsid, struct nvme_id_ns *ns);

/**
 * nvme_identify_allocated_ns() - Same as nvme_identify_ns, but only for
 * 				  allocated namespaces
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace to identify
 * @ns:		User space destination address to transfer the data
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_identify_allocated_ns(int fd, __u32 nsid, struct nvme_id_ns *ns);

/**
 * nvme_identify_active_ns_list() - Retrieves active namespaces id list
 * @fd:		File descriptor of nvme device
 * @nsid:	Return namespaces greater than this identifer
 * @ns_list:	User space destination address to transfer the data
 *
 * A list of 1024 namespace IDs is returned to the host containing NSIDs in
 * increasing order that are greater than the value specified in the Namespace
 * Identifier (nsid) field of the command.
 *
 * See &struct nvme_ns_list for the definition of the returned structure.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_identify_active_ns_list(int fd, __u32 nsid, struct nvme_ns_list *list);

/**
 * nvme_identify_allocated_ns_list() - Retrieves allocated namespace id list
 * @fd:		File descriptor of nvme device
 * @nsid:	Return namespaces greater than this identifer
 * @ns_list:	User space destination address to transfer the data
 *
 * A list of 1024 namespace IDs is returned to the host containing NSIDs in
 * increasing order that are greater than the value specified in the Namespace
 * Identifier (nsid) field of the command.
 *
 * See &struct nvme_ns_list for the definition of the returned structure.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_identify_allocated_ns_list(int fd, __u32 nsid,
				    struct nvme_ns_list *list);

/**
 * nvme_identify_ctrl_list() - Retrieves identify controller list
 * @fd:		File descriptor of nvme device
 * @cntlid:	Starting CNTLID to return in the list
 * @cntlist:	User space destination address to transfer the data
 *
 * Up to 2047 controller identifiers is returned containing a controller
 * identifier greater than or equal to the controller identifier  specified in
 * @cntid.
 *
 * See &struct nvme_ctrl_list for a definition of the structure returned.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_identify_ctrl_list(int fd, __u16 cntid,
			    struct nvme_ctrl_list *ctrlist);

/**
 * nvme_identify_nsid_ctrl_list() -
 * @fd:		File descriptor of nvme device
 * @nsid:	Return controllers that are attached to this nsid
 * @cntlid:	Starting CNTLID to return in the list
 * @cntlist:	User space destination address to transfer the data
 *
 * Up to 2047 controller identifiers is returned containing a controller
 * identifier greater than or equal to the controller identifier  specified in
 * @cntid.
 *
 * See &struct nvme_ctrl_list for a definition of the structure returned.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1
 */
int nvme_identify_nsid_ctrl_list(int fd, __u32 nsid, __u16 cntid,
				 struct nvme_ctrl_list *ctrlist);

/**
 * nvme_identify_ns_descs() - Retrieves namespace descriptor list
 * @fd:		File descriptor of nvme device
 * @nsid:	The namespace id to retrieve destriptors
 * @descs:	User space destination address to transfer the data
 *
 * A list of Namespace Identification Descriptor structures is returned to the
 * host for the namespace specified in the Namespace Identifier (NSID) field if
 * it is an active NSID.
 *
 * The data returned is in the form of an arrray of 'struct nvme_ns_id_desc'.
 *
 * See &struct nvme_ns_id_desc for the definition of the returned structure.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_identify_ns_descs(int fd, __u32 nsid, struct nvme_ns_id_desc *descs);

/**
 * nvme_identify_nvmset_list() - Retrieves NVM Set List
 * @fd:		File descriptor of nvme device
 * @nvmeset_id:	NVM Set Identifier
 * @nvmset:	User space destination address to transfer the data
 *
 * Retrieves an NVM Set List, @struct nvme_id_nvmset_list. The data structure is an
 * ordered list by NVM Set Identifier, starting with the first NVM Set
 * Identifier supported by the NVM subsystem that is equal to or greater than
 * the NVM Set Identifier.
 *
 * See &struct nvme_id_nvmset_list for the defintion of the returned structure.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_identify_nvmset_list(int fd, __u16 nvmsetid,
			      struct nvme_id_nvmset_list *nvmset);

/**
 * nvme_identify_primary_ctrl() - Retrieve NVMe Primary Controller
 * 				  identification
 * @fd:		File descriptor of nvme device
 * @cntid:	Return controllers starting at this identifier
 * @cap:	User space destination buffer address to transfer the data
 *
 * See &struct nvme_primary_ctrl_cap for the defintion of the returned structure, @cap.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_identify_primary_ctrl(int fd, __u16 cntid,
			       struct nvme_primary_ctrl_cap *cap);

/**
 * nvme_identify_secondary_ctrl_list() - Retrieves secondary controller list
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace identifier
 * @cntid:	Return controllers starting at this identifier
 * @sc_list:	User space destination address to transfer the data
 *
 * A Secondary Controller List is returned to the host for up to 127 secondary
 * controllers associated with the primary controller processing this command.
 * The list contains entries for controller identifiers greater than or equal
 * to the value specified in the Controller Identifier (cntid).
 *
 * See &struct nvme_secondary_ctrls_list for a defintion of the returned
 * structure.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_identify_secondary_ctrl_list(int fd, __u32 nsid, __u16 cntid,
				      struct nvme_secondary_ctrl_list *list);

/**
 * nvme_identify_ns_granularity() - Retrieves namespace granularity
 * 				    identification
 * @fd:		File descriptor of nvme device
 * @gr_list:	User space destination address to transfer the data
 *
 * If the controller supports reporting of Namespace Granularity, then a
 * Namespace Granularity List is returned to the host for up to sixteen
 * namespace granularity descriptors
 *
 * See &struct nvme_id_ns_granularity_list for the definition of the returned
 * structure.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_identify_ns_granularity(int fd, struct nvme_id_ns_granularity_list *list);

/**
 * nvme_identify_uuid() - Retrieves device's UUIDs
 * @fd:		File descriptor of nvme device
 * @uuid_list:	User space destination address to transfer the data
 *
 * Each UUID List entry is either 0h, the NVMe Invalid UUID, or a valid UUID.
 * Valid UUIDs are those which are non-zero and are not the NVMe Invalid UUID.
 *
 * See &struct nvme_id_uuid_list for the definition of the returned structure.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_identify_uuid(int fd, struct nvme_id_uuid_list *list);

/**
 * nvme_identify_ns_csi() -
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace to identify
 * @csi:	Command Set Identifier
 * @data:	User space destination address to transfer the data
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_identify_ns_csi(int fd, __u32 nsid, __u8 csi, void *data);

/**
 * nvme_identify_ctrl_csi() -
 * @fd:		File descriptor of nvme device
 * @csi:	Command Set Identifier
 * @data:	User space destination address to transfer the data
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_identify_ctrl_csi(int fd, __u8 csi, void *data);

/**
 * nvme_identify_ctrl_nvm() -
 * @fd:	File descriptor of nvme device
 * @id:	User space destination address to transfer the data
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_nvm_identify_ctrl(int fd, struct nvme_id_ctrl_nvm *id);

/**
 * nvme_identify_iocs() -
 * @fd:		File descriptor of nvme device
 * @cntlid:	Controller ID
 * @iocs:	User space destination address to transfer the data
 *
 * Retrieves list of the controller's supported io command set vectors. See
 * @struct nvme_id_iocs.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_identify_iocs(int fd, __u16 cntlid, struct nvme_id_iocs *iocs);

/**
 * nvme_zns_identify_ns() -
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace to identify
 * @data:	User space destination address to transfer the data
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_zns_identify_ns(int fd, __u32 nsid, struct nvme_zns_id_ns *data);

/**
 * nvme_zns_identify_ctrl() -
 * @fd:	File descriptor of nvme device
 * @id:	User space destination address to transfer the data
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_zns_identify_ctrl(int fd, struct nvme_zns_id_ctrl *id);

/**
 * nvme_get_log() - NVMe Admin Get Log command
 * @fd:		File descriptor of nvme device
 * @lid:	Log page identifier, see &enum nvme_cmd_get_log_lid for known
 * 		values
 * @nsid: 	Namespace identifier, if applicable
 * @lpo:	Log page offset for partial log transfers
 * @lsp:   Log specific field
 * @lsi:   Endurance group information
 * @rae:   Retain asynchronous events
 * @uuidx: UUID selection, if supported
 * @len:   Length of provided user buffer to hold the log data in bytes
 * @log:   User space destination address to transfer the data
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_log(int fd, enum nvme_cmd_get_log_lid lid, __u32 nsid, __u64 lpo,
		 __u8 lsp, __u16 lsi, bool rae, __u8 uuidx, enum nvme_csi csi,
		 __u32 len, void *log);

static inline int nvme_get_nsid_log(int fd, enum nvme_cmd_get_log_lid lid,
				    __u32 nsid, __u32 len, void *log)
{
	return nvme_get_log(fd, lid, nsid, 0, 0, 0, false, 0, NVME_CSI_NVM, len,
			    log);
}

static inline int nvme_get_log_simple(int fd, enum nvme_cmd_get_log_lid lid,
				      __u32 len, void *log)
{
	return nvme_get_nsid_log(fd, lid, NVME_NSID_ALL, len, log);
}

/**
 * nvme_get_log_error() - Retrieve nvme error log
 * @fd:		File descriptor of nvme device
 * @entries:	Number of error log entries allocated
 * @rae:	Retain asynchronous events
 * @err_log:	Array of error logs of size 'entries'
 *
 * This log page describes extended error information for a command that
 * completed with error, or may report an error that is not specific to a
 * particular command.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_log_error(int fd, unsigned nr_entries, bool rae,
		       struct nvme_error_log_page *log);

/**
 * nvme_get_log_smart() - Retrieve nvme smart log
 * @fd:		File descriptor of nvme device
 * @nsid:	Optional namespace identifier
 * @rae:	Retain asynchronous events
 * @smart_log:	User address to store the smart log
 *
 * This log page provides SMART and general health information. The information
 * provided is over the life of the controller and is retained across power
 * cycles. To request the controller log page, the namespace identifier
 * specified is FFFFFFFFh. The controller may also support requesting the log
 * page on a per namespace basis, as indicated by bit 0 of the LPA field in the
 * Identify Controller data structure.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_log_smart(int fd, __u32 nsid, bool rae, struct nvme_smart_log *log);

/**
 * nvme_get_log_fw_slot() - Retrieves the controller firmware log
 * @fd:		File descriptor of nvme device
 * @rae:	Retain asynchronous events
 * @fw_log:	User address to store the log page
 *
 * This log page describes the firmware revision stored in each firmware slot
 * supported. The firmware revision is indicated as an ASCII string. The log
 * page also indicates the active slot number.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_log_fw_slot(int fd, bool rae, struct nvme_firmware_slot *log);

/**
 * nvme_get_log_changed_ns_list() - Retrieve namespace changed list
 * @fd:		File descriptor of nvme device
 * @rae:	Retain asynchronous events
 * @ns_list:	User address to store the log page
 *
 * This log page describes namespaces attached to this controller that have
 * changed since the last time the namespace was identified, been added, or
 * deleted.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_log_changed_ns_list(int fd, bool rae, struct nvme_ns_list *log);

/**
 * nvme_get_log_cmd_effects() - Retrieve nvme command effects log
 * @fd:		File descriptor of nvme device
 * @csi:	Command Set Identifier
 * @effects_log:User address to store the effects log
 *
 * This log page describes the commands that the controller supports and the
 * effects of those commands on the state of the NVM subsystem.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_log_cmd_effects(int fd, enum nvme_csi csi,
			     struct nvme_cmd_effects_log *log);

/**
 * nvme_get_log_device_self_test() - Retrieve the device self test log
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace ID being tested
 * @log:	Userspace address of the log payload
 *
 * The log page indicates the status of an in progress self test and the
 * percent complete of that operation, and the results of the previous 20
 * self-test operations.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_log_device_self_test(int fd, struct nvme_self_test_log *log);

/**
 * nvme_get_log_create_telemetry_host() -
 */
int nvme_get_log_create_telemetry_host(int fd, struct nvme_telemetry_log *log);

/**
 * nvme_get_log_telemetry_host() -
 * @fd:		File descriptor of nvme device
 * @offset:	Offset into the telemetry data
 * @len:	Length of provided user buffer to hold the log data in bytes
 * @log:	User address for log page data
 *
 * Retreives the Telemetry Host-Initiated log page at the requested offset
 * using the previously existing capture.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_log_telemetry_host(int fd, __u64 offset, __u32 len, void *log);

/**
 * nvme_get_log_telemetry_ctrl() -
 * @fd:		File descriptor of nvme device
 * @rae:	Retain asynchronous events
 * @offset:	Offset into the telemetry data
 * @len:	Length of provided user buffer to hold the log data in bytes
 * @log:	User address for log page data
 */
int nvme_get_log_telemetry_ctrl(int fd, bool rae, __u64 offset, __u32 len,
				void *log);

/**
 * nvme_get_log_endurance_group() -
 * @fd:		File descriptor of nvme device
 * @endgid:	Starting group identifier to return in the list
 * @log:	User address to store the endurance log
 *
 * This log page indicates if an Endurance Group Event has occurred for a
 * particular Endurance Group. If an Endurance Group Event has occurred, the
 * details of the particular event are included in the Endurance Group
 * Information log page for that Endurance Group. An asynchronous event is
 * generated when an entry for an Endurance Group is newly added to this log
 * page.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_log_endurance_group(int fd, __u16 endgid,
				 struct nvme_endurance_group_log *log);

/**
 * nvme_get_log_predictable_lat_nvmset() -
 * @fd:
 * @nvmsetid:
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_log_predictable_lat_nvmset(int fd, __u16 nvmsetid,
					struct nvme_nvmset_predictable_lat_log *log);

/**
 * nvme_get_log_predictable_lat_event() -
 * @fd:		File descriptor of nvme device
 * @rae:	Retain asynchronous events
 */
int nvme_get_log_predictable_lat_event(int fd, bool rae, __u32 offset,
				       __u32 len, void *log);

/**
 * enum nvme_log_ana_lsp -
 * @NVME_LOG_ANA_LSP_RGO_NAMESPACES:
 * @NVME_LOG_ANA_LSP_RGO_GROUPS_ONLY:
 */
enum nvme_log_ana_lsp {
	NVME_LOG_ANA_LSP_RGO_NAMESPACES				= 0,
	NVME_LOG_ANA_LSP_RGO_GROUPS_ONLY			= 1,
};

/**
 * nvme_get_log_ana() -
 * @fd:		File descriptor of nvme device
 * @lsp:	Log specific, see &enum nvme_get_log_ana_lsp
 * @rae:	Retain asynchronous events
 * @len:	The allocated length of the log page
 * @log: 	User address to store the ana log
 *
 * This log consists of a header describing the log and descriptors containing
 * the asymmetric namespace access information for ANA Groups that contain
 * namespaces that are attached to the controller processing the command.
 *
 * See &struct nvme_ana_rsp_hdr for the defintion of the returned structure.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_log_ana(int fd, enum nvme_log_ana_lsp lsp, bool rae, __u64 offset,
		     __u32 len, void *log);

/**
 * nvme_get_log_ana_groups() -
 * @fd:		File descriptor of nvme device
 * @rae:	Retain asynchronous events
 *
 * See &struct nvme_ana_group_desc for the defintion of the returned structure.
 */
int nvme_get_log_ana_groups(int fd, bool rae, __u32 len,
			    struct nvme_ana_group_desc *log);

/**
 * nvme_get_log_lba_status() -
 * @fd:		File descriptor of nvme device
 * @rae:	Retain asynchronous events
 */
int nvme_get_log_lba_status(int fd, bool rae, __u64 offset, __u32 len,
			    void *log);

/**
 * nvme_get_log_endurance_grp_evt() -
 * @fd:		File descriptor of nvme device
 * @rae:	Retain asynchronous events
 */
int nvme_get_log_endurance_grp_evt(int fd, bool rae, __u32 offset, __u32 len,
				   void *log);

/**
 * nvme_get_log_discovery() -
 * @fd:		File descriptor of nvme device
 * @rae:	Retain asynchronous events
 * @offset:	Offset of this log to retrieve
 * @len:	The allocated size for this portion of the log
 * @log:	User address to store the discovery log
 *
 * Supported only by fabrics discovery controllers, returning discovery
 * records.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_log_discovery(int fd, bool rae, __u32 offset, __u32 len, void *log);

/**
 * nvme_get_log_reservation() -
 * @fd:		File descriptor of nvme device
 * @rae:	Retain asynchronous events
 */
int nvme_get_log_reservation(int fd, bool rae,
			     struct nvme_resv_notification_log *log);

/**
 * nvme_get_log_sanitize() -
 * @fd:		File descriptor of nvme device
 * @rae:	Retain asynchronous events
 * @log:	User address to store the sanitize log
 *
 * The Sanitize Status log page reports sanitize operation time estimates and
 * information about the most recent sanitize operation.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_log_sanitize(int fd, bool rae,
			  struct nvme_sanitize_log_page *log);

/**
 * nvme_get_log_zns_changed_zones() -
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace ID
 * @rae:	Retain asynchronous events
 * @log:	User address to store the changed zone log
 *
 * The list of zones that have changed state due to an exceptional event.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_log_zns_changed_zones(int fd, __u32 nsid, bool rae,
				   struct nvme_zns_changed_zone_log *log);

/**
 * enum nvme_pevent_log_action -
 */
enum nvme_pevent_log_action {
	NVME_PEVENT_LOG_READ			= 0x0,
	NVME_PEVENT_LOG_EST_CTX_AND_READ	= 0x1,
	NVME_PEVENT_LOG_RELEASE_CTX		= 0x2,
};

/**
 * nvme_get_log_persistent_event() -
 * &fd:
 * &action:
 * @size:
 * @pevent_log:
 */
int nvme_get_log_persistent_event(int fd, enum nvme_pevent_log_action action,
				  __u32 size, void *pevent_log);

/**
 * nvme_set_features() - Set a feature attribute
 * @fd:		File descriptor of nvme device
 * @fid:	Feature identifier
 * @nsid:	Namespace ID, if applicable
 * @cdw11:	Value to set the feature to
 * @cdw12:	Feature specific command dword12 field
 * @save:	Save value across power states
 * @uuidx:	UUID Index for differentiating vendor specific encoding
 * @cdw14:	Feature specific command dword15 field
 * @data_len:	Length of feature data, if applicable, in bytes
 * @data:	User address of feature data, if applicable
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_features(int fd, __u8 fid, __u32 nsid, __u32 cdw11, __u32 cdw12,
		      bool save, __u8 uuidx, __u32 cdw15, __u32 data_len,
		      void *data, __u32 *result);

static inline int nvme_set_features_data(int fd, __u8 fid, __u32 nsid,
			__u32 cdw11, bool save, __u32 data_len, void *data,
		 	__u32 *result)
{
	return nvme_set_features(fd, fid, nsid, cdw11, 0, save, 0, 0, data_len,
				data, result);
}

static inline int nvme_set_features_simple(int fd, __u8 fid, __u32 nsid,
			__u32 cdw11, bool save, __u32 *result)
{
	return nvme_set_features_data(fd, fid, nsid, cdw11, save, 0, NULL,
				 result);
}

/**
 * nvme_set_features_arbitration() -
 * @fd:		File descriptor of nvme device
 * @save:	Save value across power states
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_features_arbitration(int fd, __u8 ab, __u8 lpw, __u8 mpw,
				  __u8 hpw, bool  save, __u32 *result);

/**
 * nvme_set_features_power_mgmt() -
 * @fd:		File descriptor of nvme device
 * @save:	Save value across power states
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_features_power_mgmt(int fd, __u8 ps, __u8 wh, bool save,
				 __u32 *result);

/**
 * nvme_set_features_lba_range() -
 * @fd:		File descriptor of nvme device
 * @save:	Save value across power states
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_features_lba_range(int fd, __u32 nsid, __u32 nr_ranges, bool save,
				struct nvme_lba_range_type *data, __u32 *result);

/**
 * enum nvme_feat_tmpthresh_thsel -
 */
enum nvme_feat_tmpthresh_thsel {
	NVME_FEATURE_TEMPTHRESH_THSEL_OVER			= 0,
	NVME_FEATURE_TEMPTHRESH_THSEL_UNDER			= 1,
};

/**
 * nvme_set_features_temp_thresh() -
 * @fd:		File descriptor of nvme device
 * @save:	Save value across power states
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_features_temp_thresh(int fd, __u16 tmpth, __u8 tmpsel,
				  enum nvme_feat_tmpthresh_thsel thsel,
				  bool save, __u32 *result);

/**
 * nvme_set_features_err_recovery() -
 * @fd:		File descriptor of nvme device
 * @save:	Save value across power states
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_features_err_recovery(int fd, __u32 nsid, __u16 tler,
				   bool dulbe, bool save, __u32 *result);

/**
 * nvme_set_features_volatile_wc() -
 * @fd:		File descriptor of nvme device
 * @save:	Save value across power states
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_features_volatile_wc(int fd, bool wce, bool save,
				  __u32 *result);

/**
 * nvme_set_features_irq_coalesce() -
 * @fd:		File descriptor of nvme device
 * @save:	Save value across power states
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_features_irq_coalesce(int fd, __u8 thr, __u8 time,
				   bool save, __u32 *result);

/**
 * nvme_set_features_irq_config() -
 * @fd:		File descriptor of nvme device
 * @save:	Save value across power states
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_features_irq_config(int fd, __u16 iv, bool cd, bool save,
				 __u32 *result);

/**
 * nvme_set_features_write_atomic() -
 * @fd:		File descriptor of nvme device
 * @save:	Save value across power states
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_features_write_atomic(int fd, bool dn, bool save,
				   __u32 *result);

/**
 * enum nvme_features_async_event_config_flags -
 */
enum nvme_features_async_event_config_flags {
	NVME_FEATURE_AENCFG_SMART_CRIT_SPARE			= 1 << 0,
	NVME_FEATURE_AENCFG_SMART_CRIT_TEMPERATURE		= 1 << 1,
	NVME_FEATURE_AENCFG_SMART_CRIT_DEGRADED			= 1 << 2,
	NVME_FEATURE_AENCFG_SMART_CRIT_READ_ONLY		= 1 << 3,
	NVME_FEATURE_AENCFG_SMART_CRIT_VOLATILE_BACKUP		= 1 << 4,
	NVME_FEATURE_AENCFG_SMART_CRIT_READ_ONLY_PMR		= 1 << 5,
	NVME_FEATURE_AENCFG_NOTICE_NAMESPACE_ATTRIBUTES		= 1 << 8,
	NVME_FEATURE_AENCFG_NOTICE_FIRMWARE_ACTIVATION		= 1 << 9,
	NVME_FEATURE_AENCFG_NOTICE_TELEMETRY_LOG		= 1 << 10,
	NVME_FEATURE_AENCFG_NOTICE_ANA_CHANGE			= 1 << 11,
	NVME_FEATURE_AENCFG_NOTICE_PL_EVENT			= 1 << 12,
	NVME_FEATURE_AENCFG_NOTICE_LBA_STATUS			= 1 << 13,
	NVME_FEATURE_AENCFG_NOTICE_EG_EVENT			= 1 << 14,
	NVME_FEATURE_AENCFG_NOTICE_DISCOVERY_CHANGE		= 1 << 31,
};

/**
 * nvme_set_features_async_event() -
 * @fd:		File descriptor of nvme device
 * @save:	Save value across power states
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_features_async_event(int fd, __u32 events, bool save,
				  __u32 *result);

/**
 * nvme_set_features_auto_pst() -
 * @fd:		File descriptor of nvme device
 * @save:	Save value across power states
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_features_auto_pst(int fd, bool apste, bool save,
			       struct nvme_feat_auto_pst *apst,
			       __u32 *result);

/**
 * nvme_set_features_timestamp() -
 * @fd:		File descriptor of nvme device
 * @save:	Save value across power states
 * @timestamp:	The current timestamp value to assign to this this feature
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_features_timestamp(int fd, bool save, __u64 timestamp);

/**
 * nvme_set_features_hctm() -
 * @fd:		File descriptor of nvme device
 * @save:	Save value across power states
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_features_hctm(int fd, __u16 tmt2, __u16 tmt1, bool save,
			   __u32 *result);

/**
 * nvme_set_features_nopsc() -
 * @fd:		File descriptor of nvme device
 * @save:	Save value across power states
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_features_nopsc(int fd, bool noppme, bool save, __u32 *result);

/**
 * nvme_set_features_rrl() -
 * @fd:		File descriptor of nvme device
 * @save:	Save value across power states
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_features_rrl(int fd, __u8 rrl, __u16 nvmsetid, bool save,
			  __u32 *result);

/**
 * nvme_set_features_plm_config() -
 * @fd:		File descriptor of nvme device
 * @save:	Save value across power states
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_features_plm_config(int fd, bool enable, __u16 nvmsetid,
				 bool save, struct nvme_plm_config *data,
				 __u32*result);

/**
 * enum nvme_feat_plm_window_select -
 */
enum nvme_feat_plm_window_select {
	NVME_FEATURE_PLM_DTWIN					= 1,
	NVME_FEATURE_PLM_NDWIN					= 2,
};

/**
 * nvme_set_features_plm_window() -
 * @fd:		File descriptor of nvme device
 * @save:	Save value across power states
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_features_plm_window(int fd, enum nvme_feat_plm_window_select sel,
				 __u16 nvmsetid, bool save, __u32 *result);

/**
 * nvme_set_features_lba_sts_interval() -
 * @fd:		File descriptor of nvme device
 * @save:	Save value across power states
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_features_lba_sts_interval(int fd, __u16 lsiri, __u16 lsipi,
				       bool save, __u32 *result);

/**
 * nvme_set_features_host_behavior() -
 * @fd:		File descriptor of nvme device
 * @save:	Save value across power states
 * @data:	
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_features_host_behavior(int fd, bool save,
				    struct nvme_feat_host_behavior *data);

/**
 * nvme_set_features_sanitize() -
 * @fd:		File descriptor of nvme device
 * @nodrm:	
 * @save:	Save value across power states
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_features_sanitize(int fd, bool nodrm, bool save, __u32 *result);

/**
 * nvme_set_features_endurance_evt_cfg() -
 * @fd:		File descriptor of nvme device
 * @endgid:
 * @egwarn:	Flags to enable warning, see &enum nvme_eg_critical_warning_flags
 * @save:	Save value across power states
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_features_endurance_evt_cfg(int fd, __u16 endgid, __u8 egwarn,
					bool save, __u32 *result);

/**
 * nvme_set_features_sw_progress() -
 * @fd:		File descriptor of nvme device
 * @pbslc:	
 * @save:	Save value across power states
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_features_sw_progress(int fd, __u8 pbslc, bool save,
				  __u32 *result);


/**
 * nvme_set_features_host_id() -
 * @fd:		File descriptor of nvme device
 * @exhid:	
 * @save:	Save value across power states
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_features_host_id(int fd, bool exhid, bool save, __u8 *hostid);

/**
 *
 */
enum nvme_feat_resv_notify_flags {
	NVME_FEAT_RESV_NOTIFY_REGPRE		= 1 << 1,
	NVME_FEAT_RESV_NOTIFY_RESREL		= 1 << 2,
	NVME_FEAT_RESV_NOTIFY_RESPRE		= 1 << 3,
};

/**
 * nvme_set_features_resv_mask() -
 * @fd:		File descriptor of nvme device
 * @mask:	
 * @save:	Save value across power states
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_features_resv_mask(int fd, __u32 mask, bool save, __u32 *result);

/**
 * nvme_set_features_resv_persist() -
 * @fd:		File descriptor of nvme device
 * @ptpl:	
 * @save:	Save value across power states
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_features_resv_persist(int fd, bool ptpl, bool save, __u32 *result);

/**
 * enum nvme_feat_ns_wp_cfg_state -
 * @NVME_FEAT_NS_NO_WRITE_PROTECT:
 * @NVME_FEAT_NS_WRITE_PROTECT:
 * @NVME_FEAT_NS_WRITE_PROTECT_PWR_CYCLE:
 * @NVME_FEAT_NS_WRITE_PROTECT_PERMANENT:
 */
enum nvme_feat_nswpcfg_state {
	NVME_FEAT_NS_NO_WRITE_PROTECT 		= 0,
	NVME_FEAT_NS_WRITE_PROTECT		= 1,
	NVME_FEAT_NS_WRITE_PROTECT_PWR_CYCLE	= 2,
	NVME_FEAT_NS_WRITE_PROTECT_PERMANENT	= 3,
};

/**
 * nvme_set_features_write_protect() -
 * @fd:		File descriptor of nvme device
 * @stat:	
 * @save:	Save value across power states
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_features_write_protect(int fd, enum nvme_feat_nswpcfg_state state,
				    bool save, __u32 *result);

/**
 * nvme_set_features_iocs_profile() -
 * @fd:		File descriptor of nvme device
 * @iocsi:	IO Command Set Combination Index
 * @save:	Save value across power states
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_features_iocs_profile(int fd, __u8 iocsi, bool save);

/**
 * nvme_get_features() - Retrieve a feature attribute
 * @fd:		File descriptor of nvme device
 * @fid:	Feature identifier, see &enum nvme_features_id
 * @nsid:	Namespace ID, if applicable
 * @sel:	Select which type of attribute to return, see &enum nvme_get_features_sel
 * @cdw11:	Feature specific command dword11 field
 * @uuidx:	UUID Index for differentiating vendor specific encoding
 * @data_len:	Length of feature data, if applicable, in bytes
 * @data:	User address of feature data, if applicable
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_features(int fd, enum nvme_features_id fid, __u32 nsid,
		      enum nvme_get_features_sel sel, __u32 cdw11, __u8 uuidx,
		      __u32 data_len, void *data, __u32 *result);

static inline int nvme_get_features_data(int fd, enum nvme_features_id fid,
			__u32 nsid, __u32 data_len, void *data, __u32 *result)
{
	return nvme_get_features(fd, fid, nsid, NVME_GET_FEATURES_SEL_CURRENT,
				 0, 0, data_len, data, result);
}
static inline int nvme_get_features_simple(int fd, enum nvme_features_id fid,
			__u32 nsid, __u32 *result)
{
	return nvme_get_features_data(fd, fid, nsid, 0, NULL, result);
}

/**
 * nvme_get_features_arbitration() -
 * @fd:		File descriptor of nvme device
 * @sel:	Select which type of attribute to return, see &enum nvme_get_features_sel
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_features_arbitration(int fd, enum nvme_get_features_sel sel,
				  __u32 *result);

/**
 * nvme_get_features_power_mgmt() -
 * @fd:		File descriptor of nvme device
 * @sel:	Select which type of attribute to return, see &enum nvme_get_features_sel
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_features_power_mgmt(int fd, enum nvme_get_features_sel sel,
				 __u32 *result);

/**
 * nvme_get_features_lba_range() -
 * @fd:		File descriptor of nvme device
 * @sel:	Select which type of attribute to return, see &enum nvme_get_features_sel
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_features_lba_range(int fd, enum nvme_get_features_sel sel,
				struct nvme_lba_range_type *data,
				__u32 *result);
/**
 * nvme_get_features_temp_thresh() -
 * @fd:		File descriptor of nvme device
 * @sel:	Select which type of attribute to return, see &enum nvme_get_features_sel
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_features_temp_thresh(int fd, enum nvme_get_features_sel sel,
				  __u32 *result);

/**
 * nvme_get_features_err_recovery() -
 * @fd:		File descriptor of nvme device
 * @sel:	Select which type of attribute to return, see &enum nvme_get_features_sel
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_features_err_recovery(int fd, enum nvme_get_features_sel sel,
				   __u32 *result);

/**
 * nvme_get_features_volatile_wc() -
 * @fd:		File descriptor of nvme device
 * @sel:	Select which type of attribute to return, see &enum nvme_get_features_sel
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_features_volatile_wc(int fd, enum nvme_get_features_sel sel,
				  __u32 *result);

/**
 * nvme_get_features_num_queues() -
 * @fd:		File descriptor of nvme device
 * @sel:	Select which type of attribute to return, see &enum nvme_get_features_sel
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_features_num_queues(int fd, enum nvme_get_features_sel sel,
				 __u32 *result);

/**
 * nvme_get_features_irq_coalesce() -
 * @fd:		File descriptor of nvme device
 * @sel:	Select which type of attribute to return, see &enum nvme_get_features_sel
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_features_irq_coalesce(int fd, enum nvme_get_features_sel sel,
				   __u32 *result);

/**
 * nvme_get_features_irq_config() -
 * @fd:		File descriptor of nvme device
 * @sel:	Select which type of attribute to return, see &enum nvme_get_features_sel
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_features_irq_config(int fd, enum nvme_get_features_sel sel,
				 __u16 iv, __u32 *result);

/**
 * nvme_get_features_write_atomic() -
 * @fd:		File descriptor of nvme device
 * @sel:	Select which type of attribute to return, see &enum nvme_get_features_sel
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_features_write_atomic(int fd, enum nvme_get_features_sel sel,
				   __u32 *result);

/**
 * nvme_get_features_async_event() -
 * @fd:		File descriptor of nvme device
 * @sel:	Select which type of attribute to return, see &enum nvme_get_features_sel
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_features_async_event(int fd, enum nvme_get_features_sel sel,
				  __u32 *result);

/**
 * nvme_get_features_auto_pst() -
 * @fd:		File descriptor of nvme device
 * @sel:	Select which type of attribute to return, see &enum nvme_get_features_sel
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_features_auto_pst(int fd, enum nvme_get_features_sel sel,
			       struct nvme_feat_auto_pst *apst, __u32 *result);

/**
 * nvme_get_features_host_mem_buf() -
 * @fd:		File descriptor of nvme device
 * @sel:	Select which type of attribute to return, see &enum nvme_get_features_sel
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_features_host_mem_buf(int fd, enum nvme_get_features_sel sel,
				   __u32 *result);

/**
 * nvme_get_features_timestamp() -
 * @fd:		File descriptor of nvme device
 * @sel:	Select which type of attribute to return, see &enum nvme_get_features_sel
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_features_timestamp(int fd, enum nvme_get_features_sel sel,
				struct nvme_timestamp *ts);

/**
 * nvme_get_features_kato() -
 * @fd:		File descriptor of nvme device
 * @sel:	Select which type of attribute to return, see &enum nvme_get_features_sel
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_features_kato(int fd, enum nvme_get_features_sel sel, __u32 *result);

/**
 * nvme_get_features_hctm() -
 * @fd:		File descriptor of nvme device
 * @sel:	Select which type of attribute to return, see &enum nvme_get_features_sel
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_features_hctm(int fd, enum nvme_get_features_sel sel, __u32 *result);

/**
 * nvme_get_features_nopsc() -
 * @fd:		File descriptor of nvme device
 * @sel:	Select which type of attribute to return, see &enum nvme_get_features_sel
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_features_nopsc(int fd, enum nvme_get_features_sel sel, __u32 *result);

/**
 * nvme_get_features_rrl() -
 * @fd:		File descriptor of nvme device
 * @sel:	Select which type of attribute to return, see &enum nvme_get_features_sel
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_features_rrl(int fd, enum nvme_get_features_sel sel, __u32 *result);

/**
 * nvme_get_features_plm_config() -
 * @fd:		File descriptor of nvme device
 * @sel:	Select which type of attribute to return, see &enum nvme_get_features_sel
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_features_plm_config(int fd, enum nvme_get_features_sel sel,
				 __u16 nvmsetid, struct nvme_plm_config *data,
				 __u32 *result);

/**
 * nvme_get_features_plm_window() -
 * @fd:		File descriptor of nvme device
 * @sel:	Select which type of attribute to return, see &enum nvme_get_features_sel
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_features_plm_window(int fd, enum nvme_get_features_sel sel,
	__u16 nvmsetid, __u32 *result);

/**
 * nvme_get_features_lba_sts_interval() -
 * @fd:		File descriptor of nvme device
 * @sel:	Select which type of attribute to return, see &enum nvme_get_features_sel
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_features_lba_sts_interval(int fd, enum nvme_get_features_sel sel,
				       __u32 *result);

/**
 * nvme_get_features_host_behavior() -
 * @fd:		File descriptor of nvme device
 * @sel:	Select which type of attribute to return, see &enum nvme_get_features_sel
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_features_host_behavior(int fd, enum nvme_get_features_sel sel,
				    struct nvme_feat_host_behavior *data,
				    __u32 *result);

/**
 * nvme_get_features_sanitize() -
 * @fd:		File descriptor of nvme device
 * @sel:	Select which type of attribute to return, see &enum nvme_get_features_sel
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_features_sanitize(int fd, enum nvme_get_features_sel sel,
				__u32 *result);

/**
 * nvme_get_features_endurance_event_cfg() -
 * @fd:		File descriptor of nvme device
 * @sel:	Select which type of attribute to return, see &enum nvme_get_features_sel
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_features_endurance_event_cfg(int fd, enum nvme_get_features_sel sel,
					  __u16 endgid, __u32 *result);

/**
 * nvme_get_features_sw_progress() -
 * @fd:		File descriptor of nvme device
 * @sel:	Select which type of attribute to return, see &enum nvme_get_features_sel
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_features_sw_progress(int fd, enum nvme_get_features_sel sel,
				  __u32 *result);

/**
 * nvme_get_features_host_id() -
 * @fd:		File descriptor of nvme device
 * @sel:	Select which type of attribute to return, see &enum nvme_get_features_sel
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_features_host_id(int fd, enum nvme_get_features_sel sel,
			      bool exhid, __u32 len, __u8 *hostid);

/**
 * nvme_get_features_resv_mask() -
 * @fd:		File descriptor of nvme device
 * @sel:	Select which type of attribute to return, see &enum nvme_get_features_sel
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_features_resv_mask(int fd, enum nvme_get_features_sel sel,
				__u32 *result);

/**
 * nvme_get_features_resv_persist() -
 * @fd:		File descriptor of nvme device
 * @sel:	Select which type of attribute to return, see &enum nvme_get_features_sel
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_features_resv_persist(int fd, enum nvme_get_features_sel sel,
				   __u32 *result);

/**
 * nvme_get_features_write_protect() -
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace ID
 * @sel:	Select which type of attribute to return, see &enum nvme_get_features_sel
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_features_write_protect(int fd, __u32 nsid,
				    enum nvme_get_features_sel sel,
				    __u32 *result);

/**
 * nvme_get_features_iocs_profile() -
 * @fd:		File descriptor of nvme device
 * @sel:	Select which type of attribute to return, see &enum nvme_get_features_sel
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_features_iocs_profile(int fd, enum nvme_get_features_sel sel,
				   __u32 *result);

/**
 * nvme_format_nvm() - Format nvme namespace(s)
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace ID to format
 * @lbaf:	Logical block address format
 * @mset:	Metadata settings (extended or separated), true if extended
 * @pi:		Protection information type
 * @pil:	Protection information location (beginning or end), true if end
 * @ses:	Secure erase settings
 * @timeout:	Set to override default timeout to this value in milliseconds;
 * 		useful for long running formats. 0 will use system default.
 *
 * The Format NVM command low level formats the NVM media. This command is used
 * by the host to change the LBA data size and/or metadata size. A low level
 * format may destroy all data and metadata associated with all namespaces or
 * only the specific namespace associated with the command
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_format_nvm(int fd, __u32 nsid, __u8 lbaf,
		    enum nvme_cmd_format_mset mset,
		    enum nvme_cmd_format_pi pi,
		    enum nvme_cmd_format_pil pil,
		    enum nvme_cmd_format_ses ses,
		    __u32 timeout);

/**
 * nvme_ns_mgmt() -
 * @fd:		File descriptor of nvme device
 */
int nvme_ns_mgmt(int fd, __u32 nsid, enum nvme_ns_mgmt_sel sel,
		 struct nvme_id_ns *ns, __u32 *result, __u32 timeout);

/**
 * nvme_ns_mgmt_create() -
 * @fd:		File descriptor of nvme device
 * @ns:		Namespace identifiaction that defines creation parameters
 * @nsid:	On success, set to the namespace id that was created
 * @timeout:	Overide the default timeout to this value in milliseconds;
 * 		set to 0 to use the system default.
 *
 * On successful creation, the namespace exists in the subsystem, but is not
 * attached to any controller. Use the &nvme_ns_attach_ctrls() to assign the
 * namespace to one or more controllers.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_ns_mgmt_create(int fd, struct nvme_id_ns *ns, __u32 *nsid,
			__u32 timeout);

/**
 * nvme_ns_mgmt_delete() -
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace identifier to delete
 *
 * It is recommended that a namespace being deleted is not attached to any
 * controller. Use the &nvme_ns_detach_ctrls() first if the namespace is still
 * attached.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_ns_mgmt_delete(int fd, __u32 nsid);

/**
 * nvme_ns_attach() - Attach or detach namespace to controller(s)
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace ID to execute attach selection
 * @sel:	Attachment selection, see &enum nvme_ns_attach_sel
 * @ctrlist:	Controller list to modify attachment state of nsid
 */
int nvme_ns_attach(int fd, __u32 nsid, enum nvme_ns_attach_sel sel,
		   struct nvme_ctrl_list *ctrlist);

/**
 * nvme_ns_attach_ctrls() -
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace ID to attach
 * @ctrlist:	Controller list to modify attachment state of nsid
 */
int nvme_ns_attach_ctrls(int fd, __u32 nsid, struct nvme_ctrl_list *ctrlist);

/**
 * nvme_ns_detach_ctrls() -
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace ID to detach
 * @ctrlist:	Controller list to modify attachment state of nsid
 */
int nvme_ns_detach_ctrls(int fd, __u32 nsid, struct nvme_ctrl_list *ctrlist);

/**
 * nvme_fw_download() - Download part or all of a firmware image to the
 * 			controller
 * @fd:		File descriptor of nvme device
 * @offset:	Offset in the firmware data
 * @data_len:	Length of data in this command in bytes
 * @data:	Userspace address of the firmware data
 *
 * The Firmware Image Download command downloads all or a portion of an image
 * for a future update to the controller. The Firmware Image Download command
 * downloads a new image (in whole or in part) to the controller.
 *
 * The image may be constructed of multiple pieces that are individually
 * downloaded with separate Firmware Image Download commands. Each Firmware
 * Image Download command includes a Dword Offset and Number of Dwords that
 * specify a dword range.
 *
 * The new firmware image is not activated as part of the Firmware Image
 * Download command. Use the nvme_fw_commit() to activate a newly downloaded
 * image.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_fw_download(int fd, __u32 offset, __u32 data_len, void *data);

/**
 * nvme_fw_commit() - Commit firmware using the specified action
 * @fd:		File descriptor of nvme device
 * @slot:	Firmware slot to commit the downloaded image
 * @action:	Action to use for the firmware image, see &enum nvme_fw_commit_ca
 * @bpid:	Set to true to select the boot partition id
 *
 * The Firmware Commit command modifies the firmware image or Boot Partitions.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise. The command
 * 	   status
 * 	   response may specify additional
 * 	   reset actions required to complete the commit process.
 */
int nvme_fw_commit(int fd, __u8 slot, enum nvme_fw_commit_ca action, bool bpid);

/**
 * nvme_security_send() -
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace ID to issue security command on
 * @nssf:	NVMe Security Specific field
 * @spsp0:	Security Protocol Specific field
 * @spsp1:	Security Protocol Specific field
 * @secp:	Security Protocol
 * @tl:		Protocol specific transfer length
 * @data_len:	Data length of the payload in bytes
 * @data:	Security data payload to send
 * @result:	The command completion result from CQE dword0
 *
 * The Security Send command transfers security protocol data to the
 * controller. The data structure transferred to the controller as part of this
 * command contains security protocol specific commands to be performed by the
 * controller. The data structure transferred may also contain data or
 * parameters associated with the security protocol commands.
 *
 * The security data is protocol specific and is not defined by the NVMe
 * specification.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_security_send(int fd, __u32 nsid, __u8 nssf, __u8 spsp0, __u8 spsp1,
		       __u8 secp, __u32 tl, __u32 data_len, void *data,
		       __u32 *result);

/**
 * nvme_security_receive() -
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace ID to issue security command on
 * @nssf:	NVMe Security Specific field
 * @spsp0:	Security Protocol Specific field
 * @spsp1:	Security Protocol Specific field
 * @secp:	Security Protocol
 * @al:		Protocol specific allocation length
 * @data_len:	Data length of the payload in bytes
 * @data:	Security data payload to send
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_security_receive(int fd, __u32 nsid, __u8 nssf, __u8 spsp0,
			  __u8 spsp1, __u8 secp, __u32 al, __u32 data_len,
			  void *data, __u32 *result);

/**
 * nvme_get_lba_status() - Retrieve information on possibly unrecoverable LBAs
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace ID to retrieve LBA status
 * @slba:	Starting logical block address to check statuses
 * @mndw:	Maximum number of dwords to return
 * @atype:	Action type mechanism to determine LBA status desctriptors to
 * 		return, see &enum nvme_lba_status_atype
 * @rl:		Range length from slba to perform the action
 * @lbas:	Data payload to return status descriptors
 *
 * The Get LBA Status command requests information about Potentially
 * Unrecoverable LBAs. Refer to the specification for action type descriptions.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_lba_status(int fd, __u32 nsid, __u64 slba, __u32 mndw, __u16 rl,
			enum nvme_lba_status_atype atype,
			struct nvme_lba_status *lbas);

/**
 * nvme_directive_send() - Send directive command
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace ID, if applicable
 * @dspec:	Directive specific field
 * @doper:	Directive send operation, see &enum nvme_directive_send_doper
 * @dtype:	Directive type, see &enum nvme_directive_dtype
 * @dw12:	Directive specific command dword12
 * @data_len:	Length of data payload in bytes
 * @data:	Usespace address of data payload
 * @result:	If successful, the CQE dword0 value
 *
 * Directives is a mechanism to enable host and NVM subsystem or controller
 * information exchange. The Directive Send command transfers data related to a
 * specific Directive Type from the host to the controller.
 *
 * See the NVMe specification for more information.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_directive_send(int fd, __u32 nsid, __u16 dspec,
			enum nvme_directive_send_doper doper,
			enum nvme_directive_dtype dtype, __u32 cdw12,
			__u32 data_len, void *data, __u32 *result);

/**
 * nvme_directive_send_id_endir() -
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace ID
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_directive_send_id_endir(int fd, __u32 nsid, bool endir,
				 enum nvme_directive_dtype dtype,
				 struct nvme_id_directives *id);

/**
 * nvme_directive_send_stream_release_identifier() -
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace ID
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_directive_send_stream_release_identifier(int fd, __u32 nsid,
						  __u16 stream_id);

/**
 * nvme_directive_send_stream_release_resource() -
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace ID
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_directive_send_stream_release_resource(int fd, __u32 nsid);

/**
 * nvme_directive_recv() - Receive directive specific data
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace ID, if applicable
 * @dspec:	Directive specific field
 * @doper:	Directive receive operation, see &enum nvme_directive_receive_doper
 * @dtype:	Directive type, see &enum nvme_directive_dtype
 * @dw12:	Directive specific command dword12
 * @data_len:	Length of data payload
 * @data:	Usespace address of data payload in bytes
 * @result:	If successful, the CQE dword0 value
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_directive_recv(int fd, __u32 nsid, __u16 dspec,
			enum nvme_directive_receive_doper doper,
			enum nvme_directive_dtype dtype, __u32 cdw12,
			__u32 data_len, void *data, __u32 *result);

/**
 * nvme_directive_recv_identify_parameters() -
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace ID
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_directive_recv_identify_parameters(int fd, __u32 nsid,
					    struct nvme_id_directives *id);

/**
 * nvme_directive_recv_stream_parameters() -
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace ID
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_directive_recv_stream_parameters(int fd, __u32 nsid,
					  struct nvme_streams_directive_params *parms);

/**
 * nvme_directive_recv_stream_status() -
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace ID
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_directive_recv_stream_status(int fd, __u32 nsid, unsigned nr_entries,
				      struct nvme_streams_directive_status *id);

/**
 * nvme_directive_recv_stream_allocate() -
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace ID
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_directive_recv_stream_allocate(int fd, __u32 nsid, __u16 nsr,
					__u32 *result);

/**
 * enum nvme_fctype -
 * @nvme_fabrics_type_property_set:
 * @nvme_fabrics_type_connect:
 * @nvme_fabrics_type_property_get:
 * @nvme_fabrics_type_auth_send:
 * @nvme_fabrics_type_auth_receive:
 * @nvme_fabrics_type_disconnect:
 */
enum nvme_fctype {
	nvme_fabrics_type_property_set		= 0x00,
	nvme_fabrics_type_connect		= 0x01,
	nvme_fabrics_type_property_get		= 0x04,
	nvme_fabrics_type_auth_send		= 0x05,
	nvme_fabrics_type_auth_receive		= 0x06,
	nvme_fabrics_type_disconnect		= 0x08,
};

/**
 * nvme_set_property() - Set controller property
 * @fd:		File descriptor of nvme device
 * @offset:	Property offset from the base to set
 * @value:	The value to set the property
 *
 * This is an NVMe-over-Fabrics specific command, not applicable to PCIe. These
 * properties align to the PCI MMIO controller registers.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_property(int fd, int offset, __u64 value);

/**
 * nvme_get_property() - Get a controller property
 * @fd:		File descriptor of nvme device
 * @offset:	Property offset from the base to retrieve
 * @value:	Where the property's value will be stored on success
 *
 * This is an NVMe-over-Fabrics specific command, not applicable to PCIe. These
 * properties align to the PCI MMIO controller registers.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_property(int fd, int offset, __u64 *value);

/**
 * nvme_sanitize_nvm() - Start a sanitize operation
 * @fd:		File descriptor of nvme device
 * @sanact:	Sanitize action, see &enum nvme_sanitize_sanact
 * @ause:	Set to allow unrestriced sanitize exit
 * @owpass:	Overwrite pass count
 * @oipbp:	Set to overwrite invert pattern between passes
 * @nodas:	Set to not deallocate blocks after sanitizing
 * @ovrpat:	Overwrite pattern
 *
 * A sanitize operation alters all user data in the NVM subsystem such that
 * recovery of any previous user data from any cache, the non-volatile media,
 * or any Controller Memory Buffer is not possible.
 *
 * The Sanitize command starts a sanitize operation or to recover from a
 * previously failed sanitize operation. The sanitize operation types that may
 * be supported are Block Erase, Crypto Erase, and Overwrite. All sanitize
 * operations are processed in the background, i.e., completion of the sanitize
 * command does not indicate completion of the sanitize operation.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_sanitize_nvm(int fd, enum nvme_sanitize_sanact sanact, bool ause,
		      __u8 owpass, bool oipbp, bool nodas, __u32 ovrpat);

/**
 * nvme_dev_self_test() - Start or abort a self test
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace ID to test
 * @stc:	Self test code, see &enum nvme_dst_stc
 *
 * The Device Self-test command starts a device self-test operation or abort a
 * device self-test operation. A device self-test operation is a diagnostic
 * testing sequence that tests the integrity and functionality of the
 * controller and may include testing of the media associated with namespaces.
 * The controller may return a response to this command immediately while
 * running the self-test in the background.
 *
 * Set the 'nsid' field to 0 to not include namepsaces in the test. Set to
 * 0xffffffff to test all namespaces. All other values tests a specific
 * namespace, if present.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_dev_self_test(int fd, __u32 nsid, enum nvme_dst_stc stc);

/**
 * nvme_virtual_mgmt() - Virtualization resource management
 * @fd:		File descriptor of nvme device
 * @act:	Virtual resource action, see &enum nvme_virt_mgmt_act
 * @rt:		Resource type to modify, see &enum nvme_virt_mgmt_rt
 * @cntlid:	Controller id for which resources are bing modified
 * @nr:		Number of resources being allocated or assigned
 * @result:	If successful, the CQE dword0
 *
 * The Virtualization Management command is supported by primary controllers
 * that support the Virtualization Enhancements capability. This command is
 * used for several functions:
 *
 *	- Modifying Flexible Resource allocation for the primary controller
 *	- Assigning Flexible Resources for secondary controllers
 *	- Setting the Online and Offline state for secondary controllers
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_virtual_mgmt(int fd, enum nvme_virt_mgmt_act act,
		      enum nvme_virt_mgmt_rt rt, __u16 cntlid, __u16 nr,
		      __u32 *result);

/**
 * enum nvme_io_opcode -
 * @nvme_cmd_flush:
 * @nvme_cmd_write:
 * @nvme_cmd_read:
 * @nvme_cmd_write_uncor:
 * @nvme_cmd_compare:
 * @nvme_cmd_write_zeroes:
 * @nvme_cmd_dsm:
 * @nvme_cmd_verify:
 * @nvme_cmd_resv_register:
 * @nvme_cmd_resv_report:
 * @nvme_cmd_resv_acquire:
 * @nvme_cmd_resv_release:
 */
enum nvme_io_opcode {
	nvme_cmd_flush		= 0x00,
	nvme_cmd_write		= 0x01,
	nvme_cmd_read		= 0x02,
	nvme_cmd_write_uncor	= 0x04,
	nvme_cmd_compare	= 0x05,
	nvme_cmd_write_zeroes	= 0x08,
	nvme_cmd_dsm		= 0x09,
	nvme_cmd_verify		= 0x0c,
	nvme_cmd_resv_register	= 0x0d,
	nvme_cmd_resv_report	= 0x0e,
	nvme_cmd_resv_acquire	= 0x11,
	nvme_cmd_resv_release	= 0x15,
	nvme_cmd_copy		= 0x19,
	nvme_zns_cmd_mgmt_send	= 0x79,
	nvme_zns_cmd_mgmt_recv	= 0x7a,
	nvme_zns_cmd_append	= 0x7d,
};

/**
 * nvme_flush() - Send an nvme flush command
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace identifier
 *
 * The Flush command requests that the contents of volatile write cache be made
 * non-volatile.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_flush(int fd, __u32 nsid);

/**
 * enum nvme_io_control_flags -
 * @NVME_IO_DTYPE_STREAMS:
 * @NVME_IO_DEAC:
 * @NVME_IO_ZNS_APPEND_PIREMAP:
 * @NVME_IO_PRINFO_PRCHK_REF:
 * @NVME_IO_PRINFO_PRCHK_APP:
 * @NVME_IO_PRINFO_PRCHK_GUARD:
 * @NVME_IO_PRINFO_PRACT:
 * @NVME_IO_FUA:
 * @NVME_IO_LR:
 */
enum nvme_io_control_flags {
	NVME_IO_DTYPE_STREAMS		= 1 << 4,
	NVME_IO_DEAC			= 1 << 9,
	NVME_IO_ZNS_APPEND_PIREMAP	= 1 << 9,
	NVME_IO_PRINFO_PRCHK_REF	= 1 << 10,
	NVME_IO_PRINFO_PRCHK_APP	= 1 << 11,
	NVME_IO_PRINFO_PRCHK_GUARD	= 1 << 12,
	NVME_IO_PRINFO_PRACT		= 1 << 13,
	NVME_IO_FUA			= 1 << 14,
	NVME_IO_LR			= 1 << 15,
};

/**
 * enum nvme_io_dsm_flag -
 * @NVME_IO_DSM_FREQ_UNSPEC:
 * @NVME_IO_DSM_FREQ_TYPICAL:
 * @NVME_IO_DSM_FREQ_RARE:
 * @NVME_IO_DSM_FREQ_READS:
 * @NVME_IO_DSM_FREQ_WRITES:
 * @NVME_IO_DSM_FREQ_RW:
 * @NVME_IO_DSM_FREQ_ONCE:
 * @NVME_IO_DSM_FREQ_PREFETCH:
 * @NVME_IO_DSM_FREQ_TEMP:
 * @NVME_IO_DSM_LATENCY_NONE:
 * @NVME_IO_DSM_LATENCY_IDLE:
 * @NVME_IO_DSM_LATENCY_NORM:
 * @NVME_IO_DSM_LATENCY_LOW:
 * @NVME_IO_DSM_SEQ_REQ:
 * @NVME_IO_DSM_COMPRESSED:
 */
enum nvme_io_dsm_flags {
	NVME_IO_DSM_FREQ_UNSPEC		= 0,
	NVME_IO_DSM_FREQ_TYPICAL	= 1,
	NVME_IO_DSM_FREQ_RARE		= 2,
	NVME_IO_DSM_FREQ_READS		= 3,
	NVME_IO_DSM_FREQ_WRITES		= 4,
	NVME_IO_DSM_FREQ_RW		= 5,
	NVME_IO_DSM_FREQ_ONCE		= 6,
	NVME_IO_DSM_FREQ_PREFETCH	= 7,
	NVME_IO_DSM_FREQ_TEMP		= 8,
	NVME_IO_DSM_LATENCY_NONE	= 0 << 4,
	NVME_IO_DSM_LATENCY_IDLE	= 1 << 4,
	NVME_IO_DSM_LATENCY_NORM	= 2 << 4,
	NVME_IO_DSM_LATENCY_LOW		= 3 << 4,
	NVME_IO_DSM_SEQ_REQ		= 1 << 6,
	NVME_IO_DSM_COMPRESSED		= 1 << 7,
};

/**
 * nvme_read() - Submit an nvme user read command
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace ID
 * @slba:	Starting logical block
 * @nblocks:	Number of logical blocks to send (0's based value)
 * @control:	Command control flags, see &enum nvme_io_control_flags.
 * @dsm:	Data set management attributes, see &enum nvme_io_dsm_flags
 * @reftag:	This field specifies the Initial Logical Block Reference Tag
 * 		expected value. Used only if the namespace is formatted to use
 * 		end-to-end protection information.
 * @apptag:	This field specifies the Application Tag Mask expected value.
 * 		Used only if the namespace is formatted to use end-to-end
 * 		protection information.
 * @appmask:	This field specifies the Application Tag expected value. Used
 * 		only if the namespace is formatted to use end-to-end protection
 * 		information.
 * @data_len:	Length of user buffer, @data, in bytes
 * @data:	Pointer to user address of the data buffer
 * metadata_len:Length of user buffer, @metadata, in bytes
 * @metadata:	Pointer to user address of the metadata buffer
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_read(int fd, __u32 nsid, __u64 slba, __u16 nlb, __u16 control,
	      __u8 dsm, __u32 reftag, __u16 apptag, __u16 appmask,
	      __u32 data_len, void *data, __u32 metadata_len, void *metadata);

/**
 * nvme_write() - Submit an nvme user write command
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace ID
 * @slba:	Starting logical block
 * @nblocks:	Number of logical blocks to send (0's based value)
 * @control:	Command control flags, see &enum nvme_io_control_flags.
 * @dsm:	Data set management attributes, see &enum nvme_io_dsm_flags
 * @dspec:	Directive specific command, eg: stream identifier
 * @reftag:	This field specifies the Initial Logical Block Reference Tag
 * 		expected value. Used only if the namespace is formatted to use
 * 		end-to-end protection information.
 * @apptag:	This field specifies the Application Tag Mask expected value.
 * 		Used only if the namespace is formatted to use end-to-end
 * 		protection information.
 * @appmask:	This field specifies the Application Tag expected value. Used
 * 		only if the namespace is formatted to use end-to-end protection
 * 		information.
 * @data_len:	Length of user buffer, @data, in bytes
 * @data:	Pointer to user address of the data buffer
 * metadata_len:Length of user buffer, @metadata, in bytes
 * @metadata:	Pointer to user address of the metadata buffer
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_write(int fd, __u32 nsid, __u64 slba, __u16 nlb, __u16 control,
	       __u8 dsm, __u16 dspec, __u32 reftag, __u16 apptag,
	       __u16 appmask, __u32 data_len, void *data, __u32 metadata_len,
	       void *metadata);

/**
 * nvme_compare() - Submit an nvme user compare command
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace ID
 * @slba:	Starting logical block
 * @nblocks:	Number of logical blocks to send (0's based value)
 * @control:	Command control flags, see &enum nvme_io_control_flags.
 * @reftag:	This field specifies the Initial Logical Block Reference Tag
 * 		expected value. Used only if the namespace is formatted to use
 * 		end-to-end protection information.
 * @apptag:	This field specifies the Application Tag Mask expected value.
 * 		Used only if the namespace is formatted to use end-to-end
 * 		protection information.
 * @appmask:	This field specifies the Application Tag expected value. Used
 * 		only if the namespace is formatted to use end-to-end protection
 * 		information.
 * @data_len:	Length of user buffer, @data, in bytes
 * @data:	Pointer to user address of the data buffer
 * metadata_len:Length of user buffer, @metadata, in bytes
 * @metadata:	Pointer to user address of the metadata buffer
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_compare(int fd, __u32 nsid, __u64 slba, __u16 nlb, __u16 control,
		 __u32 reftag, __u16 apptag, __u16 appmask, __u32 data_len,
		 void *data, __u32 metadata_len, void *metadata);

/**
 * nvme_write_zeros() - Submit an nvme write zeroes command
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace identifier
 * @slba:	Starting logical block
 * @nlb:	Number of logical blocks to clear (0's based value)
 * @control:	Command control flags, see &enum nvme_io_control_flags.
 * @reftag:	This field specifies the Initial Logical Block Reference Tag
 * 		expected value. Used only if the namespace is formatted to use
 * 		end-to-end protection information.
 * @apptag:	This field specifies the Application Tag Mask expected value.
 * 		Used only if the namespace is formatted to use end-to-end
 * 		protection information.
 * @appmask:	This field specifies the Application Tag expected value. Used
 * 		only if the namespace is formatted to use end-to-end protection
 * 		information.
 *
 * The Write Zeroes command sets a range of logical blocks to zero.  After
 * successful completion of this command, the value returned by subsequent
 * reads of logical blocks in this range shall be all bytes cleared to 0h until
 * a write occurs to this LBA range.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_write_zeros(int fd, __u32 nsid, __u64 slba, __u16 nlb, __u16 control,
		     __u32 reftag, __u16 apptag, __u16 appmask);

/**
 * nvme_write_uncorrectable() - Submit an nvme write uncorrectable command
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace identifier
 * @slba:	Starting logical block
 * @nlb:	Number of logical blocks to invalidate (0's based value)
 *
 * The Write Uncorrectable command marks a range of logical blocks as invalid.
 * When the specified logical block(s) are read after this operation, a failure
 * is returned with Unrecovered Read Error status. To clear the invalid logical
 * block status, a write operation on those logical blocks is required.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_write_uncorrectable(int fd, __u32 nsid, __u64 slba, __u16 nlb);

/**
 * nvme_verify() - Send an nvme verify command
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace identifier
 * @slba:	Starting logical block
 * @nlb:	Number of logical blocks to verify (0's based value)
 * @control:	Command control flags, see &enum nvme_io_control_flags.
 * @reftag:	This field specifies the Initial Logical Block Reference Tag
 * 		expected value. Used only if the namespace is formatted to use
 * 		end-to-end protection information.
 * @apptag:	This field specifies the Application Tag Mask expected value.
 * 		Used only if the namespace is formatted to use end-to-end
 * 		protection information.
 * @appmask:	This field specifies the Application Tag expected value. Used
 * 		only if the namespace is formatted to use end-to-end protection
 * 		information.
 *
 * The Verify command verifies integrity of stored information by reading data
 * and metadata, if applicable, for the LBAs indicated without transferring any
 * data or metadata to the host.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_verify(int fd, __u32 nsid, __u64 slba, __u16 nlb, __u16 control,
		__u32 reftag, __u16 apptag, __u16 appmask);

/**
 * enum nvme_dsm_attributes -
 * @NVME_DSMGMT_IDR:
 * @NVME_DSMGMT_IDW:
 * @NVME_DSMGMT_AD:
 */
enum nvme_dsm_attributes {
	NVME_DSMGMT_IDR			= 1 << 0,
	NVME_DSMGMT_IDW			= 1 << 1,
	NVME_DSMGMT_AD			= 1 << 2,
};

/**
 * nvme_dsm() - Send an nvme data set management command
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace identifier
 * @attrs:	DSM attributes, see &enum nvme_dsm_attributes
 * &nr_ranges:	Number of block ranges in the data set management attributes
 * @dsm:	The data set management attributes
 *
 * The Dataset Management command is used by the host to indicate attributes
 * for ranges of logical blocks. This includes attributes like frequency that
 * data is read or written, access size, and other information that may be used
 * to optimize performance and reliability, and may be used to
 * deallocate/unmap/trim those logical blocks.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_dsm(int fd, __u32 nsid, __u32 attrs, __u16 nr_ranges,
	     struct nvme_dsm_range *dsm);

/**
 * nvme_copy() -
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_copy(int fd, __u32 nsid, struct nvme_copy_range *copy, __u64 sdlba,
		__u16 nr, __u8 prinfor, __u8 prinfow, __u8 dtype, __u16 dspec,
		__u8 format, int lr, int fua, __u32 ilbrt, __u16 lbatm,
		__u16 lbat);

/**
 * enum nvme_resv_rtype -
 * @NVME_RESERVATION_RTYPE_WE:
 * @NVME_RESERVATION_RTYPE_EA:
 * @NVME_RESERVATION_RTYPE_WERO:
 * @NVME_RESERVATION_RTYPE_EARO:
 * @NVME_RESERVATION_RTYPE_WEAR:
 * @NVME_RESERVATION_RTYPE_EAAR:
 */
enum nvme_resv_rtype {
	NVME_RESERVATION_RTYPE_WE	= 1,
	NVME_RESERVATION_RTYPE_EA	= 2,
	NVME_RESERVATION_RTYPE_WERO	= 3,
	NVME_RESERVATION_RTYPE_EARO	= 4,
	NVME_RESERVATION_RTYPE_WEAR	= 5,
	NVME_RESERVATION_RTYPE_EAAR	= 6,
};

/**
 * enum nvme_resv_racqa -
 * @NVME_RESERVATION_RACQA_ACQUIRE:
 * @NVME_RESERVATION_RACQA_PREEMPT:
 * @NVME_RESERVATION_RACQA_PREEMPT_AND_ABORT:
 */
enum nvme_resv_racqa {
	NVME_RESERVATION_RACQA_ACQUIRE			= 0,
	NVME_RESERVATION_RACQA_PREEMPT			= 1,
	NVME_RESERVATION_RACQA_PREEMPT_AND_ABORT	= 2,
};

/**
 * nvme_resv_acquire() - Send an nvme reservation acquire
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace identifier
 * @rtype:	The type of reservation to be create, see &enum nvme_resv_rtype
 * @racqa:	The action that is performed by the command, see &enum nvme_resv_racqa
 * @iekey:	Set to ignore the existing key
 * @crkey:	The current reservation key associated with the host
 * @nrkey:	The reservation key to be unregistered from the namespace if
 * 		the action is preempt
 *
 * The Reservation Acquire command acquires a reservation on a namespace,
 * preempt a reservation held on a namespace, and abort a reservation held on a
 * namespace.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_resv_acquire(int fd, __u32 nsid, enum nvme_resv_rtype rtype,
		      enum nvme_resv_racqa racqa, bool iekey,
		      __u64 crkey, __u64 nrkey);

/**
 * enum nvme_resv_rrega -
 * @NVME_RESERVATION_RREGA_REGISTER_KEY:
 * @NVME_RESERVATION_RREGA_UNREGISTER_KEY:
 * @NVME_RESERVATION_RREGA_REPLACE_KEY:
 */
enum nvme_resv_rrega {
	NVME_RESERVATION_RREGA_REGISTER_KEY		= 0,
	NVME_RESERVATION_RREGA_UNREGISTER_KEY		= 1,
	NVME_RESERVATION_RREGA_REPLACE_KEY		= 2,
};

/**
 * enum nvme_resv_cptpl -
 * @NVME_RESERVATION_CPTPL_NO_CHANGE:
 * @NVME_RESERVATION_CPTPL_CLEAR:
 * @NVME_RESERVATION_CPTPL_PERSIST:
 */
enum nvme_resv_cptpl {
	NVME_RESERVATION_CPTPL_NO_CHANGE		= 0,
	NVME_RESERVATION_CPTPL_CLEAR			= 2,
	NVME_RESERVATION_CPTPL_PERSIST			= 3,
};

/**
 * nvme_resv_register() - Send an nvme reservation register
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace identifier
 * @rrega:	The registration action, see &enum nvme_resv_rrega
 * @cptpl:	Change persist through power loss, see &enum nvme_resv_cptpl
 * @iekey:	Set to ignore the existing key
 * @crkey:	The current reservation key associated with the host
 * @nrkey:	The new reservation key to be register if action is register or
 * 		replace
 *
 * The Reservation Register command registers, unregisters, or replaces a
 * reservation key.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_resv_register(int fd, __u32 nsid, enum nvme_resv_rrega rrega,
		       enum nvme_resv_cptpl cptpl, bool iekey,
		       __u64 crkey, __u64 nrkey);

/**
 * enum nvme_resv_rrela -
 * @NVME_RESERVATION_RRELA_RELEASE:
 * @NVME_RESERVATION_RRELA_CLEAR:
 */
enum nvme_resv_rrela {
	NVME_RESERVATION_RRELA_RELEASE			= 0,
	NVME_RESERVATION_RRELA_CLEAR			= 1
};

/**
 * nvme_resv_release() - Send an nvme reservation release
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace identifier
 * @rtype:	The type of reservation to be create, see &enum nvme_resv_rtype
 * @rrela:	Reservation releast action, see &enum nvme_resv_rrela
 * @iekey:	Set to ignore the existing key
 * @crkey:	The current reservation key to release
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_resv_release(int fd, __u32 nsid, enum nvme_resv_rtype rtype,
		      enum nvme_resv_rrela rrela, bool iekey,
		      __u64 crkey);

/**
 * nvme_resv_report() - Send an nvme reservation report
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace identifier
 * @eds:	Request extended Data Structure
 * @len:	Number of bytes to request transfered with this command
 * @report:	The user space destination address to store the reservation report
 *
 * Returns a Reservation Status data structure to memory that describes the
 * registration and reservation status of a namespace. See the defintion for
 * the returned structure, &struct nvme_reservation_status, for more details.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_resv_report(int fd, __u32 nsid, bool eds, __u32 len,
		     struct nvme_resv_status *report);

enum nvme_zns_send_action {
	NVME_ZNS_ZSA_CLOSE		= 0x1,
	NVME_ZNS_ZSA_FINISH		= 0x2,
	NVME_ZNS_ZSA_OPEN		= 0x3,
	NVME_ZNS_ZSA_RESET		= 0x4,
	NVME_ZNS_ZSA_OFFLINE		= 0x5,
	NVME_ZNS_ZSA_SET_DESC_EXT	= 0x10,
};

/**
 * nvme_zns_mgmt_send() -
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace ID
 * @slba:
 * @select_all:
 * @zsa:
 * @data_len:
 * @data:
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_zns_mgmt_send(int fd, __u32 nsid, __u64 slba, bool select_all,
		       enum nvme_zns_send_action zsa, __u32 data_len,
		       void *data);

/**
 * enum nvme_zns_recv_action -
 */
enum nvme_zns_recv_action {
	NVME_ZNS_ZRA_REPORT_ZONES		= 0x0,
	NVME_ZNS_ZRA_EXTENDED_REPORT_ZONES	= 0x1,
};

/**
 * nvme_zns_mgmt_recv() -
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace ID
 * @slba:
 * @zra:
 * @zrasf:
 * @zras_feat:
 * @data_len:
 * @data:
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_zns_mgmt_recv(int fd, __u32 nsid, __u64 slba,
		       enum nvme_zns_recv_action zra, __u16 zrasf,
		       bool zras_feat, __u32 data_len, void *data);

/**
 * enum nvme_zns_report_options -
 */
enum nvme_zns_report_options {
	NVME_ZNS_ZRAS_REPORT_ALL		= 0x0,
	NVME_ZNS_ZRAS_REPORT_EMPTY		= 0x1,
	NVME_ZNS_ZRAS_REPORT_IMPL_OPENED	= 0x2,
	NVME_ZNS_ZRAS_REPORT_EXPL_OPENED	= 0x3,
	NVME_ZNS_ZRAS_REPORT_CLOSED		= 0x4,
	NVME_ZNS_ZRAS_REPORT_FULL		= 0x5,
	NVME_ZNS_ZRAS_REPORT_READ_ONLY		= 0x6,
	NVME_ZNS_ZRAS_REPORT_OFFLINE		= 0x7,
};

int nvme_zns_report_zones(int fd, __u32 nsid, __u64 slba, bool extended,
			  enum nvme_zns_report_options opts, bool partial,
			  __u32 data_len, void *data);

/**
 * nvme_zns_append() -
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace ID
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_zns_append(int fd, __u32 nsid, __u64 zslba, __u16 nlb, __u16 control,
		    __u32 ilbrt, __u16 lbat, __u16 lbatm, __u32 data_len,
		    void *data, __u32 metadata_len, void *metadata,
		    __u64 *result);

#endif /* _LIBNVME_IOCTL_H */
