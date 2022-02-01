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

/* '0' is interpreted by the kernel to mean 'apply the default timeout' */
#define NVME_DEFAULT_IOCTL_TIMEOUT 0

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
 * nvme_identify_args - Arguments for the NVMe Identify command
 * @data:	User space destination address to transfer the data
 * @timeout:	Timeout in ms (0 for default timeout)
 * @fd:		File descriptor of nvme device
 * @result:	The command completion result from CQE dword0
 * @cns:	The Controller or Namespace structure, see @enum nvme_identify_cns
 * @csi:	Command Set Identifier
 * @nsid:	Namespace identifier, if applicable
 * @domid:	Domain identifier, if applicable
 * @cntid:	The Controller Identifier, if applicable
 * @nvmsetid:	The NVMe Set ID if CNS is 04h
 * @uuidx:	UUID Index if controller supports this id selection method
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
	__u16 nvmsetid;
	__u16 domid;
	__u8 uuidx;
} __attribute__((packed, aligned(__alignof__(__u32*))));

/**
 * nvme_identify() - Send the NVMe Identify command
 * @args:	&struct nvme_identify_args argument structure
 *
 * The Identify command returns a data buffer that describes information about
 * the NVM subsystem, the controller or the namespace(s).
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_identify(struct nvme_identify_args *args);

static int nvme_identify_cns_nsid(int fd, enum nvme_identify_cns cns,
			__u32 nsid, void *data)
{
	struct nvme_identify_args args = {
		.result = NULL,
		.data = data,
		.args_size = sizeof(args),
		.fd = fd,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.cns = cns,
		.csi = NVME_CSI_NVM,
		.nsid = nsid,
		.cntid = NVME_CNTLID_NONE,
		.nvmsetid = NVME_NVMSETID_NONE,
		.domid = NVME_DOMID_NONE,
		.uuidx = NVME_UUID_NONE,
	};

	return nvme_identify(&args);
}

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
static inline int nvme_identify_ctrl(int fd, struct nvme_id_ctrl *id)
{
	return nvme_identify_cns_nsid(fd, NVME_IDENTIFY_CNS_CTRL,
				      NVME_NSID_NONE, id);
}

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
static inline int nvme_identify_ns(int fd, __u32 nsid, struct nvme_id_ns *ns)
{
	return nvme_identify_cns_nsid(fd, NVME_IDENTIFY_CNS_NS, nsid, ns);
}

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
static inline int nvme_identify_allocated_ns(int fd, __u32 nsid,
			struct nvme_id_ns *ns)
{
	return nvme_identify_cns_nsid(fd, NVME_IDENTIFY_CNS_ALLOCATED_NS,
				      nsid, ns);
}

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
static inline int nvme_identify_active_ns_list(int fd, __u32 nsid,
			struct nvme_ns_list *list)
{
	return nvme_identify_cns_nsid(fd, NVME_IDENTIFY_CNS_NS_ACTIVE_LIST,
				      nsid, list);
}

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
static inline int nvme_identify_allocated_ns_list(int fd, __u32 nsid,
			struct nvme_ns_list *list)
{
	return nvme_identify_cns_nsid(fd, NVME_IDENTIFY_CNS_ALLOCATED_NS_LIST,
				      nsid, list);
}

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
static inline int nvme_identify_ctrl_list(int fd, __u16 cntid,
			struct nvme_ctrl_list *ctrlist)
{
	struct nvme_identify_args args = {
		.result = NULL,
		.data = ctrlist,
		.args_size = sizeof(args),
		.fd = fd,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.cns = NVME_IDENTIFY_CNS_CTRL_LIST,
		.csi = NVME_CSI_NVM,
		.nsid = NVME_NSID_NONE,
		.cntid = cntid,
		.nvmsetid = NVME_NVMSETID_NONE,
		.domid = NVME_DOMID_NONE,
		.uuidx = NVME_UUID_NONE,
	};

	return nvme_identify(&args);
}

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
static inline int nvme_identify_nsid_ctrl_list(int fd, __u32 nsid, __u16 cntid,
			struct nvme_ctrl_list *ctrlist)
{
	struct nvme_identify_args args = {
		.result = NULL,
		.data = ctrlist,
		.args_size = sizeof(args),
		.fd = fd,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.cns = NVME_IDENTIFY_CNS_NS_CTRL_LIST,
		.csi = NVME_CSI_NVM,
		.nsid = nsid,
		.cntid = cntid,
		.nvmsetid = NVME_NVMSETID_NONE,
		.domid = NVME_DOMID_NONE,
		.uuidx = NVME_UUID_NONE,
	};

	return nvme_identify(&args);
}

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
static inline int nvme_identify_ns_descs(int fd, __u32 nsid,
			struct nvme_ns_id_desc *descs)
{
	return nvme_identify_cns_nsid(fd, NVME_IDENTIFY_CNS_NS_DESC_LIST,
				      nsid, descs);
}

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
static inline int nvme_identify_nvmset_list(int fd, __u16 nvmsetid,
			struct nvme_id_nvmset_list *nvmset)
{
	struct nvme_identify_args args = {
		.result = NULL,
		.data = nvmset,
		.args_size = sizeof(args),
		.fd = fd,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.cns = NVME_IDENTIFY_CNS_NVMSET_LIST,
		.csi = NVME_CSI_NVM,
		.nsid = NVME_NSID_NONE,
		.cntid = NVME_CNTLID_NONE,
		.nvmsetid = nvmsetid,
		.domid = NVME_DOMID_NONE,
		.uuidx = NVME_UUID_NONE,
	};

	return nvme_identify(&args);
}

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
static inline int nvme_identify_primary_ctrl(int fd, __u16 cntid,
			struct nvme_primary_ctrl_cap *cap)
{
	struct nvme_identify_args args = {
		.result = NULL,
		.data = cap,
		.args_size = sizeof(args),
		.fd = fd,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.cns = NVME_IDENTIFY_CNS_PRIMARY_CTRL_CAP,
		.csi = NVME_CSI_NVM,
		.nsid = NVME_NSID_NONE,
		.cntid = cntid,
		.nvmsetid = NVME_NVMSETID_NONE,
		.domid = NVME_DOMID_NONE,
		.uuidx = NVME_UUID_NONE,
	};

	return nvme_identify(&args);
}

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
static inline int nvme_identify_secondary_ctrl_list(int fd, __u32 nsid,
			__u16 cntid, struct nvme_secondary_ctrl_list *list)
{
	struct nvme_identify_args args = {
		.result = NULL,
		.data = list,
		.args_size = sizeof(args),
		.fd = fd,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.cns = NVME_IDENTIFY_CNS_SECONDARY_CTRL_LIST,
		.csi = NVME_CSI_NVM,
		.nsid = nsid,
		.cntid = cntid,
		.nvmsetid = NVME_NVMSETID_NONE,
		.domid = NVME_DOMID_NONE,
		.uuidx = NVME_UUID_NONE,
	};

	return nvme_identify(&args);
}

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
static inline int nvme_identify_ns_granularity(int fd,
			struct nvme_id_ns_granularity_list *list)
{
	return nvme_identify_cns_nsid(fd, NVME_IDENTIFY_CNS_NS_GRANULARITY,
				      NVME_NSID_NONE, list);
}

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
static inline int nvme_identify_uuid(int fd, struct nvme_id_uuid_list *list)
{
	return nvme_identify_cns_nsid(fd, NVME_IDENTIFY_CNS_UUID_LIST,
				      NVME_NSID_NONE, list);
}

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
static inline int nvme_identify_ns_csi(int fd, __u32 nsid,
			enum nvme_csi csi, void *data)
{
	struct nvme_identify_args args = {
		.result = NULL,
		.data = data,
		.args_size = sizeof(args),
		.fd = fd,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.cns = NVME_IDENTIFY_CNS_CSI_NS,
		.csi = csi,
		.nsid = nsid,
		.cntid = NVME_CNTLID_NONE,
		.nvmsetid = NVME_NVMSETID_NONE,
		.domid = NVME_DOMID_NONE,
		.uuidx = NVME_UUID_NONE,
	};

	return nvme_identify(&args);
}

/**
 * nvme_identify_ctrl_csi() -
 * @fd:		File descriptor of nvme device
 * @csi:	Command Set Identifier
 * @data:	User space destination address to transfer the data
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
static inline int nvme_identify_ctrl_csi(int fd, enum nvme_csi csi, void *data)
{
	struct nvme_identify_args args = {
		.result = NULL,
		.data = data,
		.args_size = sizeof(args),
		.fd = fd,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.cns = NVME_IDENTIFY_CNS_CSI_CTRL,
		.csi = csi,
		.nsid = NVME_NSID_NONE,
		.cntid = NVME_CNTLID_NONE,
		.nvmsetid = NVME_NVMSETID_NONE,
		.domid = NVME_DOMID_NONE,
		.uuidx = NVME_UUID_NONE,
	};

	return nvme_identify(&args);
}

/**
 * nvme_identify_active_ns_list_csi() -
 * @fd:		File descriptor of nvme device
 * @nsid:	Return namespaces greater than this identifier
 * @csi:	Command Set Identifier
 * @ns_list:	User space destination address to transfer the data
 *
 * A list of 1024 namespace IDs is returned to the host containing active
 * NSIDs in increasing order that are greater than the value specified in
 * the Namespace Identifier (nsid) field of the command and matching the
 * I/O Command Set specified in the @csi argument.
 *
 * See &struct nvme_ns_list for the definition of the returned structure.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
static inline int nvme_identify_active_ns_list_csi(int fd, __u32 nsid,
			enum nvme_csi csi, struct nvme_ns_list *list)
{
	struct nvme_identify_args args = {
		.result = NULL,
		.data = list,
		.args_size = sizeof(args),
		.fd = fd,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.cns = NVME_IDENTIFY_CNS_NS_ACTIVE_LIST,
		.csi = csi,
		.nsid = nsid,
		.cntid = NVME_CNTLID_NONE,
		.nvmsetid = NVME_NVMSETID_NONE,
		.domid = NVME_DOMID_NONE,
		.uuidx = NVME_UUID_NONE,
	};

	return nvme_identify(&args);
}

/**
 * nvme_identify_allocated_ns_list_csi() -
 * @fd:		File descriptor of nvme device
 * @nsid:	Return namespaces greater than this identifier
 * @csi:	Command Set Identifier
 * @ns_list:	User space destination address to transfer the data
 *
 * A list of 1024 namespace IDs is returned to the host containing allocated
 * NSIDs in increasing order that are greater than the value specified in
 * the @nsid field of the command and matching the I/O Command Set
 * specified in the @csi argument.
 *
 * See &struct nvme_ns_list for the definition of the returned structure.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
static inline int nvme_identify_allocated_ns_list_csi(int fd, __u32 nsid,
			enum nvme_csi csi, struct nvme_ns_list *list)
{
	struct nvme_identify_args args = {
		.result = NULL,
		.data = list,
		.args_size = sizeof(args),
		.fd = fd,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.cns = NVME_IDENTIFY_CNS_ALLOCATED_NS_LIST,
		.csi = csi,
		.nsid = nsid,
		.cntid = NVME_CNTLID_NONE,
		.nvmsetid = NVME_NVMSETID_NONE,
		.domid = NVME_DOMID_NONE,
		.uuidx = NVME_UUID_NONE,
	};

	return nvme_identify(&args);
}

/**
 * nvme_identify_independent_identify_ns() -
 * @fd:		File descriptor of nvme device
 * @nsid:	Return namespaces greater than this identifier
 * @ns:		I/O Command Set Independent Identify Namespace data
 *		structure
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
static inline int nvme_identify_independent_identify_ns(int fd, __u32 nsid,
			struct nvme_id_independent_id_ns *ns)
{
	struct nvme_identify_args args = {
		.result = NULL,
		.data = ns,
		.args_size = sizeof(args),
		.fd = fd,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.cns = NVME_IDENTIFY_CNS_CSI_INDEPENDENT_ID_NS,
		.csi = NVME_CSI_NVM,
		.nsid = nsid,
		.cntid = NVME_CNTLID_NONE,
		.nvmsetid = NVME_NVMSETID_NONE,
		.domid = NVME_DOMID_NONE,
		.uuidx = NVME_UUID_NONE,
	};

	return nvme_identify(&args);
}

/**
 * nvme_identify_ctrl_nvm() -
 * @fd:	File descriptor of nvme device
 * @id:	User space destination address to transfer the data
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
static inline int nvme_nvm_identify_ctrl(int fd, struct nvme_id_ctrl_nvm *id)
{
	return nvme_identify_ctrl_csi(fd, NVME_CSI_NVM, id);
}

/**
 * nvme_idnetifY_domain_list() -
 * @fd:		File descriptor of nvme device
 * @domid:	Domain ID
 * @list:	User space destiantion address to transfer data
 *
 * A list of 31 domain IDs is returned to the host containing domain
 * attributes in increasing order that are greater than the value
 * specified in the @domid field.
 *
 * See @struct nvme_identify_domain_attr for the definition of the
 * returned structure.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
static inline int nvme_identify_domain_list(int fd, __u16 domid,
			struct nvme_id_domain_list *list)
{
	struct nvme_identify_args args = {
		.result = NULL,
		.data = list,
		.args_size = sizeof(args),
		.fd = fd,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.cns = NVME_IDENTIFY_CNS_DOMAIN_LIST,
		.csi = NVME_CSI_NVM,
		.nsid = NVME_NSID_NONE,
		.cntid = NVME_CNTLID_NONE,
		.nvmsetid = NVME_NVMSETID_NONE,
		.domid = domid,
		.uuidx = NVME_UUID_NONE,
	};

	return nvme_identify(&args);
}

/**
 * nvme_identifiy_endurance_group_list() -
 * @fd:		File descriptor of nvme device
 * @endgrp_id:	Endurance group identifier
 * @list:	Array of endurance group identifiers
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
static inline int nvme_identify_endurance_group_list(int fd, __u16 endgrp_id,
			struct nvme_id_endurance_group_list *list)
{
	struct nvme_identify_args args = {
		.result = NULL,
		.data = list,
		.args_size = sizeof(args),
		.fd = fd,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.cns = NVME_IDENTIFY_CNS_ENDURANCE_GROUP_ID,
		.csi = NVME_CSI_NVM,
		.nsid = NVME_NSID_NONE,
		.cntid = NVME_CNTLID_NONE,
		.nvmsetid = NVME_NVMSETID_NONE,
		.domid = endgrp_id,
		.uuidx = NVME_UUID_NONE,
	};

	return nvme_identify(&args);
}

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
static inline int nvme_identify_iocs(int fd, __u16 cntlid,
			struct nvme_id_iocs *iocs)
{
	struct nvme_identify_args args = {
		.result = NULL,
		.data = iocs,
		.args_size = sizeof(args),
		.fd = fd,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.cns = NVME_IDENTIFY_CNS_COMMAND_SET_STRUCTURE,
		.csi = NVME_CSI_NVM,
		.nsid = NVME_NSID_NONE,
		.cntid = cntlid,
		.nvmsetid = NVME_NVMSETID_NONE,
		.domid = NVME_DOMID_NONE,
		.uuidx = NVME_UUID_NONE,
	};

	return nvme_identify(&args);
}

/**
 * nvme_zns_identify_ns() -
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace to identify
 * @data:	User space destination address to transfer the data
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
static inline int nvme_zns_identify_ns(int fd, __u32 nsid,
			struct nvme_zns_id_ns *data)
{
	struct nvme_identify_args args = {
		.result = NULL,
		.data = data,
		.args_size = sizeof(args),
		.fd = fd,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.cns = NVME_IDENTIFY_CNS_CSI_NS,
		.csi = NVME_CSI_ZNS,
		.nsid = nsid,
		.cntid = NVME_CNTLID_NONE,
		.nvmsetid = NVME_NVMSETID_NONE,
		.domid = NVME_DOMID_NONE,
	};

	return nvme_identify(&args);
}

/**
 * nvme_zns_identify_ctrl() -
 * @fd:	File descriptor of nvme device
 * @id:	User space destination address to transfer the data
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
static inline int nvme_zns_identify_ctrl(int fd, struct nvme_zns_id_ctrl *id)
{
	return nvme_identify_ctrl_csi(fd, NVME_CSI_ZNS, id);
}

/**
 * nvme_get_log_args - Arguments for the NVMe Admin Get Log command
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
 * @lsi:	Endurance group information
 * @domid:	Domain Identifier selection, if supported
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
	__u16 domid;
	__u8 lsp;
	__u8 uuidx;
	bool rae;
	bool ot;
} __attribute__((packed, aligned(__alignof__(__u64))));

/**
 * nvme_get_log() - NVMe Admin Get Log command
 * @args:	&struct nvme_get_log_args argument structure
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_log(struct nvme_get_log_args *args);

static inline int nvme_get_nsid_log(int fd, bool rae,
			enum nvme_cmd_get_log_lid lid,
			__u32 nsid, __u32 len, void *log)
{
	struct nvme_get_log_args args = {
		.lpo = 0,
		.result = NULL,
		.log = log,
		.args_size = sizeof(args),
		.fd = fd,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.lid = lid,
		.len = len,
		.nsid = nsid,
		.csi = NVME_CSI_NVM,
		.lsi = NVME_LOG_LSI_NONE,
		.domid = NVME_DOMID_NONE,
		.lsp = NVME_LOG_LSP_NONE,
		.uuidx = NVME_UUID_NONE,
		.rae = false,
		.ot = false,
	};

	return nvme_get_log(&args);
}

static inline int nvme_get_log_simple(int fd, enum nvme_cmd_get_log_lid lid,
				      __u32 len, void *log)
{
	return nvme_get_nsid_log(fd, false, lid, NVME_NSID_ALL, len, log);
}

/** nvme_get_log_supported_log_pages() - Retrieve nmve supported log pages
 * @fd:		File descriptor of nvme device
 * @rae:	Retain asynchronous events
 * @log:	Array of LID supported and Effects data structures
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
static inline int nvme_get_log_supported_log_pages(int fd, bool rae,
			struct nvme_supported_log_pages *log)
{
	return nvme_get_nsid_log(fd, rae, NVME_LOG_LID_SUPPORTED_LOG_PAGES,
				 NVME_NSID_ALL, sizeof(*log), log);
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
static inline int nvme_get_log_error(int fd, unsigned nr_entries, bool rae,
		       struct nvme_error_log_page *log)
{
	return nvme_get_nsid_log(fd, rae, NVME_LOG_LID_ERROR,
				 NVME_NSID_ALL, sizeof(*log) * nr_entries, log);
}

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
static inline int nvme_get_log_smart(int fd, __u32 nsid, bool rae,
				     struct nvme_smart_log *log)
{
	return nvme_get_nsid_log(fd, rae, NVME_LOG_LID_SMART,
				 nsid, sizeof(*log), log);
}

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
static inline int nvme_get_log_fw_slot(int fd, bool rae,
			struct nvme_firmware_slot *log)
{
	return nvme_get_nsid_log(fd, rae, NVME_LOG_LID_SMART,
				 NVME_NSID_ALL, sizeof(*log), log);
}

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
static inline int nvme_get_log_changed_ns_list(int fd, bool rae,
			struct nvme_ns_list *log)
{
	return nvme_get_nsid_log(fd, rae, NVME_LOG_LID_CHANGED_NS,
				 NVME_NSID_ALL, sizeof(*log), log);
}

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
static inline int nvme_get_log_cmd_effects(int fd, enum nvme_csi csi,
					   struct nvme_cmd_effects_log *log)
{
	struct nvme_get_log_args args = {
		.lpo = 0,
		.result = NULL,
		.log = log,
		.args_size = sizeof(args),
		.fd = fd,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.lid = NVME_LOG_LID_CMD_EFFECTS,
		.len = sizeof(*log),
		.nsid = NVME_NSID_ALL,
		.csi = csi,
		.lsi = NVME_LOG_LSI_NONE,
		.domid = NVME_DOMID_NONE,
		.lsp = NVME_LOG_LSP_NONE,
		.uuidx = NVME_UUID_NONE,
		.rae = false,
		.ot = false,
	};
	return nvme_get_log(&args);
}

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
static inline int nvme_get_log_device_self_test(int fd,
			struct nvme_self_test_log *log)
{
	return nvme_get_nsid_log(fd, false, NVME_LOG_LID_DEVICE_SELF_TEST,
				 NVME_NSID_ALL, sizeof(*log), log);
}

/**
 * nvme_get_log_create_telemetry_host() -
 */
static inline int nvme_get_log_create_telemetry_host(int fd,
			struct nvme_telemetry_log *log)
{
	struct nvme_get_log_args args = {
		.lpo = 0,
		.result = NULL,
		.log = log,
		.args_size = sizeof(args),
		.fd = fd,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.lid = NVME_LOG_LID_TELEMETRY_HOST,
		.len = sizeof(*log),
		.nsid = NVME_NSID_NONE,
		.csi = NVME_CSI_NVM,
		.lsi = NVME_LOG_LSI_NONE,
		.domid = NVME_DOMID_NONE,
		.lsp = NVME_LOG_TELEM_HOST_LSP_CREATE,
		.uuidx = NVME_UUID_NONE,
		.rae = false,
		.ot = false,
	};
	return nvme_get_log(&args);
}

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
static inline int nvme_get_log_telemetry_host(int fd, __u64 offset,
			__u32 len, void *log)
{
	struct nvme_get_log_args args = {
		.lpo = 0,
		.result = NULL,
		.log = log,
		.args_size = sizeof(args),
		.fd = fd,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.lid = NVME_LOG_LID_TELEMETRY_HOST,
		.len = len,
		.nsid = NVME_NSID_NONE,
		.csi = NVME_CSI_NVM,
		.lsi = NVME_LOG_LSI_NONE,
		.domid = NVME_DOMID_NONE,
		.lsp = NVME_LOG_TELEM_HOST_LSP_RETAIN,
		.uuidx = NVME_UUID_NONE,
		.rae = false,
		.ot = false,
	};
	return nvme_get_log(&args);
}

/**
 * nvme_get_log_telemetry_ctrl() -
 * @fd:		File descriptor of nvme device
 * @rae:	Retain asynchronous events
 * @offset:	Offset into the telemetry data
 * @len:	Length of provided user buffer to hold the log data in bytes
 * @log:	User address for log page data
 */
static inline int nvme_get_log_telemetry_ctrl(int fd, bool rae,
			__u64 offset, __u32 len, void *log)
{
	struct nvme_get_log_args args = {
		.lpo = offset,
		.result = NULL,
		.log = log,
		.args_size = sizeof(args),
		.fd = fd,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.lid = NVME_LOG_LID_TELEMETRY_CTRL,
		.len = len,
		.nsid = NVME_NSID_NONE,
		.csi = NVME_CSI_NVM,
		.lsi = NVME_LOG_LSI_NONE,
		.domid = NVME_DOMID_NONE,
		.lsp = NVME_LOG_LSP_NONE,
		.uuidx = NVME_UUID_NONE,
		.rae = rae,
		.ot = false,
	};
	return nvme_get_log(&args);
}

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
static inline int nvme_get_log_endurance_group(int fd, __u16 endgid,
			struct nvme_endurance_group_log *log)
{
	struct nvme_get_log_args args = {
		.lpo = 0,
		.result = NULL,
		.log = log,
		.args_size = sizeof(args),
		.fd = fd,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.lid = NVME_LOG_LID_ENDURANCE_GROUP,
		.len = sizeof(*log),
		.nsid = NVME_NSID_NONE,
		.csi = NVME_CSI_NVM,
		.lsi = endgid,
		.domid = NVME_DOMID_NONE,
		.lsp = NVME_LOG_LSP_NONE,
		.uuidx = NVME_UUID_NONE,
		.rae = false,
		.ot = false,
	};
	return nvme_get_log(&args);
}

/**
 * nvme_get_log_predictable_lat_nvmset() -
 * @fd:
 * @nvmsetid:
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
static inline int nvme_get_log_predictable_lat_nvmset(int fd, __u16 nvmsetid,
			struct nvme_nvmset_predictable_lat_log *log)
{
	struct nvme_get_log_args args = {
		.lpo = 0,
		.result = NULL,
		.log = log,
		.args_size = sizeof(args),
		.fd = fd,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.lid = NVME_LOG_LID_PREDICTABLE_LAT_NVMSET,
		.len = sizeof(*log),
		.nsid = NVME_NSID_NONE,
		.csi = NVME_CSI_NVM,
		.lsi = nvmsetid,
		.domid = NVME_DOMID_NONE,
		.lsp = NVME_LOG_LSP_NONE,
		.uuidx = NVME_UUID_NONE,
		.rae = false,
		.ot = false,
	};
	return nvme_get_log(&args);
}

/**
 * nvme_get_log_predictable_lat_event() -
 * @fd:		File descriptor of nvme device
 * @rae:	Retain asynchronous events
 */
static inline int nvme_get_log_predictable_lat_event(int fd, bool rae,
			__u32 offset, __u32 len, void *log)
{
	struct nvme_get_log_args args = {
		.lpo = offset,
		.result = NULL,
		.log = log,
		.args_size = sizeof(args),
		.fd = fd,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.lid = NVME_LOG_LID_PREDICTABLE_LAT_AGG,
		.len = len,
		.nsid = NVME_NSID_NONE,
		.csi = NVME_CSI_NVM,
		.lsi = NVME_LOG_LSI_NONE,
		.domid = NVME_DOMID_NONE,
		.lsp = NVME_LOG_LSP_NONE,
		.uuidx = NVME_UUID_NONE,
		.rae = rae,
		.ot = false,
	};
	return nvme_get_log(&args);
}

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
static int nvme_get_log_ana(int fd, enum nvme_log_ana_lsp lsp, bool rae,
			__u64 offset, __u32 len, void *log)
{
	struct nvme_get_log_args args = {
		.lpo = offset,
		.result = NULL,
		.log = log,
		.args_size = sizeof(args),
		.fd = fd,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.lid = NVME_LOG_LID_ANA,
		.len = len,
		.nsid = NVME_NSID_NONE,
		.csi = NVME_CSI_NVM,
		.lsi = NVME_LOG_LSI_NONE,
		.domid = NVME_DOMID_NONE,
		.lsp = lsp,
		.uuidx = NVME_UUID_NONE,
		.rae = false,
		.ot = false,
	};
	return nvme_get_log(&args);
}

/**
 * nvme_get_log_ana_groups() -
 * @fd:		File descriptor of nvme device
 * @rae:	Retain asynchronous events
 *
 * See &struct nvme_ana_group_desc for the defintion of the returned structure.
 */
static inline int nvme_get_log_ana_groups(int fd, bool rae, __u32 len,
			    struct nvme_ana_group_desc *log)
{
	return nvme_get_log_ana(fd, NVME_LOG_ANA_LSP_RGO_GROUPS_ONLY, rae, 0,
				len, log);
}

/**
 * nvme_get_log_lba_status() -
 * @fd:		File descriptor of nvme device
 * @rae:	Retain asynchronous events
 */
static inline int nvme_get_log_lba_status(int fd, bool rae,
			__u64 offset, __u32 len, void *log)
{
	struct nvme_get_log_args args = {
		.lpo = offset,
		.result = NULL,
		.log = log,
		.args_size = sizeof(args),
		.fd = fd,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.lid = NVME_LOG_LID_LBA_STATUS,
		.len = len,
		.nsid = NVME_NSID_NONE,
		.csi = NVME_CSI_NVM,
		.lsi = NVME_LOG_LSI_NONE,
		.domid = NVME_DOMID_NONE,
		.lsp = NVME_LOG_LSP_NONE,
		.uuidx = NVME_UUID_NONE,
		.rae = rae,
		.ot = false,
	};
	return nvme_get_log(&args);
}

/**
 * nvme_get_log_endurance_grp_evt() -
 * @fd:		File descriptor of nvme device
 * @rae:	Retain asynchronous events
 */
static inline int nvme_get_log_endurance_grp_evt(int fd, bool rae,
			__u32 offset, __u32 len, void *log)
{
	struct nvme_get_log_args args = {
		.lpo = offset,
		.result = NULL,
		.log = log,
		.args_size = sizeof(args),
		.fd = fd,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.lid = NVME_LOG_LID_ENDURANCE_GRP_EVT,
		.len = len,
		.nsid = NVME_NSID_NONE,
		.csi = NVME_CSI_NVM,
		.lsi = NVME_LOG_LSI_NONE,
		.domid = NVME_DOMID_NONE,
		.lsp = NVME_LOG_LSP_NONE,
		.uuidx = NVME_UUID_NONE,
		.rae = rae,
		.ot = false,
	};
	return nvme_get_log(&args);
}

/**
 * nvme_get_log_fid_supported_effects() -
 * @fd:		File descriptor of nvme device
 * @rae:	Retain asynchronous events
 * @log:	FID Supported and Effects data structure
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise
 */
static inline int nvme_get_log_fid_supported_effects(int fd, bool rae,
			struct nvme_fid_supported_effects_log *log)
{
	return nvme_get_nsid_log(fd, rae, NVME_LOG_LID_FID_SUPPORTED_EFFECTS,
				 NVME_NSID_NONE, sizeof(*log), log);
}

/**
 * nvme_get_log_boot_partition() -
 * @fd:		File descriptor of nvme device
 * @rae:	Retain asynchronous events
 * @lsp:	The log specified field of LID
 * @len:	The allocated size, minimum
 *		struct nvme_boot_partition
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise
 */
static inline int nvme_get_log_boot_partition(int fd, bool rae,
			__u8 lsp, __u32 len, struct nvme_boot_partition *part)
{
	struct nvme_get_log_args args = {
		.lpo = 0,
		.result = NULL,
		.log = part,
		.args_size = sizeof(args),
		.fd = fd,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.lid = NVME_LOG_LID_BOOT_PARTITION,
		.len = len,
		.nsid = NVME_NSID_NONE,
		.csi = NVME_CSI_NVM,
		.lsi = NVME_LOG_LSI_NONE,
		.domid = NVME_DOMID_NONE,
		.lsp = NVME_LOG_LSP_NONE,
		.uuidx = NVME_UUID_NONE,
		.rae = rae,
		.ot = false,
	};
	return nvme_get_log(&args);
}

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
static inline int nvme_get_log_discovery(int fd, bool rae,
			__u32 offset, __u32 len, void *log)
{
	struct nvme_get_log_args args = {
		.lpo = offset,
		.result = NULL,
		.log = log,
		.args_size = sizeof(args),
		.fd = fd,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.lid = NVME_LOG_LID_DISCOVER,
		.len = len,
		.nsid = NVME_NSID_NONE,
		.csi = NVME_CSI_NVM,
		.lsi = NVME_LOG_LSI_NONE,
		.domid = NVME_DOMID_NONE,
		.lsp = NVME_LOG_LSP_NONE,
		.uuidx = NVME_UUID_NONE,
		.rae = rae,
		.ot = false,
	};
	return nvme_get_log(&args);
}

/**
 * nvme_get_log_media_unit_stat() -
 * @fd:		File descriptor of nvme device
 * @domid:	Domain Identifier selection, if supported
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise
 */
static inline int nvme_get_log_media_unit_stat(int fd, __u16 domid,
			struct nvme_media_unit_stat_log *mus)
{
	struct nvme_get_log_args args = {
		.lpo = 0,
		.result = NULL,
		.log = mus,
		.args_size = sizeof(args),
		.fd = fd,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.lid = NVME_LOG_LID_MEDIA_UNIT_STATUS,
		.len = sizeof(*mus),
		.nsid = NVME_NSID_NONE,
		.csi = NVME_CSI_NVM,
		.lsi = NVME_LOG_LSI_NONE,
		.domid = domid,
		.lsp = NVME_LOG_LSP_NONE,
		.uuidx = NVME_UUID_NONE,
		.rae = false,
		.ot = false,
	};
	return nvme_get_log(&args);
}

/**
 * nvme_get_log_reservation() -
 * @fd:		File descriptor of nvme device
 * @rae:	Retain asynchronous events
 */
static inline int nvme_get_log_reservation(int fd, bool rae,
			struct nvme_resv_notification_log *log)
{
	return nvme_get_nsid_log(fd, rae, NVME_LOG_LID_RESERVATION,
				 NVME_NSID_ALL, sizeof(*log), log);
}

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
static inline int nvme_get_log_sanitize(int fd, bool rae,
			struct nvme_sanitize_log_page *log)
{
	return nvme_get_nsid_log(fd, rae, NVME_LOG_LID_SANITIZE,
				 NVME_NSID_ALL, sizeof(*log), log);
}

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
static inline int nvme_get_log_zns_changed_zones(int fd, __u32 nsid, bool rae,
			struct nvme_zns_changed_zone_log *log)
{
	struct nvme_get_log_args args = {
		.lpo = 0,
		.result = NULL,
		.log = log,
		.args_size = sizeof(args),
		.fd = fd,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.lid = NVME_LOG_LID_ZNS_CHANGED_ZONES,
		.len = sizeof(*log),
		.nsid = nsid,
		.csi = NVME_CSI_ZNS,
		.lsi = NVME_LOG_LSI_NONE,
		.domid = NVME_DOMID_NONE,
		.lsp = NVME_LOG_LSP_NONE,
		.uuidx = NVME_UUID_NONE,
		.rae = rae,
		.ot = false,
	};
	return nvme_get_log(&args);
}

/**
 * nvme_get_log_persistent_event() -
 * @fd:		File descriptor of nvme device
 * @action:	Action the controller should take during processing this command
 * @size:	Size of @pevent_log
 * @pevent_log:	User address to store the persistent event log
 */
static inline int nvme_get_log_persistent_event(int fd,
			enum nvme_pevent_log_action action,
			__u32 size, void *pevent_log)
{
	struct nvme_get_log_args args = {
		.lpo = 0,
		.result = NULL,
		.log = pevent_log,
		.args_size = sizeof(args),
		.fd = fd,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.lid = NVME_LOG_LID_PERSISTENT_EVENT,
		.len = size,
		.nsid = NVME_NSID_ALL,
		.csi = NVME_CSI_NVM,
		.lsi = NVME_LOG_LSI_NONE,
		.domid = NVME_DOMID_NONE,
		.lsp = NVME_LOG_LSP_NONE,
		.uuidx = NVME_UUID_NONE,
		.rae = false,
		.ot = false,
	};
	return nvme_get_log(&args);
}

/**
 * nvme_set_features_args - Arguments for the NVMe Admin Set Feature command
 * @result:	The command completion result from CQE dword0
 * @data:	User address of feature data, if applicable
 * @fd:		File descriptor of nvme device
 * @timeout:	Timeout in ms
 * @nsid:	Namespace ID, if applicable
 * @cdw11:	Value to set the feature to
 * @cdw12:	Feature specific command dword12 field
 * @cdw14:	Feature specific command dword15 field
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
	__u32 cdw15;
	__u32 data_len;
	bool save;
	__u8 uuidx;
	__u8 fid;
} __attribute__((packed, aligned(__alignof__(__u32*))));

/**
 * nvme_set_features_args() - Set a feature attribute
 * @args:	&struct nvme_set_features_args argument structure
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_features(struct nvme_set_features_args *args);

static inline int nvme_set_features_data(int fd, __u8 fid, __u32 nsid,
			__u32 cdw11, bool save, __u32 data_len, void *data,
			__u32 *result)
{
	struct nvme_set_features_args args = {
		.result = result,
		.data = data,
		.args_size = sizeof(args),
		.fd = fd,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.nsid = nsid,
		.cdw11 = cdw11,
		.cdw12 = 0,
		.cdw15 = 0,
		.data_len = data_len,
		.save = save,
		.uuidx = 0,
		.fid = fid,
	};
	return nvme_set_features(&args);
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
 * nvme_get_features_args - Arguments for the NVMe Admin Get Feature command
 * @fd:		File descriptor of nvme device
 * @result:	The command completion result from CQE dword0
 * @timeout:	Timeout in ms
 * @nsid:	Namespace ID, if applicable
 * @sel:	Select which type of attribute to return,
 * 		see &enum nvme_get_features_sel
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
} __attribute__((packed, aligned(__alignof__(__u32*))));

/**
 * nvme_get_features() - Retrieve a feature attribute
 * @args:	&struct nvme_get_features_args argument structure
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_features(struct nvme_get_features_args *args);

static inline int nvme_get_features_data(int fd, enum nvme_features_id fid,
			__u32 nsid, __u32 data_len, void *data, __u32 *result)
{
	struct nvme_get_features_args args = {
		.result = result,
		.data = data,
		.args_size = sizeof(args),
		.fd = fd,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.nsid = nsid,
		.sel = NVME_GET_FEATURES_SEL_CURRENT,
		.cdw11 = 0,
		.data_len = data_len,
		.fid = fid,
		.uuidx = NVME_UUID_NONE,
	};

	return nvme_get_features(&args);
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
 * nvme_format_nvm_args - Arguments for the Format Nvme Namespace command
 * @result:	The command completion result from CQE dword0
 * @fd:		File descriptor of nvme device
 * @timeout:	Set to override default timeout to this value in milliseconds;
 *		useful for long running formats. 0 will use system default.
 * @nsid:	Namespace ID to format
 * @mset:	Metadata settings (extended or separated), true if extended
 * @pi:		Protection information type
 * @pil:	Protection information location (beginning or end), true if end
 * @ses:	Secure erase settings
 * @lbaf:	Logical block address format
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
} __attribute__((packed, aligned(__alignof__(__u32*))));

/**
 * nvme_format_nvm() - Format nvme namespace(s)
 * @args:	&struct nvme_format_nvme_args argument structure
 *
 * The Format NVM command low level formats the NVM media. This command is used
 * by the host to change the LBA data size and/or metadata size. A low level
 * format may destroy all data and metadata associated with all namespaces or
 * only the specific namespace associated with the command
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_format_nvm(struct nvme_format_nvm_args *args);

/**
 * nvme_ns_mgmt_args - Arguments for NVMe Namespace Management command
 * @result:	NVMe command result
 * @ns:		Namespace identication descriptors
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
} __attribute__((packed, aligned(__alignof__(__u32*))));

/**
 * nvme_ns_mgmt() -
 * @args:	&struct nvme_ns_mgmt_args Argument structure
 */
int nvme_ns_mgmt(struct nvme_ns_mgmt_args *args);

/**
 * nvme_ns_mgmt_create() -
 * @fd:		File descriptor of nvme device
 * @ns:		Namespace identification that defines ns creation parameters
 * @nsid:		On success, set to the namespace id that was created
 * @timeout:		Overide the default timeout to this value in milliseconds;
 * 			set to 0 to use the system default.
 * @csi:		Command Set Identifier
 *
 * On successful creation, the namespace exists in the subsystem, but is not
 * attached to any controller. Use the &nvme_ns_attach_ctrls() to assign the
 * namespace to one or more controllers.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
static inline int nvme_ns_mgmt_create(int fd, struct nvme_id_ns *ns,
			__u32 *nsid, __u32 timeout, __u8 csi)
{
	struct nvme_ns_mgmt_args args = {
		.result = nsid,
		.ns = ns,
		.args_size = sizeof(args),
		.fd = fd,
		.timeout = timeout,
		.nsid = NVME_NSID_NONE,
		.sel = NVME_NS_MGMT_SEL_CREATE,
		.csi = csi,
	};

	return nvme_ns_mgmt(&args);
}

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
static inline int nvme_ns_mgmt_delete(int fd, __u32 nsid)
{
	struct nvme_ns_mgmt_args args = {
		.result = NULL,
		.ns = NULL,
		.args_size = sizeof(args),
		.fd = fd,
		.timeout = 0,
		.nsid = nsid,
		.sel = NVME_NS_MGMT_SEL_DELETE,
		.csi = 0,
	};

	return nvme_ns_mgmt(&args);
}

/**
 * nvme_ns_attach_args - Arguments for Nvme Namespace Management command
 * @result:	NVMe command result
 * @ctrlist:	Controller list to modify attachment state of nsid
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
} __attribute__((packed, aligned(__alignof__(__u32*))));

/**
 * nvme_ns_attach_args - Attach or detach namespace to controller(s)
 * @args:	&struct nvme_ns_attach_args Argument structure
 */
int nvme_ns_attach(struct nvme_ns_attach_args *args);

/**
 * nvme_ns_attach_ctrls() -
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace ID to attach
 * @ctrlist:	Controller list to modify attachment state of nsid
 */
static inline int nvme_ns_attach_ctrls(int fd, __u32 nsid,
			struct nvme_ctrl_list *ctrlist)
{
	struct nvme_ns_attach_args args = {
		.result = NULL,
		.ctrlist = ctrlist,
		.args_size = sizeof(args),
		.fd = fd,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.nsid = nsid,
		.sel = NVME_NS_ATTACH_SEL_CTRL_ATTACH,
	};

	return nvme_ns_attach(&args);
}

/**
 * nvme_ns_detach_ctrls() -
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace ID to detach
 * @ctrlist:	Controller list to modify attachment state of nsid
 */
static inline int nvme_ns_detach_ctrls(int fd, __u32 nsid,
			struct nvme_ctrl_list *ctrlist)
{
	struct nvme_ns_attach_args args = {
		.result = NULL,
		.ctrlist = ctrlist,
		.args_size = sizeof(args),
		.fd = fd,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.nsid = nsid,
		.sel = NVME_NS_ATTACH_SEL_CTRL_DEATTACH,
	};

	return nvme_ns_attach(&args);
}

/**
 * nvme_fw_download_args - Arguments for the NVMe Firmware Download command
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
} __attribute__((packed, aligned(__alignof__(__u32*))));

/**
 * nvme_fw_download() - Download part or all of a firmware image to the
 * 			controller
 * @args:	&struct nvme_fw_download_args argument structure
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
int nvme_fw_download(struct nvme_fw_download_args *args);

/**
 * nvme_fw_commit_args - Arguments for the NVMe Firmware Commit command
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
} __attribute__((packed, aligned(__alignof__(__u32*))));

/**
 * nvme_fw_commit() - Commit firmware using the specified action
 * @args:	&struct nvme_fw_commit_args argument structure
 *
 * The Firmware Commit command modifies the firmware image or Boot Partitions.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise. The command
 * status response may specify additional reset actions required to complete
 * the commit process.
 */
int nvme_fw_commit(struct nvme_fw_commit_args *args);

/**
 * nvme_security_send_args - Arguments for the NVMe Security Send command
 * @result:	The command completion result from CQE dword0
 * @data:	Security data payload to send
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
} __attribute__((packed, aligned(__alignof__(__u32*))));

/**
 * nvme_security_send() -
 * @args:	&struct nvme_security_send argument structure
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
int nvme_security_send(struct nvme_security_send_args *args);

/**
 * nvme_security_receive_args - Arguments for the NVMe Security Receive command
 * @result:	The command completion result from CQE dword0
 * @data:	Security data payload to send
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
} __attribute__((packed, aligned(__alignof__(__u32*))));

/**
 * nvme_security_receive() -
 * @args:	&struct nvme_security_recevice argument structure
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_security_receive(struct nvme_security_receive_args *args);

/**
 * nvme_get_lba_status_args - Arguments for the NVMe Get LBA Status command
 * @lbas:	Data payload to return status descriptors
 * @result:	The command completion result from CQE dword0
 * @slba:	Starting logical block address to check statuses
 * @fd:		File descriptor of nvme device
 * @timeout:	Timeout in ms
 * @nsid:	Namespace ID to retrieve LBA status
 * @mndw:	Maximum number of dwords to return
 * @atype:	Action type mechanism to determine LBA status desctriptors to
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
} __attribute__((packed, aligned(__alignof__(__u64))));

/**
 * nvme_get_lba_status() - Retrieve information on possibly unrecoverable LBAs
 * @args:	&struct nvme_get_lba_status_args argument structure
 *
 * The Get LBA Status command requests information about Potentially
 * Unrecoverable LBAs. Refer to the specification for action type descriptions.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_lba_status(struct nvme_get_lba_status_args *args);

/**
 * nvme_directive_send_args - Arguments for the NVMe Directive Send command
 * @result:	If successful, the CQE dword0 value
 * @data:	Data payload to to be send
 * @fd:		File descriptor of nvme device
 * @timeout:	Timeout in ms
 * @nsid:	Namespace ID, if applicable
 * @doper:	Directive send operation, see &enum nvme_directive_send_doper
 * @dtype:	Directive type, see &enum nvme_directive_dtype
 * @dw12:	Directive specific command dword12
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
} __attribute__((packed, aligned(__alignof__(__u32*))));

/**
 * nvme_directive_send() - Send directive command
 * @args:	&struct nvme_directive_send_args argument structure
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
int nvme_directive_send(struct nvme_directive_send_args *args);

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
static inline int nvme_directive_send_stream_release_identifier(int fd,
			__u32 nsid, __u16 stream_id)
{
	struct nvme_directive_send_args args = {
		.result = NULL,
		.data = NULL,
		.args_size = sizeof(args),
		.fd = fd,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.nsid = nsid,
		.doper = NVME_DIRECTIVE_SEND_STREAMS_DOPER_RELEASE_IDENTIFIER,
		.dtype = NVME_DIRECTIVE_DTYPE_STREAMS,
		.cdw12 = 0,
		.data_len = 0,
		.dspec = stream_id,
	};

	return nvme_directive_send(&args);
}

/**
 * nvme_directive_send_stream_release_resource() -
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace ID
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
static inline int nvme_directive_send_stream_release_resource(int fd, __u32 nsid)
{
	struct nvme_directive_send_args args = {
		.result = NULL,
		.data = NULL,
		.args_size = sizeof(args),
		.fd = fd,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.nsid = nsid,
		.doper = NVME_DIRECTIVE_SEND_STREAMS_DOPER_RELEASE_RESOURCE,
		.dtype = NVME_DIRECTIVE_DTYPE_STREAMS,
		.cdw12 = 0,
		.data_len = 0,
		.dspec = 0,
	};

	return nvme_directive_send(&args);
}

/**
 * nvme_directive_recv_args - Arguments for the NVMe Directive Receive command
 * @result:	If successful, the CQE dword0 value
 * @data:	Usespace address of data payload
 * @fd:		File descriptor of nvme device
 * @timeout:	Timeout in ms
 * @nsid:	Namespace ID, if applicable
 * @doper:	Directive send operation, see &enum nvme_directive_send_doper
 * @dtype:	Directive type, see &enum nvme_directive_dtype
 * @dw12:	Directive specific command dword12
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
} __attribute__((packed, aligned(__alignof__(__u32*))));

/**
 * nvme_directive_recv() - Receive directive specific data
 * @args:	&struct nvme_directive_recv_args argument structure
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_directive_recv(struct nvme_directive_recv_args *args);

/**
 * nvme_directive_recv_identify_parameters() -
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace ID
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
static inline int nvme_directive_recv_identify_parameters(int fd, __u32 nsid,
			struct nvme_id_directives *id)
{
	struct nvme_directive_recv_args args = {
		.result = NULL,
		.data = id,
		.args_size = sizeof(args),
		.fd = fd,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.nsid = nsid,
		.doper = NVME_DIRECTIVE_RECEIVE_IDENTIFY_DOPER_PARAM,
		.dtype = NVME_DIRECTIVE_DTYPE_IDENTIFY,
		.cdw12 = 0,
		.data_len = sizeof(*id),
		.dspec = 0,
	};

	return nvme_directive_recv(&args);
}

/**
 * nvme_directive_recv_stream_parameters() -
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace ID
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
static inline int nvme_directive_recv_stream_parameters(int fd, __u32 nsid,
			struct nvme_streams_directive_params *parms)
{
	struct nvme_directive_recv_args args = {
		.result = NULL,
		.data = parms,
		.args_size = sizeof(args),
		.fd = fd,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.nsid = nsid,
		.doper = NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_PARAM,
		.dtype = NVME_DIRECTIVE_DTYPE_STREAMS,
		.cdw12 = 0,
		.data_len = sizeof(*parms),
		.dspec = 0,
	};

	return nvme_directive_recv(&args);
}

/**
 * nvme_directive_recv_stream_status() -
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace ID
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
static inline int nvme_directive_recv_stream_status(int fd, __u32 nsid,
			unsigned nr_entries,
			struct nvme_streams_directive_status *id)
{
	struct nvme_directive_recv_args args = {
		.result = NULL,
		.data = id,
		.args_size = sizeof(args),
		.fd = fd,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.nsid = nsid,
		.doper = NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_STATUS,
		.dtype = NVME_DIRECTIVE_DTYPE_STREAMS,
		.cdw12 = 0,
		.data_len = sizeof(*id),
		.dspec = 0,
	};

	return nvme_directive_recv(&args);
}

/**
 * nvme_directive_recv_stream_allocate() -
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace ID
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
static inline int nvme_directive_recv_stream_allocate(int fd, __u32 nsid,
			__u16 nsr, __u32 *result)
{
	struct nvme_directive_recv_args args = {
		.result = result,
		.data = NULL,
		.args_size = sizeof(args),
		.fd = fd,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.nsid = nsid,
		.doper = NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_RESOURCE,
		.dtype = NVME_DIRECTIVE_DTYPE_STREAMS,
		.cdw12 = nsr,
		.data_len = 0,
		.dspec = 0,
	};

	return nvme_directive_recv(&args);
}

/**
 * nvme_capacity_mgmt_args - Arguments for the NVMe Capacity Management command
 * @result:	If successful, the CQE dword0 value
 * @fd:		File descriptor of nvme device
 * @dw11:	Least significant 32 bits of the capacity in bytes of the
 *		Endurance Group or NVM Set to be created
 * @dw12:	Most significant 32 bits of the capacity in bytes of the
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
} __attribute__((packed, aligned(__alignof__(__u32*))));

/**
 * nvme_capacity_mgmt() -
 * @args:	&struct nvme_capacity_mgmt_args argument structure
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_capacity_mgmt(struct nvme_capacity_mgmt_args *args);

/**
 * nvme_lockdown_args - Arguments for the NVME Lockdown command
 * @fd:		File descriptor of nvme device
 * @result:	The command completion result from CQE dword0
 * @timeout:	Timeout in ms (0 for default timeout)
 * @scp:	Scope of the command
 * @prhbt:	Prohibit or allow the command opcode or Set Features command
 * @ifc:	Affected interface
 * @ofi:	Opcode or Feature Identifier
 * @uuid:	UUID Index if controller supports this id selection method
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
} __attribute__((__packed__));

/**
 * nvme_lockdown() - Issue lockdown command
 * @args:	&struct nvme_lockdown_args argument structure
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_lockdown(struct nvme_lockdown_args *args);

/**
 * nvme_set_property_args - Arguments for NVMe Set Property command
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
} __attribute__((packed, aligned(__alignof__(__u64))));

/**
 * nvme_set_property() - Set controller property
 * @args:	&struct nvme_set_property_args argument structure
 *
 * This is an NVMe-over-Fabrics specific command, not applicable to PCIe. These
 * properties align to the PCI MMIO controller registers.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_property(struct nvme_set_property_args *args);

/**
 * nvme_get_property_args - Arguments for NVMe Get Property command
 * @value:	Where the property's value will be stored on success
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
} __attribute__((packed, aligned(__alignof__(__u64*))));

/**
 * nvme_get_property() - Get a controller property
 * @args:	&struct nvme_get_propert_args argument structure
 *
 * This is an NVMe-over-Fabrics specific command, not applicable to PCIe. These
 * properties align to the PCI MMIO controller registers.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_property(struct nvme_get_property_args *args);

/**
 * nvme_sanitize_nvm_args - Arguments for the NVMe Sanitize NVM command
 * @result:	The command completion result from CQE dword0
 * @fd:		File descriptor of nvme device
 * @timeout:	Timeout in ms
 * @ovrpat:	Overwrite pattern
 * @sanact:	Sanitize action, see &enum nvme_sanitize_sanact
 * @ause:	Set to allow unrestriced sanitize exit
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
} __attribute__((packed, aligned(__alignof__(__u32*))));

/**
 * nvme_sanitize_nvm() - Start a sanitize operation
 * @args:	&struct nvme_sanitize_nvm_args argument structure
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
int nvme_sanitize_nvm(struct nvme_sanitize_nvm_args *args);

/**
 * nvme_dev_self_test_args - Arguments for the NVMe Device Self Test command
 * @result:	The command completion result from CQE dword0
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
} __attribute__((packed, aligned(__alignof__(__u32*))));

/**
 * nvme_dev_self_test() - Start or abort a self test
 * @args:	&struct nvme_dev_self_test argument structure
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
int nvme_dev_self_test(struct nvme_dev_self_test_args *args);

/**
 * nvme_virtual_mgmt_args - Arguments for the NVMe Virtualization
 * 			    resource management command
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
} __attribute__((packed, aligned(__alignof__(__u32*))));

/**
 * nvme_virtual_mgmt() - Virtualization resource management
 * @args:	&struct nvme_virtual_mgmt_args argument structure
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
int nvme_virtual_mgmt(struct nvme_virtual_mgmt_args *args);

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
static inline int nvme_flush(int fd, __u32 nsid) {
	struct nvme_passthru_cmd cmd = {};

	cmd.opcode = nvme_cmd_flush;
	cmd.nsid = nsid;

	return nvme_submit_io_passthru(fd, &cmd, NULL);
}

/**
 * nvme_io_args - Arguments for NVMe I/O commands
 * @slba:	Starting logical block
 * @storage_tag: This filed specifies Variable Sized Expected Logical Block
 *		Storage Tag (ELBST) and Expected Logical Block Reference
 *		Tag (ELBRT)
 * @result:	The command completion result from CQE dword0
 * @data:	Pointer to user address of the data buffer
 * @metadata:	Pointer to user address of the metadata buffer
 * @fd:		File descriptor of nvme device
 * @timeout:	Timeout in ms
 * @nsid:	Namespace ID
 * @data_len:	Length of user buffer, @data, in bytes
 * @metadata_len:Length of user buffer, @metadata, in bytes
 * @nbl:	Number of logical blocks to send (0's based value)
 * @control:	Command control flags, see &enum nvme_io_control_flags.
 * @apptag:	This field specifies the Application Tag Mask expected value.
 *		Used only if the namespace is formatted to use end-to-end
 *		protection information.
 * @appmask:	This field specifies the Application Tag expected value. Used
 *		only if the namespace is formatted to use end-to-end protection
 *		information.
 * @reftag:	This field specifies the Initial Logical Block Reference Tag
 *		expected value. Used only if the namespace is formatted to use
 *		end-to-end protection information.
 * @dsm:	Data set management attributes, see &enum nvme_io_dsm_flags
 * @dspec:	Directive specific value
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
	__u8 dsm;
	__u8 dspec;
} __attribute__((__packed__, aligned(__alignof__(__u64))));

/**
 * nvme_io() - Submit an nvme user I/O command
 * @args:	&struct nvme_io_args argument structure
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_io(struct nvme_io_args *args, __u8 opcode);

/**
 * nvme_read() - Submit an nvme user read command
 * @args:	&struct nvme_io_args argument structure
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
static inline int nvme_read(struct nvme_io_args *args)
{
	return nvme_io(args, nvme_cmd_read);
}

/**
 * nvme_write() - Submit an nvme user write command
 * @args:	&struct nvme_io_args argument structure
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
static inline int nvme_write(struct nvme_io_args *args)
{
	return nvme_io(args, nvme_cmd_write);
}

/**
 * nvme_compare() - Submit an nvme user compare command
 * @args:	&struct nvme_io_args argument structure
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
static inline int nvme_compare(struct nvme_io_args *args)
{
	return nvme_io(args, nvme_cmd_compare);
}

/**
 * nvme_write_zeros() - Submit an nvme write zeroes command
 * @args:	&struct nvme_io_args argument structure
 *
 * The Write Zeroes command sets a range of logical blocks to zero.  After
 * successful completion of this command, the value returned by subsequent
 * reads of logical blocks in this range shall be all bytes cleared to 0h until
 * a write occurs to this LBA range.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
static inline int nvme_write_zeros(struct nvme_io_args *args)
{
	return nvme_io(args, nvme_cmd_write_zeroes);
}

/**
 * nvme_write_uncorrectable() - Submit an nvme write uncorrectable command
 * @args:	&struct nvme_io_args argument structure
 *
 * The Write Uncorrectable command marks a range of logical blocks as invalid.
 * When the specified logical block(s) are read after this operation, a failure
 * is returned with Unrecovered Read Error status. To clear the invalid logical
 * block status, a write operation on those logical blocks is required.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
static inline int nvme_write_uncorrectable(struct nvme_io_args *args)
{
	return nvme_io(args, nvme_cmd_write_uncor);
}

/**
 * nvme_verify() - Send an nvme verify command
 * @args:	&struct nvme_io_args argument structure
 *
 * The Verify command verifies integrity of stored information by reading data
 * and metadata, if applicable, for the LBAs indicated without transferring any
 * data or metadata to the host.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
static inline int nvme_verify(struct nvme_io_args *args)
{
	return nvme_io(args, nvme_cmd_verify);
}

/**
 * nvme_dsm_args - Arguments for the NVMe Dataset Management command
 * @result:	The command completion result from CQE dword0
 * @dsm:	The data set management attributes
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
} __attribute__((packed, aligned(__alignof__(__u32*))));

/**
 * nvme_dsm() - Send an nvme data set management command
 * @args:	&struct nvme_dsm_args argument structure
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
int nvme_dsm(struct nvme_dsm_args *args);

/**
 * nvme_copy_args - Arguments for the NVMe Copy command
 * @sdlba:	Start destination LBA
 * @result:	The command completion result from CQE dword0
 * @copy:	Range descriptior
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
} __attribute__((packed, aligned(__alignof__(__u64))));

/**
 * nvme_copy() -
 *
 * @args:	&struct nvme_copy_args argument structure
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_copy(struct nvme_copy_args *args);

/**
 * nvme_resv_acquire_args - Arguments for the NVMe Reservation Acquire Comand
 * @nrkey:	The reservation key to be unregistered from the namespace if
 *		the action is preempt
 * @iekey:	Set to ignore the existing key
 * @result:	The command completion result from CQE dword0
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
} __attribute__((packed, aligned(__alignof__(__u64))));

/**
 * nvme_resv_acquire() - Send an nvme reservation acquire
 * @args:	&struct nvme_resv_acquire argument structure
 *
 * The Reservation Acquire command acquires a reservation on a namespace,
 * preempt a reservation held on a namespace, and abort a reservation held on a
 * namespace.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_resv_acquire(struct nvme_resv_acquire_args *args);

/**
 * nvme_resv_register_args - Arguments for the NVMe Reservation Register command
 * @crkey:	The current reservation key associated with the host
 * @nrkey:	The new reservation key to be register if action is register or
 *		replace
 * @result:	The command completion result from CQE dword0
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
} __attribute__((packed, aligned(__alignof__(__u64))));

/**
 * nvme_resv_register() - Send an nvme reservation register
 * @args:	&struct nvme_resv_register_args argument structure
 *
 * The Reservation Register command registers, unregisters, or replaces a
 * reservation key.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_resv_register(struct nvme_resv_register_args *args);

/**
 * nvme_resv_release_args - Arguments for the NVMe Reservation Release Command
 * @crkey:	The current reservation key to release
 * @result:	The command completion result from CQE dword0
 * @fd:		File descriptor of nvme device
 * @timeout:	Timeout in ms
 * @nsid:	Namespace identifier
 * @rtype:	The type of reservation to be create, see &enum nvme_resv_rtype
 * @rrela:	Reservation releast action, see &enum nvme_resv_rrela
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
} __attribute__((packed, aligned(__alignof__(__u64))));

/**
 * nvme_resv_release() - Send an nvme reservation release
 * @args:	&struct nvme_resv_release_args argument structure
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_resv_release(struct nvme_resv_release_args *args);

/**
 * nvme_resv_report_args - Arguments for the NVMe Reservation Report command
 * @result:	The command completion result from CQE dword0
 * @report:	The user space destination address to store the reservation
 *		report
 * @fd:		File descriptor of nvme device
 * @timeout:	Timeout in ms
 * @nsid:	Namespace identifier
 * @len:	Number of bytes to request transfered with this command
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
} __attribute__((packed, aligned(__alignof__(__u32*))));

/**
 * nvme_resv_report() - Send an nvme reservation report
 * @args:	struct nvme_resv_report_args argument structure
 *
 * Returns a Reservation Status data structure to memory that describes the
 * registration and reservation status of a namespace. See the defintion for
 * the returned structure, &struct nvme_reservation_status, for more details.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_resv_report(struct nvme_resv_report_args *args);

/**
 * nvme_zns_mgmt_send_args - Arguments for the NVMe ZNS Management Send command
 * @slba:	Starting logical block address
 * @result:	The command completion result from CQE dword0
 * @data:	Userspace address of the data
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
} __attribute__((packed, aligned(__alignof__(__u64))));

/**
 * nvme_zns_mgmt_send() -
 * @args:	&struct nvme_zns_mgmt_send_args argument structure
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_zns_mgmt_send(struct nvme_zns_mgmt_send_args *args);


/**
 * nvme_zns_mgmt_recv_args - Arguments for the NVMe ZNS Management Receive command
 * @slba:	Starting logical block address
 * @result:	The command completion result from CQE dword0
 * @data:	Userspace address of the data
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
} __attribute__((packed, aligned(__alignof__(__u64))));

/**
 * nvme_zns_mgmt_recv() -
 * @args:	&struct nvme_zns_mgmt_recv_args argument structure
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_zns_mgmt_recv(struct nvme_zns_mgmt_recv_args *args);

/**
 * nvme_zns_report_zones() - Return the list of zones
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace ID
 * @slba:	Starting LBA
 * @opts:	Reporting options
 * @extended:	Extended report
 * @partial:	Partial report requested
 * @data_len:	Length of the data buffer
 * @data:	Userspace address of the report zones data
 * @timeout:	timeout in ms
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
static inline int nvme_zns_report_zones(int fd, __u32 nsid, __u64 slba,
			  enum nvme_zns_report_options opts,
			  bool extended, bool partial,
			  __u32 data_len, void *data,
			  __u32 timeout, __u32 *result)
{
	struct nvme_zns_mgmt_recv_args args = {
		.slba = slba,
		.result = result,
		.data = data,
		.args_size = sizeof(args),
		.fd = fd,
		.timeout = timeout,
		.nsid = nsid,
		.zra = extended ? NVME_ZNS_ZRA_EXTENDED_REPORT_ZONES :
		NVME_ZNS_ZRA_REPORT_ZONES,
		.data_len = data_len,
		.zrasf = opts,
		.zras_feat = partial,
	};

	return nvme_zns_mgmt_recv(&args);
}

/**
 * nvme_zns_append_args - Arguments for the NVMe ZNS Append command
 * @zslba:	Zone start logical block address
 * @fd:		File descriptor of nvme device
 * @result:	The command completion result from CQE dword0
 * @data:	Userspace address of the data
 * @metadata:	Userspace address of the metadata
 * @timeout:	Timeout in ms
 * @nsid:	Namespace ID
 * @ilbrt:	Initial logical block reference tag
 * @data_len:	Length of @data
 * @metadata_len: Length of @metadata
 * @nlb:	Number of logical blocks
 * @control:
 * @lbat:	Logical block application tag
 * @lbatm:	Logical block application tag mask
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
} __attribute__((packed, aligned(__alignof__(__u64))));

/**
 * nvme_zns_append() - Append data to a zone
 * @args:	&struct nvme_zns_append_args argument structure
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_zns_append(struct nvme_zns_append_args *args);

#endif /* _LIBNVME_IOCTL_H */
