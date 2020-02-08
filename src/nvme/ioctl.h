#ifndef _LIBNVME_IOCTL_H
#define _LIBNVME_IOCTL_H

#include <sys/ioctl.h>

#include "types.h"

/*
 * We can not always count on the kernel UAPI being installed. Use the same
 * 'ifdef' guard to avoid double definitions just in case.
 */
#ifndef _UAPI_LINUX_NVME_IOCTL_H
#define _UAPI_LINUX_NVME_IOCTL_H

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

/**
 * nvme_submit_admin_passthru64() - Submit a 64-bit nvme passthrough admin
 * 				    command
 * @fd:		File descriptor of nvme device
 * @cmd:	The nvme admin command to send
 * @result:	Optional field to return the result from the CQE DW0-1
 *
 * Uses NVME_IOCTL_ADMIN64_CMD for the ioctl request.
 *
 * Return: The nvme command status if a response was received or -1
 * 	   with errno set otherwise.
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
 * Return: The nvme command status if a response was received or -1
 * 	   with errno set otherwise.
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
 * Return: The nvme command status if a response was received or -1
 * 	   with errno set otherwise.
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
 * Return: The nvme command status if a response was received or -1
 * 	   with errno set otherwise.
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
 * Return: The nvme command status if a response was received or -1
 * 	   with errno set otherwise.
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
 * Return: The nvme command status if a response was received or -1 with errno
 * 	   set otherwise.
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
 * Return: The nvme command status if a response was received or -1
 * 	   with errno set otherwise.
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
 * Return: The nvme command status if a response was received or -1
 * 	   with errno set otherwise.
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
 * 	   otherwise.
 */
int nvme_subsystem_reset(int fd);

/**
 * nvme_ctrl_reset() - Initiate a controller reset
 * @fd:		File descriptor of nvme device
 *
 * This should only be sent to controller handles, not to namespaces.
 *
 * Return: Zero if a reset was initiated or -1 with errno set otherwise.
 */
int nvme_ctrl_reset(int fd);

/**
 * nvme_ns_rescan() - Initiate a controller rescan
 * @fd:		File descriptor of nvme device
 *
 * This should only be sent to controller handles, not to namespaces.
 *
 * Return: Zero if a rescan was initiated or -1 with errno set otherwise.
 */
int nvme_ns_rescan(int fd);

/**
 * nvme_get_nsid() - Retrieve the NSID from a namespace file descriptor
 * @fd:		File descriptor of nvme namespace
 *
 * This should only be sent to namespace handles, not to controllers.
 *
 * Return: The namespace identifier if a succecssful or -1 with errno set
 * 	   otherwise.
 */
int nvme_get_nsid(int fd);

#endif /* _LIBNVME_IOCTL_H */
