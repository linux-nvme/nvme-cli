// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 *	    Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 */

#ifndef _LIBNVME_IOCTL_H
#define _LIBNVME_IOCTL_H

#include <stddef.h>
#include <sys/ioctl.h>
#include "types.h"
#include "api-types.h"

/*
 * We can not always count on the kernel UAPI being installed. Use the same
 * 'ifdef' guard to avoid double definitions just in case.
 */
#ifndef _UAPI_LINUX_NVME_IOCTL_H
#define _UAPI_LINUX_NVME_IOCTL_H

#ifndef _LINUX_NVME_IOCTL_H
#define _LINUX_NVME_IOCTL_H

/**
 * DOC: ioctl.h
 *
 * Linux NVMe ioctl interface functions
 */

/* '0' is interpreted by the kernel to mean 'apply the default timeout' */
#define NVME_DEFAULT_IOCTL_TIMEOUT 0

/*
 * 4k is the smallest possible transfer unit, so restricting to 4k
 * avoids having to check the MDTS value of the controller.
 */
#define NVME_LOG_PAGE_PDU_SIZE 4096

/**
 * struct nvme_passthru_cmd - nvme passthrough command structure
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
 * struct nvme_passthru_cmd64 - 64-bit nvme passthrough command structure
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
 * @rsvd2:	Reserved for future use (and fills an implicit struct pad
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

/**
 * struct nvme_uring_cmd - nvme uring command structure
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
 * @rsvd2:	Reserved for future use (and fills an implicit struct pad
 */
struct nvme_uring_cmd {
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
	__u32   rsvd2;
};

#define NVME_IOCTL_ID		_IO('N', 0x40)
#define NVME_IOCTL_RESET	_IO('N', 0x44)
#define NVME_IOCTL_SUBSYS_RESET	_IO('N', 0x45)
#define NVME_IOCTL_RESCAN	_IO('N', 0x46)
#define NVME_IOCTL_ADMIN_CMD	_IOWR('N', 0x41, struct nvme_passthru_cmd)
#define NVME_IOCTL_IO_CMD	_IOWR('N', 0x43, struct nvme_passthru_cmd)
#define NVME_IOCTL_ADMIN64_CMD  _IOWR('N', 0x47, struct nvme_passthru_cmd64)
#define NVME_IOCTL_IO64_CMD     _IOWR('N', 0x48, struct nvme_passthru_cmd64)

/* io_uring async commands: */
#define NVME_URING_CMD_IO	_IOWR('N', 0x80, struct nvme_uring_cmd)
#define NVME_URING_CMD_IO_VEC	_IOWR('N', 0x81, struct nvme_uring_cmd)

#endif /* _UAPI_LINUX_NVME_IOCTL_H */

#endif /* _LINUX_NVME_IOCTL_H */

/**
 * sizeof_args - Helper function used to determine structure sizes
 * @type:	Argument structure type
 * @member:	Member inside the type
 * @align:	Alignment information
 */
#define sizeof_args(type, member, align)					\
({										\
	type s;									\
	size_t t = offsetof(type, member) + sizeof(s.member);			\
	size_t p = (sizeof(align) - (t % sizeof(align))) % sizeof(align);	\
	t + p;									\
})

enum nvme_cmd_dword_fields {
	NVME_DEVICE_SELF_TEST_CDW10_STC_SHIFT			= 0,
	NVME_DEVICE_SELF_TEST_CDW10_STC_MASK			= 0xf,
	NVME_DIRECTIVE_CDW11_DOPER_SHIFT			= 0,
	NVME_DIRECTIVE_CDW11_DTYPE_SHIFT			= 8,
	NVME_DIRECTIVE_CDW11_DPSEC_SHIFT			= 16,
	NVME_DIRECTIVE_CDW11_DOPER_MASK				= 0xff,
	NVME_DIRECTIVE_CDW11_DTYPE_MASK				= 0xff,
	NVME_DIRECTIVE_CDW11_DPSEC_MASK				= 0xffff,
	NVME_DIRECTIVE_SEND_IDENTIFY_CDW12_ENDIR_SHIFT		= 0,
	NVME_DIRECTIVE_SEND_IDENTIFY_CDW12_DTYPE_SHIFT		= 1,
	NVME_DIRECTIVE_SEND_IDENTIFY_CDW12_ENDIR_MASK		= 0x1,
	NVME_DIRECTIVE_SEND_IDENTIFY_CDW12_DTYPE_MASK		= 0x1,
	NVME_FW_COMMIT_CDW10_FS_SHIFT				= 0,
	NVME_FW_COMMIT_CDW10_CA_SHIFT				= 3,
	NVME_FW_COMMIT_CDW10_BPID_SHIFT				= 31,
	NVME_FW_COMMIT_CDW10_FS_MASK				= 0x7,
	NVME_FW_COMMIT_CDW10_CA_MASK				= 0x7,
	NVME_FW_COMMIT_CDW10_BPID_MASK				= 0x1,
	NVME_GET_FEATURES_CDW10_SEL_SHIFT			= 8,
	NVME_GET_FEATURES_CDW10_SEL_MASK			= 0x7,
	NVME_SET_FEATURES_CDW10_SAVE_SHIFT			= 31,
	NVME_SET_FEATURES_CDW10_SAVE_MASK			= 0x1,
	NVME_FEATURES_CDW10_FID_SHIFT				= 0,
	NVME_FEATURES_CDW14_UUID_SHIFT				= 0,
	NVME_FEATURES_CDW10_FID_MASK				= 0xff,
	NVME_FEATURES_CDW14_UUID_MASK				= 0x7f,
	NVME_LOG_CDW10_LID_SHIFT				= 0,
	NVME_LOG_CDW10_LSP_SHIFT				= 8,
	NVME_LOG_CDW10_RAE_SHIFT				= 15,
	NVME_LOG_CDW10_NUMDL_SHIFT				= 16,
	NVME_LOG_CDW11_NUMDU_SHIFT				= 0,
	NVME_LOG_CDW11_LSI_SHIFT				= 16,
	NVME_LOG_CDW14_UUID_SHIFT				= 0,
	NVME_LOG_CDW14_CSI_SHIFT				= 24,
	NVME_LOG_CDW14_OT_SHIFT					= 23,
	NVME_LOG_CDW10_LID_MASK					= 0xff,
	NVME_LOG_CDW10_LSP_MASK					= 0x7f,
	NVME_LOG_CDW10_RAE_MASK					= 0x1,
	NVME_LOG_CDW10_NUMDL_MASK				= 0xffff,
	NVME_LOG_CDW11_NUMDU_MASK				= 0xffff,
	NVME_LOG_CDW11_LSI_MASK					= 0xffff,
	NVME_LOG_CDW14_UUID_MASK				= 0x7f,
	NVME_LOG_CDW14_CSI_MASK					= 0xff,
	NVME_LOG_CDW14_OT_MASK					= 0x1,
	NVME_IDENTIFY_CDW10_CNS_SHIFT				= 0,
	NVME_IDENTIFY_CDW10_CNTID_SHIFT				= 16,
	NVME_IDENTIFY_CDW11_CNSSPECID_SHIFT			= 0,
	NVME_IDENTIFY_CDW14_UUID_SHIFT				= 0,
	NVME_IDENTIFY_CDW11_CSI_SHIFT				= 24,
	NVME_IDENTIFY_CDW10_CNS_MASK				= 0xff,
	NVME_IDENTIFY_CDW10_CNTID_MASK				= 0xffff,
	NVME_IDENTIFY_CDW11_CNSSPECID_MASK			= 0xffff,
	NVME_IDENTIFY_CDW14_UUID_MASK				= 0x7f,
	NVME_IDENTIFY_CDW11_CSI_MASK				= 0xff,
	NVME_NAMESPACE_ATTACH_CDW10_SEL_SHIFT			= 0,
	NVME_NAMESPACE_ATTACH_CDW10_SEL_MASK			= 0xf,
	NVME_NAMESPACE_MGMT_CDW10_SEL_SHIFT			= 0,
	NVME_NAMESPACE_MGMT_CDW10_SEL_MASK			= 0xf,
	NVME_NAMESPACE_MGMT_CDW11_CSI_SHIFT			= 24,
	NVME_NAMESPACE_MGMT_CDW11_CSI_MASK			= 0xff,
	NVME_VIRT_MGMT_CDW10_ACT_SHIFT				= 0,
	NVME_VIRT_MGMT_CDW10_RT_SHIFT				= 8,
	NVME_VIRT_MGMT_CDW10_CNTLID_SHIFT			= 16,
	NVME_VIRT_MGMT_CDW11_NR_SHIFT				= 0,
	NVME_VIRT_MGMT_CDW10_ACT_MASK				= 0xf,
	NVME_VIRT_MGMT_CDW10_RT_MASK				= 0x7,
	NVME_VIRT_MGMT_CDW10_CNTLID_MASK			= 0xffff,
	NVME_VIRT_MGMT_CDW11_NR_MASK				= 0xffff,
	NVME_FORMAT_CDW10_LBAF_SHIFT				= 0,
	NVME_FORMAT_CDW10_MSET_SHIFT				= 4,
	NVME_FORMAT_CDW10_PI_SHIFT				= 5,
	NVME_FORMAT_CDW10_PIL_SHIFT				= 8,
	NVME_FORMAT_CDW10_SES_SHIFT				= 9,
	NVME_FORMAT_CDW10_LBAFU_SHIFT				= 12,
	NVME_FORMAT_CDW10_LBAF_MASK				= 0xf,
	NVME_FORMAT_CDW10_MSET_MASK				= 0x1,
	NVME_FORMAT_CDW10_PI_MASK				= 0x7,
	NVME_FORMAT_CDW10_PIL_MASK				= 0x1,
	NVME_FORMAT_CDW10_SES_MASK				= 0x7,
	NVME_FORMAT_CDW10_LBAFU_MASK				= 0x3,
	NVME_SANITIZE_CDW10_SANACT_SHIFT			= 0,
	NVME_SANITIZE_CDW10_AUSE_SHIFT				= 3,
	NVME_SANITIZE_CDW10_OWPASS_SHIFT			= 4,
	NVME_SANITIZE_CDW10_OIPBP_SHIFT				= 8,
	NVME_SANITIZE_CDW10_NODAS_SHIFT				= 9,
	NVME_SANITIZE_CDW10_EMVS_SHIFT				= 10,
	NVME_SANITIZE_CDW10_SANACT_MASK				= 0x7,
	NVME_SANITIZE_CDW10_AUSE_MASK				= 0x1,
	NVME_SANITIZE_CDW10_OWPASS_MASK				= 0xf,
	NVME_SANITIZE_CDW10_OIPBP_MASK				= 0x1,
	NVME_SANITIZE_CDW10_NODAS_MASK				= 0x1,
	NVME_SANITIZE_CDW10_EMVS_MASK				= 0x1,
	NVME_SECURITY_NSSF_SHIFT				= 0,
	NVME_SECURITY_SPSP0_SHIFT				= 8,
	NVME_SECURITY_SPSP1_SHIFT				= 16,
	NVME_SECURITY_SECP_SHIFT				= 24,
	NVME_SECURITY_NSSF_MASK					= 0xff,
	NVME_SECURITY_SPSP0_MASK				= 0xff,
	NVME_SECURITY_SPSP1_MASK				= 0xff,
	NVME_SECURITY_SECP_MASK					= 0xffff,
	NVME_GET_LBA_STATUS_CDW13_RL_SHIFT			= 0,
	NVME_GET_LBA_STATUS_CDW13_ATYPE_SHIFT			= 24,
	NVME_GET_LBA_STATUS_CDW13_RL_MASK			= 0xffff,
	NVME_GET_LBA_STATUS_CDW13_ATYPE_MASK			= 0xff,
	NVME_ZNS_MGMT_SEND_ZSASO_SHIFT				= 9,
	NVME_ZNS_MGMT_SEND_ZSASO_MASK				= 0x1,
	NVME_ZNS_MGMT_SEND_SEL_SHIFT				= 8,
	NVME_ZNS_MGMT_SEND_SEL_MASK				= 0x1,
	NVME_ZNS_MGMT_SEND_ZSA_SHIFT				= 0,
	NVME_ZNS_MGMT_SEND_ZSA_MASK				= 0xff,
	NVME_ZNS_MGMT_RECV_ZRA_SHIFT				= 0,
	NVME_ZNS_MGMT_RECV_ZRA_MASK				= 0xff,
	NVME_ZNS_MGMT_RECV_ZRASF_SHIFT				= 8,
	NVME_ZNS_MGMT_RECV_ZRASF_MASK				= 0xff,
	NVME_ZNS_MGMT_RECV_ZRAS_FEAT_SHIFT			= 16,
	NVME_ZNS_MGMT_RECV_ZRAS_FEAT_MASK			= 0x1,
	NVME_DIM_TAS_SHIFT					= 0,
	NVME_DIM_TAS_MASK					= 0xF,
};

/**
 * nvme_submit_admin_passthru64() - Submit a 64-bit nvme passthrough admin
 *				    command
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
 * nvme_admin_passthru64() - Submit a 64-bit nvme passthrough command
 * @fd:		File descriptor of nvme device
 * @opcode:	The nvme io command to send
 * @flags:	NVMe command flags (not used)
 * @rsvd:	Reserved for future use
 * @nsid:	Namespace identifier
 * @cdw2:	Command dword 2
 * @cdw3:	Command dword 3
 * @cdw10:	Command dword 10
 * @cdw11:	Command dword 11
 * @cdw12:	Command dword 12
 * @cdw13:	Command dword 13
 * @cdw14:	Command dword 14
 * @cdw15:	Command dword 15
 * @data_len:	Length of the data transferred in this command in bytes
 * @data:	Pointer to user address of the data buffer
 * @metadata_len:Length of metadata transferred in this command
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
 * @rsvd:	Reserved for future use
 * @nsid:	Namespace identifier
 * @cdw2:	Command dword 2
 * @cdw3:	Command dword 3
 * @cdw10:	Command dword 10
 * @cdw11:	Command dword 11
 * @cdw12:	Command dword 12
 * @cdw13:	Command dword 13
 * @cdw14:	Command dword 14
 * @cdw15:	Command dword 15
 * @data_len:	Length of the data transferred in this command in bytes
 * @data:	Pointer to user address of the data buffer
 * @metadata_len:Length of metadata transferred in this command
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
 * @rsvd:	Reserved for future use
 * @nsid:	Namespace identifier
 * @cdw2:	Command dword 2
 * @cdw3:	Command dword 3
 * @cdw10:	Command dword 10
 * @cdw11:	Command dword 11
 * @cdw12:	Command dword 12
 * @cdw13:	Command dword 13
 * @cdw14:	Command dword 14
 * @cdw15:	Command dword 15
 * @data_len:	Length of the data transferred in this command in bytes
 * @data:	Pointer to user address of the data buffer
 * @metadata_len:Length of metadata transferred in this command
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
 * @rsvd:	Reserved for future use
 * @nsid:	Namespace identifier
 * @cdw2:	Command dword 2
 * @cdw3:	Command dword 3
 * @cdw10:	Command dword 10
 * @cdw11:	Command dword 11
 * @cdw12:	Command dword 12
 * @cdw13:	Command dword 13
 * @cdw14:	Command dword 14
 * @cdw15:	Command dword 15
 * @data_len:	Length of the data transferred in this command in bytes
 * @data:	Pointer to user address of the data buffer
 * @metadata_len:Length of metadata transferred in this command
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

static inline int nvme_identify_cns_nsid(int fd, enum nvme_identify_cns cns,
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
		.cns_specific_id = NVME_CNSSPECID_NONE,
		.uuidx = NVME_UUID_NONE,
	};

	return nvme_identify(&args);
}

/**
 * nvme_identify_ctrl() - Retrieves nvme identify controller
 * @fd:		File descriptor of nvme device
 * @id:		User space destination address to transfer the data,
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
 *				  allocated namespaces
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
 * @nsid:	Return namespaces greater than this identifier
 * @list:	User space destination address to transfer the data
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
 * @nsid:	Return namespaces greater than this identifier
 * @list:	User space destination address to transfer the data
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
 * @cntid:	Starting CNTLID to return in the list
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
			struct nvme_ctrl_list *cntlist)
{
	struct nvme_identify_args args = {
		.result = NULL,
		.data = cntlist,
		.args_size = sizeof(args),
		.fd = fd,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.cns = NVME_IDENTIFY_CNS_CTRL_LIST,
		.csi = NVME_CSI_NVM,
		.nsid = NVME_NSID_NONE,
		.cntid = cntid,
		.cns_specific_id = NVME_CNSSPECID_NONE,
		.uuidx = NVME_UUID_NONE,
	};

	return nvme_identify(&args);
}

/**
 * nvme_identify_nsid_ctrl_list() - Retrieves controller list attached to an nsid
 * @fd:		File descriptor of nvme device
 * @nsid:	Return controllers that are attached to this nsid
 * @cntid:	Starting CNTLID to return in the list
 * @cntlist:	User space destination address to transfer the data
 *
 * Up to 2047 controller identifiers are returned containing a controller
 * identifier greater than or equal to the controller identifier  specified in
 * @cntid attached to @nsid.
 *
 * See &struct nvme_ctrl_list for a definition of the structure returned.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1
 */
static inline int nvme_identify_nsid_ctrl_list(int fd, __u32 nsid, __u16 cntid,
			struct nvme_ctrl_list *cntlist)
{
	struct nvme_identify_args args = {
		.result = NULL,
		.data = cntlist,
		.args_size = sizeof(args),
		.fd = fd,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.cns = NVME_IDENTIFY_CNS_NS_CTRL_LIST,
		.csi = NVME_CSI_NVM,
		.nsid = nsid,
		.cntid = cntid,
		.cns_specific_id = NVME_CNSSPECID_NONE,
		.uuidx = NVME_UUID_NONE,
	};

	return nvme_identify(&args);
}

/**
 * nvme_identify_ns_descs() - Retrieves namespace descriptor list
 * @fd:		File descriptor of nvme device
 * @nsid:	The namespace id to retrieve descriptors
 * @descs:	User space destination address to transfer the data
 *
 * A list of Namespace Identification Descriptor structures is returned to the
 * host for the namespace specified in the Namespace Identifier (NSID) field if
 * it is an active NSID.
 *
 * The data returned is in the form of an array of 'struct nvme_ns_id_desc'.
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
 * @nvmsetid:	NVM Set Identifier
 * @nvmset:	User space destination address to transfer the data
 *
 * Retrieves an NVM Set List, &struct nvme_id_nvmset_list. The data structure
 * is an ordered list by NVM Set Identifier, starting with the first NVM Set
 * Identifier supported by the NVM subsystem that is equal to or greater than
 * the NVM Set Identifier.
 *
 * See &struct nvme_id_nvmset_list for the definition of the returned structure.
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
		.cns_specific_id = nvmsetid,
		.uuidx = NVME_UUID_NONE,
	};

	return nvme_identify(&args);
}

/**
 * nvme_identify_primary_ctrl() - Retrieve NVMe Primary Controller
 *				  identification
 * @fd:		File descriptor of nvme device
 * @cntid:	Return controllers starting at this identifier
 * @cap:	User space destination buffer address to transfer the data
 *
 * See &struct nvme_primary_ctrl_cap for the definition of the returned structure, @cap.
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
		.cns_specific_id = NVME_CNSSPECID_NONE,
		.uuidx = NVME_UUID_NONE,
	};

	return nvme_identify(&args);
}

/**
 * nvme_identify_secondary_ctrl_list() - Retrieves secondary controller list
 * @fd:		File descriptor of nvme device
 * @cntid:	Return controllers starting at this identifier
 * @sc_list:	User space destination address to transfer the data
 *
 * A Secondary Controller List is returned to the host for up to 127 secondary
 * controllers associated with the primary controller processing this command.
 * The list contains entries for controller identifiers greater than or equal
 * to the value specified in the Controller Identifier (cntid).
 *
 * See &struct nvme_secondary_ctrls_list for a definition of the returned
 * structure.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
static inline int nvme_identify_secondary_ctrl_list(int fd,
			__u16 cntid, struct nvme_secondary_ctrl_list *sc_list)
{
	struct nvme_identify_args args = {
		.result = NULL,
		.data = sc_list,
		.args_size = sizeof(args),
		.fd = fd,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.cns = NVME_IDENTIFY_CNS_SECONDARY_CTRL_LIST,
		.csi = NVME_CSI_NVM,
		.nsid = NVME_NSID_NONE,
		.cntid = cntid,
		.cns_specific_id = NVME_CNSSPECID_NONE,
		.uuidx = NVME_UUID_NONE,
	};

	return nvme_identify(&args);
}

/**
 * nvme_identify_ns_granularity() - Retrieves namespace granularity
 *				    identification
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
			struct nvme_id_ns_granularity_list *gr_list)
{
	return nvme_identify_cns_nsid(fd, NVME_IDENTIFY_CNS_NS_GRANULARITY,
				      NVME_NSID_NONE, gr_list);
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
static inline int nvme_identify_uuid(int fd, struct nvme_id_uuid_list *uuid_list)
{
	return nvme_identify_cns_nsid(fd, NVME_IDENTIFY_CNS_UUID_LIST,
				      NVME_NSID_NONE, uuid_list);
}

/**
 * nvme_identify_ns_csi() - I/O command set specific identify namespace data
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace to identify
 * @uuidx:	UUID Index for differentiating vendor specific encoding
 * @csi:	Command Set Identifier
 * @data:	User space destination address to transfer the data
 *
 * An I/O Command Set specific Identify Namespace data structure is returned
 * for the namespace specified in @nsid.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
static inline int nvme_identify_ns_csi(int fd, __u32 nsid, __u8 uuidx,
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
		.cns_specific_id = NVME_CNSSPECID_NONE,
		.uuidx = uuidx,
	};

	return nvme_identify(&args);
}

/**
 * nvme_identify_ctrl_csi() - I/O command set specific Identify Controller data
 * @fd:		File descriptor of nvme device
 * @csi:	Command Set Identifier
 * @data:	User space destination address to transfer the data
 *
 * An I/O Command Set specific Identify Controller data structure is returned
 * to the host for the controller processing the command. The specific Identify
 * Controller data structure to be returned is specified by @csi.
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
		.cns_specific_id = NVME_CNSSPECID_NONE,
		.uuidx = NVME_UUID_NONE,
	};

	return nvme_identify(&args);
}

/**
 * nvme_identify_active_ns_list_csi() - Active namespace ID list associated with a specified I/O command set
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
			enum nvme_csi csi, struct nvme_ns_list *ns_list)
{
	struct nvme_identify_args args = {
		.result = NULL,
		.data = ns_list,
		.args_size = sizeof(args),
		.fd = fd,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.cns = NVME_IDENTIFY_CNS_CSI_NS_ACTIVE_LIST,
		.csi = csi,
		.nsid = nsid,
		.cntid = NVME_CNTLID_NONE,
		.cns_specific_id = NVME_CNSSPECID_NONE,
		.uuidx = NVME_UUID_NONE,
	};

	return nvme_identify(&args);
}

/**
 * nvme_identify_allocated_ns_list_csi() - Allocated namespace ID list associated with a specified I/O command set
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
			enum nvme_csi csi, struct nvme_ns_list *ns_list)
{
	struct nvme_identify_args args = {
		.result = NULL,
		.data = ns_list,
		.args_size = sizeof(args),
		.fd = fd,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.cns = NVME_IDENTIFY_CNS_CSI_ALLOCATED_NS_LIST,
		.csi = csi,
		.nsid = nsid,
		.cntid = NVME_CNTLID_NONE,
		.cns_specific_id = NVME_CNSSPECID_NONE,
		.uuidx = NVME_UUID_NONE,
	};

	return nvme_identify(&args);
}

/**
 * nvme_identify_independent_identify_ns() - I/O command set independent Identify namespace data
 * @fd:		File descriptor of nvme device
 * @nsid:	Return namespaces greater than this identifier
 * @ns:		I/O Command Set Independent Identify Namespace data
 *		structure
 *
 * The I/O command set independent Identify namespace data structure for
 * the namespace identified with @ns is returned to the host.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
static inline int nvme_identify_independent_identify_ns(int fd, __u32 nsid,
			struct nvme_id_independent_id_ns *ns)
{
	return nvme_identify_cns_nsid(
		fd, NVME_IDENTIFY_CNS_CSI_INDEPENDENT_ID_NS, nsid, ns);
}

/**
 * nvme_identify_ns_csi_user_data_format() - Identify namespace user data format
 * @fd:		File descriptor of nvme device
 * @user_data_format: Return namespaces capability of identifier
 * @uuidx:	UUID selection, if supported
 * @csi:	Command Set Identifier
 * @data:	User space destination address to transfer the data
 *
 * Identify Namespace data structure for the specified User Data Format
 * index containing the namespace capabilities for the NVM Command Set.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
static inline int nvme_identify_ns_csi_user_data_format(int fd,
			__u16 user_data_format, __u8 uuidx,
			enum nvme_csi csi, void *data)
{
	struct nvme_identify_args args = {
		.result = NULL,
		.data = data,
		.args_size = sizeof(args),
		.fd = fd,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.cns = NVME_IDENTIFY_CNS_NS_USER_DATA_FORMAT,
		.csi = csi,
		.nsid = NVME_NSID_NONE,
		.cntid = NVME_CNTLID_NONE,
		.cns_specific_id = user_data_format,
		.uuidx = uuidx,
	};

	return nvme_identify(&args);
}

/**
 * nvme_identify_iocs_ns_csi_user_data_format() - Identify I/O command set namespace data structure
 * @fd:		File descriptor of nvme device
 * @user_data_format: Return namespaces capability of identifier
 * @uuidx:	UUID selection, if supported
 * @csi:	Command Set Identifier
 * @data:	User space destination address to transfer the data
 *
 * I/O Command Set specific Identify Namespace data structure for
 * the specified User Data Format index containing the namespace
 * capabilities for the I/O Command Set specified in the CSI field.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
static inline int nvme_identify_iocs_ns_csi_user_data_format(int fd,
			__u16 user_data_format, __u8 uuidx,
			enum nvme_csi csi, void *data)
{
	struct nvme_identify_args args = {
		.result = NULL,
		.data = data,
		.args_size = sizeof(args),
		.fd = fd,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.cns = NVME_IDENTIFY_CNS_CSI_NS_USER_DATA_FORMAT,
		.csi = csi,
		.nsid = NVME_NSID_NONE,
		.cntid = NVME_CNTLID_NONE,
		.cns_specific_id = user_data_format,
		.uuidx = uuidx,
	};

	return nvme_identify(&args);
}

/**
 * nvme_nvm_identify_ctrl() - Identify controller data
 * @fd:	File descriptor of nvme device
 * @id:	User space destination address to transfer the data
 *
 * Return an identify controller data structure to the host of
 * processing controller.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
static inline int nvme_nvm_identify_ctrl(int fd, struct nvme_id_ctrl_nvm *id)
{
	return nvme_identify_ctrl_csi(fd, NVME_CSI_NVM, id);
}

/**
 * nvme_identify_domain_list() - Domain list data
 * @fd:		File descriptor of nvme device
 * @domid:	Domain ID
 * @list:	User space destination address to transfer data
 *
 * A list of 31 domain IDs is returned to the host containing domain
 * attributes in increasing order that are greater than the value
 * specified in the @domid field.
 *
 * See &struct nvme_identify_domain_attr for the definition of the
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
		.cns_specific_id = domid,
		.uuidx = NVME_UUID_NONE,
	};

	return nvme_identify(&args);
}

/**
 * nvme_identify_endurance_group_list() - Endurance group list data
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
		.cns_specific_id = endgrp_id,
		.uuidx = NVME_UUID_NONE,
	};

	return nvme_identify(&args);
}

/**
 * nvme_identify_iocs() - I/O command set data structure
 * @fd:		File descriptor of nvme device
 * @cntlid:	Controller ID
 * @iocs:	User space destination address to transfer the data
 *
 * Retrieves list of the controller's supported io command set vectors. See
 * &struct nvme_id_iocs.
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
		.cns_specific_id = NVME_CNSSPECID_NONE,
		.uuidx = NVME_UUID_NONE,
	};

	return nvme_identify(&args);
}

/**
 * nvme_zns_identify_ns() - ZNS identify namespace data
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
	return nvme_identify_ns_csi(
		fd, nsid, NVME_UUID_NONE, NVME_CSI_ZNS, data);
}

/**
 * nvme_zns_identify_ctrl() - ZNS identify controller data
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
 * nvme_get_log() - NVMe Admin Get Log command
 * @args:	&struct nvme_get_log_args argument structure
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_log(struct nvme_get_log_args *args);

/**
 * nvme_get_log_page() - Get log page data
 * @fd:		File descriptor of nvme device
 * @xfer_len:	Max log transfer size per request to split the total.
 * @args:	&struct nvme_get_log_args argument structure
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_log_page(int fd, __u32 xfer_len, struct nvme_get_log_args *args);

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
		.lsp = NVME_LOG_LSP_NONE,
		.uuidx = NVME_UUID_NONE,
		.rae = rae,
		.ot = false,
	};

	return nvme_get_log_page(fd, NVME_LOG_PAGE_PDU_SIZE, &args);
}

static inline int nvme_get_log_simple(int fd, enum nvme_cmd_get_log_lid lid,
				      __u32 len, void *log)
{
	return nvme_get_nsid_log(fd, false, lid, NVME_NSID_ALL, len, log);
}

/**
 * nvme_get_log_supported_log_pages() - Retrieve nmve supported log pages
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
 * @nr_entries:	Number of error log entries allocated
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
static inline int nvme_get_log_error(int fd, unsigned int nr_entries, bool rae,
				     struct nvme_error_log_page *err_log)
{
	return nvme_get_nsid_log(fd, rae, NVME_LOG_LID_ERROR,
				 NVME_NSID_ALL, sizeof(*err_log) * nr_entries,
				 err_log);
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
				     struct nvme_smart_log *smart_log)
{
	return nvme_get_nsid_log(fd, rae, NVME_LOG_LID_SMART,
				 nsid, sizeof(*smart_log), smart_log);
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
			struct nvme_firmware_slot *fw_log)
{
	return nvme_get_nsid_log(fd, rae, NVME_LOG_LID_FW_SLOT,
				 NVME_NSID_ALL, sizeof(*fw_log), fw_log);
}

/**
 * nvme_get_log_changed_ns_list() - Retrieve namespace changed list
 * @fd:		File descriptor of nvme device
 * @rae:	Retain asynchronous events
 * @ns_log:	User address to store the log page
 *
 * This log page describes namespaces attached to this controller that have
 * changed since the last time the namespace was identified, been added, or
 * deleted.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
static inline int nvme_get_log_changed_ns_list(int fd, bool rae,
			struct nvme_ns_list *ns_log)
{
	return nvme_get_nsid_log(fd, rae, NVME_LOG_LID_CHANGED_NS,
				 NVME_NSID_ALL, sizeof(*ns_log), ns_log);
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
			struct nvme_cmd_effects_log *effects_log)
{
	struct nvme_get_log_args args = {
		.lpo = 0,
		.result = NULL,
		.log = effects_log,
		.args_size = sizeof(args),
		.fd = fd,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.lid = NVME_LOG_LID_CMD_EFFECTS,
		.len = sizeof(*effects_log),
		.nsid = NVME_NSID_ALL,
		.csi = csi,
		.lsi = NVME_LOG_LSI_NONE,
		.lsp = NVME_LOG_LSP_NONE,
		.uuidx = NVME_UUID_NONE,
		.rae = false,
		.ot = false,
	};
	return nvme_get_log_page(fd, NVME_LOG_PAGE_PDU_SIZE, &args);
}

/**
 * nvme_get_log_device_self_test() - Retrieve the device self test log
 * @fd:		File descriptor of nvme device
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
 * nvme_get_log_create_telemetry_host() - Create host telemetry log
 * @fd:		File descriptor of nvme device
 * @log:	Userspace address of the log payload
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
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
		.lsp = NVME_LOG_TELEM_HOST_LSP_CREATE,
		.uuidx = NVME_UUID_NONE,
		.rae = false,
		.ot = false,
	};
	return nvme_get_log_page(fd, NVME_LOG_PAGE_PDU_SIZE, &args);
}

/**
 * nvme_get_log_telemetry_host() - Get Telemetry Host-Initiated log page
 * @fd:		File descriptor of nvme device
 * @offset:	Offset into the telemetry data
 * @len:	Length of provided user buffer to hold the log data in bytes
 * @log:	User address for log page data
 *
 * Retrieves the Telemetry Host-Initiated log page at the requested offset
 * using the previously existing capture.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
static inline int nvme_get_log_telemetry_host(int fd, __u64 offset,
			__u32 len, void *log)
{
	struct nvme_get_log_args args = {
		.lpo = offset,
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
		.lsp = NVME_LOG_TELEM_HOST_LSP_RETAIN,
		.uuidx = NVME_UUID_NONE,
		.rae = false,
		.ot = false,
	};
	return nvme_get_log_page(fd, NVME_LOG_PAGE_PDU_SIZE, &args);
}

/**
 * nvme_get_log_telemetry_ctrl() - Get Telemetry Controller-Initiated log page
 * @fd:		File descriptor of nvme device
 * @rae:	Retain asynchronous events
 * @offset:	Offset into the telemetry data
 * @len:	Length of provided user buffer to hold the log data in bytes
 * @log:	User address for log page data
 *
 * Retrieves the Telemetry Controller-Initiated log page at the requested offset
 * using the previously existing capture.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
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
		.lsp = NVME_LOG_LSP_NONE,
		.uuidx = NVME_UUID_NONE,
		.rae = rae,
		.ot = false,
	};
	return nvme_get_log_page(fd, NVME_LOG_PAGE_PDU_SIZE, &args);
}

/**
 * nvme_get_log_endurance_group() - Get Endurance Group log
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
		.lsp = NVME_LOG_LSP_NONE,
		.uuidx = NVME_UUID_NONE,
		.rae = false,
		.ot = false,
	};
	return nvme_get_log_page(fd, NVME_LOG_PAGE_PDU_SIZE, &args);
}

/**
 * nvme_get_log_predictable_lat_nvmset() - Predictable Latency Per NVM Set
 * @fd:		File descriptor of nvme device
 * @nvmsetid:	NVM set id
 * @log:	User address to store the predictable latency log
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
		.lsp = NVME_LOG_LSP_NONE,
		.uuidx = NVME_UUID_NONE,
		.rae = false,
		.ot = false,
	};
	return nvme_get_log_page(fd, NVME_LOG_PAGE_PDU_SIZE, &args);
}

/**
 * nvme_get_log_predictable_lat_event() - Retrieve Predictable Latency Event Aggregate Log Page
 * @fd:		File descriptor of nvme device
 * @rae:	Retain asynchronous events
 * @offset:	Offset into the predictable latency event
 * @len:	Length of provided user buffer to hold the log data in bytes
 * @log:	User address for log page data
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
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
		.lsp = NVME_LOG_LSP_NONE,
		.uuidx = NVME_UUID_NONE,
		.rae = rae,
		.ot = false,
	};
	return nvme_get_log_page(fd, NVME_LOG_PAGE_PDU_SIZE, &args);
}

/**
 * nvme_get_log_fdp_configurations() - Get list of Flexible Data Placement configurations
 * @fd:		File descriptor of nvme device
 * @egid:	Endurance group identifier
 * @offset:	Offset into log page
 * @len:	Length (in bytes) of provided user buffer to hold the log data
 * @log:	Log page data buffer
 */
static inline int nvme_get_log_fdp_configurations(int fd, __u16 egid,
			__u32 offset, __u32 len, void *log)
{
	struct nvme_get_log_args args = {
		.lpo = offset,
		.result = NULL,
		.log = log,
		.args_size = sizeof(args),
		.fd = fd,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.lid = NVME_LOG_LID_FDP_CONFIGS,
		.len = len,
		.nsid = NVME_NSID_NONE,
		.csi = NVME_CSI_NVM,
		.lsi = egid,
		.lsp = NVME_LOG_LSP_NONE,
		.uuidx = NVME_UUID_NONE,
	};

	return nvme_get_log(&args);
}

/**
 * nvme_get_log_reclaim_unit_handle_usage() - Get reclaim unit handle usage
 * @fd:		File descriptor of nvme device
 * @egid:	Endurance group identifier
 * @offset:	Offset into log page
 * @len:	Length (in bytes) of provided user buffer to hold the log data
 * @log:	Log page data buffer
 */
static inline int nvme_get_log_reclaim_unit_handle_usage(int fd, __u16 egid,
			__u32 offset, __u32 len, void *log)
{
	struct nvme_get_log_args args = {
		.lpo = offset,
		.result = NULL,
		.log = log,
		.args_size = sizeof(args),
		.fd = fd,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.lid = NVME_LOG_LID_FDP_RUH_USAGE,
		.len = len,
		.nsid = NVME_NSID_NONE,
		.csi = NVME_CSI_NVM,
		.lsi = egid,
		.lsp = NVME_LOG_LSP_NONE,
		.uuidx = NVME_UUID_NONE,
	};

	return nvme_get_log(&args);
}

/**
 * nvme_get_log_fdp_stats() - Get Flexible Data Placement statistics
 * @fd:		File descriptor of nvme device
 * @egid:	Endurance group identifier
 * @offset:	Offset into log page
 * @len:	Length (in bytes) of provided user buffer to hold the log data
 * @log:	Log page data buffer
 */
static inline int nvme_get_log_fdp_stats(int fd, __u16 egid, __u32 offset, __u32 len, void *log)
{
	struct nvme_get_log_args args = {
		.lpo = offset,
		.result = NULL,
		.log = log,
		.args_size = sizeof(args),
		.fd = fd,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.lid = NVME_LOG_LID_FDP_STATS,
		.len = len,
		.nsid = NVME_NSID_NONE,
		.csi = NVME_CSI_NVM,
		.lsi = egid,
		.lsp = NVME_LOG_LSP_NONE,
		.uuidx = NVME_UUID_NONE,
	};

	return nvme_get_log(&args);
}

/**
 * nvme_get_log_fdp_events() - Get Flexible Data Placement events
 * @fd:			File descriptor of nvme device
 * @egid:		Endurance group identifier
 * @host_events:	Whether to report host or controller events
 * @offset:		Offset into log page
 * @len:		Length (in bytes) of provided user buffer to hold the log data
 * @log:		Log page data buffer
 */
static inline int nvme_get_log_fdp_events(int fd, __u16 egid, bool host_events, __u32 offset,
		__u32 len, void *log)
{
	struct nvme_get_log_args args = {
		.lpo = offset,
		.result = NULL,
		.log = log,
		.args_size = sizeof(args),
		.fd = fd,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.lid = NVME_LOG_LID_FDP_EVENTS,
		.len = len,
		.nsid = NVME_NSID_NONE,
		.csi = NVME_CSI_NVM,
		.lsi = egid,
		.lsp = (__u8)(host_events ? 0x1 : 0x0),
		.uuidx = NVME_UUID_NONE,
	};

	return nvme_get_log(&args);
}

/**
 * nvme_get_log_ana() - Retrieve Asymmetric Namespace Access log page
 * @fd:		File descriptor of nvme device
 * @lsp:	Log specific, see &enum nvme_get_log_ana_lsp
 * @rae:	Retain asynchronous events
 * @offset:	Offset to the start of the log page
 * @len:	The allocated length of the log page
 * @log:	User address to store the ana log
 *
 * This log consists of a header describing the log and descriptors containing
 * the asymmetric namespace access information for ANA Groups that contain
 * namespaces that are attached to the controller processing the command.
 *
 * See &struct nvme_ana_log for the definition of the returned structure.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
static inline int nvme_get_log_ana(int fd, enum nvme_log_ana_lsp lsp, bool rae,
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
		.lsp = (__u8)lsp,
		.uuidx = NVME_UUID_NONE,
		.rae = rae,
		.ot = false,
	};
	return nvme_get_log_page(fd, NVME_LOG_PAGE_PDU_SIZE, &args);
}

/**
 * nvme_get_log_ana_groups() - Retrieve Asymmetric Namespace Access groups only log page
 * @fd:		File descriptor of nvme device
 * @rae:	Retain asynchronous events
 * @len:	The allocated length of the log page
 * @log:	User address to store the ana group log
 *
 * See &struct nvme_ana_log for the definition of the returned structure.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
static inline int nvme_get_log_ana_groups(int fd, bool rae, __u32 len,
			    struct nvme_ana_log *log)
{
	return nvme_get_log_ana(fd, NVME_LOG_ANA_LSP_RGO_GROUPS_ONLY, rae, 0,
				len, log);
}

/**
 * nvme_get_ana_log_atomic() - Retrieve Asymmetric Namespace Access log page atomically
 * @fd:		File descriptor of nvme device
 * @rgo:	Whether to retrieve ANA groups only (no NSIDs)
 * @rae:	Whether to retain asynchronous events
 * @retries:	The maximum number of times to retry on log page changes
 * @log:	Pointer to a buffer to receive the ANA log page
 * @len:	Input: the length of the log page buffer.
 * 		Output: the actual length of the ANA log page.
 *
 * See &struct nvme_ana_log for the definition of the returned structure.
 *
 * Return: If successful, returns 0 and sets *len to the actual log page length.
 * If unsuccessful, returns the nvme command status if a response was received
 * (see &enum nvme_status_field) or -1 with errno set otherwise.
 * Sets errno = EINVAL if retries == 0.
 * Sets errno = EAGAIN if unable to read the log page atomically
 * because chgcnt changed during each of the retries attempts.
 * Sets errno = ENOSPC if the full log page does not fit in the provided buffer.
 */
int nvme_get_ana_log_atomic(int fd, bool rgo, bool rae, unsigned int retries,
			    struct nvme_ana_log *log, __u32 *len);

/**
 * nvme_get_log_lba_status() - Retrieve LBA Status
 * @fd:		File descriptor of nvme device
 * @rae:	Retain asynchronous events
 * @offset:	Offset to the start of the log page
 * @len:	The allocated length of the log page
 * @log:	User address to store the log page
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
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
		.lsp = NVME_LOG_LSP_NONE,
		.uuidx = NVME_UUID_NONE,
		.rae = rae,
		.ot = false,
	};
	return nvme_get_log_page(fd, NVME_LOG_PAGE_PDU_SIZE, &args);
}

/**
 * nvme_get_log_endurance_grp_evt() - Retrieve Rotational Media Information
 * @fd:		File descriptor of nvme device
 * @rae:	Retain asynchronous events
 * @offset:	Offset to the start of the log page
 * @len:	The allocated length of the log page
 * @log:	User address to store the log page
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
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
		.lsp = NVME_LOG_LSP_NONE,
		.uuidx = NVME_UUID_NONE,
		.rae = rae,
		.ot = false,
	};
	return nvme_get_log_page(fd, NVME_LOG_PAGE_PDU_SIZE, &args);
}

/**
 * nvme_get_log_fid_supported_effects() - Retrieve Feature Identifiers Supported and Effects
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
 * nvme_get_log_mi_cmd_supported_effects() - displays the MI Commands Supported by the controller
 * @fd:     File descriptor of nvme device
 * @rae:    Retain asynchronous events
 * @log:    MI Command Supported and Effects data structure
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise
 */
static inline int nvme_get_log_mi_cmd_supported_effects(int fd, bool rae,
			struct nvme_mi_cmd_supported_effects_log *log)
{
	return nvme_get_nsid_log(fd, rae, NVME_LOG_LID_MI_CMD_SUPPORTED_EFFECTS,
				 NVME_NSID_NONE, sizeof(*log), log);
}

/**
 * nvme_get_log_boot_partition() - Retrieve Boot Partition
 * @fd:		File descriptor of nvme device
 * @rae:	Retain asynchronous events
 * @lsp:	The log specified field of LID
 * @len:	The allocated size, minimum
 *		struct nvme_boot_partition
 * @part:	User address to store the log page
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
		.lsp = lsp,
		.uuidx = NVME_UUID_NONE,
		.rae = rae,
		.ot = false,
	};
	return nvme_get_log_page(fd, NVME_LOG_PAGE_PDU_SIZE, &args);
}

/**
 * nvme_get_log_phy_rx_eom() - Retrieve Physical Interface Receiver Eye Opening Measurement Log
 * @fd:		File descriptor of nvme device
 * @lsp:	Log specific, controls action and measurement quality
 * @controller:	Target controller ID
 * @len:	The allocated size, minimum
 *		struct nvme_phy_rx_eom_log
 * @log:	User address to store the log page
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise
 */
static inline int nvme_get_log_phy_rx_eom(int fd, __u8 lsp, __u16 controller,
				__u32 len, struct nvme_phy_rx_eom_log *log)
{
	struct nvme_get_log_args args = {
		.lpo = 0,
		.result = NULL,
		.log = log,
		.args_size = sizeof(args),
		.fd = fd,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.lid = NVME_LOG_LID_PHY_RX_EOM,
		.len = len,
		.nsid = NVME_NSID_NONE,
		.csi = NVME_CSI_NVM,
		.lsi = controller,
		.lsp = lsp,
		.uuidx = NVME_UUID_NONE,
		.rae = false,
		.ot = false,
	};
	return nvme_get_log_page(fd, NVME_LOG_PAGE_PDU_SIZE, &args);
}

/**
 * nvme_get_log_discovery() - Retrieve Discovery log page
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
		.lsp = NVME_LOG_LSP_NONE,
		.uuidx = NVME_UUID_NONE,
		.rae = rae,
		.ot = false,
	};
	return nvme_get_log_page(fd, NVME_LOG_PAGE_PDU_SIZE, &args);
}

/**
 * nvme_get_log_media_unit_stat() - Retrieve Media Unit Status
 * @fd:		File descriptor of nvme device
 * @domid:	Domain Identifier selection, if supported
 * @mus:	User address to store the Media Unit statistics log
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
		.lsi = domid,
		.lsp = NVME_LOG_LSP_NONE,
		.uuidx = NVME_UUID_NONE,
		.rae = false,
		.ot = false,
	};
	return nvme_get_log_page(fd, NVME_LOG_PAGE_PDU_SIZE, &args);
}

/**
 * nvme_get_log_support_cap_config_list() - Retrieve Supported Capacity Configuration List
 * @fd:		File descriptor of nvme device
 * @domid:	Domain Identifier selection, if supported
 * @cap:	User address to store supported capabilities config list
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise
 */
static inline int nvme_get_log_support_cap_config_list(int fd, __u16 domid,
			struct nvme_supported_cap_config_list_log *cap)
{
	struct nvme_get_log_args args = {
		.lpo = 0,
		.result = NULL,
		.log = cap,
		.args_size = sizeof(args),
		.fd = fd,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.lid = NVME_LOG_LID_SUPPORTED_CAP_CONFIG_LIST,
		.len = sizeof(*cap),
		.nsid = NVME_NSID_NONE,
		.csi = NVME_CSI_NVM,
		.lsi = domid,
		.lsp = NVME_LOG_LSP_NONE,
		.uuidx = NVME_UUID_NONE,
		.rae = false,
		.ot = false,
	};
	return nvme_get_log_page(fd, NVME_LOG_PAGE_PDU_SIZE, &args);
}

/**
 * nvme_get_log_reservation() - Retrieve Reservation Notification
 * @fd:		File descriptor of nvme device
 * @rae:	Retain asynchronous events
 * @log:	User address to store the reservation log
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise
 */
static inline int nvme_get_log_reservation(int fd, bool rae,
			struct nvme_resv_notification_log *log)
{
	return nvme_get_nsid_log(fd, rae, NVME_LOG_LID_RESERVATION,
				 NVME_NSID_ALL, sizeof(*log), log);
}

/**
 * nvme_get_log_sanitize() - Retrieve Sanitize Status
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
 * nvme_get_log_zns_changed_zones() - Retrieve list of zones that have changed
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
		.lsp = NVME_LOG_LSP_NONE,
		.uuidx = NVME_UUID_NONE,
		.rae = rae,
		.ot = false,
	};
	return nvme_get_log_page(fd, NVME_LOG_PAGE_PDU_SIZE, &args);
}

/**
 * nvme_get_log_persistent_event() - Retrieve Persistent Event Log
 * @fd:		File descriptor of nvme device
 * @action:	Action the controller should take during processing this command
 * @size:	Size of @pevent_log
 * @pevent_log:	User address to store the persistent event log
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
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
		.lsp = (__u8)action,
		.uuidx = NVME_UUID_NONE,
		.rae = false,
		.ot = false,
	};
	return nvme_get_log_page(fd, NVME_LOG_PAGE_PDU_SIZE, &args);
}

/**
 * nvme_set_features() - Set a feature attribute
 * @args:	&struct nvme_set_features_args argument structure
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_features(struct nvme_set_features_args *args);

/**
 * nvme_set_features_data() - Helper function for @nvme_set_features()
 * @fd:		File descriptor of nvme device
 * @fid:	Feature identifier
 * @nsid:	Namespace ID, if applicable
 * @cdw11:	Value to set the feature to
 * @save:	Save value across power states
 * @data_len:	Length of feature data, if applicable, in bytes
 * @data:	User address of feature data, if applicable
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
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
		.cdw13 = 0,
		.cdw15 = 0,
		.data_len = data_len,
		.save = save,
		.uuidx = NVME_UUID_NONE,
		.fid = fid,
	};
	return nvme_set_features(&args);
}

/**
 * nvme_set_features_simple() - Helper function for @nvme_set_features()
 * @fd:		File descriptor of nvme device
 * @fid:	Feature identifier
 * @nsid:	Namespace ID, if applicable
 * @cdw11:	Value to set the feature to
 * @save:	Save value across power states
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
static inline int nvme_set_features_simple(int fd, __u8 fid, __u32 nsid,
			__u32 cdw11, bool save, __u32 *result)
{
	return nvme_set_features_data(fd, fid, nsid, cdw11, save, 0, NULL,
				 result);
}

/**
 * nvme_set_features_arbitration() - Set arbitration features
 * @fd:		File descriptor of nvme device
 * @ab:		Arbitration Burst
 * @lpw:	Low Priority Weight
 * @mpw:	Medium Priority Weight
 * @hpw:	High Priority Weight
 * @save:	Save value across power states
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_features_arbitration(int fd, __u8 ab, __u8 lpw, __u8 mpw,
				  __u8 hpw, bool  save, __u32 *result);

/**
 * nvme_set_features_power_mgmt() - Set power management feature
 * @fd:		File descriptor of nvme device
 * @ps:		Power State
 * @wh:		Workload Hint
 * @save:	Save value across power states
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_features_power_mgmt(int fd, __u8 ps, __u8 wh, bool save,
				 __u32 *result);

/**
 * nvme_set_features_lba_range() - Set LBA range feature
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace ID
 * @nr_ranges:	Number of ranges in @data
 * @save:	Save value across power states
 * @data:	User address of feature data
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_features_lba_range(int fd, __u32 nsid, __u8 nr_ranges, bool save,
				struct nvme_lba_range_type *data, __u32 *result);

/**
 * nvme_set_features_temp_thresh() - Set temperature threshold feature
 * @fd:		File descriptor of nvme device
 * @tmpth:	Temperature Threshold
 * @tmpsel:	Threshold Temperature Select
 * @thsel:	Threshold Type Select
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
 * nvme_set_features_err_recovery() - Set error recovery feature
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace ID
 * @tler:	Time-limited error recovery value
 * @dulbe:	Deallocated or Unwritten Logical Block Error Enable
 * @save:	Save value across power states
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_features_err_recovery(int fd, __u32 nsid, __u16 tler,
				   bool dulbe, bool save, __u32 *result);

/**
 * nvme_set_features_volatile_wc() - Set volatile write cache feature
 * @fd:		File descriptor of nvme device
 * @wce:	Write cache enable
 * @save:	Save value across power states
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_features_volatile_wc(int fd, bool wce, bool save,
				  __u32 *result);

/**
 * nvme_set_features_irq_coalesce() - Set IRQ coalesce feature
 * @fd:		File descriptor of nvme device
 * @thr:	Aggregation Threshold
 * @time:	Aggregation Time
 * @save:	Save value across power states
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_features_irq_coalesce(int fd, __u8 thr, __u8 time,
				   bool save, __u32 *result);

/**
 * nvme_set_features_irq_config() - Set IRQ config feature
 * @fd:		File descriptor of nvme device
 * @iv:		Interrupt Vector
 * @cd:		Coalescing Disable
 * @save:	Save value across power states
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_features_irq_config(int fd, __u16 iv, bool cd, bool save,
				 __u32 *result);

/**
 * nvme_set_features_write_atomic() - Set write atomic feature
 * @fd:		File descriptor of nvme device
 * @dn:		Disable Normal
 * @save:	Save value across power states
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_features_write_atomic(int fd, bool dn, bool save,
				   __u32 *result);

/**
 * nvme_set_features_async_event() - Set asynchronous event feature
 * @fd:		File descriptor of nvme device
 * @events:	Events to enable
 * @save:	Save value across power states
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_features_async_event(int fd, __u32 events, bool save,
				  __u32 *result);

/**
 * nvme_set_features_auto_pst() - Set autonomous power state feature
 * @fd:		File descriptor of nvme device
 * @apste:	Autonomous Power State Transition Enable
 * @apst:	Autonomous Power State Transition
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
 * nvme_set_features_timestamp() - Set timestamp feature
 * @fd:		File descriptor of nvme device
 * @save:	Save value across power states
 * @timestamp:	The current timestamp value to assign to this feature
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_features_timestamp(int fd, bool save, __u64 timestamp);

/**
 * nvme_set_features_hctm() - Set thermal management feature
 * @fd:		File descriptor of nvme device
 * @tmt2:	Thermal Management Temperature 2
 * @tmt1:	Thermal Management Temperature 1
 * @save:	Save value across power states
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_features_hctm(int fd, __u16 tmt2, __u16 tmt1, bool save,
			   __u32 *result);

/**
 * nvme_set_features_nopsc() - Set non-operational power state feature
 * @fd:		File descriptor of nvme device
 * @noppme:	Non-Operational Power State Permissive Mode Enable
 * @save:	Save value across power states
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_features_nopsc(int fd, bool noppme, bool save, __u32 *result);

/**
 * nvme_set_features_rrl() - Set read recovery level feature
 * @fd:		File descriptor of nvme device
 * @rrl:	Read recovery level setting
 * @nvmsetid:	NVM set id
 * @save:	Save value across power states
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_features_rrl(int fd, __u8 rrl, __u16 nvmsetid, bool save,
			  __u32 *result);

/**
 * nvme_set_features_plm_config() - Set predictable latency feature
 * @fd:		File descriptor of nvme device
 * @enable:	Predictable Latency Enable
 * @nvmsetid:	NVM Set Identifier
 * @save:	Save value across power states
 * @data:	Pointer to structure nvme_plm_config
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_features_plm_config(int fd, bool enable, __u16 nvmsetid,
				 bool save, struct nvme_plm_config *data,
				 __u32 *result);

/**
 * nvme_set_features_plm_window() - Set window select feature
 * @fd:		File descriptor of nvme device
 * @sel:	Window Select
 * @nvmsetid:	NVM Set Identifier
 * @save:	Save value across power states
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_features_plm_window(int fd, enum nvme_feat_plm_window_select sel,
				 __u16 nvmsetid, bool save, __u32 *result);

/**
 * nvme_set_features_lba_sts_interval() - Set LBA status information feature
 * @fd:		File descriptor of nvme device
 * @save:	Save value across power states
 * @lsiri:	LBA Status Information Report Interval
 * @lsipi:	LBA Status Information Poll Interval
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_features_lba_sts_interval(int fd, __u16 lsiri, __u16 lsipi,
				       bool save, __u32 *result);

/**
 * nvme_set_features_host_behavior() - Set host behavior feature
 * @fd:		File descriptor of nvme device
 * @save:	Save value across power states
 * @data:	Pointer to structure nvme_feat_host_behavior
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_features_host_behavior(int fd, bool save,
				    struct nvme_feat_host_behavior *data);

/**
 * nvme_set_features_sanitize() - Set sanitize feature
 * @fd:		File descriptor of nvme device
 * @nodrm:	No-Deallocate Response Mode
 * @save:	Save value across power states
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_features_sanitize(int fd, bool nodrm, bool save, __u32 *result);

/**
 * nvme_set_features_endurance_evt_cfg() - Set endurance event config feature
 * @fd:		File descriptor of nvme device
 * @endgid:	Endurance Group Identifier
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
 * nvme_set_features_sw_progress() - Set pre-boot software load count feature
 * @fd:		File descriptor of nvme device
 * @pbslc:	Pre-boot Software Load Count
 * @save:	Save value across power states
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_features_sw_progress(int fd, __u8 pbslc, bool save,
				  __u32 *result);

/**
 * nvme_set_features_host_id() - Set enable extended host identifiers feature
 * @fd:		File descriptor of nvme device
 * @exhid:	Enable Extended Host Identifier
 * @save:	Save value across power states
 * @hostid:	Host ID to set
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_features_host_id(int fd, bool exhid, bool save, __u8 *hostid);

/**
 * nvme_set_features_resv_mask() - Set reservation notification mask feature
 *
 * Deprecated: doesn't support specifying a NSID.
 * Use nvme_set_features_resv_mask2() instead.
 *
 * @fd:		File descriptor of nvme device
 * @mask:	Reservation Notification Mask Field
 * @save:	Save value across power states
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_features_resv_mask(int fd, __u32 mask, bool save, __u32 *result)
	__attribute__((deprecated));

/**
 * nvme_set_features_resv_mask2() - Set reservation notification mask feature
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace ID
 * @mask:	Reservation Notification Mask Field
 * @save:	Save value across power states
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_features_resv_mask2(int fd, __u32 nsid, __u32 mask, bool save,
				 __u32 *result);

/**
 * nvme_set_features_resv_persist() - Set persist through power loss feature
 *
 * Deprecated: doesn't support specifying a NSID.
 * Use nvme_set_features_resv_persist2() instead.
 *
 * @fd:		File descriptor of nvme device
 * @ptpl:	Persist Through Power Loss
 * @save:	Save value across power states
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_features_resv_persist(int fd, bool ptpl, bool save, __u32 *result)
	 __attribute__((deprecated));

/**
 * nvme_set_features_resv_persist2() - Set persist through power loss feature
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace ID
 * @ptpl:	Persist Through Power Loss
 * @save:	Save value across power states
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_features_resv_persist2(int fd, __u32 nsid, bool ptpl, bool save,
				    __u32 *result);

/**
 * nvme_set_features_write_protect() - Set write protect feature
 *
 * Deprecated: doesn't support specifying a NSID.
 * Use nvme_set_features_write_protect2() instead.
 *
 * @fd:		File descriptor of nvme device
 * @state:	Write Protection State
 * @save:	Save value across power states
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_features_write_protect(int fd, enum nvme_feat_nswpcfg_state state,
				    bool save, __u32 *result)
	__attribute__((deprecated));

/**
 * nvme_set_features_write_protect2() - Set write protect feature
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace ID
 * @state:	Write Protection State
 * @save:	Save value across power states
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_features_write_protect2(int fd, __u32 nsid,
				     enum nvme_feat_nswpcfg_state state,
				     bool save, __u32 *result);

/**
 * nvme_set_features_iocs_profile() - Set I/O command set profile feature
 * @fd:		File descriptor of nvme device
 * @iocsi:	I/O Command Set Combination Index
 * @save:	Save value across power states
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_set_features_iocs_profile(int fd, __u16 iocsi, bool save);

/**
 * nvme_get_features() - Retrieve a feature attribute
 * @args:	&struct nvme_get_features_args argument structure
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_features(struct nvme_get_features_args *args);

/**
 * nvme_get_features_data() - Helper function for @nvme_get_features()
 * @fd:		File descriptor of nvme device
 * @fid:	Feature identifier
 * @nsid:	Namespace ID, if applicable
 * @data_len:	Length of feature data, if applicable, in bytes
 * @data:	User address of feature data, if applicable
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
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
		.fid = (__u8)fid,
		.uuidx = NVME_UUID_NONE,
	};

	return nvme_get_features(&args);
}

/**
 * nvme_get_features_simple() - Helper function for @nvme_get_features()
 * @fd:		File descriptor of nvme device
 * @fid:	Feature identifier
 * @nsid:	Namespace ID, if applicable
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
static inline int nvme_get_features_simple(int fd, enum nvme_features_id fid,
			__u32 nsid, __u32 *result)
{
	return nvme_get_features_data(fd, fid, nsid, 0, NULL, result);
}

/**
 * nvme_get_features_arbitration() - Get arbitration feature
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
 * nvme_get_features_power_mgmt() - Get power management feature
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
 * nvme_get_features_lba_range() - Get LBA range feature
 *
 * Deprecated: doesn't support specifying a NSID.
 * Use nvme_get_features_lba_range2() instead.
 *
 * @fd:		File descriptor of nvme device
 * @sel:	Select which type of attribute to return, see &enum nvme_get_features_sel
 * @data:	User address of feature data, if applicable
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_features_lba_range(int fd, enum nvme_get_features_sel sel,
				struct nvme_lba_range_type *data,
				__u32 *result) __attribute__((deprecated));

/**
 * nvme_get_features_lba_range2() - Get LBA range feature
 * @fd:		File descriptor of nvme device
 * @sel:	Select which type of attribute to return, see &enum nvme_get_features_sel
 * @nsid:	Namespace ID
 * @data:	Buffer to receive LBA Range Type data structure
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_features_lba_range2(int fd, enum nvme_get_features_sel sel,
				 __u32 nsid, struct nvme_lba_range_type *data,
				 __u32 *result);

/**
 * nvme_get_features_temp_thresh() - Get temperature threshold feature
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
 * nvme_get_features_err_recovery() - Get error recovery feature
 *
 * Deprecated: doesn't support specifying a NSID.
 * Use nvme_get_features_err_recovery2() instead.
 *
 * @fd:		File descriptor of nvme device
 * @sel:	Select which type of attribute to return, see &enum nvme_get_features_sel
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_features_err_recovery(int fd, enum nvme_get_features_sel sel,
				   __u32 *result) __attribute__((deprecated));

/**
 * nvme_get_features_err_recovery2() - Get error recovery feature
 * @fd:		File descriptor of nvme device
 * @sel:	Select which type of attribute to return, see &enum nvme_get_features_sel
 * @nsid:	Namespace ID
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_features_err_recovery2(int fd, enum nvme_get_features_sel sel,
				    __u32 nsid, __u32 *result);

/**
 * nvme_get_features_volatile_wc() - Get volatile write cache feature
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
 * nvme_get_features_num_queues() - Get number of queues feature
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
 * nvme_get_features_irq_coalesce() - Get IRQ coalesce feature
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
 * nvme_get_features_irq_config() - Get IRQ config feature
 * @fd:		File descriptor of nvme device
 * @sel:	Select which type of attribute to return, see &enum nvme_get_features_sel
 * @iv:
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_features_irq_config(int fd, enum nvme_get_features_sel sel,
				 __u16 iv, __u32 *result);

/**
 * nvme_get_features_write_atomic() - Get write atomic feature
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
 * nvme_get_features_async_event() - Get asynchronous event feature
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
 * nvme_get_features_auto_pst() - Get autonomous power state feature
 * @fd:		File descriptor of nvme device
 * @sel:	Select which type of attribute to return, see &enum nvme_get_features_sel
 * @apst:
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_features_auto_pst(int fd, enum nvme_get_features_sel sel,
			       struct nvme_feat_auto_pst *apst, __u32 *result);

/**
 * nvme_get_features_host_mem_buf() - Get host memory buffer feature
 *
 * Deprecated: doesn't fetch the Host Memory Buffer Attributes data structure.
 * Use nvme_get_features_host_mem_buf2() instead.
 *
 * @fd:		File descriptor of nvme device
 * @sel:	Select which type of attribute to return, see &enum nvme_get_features_sel
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_features_host_mem_buf(int fd, enum nvme_get_features_sel sel,
				   __u32 *result) __attribute__((deprecated));

/**
 * nvme_get_features_host_mem_buf2() - Get host memory buffer feature
 * @fd:		File descriptor of nvme device
 * @sel:	Select which type of attribute to return, see &enum nvme_get_features_sel
 * @attrs:	Buffer for returned Host Memory Buffer Attributes
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_features_host_mem_buf2(int fd, enum nvme_get_features_sel sel,
				    struct nvme_host_mem_buf_attrs *attrs,
				    __u32 *result);

/**
 * nvme_get_features_timestamp() - Get timestamp feature
 * @fd:		File descriptor of nvme device
 * @sel:	Select which type of attribute to return, see &enum nvme_get_features_sel
 * @ts:		Current timestamp
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_features_timestamp(int fd, enum nvme_get_features_sel sel,
				struct nvme_timestamp *ts);

/**
 * nvme_get_features_kato() - Get keep alive timeout feature
 * @fd:		File descriptor of nvme device
 * @sel:	Select which type of attribute to return, see &enum nvme_get_features_sel
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_features_kato(int fd, enum nvme_get_features_sel sel, __u32 *result);

/**
 * nvme_get_features_hctm() - Get thermal management feature
 * @fd:		File descriptor of nvme device
 * @sel:	Select which type of attribute to return, see &enum nvme_get_features_sel
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_features_hctm(int fd, enum nvme_get_features_sel sel, __u32 *result);

/**
 * nvme_get_features_nopsc() - Get non-operational power state feature
 * @fd:		File descriptor of nvme device
 * @sel:	Select which type of attribute to return, see &enum nvme_get_features_sel
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_features_nopsc(int fd, enum nvme_get_features_sel sel, __u32 *result);

/**
 * nvme_get_features_rrl() - Get read recovery level feature
 * @fd:		File descriptor of nvme device
 * @sel:	Select which type of attribute to return, see &enum nvme_get_features_sel
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_features_rrl(int fd, enum nvme_get_features_sel sel, __u32 *result);

/**
 * nvme_get_features_plm_config() - Get predictable latency feature
 * @fd:		File descriptor of nvme device
 * @sel:	Select which type of attribute to return, see &enum nvme_get_features_sel
 * @nvmsetid:	NVM set id
 * @data:
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_features_plm_config(int fd, enum nvme_get_features_sel sel,
				 __u16 nvmsetid, struct nvme_plm_config *data,
				 __u32 *result);

/**
 * nvme_get_features_plm_window() - Get window select feature
 * @fd:		File descriptor of nvme device
 * @sel:	Select which type of attribute to return, see &enum nvme_get_features_sel
 * @nvmsetid:	NVM set id
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_features_plm_window(int fd, enum nvme_get_features_sel sel,
	__u16 nvmsetid, __u32 *result);

/**
 * nvme_get_features_lba_sts_interval() - Get LBA status information feature
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
 * nvme_get_features_host_behavior() - Get host behavior feature
 * @fd:		File descriptor of nvme device
 * @sel:	Select which type of attribute to return, see &enum nvme_get_features_sel
 * @data:	Pointer to structure nvme_feat_host_behavior
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_features_host_behavior(int fd, enum nvme_get_features_sel sel,
				    struct nvme_feat_host_behavior *data,
				    __u32 *result);

/**
 * nvme_get_features_sanitize() - Get sanitize feature
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
 * nvme_get_features_endurance_event_cfg() - Get endurance event config feature
 * @fd:		File descriptor of nvme device
 * @sel:	Select which type of attribute to return, see &enum nvme_get_features_sel
 * @endgid:	Endurance Group Identifier
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_features_endurance_event_cfg(int fd, enum nvme_get_features_sel sel,
					  __u16 endgid, __u32 *result);

/**
 * nvme_get_features_sw_progress() - Get software progress feature
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
 * nvme_get_features_host_id() - Get host id feature
 * @fd:		File descriptor of nvme device
 * @sel:	Select which type of attribute to return, see &enum nvme_get_features_sel
 * @exhid:	Enable Extended Host Identifier
 * @len:	Length of @hostid
 * @hostid:	Buffer for returned host ID
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_features_host_id(int fd, enum nvme_get_features_sel sel,
			      bool exhid, __u32 len, __u8 *hostid);

/**
 * nvme_get_features_resv_mask() - Get reservation mask feature
 *
 * Deprecated: doesn't support specifying a NSID.
 * Use nvme_get_features_resv_mask2() instead.
 *
 * @fd:		File descriptor of nvme device
 * @sel:	Select which type of attribute to return, see &enum nvme_get_features_sel
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_features_resv_mask(int fd, enum nvme_get_features_sel sel,
				__u32 *result) __attribute__((deprecated));

/**
 * nvme_get_features_resv_mask2() - Get reservation mask feature
 * @fd:		File descriptor of nvme device
 * @sel:	Select which type of attribute to return, see &enum nvme_get_features_sel
 * @nsid:	Namespace ID
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_features_resv_mask2(int fd, enum nvme_get_features_sel sel,
				 __u32 nsid, __u32 *result);

/**
 * nvme_get_features_resv_persist() - Get reservation persist feature
 *
 * Deprecated: doesn't support specifying a NSID.
 * Use nvme_get_features_resv_persist2() instead.
 *
 * @fd:		File descriptor of nvme device
 * @sel:	Select which type of attribute to return, see &enum nvme_get_features_sel
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_features_resv_persist(int fd, enum nvme_get_features_sel sel,
				   __u32 *result) __attribute__((deprecated));

/**
 * nvme_get_features_resv_persist2() - Get reservation persist feature
 * @fd:		File descriptor of nvme device
 * @sel:	Select which type of attribute to return, see &enum nvme_get_features_sel
 * @nsid:	Namespace ID
 * @result:	The command completion result from CQE dword0
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_features_resv_persist2(int fd, enum nvme_get_features_sel sel,
				    __u32 nsid, __u32 *result);

/**
 * nvme_get_features_write_protect() - Get write protect feature
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
 * nvme_get_features_iocs_profile() - Get IOCS profile feature
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
 * nvme_ns_mgmt() - Issue a Namespace management command
 * @args:	&struct nvme_ns_mgmt_args Argument structure
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_ns_mgmt(struct nvme_ns_mgmt_args *args);

/**
 * nvme_ns_mgmt_create() - Create a non attached namespace
 * @fd:		File descriptor of nvme device
 * @ns:		Namespace identification that defines ns creation parameters
 * @nsid:		On success, set to the namespace id that was created
 * @timeout:		Override the default timeout to this value in milliseconds;
 *			set to 0 to use the system default.
 * @csi:		Command Set Identifier
 * @data:	Host Software Specified Fields that defines ns creation parameters
 *
 * On successful creation, the namespace exists in the subsystem, but is not
 * attached to any controller. Use the nvme_ns_attach_ctrls() to assign the
 * namespace to one or more controllers.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
static inline int nvme_ns_mgmt_create(int fd, struct nvme_id_ns *ns,
			__u32 *nsid, __u32 timeout, __u8 csi,
			struct nvme_ns_mgmt_host_sw_specified *data)
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
		.rsvd1 = { 0, },
		.rsvd2 = NULL,
		.data = data,
	};

	return nvme_ns_mgmt(&args);
}

/**
 * nvme_ns_mgmt_delete_timeout() - Delete a non attached namespace with timeout
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace identifier to delete
 * @timeout:	Override the default timeout to this value in milliseconds;
 *		set to 0 to use the system default.
 *
 * It is recommended that a namespace being deleted is not attached to any
 * controller. Use the nvme_ns_detach_ctrls() first if the namespace is still
 * attached.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
static inline int nvme_ns_mgmt_delete_timeout(int fd, __u32 nsid, __u32 timeout)
{
	struct nvme_ns_mgmt_args args = {
		.result = NULL,
		.ns = NULL,
		.args_size = sizeof(args),
		.fd = fd,
		.timeout = timeout,
		.nsid = nsid,
		.sel = NVME_NS_MGMT_SEL_DELETE,
		.csi = 0,
		.rsvd1 = { 0, },
		.rsvd2 = NULL,
		.data = NULL,
	};

	return nvme_ns_mgmt(&args);
}

/**
 * nvme_ns_mgmt_delete() - Delete a non attached namespace
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace identifier to delete
 *
 * It is recommended that a namespace being deleted is not attached to any
 * controller. Use the nvme_ns_detach_ctrls() first if the namespace is still
 * attached.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
static inline int nvme_ns_mgmt_delete(int fd, __u32 nsid)
{
	return nvme_ns_mgmt_delete_timeout(fd, nsid, 0);
}

/**
 * nvme_ns_attach() - Attach or detach namespace to controller(s)
 * @args:	&struct nvme_ns_attach_args Argument structure
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_ns_attach(struct nvme_ns_attach_args *args);

/**
 * nvme_ns_attach_ctrls() - Attach namespace to controllers
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace ID to attach
 * @ctrlist:	Controller list to modify attachment state of nsid
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
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
 * nvme_ns_detach_ctrls() - Detach namespace from controllers
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace ID to detach
 * @ctrlist:	Controller list to modify attachment state of nsid
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
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
 * nvme_fw_download() - Download part or all of a firmware image to the
 *			controller
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
 * nvme_security_send() - Security Send command
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
 * nvme_security_receive() - Security Receive command
 * @args:	&struct nvme_security_receive argument structure
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_security_receive(struct nvme_security_receive_args *args);

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
 * nvme_directive_send_id_endir() - Directive Send Enable Directive
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace Identifier
 * @endir:	Enable Directive
 * @dtype:	Directive Type
 * @id:		Pointer to structure nvme_id_directives
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_directive_send_id_endir(int fd, __u32 nsid, bool endir,
				 enum nvme_directive_dtype dtype,
				 struct nvme_id_directives *id);

/**
 * nvme_directive_send_stream_release_identifier() - Directive Send Stream release
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace ID
 * @stream_id:	Stream identifier
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
 * nvme_directive_send_stream_release_resource() - Directive Send Stream release resources
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
 * nvme_directive_recv() - Receive directive specific data
 * @args:	&struct nvme_directive_recv_args argument structure
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_directive_recv(struct nvme_directive_recv_args *args);

/**
 * nvme_directive_recv_identify_parameters() - Directive receive identifier parameters
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace ID
 * @id:		Identify parameters buffer
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
 * nvme_directive_recv_stream_parameters() - Directive receive stream parameters
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace ID
 * @parms:	Streams directive parameters buffer
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
 * nvme_directive_recv_stream_status() - Directive receive stream status
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace ID
 * @nr_entries: Number of streams to receive
 * @id:		Stream status buffer
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
static inline int nvme_directive_recv_stream_status(int fd, __u32 nsid,
			unsigned int nr_entries,
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
 * nvme_directive_recv_stream_allocate() - Directive receive stream allocate
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace ID
 * @nsr:	Namespace Streams Requested
 * @result:	If successful, the CQE dword0 value
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
 * nvme_capacity_mgmt() - Capacity management command
 * @args:	&struct nvme_capacity_mgmt_args argument structure
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_capacity_mgmt(struct nvme_capacity_mgmt_args *args);

/**
 * nvme_lockdown() - Issue lockdown command
 * @args:	&struct nvme_lockdown_args argument structure
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_lockdown(struct nvme_lockdown_args *args);

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
 * Set the 'nsid' field to 0 to not include namespaces in the test. Set to
 * 0xffffffff to test all namespaces. All other values tests a specific
 * namespace, if present.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_dev_self_test(struct nvme_dev_self_test_args *args);

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
static inline int nvme_flush(int fd, __u32 nsid)
{
	struct nvme_passthru_cmd cmd = {};

	cmd.opcode = nvme_cmd_flush;
	cmd.nsid = nsid;

	return nvme_submit_io_passthru(fd, &cmd, NULL);
}

/**
 * nvme_io() - Submit an nvme user I/O command
 * @args:	&struct nvme_io_args argument structure
 * @opcode:	Opcode to execute
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
 * nvme_copy() - Copy command
 *
 * @args:	&struct nvme_copy_args argument structure
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_copy(struct nvme_copy_args *args);

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
 * nvme_resv_release() - Send an nvme reservation release
 * @args:	&struct nvme_resv_release_args argument structure
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_resv_release(struct nvme_resv_release_args *args);

/**
 * nvme_resv_report() - Send an nvme reservation report
 * @args:	struct nvme_resv_report_args argument structure
 *
 * Returns a Reservation Status data structure to memory that describes the
 * registration and reservation status of a namespace. See the definition for
 * the returned structure, &struct nvme_reservation_status, for more details.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_resv_report(struct nvme_resv_report_args *args);

/**
 * nvme_io_mgmt_recv() - I/O Management Receive command
 * @args:	&struct nvme_io_mgmt_recv_args argument structure
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_io_mgmt_recv(struct nvme_io_mgmt_recv_args *args);

/**
 * nvme_fdp_reclaim_unit_handle_status() - Get reclaim unit handle status
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace identifier
 * @data_len:	Length of response buffer
 * @data:	Response buffer
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
static inline int nvme_fdp_reclaim_unit_handle_status(int fd, __u32 nsid,
			__u32 data_len, void *data)
{
	struct nvme_io_mgmt_recv_args args = {
		.data = data,
		.args_size = sizeof(args),
		.fd = fd,
		.nsid = nsid,
		.data_len = data_len,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.mos = 0,
		.mo = NVME_IO_MGMT_RECV_RUH_STATUS,
	};

	return nvme_io_mgmt_recv(&args);
}

/**
 * nvme_io_mgmt_send() - I/O Management Send command
 * @args:	&struct nvme_io_mgmt_send_args argument structure
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_io_mgmt_send(struct nvme_io_mgmt_send_args *args);

/**
 * nvme_fdp_reclaim_unit_handle_update() - Update a list of reclaim unit handles
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace identifier
 * @npids:	Number of placement identifiers
 * @pids:	List of placement identifiers
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
static inline int nvme_fdp_reclaim_unit_handle_update(int fd, __u32 nsid,
			unsigned int npids, __u16 *pids)
{
	struct nvme_io_mgmt_send_args args = {
		.data = (void *)pids,
		.args_size = sizeof(args),
		.fd = fd,
		.nsid = nsid,
		.data_len = (__u32)(npids * sizeof(__u16)),
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.mos = (__u16)(npids - 1),
		.mo = NVME_IO_MGMT_SEND_RUH_UPDATE,
	};

	return nvme_io_mgmt_send(&args);
}

/**
 * nvme_zns_mgmt_send() - ZNS management send command
 * @args:	&struct nvme_zns_mgmt_send_args argument structure
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_zns_mgmt_send(struct nvme_zns_mgmt_send_args *args);


/**
 * nvme_zns_mgmt_recv() - ZNS management receive command
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
		.zrasf = (__u16)opts,
		.zras_feat = partial,
	};

	return nvme_zns_mgmt_recv(&args);
}

/**
 * nvme_zns_append() - Append data to a zone
 * @args:	&struct nvme_zns_append_args argument structure
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_zns_append(struct nvme_zns_append_args *args);

/**
 * nvme_dim_send - Send a Discovery Information Management (DIM) command
 * @args:	&struct nvme_dim_args argument structure
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_dim_send(struct nvme_dim_args *args);

#endif /* _LIBNVME_IOCTL_H */
