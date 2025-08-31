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

#include <string.h>
#include <endian.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <sys/ioctl.h>

#include <nvme/types.h>
#include <nvme/api-types.h>

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

/*
 * should not exceed CAP.MQES, 16 is rational for most ssd
 */
#define NVME_URING_ENTRIES 16

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
#define NVME_URING_CMD_ADMIN	_IOWR('N', 0x82, struct nvme_uring_cmd)
#define NVME_URING_CMD_ADMIN_VEC _IOWR('N', 0x83, struct nvme_uring_cmd)

#endif /* _UAPI_LINUX_NVME_IOCTL_H */

#endif /* _LINUX_NVME_IOCTL_H */

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
	NVME_GET_FEATURES_CDW10_FID_SHIFT			= 0,
	NVME_GET_FEATURES_CDW10_FID_MASK			= 0xff,
	NVME_GET_FEATURES_CDW14_UUID_SHIFT			= 0,
	NVME_GET_FEATURES_CDW14_UUID_MASK			= 0x7f,
	NVME_SET_FEATURES_CDW10_SV_SHIFT			= 31,
	NVME_SET_FEATURES_CDW10_SV_MASK  			= 0x1,
	NVME_SET_FEATURES_CDW10_FID_SHIFT			= 0,
	NVME_SET_FEATURES_CDW10_FID_MASK			= 0xff,
	NVME_SET_FEATURES_CDW11_NUM_SHIFT			= 0,
	NVME_SET_FEATURES_CDW11_NUM_MASK			= 0x3f,
	NVME_SET_FEATURES_CDW14_UUID_SHIFT			= 0,
	NVME_SET_FEATURES_CDW14_UUID_MASK			= 0x7f,
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
	NVME_IDENTIFY_CDW11_FIDX_SHIFT				= 0,
	NVME_IDENTIFY_CDW11_DOMID_SHIFT				= 0,
	NVME_IDENTIFY_CDW11_ENGGID_SHIFT			= 0,
	NVME_IDENTIFY_CDW14_UUID_SHIFT				= 0,
	NVME_IDENTIFY_CDW11_CSI_SHIFT				= 24,
	NVME_IDENTIFY_CDW10_CNS_MASK				= 0xff,
	NVME_IDENTIFY_CDW10_CNTID_MASK				= 0xffff,
	NVME_IDENTIFY_CDW11_CNSSPECID_MASK			= 0xffff,
	NVME_IDENTIFY_CDW11_FIDX_MASK				= 0xffff,
	NVME_IDENTIFY_CDW11_DOMID_MASK				= 0xffff,
	NVME_IDENTIFY_CDW11_ENGGID_MASK				= 0xffff,
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
	NVME_FORMAT_CDW10_LBAFL_SHIFT				= 0,
	NVME_FORMAT_CDW10_MSET_SHIFT				= 4,
	NVME_FORMAT_CDW10_PI_SHIFT				= 5,
	NVME_FORMAT_CDW10_PIL_SHIFT				= 8,
	NVME_FORMAT_CDW10_SES_SHIFT				= 9,
	NVME_FORMAT_CDW10_LBAFU_SHIFT				= 12,
	NVME_FORMAT_CDW10_LBAFL_MASK				= 0xf,
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
	NVME_DSM_CDW10_NR_SHIFT					= 0,
	NVME_DSM_CDW10_NR_MASK					= 0xff,
	NVME_DSM_CDW11_IDR_SHIFT				= 0,
	NVME_DSM_CDW11_IDR_MASK					= 0x1,
	NVME_DSM_CDW11_IDW_SHIFT				= 1,
	NVME_DSM_CDW11_IDW_MASK					= 0x1,
	NVME_DSM_CDW11_AD_SHIFT					= 2,
	NVME_DSM_CDW11_AD_MASK					= 0x1,
};

#define NVME_FIELD_ENCODE(value, shift, mask) \
	(((__u32)(value) & (mask)) << (shift))

#define NVME_FIELD_DECODE(value, shift, mask) \
	(((value) >> (shift)) & (mask))

/**
 * nvme_submit_admin_passthru64() - Submit a 64-bit nvme passthrough admin
 *				    command
 * @hdl:	Transport handle
 * @cmd:	The nvme admin command to send
 * @result:	Optional field to return the result from the CQE DW0-1
 *
 * Uses NVME_IOCTL_ADMIN64_CMD for the ioctl request.
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int nvme_submit_admin_passthru64(struct nvme_transport_handle *hdl, struct nvme_passthru_cmd64 *cmd,
				 __u64 *result);

/**
 * nvme_admin_passthru64() - Submit a 64-bit nvme passthrough command
 * @hdl:	Transport handle
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
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int nvme_admin_passthru64(struct nvme_transport_handle *hdl, __u8 opcode, __u8 flags, __u16 rsvd,
		__u32 nsid, __u32 cdw2, __u32 cdw3, __u32 cdw10, __u32 cdw11,
		__u32 cdw12, __u32 cdw13, __u32 cdw14, __u32 cdw15,
		__u32 data_len, void *data, __u32 metadata_len, void *metadata,
		__u32 timeout_ms, __u64 *result);

/**
 * nvme_submit_admin_passthru() - Submit an nvme passthrough admin command
 * @hdl:	Transport handle
 * @cmd:	The nvme admin command to send
 * @result:	Optional field to return the result from the CQE DW0
 *
 * Uses NVME_IOCTL_ADMIN_CMD for the ioctl request.
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int nvme_submit_admin_passthru(struct nvme_transport_handle *hdl, struct nvme_passthru_cmd *cmd,
			       __u32 *result);

/**
 * nvme_admin_passthru() - Submit an nvme passthrough command
 * @hdl:	Transport handle
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
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int nvme_admin_passthru(struct nvme_transport_handle *hdl, __u8 opcode, __u8 flags, __u16 rsvd,
		__u32 nsid, __u32 cdw2, __u32 cdw3, __u32 cdw10, __u32 cdw11,
		__u32 cdw12, __u32 cdw13, __u32 cdw14, __u32 cdw15,
		__u32 data_len, void *data, __u32 metadata_len, void *metadata,
		__u32 timeout_ms, __u32 *result);

/**
 * nvme_submit_io_passthru64() - Submit a 64-bit nvme passthrough command
 * @hdl:	Transport handle
 * @cmd:	The nvme io command to send
 * @result:	Optional field to return the result from the CQE DW0-1
 *
 * Uses NVME_IOCTL_IO64_CMD for the ioctl request.
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int nvme_submit_io_passthru64(struct nvme_transport_handle *hdl, struct nvme_passthru_cmd64 *cmd,
			    __u64 *result);

/**
 * nvme_io_passthru64() - Submit an nvme io passthrough command
 * @hdl:	Transport handle
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
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int nvme_io_passthru64(struct nvme_transport_handle *hdl, __u8 opcode, __u8 flags, __u16 rsvd,
		__u32 nsid, __u32 cdw2, __u32 cdw3, __u32 cdw10, __u32 cdw11,
		__u32 cdw12, __u32 cdw13, __u32 cdw14, __u32 cdw15,
		__u32 data_len, void *data, __u32 metadata_len, void *metadata,
		__u32 timeout_ms, __u64 *result);

/**
 * nvme_submit_io_passthru() - Submit an nvme passthrough command
 * @hdl:	Transport handle
 * @cmd:	The nvme io command to send
 * @result:	Optional field to return the result from the CQE dword 0
 * @result:	Optional field to return the result from the CQE DW0
 *
 * Uses NVME_IOCTL_IO_CMD for the ioctl request.
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int nvme_submit_io_passthru(struct nvme_transport_handle *hdl, struct nvme_passthru_cmd *cmd,
			    __u32 *result);

/**
 * nvme_io_passthru() - Submit an nvme io passthrough command
 * @hdl:	Transport handle
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
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int nvme_io_passthru(struct nvme_transport_handle *hdl, __u8 opcode, __u8 flags, __u16 rsvd,
		__u32 nsid, __u32 cdw2, __u32 cdw3, __u32 cdw10, __u32 cdw11,
		__u32 cdw12, __u32 cdw13, __u32 cdw14, __u32 cdw15,
		__u32 data_len, void *data, __u32 metadata_len, void *metadata,
		__u32 timeout_ms, __u32 *result);

/**
 * nvme_subsystem_reset() - Initiate a subsystem reset
 * @hdl:	Transport handle
 *
 * This should only be sent to controller handles, not to namespaces.
 *
 * Return: Zero if a subsystem reset was initiated or -1 with errno set
 * otherwise.
 */
int nvme_subsystem_reset(struct nvme_transport_handle *hdl);

/**
 * nvme_ctrl_reset() - Initiate a controller reset
 * @hdl:	Transport handle
 *
 * This should only be sent to controller handles, not to namespaces.
 *
 * Return: 0 if a reset was initiated or -1 with errno set otherwise.
 */
int nvme_ctrl_reset(struct nvme_transport_handle *hdl);

/**
 * nvme_ns_rescan() - Initiate a controller rescan
 * @hdl:	Transport handle
 *
 * This should only be sent to controller handles, not to namespaces.
 *
 * Return: 0 if a rescan was initiated or -1 with errno set otherwise.
 */
int nvme_ns_rescan(struct nvme_transport_handle *hdl);

/**
 * nvme_get_nsid() - Retrieve the NSID from a namespace file descriptor
 * @hdl:	Transport handle
 * @nsid:	User pointer to namespace id
 *
 * This should only be sent to namespace handles, not to controllers. The
 * kernel's interface returns the nsid as the return value. This is unfortunate
 * for many architectures that are incapable of allowing distinguishing a
 * namespace id > 0x80000000 from a negative error number.
 *
 * Return: 0 if @nsid was set successfully or -1 with errno set otherwise.
 */
int nvme_get_nsid(struct nvme_transport_handle *hdl, __u32 *nsid);

/**
 * nvme_init_identify() - Initialize passthru command for
 * NVMe Identify
 * @cmd:	Command data structure to initialize
 * @nsid:	Namespace identifier
 * @csi:	Command Set Identifier
 * @cns:	The Controller or Namespace structure,
 *              see @enum nvme_identify_cns
 * @data:	User space destination address to transfer the data
 * @len:	Length of provided user buffer to hold the data in bytes
 *
 * Prepare the @cmd data structure for the NVMe Identify command.
 */
static inline void
nvme_init_identify(struct nvme_passthru_cmd *cmd,
		__u32 nsid, enum nvme_csi csi, enum nvme_identify_cns cns,
		void *data, __u32 len)
{
	__u32 cdw10 = NVME_FIELD_ENCODE(cns,
					NVME_IDENTIFY_CDW10_CNS_SHIFT,
					NVME_IDENTIFY_CDW10_CNS_MASK);
	__u32 cdw11 = NVME_FIELD_ENCODE(csi,
					NVME_IDENTIFY_CDW11_CSI_SHIFT,
					NVME_IDENTIFY_CDW11_CSI_MASK);

	memset(cmd, 0, sizeof(*cmd));

	cmd->opcode	= nvme_admin_identify;
	cmd->nsid	= nsid;
	cmd->cdw10	= cdw10;
	cmd->cdw11	= cdw11;
	cmd->data_len	= len;
	cmd->addr	= (__u64)(uintptr_t)data;
}

/**
 * nvme_init_identify_ns() - Initialize passthru command for
 * NVMe Identify Namespace data structure
 * @cmd:	Command data structure to initialize
 * @nsid:	Namespace identifier
 * @id:		User space destination address to transfer the data
 *
 * Initializes the passthru command buffer for the Identify command with
 * CNS value %NVME_IDENTIFY_CNS_NS.
 */
static inline void
nvme_init_identify_ns(struct nvme_passthru_cmd *cmd,
		__u32 nsid, struct nvme_id_ns *id)
{
	nvme_init_identify(cmd, nsid, NVME_CSI_NVM,
			   NVME_IDENTIFY_CNS_NS,
			   id, sizeof(*id));
}

/**
 * nvme_init_identify_ctrl() - Initialize passthru command for
 * NVMe Identify Controller data structure
 * @cmd:	Command data structure to initialize
 * @id:		User space destination address to transfer the data,
 *
 * Initializes the passthru command buffer for the Identify command with
 * CNS value %NVME_IDENTIFY_CNS_CTRL.
 */
static inline void
nvme_init_identify_ctrl(struct nvme_passthru_cmd *cmd, struct nvme_id_ctrl *id)
{
	nvme_init_identify(cmd, NVME_NSID_NONE, NVME_CSI_NVM,
			   NVME_IDENTIFY_CNS_CTRL,
			   id, sizeof(*id));
}

/**
 * nvme_init_identify_active_ns_list() - Initialize passthru command for
 * Active Namespaces ID list
 * @cmd:	Command data structure to initialize
 * @nsid:	Namespace identifier
 * @list:	User space destination address to transfer the data
 *
 * Initializes the passthru command buffer for the Identify command with
 * CNS value %NVME_IDENTIFY_CNS_NS_ACTIVE_LIST.
 */
static inline void
nvme_init_identify_active_ns_list(struct nvme_passthru_cmd *cmd,
		__u32 nsid, struct nvme_ns_list *list)
{
	nvme_init_identify(cmd, nsid, NVME_CSI_NVM,
			   NVME_IDENTIFY_CNS_NS_ACTIVE_LIST,
			   list, sizeof(*list));
}

/**
 * nvme_init_identify_ns_descs_list() - Initialize passthru command for
 * Namespace Descriptor list
 * @cmd:	Command data structure to initialize
 * @nsid:	The namespace id to retrieve descriptors
 * @descs:	User space destination address to transfer the data
 *
 * Initializes the passthru command buffer for the Identify command with
 * CNS value %NVME_IDENTIFY_CNS_NS_DESC_LIST.
 */
static inline void
nvme_init_identify_ns_descs_list(struct nvme_passthru_cmd *cmd,
		__u32 nsid, struct nvme_ns_id_desc *descs)
{
	nvme_init_identify(cmd, nsid, NVME_CSI_NVM,
			   NVME_IDENTIFY_CNS_NS_DESC_LIST,
			   descs, NVME_IDENTIFY_DATA_SIZE);
}

/**
 * nvme_init_identify_nvmset_list() - Initialize passthru command for
 * NVM Set List data structure
 * @cmd:	Command data structure to initialize
 * @nsid:	Namespace identifier
 * @nvmsetid:	NVM Set Identifier
 * @nvmset:	User space destination address to transfer the data
 *
 * Initializes the passthru command buffer for the Identify command with
 * CNS value %NVME_IDENTIFY_CNS_NS_ACTIVE_LIST.
 */
static inline void
nvme_init_identify_nvmset_list(struct nvme_passthru_cmd *cmd,
		__u32 nsid, __u16 nvmsetid, struct nvme_id_nvmset_list *nvmset)
{
	nvme_init_identify(cmd, nsid, NVME_CSI_NVM,
			   NVME_IDENTIFY_CNS_NVMSET_LIST,
			   nvmset, sizeof(*nvmset));
	cmd->cdw11 |= NVME_FIELD_ENCODE(nvmsetid,
					NVME_IDENTIFY_CDW11_CNSSPECID_SHIFT,
					NVME_IDENTIFY_CDW11_CNSSPECID_MASK);
}

/**
 * nvme_init_identify_csi_ns() - Initialize passthru command for
 * I/O Command Set specific Identify Namespace data structure
 * @cmd:	Command data structure to initialize
 * @nsid:	Namespace identifier
 * @csi:	Command Set Identifier
 * @uidx:	UUID Index for differentiating vendor specific encoding
 * @data:	User space destination address to transfer the data
 *
 * Initializes the passthru command buffer for the Identify command with
 * CNS value %NVME_IDENTIFY_CNS_CSI_NS.
 */
static inline void
nvme_init_identify_csi_ns(struct nvme_passthru_cmd *cmd,
		__u32 nsid, enum nvme_csi csi, __u8 uidx, void *data)
{
	nvme_init_identify(cmd, nsid, csi,
			   NVME_IDENTIFY_CNS_CSI_NS,
			   data, NVME_IDENTIFY_DATA_SIZE);
	cmd->cdw14 |= NVME_FIELD_ENCODE(uidx,
					NVME_IDENTIFY_CDW14_UUID_SHIFT,
					NVME_IDENTIFY_CDW14_UUID_MASK);
}

/**
 * nvme_init_identify_csi_ctrl() - Initialize passthru command for
 * I/O Command Set specific Identify Controller data structure
 * @cmd:	Command data structure to initialize
 * @csi:	Command Set Identifier
 * @data:	User space destination address to transfer the data
 *
 * Initializes the passthru command buffer for the Identify command with
 * CNS value %NVME_IDENTIFY_CNS_CSI_CTRL.
 */
static inline void
nvme_init_identify_csi_ctrl(struct nvme_passthru_cmd *cmd,
		enum nvme_csi csi, void *data)
{
	nvme_init_identify(cmd, NVME_NSID_NONE, csi,
			   NVME_IDENTIFY_CNS_CSI_CTRL,
			   data, NVME_IDENTIFY_DATA_SIZE);
}

/**
 * nvme_init_identify_csi_active_ns_list() - Initialize passthru command
 * for Active namespace ID list
 * @cmd:	Command data structure to initialize
 * @nsid:	Return namespaces greater than this identifier
 * @csi:	Command Set Identifier
 * @ns_list:	User space destination address to transfer the data
 *
 * Initializes the passthru command buffer for the Identify command with
 * CNS value %NVME_IDENTIFY_CNS_CSI_NS_ACTIVE_LIST.
 */
static inline void
nvme_init_identify_csi_active_ns_list(struct nvme_passthru_cmd *cmd,
		__u32 nsid, enum nvme_csi csi, struct nvme_ns_list *ns_list)
{
	nvme_init_identify(cmd, nsid, csi,
			   NVME_IDENTIFY_CNS_CSI_NS_ACTIVE_LIST,
			   ns_list, sizeof(*ns_list));
}

/**
 * nvme_init_identify_csi_independent_identify_id_ns() -Initialize passthru
 * command for I/O Command Set Independent Identify Namespace data structure
 * @cmd:	Command data structure to initialize
 * @nsid:	Return namespaces greater than this identifier
 * @ns:		I/O Command Set Independent Identify Namespace data
 *		structure
 *
 * Initializes the passthru command buffer for the Identify command with
 * CNS value %NVME_IDENTIFY_CNS_CSI_INDEPENDENT_ID_NS.
 */
static inline void
nvme_init_identify_csi_independent_identify_id_ns(struct nvme_passthru_cmd *cmd,
		__u32 nsid, struct nvme_id_independent_id_ns *ns)
{
	nvme_init_identify(cmd, nsid, NVME_CSI_NVM,
			   NVME_IDENTIFY_CNS_CSI_INDEPENDENT_ID_NS,
			   ns, sizeof(*ns));
}

/**
 * nvme_init_identify_ns_user_data_format() - Initialize passthru command
 * for Identify namespace user data format
 * @cmd:	Command data structure to initialize
 * @csi:	Command Set Identifier
 * @fidx:	Format Index
 * @uidx:	UUID selection, if supported
 * @data:	User space destination address to transfer the data
 *
 * Initializes the passthru command buffer for the Identify command with
 * CNS value %NVME_IDENTIFY_CNS_NS_USER_DATA_FORMAT.
 */
static inline void
nvme_init_identify_ns_user_data_format(struct nvme_passthru_cmd *cmd,
		enum nvme_csi csi, __u16 fidx, __u8 uidx, void *data)
{
	nvme_init_identify(cmd, NVME_NSID_NONE, csi,
			   NVME_IDENTIFY_CNS_NS_USER_DATA_FORMAT,
			   data, NVME_IDENTIFY_DATA_SIZE);
	cmd->cdw11 |= NVME_FIELD_ENCODE(fidx,
					NVME_IDENTIFY_CDW11_FIDX_SHIFT,
					NVME_IDENTIFY_CDW11_FIDX_MASK);
	cmd->cdw14 |= NVME_FIELD_ENCODE(uidx,
					NVME_IDENTIFY_CDW14_UUID_SHIFT,
					NVME_IDENTIFY_CDW14_UUID_MASK);
}

/**
 * nvme_init_identify_csi_ns_user_data_format() - Initialize passthru
 * command for Identify namespace user data format
 * @cmd:	Command data structure to initialize
 * @csi:	Command Set Identifier
 * @fidx:	Format Index
 * @uidx:	UUID selection, if supported
 * @data:	User space destination address to transfer the data
 *
 * Initializes the passthru command buffer for the Identify command with
 * CNS value %NVME_IDENTIFY_CNS_CSI_NS_USER_DATA_FORMAT.
 */
static inline void
nvme_init_identify_csi_ns_user_data_format(struct nvme_passthru_cmd *cmd,
		enum nvme_csi csi, __u16 fidx, __u8 uidx, void *data)
{
	nvme_init_identify(cmd, NVME_NSID_NONE, csi,
			   NVME_IDENTIFY_CNS_CSI_NS_USER_DATA_FORMAT,
			   data, NVME_IDENTIFY_DATA_SIZE);
	cmd->cdw11 |= NVME_FIELD_ENCODE(fidx,
					NVME_IDENTIFY_CDW11_FIDX_SHIFT,
					NVME_IDENTIFY_CDW11_FIDX_MASK);
	cmd->cdw14 |= NVME_FIELD_ENCODE(uidx,
					NVME_IDENTIFY_CDW14_UUID_SHIFT,
					NVME_IDENTIFY_CDW14_UUID_MASK);
}

/**
 * nvme_init_identify_allocated_ns_list() - Initialize passthru command
 * for Allocated namespace ID list
 * @cmd:	Command data structure to initialize
 * @nsid:	Return namespaces greater than this identifier
 * @ns_list:	User space destination address to transfer the data
 *
 * Initializes the passthru command buffer for the Identify command with
 * CNS value %NVME_IDENTIFY_CNS_ALLOCATED_NS_LIST.
 */
static inline void
nvme_init_identify_allocated_ns_list(struct nvme_passthru_cmd *cmd,
		__u32 nsid, struct nvme_ns_list *ns_list)
{
	nvme_init_identify(cmd, nsid, NVME_CSI_NVM,
			   NVME_IDENTIFY_CNS_ALLOCATED_NS_LIST,
			   ns_list, sizeof(*ns_list));
}

/**
 * nvme_init_identify_allocated_ns() - Initialize passthru command
 * for allocated Namespace ID list
 * @cmd:	Command data structure to initialize
 * @nsid:	Namespace to identify
 * @ns:		User space destination address to transfer the data
 *
 * Initializes the passthru command buffer for the Identify command with
 * CNS value %NVME_IDENTIFY_CNS_ALLOCATED_NS.
 */
static inline void
nvme_init_identify_allocated_ns(struct nvme_passthru_cmd *cmd,
		__u32 nsid, struct nvme_id_ns *ns)
{
	nvme_init_identify(cmd, nsid, NVME_CSI_NVM,
			  NVME_IDENTIFY_CNS_ALLOCATED_NS,
			  ns, sizeof(*ns));
}

/**
 * nvme_init_identify_ns_ctrl_list() - Initialize passhtru command
 * for Controller List
 * @cmd:	Command data structure to initialize
 * @nsid:	Return controllers that are attached to this nsid
 * @cntid:	Starting CNTLID to return in the list
 * @cntlist:	User space destination address to transfer the data
 *
 * Initializes the passthru command buffer for the Identify command with
 * CNS value %NVME_IDENTIFY_CNS_NS_CTRL_LIST.
 */
static inline void
nvme_init_identify_ns_ctrl_list(struct nvme_passthru_cmd *cmd,
		__u32 nsid, __u16 cntid, struct nvme_ctrl_list *cntlist)
{
	nvme_init_identify(cmd, nsid, NVME_CSI_NVM,
			   NVME_IDENTIFY_CNS_NS_CTRL_LIST,
			   cntlist, sizeof(*cntlist));
	cmd->cdw10 |= NVME_FIELD_ENCODE(cntid,
					NVME_IDENTIFY_CDW10_CNTID_SHIFT,
					NVME_IDENTIFY_CDW10_CNTID_MASK);
}

/**
 * nvme_init_identify_ctrl_list() - Initialize passthru command for
 * Controller List of controllers
 * @cmd:	Command data structure to initialize
 * @cntid:	Starting CNTLID to return in the list
 * @cntlist:	User space destination address to transfer the data
 *
 * Initializes the passthru command buffer for the Identify command with
 * CNS value %NVME_IDENTIFY_CNS_CTRL_LIST.
 */
static inline void
nvme_init_identify_ctrl_list(struct nvme_passthru_cmd *cmd,
		__u16 cntid, struct nvme_ctrl_list *cntlist)
{
	nvme_init_identify(cmd, NVME_NSID_NONE, NVME_CSI_NVM,
			   NVME_IDENTIFY_CNS_CTRL_LIST,
			   cntlist, sizeof(*cntlist));
	cmd->cdw10 |= NVME_FIELD_ENCODE(cntid,
					NVME_IDENTIFY_CDW10_CNTID_SHIFT,
					NVME_IDENTIFY_CDW10_CNTID_MASK);
}

/**
 * nvme_init_identify_primary_ctrl_cap() - Initialize passthru command
 * for Primary Controller Capabilities data
 * @cmd:	Command data structure to initialize
 * @cntid:	Return controllers starting at this identifier
 * @cap:	User space destination buffer address to transfer the data
 *
 * Initializes the passthru command buffer for the Identify command with
 * CNS value %NVME_IDENTIFY_CNS_PRIMARY_CTRL_CAP.
 */
static inline void
nvme_init_identify_primary_ctrl_cap(struct nvme_passthru_cmd *cmd,
		__u16 cntid, struct nvme_primary_ctrl_cap *cap)
{
	nvme_init_identify(cmd, NVME_NSID_NONE, NVME_CSI_NVM,
			   NVME_IDENTIFY_CNS_PRIMARY_CTRL_CAP,
			   cap, sizeof(*cap));
	cmd->cdw10 |= NVME_FIELD_ENCODE(cntid,
					NVME_IDENTIFY_CDW10_CNTID_SHIFT,
					NVME_IDENTIFY_CDW10_CNTID_MASK);
}

/**
 * nvme_init_identify_secondary_ctrl_list() - Initialize passhru command
 * for Secondary Controller list
 * @cmd:	Command data structure to initialize
 * @cntid:	Return controllers starting at this identifier
 * @sc_list:	User space destination address to transfer the data
 *
 * Initializes the passthru command buffer for the Identify command with
 * CNS value %NVME_IDENTIFY_CNS_SECONDARY_CTRL_LIST.
 */
static inline void
nvme_init_identify_secondary_ctrl_list(struct nvme_passthru_cmd *cmd,
		__u16 cntid, struct nvme_secondary_ctrl_list *sc_list)
{
	nvme_init_identify(cmd, NVME_NSID_NONE, NVME_CSI_NVM,
			   NVME_IDENTIFY_CNS_SECONDARY_CTRL_LIST,
			   sc_list, sizeof(*sc_list));
	cmd->cdw10 |= NVME_FIELD_ENCODE(cntid,
					NVME_IDENTIFY_CDW10_CNTID_SHIFT,
					NVME_IDENTIFY_CDW10_CNTID_MASK);
}


/**
 * nvme_init_identify_ns_granularity() - Initialize passthru command for
 * Namespace Granularity list
 * @cmd:	Command data structure to initialize
 * @gr_list:	User space destination address to transfer the data
 *
 * Initializes the passthru command buffer for the Identify command with
 * CNS value %NVME_IDENTIFY_CNS_SECONDARY_CTRL_LIST.
 */
static inline void
nvme_init_identify_ns_granularity(struct nvme_passthru_cmd *cmd,
		struct nvme_id_ns_granularity_list *gr_list)
{
	nvme_init_identify(cmd, NVME_NSID_NONE, NVME_CSI_NVM,
			   NVME_IDENTIFY_CNS_NS_GRANULARITY,
			   gr_list, sizeof(*gr_list));
}

/**
 * nvme_init_identify_uuid_list() - Initialize passthru command for
 * UUID list
 * @cmd:	Command data structure to initialize
 * @uuid_list:	User space destination address to transfer the data
 *
 * Initializes the passthru command buffer for the Identify command with
 * CNS value %NVME_IDENTIFY_CNS_UUID_LIST.
 */
static inline void
nvme_init_identify_uuid_list(struct nvme_passthru_cmd *cmd,
		struct nvme_id_uuid_list *uuid_list)
{
	nvme_init_identify(cmd, NVME_UUID_NONE, NVME_CSI_NVM,
			   NVME_IDENTIFY_CNS_UUID_LIST,
			   uuid_list, sizeof(*uuid_list));
}

/**
 * nvme_init_identify_domain_list() - Initialize passthru command for
 * Domain list
 * @cmd:	Command data structure to initialize
 * @domid:	Domain ID
 * @list:	User space destination address to transfer data
 *
 * Initializes the passthru command buffer for the Identify command with
 * CNS value %NVME_IDENTIFY_CNS_DOMAIN_LIST.
 */
static inline void
nvme_init_identify_domain_list(struct nvme_passthru_cmd *cmd,
		__u16 domid, struct nvme_id_domain_list *list)
{
	nvme_init_identify(cmd, NVME_NSID_NONE, NVME_CSI_NVM,
			     NVME_IDENTIFY_CNS_DOMAIN_LIST,
			     list, sizeof(*list));
	cmd->cdw11 |= NVME_FIELD_ENCODE(domid,
					NVME_IDENTIFY_CDW11_DOMID_SHIFT,
					NVME_IDENTIFY_CDW11_DOMID_MASK);
}

/**
 * nvme_init_identify_endurance_group_id() - Initialize passthru command for
 * Endurance group list
 * @cmd:	Command data structure to initialize
 * @enggid:	Endurance group identifier
 * @list:	Array of endurance group identifiers
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
static inline void
nvme_init_identify_endurance_group_id(struct nvme_passthru_cmd *cmd,
		__u16 enggid, struct nvme_id_endurance_group_list *list)
{
	nvme_init_identify(cmd, NVME_NSID_NONE, NVME_CSI_NVM,
			     NVME_IDENTIFY_CNS_ENDURANCE_GROUP_ID,
			     list, sizeof(*list));
	cmd->cdw11 |= NVME_FIELD_ENCODE(enggid,
					NVME_IDENTIFY_CDW11_ENGGID_SHIFT,
					NVME_IDENTIFY_CDW11_ENGGID_MASK);
}

/**
 * nvme_init_identify_csi_allocated_ns_list() - Initialize passthru command for
 * I/O Command Set specific Allocated Namespace Id list
 * @cmd:	Command data structure to initialize
 * @nsid:	Return namespaces greater than this identifier
 * @csi:	Command Set Identifier
 * @ns_list:	User space destination address to transfer the data
 *
 * Initializes the passthru command buffer for the Identify command with
 * CNS value %NVME_IDENTIFY_CNS_CSI_ALLOCATED_NS_LIST.
 */
static inline void
nvme_init_identify_csi_allocated_ns_list(struct nvme_passthru_cmd *cmd,
		__u32 nsid, enum nvme_csi csi, struct nvme_ns_list *ns_list)
{
	nvme_init_identify(cmd, nsid, csi,
			   NVME_IDENTIFY_CNS_CSI_ALLOCATED_NS_LIST,
			   ns_list, sizeof(*ns_list));
}

/**
 * nvme_init_identify_csi_id_ns_data_structure() - Initialize passthru command for
 * I/O Command Set specific Identify Namespace data structure
 * @cmd:	Command data structure to initialize
 * @nsid:	Return namespaces greater than this identifier
 * @csi:	Command Set Identifier
 * @data:	User space destination address to transfer the data
 *
 * Initializes the passthru command buffer for the Identify command with
 * CNS value %NVME_IDENTIFY_CNS_CSI_ID_NS_DATA_STRUCTURE.
 */
static inline void
nvme_init_identify_csi_id_ns_data_structure(struct nvme_passthru_cmd *cmd,
		__u32 nsid, enum nvme_csi csi, void *data)
{
	nvme_init_identify(cmd, nsid, csi,
			   NVME_IDENTIFY_CNS_CSI_ID_NS_DATA_STRUCTURE,
			   data, NVME_IDENTIFY_DATA_SIZE);
}

/**
 * nvme_init_identify_command_set_structure() - Initialize passthru command for
 * I/O Command Set data structure
 * @cmd:	Command data structure to initialize
 * @cntid:	Controller ID
 * @iocs:	User space destination address to transfer the data
 *
 * Retrieves list of the controller's supported io command set vectors. See
 * &struct nvme_id_iocs.
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
static inline void
nvme_init_identify_command_set_structure(struct nvme_passthru_cmd *cmd,
		__u16 cntid, struct nvme_id_iocs *iocs)
{
	nvme_init_identify(cmd, NVME_NSID_NONE, NVME_CSI_NVM,
			   NVME_IDENTIFY_CNS_COMMAND_SET_STRUCTURE,
			   iocs, sizeof(*iocs));
	cmd->cdw10 |= NVME_FIELD_ENCODE(cntid,
					NVME_IDENTIFY_CDW10_CNTID_SHIFT,
					NVME_IDENTIFY_CDW10_CNTID_MASK);
}

/**
 * nvme_init_zns_identify_ns() - Initialize passthru command for
 * ZNS identify namespace data
 * @cmd:	Command data structure to initialize
 * @nsid:	Namespace to identify
 * @data:	User space destination address to transfer the data
 */
static inline void
nvme_init_zns_identify_ns(struct nvme_passthru_cmd *cmd,
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
nvme_init_zns_identify_ctrl(struct nvme_passthru_cmd *cmd,
		struct nvme_zns_id_ctrl *id)
{
	nvme_init_identify(cmd, NVME_NSID_NONE, NVME_CSI_ZNS,
			   NVME_IDENTIFY_CNS_CSI_CTRL,
			   id, sizeof(*id));
}

/**
 * nvme_get_log() - Get log page data
 * @hdl:	Transport handle
 * @cmd:	Passthru command
 * @rae:	Retain asynchronous events
 * @xfer_len:	Max log transfer size per request to split the total.
 * @result:	The command completion result from CQE dword0
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int nvme_get_log(struct nvme_transport_handle *hdl,
		struct nvme_passthru_cmd *cmd, bool rae,
		 __u32 xfer_len, __u32 *result);

/**
 * nvme_init_get_log_lpo() - Initializes passthru command with a
 * Log Page Offset
 * @cmd:	Passthru command
 * @lpo:	Log Page Offset to set set
 */
static inline void
nvme_init_get_log_lpo(struct nvme_passthru_cmd *cmd, __u64 lpo)
{
	cmd->cdw12 = lpo & 0xffffffff;
	cmd->cdw13 = lpo >> 32;
}

/**
 * nvme_init_get_log() - Initialize passthru command for
 * NVMe Admin Get Log
 * @cmd:	Passthru command to use
 * @nsid:	Namespace identifier, if applicable
 * @lid:	Log Page Identifier, see &enum nvme_cmd_get_log_lid
 * @csi:	Command set identifier, see &enum nvme_csi for known values
 * @data:	User space destination address to transfer the data
 * @len:	Length of provided user buffer to hold the log data in bytes
 */
static inline void
nvme_init_get_log(struct nvme_passthru_cmd *cmd, __u32 nsid,
		enum nvme_cmd_get_log_lid lid, enum nvme_csi csi,
		void *data, __u32 len)
{
	__u32 numd = (len >> 2) - 1;
	__u16 numdu = numd >> 16;
	__u16 numdl = numd & 0xffff;
	__u32 cdw10 = NVME_FIELD_ENCODE(lid,
					NVME_LOG_CDW10_LID_SHIFT,
					NVME_LOG_CDW10_LID_MASK) |
		      NVME_FIELD_ENCODE(numdl,
					NVME_LOG_CDW10_NUMDL_SHIFT,
					NVME_LOG_CDW10_NUMDL_MASK);
	__u32 cdw11 = NVME_FIELD_ENCODE(numdu,
					NVME_LOG_CDW11_NUMDU_SHIFT,
					NVME_LOG_CDW11_NUMDU_MASK);
	__u32 cdw14 = NVME_FIELD_ENCODE(csi,
					NVME_LOG_CDW14_CSI_SHIFT,
					NVME_LOG_CDW14_CSI_MASK);

	memset(cmd, 0, sizeof(*cmd));

	cmd->opcode	= nvme_admin_get_log_page;
	cmd->nsid	= nsid;
	cmd->cdw10	= cdw10;
	cmd->cdw11	= cdw11;
	cmd->cdw14	= cdw14;
	cmd->data_len	= len;
	cmd->addr	= (__u64)(uintptr_t)data;
}

/**
 * nvme_init_get_log_supported_log_pages() -  Initialize passthru command for
 * Supported Log Pages
 * @cmd:	Passthru command to use
 * @csi:	Command set identifier, see &enum nvme_csi for known values
 * @log:	Array of LID supported and Effects data structures
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_SUPPORTED_LOG_PAGES.
 */
static inline void
nvme_init_get_log_supported_log_pages(struct nvme_passthru_cmd *cmd,
		enum nvme_csi csi, struct nvme_supported_log_pages *log)
{
	nvme_init_get_log(cmd, NVME_NSID_ALL, NVME_LOG_LID_SUPPORTED_LOG_PAGES,
		csi, log, sizeof(*log));
}

/**
 * nvme_init_get_log_error() - Initialize passthru command for Error Information
 * @cmd:	Passthru command to use
 * @nr_entries:	Number of error log entries allocated
 * @err_log:	Array of error logs of size 'entries'
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_ERROR.
 */
static inline void
nvme_init_get_log_error(struct nvme_passthru_cmd *cmd, unsigned int nr_entries,
		struct nvme_error_log_page *err_log)
{
	nvme_init_get_log(cmd, NVME_NSID_ALL, NVME_LOG_LID_ERROR,
		NVME_CSI_NVM, err_log, sizeof(*err_log) * nr_entries);
}

/**
 * nvme_init_get_log_smart() - Initialize passthru command for
 * SMART / Health Information
 * @cmd:	Passthru command to use
 * @nsid:	Optional namespace identifier
 * @smart_log:	User address to store the smart log
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_SMART.
 */
static inline void
nvme_init_get_log_smart(struct nvme_passthru_cmd *cmd, __u32 nsid,
		struct nvme_smart_log *smart_log)
{
	nvme_init_get_log(cmd, nsid, NVME_LOG_LID_SMART, NVME_CSI_NVM,
		smart_log, sizeof(*smart_log));
}

/**
 * nvme_init_get_log_fw_slot() - Initialize passthru command for
 * Firmware Slot Information
 * @cmd:	Passthru command to use
 * @fw_log:	User address to store the log page
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_SMART.
 */
static inline void
nvme_init_get_log_fw_slot(struct nvme_passthru_cmd *cmd,
		struct nvme_firmware_slot *fw_log)
{
	nvme_init_get_log(cmd, NVME_NSID_ALL, NVME_LOG_LID_FW_SLOT,
		NVME_CSI_NVM, fw_log, sizeof(*fw_log));
}

/**
 * nvme_init_get_log_changed_ns() - Initialize passthru command for
 * Changed Attached Namespace List
 * @cmd:	Passthru command to use
 * @ns_log:	User address to store the log page
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_CHANGED_NS.
 */
static inline void
nvme_init_get_log_changed_ns(struct nvme_passthru_cmd *cmd,
			struct nvme_ns_list *ns_log)
{
	nvme_init_get_log(cmd, NVME_NSID_ALL, NVME_LOG_LID_CHANGED_NS,
		NVME_CSI_NVM, ns_log, sizeof(*ns_log));
}


/**
 * nvme_init_get_log_cmd_effects() - Initialize passthru command for
 * Commands Supported and Effects
 * @cmd:	Passthru command to use
 * @csi:	Command Set Identifier
 * @effects_log:User address to store the effects log
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_CMD_EFFECTS.
 */
static inline void
nvme_init_get_log_cmd_effects(struct nvme_passthru_cmd *cmd,
		enum nvme_csi csi, struct nvme_cmd_effects_log *effects_log)
{
	nvme_init_get_log(cmd, NVME_NSID_ALL, NVME_LOG_LID_CMD_EFFECTS, csi,
		 effects_log, sizeof(*effects_log));
}

/**
 * nvme_init_get_log_device_self_test() - Initialize passthru command for
 * Device Self-test
 * @cmd:	Passthru command to use
 * @log:	Userspace address of the log payload
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_DEVICE_SELF_TEST.
 */
static inline void
nvme_init_get_log_device_self_test(struct nvme_passthru_cmd *cmd,
		struct nvme_self_test_log *log)
{
	nvme_init_get_log(cmd, NVME_NSID_ALL, NVME_LOG_LID_DEVICE_SELF_TEST,
		NVME_CSI_NVM, log, sizeof(*log));
}

/**
 * nvme_init_get_log_telemetry_host() - Initialize passthru command for
 * Telemetry Host-Initiated
 * @cmd:	Passthru command to use
 * @lpo:	Offset into the telemetry data
 * @log:	User address for log page data
 * @len:	Length of provided user buffer to hold the log data in bytes
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_TELEMETRY_HOST.
 */
static inline void
nvme_init_get_log_telemetry_host(struct nvme_passthru_cmd *cmd, __u64 lpo,
		void *log, __u32 len)
{
	nvme_init_get_log(cmd, NVME_NSID_NONE, NVME_LOG_LID_TELEMETRY_HOST,
		NVME_CSI_NVM, log, len);
	cmd->cdw10 |= NVME_FIELD_ENCODE(NVME_LOG_TELEM_HOST_LSP_RETAIN,
			NVME_LOG_CDW10_LSP_SHIFT,
			NVME_LOG_CDW10_LSP_MASK);
	nvme_init_get_log_lpo(cmd, lpo);
}

/**
 * nvme_init_get_log_create_telemetry_host_mcda() - Initialize passthru
 * command for Create Telemetry Host-Initiated
 * @cmd:	Passthru command to use
 * @mcda:	Maximum Created Data Area
 * @log:	Userspace address of the log payload
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_TELEMETRY_HOST and
 * LSP value %NVME_LOG_TELEM_HOST_LSP_CREATE.
 */
static inline void
nvme_init_get_log_create_telemetry_host_mcda(struct nvme_passthru_cmd *cmd,
		enum nvme_telemetry_da mcda, struct nvme_telemetry_log *log)
{
	nvme_init_get_log(cmd, NVME_NSID_NONE, NVME_LOG_LID_TELEMETRY_HOST,
		NVME_CSI_NVM, log, sizeof(*log));
	cmd->cdw10 |= NVME_FIELD_ENCODE(
			mcda << 1 | NVME_LOG_TELEM_HOST_LSP_CREATE,
			NVME_LOG_CDW10_LSP_SHIFT,
			NVME_LOG_CDW10_LSP_MASK);
}

/**
 * nvme_init_get_log_create_telemetry_host() - Initialize passthru command for
 * Create Telemetry Host-Initiated
 * @cmd:	Passthru command to use
 * @log:	Userspace address of the log payload
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_TELEMETRY_HOST and
 * LSP value %NVME_LOG_TELEM_HOST_LSP_CREATE.
 */
static inline void
nvme_init_get_log_create_telemetry_host(struct nvme_passthru_cmd *cmd,
			struct nvme_telemetry_log *log)
{
	nvme_init_get_log_create_telemetry_host_mcda(cmd,
		NVME_TELEMETRY_DA_CTRL_DETERMINE, log);
}

/**
 * nvme_init_get_log_telemetry_ctrl() - Initialize passthru command for
 * Telemetry Controller-Initiated
 * @cmd:	Passthru command to use
 * @lpo:	Offset into the telemetry data
 * @log:	User address for log page data
 * @len:	Length of provided user buffer to hold the log data in bytes
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_TELEMETRY_CTRL.
 */
static inline void
nvme_init_get_log_telemetry_ctrl(struct nvme_passthru_cmd *cmd,
		__u64 lpo, void *log, __u32 len)
{
	nvme_init_get_log(cmd, NVME_NSID_NONE, NVME_LOG_LID_TELEMETRY_CTRL,
		NVME_CSI_NVM, log, len);
	nvme_init_get_log_lpo(cmd, lpo);
}

/**
 * nvme_init_get_log_endurance_group() - Initialize passthru command for
 * Endurance Group Information
 * @cmd:	Passthru command to use
 * @endgid:	Starting group identifier to return in the list
 * @log:	User address to store the endurance log
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_ENDURANCE_GROUP.
 */
static inline void
nvme_init_get_log_endurance_group(struct nvme_passthru_cmd *cmd, __u16 endgid,
		struct nvme_endurance_group_log *log)
{
	nvme_init_get_log(cmd, NVME_NSID_NONE, NVME_LOG_LID_ENDURANCE_GROUP,
		NVME_CSI_NVM, log, sizeof(*log));
	cmd->cdw11 |= NVME_FIELD_ENCODE(endgid,
			NVME_LOG_CDW11_LSI_SHIFT,
			NVME_LOG_CDW11_LSI_MASK);
}

/**
 * nvme_init_get_log_predictable_lat_nvmset() - Initialize passthru command for
 * Predictable Latency Per NVM Set
 * @cmd:	Passthru command to use
 * @nvmsetid:	NVM set id
 * @log:	User address to store the predictable latency log
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_PREDICTABLE_LAT_NVMSET.
 */
static inline void
nvme_init_get_log_predictable_lat_nvmset(struct nvme_passthru_cmd *cmd,
		__u16 nvmsetid, struct nvme_nvmset_predictable_lat_log *log)
{
	nvme_init_get_log(cmd, NVME_NSID_NONE,
		NVME_LOG_LID_PREDICTABLE_LAT_NVMSET, NVME_CSI_NVM,
		log, sizeof(*log));
	cmd->cdw11 |= NVME_FIELD_ENCODE(nvmsetid,
			NVME_LOG_CDW11_LSI_SHIFT,
			NVME_LOG_CDW11_LSI_MASK);
}

/**
 * nvme_init_get_log_predictable_lat_event() - Initialize passthru command for
 * Predictable Latency Event Aggregate
 * @cmd:	Passthru command to use
 * @lpo:	Offset into the predictable latency event
 * @log:	User address for log page data
 * @len:	Length of provided user buffer to hold the log data in bytes
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_PREDICTABLE_LAT_AGG.
 */
static inline void
nvme_init_get_log_predictable_lat_event(struct nvme_passthru_cmd *cmd,
		__u64 lpo, void *log, __u32 len)
{
	nvme_init_get_log(cmd, NVME_NSID_NONE,
		NVME_LOG_LID_PREDICTABLE_LAT_AGG, NVME_CSI_NVM,
		log, len);
	cmd->cdw12 = lpo & 0xffffffff;
	cmd->cdw13 = lpo >> 32;
}

/**
 * nvme_init_get_log_ana() - Initialize passthru command for
 * Asymmetric Namespace Access
 * @cmd:	Passthru command to use
 * @lsp:	Log specific, see &enum nvme_get_log_ana_lsp
 * @lpo:	Offset to the start of the log page
 * @log:	User address to store the ana log
 * @len:	The allocated length of the log page
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_ANA.
 */
static inline void
nvme_init_get_log_ana(struct nvme_passthru_cmd *cmd,
		enum nvme_log_ana_lsp lsp, __u64 lpo, void *log, __u32 len)
{
	nvme_init_get_log(cmd, NVME_NSID_NONE,
		NVME_LOG_LID_ANA, NVME_CSI_NVM,
		log, len);
	cmd->cdw10 |= NVME_FIELD_ENCODE(lsp,
			NVME_LOG_CDW10_LSP_SHIFT,
			NVME_LOG_CDW10_LSP_MASK);
	cmd->cdw12 = lpo & 0xffffffff;
	cmd->cdw13 = lpo >> 32;
}

/**
 * nvme_init_get_log_ana_groups() - Initialize passthru command for
 * Asymmetric Namespace Access groups
 * @cmd:	Passthru command to use
 * @log:	User address to store the ana group log
 * @len:	The allocated length of the log page
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_ANA and LSP value %NVME_LOG_ANA_LSP_RGO_GROUPS_ONLY
 */
static inline void
nvme_init_get_log_ana_groups(struct nvme_passthru_cmd *cmd,
		struct nvme_ana_log *log, __u32 len)
{
	nvme_init_get_log_ana(cmd, NVME_LOG_ANA_LSP_RGO_GROUPS_ONLY,
		0, log, len);
}

/**
 * nvme_init_get_log_persistent_event() - Initialize passthru command for
 * Persistent Event Log
 * @cmd:	Passthru command to use
 * @action:	Action the controller should take during processing this command
 * @pevent_log:	User address to store the persistent event log
 * @len:	Size of @pevent_log
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_PERSISTENT_EVENT
 */
static inline void
nvme_init_get_log_persistent_event(struct nvme_passthru_cmd *cmd,
		enum nvme_pevent_log_action action,
		void *pevent_log, __u32 len)
{
	nvme_init_get_log(cmd, NVME_NSID_ALL,
		NVME_LOG_LID_PERSISTENT_EVENT, NVME_CSI_NVM,
		pevent_log, len);
	cmd->cdw10 |= NVME_FIELD_ENCODE(action,
			NVME_LOG_CDW10_LSP_SHIFT,
			NVME_LOG_CDW10_LSP_MASK);
}

/**
 * nvme_init_get_log_lba_status() - Initialize passthru command for
 * Retrieve LBA Status
 * @cmd:	Passthru command to use
 * @lpo:	Offset to the start of the log page
 * @log:	User address to store the log page
 * @len:	The allocated length of the log page
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_LBA_STATUS
 */
static inline void
nvme_init_get_log_lba_status(struct nvme_passthru_cmd *cmd,
		__u64 lpo, void *log, __u32 len)
{
	nvme_init_get_log(cmd, NVME_NSID_NONE,
		NVME_LOG_LID_LBA_STATUS, NVME_CSI_NVM,
		log, len);
	cmd->cdw12 = lpo & 0xffffffff;
	cmd->cdw13 = lpo >> 32;
}

/**
 * nvme_init_get_log_endurance_grp_evt() - Initialize passthru command for
 * Endurance Group Event Aggregate
 * @cmd:	Passthru command to use
 * @lpo:	Offset to the start of the log page
 * @log:	User address to store the log page
 * @len:	The allocated length of the log page
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_ENDURANCE_GRP_EVT
 */
static inline void
nvme_init_get_log_endurance_grp_evt(struct nvme_passthru_cmd *cmd,
		__u64 lpo, void *log, __u32 len)
{
	nvme_init_get_log(cmd, NVME_NSID_NONE,
		NVME_LOG_LID_ENDURANCE_GRP_EVT, NVME_CSI_NVM,
		log, len);
	nvme_init_get_log_lpo(cmd, lpo);
}

/**
 * nvme_init_get_log_media_unit_stat() - Initialize passthru command for
 * Media Unit Status
 * @cmd:	Passthru command to use
 * @domid:	Domain Identifier selection, if supported
 * @mus:	User address to store the Media Unit statistics log
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_MEDIA_UNIT_STATUS
 */
static inline void
nvme_init_get_log_media_unit_stat(struct nvme_passthru_cmd *cmd,
		__u16 domid, struct nvme_media_unit_stat_log *mus)
{
	nvme_init_get_log(cmd, NVME_NSID_NONE,
		NVME_LOG_LID_MEDIA_UNIT_STATUS, NVME_CSI_NVM,
		mus, sizeof(*mus));
	cmd->cdw11 |= NVME_FIELD_ENCODE(domid,
			NVME_LOG_CDW11_LSI_SHIFT,
			NVME_LOG_CDW11_LSI_MASK);
}

/**
 * nvme_init_get_log_support_cap_config_list() - Initialize passthru command for
 * Supported Capacity Configuration List
 * @cmd:	Passthru command to use
 * @domid:	Domain Identifier selection, if supported
 * @cap:	User address to store supported capabilities config list
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_SUPPORTED_CAP_CONFIG_LIST
 */
static inline void
nvme_init_get_log_support_cap_config_list(struct nvme_passthru_cmd *cmd,
		__u16 domid, struct nvme_supported_cap_config_list_log *cap)
{
	nvme_init_get_log(cmd, NVME_NSID_NONE,
		NVME_LOG_LID_SUPPORTED_CAP_CONFIG_LIST, NVME_CSI_NVM,
		cap, sizeof(*cap));
	cmd->cdw11 |= NVME_FIELD_ENCODE(domid,
			NVME_LOG_CDW11_LSI_SHIFT,
			NVME_LOG_CDW11_LSI_MASK);
}

/**
 * nvme_init_get_log_fid_supported_effects() - Initialize passthru command for
 * Feature Identifiers Supported and Effects
 * @cmd:	Passthru command to use
 * @csi:	Command set identifier, see &enum nvme_csi for known values
 * @log:	FID Supported and Effects data structure
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_FID_SUPPORTED_EFFECTS
 */
static inline void
nvme_init_get_log_fid_supported_effects(struct nvme_passthru_cmd *cmd,
		enum nvme_csi csi, struct nvme_fid_supported_effects_log *log)
{
	nvme_init_get_log(cmd, NVME_NSID_NONE,
		NVME_LOG_LID_FID_SUPPORTED_EFFECTS, csi,
		log, sizeof(*log));
}

/**
 * nvme_init_get_log_mi_cmd_supported_effects() - Initialize passthru command
 * for MI Commands Supported by the controller
 * @cmd:	Passthru command to use
 * @log:	MI Command Supported and Effects data structure
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_MI_CMD_SUPPORTED_EFFECTS
 */
static inline void
nvme_init_get_log_mi_cmd_supported_effects(struct nvme_passthru_cmd *cmd,
		struct nvme_mi_cmd_supported_effects_log *log)
{
	nvme_init_get_log(cmd, NVME_NSID_NONE,
		NVME_LOG_LID_MI_CMD_SUPPORTED_EFFECTS, NVME_CSI_NVM,
		log, sizeof(*log));
}

/**
 * nvme_init_get_log_lockdown() - Initialize passthru command for
 * Command and Feature Lockdown
 * @cmd:		Passthru command to use
 * @cnscp:		Contents and Scope of Command and Feature Identifier
 *			Lists
 * @lockdown_log:	Buffer to store the lockdown log
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_CMD_AND_FEAT_LOCKDOWN
 */
static inline void
nvme_init_get_log_lockdown(struct nvme_passthru_cmd *cmd,
		__u8 cnscp, struct nvme_lockdown_log *lockdown_log)
{
	nvme_init_get_log(cmd, NVME_NSID_ALL,
		NVME_LOG_LID_CMD_AND_FEAT_LOCKDOWN, NVME_CSI_NVM,
		lockdown_log, sizeof(*lockdown_log));
	cmd->cdw10 |= NVME_FIELD_ENCODE(cnscp,
			NVME_LOG_CDW10_LSP_SHIFT,
			NVME_LOG_CDW10_LSP_MASK);
}

/**
 * nvme_init_get_log_boot_partition() - Initialize passthru command for
 * Boot Partition
 * @cmd:	Passthru command to use
 * @lsp:	The log specified field of LID
 * @part:	User address to store the log page
 * @len:	The allocated size, minimum
 *		struct nvme_boot_partition
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_BOOT_PARTITION
 */
static inline void
nvme_init_get_log_boot_partition(struct nvme_passthru_cmd *cmd,
		__u8 lsp, struct nvme_boot_partition *part, __u32 len)
{
	nvme_init_get_log(cmd, NVME_NSID_NONE,
		NVME_LOG_LID_BOOT_PARTITION, NVME_CSI_NVM,
		part, len);
	cmd->cdw10 |= NVME_FIELD_ENCODE(lsp,
			NVME_LOG_CDW10_LSP_SHIFT,
			NVME_LOG_CDW10_LSP_MASK);
}

/**
 * nvme_init_get_log_rotational_media_info() - Initialize passthru command for
 * Rotational Media Information Log
 * @cmd:	Passthru command to use
 * @endgid:	Endurance Group Identifier
 * @log:	User address to store the log page
 * @len:	The allocated length of the log page
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_ROTATIONAL_MEDIA_INFO
 */
static inline void
nvme_init_get_log_rotational_media_info(struct nvme_passthru_cmd *cmd,
		__u16 endgid, struct nvme_rotational_media_info_log *log,
		__u32 len)
{
	nvme_init_get_log(cmd, NVME_NSID_NONE,
		NVME_LOG_LID_ROTATIONAL_MEDIA_INFO, NVME_CSI_NVM,
		log, len);
	cmd->cdw11 |= NVME_FIELD_ENCODE(endgid,
			NVME_LOG_CDW11_LSI_SHIFT,
			NVME_LOG_CDW11_LSI_MASK);
}

/**
 * nvme_init_get_log_dispersed_ns_participating_nss() - Initialize passthru
 * command for Dispersed Namespace Participating NVM Subsystems
 * @cmd:	Passthru command to use
 * @nsid:	Namespace Identifier
 * @log:	User address to store the log page
 * @len:	The allocated length of the log page
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_DISPERSED_NS_PARTICIPATING_NSS
 */
static inline void
nvme_init_get_log_dispersed_ns_participating_nss(struct nvme_passthru_cmd *cmd,
		__u32 nsid, struct nvme_dispersed_ns_participating_nss_log *log,
		__u32 len)
{
	nvme_init_get_log(cmd, nsid,
		NVME_LOG_LID_DISPERSED_NS_PARTICIPATING_NSS, NVME_CSI_NVM,
		log, len);
}

/**
 * nvme_init_get_log_mgmt_addr_list() - Initialize passthru command for
 * Management Address List
 * @cmd:	Passthru command to use
 * @log:	User address to store the log page
 * @len:	The allocated length of the log page
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_MGMT_ADDR_LIST
 */
static inline void
nvme_init_get_log_mgmt_addr_list(struct nvme_passthru_cmd *cmd,
		struct nvme_mgmt_addr_list_log *log, __u32 len)
{
	nvme_init_get_log(cmd, NVME_NSID_ALL,
		NVME_LOG_LID_MGMT_ADDR_LIST, NVME_CSI_NVM,
		log, len);
}

/**
 * nvme_init_get_log_phy_rx_eom() - Initialize passthru command for
 * Physical Interface Receiver Eye Opening Measurement
 * @cmd:	Passthru command to use
 * @lsp:	Log specific, controls action and measurement quality
 * @controller:	Target controller ID
 * @log:	User address to store the log page
 * @len:	The allocated size, minimum
 *		struct nvme_phy_rx_eom_log
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_PHY_RX_EOM
 */
static inline void
nvme_init_get_log_phy_rx_eom(struct nvme_passthru_cmd *cmd,
		__u8 lsp, __u16 controller, struct nvme_phy_rx_eom_log *log,
		__u32 len)
{
	nvme_init_get_log(cmd, NVME_NSID_NONE,
		NVME_LOG_LID_PHY_RX_EOM, NVME_CSI_NVM,
		log, len);
	cmd->cdw10 |= NVME_FIELD_ENCODE(lsp,
			NVME_LOG_CDW10_LSP_SHIFT,
			NVME_LOG_CDW10_LSP_MASK);
	cmd->cdw11 |= NVME_FIELD_ENCODE(controller,
			NVME_LOG_CDW11_LSI_SHIFT,
			NVME_LOG_CDW11_LSI_MASK);
}

/**
 * nvme_init_get_log_reachability_groups() - Initialize passthru command for
 * Retrieve Reachability Groups
 * @cmd:	Passthru command to use
 * @rgo:	Return groups only
 * @log:	User address to store the log page
 * @len:	The allocated length of the log page
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_REACHABILITY_GROUPS
 */
static inline void
nvme_init_get_log_reachability_groups(struct nvme_passthru_cmd *cmd,
		bool rgo, struct nvme_reachability_groups_log *log, __u32 len)
{
	nvme_init_get_log(cmd, NVME_NSID_ALL,
		NVME_LOG_LID_REACHABILITY_GROUPS, NVME_CSI_NVM,
		log, len);
	cmd->cdw10 |= NVME_FIELD_ENCODE((__u8)rgo,
			NVME_LOG_CDW10_LSP_SHIFT,
			NVME_LOG_CDW10_LSP_MASK);
}

/**
 * nvme_init_get_log_reachability_associations() - Initialize passthru command
 * for Reachability Associations Log
 * @cmd:	Passthru command to use
 * @rao:	Return associations only
 * @log:	User address to store the log page
 * @len:	The allocated length of the log page
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_REACHABILITY_ASSOCIATIONS
 */
static inline void
nvme_init_get_log_reachability_associations(struct nvme_passthru_cmd *cmd,
		bool rao, struct nvme_reachability_associations_log *log,
		__u32 len)
{
	nvme_init_get_log(cmd, NVME_NSID_ALL,
		NVME_LOG_LID_REACHABILITY_ASSOCIATIONS, NVME_CSI_NVM,
		log, len);
	cmd->cdw10 |= NVME_FIELD_ENCODE((__u8)rao,
			NVME_LOG_CDW10_LSP_SHIFT,
			NVME_LOG_CDW10_LSP_MASK);
}

/**
 * nvme_init_get_log_changed_alloc_ns() - Initialize passthru command for
 * Changed Allocated Namespace List
 * @cmd:	Passthru command to use
 * @log:	User address to store the log page
 * @len:	The allocated length of the log page
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_CHANGED_ALLOC_NS
 */
static inline void
nvme_init_get_log_changed_alloc_ns(struct nvme_passthru_cmd *cmd,
		struct nvme_ns_list *log, __u32 len)
{
	nvme_init_get_log(cmd, NVME_NSID_ALL,
		NVME_LOG_LID_CHANGED_ALLOC_NS, NVME_CSI_NVM,
		log, len);
}

/**
 * nvme_init_get_log_fdp_configurations() - Initialize passthru command for
 * Flexible Data Placement Configurations
 * @cmd:	Passthru command to use
 * @egid:	Endurance group identifier
 * @lpo:	Offset into log page
 * @log:	Log page data buffer
 * @len:	Length (in bytes) of provided user buffer to hold the log data
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_FDP_CONFIGS
 */
static inline void
nvme_init_get_log_fdp_configurations(struct nvme_passthru_cmd *cmd,
		__u16 egid, __u64 lpo, void *log, __u32 len)
{
	nvme_init_get_log(cmd, NVME_NSID_NONE,
		NVME_LOG_LID_FDP_CONFIGS, NVME_CSI_NVM,
		log, len);
	cmd->cdw11 |= NVME_FIELD_ENCODE(egid,
			NVME_LOG_CDW11_LSI_SHIFT,
			NVME_LOG_CDW11_LSI_MASK);
	nvme_init_get_log_lpo(cmd, lpo);
}

/**
 * nvme_init_get_log_reclaim_unit_handle_usage() - Initialize passthru
 * command for Reclaim Unit Handle Usage
 * @cmd:	Passthru command to use
 * @egid:	Endurance group identifier
 * @lpo:	Offset into log page
 * @log:	Log page data buffer
 * @len:	Length (in bytes) of provided user buffer to hold the log data
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_RUH_USAGE
 */
static inline void
nvme_init_get_log_reclaim_unit_handle_usage(struct nvme_passthru_cmd *cmd,
		__u16 egid, __u64 lpo, void *log, __u32 len)
{
	nvme_init_get_log(cmd, NVME_NSID_NONE,
		NVME_LOG_LID_FDP_RUH_USAGE, NVME_CSI_NVM,
		log, len);
	cmd->cdw11 |= NVME_FIELD_ENCODE(egid,
			NVME_LOG_CDW11_LSI_SHIFT,
			NVME_LOG_CDW11_LSI_MASK);
	nvme_init_get_log_lpo(cmd, lpo);
}

/**
 * nvme_init_get_log_fdp_stats() - Initialize passthru command for
 * Get Flexible Data Placement Statistics
 * @cmd:	Passthru command to use
 * @egid:	Endurance group identifier
 * @lpo:	Offset into log page
 * @log:	Log page data buffer
 * @len:	Length (in bytes) of provided user buffer to hold the log data
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_FDP_STATS
 */
static inline
void nvme_init_get_log_fdp_stats(struct nvme_passthru_cmd *cmd,
		__u16 egid, __u64 lpo, void *log, __u32 len)
{
	nvme_init_get_log(cmd, NVME_NSID_NONE,
		NVME_LOG_LID_FDP_STATS, NVME_CSI_NVM,
		log, len);
	cmd->cdw11 |= NVME_FIELD_ENCODE(egid,
			NVME_LOG_CDW11_LSI_SHIFT,
			NVME_LOG_CDW11_LSI_MASK);
	nvme_init_get_log_lpo(cmd, lpo);
}

/**
 * nvme_init_get_log_fdp_events() - Initialize passthru command for
 * Flexible Data Placement Events
 * @cmd:		Passthru command to use
 * @host_events:	Whether to report host or controller events
 * @egid:		Endurance group identifier
 * @lpo:		Offset into log page
 * @log:		Log page data buffer
 * @len:		Length (in bytes) of provided user buffer to hold
 *			the log data
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_FDP_EVENTS
 */
static inline void
nvme_init_get_log_fdp_events(struct nvme_passthru_cmd *cmd,
		bool host_events, __u16 egid, __u64 lpo, void *log, __u32 len)
{
	nvme_init_get_log(cmd, NVME_NSID_NONE,
		NVME_LOG_LID_FDP_EVENTS, NVME_CSI_NVM,
		log, len);
	cmd->cdw10 |= NVME_FIELD_ENCODE((__u8)(host_events ? 0x1 : 0x0),
			NVME_LOG_CDW10_LSP_SHIFT,
			NVME_LOG_CDW10_LSP_MASK);
	cmd->cdw11 |= NVME_FIELD_ENCODE(egid,
			NVME_LOG_CDW11_LSI_SHIFT,
			NVME_LOG_CDW11_LSI_MASK);
	nvme_init_get_log_lpo(cmd, lpo);
}


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
nvme_init_get_log_discovery(struct nvme_passthru_cmd *cmd,
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
nvme_init_get_log_host_discovery(struct nvme_passthru_cmd *cmd,
		bool allhoste, struct nvme_host_discover_log *log, __u32 len)
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
nvme_init_get_log_ave_discovery(struct nvme_passthru_cmd *cmd,
		struct nvme_ave_discover_log *log, __u32 len)
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
nvme_init_get_log_pull_model_ddc_req(struct nvme_passthru_cmd *cmd,
		struct nvme_pull_model_ddc_req_log *log, __u32 len)
{
	nvme_init_get_log(cmd, NVME_NSID_ALL,
		NVME_LOG_LID_PULL_MODEL_DDC_REQ, NVME_CSI_NVM,
		log, len);
}

/**
 * nvme_init_get_log_reservation() - Initialize passthru command for
 * Reservation Notification
 * @cmd:	Passthru command to use
 * @log:	User address to store the reservation log
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_RESERVATION
 */
static inline void
nvme_init_get_log_reservation(struct nvme_passthru_cmd *cmd,
			struct nvme_resv_notification_log *log)
{
	nvme_init_get_log(cmd, NVME_NSID_ALL,
		NVME_LOG_LID_RESERVATION, NVME_CSI_NVM,
		log, sizeof(*log));
}

/**
 * nvme_init_get_log_sanitize() - Initialize passthru command for
 * Sanitize Status
 * @cmd:	Passthru command to use
 * @log:	User address to store the sanitize log
 *
 * Initializes the passthru command buffer for the Get Log command with
 * LID value %NVME_LOG_LID_SANITIZE
 */
static inline void
nvme_init_get_log_sanitize(struct nvme_passthru_cmd *cmd,
		struct nvme_sanitize_log_page *log)
{
	nvme_init_get_log(cmd, NVME_NSID_ALL,
		NVME_LOG_LID_SANITIZE, NVME_CSI_NVM,
		log, sizeof(*log));
}

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
nvme_init_get_log_zns_changed_zones(struct nvme_passthru_cmd *cmd,
		__u32 nsid, struct nvme_zns_changed_zone_log *log)
{
	nvme_init_get_log(cmd, nsid,
		NVME_LOG_LID_ZNS_CHANGED_ZONES, NVME_CSI_ZNS,
		log, sizeof(*log));
}

/**
 * nvme_get_ana_log_atomic() - Retrieve Asymmetric Namespace Access
 * log page atomically
 * @hdl:	Transport handle
 * @rae:	Whether to retain asynchronous events
 * @rgo:	Whether to retrieve ANA groups only (no NSIDs)
 * @log:	Pointer to a buffer to receive the ANA log page
 * @len:	Input: the length of the log page buffer.
 *		Output: the actual length of the ANA log page.
 * @retries:	The maximum number of times to retry on log page changes
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
int
nvme_get_ana_log_atomic(struct nvme_transport_handle *hdl, bool rae, bool rgo,
		struct nvme_ana_log *log, __u32 *len, unsigned int retries);

/**
 * nvme_init_set_features() - Initialize passthru command for
 * Set Features
 * @cmd:	Passthru command to use
 * @fid:	Feature identifier
 * @sv:		Save value across power states
 */
static inline void
nvme_init_set_features(struct nvme_passthru_cmd *cmd, __u8 fid, bool sv)
{
	__u32 cdw10 = NVME_FIELD_ENCODE(fid,
			NVME_SET_FEATURES_CDW10_FID_SHIFT,
			NVME_SET_FEATURES_CDW10_FID_MASK) |
		      NVME_FIELD_ENCODE(sv,
			NVME_SET_FEATURES_CDW10_SV_SHIFT,
			NVME_SET_FEATURES_CDW10_SV_MASK);

	memset(cmd, 0, sizeof(*cmd));

	cmd->opcode	= nvme_admin_set_features;
	cmd->cdw10	= cdw10;
}

/**
 * nvme_init_set_features_arbitration() -Initialize passthru command for
 * Arbitration Features
 * @cmd:	Passthru command to use
 * @sv:		Save value across power states
 * @ab:		Arbitration Burst
 * @lpw:	Low Priority Weight
 * @mpw:	Medium Priority Weight
 * @hpw:	High Priority Weight
 *
 * Initializes the passthru command buffer for the Set Features command with
 * FID value %NVME_FEAT_FID_ARBRITARTION
 */
static inline void
nvme_init_set_features_arbitration(struct nvme_passthru_cmd *cmd,
		bool sv, __u8 ab, __u8 lpw, __u8 mpw, __u8 hpw)
{
	nvme_init_set_features(cmd, NVME_FEAT_FID_ARBITRATION, sv);
	cmd->cdw11 = NVME_FIELD_ENCODE(ab,
			NVME_FEAT_ARBITRATION_BURST_SHIFT,
			NVME_FEAT_ARBITRATION_BURST_MASK) |
		     NVME_FIELD_ENCODE(lpw,
			NVME_FEAT_ARBITRATION_LPW_SHIFT,
			NVME_FEAT_ARBITRATION_LPW_MASK) |
		     NVME_FIELD_ENCODE(mpw,
			NVME_FEAT_ARBITRATION_MPW_SHIFT,
			NVME_FEAT_ARBITRATION_MPW_MASK) |
		     NVME_FIELD_ENCODE(hpw,
			NVME_FEAT_ARBITRATION_HPW_SHIFT,
			NVME_FEAT_ARBITRATION_HPW_MASK);
}

/**
 * nvme_init_set_features_power_mgmt() - Initialize passthru command for
 * Power Management
 * @cmd:	Passthru command to use
 * @sv:		Save value across power states
 * @ps:		Power State
 * @wh:		Workload Hint
 *
 * Initializes the passthru command buffer for the Set Features command with
 * FID value %NVME_FEAT_FID_PWRMGMT_PS
 */
static inline void
nvme_init_set_features_power_mgmt(struct nvme_passthru_cmd *cmd,
		bool sv, __u8 ps, __u8 wh)
{

	nvme_init_set_features(cmd, NVME_FEAT_FID_POWER_MGMT, sv);
	cmd->cdw11 = NVME_FIELD_ENCODE(ps,
			NVME_FEAT_PWRMGMT_PS_SHIFT,
			NVME_FEAT_PWRMGMT_PS_MASK) |
		     NVME_FIELD_ENCODE(wh,
			NVME_FEAT_PWRMGMT_WH_SHIFT,
			NVME_FEAT_PWRMGMT_WH_MASK);
}

/**
 * nvme_init_set_features_lba_range() - Initialize passthru command for
 * LBA Range
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID
 * @sv:		Save value across power states
 * @num:	Number of ranges in @data
 * @data:	User address of feature data
 *
 * Initializes the passthru command buffer for the Set Features command with
 * FID value %NVME_FEAT_FID_LBA_RANGE
 */
static inline void
nvme_init_set_features_lba_range(struct nvme_passthru_cmd *cmd,
		__u32 nsid, bool sv, __u8 num,
		struct nvme_lba_range_type *data)
{
	nvme_init_set_features(cmd, NVME_FEAT_FID_LBA_RANGE, sv);
	cmd->nsid = nsid;
	cmd->cdw11 = NVME_FIELD_ENCODE(num - 1,
			NVME_SET_FEATURES_CDW11_NUM_SHIFT,
			NVME_SET_FEATURES_CDW11_NUM_MASK);
	cmd->data_len = sizeof(*data);
	cmd->addr = (__u64)(uintptr_t)data;
}

/**
 * nvme_init_set_features_temp_thresh() - Initialize passthru command for
 * Temperature Threshold
 * @cmd:	Passthru command to use
 * @sv:		Save value across power states
 * @tmpth:	Temperature Threshold
 * @tmpsel:	Threshold Temperature Select
 * @thsel:	Threshold Type Select
 * @tmpthh:	Temperature Threshold Hysteresis
 *
 * Initializes the passthru command buffer for the Set Features command with
 * FID value %NVME_FEAT_FID_TEMP_THRESH
 */
static inline void
nvme_init_set_features_temp_thresh(struct nvme_passthru_cmd *cmd,
		bool sv, __u16 tmpth, __u8 tmpsel,
		enum nvme_feat_tmpthresh_thsel thsel, __u8 tmpthh)
{

	nvme_init_set_features(cmd, NVME_FEAT_FID_TEMP_THRESH, sv);
	cmd->cdw11 = NVME_FIELD_ENCODE(tmpth,
			NVME_FEAT_TT_TMPTH_SHIFT,
			NVME_FEAT_TT_TMPTH_MASK) |
		     NVME_FIELD_ENCODE(tmpsel,
			NVME_FEAT_TT_TMPSEL_SHIFT,
			NVME_FEAT_TT_TMPSEL_MASK) |
		     NVME_FIELD_ENCODE(thsel,
			NVME_FEAT_TT_THSEL_SHIFT,
			NVME_FEAT_TT_THSEL_MASK) |
		     NVME_FIELD_ENCODE(tmpthh,
			NVME_FEAT_TT_TMPTHH_SHIFT,
			NVME_FEAT_TT_TMPTHH_MASK);
}

/**
 * nvme_init_set_features_err_recovery() - Initialize passthru command for
 * Error Recovery
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID
 * @sv:		Save value across power states
 * @tler:	Time-limited error recovery value
 * @dulbe:	Deallocated or Unwritten Logical Block Error Enable
 *
 * Initializes the passthru command buffer for the Set Features command with
 * FID value %NVME_FEAT_FID_ERR_RECOVERY
 */
static inline void
nvme_init_set_features_err_recovery(struct nvme_passthru_cmd *cmd,
		__u32 nsid, bool sv, __u16 tler, bool dulbe)
{
	nvme_init_set_features(cmd, NVME_FEAT_FID_ERR_RECOVERY, sv);
	cmd->nsid = nsid;
	cmd->cdw11 = NVME_FIELD_ENCODE(tler,
			NVME_FEAT_ERROR_RECOVERY_TLER_SHIFT,
			NVME_FEAT_ERROR_RECOVERY_TLER_MASK) |
		     NVME_FIELD_ENCODE(dulbe,
			NVME_FEAT_ERROR_RECOVERY_DULBE_SHIFT,
			NVME_FEAT_ERROR_RECOVERY_DULBE_MASK);
}

/**
 * nvme_init_set_features_volatile_wc() - Initialize passthru command for
 * Volatile Write Cache
 * @cmd:	Passthru command to use
 * @sv:		Save value across power states
 * @wce:	Write cache enable
 *
 * Initializes the passthru command buffer for the Set Features command with
 * FID value %NVME_FEAT_FID_VOLATILE_WC
 */
static inline void
nvme_init_set_features_volatile_wc(struct nvme_passthru_cmd *cmd,
		bool sv, bool wce)
{
	nvme_init_set_features(cmd, NVME_FEAT_FID_VOLATILE_WC, sv);
	cmd->cdw11 = NVME_FIELD_ENCODE(wce,
			NVME_FEAT_VWC_WCE_SHIFT,
			NVME_FEAT_VWC_WCE_MASK);
}

/**
 * nvme_init_set_features_irq_coalesce() - Initialize passthru command for
 * IRQ Coalescing
 * @cmd:	Passthru command to use
 * @sv:		Save value across power states
 * @thr:	Aggregation Threshold
 * @time:	Aggregation Time
 *
 * Initializes the passthru command buffer for the Set Features command with
 * FID value %NVME_FEAT_FID_IRQ_COALESCE
 */
static inline void
nvme_init_set_features_irq_coalesce(struct nvme_passthru_cmd *cmd,
                bool sv, __u8 thr, __u8 time)
{
	nvme_init_set_features(cmd, NVME_FEAT_FID_IRQ_COALESCE, sv);
	cmd->cdw11 = NVME_FIELD_ENCODE(thr,
			NVME_FEAT_IRQC_THR_SHIFT,
			NVME_FEAT_IRQC_THR_MASK) |
		     NVME_FIELD_ENCODE(time,
			NVME_FEAT_IRQC_TIME_SHIFT,
			NVME_FEAT_IRQC_TIME_MASK);
}

/**
 * nvme_init_set_features_irq_config() - Initialize passthru command for
 * IRQ Config
 * @cmd:	Passthru command to use
 * @sv:		Save value across power states
 * @iv:		Interrupt Vector
 * @cd:		Coalescing Disable
 *
 * Initializes the passthru command buffer for the Set Features command with
 * FID value %NVME_FEAT_FID_IRQ_CONFIG
 */
static inline void
nvme_init_set_features_irq_config(struct nvme_passthru_cmd *cmd,
		bool sv, __u16 iv, bool cd)
{
	nvme_init_set_features(cmd, NVME_FEAT_FID_IRQ_CONFIG, sv);
	cmd->cdw11 = NVME_FIELD_ENCODE(iv,
			NVME_FEAT_ICFG_IV_SHIFT,
			NVME_FEAT_ICFG_IV_MASK) |
		     NVME_FIELD_ENCODE(cd,
			NVME_FEAT_ICFG_CD_SHIFT,
			NVME_FEAT_ICFG_CD_MASK);
}

/**
 * nvme_init_set_features_write_atomic() - Initialize passthru command for
 * Write Atomic
 * @cmd:	Passthru command to use
 * @sv:		Save value across power states
 * @dn:		Disable Normal
 *
 * Initializes the passthru command buffer for the Set Features command with
 * FID value %NVME_FEAT_FID_WRITE_ATOMIC
 */
static inline void
nvme_init_set_features_write_atomic(struct nvme_passthru_cmd *cmd,
		bool sv, bool dn)
{
	nvme_init_set_features(cmd, NVME_FEAT_FID_WRITE_ATOMIC, sv);
	cmd->cdw11 = NVME_FIELD_ENCODE(dn,
			NVME_FEAT_WA_DN_SHIFT,
			NVME_FEAT_WA_DN_MASK);
}

/**
 * nvme_init_set_features_async_event() - Initialize passthru command for
 * Asynchronous Event Configuration
 * @cmd:	Passthru command to use
 * @sv:		Save value across power states
 * @events:	Events to enable
 *
 * Initializes the passthru command buffer for the Set Features command with
 * FID value %NVME_FEAT_FID_ASYNC_EVENT
 */
static inline void
nvme_init_set_features_async_event(struct nvme_passthru_cmd *cmd,
		bool sv, __u32 events)
{
	nvme_init_set_features(cmd, NVME_FEAT_FID_ASYNC_EVENT, sv);
	cmd->cdw11 = events;
}

/**
 * nvme_init_set_features_auto_pst() - Initialize passthru command for
 * Autonomous Power State Transition
 * @cmd:	Passthru command to use
 * @sv:		Save value across power states
 * @apste:	Autonomous Power State Transition Enable
 * @apst:	Autonomous Power State Transition data buffer
 *
 * Initializes the passthru command buffer for the Set Features command with
 * FID value %NVME_FEAT_FID_AUTO_PST
 */
static inline void
nvme_init_set_features_auto_pst(struct nvme_passthru_cmd *cmd,
                bool sv, bool apste, struct nvme_feat_auto_pst *apst)
{
        nvme_init_set_features(cmd, NVME_FEAT_FID_AUTO_PST, sv);
        cmd->cdw11 = NVME_FIELD_ENCODE(apste,
                                       NVME_FEAT_APST_APSTE_SHIFT,
                                       NVME_FEAT_APST_APSTE_MASK);
	cmd->data_len = sizeof(*apst);
	cmd->addr = (__u64)(uintptr_t)apst;
}

/**
 * nvme_init_set_features_timestamp() - Initialize passthru command for
 * Timestamp
 * @cmd:	Passthru command to use
 * @sv:		Save value across power states
 * @tstmp:	The current timestamp value to assign to this feature
 * @ts:		Timestamp data buffer (populated by this function)
 *
 * Initializes the passthru command buffer for the Set Features command with
 * FID value %NVME_FEAT_FID_TIMESTAMP. The caller must provide a valid
 * buffer via @ts, which this function will populate.
 */
static inline void
nvme_init_set_features_timestamp(struct nvme_passthru_cmd *cmd,
		bool sv, __u64 tstmp, struct nvme_timestamp *ts)
{
	__le64 t = htole64(tstmp);

	memcpy(ts, &t, sizeof(__le64));

	nvme_init_set_features(cmd, NVME_FEAT_FID_TIMESTAMP, sv);
	cmd->data_len = sizeof(*ts);
	cmd->addr = (__u64)(uintptr_t)ts;
}

/**
 * nvme_init_set_features_hctm() - Initialize passthru command for
 * Host Controlled Thermal Management
 * @cmd:	Passthru command to use
 * @sv:		Save value across power states
 * @tmt2:	Thermal Management Temperature 2
 * @tmt1:	Thermal Management Temperature 1
 *
 * Initializes the passthru command buffer for the Set Features command with
 * FID value %NVME_FEAT_FID_HCTM
 */
static inline void
nvme_init_set_features_hctm(struct nvme_passthru_cmd *cmd,
		bool sv, __u16 tmt2, __u16 tmt1)
{
	nvme_init_set_features(cmd, NVME_FEAT_FID_HCTM, sv);
	cmd->cdw11 = NVME_FIELD_ENCODE(tmt2,
				       NVME_FEAT_HCTM_TMT2_SHIFT,
				       NVME_FEAT_HCTM_TMT2_MASK) |
		     NVME_FIELD_ENCODE(tmt1,
				       NVME_FEAT_HCTM_TMT1_SHIFT,
				       NVME_FEAT_HCTM_TMT1_MASK);
}

/**
 * nvme_init_set_features_nopsc() - Initialize passthru command for
 * Non-Operational Power State Config
 * @cmd:	Passthru command to use
 * @sv:		Save value across power states
 * @noppme:	Non-Operational Power State Permissive Mode Enable
 *
 * Initializes the passthru command buffer for the Set Features command with
 * FID value %NVME_FEAT_FID_NOPSC
 */
static inline void
nvme_init_set_features_nopsc(struct nvme_passthru_cmd *cmd,
		bool sv, bool noppme)
{
	nvme_init_set_features(cmd, NVME_FEAT_FID_NOPSC, sv);
	cmd->cdw11 = NVME_FIELD_ENCODE(noppme,
				       NVME_FEAT_NOPS_NOPPME_SHIFT,
				       NVME_FEAT_NOPS_NOPPME_MASK);
}

/**
 * nvme_init_set_features_rrl() - Initialize passthru command for
 * Read Recovery Level
 * @cmd:	Passthru command to use
 * @sv:		Save value across power states
 * @nvmsetid:	NVM set id
 * @rrl:	Read recovery level setting
 *
 * Initializes the passthru command buffer for the Set Features command with
 * FID value %NVME_FEAT_FID_RRL
 */
static inline void
nvme_init_set_features_rrl(struct nvme_passthru_cmd *cmd,
                bool sv, __u16 nvmsetid, __u8 rrl)
{
        nvme_init_set_features(cmd, NVME_FEAT_FID_RRL, sv);
	cmd->cdw11 = NVME_FIELD_ENCODE(nvmsetid,
			NVME_FEAT_RRL_NVMSETID_SHIFT,
			NVME_FEAT_RRL_NVMSETID_MASK);
	cmd->cdw12 = NVME_FIELD_ENCODE(rrl,
			NVME_FEAT_RRL_RRL_SHIFT,
			NVME_FEAT_RRL_RRL_MASK);
}

/**
 * nvme_init_set_features_plm_config() - Initialize passthru command for
 * Predictable Latency Mode Config
 * @cmd:	Passthru command to use
 * @sv:		Save value across power states
 * @nvmsetid:	NVM Set Identifier
 * @lpe:	Predictable Latency Enable
 * @data:	Pointer to structure nvme_plm_config
 *
 * Initializes the passthru command buffer for the Set Features command with
 * FID value %NVME_FEAT_FID_PLM_CONFIG
 */
static inline void
nvme_init_set_features_plm_config(struct nvme_passthru_cmd *cmd,
		bool sv, __u16 nvmsetid, bool lpe, struct nvme_plm_config *data)
{
	nvme_init_set_features(cmd, NVME_FEAT_FID_PLM_CONFIG, sv);
	cmd->cdw11 = NVME_FIELD_ENCODE(nvmsetid,
			NVME_FEAT_PLM_NVMSETID_SHIFT,
			NVME_FEAT_PLM_NVMSETID_MASK);
	cmd->cdw12 = NVME_FIELD_ENCODE(lpe,
			NVME_FEAT_PLM_LPE_SHIFT,
			NVME_FEAT_PLM_LPE_MASK);
        cmd->data_len = sizeof(*data);
        cmd->addr = (__u64)(uintptr_t)data;
}

/**
 * nvme_init_set_features_plm_window() - Initialize passthru command for
 * Predictable Latency Mode Window
 * @cmd:	Passthru command to use
 * @sv:		Save value across power states
 * @nvmsetid:	NVM Set Identifier
 * @wsel:	Window Select
 *
 * Initializes the passthru command buffer for the Set Features command with
 * FID value %NVME_FEAT_FID_PLM_WINDOW
 */
static inline void
nvme_init_set_features_plm_window(struct nvme_passthru_cmd *cmd,
		bool sv, __u16 nvmsetid,
		enum nvme_feat_plm_window_select wsel)
{
	nvme_init_set_features(cmd, NVME_FEAT_FID_PLM_WINDOW, sv);
	cmd->cdw11 = NVME_FIELD_ENCODE(nvmsetid,
			NVME_FEAT_PLM_NVMSETID_SHIFT,
			NVME_FEAT_PLM_NVMSETID_MASK);
	cmd->cdw12 = NVME_FIELD_ENCODE(wsel,
			NVME_FEAT_PLMW_WS_SHIFT,
			NVME_FEAT_PLMW_WS_MASK);
}

/**
 * nvme_init_set_features_lba_sts_interval() - Initialize passthru command for
 * LBA Status Information Interval
 * @cmd:        Passthru command to use
 * @sv:         Save value across power states
 * @lsiri:      LBA Status Information Report Interval
 * @lsipi:      LBA Status Information Poll Interval
 *
 * Initializes the passthru command buffer for the Set Features command with
 * FID value %NVME_FEAT_FID_LBA_STS_INTERVAL
 */
static inline void
nvme_init_set_features_lba_sts_interval(struct nvme_passthru_cmd *cmd,
		bool sv, __u16 lsiri, __u16 lsipi)
{
	nvme_init_set_features(cmd, NVME_FEAT_FID_LBA_STS_INTERVAL, sv);
	cmd->cdw11 = NVME_FIELD_ENCODE(lsiri,
			NVME_FEAT_LBAS_LSIRI_SHIFT,
			NVME_FEAT_LBAS_LSIRI_MASK) |
		     NVME_FIELD_ENCODE(lsipi,
			NVME_FEAT_LBAS_LSIPI_SHIFT,
			NVME_FEAT_LBAS_LSIPI_MASK);
}

/**
 * nvme_init_set_features_host_behavior() - Initialize passthru command for
 * Host Behavior
 * @cmd:	Passthru command to use
 * @sv:		Save value across power states
 * @data:	Pointer to structure nvme_feat_host_behavior
 *
 * Initializes the passthru command buffer for the Set Features command with
 * FID value %NVME_FEAT_FID_HOST_BEHAVIOR
 */
static inline void
nvme_init_set_features_host_behavior(struct nvme_passthru_cmd *cmd,
		bool sv, struct nvme_feat_host_behavior *data)
{
	nvme_init_set_features(cmd, NVME_FEAT_FID_HOST_BEHAVIOR, sv);
	cmd->data_len = sizeof(*data);
	cmd->addr = (__u64)(uintptr_t)data;
}

/**
 * nvme_init_set_features_sanitize() - Initialize passthru command for
 * Sanitize
 * @cmd:	Passthru command to use
 * @sv:		Save value across power states
 * @nodrm:	No-Deallocate Response Mode
 *
 * Initializes the passthru command buffer for the Set Features command with
 * FID value %NVME_FEAT_FID_SANITIZE
 */
static inline void
nvme_init_set_features_sanitize(struct nvme_passthru_cmd *cmd,
		bool sv, bool nodrm)
{
	nvme_init_set_features(cmd, NVME_FEAT_FID_SANITIZE, sv);
	cmd->cdw11 = NVME_FIELD_ENCODE(nodrm,
				       NVME_FEAT_SANITIZE_NODRM_SHIFT,
				       NVME_FEAT_SANITIZE_NODRM_MASK);
}

/**
 * nvme_init_set_features_endurance_evt_cfg() - Initialize passthru command for
 * Endurance Group Event Configuration
 * @cmd:	Passthru command to use
 * @sv:		Save value across power states
 * @endgid:	Endurance Group Identifier
 * @egcw:	Flags to enable warning,
 *		see &enum nvme_eg_critical_warning_flags
 *
 * Initializes the passthru command buffer for the Set Features command with
 * FID value %NVME_FEAT_FID_ENDURANCE_EVT_CFG
 */
static inline void
nvme_init_set_features_endurance_evt_cfg(struct nvme_passthru_cmd *cmd,
		bool sv, __u16 endgid, __u8 egcw)
{
	nvme_init_set_features(cmd, NVME_FEAT_FID_ENDURANCE_EVT_CFG, sv);
	cmd->cdw11 = NVME_FIELD_ENCODE(endgid,
				       NVME_FEAT_EG_ENDGID_SHIFT,
				       NVME_FEAT_EG_ENDGID_MASK) |
		     NVME_FIELD_ENCODE(egcw,
				       NVME_FEAT_EG_EGCW_SHIFT,
				       NVME_FEAT_EG_EGCW_MASK);
}

/**
 * nvme_init_set_features_sw_progress() - Initialize passthru command for
 * Software Pogress Marker
 * @cmd:	Passthru command to use
 * @sv:		Save value across power states
 * @pbslc:	Pre-boot Software Load Count
 *
 * Initializes the passthru command buffer for the Set Features command with
 * FID value %NVME_FEAT_FID_SW_PROGRESS
 */
static inline void
nvme_init_set_features_sw_progress(struct nvme_passthru_cmd *cmd,
		bool sv, __u8 pbslc)
{
	nvme_init_set_features(cmd, NVME_FEAT_FID_SW_PROGRESS, sv);
	cmd->cdw11 = NVME_FIELD_ENCODE(pbslc,
				       NVME_FEAT_SPM_PBSLC_SHIFT,
				       NVME_FEAT_SPM_PBSLC_MASK);
}

/**
 * nvme_init_set_features_host_id() - Initialize passthru command for
 * Host Identifier
 * @cmd:        Passthru command to use
 * @sv:         Save value across power states
 * @exhid:      Enable Extended Host Identifier
 * @hostid:     Host ID buffer to set
 *
 * Initializes the passthru command buffer for the Set Features command with
 * FID value %NVME_FEAT_FID_HOST_ID.
 */
static inline void
nvme_init_set_features_host_id(struct nvme_passthru_cmd *cmd,
		bool sv, bool exhid, __u8 *hostid)
{
	nvme_init_set_features(cmd, NVME_FEAT_FID_HOST_ID, sv);
	cmd->cdw11 = NVME_FIELD_ENCODE(exhid,
				       NVME_FEAT_HOSTID_EXHID_SHIFT,
				       NVME_FEAT_HOSTID_EXHID_MASK);
	cmd->data_len = exhid ? 16 : 8;
	cmd->addr = (__u64)(uintptr_t)hostid;
}

/**
 * nvme_init_set_features_resv_mask() - Initialize passthru command for
 * Reservation Notification Mask
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID
 * @sv:		Save value across power states
 * @mask:	Reservation Notification Mask Field
 *
 * Initializes the passthru command buffer for the Set Features command with
 * FID value %NVME_FEAT_FID_RESV_MASK
 */
static inline void
nvme_init_set_features_resv_mask(struct nvme_passthru_cmd *cmd, __u32 nsid,
		bool sv, __u32 mask)
{
	nvme_init_set_features(cmd, NVME_FEAT_FID_RESV_MASK, sv);
	cmd->nsid = nsid;
	cmd->cdw11 = mask;
}

/**
 * nvme_init_set_features_resv_persist() - Initialize passthru command for
 * Reservation Persistence
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID
 * @sv:		Save value across power states
 * @ptpl:	Persist Through Power Loss
 *
 * Initializes the passthru command buffer for the Set Features command with
 * FID value %NVME_FEAT_FID_RESV_PERSIST
 */
static inline void
nvme_init_set_features_resv_persist(struct nvme_passthru_cmd *cmd, __u32 nsid,
		bool sv, bool ptpl)
{
	nvme_init_set_features(cmd, NVME_FEAT_FID_RESV_PERSIST, sv);
	cmd->nsid = nsid;
	cmd->cdw11 = NVME_FIELD_ENCODE(ptpl,
			NVME_FEAT_RESP_PTPL_SHIFT,
			NVME_FEAT_RESP_PTPL_MASK);
}

/**
 * nvme_init_set_features_write_protect() - Initialize passthru command for
 * Write Protect
 * @cmd:        Passthru command to use
 * @nsid:       Namespace ID
 * @sv:         Save value across power states
 * @wps:        Write Protection State
 *
 * Initializes the passthru command buffer for the Set Features command with
 * FID value %NVME_FEAT_FID_WRITE_PROTECT
 */
static inline void
nvme_init_set_features_write_protect(struct nvme_passthru_cmd *cmd, __u32 nsid,
		bool sv, enum nvme_feat_nswpcfg_state wps)
{
	nvme_init_set_features(cmd, NVME_FEAT_FID_WRITE_PROTECT, sv);
	cmd->nsid = nsid;
	cmd->cdw11 = NVME_FIELD_ENCODE(wps,
			NVME_FEAT_WP_WPS_SHIFT,
			NVME_FEAT_WP_WPS_MASK);
}

/**
 * nvme_init_set_features_iocs_profile() - Initialize passthru command for
 * I/O Command Set Profile
 * @cmd:	Passthru command to use
 * @sv:		Save value across power states
 * @iocsci:	I/O Command Set Combination Index
 *
 * Initializes the passthru command buffer for the Set Features command with
 * FID value %NVME_FEAT_FID_IOCS_PROFILE
 */
static inline void
nvme_init_set_features_iocs_profile(struct nvme_passthru_cmd *cmd,
		bool sv, __u16 iocsci)
{
	nvme_init_set_features(cmd, NVME_FEAT_FID_IOCS_PROFILE, sv);
	cmd->cdw11 = NVME_FIELD_ENCODE(iocsci,
			NVME_FEAT_IOCSP_IOCSCI_SHIFT,
			NVME_FEAT_IOCSP_IOCSCI_MASK);
}

/**
 * nvme_init_get_features() - Initialize passthru command for
 * Get Features
 * @cmd:	Passthru command to use
 * @fid:	Feature identifier, see &enum nvme_features_id
 * @sel:	Select which type of attribute to return,
 *		see &enum nvme_get_features_sel
 */
static inline void
nvme_init_get_features(struct nvme_passthru_cmd *cmd, __u8 fid,
		enum nvme_get_features_sel sel)
{
	__u32 cdw10 = NVME_FIELD_ENCODE(fid,
			NVME_GET_FEATURES_CDW10_FID_SHIFT,
			NVME_GET_FEATURES_CDW10_FID_MASK) |
		      NVME_FIELD_ENCODE(sel,
			NVME_GET_FEATURES_CDW10_SEL_SHIFT,
			NVME_GET_FEATURES_CDW10_SEL_MASK);

	memset(cmd, 0, sizeof(*cmd));

	cmd->opcode	= nvme_admin_get_features;
	cmd->cdw10	= cdw10;
}

/**
 * nvme_init_get_features_arbitration() - Initialize passthru command for
 * Get Features - Arbitration
 * @cmd:	Passthru command to use
 * @sel:	Select which type of attribute to return,
 *		see &enum nvme_get_features_sel
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_ARBITRATION
 */
static inline void
nvme_init_get_features_arbitration(struct nvme_passthru_cmd *cmd,
		enum nvme_get_features_sel sel)
{
	nvme_init_get_features(cmd, NVME_FEAT_FID_ARBITRATION, sel);
}

/**
 * nvme_init_get_features_power_mgmt() - Initialize passthru command for
 * Get Features - Power Management
 * @cmd:	Passthru command to use
 * @sel:	Select which type of attribute to return,
 *		see &enum nvme_get_features_sel
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_POWER_MGMT
 */
static inline void
nvme_init_get_features_power_mgmt(struct nvme_passthru_cmd *cmd,
		enum nvme_get_features_sel sel)
{
	nvme_init_get_features(cmd, NVME_FEAT_FID_POWER_MGMT, sel);
}

/**
 * nvme_init_get_features_lba_range() - Initialize passthru command for
 * Get Features - LBA Range
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID
 * @sel:	Select which type of attribute to return,
 *		see &enum nvme_get_features_sel
 * @lrt:	Buffer to receive LBA Range Type data structure
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_LBA_RANGE
 */
static inline void
nvme_init_get_features_lba_range(struct nvme_passthru_cmd *cmd, __u32 nsid,
		enum nvme_get_features_sel sel, struct nvme_lba_range_type *lrt)
{
	nvme_init_get_features(cmd, NVME_FEAT_FID_LBA_RANGE, sel);
	cmd->nsid = nsid;
	cmd->data_len = sizeof(*lrt);
	cmd->addr = (__u64)(uintptr_t)lrt;
}

/**
 * nvme_init_get_features_temp_thresh() - Initialize passthru command for
 * Get Features - Temperature Threshold
 * @cmd:	Passthru command to use
 * @sel:	Select which type of attribute to return,
 * see &enum nvme_get_features_sel
 * @tmpsel:	Threshold Temperature Select
 * @thsel:	Threshold Type Select
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_TEMP_THRESH
 */
static inline void
nvme_init_get_features_temp_thresh(struct nvme_passthru_cmd *cmd,
		enum nvme_get_features_sel sel,
		__u8 tmpsel, enum nvme_feat_tmpthresh_thsel thsel)
{

	nvme_init_get_features(cmd, NVME_FEAT_FID_TEMP_THRESH, sel);
	cmd->cdw11 = NVME_FIELD_ENCODE(tmpsel,
			NVME_FEAT_TT_TMPSEL_SHIFT,
			NVME_FEAT_TT_TMPSEL_MASK) |
		     NVME_FIELD_ENCODE(thsel,
			NVME_FEAT_TT_THSEL_SHIFT,
			NVME_FEAT_TT_THSEL_MASK);
}

/**
 * nvme_init_get_features_err_recovery() - Initialize passthru command for
 * Get Features - Error Recovery
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID
 * @sel:	Select which type of attribute to return,
 *		see &enum nvme_get_features_sel
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_ERR_RECOVERY
 */
static inline void
nvme_init_get_features_err_recovery(struct nvme_passthru_cmd *cmd, __u32 nsid,
		enum nvme_get_features_sel sel)
{
	nvme_init_get_features(cmd, NVME_FEAT_FID_ERR_RECOVERY, sel);
	cmd->nsid = nsid;
}

/**
 * nvme_init_get_features_volatile_wc() - Initialize passthru command for
 * Get Features - Volatile Write Cache
 * @cmd:	Passthru command to use
 * @sel:	Select which type of attribute to return,
 * see &enum nvme_get_features_sel
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_VOLATILE_WC
 */
static inline void
nvme_init_get_features_volatile_wc(struct nvme_passthru_cmd *cmd,
		enum nvme_get_features_sel sel)
{
	nvme_init_get_features(cmd, NVME_FEAT_FID_VOLATILE_WC, sel);
}

/**
 * nvme_init_get_features_num_queues() - Initialize passthru command for
 * Get Features - Number of Queues
 * @cmd:	Passthru command to use
 * @sel:	Select which type of attribute to return,
 * see &enum nvme_get_features_sel
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_NUM_QUEUES
 */
static inline void
nvme_init_get_features_num_queues(struct nvme_passthru_cmd *cmd,
		enum nvme_get_features_sel sel)
{
	nvme_init_get_features(cmd, NVME_FEAT_FID_NUM_QUEUES, sel);
}

/**
 * nvme_init_get_features_irq_coalesce() - Initialize passthru command for
 * Get Features - IRQ Coalesce
 * @cmd:	Passthru command to use
 * @sel:	Select which type of attribute to return,
 *		see &enum nvme_get_features_sel
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_IRQ_COALESCE
 */
static inline void
nvme_init_get_features_irq_coalesce(struct nvme_passthru_cmd *cmd,
		enum nvme_get_features_sel sel)
{
	nvme_init_get_features(cmd, NVME_FEAT_FID_IRQ_COALESCE, sel);
}

/**
 * nvme_init_get_features_irq_config() - Initialize passthru command for
 * Get Features - IRQ Config
 * @cmd:	Passthru command to use
 * @sel:	Select which type of attribute to return,
 *		see &enum nvme_get_features_sel
 * @iv:		Interrupt Vector
 * @cd:		Coalescing Disable
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_IRQ_CONFIG
 */
static inline void
nvme_init_get_features_irq_config(struct nvme_passthru_cmd *cmd,
		enum nvme_get_features_sel sel,
		__u16 iv, bool cd)
{
	__u32 cdw11 = NVME_FIELD_ENCODE(iv,
				       NVME_FEAT_ICFG_IV_SHIFT,
				       NVME_FEAT_ICFG_IV_MASK) |
		     NVME_FIELD_ENCODE(cd,
				       NVME_FEAT_ICFG_CD_SHIFT,
				       NVME_FEAT_ICFG_CD_MASK);

	nvme_init_get_features(cmd, NVME_FEAT_FID_IRQ_CONFIG, sel);
	cmd->cdw11 = cdw11;
}

/**
 * nvme_init_get_features_write_atomic() - Initialize passthru command for
 * Get Features - Write Atomic
 * @cmd:        Passthru command to use
 * @sel:        Select which type of attribute to return,
 *		see &enum nvme_get_features_sel
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_WRITE_ATOMIC
 */
static inline void
nvme_init_get_features_write_atomic(struct nvme_passthru_cmd *cmd,
		enum nvme_get_features_sel sel)
{
	nvme_init_get_features(cmd, NVME_FEAT_FID_WRITE_ATOMIC, sel);
}

/**
 * nvme_init_get_features_async_event() - Initialize passthru command for
 * Get Features - Asynchronous Event Configuration
 * @cmd:        Passthru command to use
 * @sel:        Select which type of attribute to return,
 * see &enum nvme_get_features_sel
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_ASYNC_EVENT
 */
static inline void
nvme_init_get_features_async_event(struct nvme_passthru_cmd *cmd,
		enum nvme_get_features_sel sel)
{
	nvme_init_get_features(cmd, NVME_FEAT_FID_ASYNC_EVENT, sel);
}

/**
 * nvme_init_get_features_auto_pst() - Initialize passthru command for
 * Get Features - Autonomous Power State Transition
 * @cmd:	Passthru command to use
 * @sel:	Select which type of attribute to return,
 *		see &enum nvme_get_features_sel
 * @apst:	Autonomous Power State Transition data buffer
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_AUTO_PST
 */
static inline void
nvme_init_get_features_auto_pst(struct nvme_passthru_cmd *cmd,
		enum nvme_get_features_sel sel, struct nvme_feat_auto_pst *apst)
{
	nvme_init_get_features(cmd, NVME_FEAT_FID_AUTO_PST, sel);
	cmd->data_len = sizeof(*apst);
	cmd->addr = (__u64)(uintptr_t)apst;
}

/**
 * nvme_init_get_features_host_mem_buf() - Initialize passthru command for
 * Get Features - Host Memory Buffer
 * @cmd:	Passthru command to use
 * @sel:	Select which type of attribute to return,
 *		see &enum nvme_get_features_sel
 * @attrs:	Buffer for returned Host Memory Buffer Attributes
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_HOST_MEM_BUF
 */
static inline void
nvme_init_get_features_host_mem_buf(struct nvme_passthru_cmd *cmd,
		enum nvme_get_features_sel sel,
		struct nvme_host_mem_buf_attrs  *attrs)
{
	nvme_init_get_features(cmd, NVME_FEAT_FID_HOST_MEM_BUF, sel);
	cmd->data_len = sizeof(*attrs);
	cmd->addr = (__u64)(uintptr_t)attrs;
}

/**
 * nvme_init_get_features_timestamp() - Initialize passthru command for
 * Get Features - Timestamp
 * @cmd:	Passthru command to use
 * @sel:	Select which type of attribute to return,
 *		see &enum nvme_get_features_sel
 * @ts:		Current timestamp buffer
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_TIMESTAMP
 */
static inline void
nvme_init_get_features_timestamp(struct nvme_passthru_cmd *cmd,
		enum nvme_get_features_sel sel, struct nvme_timestamp *ts)
{
	nvme_init_get_features(cmd, NVME_FEAT_FID_TIMESTAMP, sel);
	cmd->data_len = sizeof(*ts);
	cmd->addr = (__u64)(uintptr_t)ts;
}

/**
 * nvme_init_get_features_kato() - Initialize passthru command for
 * Get Features - Keep Alive Timeout
 * @cmd:	Passthru command to use
 * @sel:	Select which type of attribute to return,
 *		see &enum nvme_get_features_sel
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_KATO
 */
static inline void
nvme_init_get_features_kato(struct nvme_passthru_cmd *cmd,
		enum nvme_get_features_sel sel)
{
	nvme_init_get_features(cmd, NVME_FEAT_FID_KATO, sel);
}

/**
 * nvme_init_get_features_hctm() - Initialize passthru command for
 * Get Features - Host Controlled Thermal Management
 * @cmd:	Passthru command to use
 * @sel:	Select which type of attribute to return,
 *		see &enum nvme_get_features_sel
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_HCTM
 */
static inline void
nvme_init_get_features_hctm(struct nvme_passthru_cmd *cmd,
		enum nvme_get_features_sel sel)
{
	nvme_init_get_features(cmd, NVME_FEAT_FID_HCTM, sel);
}

/**
 * nvme_init_get_features_nopsc() - Initialize passthru command for
 * Get Features - Non-Operational Power State Config
 * @cmd:	Passthru command to use
 * @sel:	Select which type of attribute to return,
 *		see &enum nvme_get_features_sel
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_NOPSC
 */
static inline void
nvme_init_get_features_nopsc(struct nvme_passthru_cmd *cmd,
		enum nvme_get_features_sel sel)
{
	nvme_init_get_features(cmd, NVME_FEAT_FID_NOPSC, sel);
}

/**
 * nvme_init_get_features_rrl() - Initialize passthru command for
 * Get Features - Read Recovery Level
 * @cmd:	Passthru command to use
 * @sel:	Select which type of attribute to return,
 *		see &enum nvme_get_features_sel
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_RRL
 */
static inline void
nvme_init_get_features_rrl(struct nvme_passthru_cmd *cmd,
		enum nvme_get_features_sel sel)
{
	nvme_init_get_features(cmd, NVME_FEAT_FID_RRL, sel);
}

/**
 * nvme_init_get_features_plm_config() - Initialize passthru command for
 * Get Features - Predictable Latency Mode Config
 * @cmd:	Passthru command to use
 * @sel:	Select which type of attribute to return,
 *		see &enum nvme_get_features_sel
 * @nvmsetid:   NVM set id
 * @plmc:       Buffer for returned Predictable Latency Mode Config
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_PLM_CONFIG
 */
static inline void
nvme_init_get_features_plm_config(struct nvme_passthru_cmd *cmd,
		enum nvme_get_features_sel sel, __u16 nvmsetid,
		struct nvme_plm_config *plmc)
{
	nvme_init_get_features(cmd, NVME_FEAT_FID_PLM_CONFIG, sel);
	cmd->cdw11 = NVME_FIELD_ENCODE(nvmsetid,
				       NVME_FEAT_PLM_NVMSETID_SHIFT,
				       NVME_FEAT_PLM_NVMSETID_MASK);
	cmd->data_len = sizeof(*plmc);
	cmd->addr = (__u64)(uintptr_t)plmc;
}

/**
 * nvme_init_get_features_plm_window() - Initialize passthru command for
 * Get Features - Predictable Latency Mode Window
 * @cmd:	Passthru command to use
 * @sel:	Select which type of attribute to return,
 *		see &enum nvme_get_features_sel
 * @nvmsetid:   NVM set id
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_PLM_WINDOW
 */
static inline void
nvme_init_get_features_plm_window(struct nvme_passthru_cmd *cmd,
		enum nvme_get_features_sel sel, __u16 nvmsetid)
{
	nvme_init_get_features(cmd, NVME_FEAT_FID_PLM_WINDOW, sel);
	cmd->cdw11 = NVME_FIELD_ENCODE(nvmsetid,
				       NVME_FEAT_PLM_NVMSETID_SHIFT,
				       NVME_FEAT_PLM_NVMSETID_MASK);
}

/**
 * nvme_init_get_features_lba_sts_interval() - Initialize passthru command for
 * Get Features - LBA Status Information Interval
 * @cmd:	Passthru command to use
 * @sel:	Select which type of attribute to return,
 *		see &enum nvme_get_features_sel
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_LBA_STS_INTERVAL
 */
static inline void
nvme_init_get_features_lba_sts_interval(struct nvme_passthru_cmd *cmd,
		enum nvme_get_features_sel sel)
{
	nvme_init_get_features(cmd, NVME_FEAT_FID_LBA_STS_INTERVAL, sel);
}

/**
 * nvme_init_get_features_host_behavior() - Initialize passthru command for
 * Get Features - Host Behavior
 * @cmd:	Passthru command to use
 * @sel:	Select which type of attribute to return,
 *		see &enum nvme_get_features_sel
 * @fhb:	Pointer to structure nvme_feat_host_behavior
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_HOST_BEHAVIOR
 */
static inline void
nvme_init_get_features_host_behavior(struct nvme_passthru_cmd *cmd,
		enum nvme_get_features_sel sel,
		struct nvme_feat_host_behavior *fhb)
{
	nvme_init_get_features(cmd, NVME_FEAT_FID_HOST_BEHAVIOR, sel);
	cmd->data_len = sizeof(*fhb);
	cmd->addr = (__u64)(uintptr_t)fhb;
}

/**
 * nvme_init_get_features_sanitize() - Initialize passthru command for
 * Get Features - Sanitize
 * @cmd:	Passthru command to use
 * @sel:	Select which type of attribute to return,
 *		see &enum nvme_get_features_sel
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_SANITIZE
 */
static inline void
nvme_init_get_features_sanitize(struct nvme_passthru_cmd *cmd,
		enum nvme_get_features_sel sel)
{
	nvme_init_get_features(cmd, NVME_FEAT_FID_SANITIZE, sel);
}

/**
 * nvme_init_get_features_endurance_event_cfg() - Initialize passthru command
 * for Get Features - Endurance Group Event Configuration
 * @cmd:	Passthru command to use
 * @sel:	Select which type of attribute to return,
 *		see &enum nvme_get_features_sel
 * @endgid:	Endurance Group Identifier
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_ENDURANCE_EVT_CFG
 */
static inline void
nvme_init_get_features_endurance_event_cfg(struct nvme_passthru_cmd *cmd,
		enum nvme_get_features_sel sel, __u16 endgid)
{
	nvme_init_get_features(cmd, NVME_FEAT_FID_ENDURANCE_EVT_CFG, sel);
	cmd->cdw11 = NVME_FIELD_ENCODE(endgid,
				       NVME_FEAT_EG_ENDGID_SHIFT,
				       NVME_FEAT_EG_ENDGID_MASK);
}

/**
 * nvme_init_get_features_sw_progress() - Initialize passthru command for
 * Get Features - Software Progress
 * @cmd:	Passthru command to use
 * @sel:	Select which type of attribute to return,
 * see &enum nvme_get_features_sel
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_SW_PROGRESS
 */
static inline void
nvme_init_get_features_sw_progress(struct nvme_passthru_cmd *cmd,
		enum nvme_get_features_sel sel)
{
	nvme_init_get_features(cmd, NVME_FEAT_FID_SW_PROGRESS, sel);
}

/**
 * nvme_init_get_features_host_id() - Initialize passthru command for
 * Get Features - Host Identifier
 * @cmd:	Passthru command to use
 * @sel:	Select which type of attribute to return,
 *		see &enum nvme_get_features_sel
 * @exhid:	Enable Extended Host Identifier
 * @hostid:	Buffer for returned host ID
 * @len:	Length of @hostid
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_HOST_ID
 */
static inline void
nvme_init_get_features_host_id(struct nvme_passthru_cmd *cmd,
		enum nvme_get_features_sel sel, bool exhid,
		void *hostid, __u32 len)
{
	nvme_init_get_features(cmd, NVME_FEAT_FID_HOST_ID, sel);
	cmd->cdw11 = NVME_FIELD_ENCODE(exhid,
				       NVME_FEAT_HOSTID_EXHID_SHIFT,
				       NVME_FEAT_HOSTID_EXHID_MASK);
	cmd->data_len = len;
	cmd->addr = (__u64)(uintptr_t)hostid;
}

/**
 * nvme_init_get_features_resv_mask() - Initialize passthru command for
 * Get Features - Reservation Notification Mask
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID
 * @sel:	Select which type of attribute to return,
 *		see &enum nvme_get_features_sel
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_RESV_MASK
 */
static inline void
nvme_init_get_features_resv_mask(struct nvme_passthru_cmd *cmd, __u32 nsid,
		enum nvme_get_features_sel sel)
{
	nvme_init_get_features(cmd, NVME_FEAT_FID_RESV_MASK, sel);
	cmd->nsid = nsid;
}

/**
 * nvme_init_get_features_resv_persist() - Initialize passthru command for
 * Get Features - Reservation Persistence
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID
 * @sel:	Select which type of attribute to return,
 *		see &enum nvme_get_features_sel
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_RESV_PERSIST
 */
static inline void
nvme_init_get_features_resv_persist(struct nvme_passthru_cmd *cmd, __u32 nsid,
		enum nvme_get_features_sel sel)
{
	nvme_init_get_features(cmd, NVME_FEAT_FID_RESV_PERSIST, sel);
	cmd->nsid = nsid;
}

/**
 * nvme_init_get_features_write_protect() - Initialize passthru command for
 * Get Features - Write Protect
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID
 * @sel:	Select which type of attribute to return,
 *		see &enum nvme_get_features_sel
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_WRITE_PROTECT
 */
static inline void
nvme_init_get_features_write_protect(struct nvme_passthru_cmd *cmd, __u32 nsid,
		enum nvme_get_features_sel sel)
{
	nvme_init_get_features(cmd, NVME_FEAT_FID_WRITE_PROTECT, sel);
	cmd->nsid = nsid;
}

/**
 * nvme_init_get_features_iocs_profile() - Initialize passthru command for
 * Get Features - I/O Command Set Profile
 * @cmd:	Passthru command to use
 * @sel:	Select which type of attribute to return,
 *		see &enum nvme_get_features_sel
 *
 * Initializes the passthru command buffer for the Get Features command with
 * FID value %NVME_FEAT_FID_IOCS_PROFILE
 */
static inline void
nvme_init_get_features_iocs_profile(struct nvme_passthru_cmd *cmd,
		enum nvme_get_features_sel sel)
{
	nvme_init_get_features(cmd, NVME_FEAT_FID_IOCS_PROFILE, sel);
}

/**
 * nvme_init_format_nvm() - Initialize passthru command for Format NVM
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID to format
 * @lbaf:	Logical block address format
 * @mset:	Metadata settings (extended or separated)
 * @pi:		Protection information type
 * @pil:	Protection information location (beginning or end)
 * @ses:	Secure erase settings
 *
 * Initializes the passthru command buffer for the Format NVM command.
 */
static inline void
nvme_init_format_nvm(struct nvme_passthru_cmd *cmd, __u32 nsid, __u8 lbaf,
		enum nvme_cmd_format_mset mset, enum nvme_cmd_format_pi pi,
		enum nvme_cmd_format_pil pil, enum nvme_cmd_format_ses ses)
{
	memset(cmd, 0, sizeof(*cmd));

	cmd->opcode = nvme_admin_format_nvm;
	cmd->nsid = nsid;
	cmd->cdw10 = NVME_FIELD_ENCODE(lbaf,
			NVME_FORMAT_CDW10_LBAFL_SHIFT,
			NVME_FORMAT_CDW10_LBAFL_MASK) |
		      NVME_FIELD_ENCODE(mset,
			NVME_FORMAT_CDW10_MSET_SHIFT,
			NVME_FORMAT_CDW10_MSET_MASK) |
		      NVME_FIELD_ENCODE(pi,
			NVME_FORMAT_CDW10_PI_SHIFT,
			NVME_FORMAT_CDW10_PI_MASK) |
		      NVME_FIELD_ENCODE(pil,
			NVME_FORMAT_CDW10_PIL_SHIFT,
			NVME_FORMAT_CDW10_PIL_MASK) |
		      NVME_FIELD_ENCODE(ses,
			NVME_FORMAT_CDW10_SES_SHIFT,
			NVME_FORMAT_CDW10_SES_MASK) |
		      NVME_FIELD_ENCODE((lbaf >> 4),
			NVME_FORMAT_CDW10_LBAFU_SHIFT,
			NVME_FORMAT_CDW10_LBAFU_MASK);
}

/**
 * nvme_init_ns_mgmt() - Initialize passthru command for Namespace Management
 * @cmd:	Passthru command to use
 * @nsid:	Namespace identifier
 * @sel:	Type of management operation to perform
 * @csi:	Command Set Identifier
 * @data:	Host Software Specified Fields buffer
 *
 * Initializes the passthru command buffer for the Namespace Management command.
 */
static inline void
nvme_init_ns_mgmt(struct nvme_passthru_cmd *cmd, __u32 nsid,
		enum nvme_ns_mgmt_sel sel, __u8 csi,
		struct nvme_ns_mgmt_host_sw_specified *data)
{
	memset(cmd, 0, sizeof(*cmd));

	cmd->opcode = nvme_admin_ns_mgmt;
	cmd->nsid = nsid;
	cmd->data_len = data ? sizeof(*data) : 0;
	cmd->addr = (__u64)(uintptr_t)data;
	cmd->cdw10 = NVME_FIELD_ENCODE(sel,
			NVME_NAMESPACE_MGMT_CDW10_SEL_SHIFT,
			NVME_NAMESPACE_MGMT_CDW10_SEL_MASK);
	cmd->cdw11 = NVME_FIELD_ENCODE(csi,
			NVME_NAMESPACE_MGMT_CDW11_CSI_SHIFT,
			NVME_NAMESPACE_MGMT_CDW11_CSI_MASK);
}

/**
 * nvme_init_ns_mgmt_create() - Initialize passthru command to create a
 * non attached namespace
 * @cmd:	Passthru command to use
 * @csi:	Command Set Identifier
 * @data:	Host Software Specified Fields buffer that defines NS
 *		creation parameters
 *
 * Initializes the passthru command buffer for the Namespace Management - Create
 * command. The command uses NVME_NSID_NONE as the target NSID.
 */
static inline void
nvme_init_ns_mgmt_create(struct nvme_passthru_cmd *cmd, __u8 csi,
		struct nvme_ns_mgmt_host_sw_specified *data)
{
	nvme_init_ns_mgmt(cmd, NVME_NSID_NONE, NVME_NS_MGMT_SEL_CREATE,
		csi, data);
}

/**
 * nvme_init_ns_mgmt_delete() - Initialize passthru command to delete a
 * non attached namespace
 * @cmd:	Passthru command to use
 * @nsid:	Namespace identifier to delete
 *
 * Initializes the passthru command buffer for the Namespace Management - Delete
 * command (NVME_NS_MGMT_SEL_DELETE). The command uses the provided @nsid as
 * the target NSID.
 */
static inline void
nvme_init_ns_mgmt_delete(struct nvme_passthru_cmd *cmd, __u32 nsid)
{
	nvme_init_ns_mgmt(cmd, nsid, NVME_NS_MGMT_SEL_DELETE,
		NVME_CSI_NVM, NULL);
}

/**
 * nvme_init_ns_attach() - Initialize passthru command for
 * Namespace Attach/Detach
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID to execute attach selection
 * @sel:	Attachment selection, see &enum nvme_ns_attach_sel
 * @ctrlist:	Controller list buffer to modify attachment state of nsid
 *
 * Initializes the passthru command buffer for the Namespace Attach/Detach command.
 */
static inline void
nvme_init_ns_attach(struct nvme_passthru_cmd *cmd, __u32 nsid,
		enum nvme_ns_attach_sel sel, struct nvme_ctrl_list *ctrlist)
{
	memset(cmd, 0, sizeof(*cmd));

	cmd->opcode = nvme_admin_ns_attach;
	cmd->nsid = nsid;
	cmd->data_len = sizeof(*ctrlist);
	cmd->addr = (__u64)(uintptr_t)ctrlist;
	cmd->cdw10 = NVME_FIELD_ENCODE(sel,
			NVME_NAMESPACE_ATTACH_CDW10_SEL_SHIFT,
			NVME_NAMESPACE_ATTACH_CDW10_SEL_MASK);
}

/**
 * nvme_init_ns_attach_ctrls() - Initialize passthru command to attach
 * namespace to controllers
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID to attach
 * @ctrlist:	Controller list buffer to modify attachment state of nsid
 *
 * Initializes the passthru command buffer for the Namespace Attach command
 * (NVME_NS_ATTACH_SEL_CTRL_ATTACH).
 */
static inline void
nvme_init_ns_attach_ctrls(struct nvme_passthru_cmd *cmd, __u32 nsid,
		struct nvme_ctrl_list *ctrlist)
{
	nvme_init_ns_attach(cmd, nsid, NVME_NS_ATTACH_SEL_CTRL_ATTACH,
		ctrlist);
}

/**
 * nvme_init_ns_detach_ctrls() - Initialize passthru command to detach
 * namespace from controllers
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID to detach
 * @ctrlist:	Controller list buffer to modify attachment state of nsid
 *
 * Initializes the passthru command buffer for the Namespace Detach command
 * (NVME_NS_ATTACH_SEL_CTRL_DEATTACH).
 */
static inline void
nvme_init_ns_detach_ctrls(struct nvme_passthru_cmd *cmd, __u32 nsid,
		struct nvme_ctrl_list *ctrlist)
{
	nvme_init_ns_attach(cmd, nsid, NVME_NS_ATTACH_SEL_CTRL_DEATTACH,
		ctrlist);
}

/**
 * nvme_init_fw_download() - Initialize passthru command to download part or
 * all of a firmware image to the controller
 * @cmd:	Passthru command to use
 * @data:	Userspace address of the firmware data buffer
 * @len:	Length of data in this command in bytes
 * @offset:	Offset in the firmware data
 *
 * Initializes the passthru command buffer for the Firmware Image
 * Download command.
 *
 * Note: Caller must ensure data_len and offset are DWord-aligned (0x4).
 *
 * Returns: 0 on success, or error code if arguments are invalid.
 */
static inline int
nvme_init_fw_download(struct nvme_passthru_cmd *cmd, void *data,
		__u32 len, __u32 offset)
{
	if (len & 0x3 || !len)
		return -EINVAL;

	if (offset & 0x3)
		return -EINVAL;

	memset(cmd, 0, sizeof(*cmd));

	cmd->opcode = nvme_admin_fw_download;
	cmd->data_len = len;
	cmd->addr = (__u64)(uintptr_t)data;
	cmd->cdw10 = (len >> 2) - 1;;
	cmd->cdw11 = offset >> 2;

	return 0;
}

/**
 * nvme_init_fw_commit() - Initialize passthru command to commit firmware
 * using the specified action
 * @cmd:	Passthru command to use
 * @fs:		Firmware slot to commit the downloaded image
 * @ca:		Action to use for the firmware image,
 *		see &enum nvme_fw_commit_ca
 * @bpid:	Set to true to select the boot partition id
 *
 * Initializes the passthru command buffer for the Firmware Commit command.
 */
static inline void
nvme_init_fw_commit(struct nvme_passthru_cmd *cmd, __u8 fs,
		    enum nvme_fw_commit_ca ca, bool bpid)
{
	memset(cmd, 0, sizeof(*cmd));

	cmd->opcode = nvme_admin_fw_commit;
	cmd->cdw10 = NVME_FIELD_ENCODE(fs,
			NVME_FW_COMMIT_CDW10_FS_SHIFT,
			NVME_FW_COMMIT_CDW10_FS_MASK) |
		      NVME_FIELD_ENCODE(ca,
			NVME_FW_COMMIT_CDW10_CA_SHIFT,
			NVME_FW_COMMIT_CDW10_CA_MASK) |
		      NVME_FIELD_ENCODE(bpid,
			NVME_FW_COMMIT_CDW10_BPID_SHIFT,
			NVME_FW_COMMIT_CDW10_BPID_MASK);
}

/**
 * nvme_init_security_send() - Initialize passthru command for Security Send
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID to issue security command on
 * @nssf:	NVMe Security Specific field
 * @spsp:	Security Protocol Specific field
 * @secp:	Security Protocol
 * @tl:		Protocol specific transfer length
 * @data:	Security data payload buffer to send
 * @len:	Data length of the payload in bytes
 *
 * Initializes the passthru command buffer for the Security Send command.
 */
static inline void
nvme_init_security_send(struct nvme_passthru_cmd *cmd, __u32 nsid, __u8 nssf,
		__u16 spsp, __u8 secp, __u32 tl, void *data, __u32 len)
{
	memset(cmd, 0, sizeof(*cmd));

	cmd->opcode = nvme_admin_security_send;
	cmd->nsid = nsid;
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
			NVME_SECURITY_SPSP1_MASK) |
		      NVME_FIELD_ENCODE(nssf,
			NVME_SECURITY_NSSF_SHIFT,
			NVME_SECURITY_NSSF_MASK);
	cmd->cdw11 = tl;
}

/**
 * nvme_init_security_receive() - Initialize passthru command for
 * Security Receive
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID to issue security command on
 * @nssf:	NVMe Security Specific field
 * @spsp:	Security Protocol Specific field
 * @secp:	Security Protocol
 * @al:		Protocol specific allocation length
 * @data:	Security data payload buffer to receive data into
 * @len:	Data length of the payload in bytes (must match @al)
 *
 * Initializes the passthru command buffer for the Security Receive command.
 */
static inline void
nvme_init_security_receive(struct nvme_passthru_cmd *cmd, __u32 nsid, __u8 nssf,
		__u16 spsp, __u8 secp, __u32 al, void *data, __u32 len)
{
	memset(cmd, 0, sizeof(*cmd));

	cmd->opcode = nvme_admin_security_recv;
	cmd->nsid = nsid;
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
			NVME_SECURITY_SPSP1_MASK) |
		     NVME_FIELD_ENCODE(nssf,
			NVME_SECURITY_NSSF_SHIFT,
			NVME_SECURITY_NSSF_MASK);
	cmd->cdw11 = al;
}

/**
 * nvme_init_get_lba_status() - Initialize passthru command to retrieve
 * information on possibly unrecoverable LBAs
 * @cmd:	Passthru command to use
 * @nsid:	Namespace ID to retrieve LBA status
 * @slba:	Starting logical block address to check statuses
 * @mndw:	Maximum number of dwords to return
 * @atype:	Action type mechanism to determine LBA status descriptors to
 *		return, see &enum nvme_lba_status_atype
 * @rl:		Range length from slba to perform the action
 * @lbas:	Data payload buffer to return status descriptors
 *
 * Initializes the passthru command buffer for the Get LBA Status command.
 */
static inline void
nvme_init_get_lba_status(struct nvme_passthru_cmd *cmd, __u32 nsid, __u64 slba,
		__u32 mndw, enum nvme_lba_status_atype atype, __u16 rl,
		struct nvme_lba_status *lbas)
{
	memset(cmd, 0, sizeof(*cmd));

	cmd->opcode = nvme_admin_get_lba_status;
	cmd->nsid = nsid;
	cmd->data_len = (mndw + 1) << 2;
	cmd->addr = (__u64)(uintptr_t)lbas;
	cmd->cdw10 = slba & 0xffffffff;
	cmd->cdw11 = slba >> 32;
	cmd->cdw12 = mndw;
	cmd->cdw13 = NVME_FIELD_ENCODE(rl,
			NVME_GET_LBA_STATUS_CDW13_RL_SHIFT,
			NVME_GET_LBA_STATUS_CDW13_RL_MASK) |
		     NVME_FIELD_ENCODE(atype,
			NVME_GET_LBA_STATUS_CDW13_ATYPE_SHIFT,
			NVME_GET_LBA_STATUS_CDW13_ATYPE_MASK);
}

/**
 * nvme_directive_send() - Send directive command
 * @hdl:	Transport handle
 * @args:	&struct nvme_directive_send_args argument structure
 *
 * Directives is a mechanism to enable host and NVM subsystem or controller
 * information exchange. The Directive Send command transfers data related to a
 * specific Directive Type from the host to the controller.
 *
 * See the NVMe specification for more information.
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int nvme_directive_send(struct nvme_transport_handle *hdl, struct nvme_directive_send_args *args);

/**
 * nvme_directive_send_id_endir() - Directive Send Enable Directive
 * @hdl:	Transport handle
 * @nsid:	Namespace Identifier
 * @endir:	Enable Directive
 * @dtype:	Directive Type
 * @id:		Pointer to structure nvme_id_directives
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int nvme_directive_send_id_endir(struct nvme_transport_handle *hdl, __u32 nsid, bool endir,
				 enum nvme_directive_dtype dtype,
				 struct nvme_id_directives *id);

/**
 * nvme_directive_send_stream_release_identifier() - Directive Send Stream release
 * @hdl:	Transport handle
 * @nsid:	Namespace ID
 * @stream_id:	Stream identifier
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
static inline int nvme_directive_send_stream_release_identifier(struct nvme_transport_handle *hdl,
			__u32 nsid, __u16 stream_id)
{
	struct nvme_directive_send_args args = {
		.result = NULL,
		.data = NULL,
		.args_size = sizeof(args),
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.nsid = nsid,
		.doper = NVME_DIRECTIVE_SEND_STREAMS_DOPER_RELEASE_IDENTIFIER,
		.dtype = NVME_DIRECTIVE_DTYPE_STREAMS,
		.cdw12 = 0,
		.data_len = 0,
		.dspec = stream_id,
	};

	return nvme_directive_send(hdl, &args);
}

/**
 * nvme_directive_send_stream_release_resource() - Directive Send Stream release resources
 * @hdl:	Transport handle
 * @nsid:	Namespace ID
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
static inline int nvme_directive_send_stream_release_resource(struct nvme_transport_handle *hdl, __u32 nsid)
{
	struct nvme_directive_send_args args = {
		.result = NULL,
		.data = NULL,
		.args_size = sizeof(args),
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.nsid = nsid,
		.doper = NVME_DIRECTIVE_SEND_STREAMS_DOPER_RELEASE_RESOURCE,
		.dtype = NVME_DIRECTIVE_DTYPE_STREAMS,
		.cdw12 = 0,
		.data_len = 0,
		.dspec = 0,
	};

	return nvme_directive_send(hdl, &args);
}

/**
 * nvme_directive_recv() - Receive directive specific data
 * @hdl:	Transport handle
 * @args:	&struct nvme_directive_recv_args argument structure
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int nvme_directive_recv(struct nvme_transport_handle *hdl, struct nvme_directive_recv_args *args);

/**
 * nvme_directive_recv_identify_parameters() - Directive receive identifier parameters
 * @hdl:	Transport handle
 * @nsid:	Namespace ID
 * @id:		Identify parameters buffer
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
static inline int nvme_directive_recv_identify_parameters(struct nvme_transport_handle *hdl, __u32 nsid,
			struct nvme_id_directives *id)
{
	struct nvme_directive_recv_args args = {
		.result = NULL,
		.data = id,
		.args_size = sizeof(args),
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.nsid = nsid,
		.doper = NVME_DIRECTIVE_RECEIVE_IDENTIFY_DOPER_PARAM,
		.dtype = NVME_DIRECTIVE_DTYPE_IDENTIFY,
		.cdw12 = 0,
		.data_len = sizeof(*id),
		.dspec = 0,
	};

	return nvme_directive_recv(hdl, &args);
}

/**
 * nvme_directive_recv_stream_parameters() - Directive receive stream parameters
 * @hdl:	Transport handle
 * @nsid:	Namespace ID
 * @parms:	Streams directive parameters buffer
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
static inline int nvme_directive_recv_stream_parameters(struct nvme_transport_handle *hdl, __u32 nsid,
			struct nvme_streams_directive_params *parms)
{
	struct nvme_directive_recv_args args = {
		.result = NULL,
		.data = parms,
		.args_size = sizeof(args),
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.nsid = nsid,
		.doper = NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_PARAM,
		.dtype = NVME_DIRECTIVE_DTYPE_STREAMS,
		.cdw12 = 0,
		.data_len = sizeof(*parms),
		.dspec = 0,
	};

	return nvme_directive_recv(hdl, &args);
}

/**
 * nvme_directive_recv_stream_status() - Directive receive stream status
 * @hdl:	Transport handle
 * @nsid:	Namespace ID
 * @nr_entries: Number of streams to receive
 * @id:		Stream status buffer
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
static inline int nvme_directive_recv_stream_status(struct nvme_transport_handle *hdl, __u32 nsid,
			unsigned int nr_entries,
			struct nvme_streams_directive_status *id)
{
	if (nr_entries > NVME_STREAM_ID_MAX) {
		errno = EINVAL;
		return -1;
	}

	struct nvme_directive_recv_args args = {
		.result = NULL,
		.data = id,
		.args_size = sizeof(args),
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.nsid = nsid,
		.doper = NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_STATUS,
		.dtype = NVME_DIRECTIVE_DTYPE_STREAMS,
		.cdw12 = 0,
		.data_len = (__u32)(sizeof(*id) + nr_entries * sizeof(__le16)),
		.dspec = 0,
	};

	return nvme_directive_recv(hdl, &args);
}

/**
 * nvme_directive_recv_stream_allocate() - Directive receive stream allocate
 * @hdl:	Transport handle
 * @nsid:	Namespace ID
 * @nsr:	Namespace Streams Requested
 * @result:	If successful, the CQE dword0 value
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
static inline int nvme_directive_recv_stream_allocate(struct nvme_transport_handle *hdl, __u32 nsid,
			__u16 nsr, __u32 *result)
{
	struct nvme_directive_recv_args args = {
		.result = result,
		.data = NULL,
		.args_size = sizeof(args),
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.nsid = nsid,
		.doper = NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_RESOURCE,
		.dtype = NVME_DIRECTIVE_DTYPE_STREAMS,
		.cdw12 = nsr,
		.data_len = 0,
		.dspec = 0,
	};

	return nvme_directive_recv(hdl, &args);
}

/**
 * nvme_capacity_mgmt() - Capacity management command
 * @hdl:	Transport handle
 * @args:	&struct nvme_capacity_mgmt_args argument structure
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int nvme_capacity_mgmt(struct nvme_transport_handle *hdl, struct nvme_capacity_mgmt_args *args);

/**
 * nvme_lockdown() - Issue lockdown command
 * @hdl:	Transport handle
 * @args:	&struct nvme_lockdown_args argument structure
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int nvme_lockdown(struct nvme_transport_handle *hdl, struct nvme_lockdown_args *args);

/**
 * nvme_set_property() - Set controller property
 * @hdl:	Transport handle
 * @args:	&struct nvme_set_property_args argument structure
 *
 * This is an NVMe-over-Fabrics specific command, not applicable to PCIe. These
 * properties align to the PCI MMIO controller registers.
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int nvme_set_property(struct nvme_transport_handle *hdl, struct nvme_set_property_args *args);

/**
 * nvme_get_property() - Get a controller property
 * @hdl:	Transport handle
 * @args:	&struct nvme_get_propert_args argument structure
 *
 * This is an NVMe-over-Fabrics specific command, not applicable to PCIe. These
 * properties align to the PCI MMIO controller registers.
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int nvme_get_property(struct nvme_transport_handle *hdl, struct nvme_get_property_args *args);

/**
 * nvme_sanitize_nvm() - Start a sanitize operation
 * @hdl:	Transport handle
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
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int nvme_sanitize_nvm(struct nvme_transport_handle *hdl, struct nvme_sanitize_nvm_args *args);

/**
 * nvme_dev_self_test() - Start or abort a self test
 * @hdl:	Transport handle
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
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int nvme_dev_self_test(struct nvme_transport_handle *hdl, struct nvme_dev_self_test_args *args);

/**
 * nvme_virtual_mgmt() - Virtualization resource management
 * @hdl:	Transport handle
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
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int nvme_virtual_mgmt(struct nvme_transport_handle *hdl, struct nvme_virtual_mgmt_args *args);

/**
 * nvme_flush() - Send an nvme flush command
 * @hdl:	Transport handle
 * @nsid:	Namespace identifier
 *
 * The Flush command requests that the contents of volatile write cache be made
 * non-volatile.
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
static inline int nvme_flush(struct nvme_transport_handle *hdl, __u32 nsid)
{
	struct nvme_passthru_cmd cmd = {};

	cmd.opcode = nvme_cmd_flush;
	cmd.nsid = nsid;

	return nvme_submit_io_passthru(hdl, &cmd, NULL);
}

/**
 * nvme_io() - Submit an nvme user I/O command
 * @hdl:	Transport handle
 * @args:	&struct nvme_io_args argument structure
 * @opcode:	Opcode to execute
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int nvme_io(struct nvme_transport_handle *hdl, struct nvme_io_args *args, __u8 opcode);

/**
 * nvme_read() - Submit an nvme user read command
 * @hdl:	Transport handle
 * @args:	&struct nvme_io_args argument structure
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
static inline int nvme_read(struct nvme_transport_handle *hdl, struct nvme_io_args *args)
{
	return nvme_io(hdl, args, nvme_cmd_read);
}

/**
 * nvme_write() - Submit an nvme user write command
 * @hdl:	Transport handle
 * @args:	&struct nvme_io_args argument structure
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
static inline int nvme_write(struct nvme_transport_handle *hdl, struct nvme_io_args *args)
{
	return nvme_io(hdl, args, nvme_cmd_write);
}

/**
 * nvme_compare() - Submit an nvme user compare command
 * @hdl:	Transport handle
 * @args:	&struct nvme_io_args argument structure
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
static inline int nvme_compare(struct nvme_transport_handle *hdl, struct nvme_io_args *args)
{
	return nvme_io(hdl, args, nvme_cmd_compare);
}

/**
 * nvme_write_zeros() - Submit an nvme write zeroes command
 * @hdl:	Transport handle
 * @args:	&struct nvme_io_args argument structure
 *
 * The Write Zeroes command sets a range of logical blocks to zero.  After
 * successful completion of this command, the value returned by subsequent
 * reads of logical blocks in this range shall be all bytes cleared to 0h until
 * a write occurs to this LBA range.
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
static inline int nvme_write_zeros(struct nvme_transport_handle *hdl, struct nvme_io_args *args)
{
	return nvme_io(hdl, args, nvme_cmd_write_zeroes);
}

/**
 * nvme_write_uncorrectable() - Submit an nvme write uncorrectable command
 * @hdl:	Transport handle
 * @args:	&struct nvme_io_args argument structure
 *
 * The Write Uncorrectable command marks a range of logical blocks as invalid.
 * When the specified logical block(s) are read after this operation, a failure
 * is returned with Unrecovered Read Error status. To clear the invalid logical
 * block status, a write operation on those logical blocks is required.
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
static inline int nvme_write_uncorrectable(struct nvme_transport_handle *hdl, struct nvme_io_args *args)
{
	return nvme_io(hdl, args, nvme_cmd_write_uncor);
}

/**
 * nvme_verify() - Send an nvme verify command
 * @hdl:	Transport handle
 * @args:	&struct nvme_io_args argument structure
 *
 * The Verify command verifies integrity of stored information by reading data
 * and metadata, if applicable, for the LBAs indicated without transferring any
 * data or metadata to the host.
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
static inline int nvme_verify(struct nvme_transport_handle *hdl, struct nvme_io_args *args)
{
	return nvme_io(hdl, args, nvme_cmd_verify);
}

/**
 * nvme_init_dsm() - Initialize passthru command for
 * NVMEe I/O Data Set Management
 * @cmd:	Passthru command to use
 * @nsid:	Namespace identifier
 * @nr:		Number of block ranges in the data set management attributes
 * @idr:	DSM Deallocate attribute
 * @idw:	DSM Integral Dataset for Read attribute
 * @ad:		DSM Integral Dataset for Read attribute
 * @data:	User space destination address to transfer the data
 * @len:	Length of provided user buffer to hold the log data in bytes
 */
static inline void
nvme_init_dsm(struct nvme_passthru_cmd *cmd,
		__u32 nsid, __u16 nr, __u8 idr, __u8 idw, __u8 ad, void *data,
		__u32 len)
{
	memset(cmd, 0, sizeof(*cmd));

	cmd->opcode	= nvme_cmd_dsm;
	cmd->nsid	= nsid;
	cmd->data_len	= len;
	cmd->addr	= (__u64)(uintptr_t)data;
	cmd->cdw10 = NVME_FIELD_ENCODE(nr,
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
 * nvme_copy() - Copy command
 * @hdl:	Transport handle
 * @args:	&struct nvme_copy_args argument structure
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int nvme_copy(struct nvme_transport_handle *hdl, struct nvme_copy_args *args);

/**
 * nvme_resv_acquire() - Send an nvme reservation acquire
 * @hdl:	Transport handle
 * @args:	&struct nvme_resv_acquire argument structure
 *
 * The Reservation Acquire command acquires a reservation on a namespace,
 * preempt a reservation held on a namespace, and abort a reservation held on a
 * namespace.
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int nvme_resv_acquire(struct nvme_transport_handle *hdl, struct nvme_resv_acquire_args *args);

/**
 * nvme_resv_register() - Send an nvme reservation register
 * @hdl:	Transport handle
 * @args:	&struct nvme_resv_register_args argument structure
 *
 * The Reservation Register command registers, unregisters, or replaces a
 * reservation key.
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int nvme_resv_register(struct nvme_transport_handle *hdl, struct nvme_resv_register_args *args);

/**
 * nvme_resv_release() - Send an nvme reservation release
 * @hdl:	Transport handle
 * @args:	&struct nvme_resv_release_args argument structure
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int nvme_resv_release(struct nvme_transport_handle *hdl, struct nvme_resv_release_args *args);

/**
 * nvme_resv_report() - Send an nvme reservation report
 * @hdl:	Transport handle
 * @args:	struct nvme_resv_report_args argument structure
 *
 * Returns a Reservation Status data structure to memory that describes the
 * registration and reservation status of a namespace. See the definition for
 * the returned structure, &struct nvme_reservation_status, for more details.
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int nvme_resv_report(struct nvme_transport_handle *hdl, struct nvme_resv_report_args *args);

/**
 * nvme_io_mgmt_recv() - I/O Management Receive command
 * @hdl:	Transport handle
 * @args:	&struct nvme_io_mgmt_recv_args argument structure
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int nvme_io_mgmt_recv(struct nvme_transport_handle *hdl, struct nvme_io_mgmt_recv_args *args);

/**
 * nvme_fdp_reclaim_unit_handle_status() - Get reclaim unit handle status
 * @hdl:	Transport handle
 * @nsid:	Namespace identifier
 * @data_len:	Length of response buffer
 * @data:	Response buffer
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
static inline int nvme_fdp_reclaim_unit_handle_status(struct nvme_transport_handle *hdl, __u32 nsid,
			__u32 data_len, void *data)
{
	struct nvme_io_mgmt_recv_args args = {
		.data = data,
		.args_size = sizeof(args),
		.nsid = nsid,
		.data_len = data_len,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.mos = 0,
		.mo = NVME_IO_MGMT_RECV_RUH_STATUS,
	};

	return nvme_io_mgmt_recv(hdl, &args);
}

/**
 * nvme_io_mgmt_send() - I/O Management Send command
 * @hdl:	Transport handle
 * @args:	&struct nvme_io_mgmt_send_args argument structure
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int nvme_io_mgmt_send(struct nvme_transport_handle *hdl, struct nvme_io_mgmt_send_args *args);

/**
 * nvme_fdp_reclaim_unit_handle_update() - Update a list of reclaim unit handles
 * @hdl:	Transport handle
 * @nsid:	Namespace identifier
 * @npids:	Number of placement identifiers
 * @pids:	List of placement identifiers
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
static inline int nvme_fdp_reclaim_unit_handle_update(struct nvme_transport_handle *hdl, __u32 nsid,
			unsigned int npids, __u16 *pids)
{
	struct nvme_io_mgmt_send_args args = {
		.data = (void *)pids,
		.args_size = sizeof(args),
		.nsid = nsid,
		.data_len = (__u32)(npids * sizeof(__u16)),
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.mos = (__u16)(npids - 1),
		.mo = NVME_IO_MGMT_SEND_RUH_UPDATE,
	};

	return nvme_io_mgmt_send(hdl, &args);
}

/**
 * nvme_zns_mgmt_send() - ZNS management send command
 * @hdl:	Transport handle
 * @args:	&struct nvme_zns_mgmt_send_args argument structure
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int nvme_zns_mgmt_send(struct nvme_transport_handle *hdl, struct nvme_zns_mgmt_send_args *args);


/**
 * nvme_zns_mgmt_recv() - ZNS management receive command
 * @hdl:	Transport handle
 * @args:	&struct nvme_zns_mgmt_recv_args argument structure
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int nvme_zns_mgmt_recv(struct nvme_transport_handle *hdl, struct nvme_zns_mgmt_recv_args *args);

/**
 * nvme_zns_report_zones() - Return the list of zones
 * @hdl:	Transport handle
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
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
static inline int nvme_zns_report_zones(struct nvme_transport_handle *hdl, __u32 nsid, __u64 slba,
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
		.timeout = timeout,
		.nsid = nsid,
		.zra = extended ? NVME_ZNS_ZRA_EXTENDED_REPORT_ZONES :
		NVME_ZNS_ZRA_REPORT_ZONES,
		.data_len = data_len,
		.zrasf = (__u16)opts,
		.zras_feat = partial,
	};

	return nvme_zns_mgmt_recv(hdl, &args);
}

/**
 * nvme_zns_append() - Append data to a zone
 * @hdl:	Transport handle
 * @args:	&struct nvme_zns_append_args argument structure
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int nvme_zns_append(struct nvme_transport_handle *hdl, struct nvme_zns_append_args *args);

/**
 * nvme_dim_send - Send a Discovery Information Management (DIM) command
 * @hdl:	Transport handle
 * @args:	&struct nvme_dim_args argument structure
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int nvme_dim_send(struct nvme_transport_handle *hdl, struct nvme_dim_args *args);

/**
 * nvme_lm_cdq() - Controller Data Queue - Controller Data Queue command
 * @hdl:	Transport handle
 * @args:	&struct nvme_lm_cdq_args argument structure
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.)
 */
int nvme_lm_cdq(struct nvme_transport_handle *hdl, struct nvme_lm_cdq_args *args);

/**
 * nvme_lm_track_send() - Track Send command
 * @hdl:	Transport handle
 * @args:	&struct nvme_lm_track_send_args argument structure
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int nvme_lm_track_send(struct nvme_transport_handle *hdl, struct nvme_lm_track_send_args *args);

/**
 * nvme_lm_migration_send() - Migration Send command
 * @hdl:	Transport handle
 * @args:	&struct nvme_lm_migration_send_args argument structure
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int nvme_lm_migration_send(struct nvme_transport_handle *hdl, struct nvme_lm_migration_send_args *args);

/**
 * nvme_lm_migration_recv - Migration Receive command
 * @hdl:	Transport handle
 * @args:	&struct nvme_lm_migration_rev_args argument structure
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int nvme_lm_migration_recv(struct nvme_transport_handle *hdl, struct nvme_lm_migration_recv_args *args);

/**
 * nvme_lm_set_features_ctrl_data_queue - Set Controller Datea Queue feature
 * @hdl:	Transport handle
 * @cdqid:	Controller Data Queue ID (CDQID)
 * @hp:		Head Pointer
 * @tpt:	Tail Pointer Trigger
 * @etpt:	Enable Tail Pointer Trigger
 * @result:	The command completions result from CQE dword0
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int nvme_lm_set_features_ctrl_data_queue(struct nvme_transport_handle *hdl, __u16 cdqid, __u32 hp, __u32 tpt, bool etpt,
					 __u32 *result);

/**
 * nvme_lm_get_features_ctrl_data_queue - Get Controller Data Queue feature
 * @hdl:	Transport handle
 * @cdqid:	Controller Data Queue ID (CDQID)
 * @data:	Get Controller Data Queue feature data
 * @result:	The command completions result from CQE dword0
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int nvme_lm_get_features_ctrl_data_queue(struct nvme_transport_handle *hdl, __u16 cdqid,
					 struct nvme_lm_ctrl_data_queue_fid_data *data,
					 __u32 *result);

/**
 * nvme_identify() - Submit a generic Identify command
 * @hdl:	Transport handle for the controller.
 * @nsid:	Namespace ID (if applicable to the requested CNS).
 * @csi:	Command Set Identifier.
 * @cns:	Identify Controller or Namespace Structure (CNS) value,
 * 		specifying the type of data to be returned.
 * @data:	Pointer to the buffer where the identification data will
 * 		be stored.
 * @len:	Length of the data buffer in bytes.
 *
 * The generic wrapper for submitting an Identify command, allowing the host
 * to specify any combination of Identify parameters.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_identify(struct nvme_transport_handle *hdl, __u32 nsid, enum nvme_csi csi,
		enum nvme_identify_cns cns, void *data, __u32 len)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_identify(&cmd, nsid, csi, cns, data, len);

	return nvme_submit_admin_passthru(hdl, &cmd, NULL);
}
/**
 * nvme_identify_ctrl() - Submit an Identify Controller command
 * @hdl:	Transport handle for the controller.
 * @id:		Pointer to the buffer (&struct nvme_id_ctrl) where the
 *		controller identification data will be stored upon
 *		successful completion.
 *
 * Submits the Identify Controller command to retrieve the controller's
 * capabilities and configuration data.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_identify_ctrl(struct nvme_transport_handle *hdl,
		struct nvme_id_ctrl *id)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_identify_ctrl(&cmd, id);

	return nvme_submit_admin_passthru(hdl, &cmd, NULL);
}

/**
 * nvme_identify_active_ns_list() - Submit an Identify Active Namespace
 * List command
 * @hdl:	Transport handle for the controller.
 * @nsid:	The Namespace ID to query
 * @ns_list:	Pointer to the buffer (&struct nvme_ns_list) where the
 *		active namespace list will be stored.
 *
 * Submits the Identify command to retrieve a list of active Namespace IDs.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_identify_active_ns_list(struct nvme_transport_handle *hdl,
		__u32 nsid, struct nvme_ns_list *ns_list)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_identify_active_ns_list(&cmd, nsid, ns_list);

	return nvme_submit_admin_passthru(hdl, &cmd, NULL);
}

/**
 * nvme_identify_ns() - Submit an Identify Namespace command
 * @hdl:	Transport handle for the controller.
 * @nsid:	The Namespace ID to identify.
 * @ns:		Pointer to the buffer (&struct nvme_id_ns) where the namespace
 *		identification data will be stored.
 *
 * Submits the Identify command to retrieve the Namespace Identification
 * data structure for a specified namespace.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */

static inline int
nvme_identify_ns(struct nvme_transport_handle *hdl,
		__u32 nsid, struct nvme_id_ns *ns)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_identify_ns(&cmd, nsid, ns);

	return nvme_submit_admin_passthru(hdl, &cmd, NULL);
}

/**
 * nvme_identify_csi_ns() - Submit a CSI-specific Identify Namespace command
 * @hdl:	Transport handle for the controller.
 * @nsid:	The Namespace ID to identify.
 * @csi:	The Command Set Identifier
 * @uidx:	The UUID Index for the command.
 * @id_ns:	Pointer to the buffer (@struct nvme_nvm_id_ns) where the
 *		CSI-specific namespace identification data will be stored.
 *
 * Submits the Identify command to retrieve Namespace Identification data
 * specific to a Command Set Identifier (CSI).
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_identify_csi_ns(struct nvme_transport_handle *hdl, __u32 nsid,
		enum nvme_csi csi, __u8 uidx, struct nvme_nvm_id_ns *id_ns)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_identify_csi_ns(&cmd, nsid, csi, uidx, id_ns);

	return nvme_submit_admin_passthru(hdl, &cmd, NULL);
}

/**
 * nvme_identify_uuid_list() - Submit an Identify UUID List command
 * @hdl:	Transport handle for the controller.
 * @uuid_list:	Pointer to the buffer (&struct nvme_id_uuid_list) where the
 *		UUID list will be stored.
 *
 * Submits the Identify command to retrieve a list of UUIDs associated
 * with the controller.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_identify_uuid_list(struct nvme_transport_handle *hdl,
		struct nvme_id_uuid_list *uuid_list)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_identify_uuid_list(&cmd, uuid_list);

	return nvme_submit_admin_passthru(hdl, &cmd, NULL);
}

/**
 * nvme_identify_csi_ns_user_data_format() - Submit an Identify CSI Namespace
 * User Data Format command
 * @hdl:	Transport handle for the controller.
 * @csi:	Command Set Identifier.
 * @fidx:	Format Index, specifying which format entry to return.
 * @uidx:	The UUID Index for the command.
 * @data:	Pointer to the buffer where the format data will be stored.
 *
 * Submits the Identify command to retrieve a CSI-specific Namespace User
 * Data Format data structure.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_identify_csi_ns_user_data_format(struct nvme_transport_handle *hdl,
		enum nvme_csi csi, __u16 fidx, __u8 uidx, void *data)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_identify_csi_ns_user_data_format(&cmd, csi, fidx, uidx, data);

	return nvme_submit_admin_passthru(hdl, &cmd, NULL);
}

/**
 * nvme_identify_ns_granularity() - Submit an Identify Namespace Granularity
 * List command
 * @hdl:	Transport handle for the controller.
 * @gr_list:	Pointer to the buffer (&struct nvme_id_ns_granularity_list)
 * 		where the granularity list will be stored.
 *
 * Submits the Identify command to retrieve the Namespace Granularity List.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_identify_ns_granularity(struct nvme_transport_handle *hdl,
		struct nvme_id_ns_granularity_list *gr_list)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_identify_ns_granularity(&cmd, gr_list);

	return nvme_submit_admin_passthru(hdl, &cmd, NULL);
}

/**
 * nvme_identify_ns_descs_list() - Submit an Identify Namespace ID Descriptor
 * List command
 * @hdl:	Transport handle for the controller.
 * @nsid:	The Namespace ID to query.
 * @descs:	Pointer to the buffer (&struct nvme_ns_id_desc) where the
 *		descriptor list will be stored.
 *
 * Submits the Identify command to retrieve the Namespace ID Descriptor List
 * for a specified namespace.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_identify_ns_descs_list(struct nvme_transport_handle *hdl,
		__u32 nsid, struct nvme_ns_id_desc *descs)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_identify_ns_descs_list(&cmd, nsid, descs);

	return nvme_submit_admin_passthru(hdl, &cmd, NULL);
}

/**
 * nvme_zns_identify_ns() - Submit a ZNS-specific Identify Namespace command
 * @hdl:	Transport handle for the controller.
 * @nsid:	The Namespace ID to identify.
 * @data:	Pointer to the buffer (&struct nvme_zns_id_ns) where the ZNS
 *		namespace identification data will be stored.
 *
 * Submits the Identify command to retrieve the Zoned Namespace (ZNS)
 * specific identification data structure for a specified namespace.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_zns_identify_ns(struct nvme_transport_handle *hdl,
		__u32 nsid, struct nvme_zns_id_ns *data)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_zns_identify_ns(&cmd, nsid, data);

	return nvme_submit_admin_passthru(hdl, &cmd, NULL);
}

/**
 * nvme_get_log_simple() - Retrieve a log page using default parameters
 * @hdl:	Transport handle for the controller.
 * @lid:	Log Identifier, specifying the log page to retrieve
 * 		(@enum nvme_cmd_get_log_lid).
 * @data:	Pointer to the buffer where the log page data will be stored.
 * @len:	Length of the data buffer in bytes.
 *
 * Submits the Get Log Page command using the common settings:
 * NVME\_NSID\_ALL, Retain Asynchronous Event (RAE) set to false,
 * and assuming the NVM Command Set.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_simple(struct nvme_transport_handle *hdl,
		enum nvme_cmd_get_log_lid lid, void *data, __u32 len)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log(&cmd, NVME_NSID_ALL, lid, NVME_CSI_NVM, data, len);

	return nvme_get_log(hdl, &cmd, false, NVME_LOG_PAGE_PDU_SIZE, NULL);
}

/**
 * nvme_get_log_supported_log_pages() - Retrieve the Supported Log Pages Log Page
 * @hdl:	Transport handle for the controller.
 * @log:	Pointer to the buffer (@struct nvme_supported_log_pages) where
 *		the log page data will be stored.
 *
 * Submits the Get Log Page command specifically for the Supported Log Pages
 * Log.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_supported_log_pages(struct nvme_transport_handle *hdl,
		struct nvme_supported_log_pages *log)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log(&cmd, NVME_NSID_ALL, NVME_LOG_LID_SUPPORTED_LOG_PAGES,
		NVME_CSI_NVM, log, sizeof(*log));

	return nvme_get_log(hdl, &cmd, false, sizeof(*log), NULL);
}


/**
 * nvme_get_log_error() - Retrieve the Error Information Log Page
 * @hdl:	Transport handle for the controller.
 * @nsid:	Namespace ID to request the log for (usually NVME_NSID_ALL).
 * @nr_entries:	The maximum number of error log entries to retrieve.
 * @err_log:	Pointer to the buffer (array of @struct nvme_error_log_page)
 *		where the log page data will be stored.
 *
 * This log page describes extended error information for a command that
 * completed with error, or may report an error that is not specific to a
 * particular command. The total size requested is determined by
 * @nr_entries * sizeof(@struct nvme_error_log_page).
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_error(struct nvme_transport_handle *hdl, __u32 nsid,
		unsigned int nr_entries, struct nvme_error_log_page *err_log)
{
	struct nvme_passthru_cmd cmd;
	size_t len = sizeof(*err_log) * nr_entries;

	nvme_init_get_log(&cmd, nsid, NVME_LOG_LID_ERROR,
		NVME_CSI_NVM, err_log, len);

	return nvme_get_log(hdl, &cmd, false, len, NULL);
}

/**
 * nvme_get_log_fw_slot() - Retrieve the Firmware Slot Information Log Page
 * @hdl:	Transport handle for the controller.
 * @nsid:	Namespace ID to request the log for (use NVME_NSID_ALL).
 * @fw_log:	Pointer to the buffer (@struct nvme_firmware_slot) where the log
 *		page data will be stored.
 *
 * This log page describes the firmware revision stored in each firmware slot
 * supported. The firmware revision is indicated as an ASCII string. The log
 * page also indicates the active slot number.
 *
 * This command is typically issued for the controller scope, thus using
 * NVME_NSID_ALL.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_fw_slot(struct nvme_transport_handle *hdl, __u32 nsid,
		struct nvme_firmware_slot *fw_log)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log(&cmd, nsid, NVME_LOG_LID_FW_SLOT,
		NVME_CSI_NVM, fw_log, sizeof(*fw_log));

	return nvme_get_log(hdl, &cmd, false, sizeof(*fw_log), NULL);
}

/**
 * nvme_get_log_changed_ns_list() - Retrieve the Namespace Change Log Page
 * @hdl:	Transport handle for the controller.
 * @nsid:	Namespace ID to request the log for (use NVME_NSID_ALL).
 * @ns_log:	Pointer to the buffer (@struct nvme_ns_list) where the log
 *		page data will be stored.
 *
 * This log page describes namespaces attached to this controller that have
 * changed since the last time the namespace was identified, been added, or
 * deleted.
 *
 * This command is typically issued for the controller scope, thus using
 * NVME_NSID_ALL. The Retain Asynchronous Event (RAE) is true to retain
 * asynchronous events associated with the log page
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_changed_ns_list(struct nvme_transport_handle *hdl, __u32 nsid,
		struct nvme_ns_list *ns_log)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log(&cmd, nsid, NVME_LOG_LID_CHANGED_NS,
		NVME_CSI_NVM, ns_log, sizeof(*ns_log));

	return nvme_get_log(hdl, &cmd, true, sizeof(*ns_log), NULL);
}

/**
 * nvme_get_log_cmd_effects() - Retrieve the Command Effects Log Page
 * @hdl:	Transport handle for the controller.
 * @csi:	Command Set Identifier for the requested log page.
 * @effects_log:Pointer to the buffer (@struct nvme_cmd_effects_log) where the
 *		log page data will be stored.
 *
 * This log page describes the commands that the controller supports and the
 * effects of those commands on the state of the NVM subsystem.
 *
 * It automatically sets the Log Identifier (LID) and Retain Asynchronous
 * Event (RAE) to false. This command is typically issued for the controller
 * scope, thus using NVME_NSID_ALL.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_cmd_effects(struct nvme_transport_handle *hdl,
		enum nvme_csi csi, struct nvme_cmd_effects_log *effects_log)
{
	struct nvme_passthru_cmd cmd;
	size_t len = sizeof(*effects_log);

	nvme_init_get_log_cmd_effects(&cmd, csi, effects_log);

	return nvme_get_log(hdl, &cmd, false, len, NULL);
}

/**
 * nvme_get_log_device_self_test() - Retrieve the Device Self-Test Log Page
 * @hdl:	Transport handle for the controller.
 * @log:	Pointer to the buffer (@struct nvme_self_test_log) where the log
 *		page data will be stored.
 *
 * This log page indicates the status of an in-progress self-test and the
 * percent complete of that operation, and the results of the previous 20
 * self-test operations.
 *
 * It automatically sets the Log Identifier (LID) and Retain Asynchronous
 * Event (RAE) to false. This command is typically issued for the controller
 * scope, thus using NVME_NSID_ALL.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_device_self_test(struct nvme_transport_handle *hdl,
		struct nvme_self_test_log *log)
{
	struct nvme_passthru_cmd cmd;
	size_t len = sizeof(*log);

	nvme_init_get_log(&cmd, NVME_NSID_ALL, NVME_LOG_LID_DEVICE_SELF_TEST,
		NVME_CSI_NVM, log, len);

	return nvme_get_log(hdl, &cmd, false, len, NULL);
}

/**
 * nvme_get_log_create_telemetry_host_mcda() - Create the Host Initiated
 * Telemetry Log
 * @hdl:	Transport handle for the controller.
 * @mcda:	Maximum Created Data Area. Specifies the maximum amount of data
 *		that may be returned by the controller.
 * @log:	Pointer to the buffer (@struct nvme_telemetry_log) where the log
 *		page data will be stored.
 *
 * Submits the Get Log Page command to initiate the creation of a Host Initiated
 * Telemetry Log. It sets the Log Identifier (LID) to Telemetry Host and
 * includes the Maximum Created Data Area (MCDA) in the Log Specific Parameter
 * (LSP) field along with the Create bit.
 *
 * It automatically sets Retain Asynchronous Event (RAE) to false.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_create_telemetry_host_mcda(struct nvme_transport_handle *hdl,
		enum nvme_telemetry_da mcda, struct nvme_telemetry_log *log)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_create_telemetry_host_mcda(&cmd, mcda, log);

	return nvme_get_log(hdl, &cmd, false, sizeof(*log), NULL);
}

/**
 * nvme_get_log_create_telemetry_host() - Create the Host Initiated Telemetry
 * Log (Controller Determined Size)
 * @hdl:	Transport handle for the controller.
 * @log:	Pointer to the buffer (@struct nvme_telemetry_log) where the log
 *		page data will be stored.
 *
 * Submits the Get Log Page command to initiate the creation of a Host Initiated
 * Telemetry Log. This is a convenience wrapper that automatically uses the
 * Controller Determined size for the Maximum Created Data Area (MCDA).
 *
 * It automatically sets Retain Asynchronous Event (RAE) to false.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_create_telemetry_host(struct nvme_transport_handle *hdl,
		struct nvme_telemetry_log *log)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_create_telemetry_host(&cmd, log);

	return nvme_get_log(hdl, &cmd, false, sizeof(*log), NULL);
}

/**
 * nvme_get_log_telemetry_host() - Retrieve the Host-Initiated
 * Telemetry Log Page (Retain)
 * @hdl:	Transport handle for the controller.
 * @lpo:	Offset (in bytes) into the telemetry data to start the retrieval.
 * @log:	Pointer to the buffer where the log page data will be stored.
 * @len:	Length of the buffer provided in @log.
 *
 * Submits the Get Log Page command to retrieve a previously captured
 * Host-Initiated Telemetry Log, starting at a specified offset (@lpo). The Log
 * Specific Parameter (LSP) field is set to indicate the capture should be
 * retained (not deleted after read).
 *
 * It automatically sets the Log Identifier (LID) and Retain Asynchronous Event
 * (RAE) to false.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_telemetry_host(struct nvme_transport_handle *hdl,
		__u64 lpo, void *log, __u32 len)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_telemetry_host(&cmd, lpo, log, len);

	return nvme_get_log(hdl, &cmd, false, len, NULL);
}

/**
 * nvme_get_log_telemetry_ctrl() - Retrieve the Controller-Initiated
 * Telemetry Log Page
 * @hdl:	Transport handle for the controller.
 * @rae:	Retain asynchronous events
 * @lpo:	Offset (in bytes) into the telemetry data to start the retrieval.
 * @log:	Pointer to the buffer where the log page data will be stored.
 * @len:	Length of the buffer provided in @log.
 *
 * Submits the Get Log Page command specifically for the Controller-Initiated
 * Telemetry Log, allowing retrieval of data starting at a specified offset
 * (@lpo).
 *
 * It automatically sets the Log Identifier (LID).
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_telemetry_ctrl(struct nvme_transport_handle *hdl, bool rae,
		__u64 lpo, void *log, __u32 len)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_telemetry_ctrl(&cmd, lpo, log, len);

	return nvme_get_log(hdl, &cmd, rae, len, NULL);
}

/**
 * nvme_get_log_endurance_group() - Retrieve the Endurance Group Log Page
 * @hdl:	Transport handle for the controller.
 * @endgid:	Starting Endurance Group Identifier (ENDGID) to return in
 *		the list.
 * @log:	Pointer to the buffer (@struct nvme_endurance_group_log) where
 * 		the log page data will be stored.
 *
 * This log page indicates if an Endurance Group Event has occurred for a
 * particular Endurance Group. The ENDGID is placed in the Log Specific
 * Identifier (LSI) field of the Get Log Page command.
 *
 * It automatically sets the Log Identifier (LID) and Retain Asynchronous
 * Event (RAE) to false. This command is typically issued for the controller
 * scope, thus using NVME_NSID_NONE.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_endurance_group(struct nvme_transport_handle *hdl,
		__u16 endgid, struct nvme_endurance_group_log *log)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_endurance_group(&cmd, endgid, log);

	return nvme_get_log(hdl, &cmd, false, sizeof(*log), NULL);
}

/**
 * nvme_get_log_predictable_lat_nvmset() - Retrieve the Predictable Latency
 * Per NVM Set Log Page
 * @hdl:	Transport handle for the controller.
 * @nvmsetid:	The NVM Set Identifier (NVMSETID) for which to retrieve the log.
 * @log:	Pointer to the buffer (@struct nvme_nvmset_predictable_lat_log)
 *		where the log page data will be stored.
 *
 * Submits the Get Log Page command specifically for the Predictable Latency Per
 * NVM Set Log. The NVMSETID is placed in the Log Specific Identifier (LSI)
 * field of the command.
 *
 * It automatically sets the Log Identifier (LID) and Retain Asynchronous
 * Event (RAE) to false. This command is typically issued for the controller
 * scope, thus using NVME_NSID_NONE.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_predictable_lat_nvmset(struct nvme_transport_handle *hdl,
		__u16 nvmsetid, struct nvme_nvmset_predictable_lat_log *log)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_predictable_lat_nvmset(&cmd, nvmsetid, log);

	return nvme_get_log(hdl, &cmd, false, sizeof(*log), NULL);
}

/**
 * nvme_get_log_predictable_lat_event() - Retrieve the Predictable Latency Event
 * Aggregate Log Page
 * @hdl:	Transport handle for the controller.
 * @rae:	Retain asynchronous events
 * @lpo:	Offset (in bytes) into the log page data to start the retrieval.
 * @log:	Pointer to the buffer where the log page data will be stored.
 * @len:	Length of the buffer provided in @log.
 *
 * Submits the Get Log Page command specifically for the Predictable Latency
 * Event Aggregate Log, allowing retrieval of data starting at a specified
 * offset (@lpo).
 *
 * It automatically sets the Log Identifier (LID) to
 * NVME_LOG_LID_PREDICTABLE_LAT_AGG.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_predictable_lat_event(struct nvme_transport_handle *hdl,
		bool rae, __u64 lpo, void *log, __u32 len)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_predictable_lat_event(&cmd, lpo, log, len);

	return nvme_get_log(hdl, &cmd, rae, len, NULL);
}

/**
 * nvme_get_log_fdp_configurations() - Retrieve the Flexible Data Placement
 * (FDP) Configurations Log Page
 * @hdl:	Transport handle for the controller.
 * @egid:	Endurance Group Identifier (EGID) to return in the
 * 		list (used in LSI).
 * @lpo:	Offset (in bytes) into the log page data to start the retrieval.
 * @log:	Pointer to the buffer where the log page data will be stored.
 * @len:	Length of the buffer provided in @log.
 *
 * Submits the Get Log Page command specifically for the FDP Configurations Log.
 * The EGID is placed in the Log Specific Identifier (LSI) field.
 *
 * It automatically sets the Log Identifier (LID) and Retain Asynchronous
 * Event (RAE) to false. This command is typically issued for the controller
 * scope, thus using NVME_NSID_NONE.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_fdp_configurations(struct nvme_transport_handle *hdl,
		__u16 egid, __u64 lpo, void *log, __u32 len)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_fdp_configurations(&cmd, egid, lpo, log, len);

	return nvme_get_log(hdl, &cmd, false, len, NULL);
}

/**
 * nvme_get_log_reclaim_unit_handle_usage() - Retrieve the FDP Reclaim Unit
 * Handle (RUH) Usage Log Page
 * @hdl:	Transport handle for the controller.
 * @egid:	Endurance Group Identifier (EGID) (used in LSI).
 * @lpo:	Offset (in bytes) into the log page data to start the retrieval.
 * @log:	Pointer to the buffer where the log page data will be stored.
 * @len:	Length of the buffer provided in @log.
 *
 * Submits the Get Log Page command specifically for the FDP Reclaim Unit Handle
 * Usage Log. The EGID is placed in the Log Specific Identifier (LSI) field.
 *
 * It automatically sets the Log Identifier (LID) and Retain Asynchronous
 * Event (RAE) to false. This command is typically issued for the controller
 * scope, thus using NVME_NSID_NONE.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_reclaim_unit_handle_usage(struct nvme_transport_handle *hdl,
		__u16 egid, __u64 lpo, void *log, __u32 len)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_reclaim_unit_handle_usage(&cmd, egid, lpo, log, len);

	return nvme_get_log(hdl, &cmd, false, len, NULL);
}

/**
 * nvme_get_log_fdp_stats() - Retrieve the Flexible Data Placement (FDP)
 * Statistics Log Page
 * @hdl:	Transport handle for the controller.
 * @egid:	Endurance Group Identifier (EGID) (used in LSI).
 * @lpo:	Offset (in bytes) into the log page data to start the retrieval.
 * @log:	Pointer to the buffer where the log page data will be stored.
 * @len:	Length of the buffer provided in @log.
 *
 * Submits the Get Log Page command specifically for the FDP Statistics Log.
 * The EGID is placed in the Log Specific Identifier (LSI) field.
 *
 * It automatically sets the Log Identifier (LID) and Retain Asynchronous
 * Event (RAE) to false. This command is typically issued for the controller
 * scope, thus using NVME_NSID_NONE.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_fdp_stats(struct nvme_transport_handle *hdl,
		__u16 egid, __u64 lpo, void *log, __u32 len)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_fdp_stats(&cmd, egid, lpo, log, len);

	return nvme_get_log(hdl, &cmd, false, len, NULL);
}

/**
 * nvme_get_log_fdp_events() - Retrieve the Flexible Data Placement (FDP)
 * Events Log Page
 * @hdl:	Transport handle for the controller.
 * @egid:	Endurance Group Identifier (EGID) (used in LSI).
 * @host_events:Whether to report host-initiated events (true) or
 * 		controller-initiated events (false).
 * @lpo:	Offset (in bytes) into the log page data to start the retrieval.
 * @log:	Pointer to the buffer where the log page data will be stored.
 * @len:	Length of the buffer provided in @log.
 *
 * Submits the Get Log Page command specifically for the FDP Events Log.
 * The EGID is placed in the Log Specific Identifier (LSI) field, and the
 * @host_events flag is used to set the Log Specific Parameter (LSP) field.
 *
 * It automatically sets the Log Identifier (LID) and Retain Asynchronous
 * Event (RAE) to false. This command is typically issued for the controller
 * scope, thus using NVME_NSID_NONE.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_fdp_events(struct nvme_transport_handle *hdl,
		__u16 egid, bool host_events, __u64 lpo, void *log, __u32 len)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_fdp_events(&cmd, egid, host_events, lpo, log, len);

	return nvme_get_log(hdl, &cmd, false, len, NULL);
}

/**
 * nvme_get_log_ana() - Retrieve the Asymmetric Namespace Access (ANA) Log Page
 * @hdl:	Transport handle for the controller.
 * @rae:	Retain asynchronous events
 * @lsp:	Log specific parameter, see &enum nvme_get_log_ana_lsp.
 * @lpo:	Offset (in bytes) into the log page data to start the retrieval.
 * @log:	Pointer to the buffer where the log page data will be stored.
 * @len:	Length of the buffer provided in @log.
 *
 * This log consists of a header describing the log and descriptors containing
 * the ANA information for groups that contain namespaces attached to the
 * controller. The @lsp parameter is placed in the Log Specific Parameter field
 * of the command.
 *
 * See &struct nvme_ana_log for the definition of the returned structure.
 *
 * It automatically sets the Log Identifier (LID) to NVME_LOG_LID_ANA.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_ana(struct nvme_transport_handle *hdl, bool rae,
		 enum nvme_log_ana_lsp lsp, __u64 lpo, void *log, __u32 len)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_ana(&cmd, lsp, lpo, log, len);

	return nvme_get_log(hdl, &cmd, rae, len, NULL);
}

/**
 * nvme_get_log_ana_groups() - Retrieve the Asymmetric Namespace Access (ANA)
 * Groups Only Log Page
 * @hdl:	Transport handle for the controller.
 * @rae:	Retain asynchronous events
 * @log:	Pointer to the buffer (@struct nvme_ana_log) where the log page
 * 		data will be stored.
 * @len:	Length of the buffer provided in @log.
 *
 * This function retrieves only the ANA Group Descriptors by setting the Log
 * Specific Parameter (LSP) field to NVME_LOG_ANA_LSP_RGO_GROUPS_ONLY. It is a
 * convenience wrapper around nvme_get_log_ana, using a Log Page Offset (LPO) of
 * 0.
 *
 * See &struct nvme_ana_log for the definition of the returned structure.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_ana_groups(struct nvme_transport_handle *hdl, bool rae,
		struct nvme_ana_log *log, __u32 len)
{
	return nvme_get_log_ana(hdl, rae, NVME_LOG_ANA_LSP_RGO_GROUPS_ONLY,
		0, log, len);
}

/**
 * nvme_get_log_lba_status() - Retrieve the LBA Status Log Page
 * @hdl:	Transport handle for the controller.
 * @rae:	Retain asynchronous events
 * @lpo:	Offset (in bytes) into the log page data to start the retrieval.
 * @log:	Pointer to the buffer where the log page data will be stored.
 * @len:	Length of the buffer provided in @log.
 *
 * Submits the Get Log Page command specifically for the LBA Status Log.
 *
 * It automatically sets the Log Identifier (LID) to NVME_LOG_LID_LBA_STATUS.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_lba_status(struct nvme_transport_handle *hdl,
		bool rae, __u64 lpo, void *log, __u32 len)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_lba_status(&cmd, lpo, log, len);

	return nvme_get_log(hdl, &cmd, rae, len, NULL);
}

/**
 * nvme_get_log_endurance_grp_evt() - Retrieve the Endurance Group Event
 * Aggregate Log Page
 * @hdl:	Transport handle for the controller.
 * @rae:	Retain asynchronous events
 * @lpo:	Offset (in bytes) into the log page data to start the retrieval.
 * @log:	Pointer to the buffer where the log page data will be stored.
 * @len:	Length of the buffer provided in @log.
 *
 * Submits the Get Log Page command specifically for the Endurance Group Event
 * Aggregate Log, allowing retrieval of data starting at a specified offset
 * (@lpo).
 *
 * It automatically sets the Log Identifier (LID) to
 * NVME_LOG_LID_ENDURANCE_GRP_EVT.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_endurance_grp_evt(struct nvme_transport_handle *hdl,
		bool rae, __u64 lpo, void *log, __u32 len)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_endurance_grp_evt(&cmd, lpo, log, len);

	return nvme_get_log(hdl, &cmd, rae, len, NULL);
}

/**
 * nvme_get_log_fid_supported_effects() - Retrieve the Feature Identifiers
 * Supported and Effects Log Page
 * @hdl:	Transport handle for the controller.
 * @csi:	Command set identifier, see &enum nvme_csi for known values
 * @log:	Pointer to the buffer (@struct nvme_fid_supported_effects_log)
 *		where the log page data will be stored.
 *
 * Submits the Get Log Page command specifically for the Feature Identifiers
 * Supported and Effects Log. It automatically sets the Log Identifier (LID).
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_fid_supported_effects(struct nvme_transport_handle *hdl,
		enum nvme_csi csi, struct nvme_fid_supported_effects_log *log)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_fid_supported_effects(&cmd, csi, log);

	return nvme_get_log(hdl, &cmd, false, sizeof(*log), NULL);
}

/**
 * nvme_get_log_mi_cmd_supported_effects() - Retrieve the Management Interface
 * (MI) Commands Supported and Effects Log Page
 * @hdl:	Transport handle for the controller.
 * @log:	Pointer to the buffer (@struct nvme_mi_cmd_supported_effects_log)
 *		where the log page data will be stored.
 *
 * Submits the Get Log Page command specifically for the MI Commands Supported
 * and Effects Log. It automatically sets the Log Identifier (LID). This command
 * is typically issued with a namespace ID of 0xFFFFFFFF (NVME_NSID_NONE).
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_mi_cmd_supported_effects(struct nvme_transport_handle *hdl,
		struct nvme_mi_cmd_supported_effects_log *log)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_mi_cmd_supported_effects(&cmd, log);

	return nvme_get_log(hdl, &cmd, false, sizeof(*log), NULL);
}

/**
 * nvme_get_log_boot_partition() - Retrieve the Boot Partition Log Page
 * @hdl:	Transport handle for the controller.
 * @lsp:	The Log Specific Parameter (LSP) field for this Log
 *		Identifier (LID).
 * @part:	Pointer to the buffer (@struct nvme_boot_partition) where the log
 *		page data will be stored.
 * @len:	Length of the buffer provided in @part.
 *
 * Submits the Get Log Page command specifically for the Boot Partition Log.
 * The LSP field is set based on the @lsp parameter.
 *
 * It automatically sets the Log Identifier (LID) to
 * NVME_LOG_LID_BOOT_PARTITION.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_boot_partition(struct nvme_transport_handle *hdl,
		__u8 lsp, struct nvme_boot_partition *part, __u32 len)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_boot_partition(&cmd, lsp, part, len);

	return nvme_get_log(hdl, &cmd, false, len, NULL);
}

/**
 * nvme_get_log_rotational_media_info() - Retrieve the Rotational Media
 * Information Log Page
 * @hdl:	Transport handle for the controller.
 * @endgid:	The Endurance Group Identifier (ENDGID) to retrieve the
 *		log for (used in LSI).
 * @log:	Pointer to the buffer (@struct nvme_rotational_media_info_log)
 *		where the log page data will be stored.
 * @len:	Length of the buffer provided in @log.
 *
 * Submits the Get Log Page command specifically for the Rotational Media
 * Information Log. The ENDGID is placed in the Log Specific Identifier (LSI)
 * field of the command.
 *
 * It automatically sets the Log Identifier (LID) and Retain Asynchronous
 * Event (RAE) to false. This command is typically issued for the controller
 * scope, thus using NVME_NSID_NONE.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_rotational_media_info(struct nvme_transport_handle *hdl,
		__u16 endgid, struct nvme_rotational_media_info_log *log,
		__u32 len)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_rotational_media_info(&cmd, endgid, log, len);

	return nvme_get_log(hdl, &cmd, false, len, NULL);
}

/**
 * nvme_get_log_dispersed_ns_participating_nss() - Retrieve the Dispersed
 * Namespace Participating NVM Subsystems Log Page
 * @hdl:	Transport handle for the controller.
 * @nsid:	Namespace ID to request the log for.
 * @log:	Pointer to the buffer
 *		(@struct nvme_dispersed_ns_participating_nss_log)
 *		where the log page data will be stored.
 * @len:	Length of the buffer provided in @log.
 *
 * Submits the Get Log Page command specifically for the Dispersed Namespace
 * Participating NVM Subsystems Log. It automatically sets the Log Identifier
 * (LID) and Retain Asynchronous Event (RAE) to false.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_dispersed_ns_participating_nss(struct nvme_transport_handle *hdl,
		__u32 nsid, struct nvme_dispersed_ns_participating_nss_log *log,
		__u32 len)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_dispersed_ns_participating_nss(&cmd, nsid, log, len);

	return nvme_get_log(hdl, &cmd, false, len, NULL);
}

/**
 * nvme_get_log_mgmt_addr_list() - Retrieve the Management Address List Log Page
 * @hdl:	Transport handle for the controller.
 * @log:	Pointer to the buffer (@struct nvme_mgmt_addr_list_log) where
 *		the log page data will be stored.
 * @len:	Length of the buffer provided in @log.
 *
 * Submits the Get Log Page command specifically for the Management Address List Log.
 *
 * It automatically sets the Log Identifier (LID) to NVME_LOG_LID_MGMT_ADDR_LIST,
 * Retain Asynchronous Event (RAE) to false, and uses NVME_NSID_NONE.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_mgmt_addr_list(struct nvme_transport_handle *hdl,
		struct nvme_mgmt_addr_list_log *log, __u32 len)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_mgmt_addr_list(&cmd, log, len);

	return nvme_get_log(hdl, &cmd, false, len, NULL);
}

/**
 * nvme_get_log_phy_rx_eom() - Retrieve the Physical Interface Receiver Eye
 * Opening Measurement Log Page
 * @hdl:	Transport handle for the controller.
 * @lsp:	Log Specific Parameter (LSP), which controls the action
 *		and measurement quality.
 * @controller:	Target Controller ID (used in LSI).
 * @log:	Pointer to the buffer (@struct nvme_phy_rx_eom_log) where the log
 *		page data will be stored.
 * @len:	Length of the buffer provided in @log.
 *
 * Submits the Get Log Page command specifically for the Physical Interface
 * Receiver Eye Opening Measurement Log. The Controller ID is placed in the
 * Log Specific Identifier (LSI) field.
 *
 * It automatically sets the Log Identifier (LID) to NVME_LOG_LID_PHY_RX_EOM,
 * and Retain Asynchronous Event (RAE) to false. This command is typically
 * issued for the controller scope, thus using NVME_NSID_NONE.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_phy_rx_eom(struct nvme_transport_handle *hdl,
		__u8 lsp, __u16 controller, struct nvme_phy_rx_eom_log *log,
		__u32 len)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_phy_rx_eom(&cmd, lsp, controller, log, len);

	return nvme_get_log(hdl, &cmd, false, len, NULL);
}

/**
 * nvme_get_log_reachability_groups() - Retrieve the Reachability Groups Log Page
 * @hdl:	Transport handle for the controller.
 * @nsid:	Namespace ID to request the log for.
 * @rgo:	Return Groups Only. Set to true to return only the Reachability
 *		Group Descriptors.
 * @log:	Pointer to the buffer (@struct nvme_reachability_groups_log)
 *		where the log page data will be stored.
 * @len:	Length of the buffer provided in @log.
 *
 * Submits the Get Log Page command specifically for the Reachability Groups Log.
 * The @rgo parameter is placed in the Log Specific Parameter (LSP) field.
 *
 * It automatically sets the Log Identifier (LID) to
 * NVME_LOG_LID_REACHABILITY_GROUPS.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_reachability_groups(struct nvme_transport_handle *hdl,
		__u32 nsid, bool rgo, struct nvme_reachability_groups_log *log,
		__u32 len)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_reachability_groups(&cmd, rgo, log, len);

	return nvme_get_log(hdl, &cmd, false, len, NULL);
}

/**
 * nvme_get_log_reachability_associations() - Retrieve the Reachability
 * Associations Log Page
 * @hdl:	Transport handle for the controller.
 * @rae:	Retain asynchronous events
 * @rao:	Return Associations Only. Set to true to return only the
 *		Reachability Association Descriptors.
 * @log:	Pointer to the buffer
 *		(@struct nvme_reachability_associations_log) where the log
 *		page data will be stored.
 * @len:	Length of the buffer provided in @log.
 *
 * Submits the Get Log Page command specifically for the Reachability
 * Associations Log. The @rao parameter is placed in the Log Specific Parameter
 * (LSP) field.
 *
 * It automatically sets the Log Identifier (LID) to
 * NVME_LOG_LID_REACHABILITY_ASSOCIATIONS.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_reachability_associations(struct nvme_transport_handle *hdl,
		bool rae, bool rao,
		struct nvme_reachability_associations_log *log, __u32 len)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_reachability_associations(&cmd, rao, log, len);

	return nvme_get_log(hdl, &cmd, rae, len, NULL);
}

/**
 * nvme_get_log_changed_alloc_ns_list() - Retrieve the Changed Allocated
 * Namespace List Log Page
 * @hdl:	Transport handle for the controller.
 * @log:	Pointer to the buffer (@struct nvme_ns_list) where the log page
 *		data will be stored.
 * @len:	Length of the buffer provided in @log.
 *
 * Submits the Get Log Page command specifically for the Changed Allocated
 * Namespace List Log.
 *
 * It automatically sets the Log Identifier (LID) to
 * NVME_LOG_LID_CHANGED_ALLOC_NS_LIST.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_changed_alloc_ns_list(struct nvme_transport_handle *hdl,
		struct nvme_ns_list *log, __u32 len)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_changed_ns(&cmd, log);

	return nvme_get_log(hdl, &cmd, true, len, NULL);
}

/**
 * nvme_get_log_discovery() - Retrieve the Discovery Log Page
 * @hdl:	Transport handle for the controller.
 * @lpo:	Offset (in bytes) into the log page data to start the retrieval.
 * @log:	Pointer to the buffer where the log page data will be stored.
 * @len:	Length of the buffer provided in @log.
 *
 * Submits the Get Log Page command specifically for the Discovery Log.
 * Supported only by NVMe-oF Discovery controllers, returning discovery records.
 *
 * It automatically sets the Log Identifier (LID) to NVME_LOG_LID_DISCOVERY.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_discovery(struct nvme_transport_handle *hdl,
		__u64 lpo, __u32 len, void *log)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_discovery(&cmd, lpo, log, len);

	return nvme_get_log(hdl, &cmd, false, len, NULL);
}

/**
 * nvme_get_log_host_discovery() - Retrieve the Host Discovery Log Page
 * @hdl:	Transport handle for the controller.
 * @rae:	Retain asynchronous events
 * @allhoste:	All Host Entries. Set to true to report all host entries.
 * @log:	Pointer to the buffer (@struct nvme_host_discover_log)
 *		where the log page data will be stored.
 * @len:	Length of the buffer provided in @log.
 *
 * Submits the Get Log Page command specifically for the Host Discovery Log.
 * The @allhoste parameter is placed in the Log Specific Parameter (LSP) field.
 *
 * It automatically sets the Log Identifier (LID) to NVME_LOG_LID_HOST_DISCOVER.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_host_discovery(struct nvme_transport_handle *hdl,
			   bool rae, bool allhoste,
			   struct nvme_host_discover_log *log, __u32 len)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_host_discovery(&cmd, allhoste, log, len);

	return nvme_get_log(hdl, &cmd, false, len, NULL);
}

/**
 * nvme_get_log_ave_discovery() - Retrieve the Asynchronous Event
 * Group (AVE) Discovery Log Page
 * @hdl:	Transport handle for the controller.
 * @rae:	Retain asynchronous events
 * @log:	Pointer to the buffer (@struct nvme_ave_discover_log) where
 *		the log page data will be stored.
 * @len:	Length of the buffer provided in @log.
 *
 * Submits the Get Log Page command specifically for the Asynchronous Event
 * Group (AVE) Discovery Log. It automatically sets the Log Identifier (LID).
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_ave_discovery(struct nvme_transport_handle *hdl,
		bool rae, struct nvme_ave_discover_log *log, __u32 len)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_ave_discovery(&cmd, log, len);

	return nvme_get_log(hdl, &cmd, rae, len, NULL);
}

/**
 * nvme_get_log_pull_model_ddc_req() - Retrieve the Pull Model DDC Request
 * Log Page
 * @hdl:	Transport handle for the controller.
 * @rae:	Retain asynchronous events
 * @log:	Pointer to the buffer (@struct nvme_pull_model_ddc_req_log)
 *		where the log page data will be stored.
 * @len:	Length of the buffer provided in @log.
 *
 * Submits the Get Log Page command specifically for the Pull Model DDC Request
 * Log. It automatically sets the Log Identifier (LID).
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_pull_model_ddc_req(struct nvme_transport_handle *hdl,
		bool rae, struct nvme_pull_model_ddc_req_log *log, __u32 len)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_pull_model_ddc_req(&cmd, log, len);

	return nvme_get_log(hdl, &cmd, rae, len, NULL);
}

/**
 * nvme_get_log_media_unit_stat() - Retrieve the Media Unit Status Log Page
 * @hdl:	Transport handle for the controller.
 * @domid:	The Domain Identifier (DOMID) selection, if supported
 *		(used in LSI).
 * @mus:	Pointer to the buffer (@struct nvme_media_unit_stat_log)
 *		where the log page data will be stored.
 *
 * Submits the Get Log Page command specifically for the Media Unit Status Log.
 * The DOMID is placed in the Log Specific Identifier (LSI) field of the
 * command.
 *
 * It automatically sets the Log Identifier (LID) to
 * NVME_LOG_LID_MEDIA_UNIT_STATUS, and Retain Asynchronous Event (RAE) to false.
 * This command is typically issued for the controller scope, thus using
 * NVME_NSID_NONE.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_media_unit_stat(struct nvme_transport_handle *hdl,
		__u16 domid, struct nvme_media_unit_stat_log *mus)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_media_unit_stat(&cmd, domid, mus);

	return nvme_get_log(hdl, &cmd, false, sizeof(*mus), NULL);
}

/**
 * nvme_get_log_support_cap_config_list() - Retrieve the Supported Capacity
 * Configuration List Log Page
 * @hdl:	Transport handle for the controller.
 * @domid:	The Domain Identifier (DOMID) selection, if
 *		supported (used in LSI).
 * @cap:	Pointer to the buffer
 *		(@struct nvme_supported_cap_config_list_log) where the log
 *		page data will be stored.
 *
 * Submits the Get Log Page command specifically for the Supported Capacity
 * Configuration List Log. The DOMID is placed in the Log Specific Identifier
 * (LSI) field of the command.
 *
 * It automatically sets the Log Identifier (LID) to
 * NVME_LOG_LID_SUPPORTED_CAP_CONFIG_LIST, and Retain Asynchronous Event (RAE)
 * to false. This command is typically issued for the controller scope, thus
 * using NVME_NSID_NONE.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_support_cap_config_list(struct nvme_transport_handle *hdl,
		__u16 domid, struct nvme_supported_cap_config_list_log *cap)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_support_cap_config_list(&cmd, domid, cap);

	return nvme_get_log(hdl, &cmd, false, sizeof(*cap), NULL);
}

/**
 * nvme_get_log_reservation() - Retrieve the Reservation Notification Log Page
 * @hdl:	Transport handle for the controller.
 * @log:	Pointer to the buffer (@struct nvme_resv_notification_log)
 *		where the log page data will be stored.
 *
 * Submits the Get Log Page command specifically for the Reservation
 * Notification Log. It automatically sets the Log Identifier (LID).
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_reservation(struct nvme_transport_handle *hdl,
		struct nvme_resv_notification_log *log)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_reservation(&cmd, log);

	return nvme_get_log(hdl, &cmd, false, sizeof(*log), NULL);
}

/**
 * nvme_get_log_sanitize() - Retrieve the Sanitize Status Log Page
 * @hdl:	Transport handle for the controller.
 * @rae:	Retain asynchronous events
 * @log:	Pointer to the buffer (@struct nvme_sanitize_log_page)
 *		where the log page data will be stored.
 *
 * Submits the Get Log Page command specifically for the Sanitize Status Log.
 * The log page reports sanitize operation time estimates and information about
 * the most recent sanitize operation.
 *
 * It automatically sets the Log Identifier (LID) to NVME_LOG_LID_SANITIZE.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_sanitize(struct nvme_transport_handle *hdl,
		bool rae, struct nvme_sanitize_log_page *log)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_sanitize(&cmd, log);

	return nvme_get_log(hdl, &cmd, rae, sizeof(*log), NULL);
}

/**
 * nvme_get_log_zns_changed_zones() - Retrieve the ZNS Changed Zones Log Page
 * @hdl:	Transport handle for the controller.
 * @nsid:	Namespace ID to request the log for.
 * @rae:	Retain asynchronous events
 * @log:	Pointer to the buffer (@struct nvme_zns_changed_zone_log)
 *		where the log page data will be stored.
 *
 * Submits the Get Log Page command specifically for the ZNS Changed Zones Log.
 * This log lists zones that have changed state due to an exceptional event.
 *
 * It automatically sets the Log Identifier (LID) to
 * NVME_LOG_LID_ZNS_CHANGED_ZONES.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_zns_changed_zones(struct nvme_transport_handle *hdl,
		__u32 nsid, bool rae, struct nvme_zns_changed_zone_log *log)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_zns_changed_zones(&cmd, nsid, log);

	return nvme_get_log(hdl, &cmd, rae, sizeof(*log), NULL);
}

/**
 * nvme_get_log_persistent_event() - Retrieve the Persistent Event Log Page
 * @hdl:	Transport handle for the controller.
 * @action:	Action the controller should take during processing this
 *		command, see &enum nvme_pevent_log_action (used in LSP).
 * @pevent_log:	Pointer to the buffer where the log page data will be stored.
 * @len:	Length of the buffer provided in @pevent_log.
 *
 * Submits the Get Log Page command specifically for the Persistent Event Log.
 * The @action parameter is placed in the Log Specific Parameter (LSP) field.
 *
 * It automatically sets the Log Identifier (LID) to
 * NVME_LOG_LID_PERSISTENT_EVENT and Retain Asynchronous Event (RAE) to false.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_persistent_event(struct nvme_transport_handle *hdl,
		enum nvme_pevent_log_action action, void *pevent_log, __u32 len)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_persistent_event(&cmd, action, pevent_log, len);

	/*
	 * Call the generic log execution function.
	 * The data length is determined by the 'len' parameter.
	 */
	return nvme_get_log(hdl, &cmd, false, len, NULL);
}

/**
 * nvme_get_log_lockdown() - Retrieve the Command and Feature Lockdown Log Page
 * @hdl:	Transport handle for the controller.
 * @cnscp:	Contents and Scope (CNSCP) of Command and Feature
 *		Identifier Lists (used in LSP).
 * @log:	Pointer to the buffer (@struct nvme_lockdown_log) where the log
 *		page data will be stored.
 *
 * Submits the Get Log Page command specifically for the Command and Feature
 * Lockdown Log. The @cnscp parameter is placed in the Log Specific Parameter
 * (LSP) field.
 *
 * It automatically sets the Log Identifier (LID) to
 * NVME_LOG_LID_CMD_AND_FEAT_LOCKDOWN and Retain Asynchronous Event (RAE) to
 * false.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_lockdown(struct nvme_transport_handle *hdl,
		__u8 cnscp, struct nvme_lockdown_log *log)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_lockdown(&cmd, cnscp, log);

	return nvme_get_log(hdl, &cmd, false, sizeof(*log), NULL);
}

/**
 * nvme_get_log_smart() - Retrieve the SMART / Health Information Log Page
 * @hdl:	Transport handle for the controller.
 * @nsid:	Namespace ID to request the log for.
 * @smart_log:	Pointer to the buffer (@struct nvme_smart_log) where the log
 *		page data will be stored.
 *
 * Submits the Get Log Page command specifically for the SMART / Health
 * Information Log. It automatically sets the Log Identifier (LID) and
 * Retain Asynchronous Event (RAE) to false.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_log_smart(struct nvme_transport_handle *hdl,
		__u32 nsid, struct nvme_smart_log *smart_log)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log_smart(&cmd, nsid, smart_log);

	return nvme_get_log(hdl, &cmd, false, NVME_LOG_PAGE_PDU_SIZE, NULL);
}

/**
 * nvme_set_features() - Submit a generic Set Features command
 * @hdl:	Transport handle for the controller.
 * @nsid:	Namespace ID 	sto apply the feature to.
 * @fid:	Feature Identifier (FID) to be set.
 * @sv:		Save Value (SV): If true, the feature value persists
 *		across power states.
 * @cdw11:	Command Dword 11 parameter (feature-specific).
 * @cdw12:	Command Dword 12 parameter (feature-specific).
 * @cdw13:	Command Dword 13 parameter (feature-specific).
 * @uidx:	UUID Index (UIDX) for the command, encoded into cdw14
 * @cdw15:	Command Dword 15 parameter (feature-specific).
 * @data:	Pointer to the data buffer to transfer (if applicable).
 * @len:	Length of the data buffer in bytes.
 * @result:	The command completion result (CQE dword0) on success.
 *
 * Submits the Set Features command, allowing all standard command
 * fields (cdw11-cdw15) and data buffer fields to be specified directly.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_set_features(struct nvme_transport_handle *hdl, __u32 nsid, __u8 fid,
		bool sv, __u32 cdw11, __u32 cdw12, __u32 cdw13, __u8 uidx,
		__u32 cdw15, void *data, __u32 len, __u32 *result)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_set_features(&cmd, fid, sv);
	cmd.nsid = nsid;
	cmd.cdw11 = cdw11;
	cmd.cdw12 = cdw12;
	cmd.cdw13 = cdw13;
	cmd.cdw14 = NVME_FIELD_ENCODE(uidx,
				      NVME_IDENTIFY_CDW14_UUID_SHIFT,
				      NVME_IDENTIFY_CDW14_UUID_MASK);
	cmd.cdw15 = cdw15;
	cmd.data_len = len;
	cmd.addr = (__u64)(uintptr_t)data;

	return nvme_submit_admin_passthru(hdl, &cmd, result);
}

/**
 * nvme_set_features_simple() - Submit a Set Features command using only cdw11
 * @hdl:	Transport handle for the controller.
 * @nsid:	Namespace ID to apply the feature to.
 * @fid:	Feature Identifier (FID) to be set.
 * @sv:		Save Value (SV): If true, the feature value persists across
 *		power states.
 * @cdw11:	Command Dword 11 parameter (feature-specific value).
 * @result:	The command completion result (CQE dword0) on success.
 *
 * Submits the Set Features command for features that only require
 * parameters in cdw11.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_set_features_simple(struct nvme_transport_handle *hdl,
		__u32 nsid, __u8 fid, bool sv, __u32 cdw11, __u32 *result)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_set_features(&cmd, fid, sv);
	cmd.nsid = nsid;
	cmd.cdw11 = cdw11;

	return nvme_submit_admin_passthru(hdl, &cmd, result);
}

/**
 * nvme_get_features() - Submit a Get Features command
 * @hdl:	Transport handle for the controller.
 * @nsid:	Namespace ID, if applicable
 * @fid:	Feature identifier, see &enum nvme_features_id
 * @sel:	Select which type of attribute to return,
 *		see &enum nvme_get_features_sel
 * @cdw11:	Feature specific command dword11 field
 * @uidx:	UUID Index for differentiating vendor specific encoding
 * @data:	User address of feature data, if applicable
 * @len:	Length of feature data, if applicable, in bytes
 * @result:	The command completion result (CQE dword0) on success.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_features(struct nvme_transport_handle *hdl, __u32 nsid,
		__u8 fid, enum nvme_get_features_sel sel,
		__u32 cdw11, __u8 uidx, void *data,
		__u32 len, __u32 *result)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_features(&cmd, fid, sel);

	cmd.nsid = nsid;
	cmd.cdw11 = cdw11;
	cmd.cdw14 = NVME_FIELD_ENCODE(uidx,
			NVME_GET_FEATURES_CDW14_UUID_SHIFT,
			NVME_GET_FEATURES_CDW14_UUID_MASK);
	cmd.data_len = len;
	cmd.addr = (__u64)(uintptr_t)data;

	return nvme_submit_admin_passthru(hdl, &cmd, result);
}

/**
 * nvme_get_features_simple() - Submit a simple Get Features command
 * @hdl:	Transport handle for the controller.
 * @fid:	Feature Identifier (FID) to be retrieved.
 * @sel:	Select (SEL), specifying which feature value
 *		to return (&struct nvme_get_features_sel).
 * @result:	The command completion result (CQE dword0) on success.
 *
 * Submits the Get Features command for features that only require parameters in
 * the CQE dword0 and do not need any parameters in cdw11 through cdw15.
 *
 * Return: 0 on success, the NVMe command status on error, or a negative
 * errno otherwise.
 */
static inline int
nvme_get_features_simple(struct nvme_transport_handle *hdl, __u8 fid,
		enum nvme_get_features_sel sel, __u32 *result)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_features(&cmd, fid, sel);

	return nvme_submit_admin_passthru(hdl, &cmd, result);
}
#endif /* _LIBNVME_IOCTL_H */
