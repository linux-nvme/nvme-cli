/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 *	    Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 */
#pragma once

#include <linux/types.h>

struct libnvme_global_ctx;
struct libnvme_transport_handle;

/**
 * struct libnvme_passthru_cmd - nvme passthrough command structure
 * @opcode:	Operation code, see &enum libnvme_io_opcodes and
 *		&enum libnvme_admin_opcodes
 * @flags:	Supported only for NVMe-MI
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
 * @result:	Set on completion to the command's CQE DWORD 0-1
 *		controller response
 */
struct libnvme_passthru_cmd {
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
 * struct libnvme_uring_cmd - nvme uring command structure
 * @opcode:	Operation code, see &enum libnvme_io_opcodes and
 *		&enum libnvme_admin_opcodes
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
struct libnvme_uring_cmd {
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
