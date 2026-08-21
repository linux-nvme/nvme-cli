// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 *
 * Subsystem Local Memory (SLM) Command Set type definitions
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <nvme/types.h>
#include <nvme/nvme-types-base.h>

/**
 * DOC: nvme-types-slm.h
 *
 * Subsystem Local Memory (SLM) Command Set type definitions
 *
 * Based on NVM Express Subsystem Local Memory Command Set Specification,
 * Revision 1.2
 *
 * Only the Host Addressable Namespaces log page (added by TP4184 Host
 * Addressable Subsystem Local Memory) is defined here. The SLM Command
 * Set itself (memory namespace Identify data structures, SLM Read/Write/
 * Copy/Fill commands) is not yet implemented in libnvme.
 */

/**
 * enum nvme_host_addressable_ns_mat - Addressable Namespaces Data Structure -
 *		Memory Access Type (MAT)
 * @NVME_HOST_ADDRESSABLE_NS_MAT_BARA_SHIFT:	Shift amount to get BAR Access (BARA)
 * @NVME_HOST_ADDRESSABLE_NS_MAT_BARA_MASK:	Mask to get BARA
 * @NVME_HOST_ADDRESSABLE_NS_MAT_CXLA_SHIFT:	Shift amount to get CXL Access (CXLA)
 * @NVME_HOST_ADDRESSABLE_NS_MAT_CXLA_MASK:	Mask to get CXLA
 */
enum nvme_host_addressable_ns_mat {
	NVME_HOST_ADDRESSABLE_NS_MAT_BARA_SHIFT	= 0,
	NVME_HOST_ADDRESSABLE_NS_MAT_BARA_MASK		= 0x1,
	NVME_HOST_ADDRESSABLE_NS_MAT_CXLA_SHIFT	= 1,
	NVME_HOST_ADDRESSABLE_NS_MAT_CXLA_MASK		= 0x1,
};

#define NVME_HOST_ADDRESSABLE_NS_MAT_BARA(mat) \
	NVME_GET(mat, HOST_ADDRESSABLE_NS_MAT_BARA)
#define NVME_HOST_ADDRESSABLE_NS_MAT_CXLA(mat) \
	NVME_GET(mat, HOST_ADDRESSABLE_NS_MAT_CXLA)

/**
 * struct nvme_host_addressable_ns_data - Addressable Namespaces Data Structure
 * @nsid:	Namespace Identifier, may or may not be attached to the
 *		controller processing the command
 * @mat:	Memory Access Type, see &enum nvme_host_addressable_ns_mat
 * @rsvd5:	Reserved
 * @memo:	Memory Offset, the offset of the memory address for this
 *		namespace from the base address of the memory access type
 *		indicated in @mat
 */
struct nvme_host_addressable_ns_data {
	__le32	nsid;
	__u8	mat;
	__u8	rsvd5[3];
	__le64	memo;
};

/**
 * struct nvme_host_addressable_ns_log - Host Addressable Namespaces log page
 *		(Log Page Identifier 85h)
 * @n:		Number of Entries in @ns
 * @rsvd2:	Reserved
 * @ns:		Addressable Namespaces List, @n entries, see
 *		&struct nvme_host_addressable_ns_data
 */
struct nvme_host_addressable_ns_log {
	__le16	n;
	__u8	rsvd2[14];
	struct nvme_host_addressable_ns_data ns[];
};
