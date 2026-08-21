// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 *          Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 *          Daniel Wagner <dwagner@suse.de>
 *
 * NVMe Base Specification type definitions
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <nvme/types.h>

/**
 * DOC: nvme-types-base.h
 *
 * NVMe Base Specification type definitions
 *
 * Based on NVM Express Base Specification,
 * Revision 2.3, August 1, 2025 (Ratified)
 *
 * This file contains core NVMe types organized by functional area:
 * - Helper Macros: NVME_GET, NVME_SET, NVME_CHECK, NVME_VAL
 * - Controller Registers: CAP, CC, CSTS, and other BAR0 registers
 * - Identify Structures: Controller, Namespace, and related data
 * - Log Pages: SMART, Error, Firmware, and other log structures
 * - Features: Feature identifiers and feature-specific data
 * - Commands: Admin and I/O command structures
 * - Namespace Management: Namespace descriptors and attributes
 * - Status & Errors: Status codes and error information
 */


#define NVME_UUID_LEN 16
#define NVME_UUID_LEN_STRING 37 /* 1b4e28ba-2fa1-11d2-883f-0016d3cca427 + \0 */

/**
 * NVME_GET() - extract field from complex value
 * @value: The original value of a complex field
 * @name: The name of the sub-field within an nvme value
 *
 * By convention, this library defines _SHIFT and _MASK such that mask can be
 * applied after the shift to isolate a specific set of bits that decode to a
 * sub-field.
 *
 * Return: The 'name' field from 'value'
 */
#define NVME_GET(value, name) \
	(((value) >> NVME_##name##_SHIFT) & NVME_##name##_MASK)

/**
 * NVME_SET() - set field into complex value
 * @value: The value to be set in its completed position
 * @name: The name of the sub-field within an nvme value
 *
 * Return: The 'name' field from 'value'
 */
#define NVME_SET(value, name) \
	(((__u32)(value) & NVME_##name##_MASK) << NVME_##name##_SHIFT)

/**
 * NVMF_GET() - extract field from complex value
 * @value: The original value of a complex field
 * @name: The name of the sub-field within an nvme value
 *
 * By convention, this library defines _SHIFT and _MASK such that mask can be
 * applied after the shift to isolate a specific set of bits that decode to a
 * sub-field.
 *
 * Returns: The 'name' field from 'value'
 */
#define NVMF_GET(value, name) \
	(((value) >> NVMF_##name##_SHIFT) & NVMF_##name##_MASK)

/**
 * NVMF_SET() - set field into complex value
 * @value: The value to be set in its completed position
 * @name: The name of the sub-field within an nvme value
 *
 * Returns: The 'name' field from 'value'
 */
#define NVMF_SET(value, name) \
	(((__u32)(value) & NVMF_##name##_MASK) << NVMF_##name##_SHIFT)

/**
 * NVME_CHECK() - check value to compare field value
 * @value: The value to be checked
 * @name: The name of the sub-field within an nvme value
 * @check: The sub-field value to check
 *
 * Return: The result of compare the value and the sub-field value
 */
#define NVME_CHECK(value, name, check) ((value) == NVME_##name##_##check)

/**
 * NVME_VAL() - get mask value shifted
 * @name: The name of the sub-field within an nvme value
 *
 * Return: The mask value shifted
 */
#define NVME_VAL(name) (NVME_##name##_MASK << NVME_##name##_SHIFT)

/**
 * enum nvme_constants - A place to stash various constant nvme values
 * @NVME_NSID_ALL:		A broadcast value that is used to specify all
 *				namespaces
 * @NVME_NSID_NONE:		The invalid namespace id, for when the nsid
 *				parameter is not used in a command
 * @NVME_UUID_NONE:		Use to omit a uuid command parameter
 * @NVME_CNTLID_NONE:		Use to omit a cntlid command parameter
 * @NVME_CNSSPECID_NONE:	Use to omit a cns_specific_id command parameter
 * @NVME_LOG_LSP_NONE:		Use to omit a log lsp command parameter
 * @NVME_LOG_LSI_NONE:		Use to omit a log lsi command parameter
 * @NVME_LOG_LPO_NONE:		Use to omit a log lpo command parameter
 * @NVME_IDENTIFY_DATA_SIZE:	The transfer size for nvme identify commands
 * @NVME_LOG_SUPPORTED_LOG_PAGES_MAX: The largest possible index in the supported
 *				log pages log.
 * @NVME_ID_NVMSET_LIST_MAX:	The largest possible nvmset index in identify
 *				nvmeset
 * @NVME_ID_UUID_LIST_MAX:	The largest possible uuid index in identify
 *				uuid list
 * @NVME_ID_CTRL_LIST_MAX:	The largest possible controller index in
 *				identify controller list
 * @NVME_ID_NS_LIST_MAX:	The largest possible namespace index in
 *				identify namespace list
 * @NVME_ID_SECONDARY_CTRL_MAX:	The largest possible secondary controller index
 *				in identify secondary controller
 * @NVME_ID_DOMAIN_LIST_MAX:	The largest possible domain index in the
 *				in domain list
 * @NVME_ID_ENDURANCE_GROUP_LIST_MAX: The largest possible endurance group
 *				index in the endurance group list
 * @NVME_ID_ND_DESCRIPTOR_MAX:	The largest possible namespace granularity
 *				index in the namespace granularity descriptor
 *				list
 * @NVME_FEAT_LBA_RANGE_MAX:	The largest possible LBA range index in feature
 *				lba range type
 * @NVME_LOG_ST_MAX_RESULTS:	The largest possible self test result index in the
 *				device self test log
 * @NVME_LOG_FID_SUPPORTED_EFFECTS_MAX:	The largest possible FID index in the
 *				feature	identifiers effects log.
 * @NVME_LOG_MI_CMD_SUPPORTED_EFFECTS_MAX:	The largest possible MI Command index
 *				in the MI Command effects log.
 * @NVME_LOG_MI_CMD_SUPPORTED_EFFECTS_RESERVED:	The reserved space in the MI Command
 *				effects log.
 * @NVME_LOG_TELEM_BLOCK_SIZE:	Specification defined size of Telemetry Data Blocks
 * @NVME_DSM_MAX_RANGES:	The largest possible range index in a data-set
 *				management command
 * @NVME_NQN_LENGTH:		Max length for NVMe Qualified Name
 * @NVMF_TRADDR_SIZE:		Max Transport Address size
 * @NVMF_TSAS_SIZE:		Max Transport Specific Address Subtype size
 * @NVME_ZNS_CHANGED_ZONES_MAX: Max number of zones in the changed zones log
 *				page
 * @NVME_STREAM_ID_MAX:	Max number of stream IDs
 * @NVME_UNDERLYING_NS_LIST_MAX: The maximum number of Underlying Namespace
 *				Entry data structures reportable in the Get
 *				Underlying Namespace List Identify data
 *				structure
 */
enum nvme_constants {
	NVME_NSID_ALL				= 0xffffffff,
	NVME_NSID_NONE				= 0,
	NVME_UUID_NONE				= 0,
	NVME_CNTLID_NONE			= 0,
	NVME_CNSSPECID_NONE			= 0,
	NVME_LOG_LSP_NONE			= 0,
	NVME_LOG_LSI_NONE			= 0,
	NVME_LOG_LPO_NONE			= 0,
	NVME_IDENTIFY_DATA_SIZE			= 4096,
	NVME_LOG_SUPPORTED_LOG_PAGES_MAX	= 256,
	NVME_ID_NVMSET_LIST_MAX			= 31,
	NVME_ID_UUID_LIST_MAX			= 127,
	NVME_ID_CTRL_LIST_MAX			= 2047,
	NVME_ID_NS_LIST_MAX			= 1024,
	NVME_ID_SECONDARY_CTRL_MAX		= 127,
	NVME_ID_DOMAIN_LIST_MAX			= 31,
	NVME_ID_ENDURANCE_GROUP_LIST_MAX	= 2047,
	NVME_ID_ND_DESCRIPTOR_MAX		= 16,
	NVME_FEAT_LBA_RANGE_MAX			= 64,
	NVME_LOG_ST_MAX_RESULTS			= 20,
	NVME_LOG_TELEM_BLOCK_SIZE		= 512,
	NVME_LOG_FID_SUPPORTED_EFFECTS_MAX	= 256,
	NVME_LOG_MI_CMD_SUPPORTED_EFFECTS_MAX	= 256,
	NVME_LOG_MI_CMD_SUPPORTED_EFFECTS_RESERVED = 768,
	NVME_DSM_MAX_RANGES			= 256,
	NVME_NQN_LENGTH				= 256,
	NVMF_TRADDR_SIZE			= 256,
	NVMF_TSAS_SIZE				= 256,
	NVME_ZNS_CHANGED_ZONES_MAX		= 511,
	NVME_STREAM_ID_MAX			= 0xffff,
	NVME_UNDERLYING_NS_LIST_MAX		= 12,
};

/**
 * enum nvme_csi - Defined command set indicators
 * @NVME_CSI_NVM:	NVM Command Set Indicator
 * @NVME_CSI_KV:	Key Value Command Set
 * @NVME_CSI_ZNS:	Zoned Namespace Command Set
 * @NVME_CSI_SLM:	Subsystem Local Memory Command Set
 * @NVME_CSI_CP:	Computational Programs Command Set
 */
enum nvme_csi {
	NVME_CSI_NVM			= 0,
	NVME_CSI_KV			= 1,
	NVME_CSI_ZNS			= 2,
	NVME_CSI_SLM			= 3,
	NVME_CSI_CP			= 4,
};

/**
 * enum nvme_register_offsets - controller registers for all transports. This
 *				is the layout of BAR0/1 for PCIe, and
 *				properties for fabrics.
 * @NVME_REG_CAP:	Controller Capabilities
 * @NVME_REG_VS:	Version
 * @NVME_REG_INTMS:	Interrupt Mask Set
 * @NVME_REG_INTMC:	Interrupt Mask Clear
 * @NVME_REG_CC:	Controller Configuration
 * @NVME_REG_CSTS:	Controller Status
 * @NVME_REG_NSSR:	NVM Subsystem Reset
 * @NVME_REG_AQA:	Admin Queue Attributes
 * @NVME_REG_ASQ:	Admin SQ Base Address
 * @NVME_REG_ACQ:	Admin CQ Base Address
 * @NVME_REG_CMBLOC:	Controller Memory Buffer Location
 * @NVME_REG_CMBSZ:	Controller Memory Buffer Size
 * @NVME_REG_BPINFO:	Boot Partition Information
 * @NVME_REG_BPRSEL:	Boot Partition Read Select
 * @NVME_REG_BPMBL:	Boot Partition Memory Buffer Location
 * @NVME_REG_CMBMSC:	Controller Memory Buffer Memory Space Control
 * @NVME_REG_CMBSTS:	Controller Memory Buffer Status
 * @NVME_REG_CMBEBS:	Controller Memory Buffer Elasticity Buffer Size
 * @NVME_REG_CMBSWTP:	Controller Memory Buffer Sustained Write Throughput
 * @NVME_REG_NSSD:	NVM Subsystem Shutdown
 * @NVME_REG_CRTO:	Controller Ready Timeouts
 * @NVME_REG_PMRCAP:	Persistent Memory Capabilities
 * @NVME_REG_PMRCTL:	Persistent Memory Region Control
 * @NVME_REG_PMRSTS:	Persistent Memory Region Status
 * @NVME_REG_PMREBS:	Persistent Memory Region Elasticity Buffer Size
 * @NVME_REG_PMRSWTP:	Memory Region Sustained Write Throughput
 * @NVME_REG_PMRMSCL:	Persistent Memory Region Controller Memory Space Control Lower
 * @NVME_REG_PMRMSCU:	Persistent Memory Region Controller Memory Space Control Upper
 */
enum nvme_register_offsets {
	NVME_REG_CAP			= 0x0000,
	NVME_REG_VS			= 0x0008,
	NVME_REG_INTMS			= 0x000c,
	NVME_REG_INTMC			= 0x0010,
	NVME_REG_CC			= 0x0014,
	NVME_REG_CSTS			= 0x001c,
	NVME_REG_NSSR			= 0x0020,
	NVME_REG_AQA			= 0x0024,
	NVME_REG_ASQ			= 0x0028,
	NVME_REG_ACQ			= 0x0030,
	NVME_REG_CMBLOC			= 0x0038,
	NVME_REG_CMBSZ			= 0x003c,
	NVME_REG_BPINFO			= 0x0040,
	NVME_REG_BPRSEL			= 0x0044,
	NVME_REG_BPMBL			= 0x0048,
	NVME_REG_CMBMSC			= 0x0050,
	NVME_REG_CMBSTS			= 0x0058,
	NVME_REG_CMBEBS			= 0x005c,
	NVME_REG_CMBSWTP		= 0x0060,
	NVME_REG_NSSD			= 0x0064,
	NVME_REG_CRTO			= 0x0068,
	NVME_REG_PMRCAP			= 0x0e00,
	NVME_REG_PMRCTL			= 0x0e04,
	NVME_REG_PMRSTS			= 0x0e08,
	NVME_REG_PMREBS			= 0x0e0c,
	NVME_REG_PMRSWTP		= 0x0e10,
	NVME_REG_PMRMSCL		= 0x0e14,
	NVME_REG_PMRMSCU		= 0x0e18,
};

/**
 * nvme_is_64bit_reg() - Checks if offset of the controller register is a know
 *			 64bit value.
 * @offset:	Offset of controller register field in bytes
 *
 * This function does not care about transport so that the offset is not going
 * to be checked inside of this function for the unsupported fields in a
 * specific transport. For example, BPMBL(Boot Partition Memory Buffer
 * Location) register is not supported by fabrics, but it can be checked here.
 *
 * Return: true if given offset is 64bit register, otherwise it returns false.
 */
static inline bool nvme_is_64bit_reg(__u32 offset)
{
	switch (offset) {
	case NVME_REG_CAP:
	case NVME_REG_ASQ:
	case NVME_REG_ACQ:
	case NVME_REG_BPMBL:
	case NVME_REG_CMBMSC:
		return true;
	default:
		return false;
	}
}

/**
 * enum nvme_cap - This field indicates the controller capabilities register
 * @NVME_CAP_MQES_SHIFT:	Shift amount to get the maximum queue entries supported
 * @NVME_CAP_CQR_SHIFT:		Shift amount to get the contiguous queues required
 * @NVME_CAP_AMS_SHIFT:		Shift amount to get the arbitration mechanism supported
 * @NVME_CAP_TO_SHIFT:		Shift amount to get the timeout
 * @NVME_CAP_DSTRD_SHIFT:	Shift amount to get the doorbell stride
 * @NVME_CAP_NSSRC_SHIFT:	Shift amount to get the NVM subsystem reset supported
 * @NVME_CAP_CSS_SHIFT:		Shift amount to get the command sets supported
 * @NVME_CAP_BPS_SHIFT:		Shift amount to get the boot partition support
 * @NVME_CAP_CPS_SHIFT:		Shift amount to get the controller power scope
 * @NVME_CAP_MPSMIN_SHIFT:	Shift amount to get the memory page size minimum
 * @NVME_CAP_MPSMAX_SHIFT:	Shift amount to get the memory page size maximum
 * @NVME_CAP_PMRS_SHIFT:	Shift amount to get the persistent memory region supported
 * @NVME_CAP_CMBS_SHIFT:	Shift amount to get the controller memory buffer supported
 * @NVME_CAP_NSSS_SHIFT:	Shift amount to get the NVM subsystem shutdown supported
 * @NVME_CAP_CRMS_SHIFT:	Shift amount to get the controller ready modes supported
 * @NVME_CAP_MQES_MASK:		Mask to get the maximum queue entries supported
 * @NVME_CAP_CQR_MASK:		Mask to get the contiguous queues required
 * @NVME_CAP_AMS_MASK:		Mask to get the arbitration mechanism supported
 * @NVME_CAP_TO_MASK:		Mask to get the timeout
 * @NVME_CAP_DSTRD_MASK:	Mask to get the doorbell stride
 * @NVME_CAP_NSSRC_MASK:	Mask to get the NVM subsystem reset supported
 * @NVME_CAP_CSS_MASK:		Mask to get the command sets supported
 * @NVME_CAP_BPS_MASK:		Mask to get the boot partition support
 * @NVME_CAP_CPS_MASK:		Mask to get the controller power scope
 * @NVME_CAP_MPSMIN_MASK:	Mask to get the memory page size minimum
 * @NVME_CAP_MPSMAX_MASK:	Mask to get the memory page size maximum
 * @NVME_CAP_PMRS_MASK:		Mask to get the persistent memory region supported
 * @NVME_CAP_CMBS_MASK:		Mask to get the controller memory buffer supported
 * @NVME_CAP_NSSS_MASK:		Mask to get the NVM subsystem shutdown supported
 * @NVME_CAP_CRMS_MASK:		Mask to get the controller ready modes supported
 * @NVME_CAP_AMS_WRR:		Weighted round robin with urgent priority class
 * @NVME_CAP_AMS_VS:		Vendor specific
 * @NVME_CAP_CSS_NVM:		NVM command set or a discovery controller
 * @NVME_CAP_CSS_CSI:		Controller supports one or more I/O command sets
 * @NVME_CAP_CSS_ADMIN:		No I/O command set is supported
 * @NVME_CAP_CPS_NONE:		Not reported
 * @NVME_CAP_CPS_CTRL:		Controller scope
 * @NVME_CAP_CPS_DOMAIN:	Domain scope
 * @NVME_CAP_CPS_NVMS:		NVM subsystem scope
 * @NVME_CAP_CRWMS:		Controller ready with media support
 * @NVME_CAP_CRIMS:		Controller ready independent of media support
 */
enum nvme_cap {
	NVME_CAP_MQES_SHIFT		= 0,
	NVME_CAP_CQR_SHIFT		= 16,
	NVME_CAP_AMS_SHIFT		= 17,
	NVME_CAP_TO_SHIFT		= 24,
	NVME_CAP_DSTRD_SHIFT		= 32,
	NVME_CAP_NSSRC_SHIFT		= 36,
	NVME_CAP_CSS_SHIFT		= 37,
	NVME_CAP_BPS_SHIFT		= 45,
	NVME_CAP_CPS_SHIFT		= 46,
	NVME_CAP_MPSMIN_SHIFT		= 48,
	NVME_CAP_MPSMAX_SHIFT		= 52,
	NVME_CAP_PMRS_SHIFT		= 56,
	NVME_CAP_CMBS_SHIFT		= 57,
	NVME_CAP_NSSS_SHIFT		= 58,
	NVME_CAP_CRMS_SHIFT		= 59,
	NVME_CAP_MQES_MASK		= 0xffff,
	NVME_CAP_CQR_MASK		= 0x1,
	NVME_CAP_AMS_MASK		= 0x3,
	NVME_CAP_TO_MASK		= 0xff,
	NVME_CAP_DSTRD_MASK		= 0xf,
	NVME_CAP_NSSRC_MASK		= 0x1,
	NVME_CAP_CSS_MASK		= 0xff,
	NVME_CAP_BPS_MASK		= 0x1,
	NVME_CAP_CPS_MASK		= 0x3,
	NVME_CAP_MPSMIN_MASK		= 0xf,
	NVME_CAP_MPSMAX_MASK		= 0xf,
	NVME_CAP_PMRS_MASK		= 0x1,
	NVME_CAP_CMBS_MASK		= 0x1,
	NVME_CAP_NSSS_MASK		= 0x1,
	NVME_CAP_CRMS_MASK		= 0x3,
	NVME_CAP_AMS_WRR		= 1 << 0,
	NVME_CAP_AMS_VS			= 1 << 1,
	NVME_CAP_CSS_NVM		= 1 << 0,
	NVME_CAP_CSS_CSI		= 1 << 6,
	NVME_CAP_CSS_ADMIN		= 1 << 7,
	NVME_CAP_CPS_NONE		= 0,
	NVME_CAP_CPS_CTRL		= 1,
	NVME_CAP_CPS_DOMAIN		= 2,
	NVME_CAP_CPS_NVMS		= 3,
	NVME_CAP_CRWMS			= 1 << 0,
	NVME_CAP_CRIMS			= 1 << 1,
};

#define NVME_CAP_MQES(cap)	NVME_GET(cap, CAP_MQES)
#define NVME_CAP_CQR(cap)	NVME_GET(cap, CAP_CQR)
#define NVME_CAP_AMS(cap)	NVME_GET(cap, CAP_AMS)
#define NVME_CAP_TO(cap)	NVME_GET(cap, CAP_TO)
#define NVME_CAP_DSTRD(cap)	NVME_GET(cap, CAP_DSTRD)
#define NVME_CAP_NSSRC(cap)	NVME_GET(cap, CAP_NSSRC)
#define NVME_CAP_CSS(cap)	NVME_GET(cap, CAP_CSS)
#define NVME_CAP_BPS(cap)	NVME_GET(cap, CAP_BPS)
#define NVME_CAP_CPS(cap)	NVME_GET(cap, CAP_CPS)
#define NVME_CAP_MPSMIN(cap)	NVME_GET(cap, CAP_MPSMIN)
#define NVME_CAP_MPSMAX(cap)	NVME_GET(cap, CAP_MPSMAX)
#define NVME_CAP_PMRS(cap)	NVME_GET(cap, CAP_PMRS)
#define NVME_CAP_CMBS(cap)	NVME_GET(cap, CAP_CMBS)
#define NVME_CAP_NSSS(cap)	NVME_GET(cap, CAP_NSSS)
#define NVME_CAP_CRMS(cap)	NVME_GET(cap, CAP_CRMS)

/**
 * enum nvme_vs - This field indicates the version
 * @NVME_VS_TER_SHIFT:	Shift amount to get the tertiary version
 * @NVME_VS_MNR_SHIFT:	Shift amount to get the minor version
 * @NVME_VS_MJR_SHIFT:	Shift amount to get the major version
 * @NVME_VS_TER_MASK:	Mask to get the tertiary version
 * @NVME_VS_MNR_MASK:	Mask to get the minor version
 * @NVME_VS_MJR_MASK:	Mask to get the major version
 */
enum nvme_vs {
	NVME_VS_TER_SHIFT		= 0,
	NVME_VS_MNR_SHIFT		= 8,
	NVME_VS_MJR_SHIFT		= 16,
	NVME_VS_TER_MASK		= 0xff,
	NVME_VS_MNR_MASK		= 0xff,
	NVME_VS_MJR_MASK		= 0xffff,
};

#define NVME_VS_TER(vs)		NVME_GET(vs, VS_TER)
#define NVME_VS_MNR(vs)		NVME_GET(vs, VS_MNR)
#define NVME_VS_MJR(vs)		NVME_GET(vs, VS_MJR)

#define NVME_MAJOR(ver)		NVME_VS_MJR(ver)
#define NVME_MINOR(ver)		NVME_VS_MNR(ver)
#define NVME_TERTIARY(ver)	NVME_VS_TER(ver)

/**
 * enum nvme_cc - This field indicates the controller configuration
 * @NVME_CC_EN_SHIFT:		Shift amount to get the enable
 * @NVME_CC_CSS_SHIFT:		Shift amount to get the I/O command set selected
 * @NVME_CC_MPS_SHIFT:		Shift amount to get the memory page size
 * @NVME_CC_AMS_SHIFT:		Shift amount to get the arbitration mechanism selected
 * @NVME_CC_SHN_SHIFT:		Shift amount to get the shutdown notification
 * @NVME_CC_IOSQES_SHIFT:	Shift amount to get the I/O submission queue entry size
 * @NVME_CC_IOCQES_SHIFT:	Shift amount to get the I/O completion queue entry size
 * @NVME_CC_CRIME_SHIFT:	Shift amount to get the controller ready independent of media enable
 * @NVME_CC_EN_MASK:		Mask to get the enable
 * @NVME_CC_CSS_MASK:		Mask to get the I/O command set selected
 * @NVME_CC_MPS_MASK:		Mask to get the memory page size
 * @NVME_CC_AMS_MASK:		Mask to get the arbitration mechanism selected
 * @NVME_CC_SHN_MASK:		Mask to get the shutdown notification
 * @NVME_CC_CRIME_MASK:		Mask to get the I/O submission queue entry size
 * @NVME_CC_IOSQES_MASK:	Mask to get the I/O completion queue entry size
 * @NVME_CC_IOCQES_MASK:	Mask to get the controller ready independent of media enable
 * @NVME_CC_CSS_NVM:		NVM command set
 * @NVME_CC_CSS_CSI:		All supported I/O command sets
 * @NVME_CC_CSS_ADMIN:		Admin command set only
 * @NVME_CC_AMS_RR:		Round robin
 * @NVME_CC_AMS_WRRU:		Weighted round robin with urgent priority class
 * @NVME_CC_AMS_VS:		Vendor specific
 * @NVME_CC_SHN_NONE:		No notification; no effect
 * @NVME_CC_SHN_NORMAL:		Normal shutdown notification
 * @NVME_CC_SHN_ABRUPT:		Abrupt shutdown notification
 * @NVME_CC_CRWME:		Controller ready with media enable
 * @NVME_CC_CRIME:		Controller ready independent of media enable
 */
enum nvme_cc {
	NVME_CC_EN_SHIFT	= 0,
	NVME_CC_CSS_SHIFT	= 4,
	NVME_CC_MPS_SHIFT	= 7,
	NVME_CC_AMS_SHIFT	= 11,
	NVME_CC_SHN_SHIFT	= 14,
	NVME_CC_IOSQES_SHIFT	= 16,
	NVME_CC_IOCQES_SHIFT	= 20,
	NVME_CC_CRIME_SHIFT	= 24,
	NVME_CC_EN_MASK		= 0x1,
	NVME_CC_CSS_MASK	= 0x7,
	NVME_CC_MPS_MASK	= 0xf,
	NVME_CC_AMS_MASK	= 0x7,
	NVME_CC_SHN_MASK	= 0x3,
	NVME_CC_CRIME_MASK	= 0x1,
	NVME_CC_IOSQES_MASK	= 0xf,
	NVME_CC_IOCQES_MASK	= 0xf,
	NVME_CC_CSS_NVM		= 0,
	NVME_CC_CSS_CSI		= 6,
	NVME_CC_CSS_ADMIN	= 7,
	NVME_CC_AMS_RR		= 0,
	NVME_CC_AMS_WRRU	= 1,
	NVME_CC_AMS_VS		= 7,
	NVME_CC_SHN_NONE	= 0,
	NVME_CC_SHN_NORMAL	= 1,
	NVME_CC_SHN_ABRUPT	= 2,
	NVME_CC_CRWME		= 0,
	NVME_CC_CRIME		= 1,
};

#define NVME_CC_EN(cc)		NVME_GET(cc, CC_EN)
#define NVME_CC_CSS(cc)		NVME_GET(cc, CC_CSS)
#define NVME_CC_MPS(cc)		NVME_GET(cc, CC_MPS)
#define NVME_CC_AMS(cc)		NVME_GET(cc, CC_AMS)
#define NVME_CC_SHN(cc)		NVME_GET(cc, CC_SHN)
#define NVME_CC_IOSQES(cc)	NVME_GET(cc, CC_IOSQES)
#define NVME_CC_IOCQES(cc)	NVME_GET(cc, CC_IOCQES)
#define NVME_CC_CRIME(cc)	NVME_GET(cc, CC_CRIME)

/**
 * enum nvme_csts - This field indicates the controller status register
 * @NVME_CSTS_RDY_SHIFT:	Shift amount to get the ready
 * @NVME_CSTS_CFS_SHIFT:	Shift amount to get the controller fatal status
 * @NVME_CSTS_SHST_SHIFT:	Shift amount to get the shutdown status
 * @NVME_CSTS_NSSRO_SHIFT:	Shift amount to get the NVM subsystem reset occurred
 * @NVME_CSTS_PP_SHIFT:		Shift amount to get the processing paused
 * @NVME_CSTS_ST_SHIFT:		Shift amount to get the shutdown type
 * @NVME_CSTS_RDY_MASK:		Mask to get the ready
 * @NVME_CSTS_CFS_MASK:		Mask to get the controller fatal status
 * @NVME_CSTS_SHST_MASK:	Mask to get the shutdown status
 * @NVME_CSTS_NSSRO_MASK:	Mask to get the NVM subsystem reset occurred
 * @NVME_CSTS_PP_MASK:		Mask to get the processing paused
 * @NVME_CSTS_ST_MASK:		Mask to get the shutdown type
 * @NVME_CSTS_SHST_NORMAL:	Normal operation
 * @NVME_CSTS_SHST_OCCUR:	Shutdown processing occurring
 * @NVME_CSTS_SHST_CMPLT:	Shutdown processing complete
 */
enum nvme_csts {
	NVME_CSTS_RDY_SHIFT	= 0,
	NVME_CSTS_CFS_SHIFT	= 1,
	NVME_CSTS_SHST_SHIFT	= 2,
	NVME_CSTS_NSSRO_SHIFT	= 4,
	NVME_CSTS_PP_SHIFT	= 5,
	NVME_CSTS_ST_SHIFT	= 6,
	NVME_CSTS_RDY_MASK	= 0x1,
	NVME_CSTS_CFS_MASK	= 0x1,
	NVME_CSTS_SHST_MASK	= 0x3,
	NVME_CSTS_NSSRO_MASK	= 0x1,
	NVME_CSTS_PP_MASK	= 0x1,
	NVME_CSTS_ST_MASK	= 0x1,
	NVME_CSTS_SHST_NORMAL	= 0,
	NVME_CSTS_SHST_OCCUR	= 1,
	NVME_CSTS_SHST_CMPLT	= 2,
};

#define NVME_CSTS_RDY(csts)	NVME_GET(csts, CSTS_RDY)
#define NVME_CSTS_CFS(csts)	NVME_GET(csts, CSTS_CFS)
#define NVME_CSTS_SHST(csts)	NVME_GET(csts, CSTS_SHST)
#define NVME_CSTS_NSSRO(csts)	NVME_GET(csts, CSTS_NSSRO)
#define NVME_CSTS_PP(csts)	NVME_GET(csts, CSTS_PP)
#define NVME_CSTS_ST(csts)	NVME_GET(csts, CSTS_ST)

/**
 * enum nvme_aqa - This field indicates the admin queue attributes
 * @NVME_AQA_ASQS_SHIFT:	Shift amount to get the admin submission queue size
 * @NVME_AQA_ACQS_SHIFT:	Shift amount to get the admin completion queue size
 * @NVME_AQA_ASQS_MASK:		Mask to get the admin submission queue size
 * @NVME_AQA_ACQS_MASK:		Mask to get the admin completion queue size
 */
enum nvme_aqa {
	NVME_AQA_ASQS_SHIFT	= 0,
	NVME_AQA_ACQS_SHIFT	= 16,
	NVME_AQA_ASQS_MASK	= 0xfff,
	NVME_AQA_ACQS_MASK	= 0xfff,
};

#define NVME_AQA_ASQS(aqa)	NVME_GET(aqa, AQA_ASQS)
#define NVME_AQA_ACQS(aqa)	NVME_GET(aqa, AQA_ACQS)

/**
 * enum nvme_asq - This field indicates the admin submission queue base address
 * @NVME_ASQ_ASQB_SHIFT:	Shift amount to get the admin submission queue base
 */
enum nvme_asq {
	NVME_ASQ_ASQB_SHIFT		= 12,
};
static const __u64 NVME_ASQ_ASQB_MASK = 0xfffffffffffffull;

#define NVME_ASQ_ASQB(asq)		NVME_GET(asq, ASQ_ASQB)

/**
 * enum nvme_acq - This field indicates the admin completion queue base address
 * @NVME_ACQ_ACQB_SHIFT:	Shift amount to get the admin completion queue base
 */
enum nvme_acq {
	NVME_ACQ_ACQB_SHIFT		= 12,
};
static const __u64 NVME_ACQ_ACQB_MASK = 0xfffffffffffffull;

#define NVME_ACQ_ACQB(acq)		NVME_GET(acq, ACQ_ACQB)

/**
 * enum nvme_cmbloc - This field indicates the controller memory buffer location
 * @NVME_CMBLOC_BIR_SHIFT:	Shift amount to get the base indicator register
 * @NVME_CMBLOC_CQMMS_SHIFT:	Shift amount to get the CMB queue mixed memory support
 * @NVME_CMBLOC_CQPDS_SHIFT:	Shift amount to get the CMB queue physically discontiguous support
 * @NVME_CMBLOC_CDPLMS_SHIFT:	Shift amount to get the CMB data pointer mixed locations support
 * @NVME_CMBLOC_CDPCILS_SHIFT:	Shift amount to get the CMB data pointer and command independent locations support
 * @NVME_CMBLOC_CDMMMS_SHIFT:	Shift amount to get the CMB data metadata mixed memory support
 * @NVME_CMBLOC_CQDA_SHIFT:	Shift amount to get the CMB queue dword alignment
 * @NVME_CMBLOC_OFST_SHIFT:	Shift amount to get the offset
 * @NVME_CMBLOC_BIR_MASK:	Mask to get the base indicator register
 * @NVME_CMBLOC_CQMMS_MASK:	Mask to get the CMB queue mixed memory support
 * @NVME_CMBLOC_CQPDS_MASK:	Mask to get the CMB queue physically discontiguous support
 * @NVME_CMBLOC_CDPLMS_MASK:	Mask to get the CMB data pointer mixed locations support
 * @NVME_CMBLOC_CDPCILS_MASK:	Mask to get the CMB data pointer and command independent locations support
 * @NVME_CMBLOC_CDMMMS_MASK:	Mask to get the CMB data metadata mixed memory support
 * @NVME_CMBLOC_CQDA_MASK:	Mask to get the CMB queue dword alignment
 * @NVME_CMBLOC_OFST_MASK:	Mask to get the offset
 */
enum nvme_cmbloc {
	NVME_CMBLOC_BIR_SHIFT		= 0,
	NVME_CMBLOC_CQMMS_SHIFT		= 3,
	NVME_CMBLOC_CQPDS_SHIFT		= 4,
	NVME_CMBLOC_CDPLMS_SHIFT	= 5,
	NVME_CMBLOC_CDPCILS_SHIFT	= 6,
	NVME_CMBLOC_CDMMMS_SHIFT	= 7,
	NVME_CMBLOC_CQDA_SHIFT		= 8,
	NVME_CMBLOC_OFST_SHIFT		= 12,
	NVME_CMBLOC_BIR_MASK		= 0x7,
	NVME_CMBLOC_CQMMS_MASK		= 0x1,
	NVME_CMBLOC_CQPDS_MASK		= 0x1,
	NVME_CMBLOC_CDPLMS_MASK		= 0x1,
	NVME_CMBLOC_CDPCILS_MASK	= 0x1,
	NVME_CMBLOC_CDMMMS_MASK		= 0x1,
	NVME_CMBLOC_CQDA_MASK		= 0x1,
	NVME_CMBLOC_OFST_MASK		= 0xfffff,
};

#define NVME_CMBLOC_BIR(cmbloc)		NVME_GET(cmbloc, CMBLOC_BIR)
#define NVME_CMBLOC_CQMMS(cmbloc)	NVME_GET(cmbloc, CMBLOC_CQMMS)
#define NVME_CMBLOC_CQPDS(cmbloc)	NVME_GET(cmbloc, CMBLOC_CQPDS)
#define NVME_CMBLOC_CDPLMS(cmbloc)	NVME_GET(cmbloc, CMBLOC_CDPLMS)
#define NVME_CMBLOC_CDPCILS(cmbloc)	NVME_GET(cmbloc, CMBLOC_CDPCILS)
#define NVME_CMBLOC_CDMMMS(cmbloc)	NVME_GET(cmbloc, CMBLOC_CDMMMS)
#define NVME_CMBLOC_CQDA(cmbloc)	NVME_GET(cmbloc, CMBLOC_CQDA)
#define NVME_CMBLOC_OFST(cmbloc)	NVME_GET(cmbloc, CMBLOC_OFST)

/**
 * enum nvme_cmbsz - This field indicates the controller memory buffer size
 * @NVME_CMBSZ_SQS_SHIFT:	Shift amount to get the submission queue support
 * @NVME_CMBSZ_CQS_SHIFT:	Shift amount to get the completion queue support
 * @NVME_CMBSZ_LISTS_SHIFT:	Shift amount to get the PLP SGL list support
 * @NVME_CMBSZ_RDS_SHIFT:	Shift amount to get the read data support
 * @NVME_CMBSZ_WDS_SHIFT:	Shift amount to get the write data support
 * @NVME_CMBSZ_SZU_SHIFT:	Shift amount to get the size units
 * @NVME_CMBSZ_SZ_SHIFT:	Shift amount to get the size
 * @NVME_CMBSZ_SQS_MASK:	Mask to get the submission queue support
 * @NVME_CMBSZ_CQS_MASK:	Mask to get the completion queue support
 * @NVME_CMBSZ_LISTS_MASK:	Mask to get the PLP SGL list support
 * @NVME_CMBSZ_RDS_MASK:	Mask to get the read data support
 * @NVME_CMBSZ_WDS_MASK:	Mask to get the write data support
 * @NVME_CMBSZ_SZU_MASK:	Mask to get the size units
 * @NVME_CMBSZ_SZ_MASK:		Mask to get the size
 * @NVME_CMBSZ_SZU_4K:		4 KiB
 * @NVME_CMBSZ_SZU_64K:		64 KiB
 * @NVME_CMBSZ_SZU_1M:		1 MiB
 * @NVME_CMBSZ_SZU_16M:		16 MiB
 * @NVME_CMBSZ_SZU_256M:	256 MiB
 * @NVME_CMBSZ_SZU_4G:		4 GiB
 * @NVME_CMBSZ_SZU_64G:		64 GiB
 */
enum nvme_cmbsz {
	NVME_CMBSZ_SQS_SHIFT	= 0,
	NVME_CMBSZ_CQS_SHIFT	= 1,
	NVME_CMBSZ_LISTS_SHIFT	= 2,
	NVME_CMBSZ_RDS_SHIFT	= 3,
	NVME_CMBSZ_WDS_SHIFT	= 4,
	NVME_CMBSZ_SZU_SHIFT	= 8,
	NVME_CMBSZ_SZ_SHIFT	= 12,
	NVME_CMBSZ_SQS_MASK	= 0x1,
	NVME_CMBSZ_CQS_MASK	= 0x1,
	NVME_CMBSZ_LISTS_MASK	= 0x1,
	NVME_CMBSZ_RDS_MASK	= 0x1,
	NVME_CMBSZ_WDS_MASK	= 0x1,
	NVME_CMBSZ_SZU_MASK	= 0xf,
	NVME_CMBSZ_SZ_MASK	= 0xfffff,
	NVME_CMBSZ_SZU_4K	= 0,
	NVME_CMBSZ_SZU_64K	= 1,
	NVME_CMBSZ_SZU_1M	= 2,
	NVME_CMBSZ_SZU_16M	= 3,
	NVME_CMBSZ_SZU_256M	= 4,
	NVME_CMBSZ_SZU_4G	= 5,
	NVME_CMBSZ_SZU_64G	= 6,
};

#define NVME_CMBSZ_SQS(cmbsz)		NVME_GET(cmbsz, CMBSZ_SQS)
#define NVME_CMBSZ_CQS(cmbsz)		NVME_GET(cmbsz, CMBSZ_CQS)
#define NVME_CMBSZ_LISTS(cmbsz)		NVME_GET(cmbsz, CMBSZ_LISTS)
#define NVME_CMBSZ_RDS(cmbsz)		NVME_GET(cmbsz, CMBSZ_RDS)
#define NVME_CMBSZ_WDS(cmbsz)		NVME_GET(cmbsz, CMBSZ_WDS)
#define NVME_CMBSZ_SZU(cmbsz)		NVME_GET(cmbsz, CMBSZ_SZU)
#define NVME_CMBSZ_SZ(cmbsz)		NVME_GET(cmbsz, CMBSZ_SZ)

/**
 * nvme_cmb_size() - Calculate size of the controller memory buffer
 * @cmbsz:	Value from controller register %NVME_REG_CMBSZ
 *
 * Return: size of controller memory buffer in bytes
 */
static inline __u64 nvme_cmb_size(__u32 cmbsz)
{
	return ((__u64)NVME_CMBSZ_SZ(cmbsz)) *
		(1ULL << (12 + 4 * NVME_CMBSZ_SZU(cmbsz)));
}

/**
 * enum nvme_bpinfo - This field indicates the boot partition information
 * @NVME_BPINFO_BPSZ_SHIFT:		Shift amount to get the boot partition size
 * @NVME_BPINFO_BRS_SHIFT:		Shift amount to get the boot read status
 * @NVME_BPINFO_ABPID_SHIFT:		Shift amount to get the active boot partition ID
 * @NVME_BPINFO_BPSZ_MASK:		Mask to get the boot partition size
 * @NVME_BPINFO_BRS_MASK:		Mask to get the boot read status
 * @NVME_BPINFO_ABPID_MASK:		Mask to get the active boot partition ID
 * @NVME_BPINFO_BRS_NONE:		No boot partition read operation requested
 * @NVME_BPINFO_BRS_READ_IN_PROGRESS:	Boot partition read in progress
 * @NVME_BPINFO_BRS_READ_SUCCESS:	Boot partition read completed successfully
 * @NVME_BPINFO_BRS_READ_ERROR:		Error completing boot partition read
 */
enum nvme_bpinfo {
	NVME_BPINFO_BPSZ_SHIFT			= 0,
	NVME_BPINFO_BRS_SHIFT			= 24,
	NVME_BPINFO_ABPID_SHIFT			= 31,
	NVME_BPINFO_BPSZ_MASK			= 0x7fff,
	NVME_BPINFO_BRS_MASK			= 0x3,
	NVME_BPINFO_ABPID_MASK			= 0x1,
	NVME_BPINFO_BRS_NONE			= 0,
	NVME_BPINFO_BRS_READ_IN_PROGRESS	= 1,
	NVME_BPINFO_BRS_READ_SUCCESS		= 2,
	NVME_BPINFO_BRS_READ_ERROR		= 3,
};

#define NVME_BPINFO_BPSZ(bpinfo)	NVME_GET(bpinfo, BPINFO_BPSZ)
#define NVME_BPINFO_BRS(bpinfo)		NVME_GET(bpinfo, BPINFO_BRS)
#define NVME_BPINFO_ABPID(bpinfo)	NVME_GET(bpinfo, BPINFO_ABPID)

/**
 * enum nvme_bprsel - This field indicates the boot partition read select
 * @NVME_BPRSEL_BPRSZ_SHIFT:	Shift amount to get the boot partition read size
 * @NVME_BPRSEL_BPROF_SHIFT:	Shift amount to get the boot partition read offset
 * @NVME_BPRSEL_BPID_SHIFT:	Shift amount to get the boot partition identifier
 * @NVME_BPRSEL_BPRSZ_MASK:	Mask to get the boot partition read size
 * @NVME_BPRSEL_BPROF_MASK:	Mask to get the boot partition read offset
 * @NVME_BPRSEL_BPID_MASK:	Mask to get the boot partition identifier
 */
enum nvme_bprsel {
	NVME_BPRSEL_BPRSZ_SHIFT		= 0,
	NVME_BPRSEL_BPROF_SHIFT		= 10,
	NVME_BPRSEL_BPID_SHIFT		= 31,
	NVME_BPRSEL_BPRSZ_MASK		= 0x3ff,
	NVME_BPRSEL_BPROF_MASK		= 0xfffff,
	NVME_BPRSEL_BPID_MASK		= 0x1,
};

#define NVME_BPRSEL_BPRSZ(bprsel)	NVME_GET(bprsel, BPRSEL_BPRSZ)
#define NVME_BPRSEL_BPROF(bprsel)	NVME_GET(bprsel, BPRSEL_BPROF)
#define NVME_BPRSEL_BPID(bprsel)	NVME_GET(bprsel, BPRSEL_BPID)

/**
 * enum nvme_bpmbl - This field indicates the boot partition memory buffer location
 * @NVME_BPMBL_BMBBA_SHIFT:	Shift amount to get the boot partition memory buffer base address
 */
enum nvme_bpmbl {
	NVME_BPMBL_BMBBA_SHIFT		= 12,
};
static const __u64 NVME_BPMBL_BMBBA_MASK = 0xfffffffffffffull;

#define NVME_BPMBL_BMBBA(bpmbl)		NVME_GET(bpmbl, BPMBL_BMBBA)

/**
 * enum nvme_cmbmsc - This field indicates the controller memory buffer memory space control
 * @NVME_CMBMSC_CRE_SHIFT:	Shift amount to get the capabilities registers enabled
 * @NVME_CMBMSC_CMSE_SHIFT:	Shift amount to get the controller memory space enable
 * @NVME_CMBMSC_CBA_SHIFT:	Shift amount to get the controller base address
 * @NVME_CMBMSC_CRE_MASK:	Mask to get the capabilities registers enabled
 * @NVME_CMBMSC_CMSE_MASK:	Mask to get the controller memory space enable
 */
enum nvme_cmbmsc {
	NVME_CMBMSC_CRE_SHIFT		= 0,
	NVME_CMBMSC_CMSE_SHIFT		= 1,
	NVME_CMBMSC_CBA_SHIFT		= 12,
	NVME_CMBMSC_CRE_MASK		= 0x1,
	NVME_CMBMSC_CMSE_MASK		= 0x1,
};
static const __u64 NVME_CMBMSC_CBA_MASK = 0xfffffffffffffull;

#define NVME_CMBMSC_CRE(cmbmsc)		NVME_GET(cmbmsc, CMBMSC_CRE)
#define NVME_CMBMSC_CMSE(cmbmsc)	NVME_GET(cmbmsc, CMBMSC_CMSE)
#define NVME_CMBMSC_CBA(cmbmsc)		NVME_GET(cmbmsc, CMBMSC_CBA)

/**
 * enum nvme_cmbsts - This field indicates the controller memory buffer status
 * @NVME_CMBSTS_CBAI_SHIFT:	Shift amount to get the controller base address invalid
 * @NVME_CMBSTS_CBAI_MASK:	Mask to get the controller base address invalid
 */
enum nvme_cmbsts {
	NVME_CMBSTS_CBAI_SHIFT	= 0,
	NVME_CMBSTS_CBAI_MASK	= 0x1,
};

#define NVME_CMBSTS_CBAI(cmbsts)	NVME_GET(cmbsts, CMBSTS_CBAI)

/**
 * enum nvme_unit - Defined buffer size and write throughput granularity units
 * @NVME_UNIT_B:	Bytes or Bytes/second
 * @NVME_UNIT_1K:	1 KiB or 1 KiB/second
 * @NVME_UNIT_1M:	1 MiB or 1 MiB/second
 * @NVME_UNIT_1G:	1 GiB or 1 GiB/second
 */
enum nvme_unit {
	NVME_UNIT_B	= 0,
	NVME_UNIT_1K	= 1,
	NVME_UNIT_1M	= 2,
	NVME_UNIT_1G	= 3,
};

/**
 * enum nvme_cmbebs - This field indicates the controller memory buffer elasticity buffer size
 * @NVME_CMBEBS_CMBSZU_SHIFT:	Shift amount to get the CMB elasticity buffer size units
 * @NVME_CMBEBS_RBB_SHIFT:	Shift amount to get the read bypass behavior
 * @NVME_CMBEBS_CMBWBZ_SHIFT:	Shift amount to get the CMB elasiticity buffer size base
 * @NVME_CMBEBS_CMBSZU_MASK:	Mask to get the CMB elasticity buffer size units
 * @NVME_CMBEBS_RBB_MASK:	Mask to get the read bypass behavior
 * @NVME_CMBEBS_CMBWBZ_MASK:	Mask to get the CMB elasiticity buffer size base
 * @NVME_CMBEBS_CMBSZU_B:	Bytes granularity
 * @NVME_CMBEBS_CMBSZU_1K:	1 KiB granularity
 * @NVME_CMBEBS_CMBSZU_1M:	1 MiB granularity
 * @NVME_CMBEBS_CMBSZU_1G:	1 GiB granularity
 */
enum nvme_cmbebs {
	NVME_CMBEBS_CMBSZU_SHIFT	= 0,
	NVME_CMBEBS_RBB_SHIFT		= 4,
	NVME_CMBEBS_CMBWBZ_SHIFT	= 8,
	NVME_CMBEBS_CMBSZU_MASK		= 0xf,
	NVME_CMBEBS_RBB_MASK		= 0x1,
	NVME_CMBEBS_CMBWBZ_MASK		= 0xffffff,
	NVME_CMBEBS_CMBSZU_B		= NVME_UNIT_B,
	NVME_CMBEBS_CMBSZU_1K		= NVME_UNIT_1K,
	NVME_CMBEBS_CMBSZU_1M		= NVME_UNIT_1M,
	NVME_CMBEBS_CMBSZU_1G		= NVME_UNIT_1G,
};

#define NVME_CMBEBS_CMBSZU(cmbebs)	NVME_GET(cmbebs, CMBEBS_CMBSZU)
#define NVME_CMBEBS_RBB(cmbebs)		NVME_GET(cmbebs, CMBEBS_RBB)
#define NVME_CMBEBS_CMBWBZ(cmbebs)	NVME_GET(cmbebs, CMBEBS_CMBWBZ)

/**
 * enum nvme_cmbswtp - This field indicates the controller memory buffer sustained write throughput
 * @NVME_CMBSWTP_CMBSWTU_SHIFT:	Shift amount to get the CMB sustained write throughput units
 * @NVME_CMBSWTP_CMBSWTV_SHIFT:	Shift amount to get the CMB sustained write throughput
 * @NVME_CMBSWTP_CMBSWTU_MASK:	Mask to get the CMB sustained write throughput units
 * @NVME_CMBSWTP_CMBSWTV_MASK:	Mask to get the CMB sustained write throughput
 * @NVME_CMBSWTP_CMBSWTU_B:	Bytes/second granularity
 * @NVME_CMBSWTP_CMBSWTU_1K:	1 KiB/second granularity
 * @NVME_CMBSWTP_CMBSWTU_1M:	1 MiB/second granularity
 * @NVME_CMBSWTP_CMBSWTU_1G:	1 GiB/second granularity
 */
enum nvme_cmbswtp {
	NVME_CMBSWTP_CMBSWTU_SHIFT	= 0,
	NVME_CMBSWTP_CMBSWTV_SHIFT	= 8,
	NVME_CMBSWTP_CMBSWTU_MASK	= 0xf,
	NVME_CMBSWTP_CMBSWTV_MASK	= 0xffffff,
	NVME_CMBSWTP_CMBSWTU_B		= NVME_UNIT_B,
	NVME_CMBSWTP_CMBSWTU_1K		= NVME_UNIT_1K,
	NVME_CMBSWTP_CMBSWTU_1M		= NVME_UNIT_1M,
	NVME_CMBSWTP_CMBSWTU_1G		= NVME_UNIT_1G,
};

#define NVME_CMBSWTP_CMBSWTU(cmbswtp)	NVME_GET(cmbswtp, CMBSWTP_CMBSWTU)
#define NVME_CMBSWTP_CMBSWTV(cmbswtp)	NVME_GET(cmbswtp, CMBSWTP_CMBSWTV)

/**
 * enum nvme_crto - This field indicates the controller ready timeouts
 * @NVME_CRTO_CRWMT_SHIFT:	Shift amount to get the  controller ready with media timeout
 * @NVME_CRTO_CRIMT_SHIFT:	Shift amount to get the controller ready independent of media timeout
 * @NVME_CRTO_CRWMT_MASK:	Mask to get the controller ready with media timeout
 * @NVME_CRTO_CRIMT_MASK:	Mask to get the controller ready independent of media timeout
 */
enum nvme_crto {
	NVME_CRTO_CRWMT_SHIFT	= 0,
	NVME_CRTO_CRIMT_SHIFT	= 16,
	NVME_CRTO_CRWMT_MASK	= 0xffff,
	NVME_CRTO_CRIMT_MASK	= 0xffff,
};

#define NVME_CRTO_CRIMT(crto)	NVME_GET(crto, CRTO_CRIMT)
#define NVME_CRTO_CRWMT(crto)	NVME_GET(crto, CRTO_CRWMT)

/**
 * enum nvme_pmrcap - This field indicates the persistent memory region capabilities
 * @NVME_PMRCAP_RDS_SHIFT:	Shift amount to get the read data support
 * @NVME_PMRCAP_WDS_SHIFT:	Shift amount to get the write data support
 * @NVME_PMRCAP_BIR_SHIFT:	Shift amount to get the base indicator register
 * @NVME_PMRCAP_PMRTU_SHIFT:	Shift amount to get the persistent memory region time units
 * @NVME_PMRCAP_PMRWBM_SHIFT:	Shift amount to get the persistent memory region write barrier mechanisms
 * @NVME_PMRCAP_PMRTO_SHIFT:	Shift amount to get the persistent memory region timeout
 * @NVME_PMRCAP_CMSS_SHIFT:	Shift amount to get the controller memory space supported
 * @NVME_PMRCAP_PMRWMB_SHIFT:	Deprecated shift amount to get the persistent memory region write barrier mechanisms
 * @NVME_PMRCAP_RDS_MASK:	Mask to get the read data support
 * @NVME_PMRCAP_WDS_MASK:	Mask to get the write data support
 * @NVME_PMRCAP_BIR_MASK:	Mask to get the base indicator register
 * @NVME_PMRCAP_PMRTU_MASK:	Mask to get the persistent memory region time units
 * @NVME_PMRCAP_PMRWBM_MASK:	Mask to get the persistent memory region write barrier mechanisms
 * @NVME_PMRCAP_PMRTO_MASK:	Mask to get the persistent memory region timeout
 * @NVME_PMRCAP_CMSS_MASK:	Mask to get the controller memory space supported
 * @NVME_PMRCAP_PMRWMB_MASK:	Deprecated mask to get the persistent memory region write barrier mechanisms
 * @NVME_PMRCAP_PMRTU_500MS:	500 milliseconds
 * @NVME_PMRCAP_PMRTU_60S:	minutes
 */
enum nvme_pmrcap {
	NVME_PMRCAP_RDS_SHIFT		= 3,
	NVME_PMRCAP_WDS_SHIFT		= 4,
	NVME_PMRCAP_BIR_SHIFT		= 5,
	NVME_PMRCAP_PMRTU_SHIFT		= 8,
	NVME_PMRCAP_PMRWBM_SHIFT	= 10,
	NVME_PMRCAP_PMRTO_SHIFT		= 16,
	NVME_PMRCAP_CMSS_SHIFT		= 24,
	NVME_PMRCAP_PMRWMB_SHIFT	= NVME_PMRCAP_PMRWBM_SHIFT, /* Deprecated */
	NVME_PMRCAP_RDS_MASK		= 0x1,
	NVME_PMRCAP_WDS_MASK		= 0x1,
	NVME_PMRCAP_BIR_MASK		= 0x7,
	NVME_PMRCAP_PMRTU_MASK		= 0x3,
	NVME_PMRCAP_PMRWBM_MASK		= 0xf,
	NVME_PMRCAP_PMRTO_MASK		= 0xff,
	NVME_PMRCAP_CMSS_MASK		= 0x1,
	NVME_PMRCAP_PMRWMB_MASK		= NVME_PMRCAP_PMRWBM_MASK, /* Deprecated */
	NVME_PMRCAP_PMRTU_500MS		= 0,
	NVME_PMRCAP_PMRTU_60S		= 1,
};

#define NVME_PMRCAP_RDS(pmrcap)		NVME_GET(pmrcap, PMRCAP_RDS)
#define NVME_PMRCAP_WDS(pmrcap)		NVME_GET(pmrcap, PMRCAP_WDS)
#define NVME_PMRCAP_BIR(pmrcap)		NVME_GET(pmrcap, PMRCAP_BIR)
#define NVME_PMRCAP_PMRTU(pmrcap)	NVME_GET(pmrcap, PMRCAP_PMRTU)
#define NVME_PMRCAP_PMRWBM(pmrcap)	NVME_GET(pmrcap, PMRCAP_PMRWBM)
#define NVME_PMRCAP_PMRTO(pmrcap)	NVME_GET(pmrcap, PMRCAP_PMRTO)
#define NVME_PMRCAP_CMSS(pmrcap)	NVME_GET(pmrcap, PMRCAP_CMSS)
#define NVME_PMRCAP_PMRWMB(pmrcap)	NVME_GET(pmrcap, PMRCAP_PMRWMB) /* Deprecated */

/**
 * enum nvme_pmrctl - This field indicates the persistent memory region control
 * @NVME_PMRCTL_EN_SHIFT:	Shift amount to get the enable
 * @NVME_PMRCTL_EN_MASK:	Mask to get the enable
 */
enum nvme_pmrctl {
	NVME_PMRCTL_EN_SHIFT	= 0,
	NVME_PMRCTL_EN_MASK	= 0x1,
};

#define NVME_PMRCTL_EN(pmrctl)		NVME_GET(pmrctl, PMRCTL_EN)

/**
 * enum nvme_pmrsts - This field indicates the persistent memory region status
 * @NVME_PMRSTS_ERR_SHIFT:	Shift amount to get the error
 * @NVME_PMRSTS_NRDY_SHIFT:	Shift amount to get the not ready
 * @NVME_PMRSTS_HSTS_SHIFT:	Shift amount to get the health status
 * @NVME_PMRSTS_CBAI_SHIFT:	Shift amount to get the controller base address invalid
 * @NVME_PMRSTS_ERR_MASK:	Mask to get the error
 * @NVME_PMRSTS_NRDY_MASK:	Mask to get the not ready
 * @NVME_PMRSTS_HSTS_MASK:	Mask to get the health status
 * @NVME_PMRSTS_CBAI_MASK:	Mask to get the controller base address invalid
 */
enum nvme_pmrsts {
	NVME_PMRSTS_ERR_SHIFT		= 0,
	NVME_PMRSTS_NRDY_SHIFT		= 8,
	NVME_PMRSTS_HSTS_SHIFT		= 9,
	NVME_PMRSTS_CBAI_SHIFT		= 12,
	NVME_PMRSTS_ERR_MASK		= 0xff,
	NVME_PMRSTS_NRDY_MASK		= 0x1,
	NVME_PMRSTS_HSTS_MASK		= 0x7,
	NVME_PMRSTS_CBAI_MASK		= 0x1,
};

#define NVME_PMRSTS_ERR(pmrsts)		NVME_GET(pmrsts, PMRSTS_ERR)
#define NVME_PMRSTS_NRDY(pmrsts)	NVME_GET(pmrsts, PMRSTS_NRDY)
#define NVME_PMRSTS_HSTS(pmrsts)	NVME_GET(pmrsts, PMRSTS_HSTS)
#define NVME_PMRSTS_CBAI(pmrsts)	NVME_GET(pmrsts, PMRSTS_CBAI)

/**
 * enum nvme_pmrebs - This field indicates the persistent memory region elasticity buffer size
 * @NVME_PMREBS_PMRSZU_SHIFT:	Shift amount to get the PMR elasticity buffer size units
 * @NVME_PMREBS_RBB_SHIFT:	Shift amount to get the read bypass behavior
 * @NVME_PMREBS_PMRWBZ_SHIFT:	Shift amount to get the PMR elasticity buffer size base
 * @NVME_PMREBS_PMRSZU_MASK:	Mask to get the PMR elasticity buffer size units
 * @NVME_PMREBS_RBB_MASK:	Mask to get the read bypass behavior
 * @NVME_PMREBS_PMRWBZ_MASK:	Mask to get the PMR elasticity buffer size base
 * @NVME_PMREBS_PMRSZU_B:	Bytes
 * @NVME_PMREBS_PMRSZU_1K:	1 KiB
 * @NVME_PMREBS_PMRSZU_1M:	1 MiB
 * @NVME_PMREBS_PMRSZU_1G:	1 GiB
 */
enum nvme_pmrebs {
	NVME_PMREBS_PMRSZU_SHIFT	= 0,
	NVME_PMREBS_RBB_SHIFT		= 4,
	NVME_PMREBS_PMRWBZ_SHIFT	= 8,
	NVME_PMREBS_PMRSZU_MASK		= 0xf,
	NVME_PMREBS_RBB_MASK		= 0x1,
	NVME_PMREBS_PMRWBZ_MASK		= 0xffffff,
	NVME_PMREBS_PMRSZU_B		= NVME_UNIT_B,
	NVME_PMREBS_PMRSZU_1K		= NVME_UNIT_1K,
	NVME_PMREBS_PMRSZU_1M		= NVME_UNIT_1M,
	NVME_PMREBS_PMRSZU_1G		= NVME_UNIT_1G,
};

#define NVME_PMREBS_PMRSZU(pmrebs)	NVME_GET(pmrebs, PMREBS_PMRSZU)
#define NVME_PMREBS_RBB(pmrebs)		NVME_GET(pmrebs, PMREBS_RBB)
#define NVME_PMREBS_PMRWBZ(pmrebs)	NVME_GET(pmrebs, PMREBS_PMRWBZ)

/**
 * nvme_pmr_size() - Calculate size of persistent memory region elasticity
 *		     buffer
 * @pmrebs:	Value from controller register %NVME_REG_PMREBS
 *
 * Return: size of controller persistent memory buffer in bytes
 */
static inline __u64 nvme_pmr_size(__u32 pmrebs)
{
	return ((__u64)NVME_PMREBS_PMRWBZ(pmrebs)) *
		(1ULL << (10 * NVME_PMREBS_PMRSZU(pmrebs)));
}

/**
 * enum nvme_pmrswtp - This field indicates the persistent memory region sustained write throughput
 * @NVME_PMRSWTP_PMRSWTU_SHIFT:	Shift amount to get the PMR sustained write throughput units
 * @NVME_PMRSWTP_PMRSWTV_SHIFT:	Shift amount to get the PMR sustained write throughput
 * @NVME_PMRSWTP_PMRSWTU_MASK:	Mask to get the PMR sustained write throughput units
 * @NVME_PMRSWTP_PMRSWTV_MASK:	Mask to get the PMR sustained write throughput
 * @NVME_PMRSWTP_PMRSWTU_BPS:	Bytes per second
 * @NVME_PMRSWTP_PMRSWTU_KBPS:	1 KiB / s
 * @NVME_PMRSWTP_PMRSWTU_MBPS:	1 MiB / s
 * @NVME_PMRSWTP_PMRSWTU_GBPS:	1 GiB / s
 */
enum nvme_pmrswtp {
	NVME_PMRSWTP_PMRSWTU_SHIFT	= 0,
	NVME_PMRSWTP_PMRSWTV_SHIFT	= 8,
	NVME_PMRSWTP_PMRSWTU_MASK	= 0xf,
	NVME_PMRSWTP_PMRSWTV_MASK	= 0xffffff,
	NVME_PMRSWTP_PMRSWTU_BPS	= NVME_UNIT_B,
	NVME_PMRSWTP_PMRSWTU_KBPS	= NVME_UNIT_1K,
	NVME_PMRSWTP_PMRSWTU_MBPS	= NVME_UNIT_1M,
	NVME_PMRSWTP_PMRSWTU_GBPS	= NVME_UNIT_1G,
};

#define NVME_PMRSWTP_PMRSWTU(pmrswtp)	NVME_GET(pmrswtp, PMRSWTP_PMRSWTU)
#define NVME_PMRSWTP_PMRSWTV(pmrswtp)	NVME_GET(pmrswtp, PMRSWTP_PMRSWTU)

/**
 * nvme_pmr_throughput() - Calculate throughput of persistent memory buffer
 * @pmrswtp:	Value from controller register %NVME_REG_PMRSWTP
 *
 * Return: throughput of controller persistent memory buffer in bytes/second
 */
static inline __u64 nvme_pmr_throughput(__u32 pmrswtp)
{
	return ((__u64)NVME_PMRSWTP_PMRSWTV(pmrswtp)) *
		(1ULL << (10 * NVME_PMRSWTP_PMRSWTU(pmrswtp)));
}

/**
 * enum nvme_pmrmsc - This field indicates the persistent memory region memory space control
 * @NVME_PMRMSC_CMSE_SHIFT:	Shift amount to get the controller memory space enable
 * @NVME_PMRMSC_CBA_SHIFT:	Shift amount to get the controller base address
 * @NVME_PMRMSC_CMSE_MASK:	Mask to get the controller memory space enable
 */
enum nvme_pmrmsc {
	NVME_PMRMSC_CMSE_SHIFT	= 1,
	NVME_PMRMSC_CBA_SHIFT	= 12,
	NVME_PMRMSC_CMSE_MASK	= 0x1,
};
static const __u64 NVME_PMRMSC_CBA_MASK = 0xfffffffffffffull;

#define NVME_PMRMSC_CMSE(pmrmsc)	NVME_GET(pmrmsc, PMRMSC_CMSE)
#define NVME_PMRMSC_CBA(pmrmsc)		NVME_GET(pmrmsc, PMRMSC_CBA)

/**
 * enum nvme_flbas - This field indicates the formatted LBA size
 * @NVME_FLBAS_LOWER_SHIFT:	Shift amount to get the format index least significant 4 bits
 * @NVME_FLBAS_META_EXT_SHIFT:	Shift amount to get the metadata transferred
 * @NVME_FLBAS_HIGHER_SHIFT:	Shift amount to get the format index most significant 2 bits
 * @NVME_FLBAS_LOWER_MASK:	Mask to get the format index least significant 4 bits
 * @NVME_FLBAS_META_EXT_MASK:	Mask to get the metadata transferred
 * @NVME_FLBAS_HIGHER_MASK:	Mask to get the format index most significant 2 bits
 */
enum nvme_flbas {
	NVME_FLBAS_LOWER_SHIFT		= 0,
	NVME_FLBAS_META_EXT_SHIFT	= 4,
	NVME_FLBAS_HIGHER_SHIFT		= 5,
	NVME_FLBAS_LOWER_MASK		= 0xf,
	NVME_FLBAS_META_EXT_MASK	= 0x1,
	NVME_FLBAS_HIGHER_MASK		= 0x3,
};

#define NVME_FLBAS_LOWER(flbas)		NVME_GET(flbas, FLBAS_LOWER)
#define NVME_FLBAS_META_EXT(flbas)	NVME_GET(flbas, FLBAS_META_EXT)
#define NVME_FLBAS_HIGHER(flbas)	NVME_GET(flbas, FLBAS_HIGHER)

/**
 * enum nvme_psd_flags - Possible flag values in nvme power state descriptor
 * @NVME_PSD_FLAGS_MXPS: Indicates the scale for the Maximum Power
 *			 field. If this bit is cleared, then the scale of the
 *			 Maximum Power field is in 0.01 Watts. If this bit is
 *			 set, then the scale of the Maximum Power field is in
 *			 0.0001 Watts.
 * @NVME_PSD_FLAGS_NOPS: Indicates whether the controller processes I/O
 *			 commands in this power state. If this bit is cleared,
 *			 then the controller processes I/O commands in this
 *			 power state. If this bit is set, then the controller
 *			 does not process I/O commands in this power state.
 */
enum nvme_psd_flags {
	NVME_PSD_FLAGS_MXPS		= 1 << 0,
	NVME_PSD_FLAGS_NOPS		= 1 << 1,
};

/**
 * enum nvme_psd_ps - Known values for &struct nvme_psd %ips and %aps. Use with
 *		      nvme_psd_power_scale() to extract the power scale field
 *		      to match this enum.
 * @NVME_PSD_PS_NOT_REPORTED:	Not reported
 * @NVME_PSD_PS_100_MICRO_WATT: 0.0001 watt scale
 * @NVME_PSD_PS_10_MILLI_WATT:	0.01 watt scale
 */
enum nvme_psd_ps {
	NVME_PSD_PS_NOT_REPORTED	= 0,
	NVME_PSD_PS_100_MICRO_WATT	= 1,
	NVME_PSD_PS_10_MILLI_WATT	= 2,
};

/**
 * enum nvme_power_measurement_type - Power measurement types.
 * @NVME_PMT_NSS_TOTAL_POWER: NVM subsystem total power
 * @NVME_PMT_RSVD_MIN:	      Reserved minimum value
 * @NVME_PMT_RSVD_MAX:	      Reserved maximum value
 * @NVME_PMT_VS_MIN:	      Vendor Specific minimum value
 * @NVME_PMT_VS_MAX:	      Vendor Specific maximum value
 */
enum nvme_power_measurement_type {
	NVME_PMT_NSS_TOTAL_POWER = 0x0,
	NVME_PMT_RSVD_MIN	 = 0x1,
	NVME_PMT_RSVD_MAX	 = 0xb,
	NVME_PMT_VS_MIN		 = 0xc,
	NVME_PMT_VS_MAX		 = 0xf,
};

/**
 * enum nvme_power_measurement_action - Power measurement actions.
 * @NVME_PMA_STOP:  Stop power measurement
 * @NVME_PMA_START: Start power measurement
 */
enum nvme_power_measurement_action {
	NVME_PMA_STOP	= 0x0,
	NVME_PMA_START	= 0x1,
};

/**
 * nvme_psd_power_scale() - power scale occupies the upper 3 bits
 * @ps: power scale value
 *
 * Return: power scale value
 */
static inline unsigned int nvme_psd_power_scale(__u8 ps)
{
	return ps >> 6;
}

/**
 * enum nvme_psd_workload - Specifies a workload hint in the Power Management
 *			    Feature (see &struct nvme_psd.apw) to inform the
 *			    NVM subsystem or indicate the conditions for the
 *			    active power level.
 * @NVME_PSD_WORKLOAD_NP: The workload is unknown or not provided.
 * @NVME_PSD_WORKLOAD_1: Extended Idle Period with a Burst of Random Write
 *			 consists of five minutes of idle followed by
 *			 thirty-two random write commands of size 1 MiB
 *			 submitted to a single controller while all other
 *			 controllers in the NVM subsystem are idle, and then
 *			 thirty (30) seconds of idle.
 * @NVME_PSD_WORKLOAD_2: Heavy Sequential Writes consists of 80,000
 *			 sequential write commands of size 128 KiB submitted to
 *			 a single controller while all other controllers in the
 *			 NVM subsystem are idle.  The submission queue(s)
 *			 should be sufficiently large allowing the host to
 *			 ensure there are multiple commands pending at all
 *			 times during the workload.
 */
enum nvme_psd_workload {
	NVME_PSD_WORKLOAD_NP	= 0,
	NVME_PSD_WORKLOAD_1	= 1,
	NVME_PSD_WORKLOAD_2	= 2,
};

/**
 * struct nvme_id_psd - Power Management data structure
 * @mp:	   Maximum Power indicates the sustained maximum power consumed by the
 *	   NVM subsystem in this power state. The power in Watts is equal to
 *	   the value in this field multiplied by the scale specified in the Max
 *	   Power Scale bit (see &enum nvme_psd_flags). A value of 0 indicates
 *	   Maximum Power is not reported.
 * @rsvd2: Reserved
 * @flags: Additional decoding flags, see &enum nvme_psd_flags.
 * @enlat: Entry Latency indicates the maximum latency in microseconds
 *	   associated with entering this power state. A value of 0 indicates
 *	   Entry Latency is not reported.
 * @exlat: Exit Latency indicates the maximum latency in microseconds
 *	   associated with exiting this power state. A value of 0 indicates
 *	   Exit Latency is not reported.
 * @rrt:   Relative Read Throughput indicates the read throughput rank
 *	   associated with this power state relative to others. The value in
 *	   this is less than the number of supported power states.
 * @rrl:   Relative Read Latency indicates the read latency rank associated
 *	   with this power state relative to others. The value in this field is
 *	   less than the number of supported power states.
 * @rwt:   Relative Write Throughput indicates write throughput rank associated
 *	   with this power state relative to others. The value in this field is
 *	   less than the number of supported power states
 * @rwl:   Relative Write Latency indicates the write latency rank associated
 *	   with this power state relative to others. The value in this field is
 *	   less than the number of supported power states
 * @idlp:  Idle Power indicates the typical power consumed by the NVM
 *	   subsystem over 30 seconds in this power state when idle.
 * @ips:   Idle Power Scale indicates the scale for &struct nvme_id_psd.idlp,
 *	   see &enum nvme_psd_ps for decoding this field.
 * @rsvd19: Reserved
 * @actp:  Active Power indicates the largest average power consumed by the
 *	   NVM subsystem over a 10 second period in this power state with
 *	   the workload indicated in the Active Power Workload field.
 * @apws:  Bits 7-6: Active Power Scale(APS) indicates the scale for the &struct
 *	   nvme_id_psd.actp, see &enum nvme_psd_ps for decoding this value.
 *	   Bits 2-0: Active Power Workload(APW) indicates the workload
 *	   used to calculate maximum power for this power state.
 *	   See &enum nvme_psd_workload for decoding this field.
 * @epfrt: Emergency power fail recovery time
 * @fqvt:  Forced quiescence vault time
 * @epfvt: Emergency power fail vault time
 * @epfr_fqv_ts: Bits 7-4: Forced quiescence vault time scale
 *		 Bits 3-0: Emergency power fail recovery time scale
 * @epfvts: Bits 3-0: Emergency power fail vault time scale
 * @rsvd28: Reserved
 * @miiell: Minimum Idle I/O Exit Latency Limit: if the Idle I/O Exit Latency
 *	    Limit capability is supported (see &enum
 *	    nvme_id_ctrl_ctratt.NVME_CTRL_CTRATT_IIELLSS) for this operational
 *	    power state, a non-zero value indicates the minimum supported
 *	    Idle I/O Exit Latency Limit in units of 100 microseconds, and a
 *	    value of 0h indicates there is no minimum. Cleared to 0h for a
 *	    non-operational power state or if the capability is not
 *	    supported.
 */
struct nvme_id_psd {
	__le16			mp;
	__u8			rsvd2;
	__u8			flags;
	__le32			enlat;
	__le32			exlat;
	__u8			rrt;
	__u8			rrl;
	__u8			rwt;
	__u8			rwl;
	__le16			idlp;
	__u8			ips;
	__u8			rsvd19;
	__le16			actp;
	__u8			apws;
	__u8			epfrt;
	__u8			fqvt;
	__u8			epfvt;
	__u8			epfr_fqv_ts;
	__u8			epfvts;
	__u8			rsvd28[2];
	__le16			miiell;
};

/**
 * struct nvme_id_ctrl - Identify Controller data structure
 * @vid:       PCI Vendor ID, the company vendor identifier that is assigned by
 *	       the PCI SIG.
 * @ssvid:     PCI Subsystem Vendor ID, the company vendor identifier that is
 *	       assigned by the PCI SIG for the subsystem.
 * @sn:	       Serial Number in ASCII
 * @mn:	       Model Number in ASCII
 * @fr:	       Firmware Revision in ASCII, the currently active firmware
 *	       revision for the NVM subsystem
 * @rab:       Recommended Arbitration Burst, reported as a power of two
 * @ieee:      IEEE assigned Organization Unique Identifier
 * @cmic:      Controller Multipath IO and Namespace Sharing  Capabilities of
 *	       the controller and NVM subsystem. See &enum nvme_id_ctrl_cmic.
 * @mdts:      Max Data Transfer Size is the largest data transfer size. The
 *	       host should not submit a command that exceeds this maximum data
 *	       transfer size. The value is in units of the minimum memory page
 *	       size (CAP.MPSMIN) and is reported as a power of two
 * @cntlid:    Controller ID, the NVM subsystem unique controller identifier
 *	       associated with the controller.
 * @ver:       Version, this field contains the value reported in the Version
 *	       register, or property (see &enum nvme_registers %NVME_REG_VS).
 * @rtd3r:     RTD3 Resume Latency, the expected latency in microseconds to resume
 *	       from Runtime D3
 * @rtd3e:     RTD3 Exit Latency, the typical latency in microseconds to enter
 *	       Runtime D3.
 * @oaes:      Optional Async Events Supported, see @enum nvme_id_ctrl_oaes.
 * @ctratt:    Controller Attributes, see @enum nvme_id_ctrl_ctratt.
 * @rrls:      Read Recovery Levels. If a bit is set, then the corresponding
 *	       Read Recovery Level is supported. If a bit is cleared, then the
 *	       corresponding Read Recovery Level is not supported.
 * @bpcap:     Boot Partition Capabilities, see &enum nvme_id_ctrl_bpcap.
 * @chsi:      CXL HDM Support Information, see &enum nvme_id_ctrl_chsi.
 * @nssl:      NVM Subsystem Shutdown Latency (NSSL). This field indicates the
 *	       typical latency in microseconds for an NVM Subsystem Shutdown to
 *	       complete.
 * @rsvd108:   Reserved
 * @plsi:      Power Loss Signaling Information (PLSI), see &enum nvme_id_ctrl_plsi
 * @cntrltype: Controller Type, see &enum nvme_id_ctrl_cntrltype
 * @fguid:     FRU GUID, a 128-bit value that is globally unique for a given
 *	       Field Replaceable Unit
 * @crdt1:     Controller Retry Delay time in 100 millisecond units if CQE CRD
 *	       field is 1
 * @crdt2:     Controller Retry Delay time in 100 millisecond units if CQE CRD
 *	       field is 2
 * @crdt3:     Controller Retry Delay time in 100 millisecond units if CQE CRD
 *	       field is 3
 * @crcap:     Controller Reachability Capabilities (CRCAP), see
 *	       &enum nvme_id_ctrl_crcap
 * @ciu:       Controller Instance Uniquifier (CIU)
 * @cirn:      Controller Instance Random Number (CIRN)
 * @rsvd144:   Reserved
 * @rsvd240:   Reserved for the NVMe Management Interface specification
 * @nvmsr:     NVM Subsystem Report, see &enum nvme_id_ctrl_nvmsr
 * @vwci:      VPD Write Cycle Information, see &enum nvme_id_ctrl_vwci
 * @mec:       Management Endpoint Capabilities, see &enum nvme_id_ctrl_mec
 * @oacs:      Optional Admin Command Support,the optional Admin commands and
 *	       features supported by the controller, see &enum nvme_id_ctrl_oacs.
 * @acl:       Abort Command Limit, the maximum number of concurrently
 *	       executing Abort commands supported by the controller. This is a
 *	       0's based value.
 * @aerl:      Async Event Request Limit, the maximum number of concurrently
 *	       outstanding Asynchronous Event Request commands supported by the
 *	       controller This is a 0's based value.
 * @frmw:      Firmware Updates indicates capabilities regarding firmware
 *	       updates. See &enum nvme_id_ctrl_frmw.
 * @lpa:       Log Page Attributes, see &enum nvme_id_ctrl_lpa.
 * @elpe:      Error Log Page Entries, the maximum number of Error Information
 *	       log entries that are stored by the controller. This field is a
 *	       0's based value.
 * @npss:      Number of Power States Supported, the number of NVM Express
 *	       power states supported by the controller, indicating the number
 *	       of valid entries in &struct nvme_id_ctrl.psd. This is a 0's
 *	       based value.
 * @avscc:     Admin Vendor Specific Command Configuration, see
 *	       &enum nvme_id_ctrl_avscc.
 * @apsta:     Autonomous Power State Transition Attributes, see
 *	       &enum nvme_id_ctrl_apsta.
 * @wctemp:    Warning Composite Temperature Threshold indicates
 *	       the minimum Composite Temperature field value (see &struct
 *	       nvme_smart_log.critical_comp_time) that indicates an overheating
 *	       condition during which controller operation continues.
 * @cctemp:    Critical Composite Temperature Threshold, field indicates the
 *	       minimum Composite Temperature field value (see &struct
 *	       nvme_smart_log.critical_comp_time) that indicates a critical
 *	       overheating condition.
 * @mtfa:      Maximum Time for Firmware Activation indicates the maximum time
 *	       the controller temporarily stops processing commands to activate
 *	       the firmware image, specified in 100 millisecond units. This
 *	       field is always valid if the controller supports firmware
 *	       activation without a reset.
 * @hmpre:     Host Memory Buffer Preferred Size indicates the preferred size
 *	       that the host is requested to allocate for the Host Memory
 *	       Buffer feature in 4 KiB units.
 * @hmmin:     Host Memory Buffer Minimum Size indicates the minimum size that
 *	       the host is requested to allocate for the Host Memory Buffer
 *	       feature in 4 KiB units.
 * @tnvmcap:   Total NVM Capacity, the total NVM capacity in the NVM subsystem.
 *	       The value is in bytes.
 * @unvmcap:   Unallocated NVM Capacity, the unallocated NVM capacity in the
 *	       NVM subsystem. The value is in bytes.
 * @rpmbs:	Replay Protected Memory Block Support, see
 *	       &enum nvme_id_ctrl_rpmbs.
 * @edstt:	Extended Device Self-test Time, if Device Self-test command is
 *	       supported (see &struct nvme_id_ctrl.oacs, %NVME_CTRL_OACS_SELF_TEST),
 *	       then this field indicates the nominal amount of time in one
 *	       minute units that the controller takes to complete an extended
 *	       device self-test operation when in power state 0.
 * @dsto:      Device Self-test Options, see &enum nvme_id_ctrl_dsto.
 * @fwug:      Firmware Update Granularity indicates the granularity and
 *	       alignment requirement of the firmware image being updated by the
 *	       Firmware Image Download command. The value is reported in 4 KiB
 *	       units. A value of 0h indicates no information on granularity is
 *	       provided. A value of FFh indicates no restriction
 * @kas:       Keep Alive Support indicates the granularity of the Keep Alive
 *	       Timer in 100 millisecond units.
 * @hctma:     Host Controlled Thermal Management Attributes, see
 *	       &enum nvme_id_ctrl_hctm.
 * @mntmt:     Minimum Thermal Management Temperature indicates the minimum
 *	       temperature, in degrees Kelvin, that the host may request in the
 *	       Thermal Management Temperature 1 field and Thermal Management
 *	       Temperature 2 field of a Set Features command with the Feature
 *	       Identifier field set to %NVME_FEAT_FID_HCTM.
 * @mxtmt:     Maximum Thermal Management Temperature indicates the maximum
 *	       temperature, in degrees Kelvin, that the host may request in the
 *	       Thermal Management Temperature 1 field and Thermal Management
 *	       Temperature 2 field of the Set Features command with the Feature
 *	       Identifier set to %NVME_FEAT_FID_HCTM.
 * @sanicap:   Sanitize Capabilities, see &enum nvme_id_ctrl_sanicap
 * @hmminds:   Host Memory Buffer Minimum Descriptor Entry Size indicates the
 *	       minimum usable size of a Host Memory Buffer Descriptor Entry in
 *	       4 KiB units.
 * @hmmaxd:    Host Memory Maximum Descriptors Entries indicates the number of
 *	       usable Host Memory Buffer Descriptor Entries.
 * @nsetidmax: NVM Set Identifier Maximum, defines the maximum value of a valid
 *	       NVM Set Identifier for any controller in the NVM subsystem.
 * @endgidmax: Endurance Group Identifier Maximum, defines the maximum value of
 *	       a valid Endurance Group Identifier for any controller in the NVM
 *	       subsystem.
 * @anatt:     ANA Transition Time indicates the maximum amount of time, in
 *	       seconds, for a transition between ANA states or the maximum
 *	       amount of time, in seconds, that the controller reports the ANA
 *	       change state.
 * @anacap:    Asymmetric Namespace Access Capabilities, see
 *	       &enum nvme_id_ctrl_anacap.
 * @anagrpmax: ANA Group Identifier Maximum indicates the maximum value of a
 *	       valid ANA Group Identifier for any controller in the NVM
 *	       subsystem.
 * @nanagrpid: Number of ANA Group Identifiers indicates the number of ANA
 *	       groups supported by this controller.
 * @pels:      Persistent Event Log Size indicates the maximum reportable size
 *	       for the Persistent Event Log.
 * @domainid:  Domain Identifier indicates the identifier of the domain
 *	       that contains this controller.
 * @kpioc:     Key Per I/O Capabilities (KPIOC), see &enum nvme_id_ctrl_kpioc
 * @rsvd359:   Reserved
 * @mptfawr:   Maximum Processing Time for Firmware Activation Without Reset
 *	       (MPTFAWR). This field shall indicate the estimated maximum time
 *	       in 100 ms units required by the controller to process a Firmware
 *	       Commit command that specifies a value of 011b in the Commit
 *	       Action field
 * @rmdca:     Restore Manufacturing Configuration Attributes, see &enum
 *	       nvme_id_ctrl_rmdca
 * @rsvd363:   Reserved
 * @megcap:    Max Endurance Group Capacity indicates the maximum capacity
 *	       of a single Endurance Group.
 * @tmpthha:   Temperature Threshold Hysteresis Attributes
 * @rsvd385:   Reserved
 * @cqt:       Command Quiesce Time (CQT). This field indicates the expected
 *	       worst-case time in 1 millisecond units for the controller to
 *	       quiesce all outstanding commands after a Keep Alive Timeout or
 *	       other communication loss.
 * @cdpa:      Configurable Device Personality Attributes: This field
 *         indicates the Configurable Device Personality feature attributes
 *         the controller supports.
 * @mup:       Maximum Unlimited Power: This field specifies the maximum
 *         power for power state 0 that results from removal of a power
 *         limit (i.e., the maximum power is not limited).
 * @ipmsr:     Interval Power Measurement Sample Rate: This field
 *         indicates the maximum interval between power measurement
 *         samples used to collect interval power measurements.
 * @msmt:      Maximum Stop Measurement Time: This field indicates the
 *         maximum stop measurement time allowed to be specified in the
 *         SMT field for a Set Features command specifying the Power
 *         Measurement feature.
 * @rsvd396:   Reserved
 * @vsen1:     Voltage Sensor 1: indicates the characteristics of Voltage
 *         Sensor 1, see &struct nvme_id_ctrl_vsds. A value of 0h indicates
 *         Voltage Sensor 1 is not supported.
 * @vsen2:     Voltage Sensor 2, see &struct nvme_id_ctrl_vsds. A value of
 *         0h indicates Voltage Sensor 2 is not supported.
 * @vsen3:     Voltage Sensor 3, see &struct nvme_id_ctrl_vsds. A value of
 *         0h indicates Voltage Sensor 3 is not supported.
 * @vsen4:     Voltage Sensor 4, see &struct nvme_id_ctrl_vsds. A value of
 *         0h indicates Voltage Sensor 4 is not supported.
 * @msvmt:     Maximum Stop Voltage Measurement Time: This field indicates
 *         the maximum stop measurement time in minutes allowed to be
 *         specified in the SVMT field for a Set Features command
 *         specifying the Voltage Measurement feature. A value of 0h
 *         indicates that a maximum stop measurement time is not reported.
 * @rsvd424:   Reserved
 * @sqes:      Submission Queue Entry Size, see &enum nvme_id_ctrl_sqes.
 * @cqes:      Completion Queue Entry Size, see &enum nvme_id_ctrl_cqes.
 * @maxcmd:    Maximum Outstanding Commands indicates the maximum number of
 *	       commands that the controller processes at one time for a
 *	       particular queue.
 * @nn:	       Number of Namespaces indicates the maximum value of a valid
 *	       nsid for the NVM subsystem. If the MNAN (&struct nvme_id_ctrl.mnan
 *	       field is cleared to 0h, then this field also indicates the
 *	       maximum number of namespaces supported by the NVM subsystem.
 * @oncs:      Optional NVM Command Support, see &enum nvme_id_ctrl_oncs.
 * @fuses:     Fused Operation Support, see &enum nvme_id_ctrl_fuses.
 * @fna:       Format NVM Attributes, see &enum nvme_id_ctrl_fna.
 * @vwc:       Volatile Write Cache, see &enum nvme_id_ctrl_vwc.
 * @awun:      Atomic Write Unit Normal indicates the size of the write
 *	       operation guaranteed to be written atomically to the NVM across
 *	       all namespaces with any supported namespace format during normal
 *	       operation. This field is specified in logical blocks and is a
 *	       0's based value.
 * @awupf:     Atomic Write Unit Power Fail indicates the size of the write
 *	       operation guaranteed to be written atomically to the NVM across
 *	       all namespaces with any supported namespace format during a
 *	       power fail or error condition. This field is specified in
 *	       logical blocks and is a 0’s based value.
 * @icsvscc:   NVM Vendor Specific Command Configuration, see
 *	       &enum nvme_id_ctrl_nvscc.
 * @nwpc:      Namespace Write Protection Capabilities, see
 *	       &enum nvme_id_ctrl_nwpc.
 * @acwu:      Atomic Compare & Write Unit indicates the size of the write
 *	       operation guaranteed to be written atomically to the NVM across
 *	       all namespaces with any supported namespace format for a Compare
 *	       and Write fused operation. This field is specified in logical
 *	       blocks and is a 0’s based value.
 * @ocfs:      Optional Copy Formats Supported, each bit n means controller
 *	       supports Copy Format n.
 * @sgls:      SGL Support, see &enum nvme_id_ctrl_sgls
 * @mnan:      Maximum Number of Allowed Namespaces indicates the maximum
 *	       number of namespaces supported by the NVM subsystem.
 * @maxdna:    Maximum Domain Namespace Attachments indicates the maximum
 *	       of the sum of the number of namespaces attached to each I/O
 *	       controller in the Domain.
 * @maxcna:    Maximum I/O Controller Namespace Attachments indicates the
 *	       maximum number of namespaces that are allowed to be attached to
 *	       this I/O controller.
 * @oaqd:      Optimal Aggregated Queue Depth indicates the recommended maximum
 *	       total number of outstanding I/O commands across all I/O queues
 *	       on the controller for optimal operation.
 * @rhiri:     Recommended Host-Initiated Refresh Interval (RHIRI). If the
 *	       Host-Initiated Refresh capability is supported, then this field
 *	       indicates the recommended time interval in days from last power
 *	       down to the time at which the host should initiate the
 *	       Host-Initiated Refresh operation. If this field is cleared to
 *	       0h, then this field is not reported.
 * @hirt:      Host-Initiated Refresh Time (HIRT). If the Host-Initiated
 *	       Refresh capability is supported, then this field indicates the
 *	       nominal amount of time in minutes that the controller takes to
 *	       complete the Host-Initiated Refresh operation. If this field is
 *	       cleared to 0h, then this field is not reported.
 * @cmmrtd:    Controller Maximum Memory Range Tracking Descriptors indicates
 *             the maximum number of Memory Range Tracking Descriptors the
 *             controller supports.
 * @nmmrtd:    NVM Subsystem Maximum Memory Range Tracking Descriptors
 *             indicates the maximum number of Memory Range Tracking Descriptors
 *             the NVM subsystem supports.
 * @minmrtg:   Minimum Memory Range Tracking Granularity indicates the minimum
 *             value supported in the Requested Memory Range Tracking
 *             Granularity (RMRTG) field of the Track Memory Ranges data
 *             structure.
 * @maxmrtg:   Maximum Memory Range Tracking Granularity indicates the maximum
 *             value supported in the Requested Memory Range Tracking
 *             Granularity (RMRTG) field of the Track Memory Ranges data
 *             structure.
 * @trattr:    Tracking Attributes indicates supported attributes for the Track Send
 *             command and Track Receive command. see &enum nvme_id_ctrl_trattr
 * @rsvd577:   Reserved
 * @mcudmq:    Maximum Controller User Data Migration Queues indicates the
 *             maximum number of User Data Migration Queues supported by the
 *             controller.
 * @mnsudmq:   Maximum NVM Subsystem User Data Migration Queues indicates the
 *             maximum number of User Data Migration Queues supported by the NVM
 *             subsystem.
 * @mcmr:      Maximum CDQ Memory Ranges indicates the maximum number of
 *             memory ranges allowed to be specified by the PRP1 field of a
 *             Controller Data Queue command.
 * @nmcmr:     NVM Subsystem Maximum CDQ Memory Ranges indicates the maximum
 *             number of memory ranges for all Controller Data Queues in the
 *             NVM subsystem.
 * @mcdqpc:    Maximum Controller Data Queue PRP Count indicates the maximum
 *             number of PRPs allowed to be specified in the PRP list in the
 *             Controller Data Queue command.
 * @rsvd588:   Reserved
 * @subnqn:    NVM Subsystem NVMe Qualified Name, UTF-8 null terminated string
 * @rsvd1024:  Reserved
 * @ioccsz:    I/O Queue Command Capsule Supported Size, defines the maximum
 *	       I/O command capsule size in 16 byte units.
 * @iorcsz:    I/O Queue Response Capsule Supported Size, defines the maximum
 *	       I/O response capsule size in 16 byte units.
 * @icdoff:    In Capsule Data Offset, defines the offset where data starts
 *	       within a capsule. This value is applicable to I/O Queues only.
 * @fcatt:     Fabrics Controller Attributes, see &enum nvme_id_ctrl_fcatt.
 * @msdbd:     Maximum SGL Data Block Descriptors indicates the maximum
 *	       number of SGL Data Block or Keyed SGL Data Block descriptors
 *	       that a host is allowed to place in a capsule. A value of 0h
 *	       indicates no limit.
 * @ofcs:      Optional Fabric Commands Support, see &enum nvme_id_ctrl_ofcs.
 * @dctype:    Discovery Controller Type (DCTYPE). This field indicates what
 *	       type of Discovery controller the controller is (see enum
 *	       nvme_id_ctrl_dctype)
 * @ccrl:      Cross-Controller Reset Limit: This field indicates the limit
 *         on the number of simultaneous in-progress Cross-Controller Reset
 *         operations this controller is able to cause to be initiated that
 *         are supported.
 * @rsvd1808:  Reserved
 * @psd:       Power State Descriptors, see &struct nvme_id_psd.
 * @vs:	       Vendor Specific
 */
struct nvme_id_ctrl {
	__le16			vid;
	__le16			ssvid;
	char			sn[20];
	char			mn[40];
	char			fr[8];
	__u8			rab;
	__u8			ieee[3];
	__u8			cmic;
	__u8			mdts;
	__le16			cntlid;
	__le32			ver;
	__le32			rtd3r;
	__le32			rtd3e;
	__le32			oaes;
	__le32			ctratt;
	__le16			rrls;
	__u8			bpcap;
	__u8			chsi;
	__le32			nssl;
	__u8			rsvd108[2];
	__u8			plsi;
	__u8			cntrltype;
	__u8			fguid[16];
	__le16			crdt1;
	__le16			crdt2;
	__le16			crdt3;
	__u8			crcap;
	__u8			ciu;
	__u8			cirn[8];
	__u8			rsvd144[96];
	__u8			rsvd240[13];
	__u8			nvmsr;
	__u8			vwci;
	__u8			mec;
	__le16			oacs;
	__u8			acl;
	__u8			aerl;
	__u8			frmw;
	__u8			lpa;
	__u8			elpe;
	__u8			npss;
	__u8			avscc;
	__u8			apsta;
	__le16			wctemp;
	__le16			cctemp;
	__le16			mtfa;
	__le32			hmpre;
	__le32			hmmin;
	__u8			tnvmcap[16];
	__u8			unvmcap[16];
	__le32			rpmbs;
	__le16			edstt;
	__u8			dsto;
	__u8			fwug;
	__le16			kas;
	__le16			hctma;
	__le16			mntmt;
	__le16			mxtmt;
	__le32			sanicap;
	__le32			hmminds;
	__le16			hmmaxd;
	__le16			nsetidmax;
	__le16			endgidmax;
	__u8			anatt;
	__u8			anacap;
	__le32			anagrpmax;
	__le32			nanagrpid;
	__le32			pels;
	__le16			domainid;
	__u8			kpioc;
	__u8			rsvd359;
	__le16			mptfawr;
	__u8			rmdca;
	__u8			rsvd363[5];
	__u8			megcap[16];
	__u8			tmpthha;
	__u8			rsvd385;
	__le16			cqt;
	__le16			cdpa;
	__le16			mup;
	__le16			ipmsr;
	__le16			msmt;
	__u8			rsvd396[10];
	__le32			vsen1 __attribute__((packed));
	__le32			vsen2 __attribute__((packed));
	__le32			vsen3 __attribute__((packed));
	__le32			vsen4 __attribute__((packed));
	__le16			msvmt;
	__u8			rsvd424[88];
	__u8			sqes;
	__u8			cqes;
	__le16			maxcmd;
	__le32			nn;
	__le16			oncs;
	__le16			fuses;
	__u8			fna;
	__u8			vwc;
	__le16			awun;
	__le16			awupf;
	__u8			icsvscc;
	__u8			nwpc;
	__le16			acwu;
	__le16			ocfs;
	__le32			sgls;
	__le32			mnan;
	__u8			maxdna[16];
	__le32			maxcna;
	__le32			oaqd;
	__u8			rhiri;
	__u8			hirt;
	__le16			cmmrtd;
	__le16			nmmrtd;
	__u8			minmrtg;
	__u8			maxmrtg;
	__u8			trattr;
	__u8			rsvd577;
	__le16			mcudmq;
	__le16			mnsudmq;
	__le16			mcmr;
	__le16			nmcmr;
	__le16			mcdqpc;
	__u8			rsvd588[180];
	char			subnqn[NVME_NQN_LENGTH];
	__u8			rsvd1024[768];

	/* Fabrics Only */
	__le32			ioccsz;
	__le32			iorcsz;
	__le16			icdoff;
	__u8			fcatt;
	__u8			msdbd;
	__le16			ofcs;
	__u8			dctype;
	__u8			ccrl;
	__u8			rsvd1808[240];

	struct nvme_id_psd	psd[32];
	__u8			vs[1024];
};

/**
 * enum nvme_cmic - This field indicates the controller multi-path I/O and NS sharing capabilities
 * @NVME_CMIC_MULTI_PORT_SHIFT:		Shift amount to get the NVM subsystem port
 * @NVME_CMIC_MULTI_CTRL_SHIFT:		Shift amount to get the controllers
 * @NVME_CMIC_MULTI_SRIOV_SHIFT:	Shift amount to get the SR-IOV virtual function
 * @NVME_CMIC_MULTI_ANA_SHIFT:		Shift amount to get the asymmetric namespace access reporting
 * @NVME_CMIC_MULTI_RSVD_SHIFT:		Shift amount to get the reserved
 * @NVME_CMIC_MULTI_PORT_MASK:		Mask to get the NVM subsystem port
 * @NVME_CMIC_MULTI_CTRL_MASK:		Mask to get the controllers
 * @NVME_CMIC_MULTI_SRIOV_MASK:		Mask to get the SR-IOV virtual function
 * @NVME_CMIC_MULTI_ANA_MASK:		Mask to get the asymmetric namespace access reporting
 * @NVME_CMIC_MULTI_RSVD_MASK:		Mask to get the reserved
 */
enum nvme_cmic {
	NVME_CMIC_MULTI_PORT_SHIFT	= 0,
	NVME_CMIC_MULTI_CTRL_SHIFT	= 1,
	NVME_CMIC_MULTI_SRIOV_SHIFT	= 2,
	NVME_CMIC_MULTI_ANA_SHIFT	= 3,
	NVME_CMIC_MULTI_RSVD_SHIFT	= 4,
	NVME_CMIC_MULTI_PORT_MASK	= 0x1,
	NVME_CMIC_MULTI_CTRL_MASK	= 0x1,
	NVME_CMIC_MULTI_SRIOV_MASK	= 0x1,
	NVME_CMIC_MULTI_ANA_MASK	= 0x1,
	NVME_CMIC_MULTI_RSVD_MASK	= 0xf,
};

#define NVME_CMIC_MULTI_PORT(cmic)	NVME_GET(cmic, CMIC_MULTI_PORT)
#define NVME_CMIC_MULTI_CTRL(cmic)	NVME_GET(cmic, CMIC_MULTI_CTRL)
#define NVME_CMIC_MULTI_SRIOV(cmic)	NVME_GET(cmic, CMIC_MULTI_SRIOV)
#define NVME_CMIC_MULTI_ANA(cmic)	NVME_GET(cmic, CMIC_MULTI_ANA)
#define NVME_CMIC_MULTI_RSVD(cmic)	NVME_GET(cmic, CMIC_MULTI_RSVD)

/**
 * enum nvme_id_ctrl_cmic - Controller Multipath IO and Namespace Sharing
 *			    Capabilities of the controller and NVM subsystem.
 * @NVME_CTRL_CMIC_MULTI_PORT:		If set, then the NVM subsystem may contain
 *					more than one NVM subsystem port, otherwise
 *					the NVM subsystem contains only a single
 *					NVM subsystem port.
 * @NVME_CTRL_CMIC_MULTI_CTRL:		If set, then the NVM subsystem may contain
 *					two or more controllers, otherwise the
 *					NVM subsystem contains only a single
 *					controller. An NVM subsystem that contains
 *					multiple controllers may be used by
 *					multiple hosts, or may provide multiple
 *					paths for a single host.
 * @NVME_CTRL_CMIC_MULTI_SRIOV:		If set, then the controller is associated
 *					with an SR-IOV Virtual Function, otherwise
 *					it is associated with a PCI Function
 *					or a Fabrics connection.
 * @NVME_CTRL_CMIC_MULTI_ANA_REPORTING: If set, then the NVM subsystem supports
 *					Asymmetric Namespace Access Reporting.
 */
enum nvme_id_ctrl_cmic {
	NVME_CTRL_CMIC_MULTI_PORT		= 1 << 0,
	NVME_CTRL_CMIC_MULTI_CTRL		= 1 << 1,
	NVME_CTRL_CMIC_MULTI_SRIOV		= 1 << 2,
	NVME_CTRL_CMIC_MULTI_ANA_REPORTING	= 1 << 3,
};

/**
 * enum nvme_id_ctrl_oaes - Optional Asynchronous Events Supported
 * @NVME_CTRL_OAES_NSAN_SHIFT: Shift amount to get the Attached Namespace Attribute Notices event supported
 * @NVME_CTRL_OAES_FA_SHIFT: Shift amount to get the Firmware Activation Notices event supported
 * @NVME_CTRL_OAES_ANA_SHIFT: Shift amount to get the ANA Change Notices supported
 * @NVME_CTRL_OAES_PLEA_SHIFT: Shift amount to get the Predictable Latency Event Aggregate Log
 *                             Change Notices event supported
 * @NVME_CTRL_OAES_LBAS_SHIFT: Shift amount to get the LBA Status Information Notices event
 *                             supported
 * @NVME_CTRL_OAES_EGE_SHIFT: Shift amount to get the Endurance Group Events Aggregate Log Change
 *                            Notices event supported
 * @NVME_CTRL_OAES_NS_SHIFT: Shift amount to get the Normal NVM Subsystem Shutdown event supported
 * @NVME_CTRL_OAES_TTH_SHIFT: Shift amount to get the Temperature Threshold Hysteresis Recovery
 *                            event supported
 * @NVME_CTRL_OAES_RGCNS_SHIFT: Shift amount to get the Reachability Groups Change Notices supported
 * @NVME_CTRL_OAES_ANSAN_SHIFT: Shift amount to get the Allocated Namespace Attribute Notices
 *                              supported
 * @NVME_CTRL_OAES_RLCC_SHIFT: Shift amount to get the Rate Limiting Configuration Change event
 *                             supported
 * @NVME_CTRL_OAES_ZD_SHIFT: Shift amount to get the Zone Descriptor Change Notifications supported
 * @NVME_CTRL_OAES_DL_SHIFT: Shift amount to get the Discover Log Page Change Notifications
 *                           supported
 * @NVME_CTRL_OAES_NSAN_MASK: Mask to get the Attached Namespace Attribute Notices event supported
 * @NVME_CTRL_OAES_FA_MASK: Mask to get the Firmware Activation Notices event supported
 * @NVME_CTRL_OAES_ANA_MASK: Mask to get the ANA Change Notices supported
 * @NVME_CTRL_OAES_PLEA_MASK: Mask to get the Predictable Latency Event Aggregate Log Change Notices
 *                            event supported
 * @NVME_CTRL_OAES_LBAS_MASK: Mask to get the LBA Status Information Notices event supported
 * @NVME_CTRL_OAES_EGE_MASK: Mask to get the Endurance Group Events Aggregate Log Change Notices
 *                           event supported
 * @NVME_CTRL_OAES_NS_MASK: Mask to get the Normal NVM Subsystem Shutdown event supported
 * @NVME_CTRL_OAES_TTH_MASK: Mask to get the Temperature Threshold Hysteresis Recovery event
 *                           supported
 * @NVME_CTRL_OAES_RGCNS_MASK: Mask to get the Reachability Groups Change Notices supported
 * @NVME_CTRL_OAES_ANSAN_MASK: Mask to get the Allocated Namespace Attribute Notices supported
 * @NVME_CTRL_OAES_RLCC_MASK: Mask to get the Rate Limiting Configuration Change event supported
 * @NVME_CTRL_OAES_ZD_MASK: Mask to get the Zone Descriptor Change Notifications supported
 * @NVME_CTRL_OAES_DL_MASK: Mask to get the Discover Log Page Change Notifications supported
 * @NVME_CTRL_OAES_NSAN: Attached Namespace Attribute Notices event supported
 * @NVME_CTRL_OAES_FA: Firmware Activation Notices event supported
 * @NVME_CTRL_OAES_ANA: ANA Change Notices supported
 * @NVME_CTRL_OAES_PLEA: Predictable Latency Event Aggregate Log Change Notices event supported
 * @NVME_CTRL_OAES_LBAS: LBA Status Information Notices event supported
 * @NVME_CTRL_OAES_EGE: Endurance Group Events Aggregate Log Change Notices event supported
 * @NVME_CTRL_OAES_NS: Normal NVM Subsystem Shutdown event supported
 * @NVME_CTRL_OAES_TTH: Temperature Threshold Hysteresis Recovery event supported
 * @NVME_CTRL_OAES_RGCNS: Reachability Groups Change Notices supported
 * @NVME_CTRL_OAES_ANSAN: Allocated Namespace Attribute Notices supported
 * @NVME_CTRL_OAES_RLCC: Rate Limiting Configuration Change event supported
 * @NVME_CTRL_OAES_ZD: Zone Descriptor Change Notifications supported
 * @NVME_CTRL_OAES_DL: Discover Log Page Change Notifications supported
 */
enum nvme_id_ctrl_oaes {
	NVME_CTRL_OAES_NSAN_SHIFT	= 8,
	NVME_CTRL_OAES_FA_SHIFT		= 9,
	NVME_CTRL_OAES_ANA_SHIFT	= 11,
	NVME_CTRL_OAES_PLEA_SHIFT	= 12,
	NVME_CTRL_OAES_LBAS_SHIFT	= 13,
	NVME_CTRL_OAES_EGE_SHIFT	= 14,
	NVME_CTRL_OAES_NS_SHIFT		= 15,
	NVME_CTRL_OAES_TTH_SHIFT	= 16,
	NVME_CTRL_OAES_RGCNS_SHIFT	= 17,
	NVME_CTRL_OAES_ANSAN_SHIFT	= 19,
	NVME_CTRL_OAES_RLCC_SHIFT	= 22,
	NVME_CTRL_OAES_ZD_SHIFT		= 27,
	NVME_CTRL_OAES_DL_SHIFT		= 31,
	NVME_CTRL_OAES_NSAN_MASK	= 0x1,
	NVME_CTRL_OAES_FA_MASK		= 0x1,
	NVME_CTRL_OAES_ANA_MASK		= 0x1,
	NVME_CTRL_OAES_PLEA_MASK	= 0x1,
	NVME_CTRL_OAES_LBAS_MASK	= 0x1,
	NVME_CTRL_OAES_EGE_MASK		= 0x1,
	NVME_CTRL_OAES_NS_MASK		= 0x1,
	NVME_CTRL_OAES_TTH_MASK		= 0x1,
	NVME_CTRL_OAES_RGCNS_MASK	= 0x1,
	NVME_CTRL_OAES_ANSAN_MASK	= 0x1,
	NVME_CTRL_OAES_RLCC_MASK	= 0x1,
	NVME_CTRL_OAES_ZD_MASK		= 0x1,
	NVME_CTRL_OAES_DL_MASK		= 0x1,
	NVME_CTRL_OAES_NSAN		= NVME_VAL(CTRL_OAES_NSAN),
	NVME_CTRL_OAES_FA		= NVME_VAL(CTRL_OAES_FA),
	NVME_CTRL_OAES_ANA		= NVME_VAL(CTRL_OAES_ANA),
	NVME_CTRL_OAES_PLEA		= NVME_VAL(CTRL_OAES_PLEA),
	NVME_CTRL_OAES_LBAS		= NVME_VAL(CTRL_OAES_LBAS),
	NVME_CTRL_OAES_EGE		= NVME_VAL(CTRL_OAES_EGE),
	NVME_CTRL_OAES_NS		= NVME_VAL(CTRL_OAES_NS),
	NVME_CTRL_OAES_TTH		= NVME_VAL(CTRL_OAES_TTH),
	NVME_CTRL_OAES_RGCNS		= NVME_VAL(CTRL_OAES_RGCNS),
	NVME_CTRL_OAES_ANSAN		= NVME_VAL(CTRL_OAES_ANSAN),
	NVME_CTRL_OAES_RLCC		= NVME_VAL(CTRL_OAES_RLCC),
	NVME_CTRL_OAES_ZD		= NVME_VAL(CTRL_OAES_ZD),
	NVME_CTRL_OAES_DL		= NVME_VAL(CTRL_OAES_DL),
};

#define NVME_CTRL_OAES_NSAN(oaes)	NVME_GET(oaes, CTRL_OAES_NSAN)
#define NVME_CTRL_OAES_FAN(oaes)	NVME_GET(oaes, CTRL_OAES_FA)
#define NVME_CTRL_OAES_ANACN(oaes)	NVME_GET(oaes, CTRL_OAES_ANA)
#define NVME_CTRL_OAES_PLEALCN(oaes)	NVME_GET(oaes, CTRL_OAES_PLEA)
#define NVME_CTRL_OAES_LBASIAN(oaes)	NVME_GET(oaes, CTRL_OAES_LBAS)
#define NVME_CTRL_OAES_EGEALPCN(oaes)	NVME_GET(oaes, CTRL_OAES_EGE)
#define NVME_CTRL_OAES_NNVMSS(oaes)	NVME_GET(oaes, CTRL_OAES_NS)
#define NVME_CTRL_OAES_TTHR(oaes)	NVME_GET(oaes, CTRL_OAES_TTH)
#define NVME_CTRL_OAES_RGCNS(oaes)	NVME_GET(oaes, CTRL_OAES_RGCNS)
#define NVME_CTRL_OAES_ANSAN(oaes)	NVME_GET(oaes, CTRL_OAES_ANSAN)
#define NVME_CTRL_OAES_RLCC(oaes)	NVME_GET(oaes, CTRL_OAES_RLCC)
#define NVME_CTRL_OAES_ZDCN(oaes)	NVME_GET(oaes, CTRL_OAES_ZD)
#define NVME_CTRL_OAES_DLPCN(oaes)	NVME_GET(oaes, CTRL_OAES_DL)

/**
 * enum nvme_id_ctrl_ctratt - Controller attributes
 * @NVME_CTRL_CTRATT_HIDS_SHIFT: HIDS shift
 * @NVME_CTRL_CTRATT_NOPSPM_SHIFT: NOPSPM shift
 * @NVME_CTRL_CTRATT_NSETS_SHIFT: NSETS shift
 * @NVME_CTRL_CTRATT_RRLVLS_SHIFT: RRLVLS shift
 * @NVME_CTRL_CTRATT_EGS_SHIFT: EGS shift
 * @NVME_CTRL_CTRATT_PLM_SHIFT: PLM shift
 * @NVME_CTRL_CTRATT_TBKAS_SHIFT: TBKAS shift
 * @NVME_CTRL_CTRATT_NG_SHIFT: NG shift
 * @NVME_CTRL_CTRATT_SQA_SHIFT: SQA shift
 * @NVME_CTRL_CTRATT_ULIST_SHIFT: ULIST shift
 * @NVME_CTRL_CTRATT_MDS_SHIFT: MDS shift
 * @NVME_CTRL_CTRATT_FCM_SHIFT: FCM shift
 * @NVME_CTRL_CTRATT_VCM_SHIFT: VCM shift
 * @NVME_CTRL_CTRATT_DEG_SHIFT: DEG shift
 * @NVME_CTRL_CTRATT_DNVMS_SHIFT: DNVMS shift
 * @NVME_CTRL_CTRATT_ELBAS_SHIFT: ELBAS shift
 * @NVME_CTRL_CTRATT_MEM_SHIFT: MEM shift
 * @NVME_CTRL_CTRATT_HMBR_SHIFT: HMBR shift
 * @NVME_CTRL_CTRATT_RHII_SHIFT: RHII shift
 * @NVME_CTRL_CTRATT_FDPS_SHIFT: FDPS shift
 * @NVME_CTRL_CTRATT_PLS_SHIFT: PLS shift
 * @NVME_CTRL_CTRATT_PMS_SHIFT: PMS shift
 * @NVME_CTRL_CTRATT_VMS_SHIFT: VMS shift
 * @NVME_CTRL_CTRATT_IIELLSS_SHIFT: IIELLSS shift
 * @NVME_CTRL_CTRATT_HIDS_MASK: HIDS mask
 * @NVME_CTRL_CTRATT_NOPSPM_MASK: NOPSPM mask
 * @NVME_CTRL_CTRATT_NSETS_MASK: NSETS mask
 * @NVME_CTRL_CTRATT_RRLVLS_MASK: RRLVLS mask
 * @NVME_CTRL_CTRATT_EGS_MASK: EGS mask
 * @NVME_CTRL_CTRATT_PLM_MASK: PLM mask
 * @NVME_CTRL_CTRATT_TBKAS_MASK: TBKAS mask
 * @NVME_CTRL_CTRATT_NG_MASK: NG mask
 * @NVME_CTRL_CTRATT_SQA_MASK: SQA mask
 * @NVME_CTRL_CTRATT_ULIST_MASK: ULIST mask
 * @NVME_CTRL_CTRATT_MDS_MASK: MDS mask
 * @NVME_CTRL_CTRATT_FCM_MASK: FCM mask
 * @NVME_CTRL_CTRATT_VCM_MASK: VCM mask
 * @NVME_CTRL_CTRATT_DEG_MASK: DEG mask
 * @NVME_CTRL_CTRATT_DNVMS_MASK: DNVMS mask
 * @NVME_CTRL_CTRATT_ELBAS_MASK: ELBAS mask
 * @NVME_CTRL_CTRATT_MEM_MASK: MEM mask
 * @NVME_CTRL_CTRATT_HMBR_MASK: HMBR mask
 * @NVME_CTRL_CTRATT_RHII_MASK: RHII mask
 * @NVME_CTRL_CTRATT_FDPS_MASK: FDPS mask
 * @NVME_CTRL_CTRATT_PLS_MASK: PLS mask
 * @NVME_CTRL_CTRATT_PMS_MASK: PMS mask
 * @NVME_CTRL_CTRATT_VMS_MASK: VMS mask
 * @NVME_CTRL_CTRATT_IIELLSS_MASK: IIELLSS mask
 * @NVME_CTRL_CTRATT_128_ID: 128-bit Host Identifier supported
 * @NVME_CTRL_CTRATT_NON_OP_PSP: Non-Operational Poser State Permissive Mode
 *				 supported
 * @NVME_CTRL_CTRATT_NVM_SETS: NVM Sets supported
 * @NVME_CTRL_CTRATT_READ_RECV_LVLS: Read Recovery Levels supported
 * @NVME_CTRL_CTRATT_ENDURANCE_GROUPS: Endurance Groups supported
 * @NVME_CTRL_CTRATT_PREDICTABLE_LAT: Predictable Latency Mode supported
 * @NVME_CTRL_CTRATT_TBKAS: Traffic Based Keep Alive Support
 * @NVME_CTRL_CTRATT_NAMESPACE_GRANULARITY: Namespace Granularity reporting
 *					    supported
 * @NVME_CTRL_CTRATT_SQ_ASSOCIATIONS: SQ Associations supported
 * @NVME_CTRL_CTRATT_UUID_LIST: UUID List reporting supported
 * @NVME_CTRL_CTRATT_MDS: Multi-Domain Subsystem supported
 * @NVME_CTRL_CTRATT_FIXED_CAP: Fixed Capacity Management  supported
 * @NVME_CTRL_CTRATT_VARIABLE_CAP: Variable Capacity Management supported
 * @NVME_CTRL_CTRATT_DEL_ENDURANCE_GROUPS: Delete Endurance Groups supported
 * @NVME_CTRL_CTRATT_DEL_NVM_SETS: Delete NVM Sets supported
 * @NVME_CTRL_CTRATT_ELBAS: Extended LBA Formats supported
 * @NVME_CTRL_CTRATT_MEM: MDTS and Size Limits Exclude Metadata supported
 * @NVME_CTRL_CTRATT_HMBR: HMB Restrict Non-Operational Power State Access
 * @NVME_CTRL_CTRATT_RHII: Reservations and Host Identifier Interaction
 * @NVME_CTRL_CTRATT_FDPS: Flexible Data Placement supported
 * @NVME_CTRL_CTRATT_PLS: Power Limit Support
 * @NVME_CTRL_CTRATT_PMS: Power Measurement Support
 * @NVME_CTRL_CTRATT_VMS: Voltage Measurement Support
 * @NVME_CTRL_CTRATT_IIELLSS: Idle I/O Exit Latency Limit Support and Scope
 * @NVME_CTRL_CTRATT_IIELLSS_POWER_STATE: Each operational power state scope
 * @NVME_CTRL_CTRATT_IIELLSS_GLOBAL: All operational power states scope
 */
enum nvme_id_ctrl_ctratt {
	NVME_CTRL_CTRATT_HIDS_SHIFT            = 0,
	NVME_CTRL_CTRATT_NOPSPM_SHIFT          = 1,
	NVME_CTRL_CTRATT_NSETS_SHIFT           = 2,
	NVME_CTRL_CTRATT_RRLVLS_SHIFT          = 3,
	NVME_CTRL_CTRATT_EGS_SHIFT             = 4,
	NVME_CTRL_CTRATT_PLM_SHIFT             = 5,
	NVME_CTRL_CTRATT_TBKAS_SHIFT           = 6,
	NVME_CTRL_CTRATT_NG_SHIFT              = 7,
	NVME_CTRL_CTRATT_SQA_SHIFT             = 8,
	NVME_CTRL_CTRATT_ULIST_SHIFT           = 9,
	NVME_CTRL_CTRATT_MDS_SHIFT             = 10,
	NVME_CTRL_CTRATT_FCM_SHIFT             = 11,
	NVME_CTRL_CTRATT_VCM_SHIFT             = 12,
	NVME_CTRL_CTRATT_DEG_SHIFT             = 13,
	NVME_CTRL_CTRATT_DNVMS_SHIFT           = 14,
	NVME_CTRL_CTRATT_ELBAS_SHIFT           = 15,
	NVME_CTRL_CTRATT_MEM_SHIFT             = 16,
	NVME_CTRL_CTRATT_HMBR_SHIFT            = 17,
	NVME_CTRL_CTRATT_RHII_SHIFT            = 18,
	NVME_CTRL_CTRATT_FDPS_SHIFT            = 19,
	NVME_CTRL_CTRATT_PLS_SHIFT             = 20,
	NVME_CTRL_CTRATT_PMS_SHIFT             = 21,
	NVME_CTRL_CTRATT_VMS_SHIFT             = 22,
	NVME_CTRL_CTRATT_IIELLSS_SHIFT         = 23,
	NVME_CTRL_CTRATT_HIDS_MASK             = 0x1,
	NVME_CTRL_CTRATT_NOPSPM_MASK           = 0x1,
	NVME_CTRL_CTRATT_NSETS_MASK            = 0x1,
	NVME_CTRL_CTRATT_RRLVLS_MASK           = 0x1,
	NVME_CTRL_CTRATT_EGS_MASK              = 0x1,
	NVME_CTRL_CTRATT_PLM_MASK              = 0x1,
	NVME_CTRL_CTRATT_TBKAS_MASK            = 0x1,
	NVME_CTRL_CTRATT_NG_MASK               = 0x1,
	NVME_CTRL_CTRATT_SQA_MASK              = 0x1,
	NVME_CTRL_CTRATT_ULIST_MASK            = 0x1,
	NVME_CTRL_CTRATT_MDS_MASK              = 0x1,
	NVME_CTRL_CTRATT_FCM_MASK              = 0x1,
	NVME_CTRL_CTRATT_VCM_MASK              = 0x1,
	NVME_CTRL_CTRATT_DEG_MASK              = 0x1,
	NVME_CTRL_CTRATT_DNVMS_MASK            = 0x1,
	NVME_CTRL_CTRATT_ELBAS_MASK            = 0x1,
	NVME_CTRL_CTRATT_MEM_MASK              = 0x1,
	NVME_CTRL_CTRATT_HMBR_MASK             = 0x1,
	NVME_CTRL_CTRATT_RHII_MASK             = 0x1,
	NVME_CTRL_CTRATT_FDPS_MASK             = 0x1,
	NVME_CTRL_CTRATT_PLS_MASK              = 0x1,
	NVME_CTRL_CTRATT_PMS_MASK              = 0x1,
	NVME_CTRL_CTRATT_VMS_MASK              = 0x1,
	NVME_CTRL_CTRATT_IIELLSS_MASK          = 0x3,
	NVME_CTRL_CTRATT_128_ID                = NVME_VAL(CTRL_CTRATT_HIDS),
	NVME_CTRL_CTRATT_NON_OP_PSP            = NVME_VAL(CTRL_CTRATT_NOPSPM),
	NVME_CTRL_CTRATT_NVM_SETS              = NVME_VAL(CTRL_CTRATT_NSETS),
	NVME_CTRL_CTRATT_READ_RECV_LVLS        = NVME_VAL(CTRL_CTRATT_RRLVLS),
	NVME_CTRL_CTRATT_ENDURANCE_GROUPS      = NVME_VAL(CTRL_CTRATT_EGS),
	NVME_CTRL_CTRATT_PREDICTABLE_LAT       = NVME_VAL(CTRL_CTRATT_PLM),
	NVME_CTRL_CTRATT_TBKAS                 = NVME_VAL(CTRL_CTRATT_TBKAS),
	NVME_CTRL_CTRATT_NAMESPACE_GRANULARITY = NVME_VAL(CTRL_CTRATT_NG),
	NVME_CTRL_CTRATT_SQ_ASSOCIATIONS       = NVME_VAL(CTRL_CTRATT_SQA),
	NVME_CTRL_CTRATT_UUID_LIST             = NVME_VAL(CTRL_CTRATT_ULIST),
	NVME_CTRL_CTRATT_MDS                   = NVME_VAL(CTRL_CTRATT_MDS),
	NVME_CTRL_CTRATT_FIXED_CAP             = NVME_VAL(CTRL_CTRATT_FCM),
	NVME_CTRL_CTRATT_VARIABLE_CAP          = NVME_VAL(CTRL_CTRATT_VCM),
	NVME_CTRL_CTRATT_DEL_ENDURANCE_GROUPS  = NVME_VAL(CTRL_CTRATT_DEG),
	NVME_CTRL_CTRATT_DEL_NVM_SETS          = NVME_VAL(CTRL_CTRATT_DNVMS),
	NVME_CTRL_CTRATT_ELBAS                 = NVME_VAL(CTRL_CTRATT_ELBAS),
	NVME_CTRL_CTRATT_MEM                   = NVME_VAL(CTRL_CTRATT_MEM),
	NVME_CTRL_CTRATT_HMBR                  = NVME_VAL(CTRL_CTRATT_HMBR),
	NVME_CTRL_CTRATT_RHII                  = NVME_VAL(CTRL_CTRATT_RHII),
	NVME_CTRL_CTRATT_FDPS                  = NVME_VAL(CTRL_CTRATT_FDPS),
	NVME_CTRL_CTRATT_PLS                   = NVME_VAL(CTRL_CTRATT_PLS),
	NVME_CTRL_CTRATT_PMS                   = NVME_VAL(CTRL_CTRATT_PMS),
	NVME_CTRL_CTRATT_VMS                   = NVME_VAL(CTRL_CTRATT_VMS),
	NVME_CTRL_CTRATT_IIELLSS               = NVME_VAL(CTRL_CTRATT_IIELLSS),
	NVME_CTRL_CTRATT_IIELLSS_POWER_STATE   = 1,
	NVME_CTRL_CTRATT_IIELLSS_GLOBAL        = 2,
};

#define NVME_CTRL_CTRATT_HIDS(ctratt)    NVME_GET(ctratt, CTRL_CTRATT_HIDS)
#define NVME_CTRL_CTRATT_NOPSPM(ctratt)  NVME_GET(ctratt, CTRL_CTRATT_NOPSPM)
#define NVME_CTRL_CTRATT_NSETS(ctratt)   NVME_GET(ctratt, CTRL_CTRATT_NSETS)
#define NVME_CTRL_CTRATT_RRLVLS(ctratt)  NVME_GET(ctratt, CTRL_CTRATT_RRLVLS)
#define NVME_CTRL_CTRATT_EGS(ctratt)     NVME_GET(ctratt, CTRL_CTRATT_EGS)
#define NVME_CTRL_CTRATT_PLM(ctratt)     NVME_GET(ctratt, CTRL_CTRATT_PLM)
#define NVME_CTRL_CTRATT_TBKAS(ctratt)   NVME_GET(ctratt, CTRL_CTRATT_TBKAS)
#define NVME_CTRL_CTRATT_NG(ctratt)      NVME_GET(ctratt, CTRL_CTRATT_NG)
#define NVME_CTRL_CTRATT_SQA(ctratt)     NVME_GET(ctratt, CTRL_CTRATT_SQA)
#define NVME_CTRL_CTRATT_ULIST(ctratt)   NVME_GET(ctratt, CTRL_CTRATT_ULIST)
#define NVME_CTRL_CTRATT_MDS(ctratt)     NVME_GET(ctratt, CTRL_CTRATT_MDS)
#define NVME_CTRL_CTRATT_FCM(ctratt)     NVME_GET(ctratt, CTRL_CTRATT_FCM)
#define NVME_CTRL_CTRATT_VCM(ctratt)     NVME_GET(ctratt, CTRL_CTRATT_VCM)
#define NVME_CTRL_CTRATT_DEG(ctratt)     NVME_GET(ctratt, CTRL_CTRATT_DEG)
#define NVME_CTRL_CTRATT_DNVMS(ctratt)   NVME_GET(ctratt, CTRL_CTRATT_DNVMS)
#define NVME_CTRL_CTRATT_ELBAS(ctratt)   NVME_GET(ctratt, CTRL_CTRATT_ELBAS)
#define NVME_CTRL_CTRATT_MEM(ctratt)     NVME_GET(ctratt, CTRL_CTRATT_MEM)
#define NVME_CTRL_CTRATT_HMBR(ctratt)    NVME_GET(ctratt, CTRL_CTRATT_HMBR)
#define NVME_CTRL_CTRATT_RHII(ctratt)    NVME_GET(ctratt, CTRL_CTRATT_RHII)
#define NVME_CTRL_CTRATT_FDPS(ctratt)    NVME_GET(ctratt, CTRL_CTRATT_FDPS)
#define NVME_CTRL_CTRATT_PLS(ctratt)     NVME_GET(ctratt, CTRL_CTRATT_PLS)
#define NVME_CTRL_CTRATT_PMS(ctratt)     NVME_GET(ctratt, CTRL_CTRATT_PMS)
#define NVME_CTRL_CTRATT_VMS(ctratt)     NVME_GET(ctratt, CTRL_CTRATT_VMS)
#define NVME_CTRL_CTRATT_IIELLSS(ctratt) NVME_GET(ctratt, CTRL_CTRATT_IIELLSS)

/**
 * enum nvme_id_ctrl_bpcap - Boot Partition Capabilities
 * @NVME_CTRL_BACAP_RPMBBPWPS_SHIFT:		Shift amount to get the RPMB Boot Partition Write
 *						Protection Support from the &struct
 *						nvme_id_ctrl.bpcap field.
 * @NVME_CTRL_BACAP_SFBPWPS_SHIFT:		Shift amount to get the Set Features Boot Partition
 *						Write Protection Support from the &struct
 *						nvme_id_ctrl.bpcap field.
 * @NVME_CTRL_BACAP_RPMBBPWPS_MASK:		Mask to get the RPMB Boot Partition Write
 *						Protection Support from the &struct
 *						nvme_id_ctrl.bpcap field.
 * @NVME_CTRL_BACAP_SFBPWPS_MASK:		Mask to get the Set Features Boot Partition Write
 *						Protection Support from the &struct
 *						nvme_id_ctrl.bpcap field.
 * @NVME_CTRL_BACAP_RPMBBPWPS_NOT_SPECIFIED:	Support for RPMB Boot Partition Write Protection
 *						is not specified.
 * @NVME_CTRL_BACAP_RPMBBPWPS_NOT_SUPPORTED:	RPMB Boot Partition Write Protection is not
 *						supported by this controller.
 * @NVME_CTRL_BACAP_RPMBBPWPS_SUPPORTED:	RPMB Boot Partition Write Protection is supported
 *						by this controller.
 */
enum nvme_id_ctrl_bpcap {
	NVME_CTRL_BACAP_RPMBBPWPS_SHIFT		= 0,
	NVME_CTRL_BACAP_SFBPWPS_SHIFT		= 2,
	NVME_CTRL_BACAP_RPMBBPWPS_MASK		= 0x3,
	NVME_CTRL_BACAP_SFBPWPS_MASK		= 0x1,
	NVME_CTRL_BACAP_RPMBBPWPS_NOT_SPECIFIED	= 0,
	NVME_CTRL_BACAP_RPMBBPWPS_NOT_SUPPORTED	= 1,
	NVME_CTRL_BACAP_RPMBBPWPS_SUPPORTED	= 2,
};

/**
 * enum nvme_id_ctrl_chsi - CXL HDM Support Information
 * @NVME_CTRL_CHSI_CHS_SHIFT:	Shift amount to get the CXL HDM Support (CHS)
 *				from the &struct nvme_id_ctrl.chsi field.
 * @NVME_CTRL_CHSI_CHS_MASK:	Mask to get CHS
 */
enum nvme_id_ctrl_chsi {
	NVME_CTRL_CHSI_CHS_SHIFT	= 0,
	NVME_CTRL_CHSI_CHS_MASK		= 0x1,
};

#define NVME_CTRL_CHSI_CHS(chsi)	NVME_GET(chsi, CTRL_CHSI_CHS)

/**
 * enum nvme_id_ctrl_rmdca - Restore Manufacturing Configuration Attributes
 * @NVME_CTRL_RMDCA_RDSCS_SHIFT:	Shift amount to get the Restore Default
 *					NVM Subsystem Configuration Supported
 *					(RDSCS) from the &struct
 *					nvme_id_ctrl.rmdca field.
 * @NVME_CTRL_RMDCA_RDSCS_MASK:	Mask to get RDSCS
 * @NVME_CTRL_RMDCA_RDNCS_SHIFT:	Shift amount to get the Restore Default
 *					Namespace Configuration Supported
 *					(RDNCS)
 * @NVME_CTRL_RMDCA_RDNCS_MASK:	Mask to get RDNCS
 * @NVME_CTRL_RMDCA_RDCCS_SHIFT:	Shift amount to get the Restore Default
 *					Capacity Management Configuration
 *					Supported (RDCCS)
 * @NVME_CTRL_RMDCA_RDCCS_MASK:	Mask to get RDCCS
 */
enum nvme_id_ctrl_rmdca {
	NVME_CTRL_RMDCA_RDSCS_SHIFT	= 0,
	NVME_CTRL_RMDCA_RDSCS_MASK	= 0x1,
	NVME_CTRL_RMDCA_RDNCS_SHIFT	= 1,
	NVME_CTRL_RMDCA_RDNCS_MASK	= 0x1,
	NVME_CTRL_RMDCA_RDCCS_SHIFT	= 2,
	NVME_CTRL_RMDCA_RDCCS_MASK	= 0x1,
};

#define NVME_CTRL_RMDCA_RDSCS(rmdca)	NVME_GET(rmdca, CTRL_RMDCA_RDSCS)
#define NVME_CTRL_RMDCA_RDNCS(rmdca)	NVME_GET(rmdca, CTRL_RMDCA_RDNCS)
#define NVME_CTRL_RMDCA_RDCCS(rmdca)	NVME_GET(rmdca, CTRL_RMDCA_RDCCS)

#define NVME_CTRL_BACAP_RPMBBPWPS(bpcap)	NVME_GET(bpcap, CTRL_BACAP_RPMBBPWPS)
#define NVME_CTRL_BACAP_SFBPWPS(bpcap)		NVME_GET(bpcap, CTRL_BACAP_SFBPWPS)

/**
 * enum nvme_id_ctrl_plsi - Power Loss Signaling Information
 * @NVME_CTRL_PLSI_PLSEPF_SHIFT:	Shift amount to get the PLS Emergency Power Fail from the
 *					&struct nvme_id_ctrl.plsi field.
 * @NVME_CTRL_PLSI_PLSFQ_SHIFT:		Shift amount to get the PLS Forced Quiescence from the
 *					&struct nvme_id_ctrl.plsi field.
 * @NVME_CTRL_PLSI_PLSEPF_MASK:		Mask to get the PLS Emergency Power Fail from the
 *					&struct nvme_id_ctrl.plsi field.
 * @NVME_CTRL_PLSI_PLSFQ_MASK:		Mask to get the PLS Forced Quiescence from the
 *					&struct nvme_id_ctrl.plsi field.
 */
enum nvme_id_ctrl_plsi {
	NVME_CTRL_PLSI_PLSEPF_SHIFT	= 0,
	NVME_CTRL_PLSI_PLSFQ_SHIFT	= 1,
	NVME_CTRL_PLSI_PLSEPF_MASK	= 0x1,
	NVME_CTRL_PLSI_PLSFQ_MASK	= 0x1,
};

#define NVME_CTRL_PLSI_PLSEPF(plsi)	NVME_GET(plsi, CTRL_PLSI_PLSEPF)
#define NVME_CTRL_PLSI_PLSFQ(plsi)	NVME_GET(plsi, CTRL_PLSI_PLSFQ)

/**
 * enum nvme_id_ctrl_crcap - Power Loss Signaling Information
 * @NVME_CTRL_CRCAP_RRSUP_SHIFT:	Shift amount to get the Reachability Reporting Supported
 *					from the &struct nvme_id_ctrl.crcap field.
 * @NVME_CTRL_CRCAP_RGIDC_SHIFT:	Shift amount to get the Reachability Group ID Changeable
 *					from the &struct nvme_id_ctrl.crcap field.
 * @NVME_CTRL_CRCAP_RRSUP_MASK:		Mask to get the Reachability Reporting Supported from the
 *					&struct nvme_id_ctrl.crcap field.
 * @NVME_CTRL_CRCAP_RGIDC_MASK:		Mask to get the Reachability Group ID Changeable from the
 *					&struct nvme_id_ctrl.crcap field.
 */
enum nvme_id_ctrl_crcap {
	NVME_CTRL_CRCAP_RRSUP_SHIFT	= 0,
	NVME_CTRL_CRCAP_RGIDC_SHIFT	= 1,
	NVME_CTRL_CRCAP_RRSUP_MASK	= 0x1,
	NVME_CTRL_CRCAP_RGIDC_MASK	= 0x1,
};

#define NVME_CTRL_CRCAP_RRSUP(crcap)	NVME_GET(crcap, CTRL_CRCAP_RRSUP)
#define NVME_CTRL_CRCAP_RGICS(crcap)	NVME_GET(crcap, CTRL_CRCAP_RGICS)

/**
 * enum nvme_id_ctrl_cntrltype - Controller types
 * @NVME_CTRL_CNTRLTYPE_IO: NVM I/O controller
 * @NVME_CTRL_CNTRLTYPE_DISCOVERY: Discovery controller
 * @NVME_CTRL_CNTRLTYPE_ADMIN: Admin controller
 */
enum nvme_id_ctrl_cntrltype {
	NVME_CTRL_CNTRLTYPE_IO			= 1,
	NVME_CTRL_CNTRLTYPE_DISCOVERY		= 2,
	NVME_CTRL_CNTRLTYPE_ADMIN		= 3,
};

/**
 * enum nvme_id_ctrl_dctype - Discovery Controller types
 * @NVME_CTRL_DCTYPE_NOT_REPORTED: Not reported (I/O, Admin, and pre-TP8010)
 * @NVME_CTRL_DCTYPE_DDC:	   Direct Discovery controller
 * @NVME_CTRL_DCTYPE_CDC:	   Central Discovery controller
 */
enum nvme_id_ctrl_dctype {
	NVME_CTRL_DCTYPE_NOT_REPORTED	= 0,
	NVME_CTRL_DCTYPE_DDC		= 1,
	NVME_CTRL_DCTYPE_CDC		= 2,
};

/**
 * enum nvme_id_ctrl_nvmsr - This field reports information associated with the
 *			     NVM Subsystem, see &struct nvme_id_ctrl.nvmsr.
 * @NVME_CTRL_NVMSR_NVMESD_SHIFT: NVMESD shift
 * @NVME_CTRL_NVMSR_NVMEE_SHIFT: NVMEE shift
 * @NVME_CTRL_NVMSR_NVMESD_MASK: NVMESD mask
 * @NVME_CTRL_NVMSR_NVMEE_MASK: NVMEE mask
 * @NVME_CTRL_NVMSR_NVMESD: If set, then the NVM Subsystem is part of an NVMe
 *			    Storage Device; if cleared, then the NVM Subsystem
 *			    is not part of an NVMe Storage Device.
 * @NVME_CTRL_NVMSR_NVMEE:  If set, then the NVM Subsystem is part of an NVMe
 *			    Enclosure; if cleared, then the NVM Subsystem is
 *			    not part of an NVMe Enclosure.
 */
enum nvme_id_ctrl_nvmsr {
	NVME_CTRL_NVMSR_NVMESD_SHIFT	= 0,
	NVME_CTRL_NVMSR_NVMEE_SHIFT	= 1,
	NVME_CTRL_NVMSR_NVMESD_MASK	= 0x1,
	NVME_CTRL_NVMSR_NVMEE_MASK	= 0x1,
	NVME_CTRL_NVMSR_NVMESD		= NVME_VAL(CTRL_NVMSR_NVMESD),
	NVME_CTRL_NVMSR_NVMEE		= NVME_VAL(CTRL_NVMSR_NVMEE),
};

#define NVME_CTRL_NVMSR_NVMESD(nvmsr)	NVME_GET(nvmsr, CTRL_NVMSR_NVMESD)
#define NVME_CTRL_NVMSR_NVMEE(nvmsr)	NVME_GET(nvmsr, CTRL_NVMSR_NVMEE)

/**
 * enum nvme_id_ctrl_vwci - This field indicates information about remaining
 *			    number of times that VPD contents are able to be
 *			    updated using the VPD Write command, see &struct
 *			    nvme_id_ctrl.vwci.
 * @NVME_CTRL_VWCI_VWCR_SHIFT: VWCR shift
 * @NVME_CTRL_VWCI_VWCRV_SHIFT: VWCRV shift
 * @NVME_CTRL_VWCI_VWCR_MASK: VWCR mask
 * @NVME_CTRL_VWCI_VWCRV_MASK: VWCRV mask
 * @NVME_CTRL_VWCI_VWCR:  Mask to get value of VPD Write Cycles Remaining. If
 *			  the VPD Write Cycle Remaining Valid bit is set, then
 *			  this field contains a value indicating the remaining
 *			  number of times that VPD contents are able to be
 *			  updated using the VPD Write command. If this field is
 *			  set to 7Fh, then the remaining number of times that
 *			  VPD contents are able to be updated using the VPD
 *			  Write command is greater than or equal to 7Fh.
 * @NVME_CTRL_VWCI_VWCRV: VPD Write Cycle Remaining Valid. If this bit is set,
 *			  then the VPD Write Cycle Remaining field is valid. If
 *			  this bit is cleared, then the VPD Write Cycles
 *			  Remaining field is invalid and cleared to 0h.
 */
enum nvme_id_ctrl_vwci {
	NVME_CTRL_VWCI_VWCR_SHIFT	= 0,
	NVME_CTRL_VWCI_VWCRV_SHIFT	= 7,
	NVME_CTRL_VWCI_VWCR_MASK	= 0x7f,
	NVME_CTRL_VWCI_VWCRV_MASK	= 0x1,
	NVME_CTRL_VWCI_VWCR		= NVME_VAL(CTRL_VWCI_VWCR),
	NVME_CTRL_VWCI_VWCRV		= NVME_VAL(CTRL_VWCI_VWCRV),
};

#define NVME_CTRL_VWCI_VWCR(vwci)	NVME_GET(vwci, CTRL_VWCI_VWCR)
#define NVME_CTRL_VWCI_VWCRV(vwci)	NVME_GET(vwci, CTRL_VWCI_VWCRV)

/**
 * enum nvme_id_ctrl_mec - Flags indicating the capabilities of the Management
 *			   Endpoint in the Controller, &struct nvme_id_ctrl.mec.
 * @NVME_CTRL_MEC_SMBUSME: If set, then the NVM Subsystem contains a Management
 *			   Endpoint on an SMBus/I2C port.
 * @NVME_CTRL_MEC_PCIEME:  If set, then the NVM Subsystem contains a Management
 *			   Endpoint on a PCIe port.
 */
enum nvme_id_ctrl_mec {
	NVME_CTRL_MEC_SMBUSME			= 1 << 0,
	NVME_CTRL_MEC_PCIEME			= 1 << 1,
};

/**
 * enum nvme_id_ctrl_oacs - Flags indicating the optional Admin commands and
 *			    features supported by the controller, see
 *			    &struct nvme_id_ctrl.oacs.
 * @NVME_CTRL_OACS_SSRS_SHIFT: Shift amount to get the Security Send Receive supported
 * @NVME_CTRL_OACS_FNVMS_SHIFT:Shift amount to get the Format NVM supported
 * @NVME_CTRL_OACS_FWDS_SHIFT: Shift amount to get the Firmware Download supported
 * @NVME_CTRL_OACS_NMS_SHIFT:  Shift amount to get the Namespace Management supported
 * @NVME_CTRL_OACS_DSTS_SHIFT: Shift amount to get the Device Self-test supported
 * @NVME_CTRL_OACS_DIRS_SHIFT: Shift amount to get the Directives supported
 * @NVME_CTRL_OACS_NSRS_SHIFT: Shift amount to get the NVMe-MI Send Receive supported
 * @NVME_CTRL_OACS_VMS_SHIFT:  Shift amount to get the Virtualization Management supported
 * @NVME_CTRL_OACS_DBCS_SHIFT: Shift amount to get the Doorbell Buffer Config supported
 * @NVME_CTRL_OACS_GLSS_SHIFT: Shift amount to get the Get LBA Status supported
 * @NVME_CTRL_OACS_CFLS_SHIFT: Shift amount to get the Command and Feature Lockdown supported
 * @NVME_CTRL_OACS_HMLMS_SHIFT:Shift amount to get the Host Managed Live Migration support
 * @NVME_CTRL_OACS_CCFLS_SHIFT: Shift amount to get the Controller-scoped
 *			       Command and Feature Lockdown supported
 * @NVME_CTRL_OACS_SSRS_MASK:  Mask to get the Security Send Receive supported
 * @NVME_CTRL_OACS_FNVMS_MASK: Mask to get the Format NVM supported
 * @NVME_CTRL_OACS_FWDS_MASK:  Mask to get the Firmware Download supported
 * @NVME_CTRL_OACS_NMS_MASK:   Mask to get the Namespace Management supported
 * @NVME_CTRL_OACS_DSTS_MASK:  Mask to get the Device Self-test supported
 * @NVME_CTRL_OACS_DIRS_MASK:  Mask to get the Directives supported
 * @NVME_CTRL_OACS_NSRS_MASK:  Mask to get the NVMe-MI Send Receive supported
 * @NVME_CTRL_OACS_VMS_MASK:   Mask to get the Virtualization Management supported
 * @NVME_CTRL_OACS_DBCS_MASK:  Mask to get the Doorbell Buffer Config supported
 * @NVME_CTRL_OACS_GLSS_MASK:  Mask to get the Get LBA Status supported
 * @NVME_CTRL_OACS_CFLS_MASK:  Mask to get the Command and Feature Lockdown supported
 * @NVME_CTRL_OACS_HMLMS_MASK: Mask to get the Host Managed Live Migration support
 * @NVME_CTRL_OACS_CCFLS_MASK: Mask to get the Controller-scoped Command and
 *			       Feature Lockdown supported
 * @NVME_CTRL_OACS_SECURITY:   If set, then the controller supports the
 *			       Security Send and Security Receive commands.
 * @NVME_CTRL_OACS_FORMAT:     If set then the controller supports the Format
 *			       NVM command.
 * @NVME_CTRL_OACS_FW:	       If set, then the controller supports the
 *			       Firmware Commit and Firmware Image Download commands.
 * @NVME_CTRL_OACS_NS_MGMT:    If set, then the controller supports the
 *			       Namespace Management capability
 * @NVME_CTRL_OACS_SELF_TEST:  If set, then the controller supports the Device
 *			       Self-test command.
 * @NVME_CTRL_OACS_DIRECTIVES: If set, then the controller supports Directives
 *			       and the Directive Send and Directive Receive
 *			       commands.
 * @NVME_CTRL_OACS_NVME_MI:    If set, then the controller supports the NVMe-MI
 *			       Send and NVMe-MI Receive commands.
 * @NVME_CTRL_OACS_VIRT_MGMT:  If set, then the controller supports the
 *			       Virtualization Management command.
 * @NVME_CTRL_OACS_DBBUF_CFG:  If set, then the controller supports the
 *			       Doorbell Buffer Config command.
 * @NVME_CTRL_OACS_LBA_STATUS: If set, then the controller supports the Get LBA
 *			       Status capability.
 * @NVME_CTRL_OACS_CMD_FEAT_LD:If set, then the controller supports the command
 *			       and feature lockdown capability.
 * @NVME_CTRL_OACS_HMLM:       If set, then the controller supports the command
 *			       and Host Managed Live Migration capability.
 * @NVME_CTRL_OACS_CTRL_SCOPED_CMD_FEAT_LD: If set, then the controller
 *			       supports the Controller-scoped Command and
 *			       Feature Lockdown capability. Cleared to '0' if
 *			       the Command and Feature Lockdown Supported
 *			       (CFLS) bit is cleared to '0'.
 */
enum nvme_id_ctrl_oacs {
	NVME_CTRL_OACS_SSRS_SHIFT		= 0,
	NVME_CTRL_OACS_FNVMS_SHIFT		= 1,
	NVME_CTRL_OACS_FWDS_SHIFT		= 2,
	NVME_CTRL_OACS_NMS_SHIFT		= 3,
	NVME_CTRL_OACS_DSTS_SHIFT		= 4,
	NVME_CTRL_OACS_DIRS_SHIFT		= 5,
	NVME_CTRL_OACS_NSRS_SHIFT		= 6,
	NVME_CTRL_OACS_VMS_SHIFT		= 7,
	NVME_CTRL_OACS_DBCS_SHIFT		= 8,
	NVME_CTRL_OACS_GLSS_SHIFT		= 9,
	NVME_CTRL_OACS_CFLS_SHIFT		= 10,
	NVME_CTRL_OACS_HMLMS_SHIFT		= 11,
	NVME_CTRL_OACS_CCFLS_SHIFT		= 13,
	NVME_CTRL_OACS_SSRS_MASK		= 1,
	NVME_CTRL_OACS_FNVMS_MASK		= 1,
	NVME_CTRL_OACS_FWDS_MASK		= 1,
	NVME_CTRL_OACS_NMS_MASK			= 1,
	NVME_CTRL_OACS_DSTS_MASK		= 1,
	NVME_CTRL_OACS_DIRS_MASK		= 1,
	NVME_CTRL_OACS_NSRS_MASK		= 1,
	NVME_CTRL_OACS_VMS_MASK			= 1,
	NVME_CTRL_OACS_DBCS_MASK		= 1,
	NVME_CTRL_OACS_GLSS_MASK		= 1,
	NVME_CTRL_OACS_CFLS_MASK		= 1,
	NVME_CTRL_OACS_HMLMS_MASK		= 1,
	NVME_CTRL_OACS_CCFLS_MASK		= 1,
	NVME_CTRL_OACS_SECURITY			= NVME_VAL(CTRL_OACS_SSRS),
	NVME_CTRL_OACS_FORMAT			= NVME_VAL(CTRL_OACS_FNVMS),
	NVME_CTRL_OACS_FW			= NVME_VAL(CTRL_OACS_FWDS),
	NVME_CTRL_OACS_NS_MGMT			= NVME_VAL(CTRL_OACS_NMS),
	NVME_CTRL_OACS_SELF_TEST		= NVME_VAL(CTRL_OACS_DSTS),
	NVME_CTRL_OACS_DIRECTIVES		= NVME_VAL(CTRL_OACS_DIRS),
	NVME_CTRL_OACS_NVME_MI			= NVME_VAL(CTRL_OACS_NSRS),
	NVME_CTRL_OACS_VIRT_MGMT		= NVME_VAL(CTRL_OACS_VMS),
	NVME_CTRL_OACS_DBBUF_CFG		= NVME_VAL(CTRL_OACS_DBCS),
	NVME_CTRL_OACS_LBA_STATUS		= NVME_VAL(CTRL_OACS_GLSS),
	NVME_CTRL_OACS_CMD_FEAT_LD		= NVME_VAL(CTRL_OACS_CFLS),
	NVME_CTRL_OACS_HMLM			= NVME_VAL(CTRL_OACS_HMLMS),
	NVME_CTRL_OACS_CTRL_SCOPED_CMD_FEAT_LD	= NVME_VAL(CTRL_OACS_CCFLS),
};

#define NVME_CTRL_OACS_SSRS(oacs)	NVME_GET(oacs, CTRL_OACS_SSRS)
#define NVME_CTRL_OACS_FNVMS(oacs)	NVME_GET(oacs, CTRL_OACS_FNVMS)
#define NVME_CTRL_OACS_FWDS(oacs)	NVME_GET(oacs, CTRL_OACS_FWDS)
#define NVME_CTRL_OACS_NMS_M(oacs)	NVME_GET(oacs, CTRL_OACS_NMS)
#define NVME_CTRL_OACS_DSTS(oacs)	NVME_GET(oacs, CTRL_OACS_DSTS)
#define NVME_CTRL_OACS_DIRS(oacs)	NVME_GET(oacs, CTRL_OACS_DIRS)
#define NVME_CTRL_OACS_NSRS(oacs)	NVME_GET(oacs, CTRL_OACS_NSRS)
#define NVME_CTRL_OACS_VMS_M(oacs)	NVME_GET(oacs, CTRL_OACS_VMS)
#define NVME_CTRL_OACS_DBCS(oacs)	NVME_GET(oacs, CTRL_OACS_DBCS)
#define NVME_CTRL_OACS_GLSS(oacs)	NVME_GET(oacs, CTRL_OACS_GLSS)
#define NVME_CTRL_OACS_CFLS(oacs)	NVME_GET(oacs, CTRL_OACS_CFLS)
#define NVME_CTRL_OACS_HMLMS(oacs)	NVME_GET(oacs, CTRL_OACS_HMLMS)
#define NVME_CTRL_OACS_CCFLS(oacs)	NVME_GET(oacs, CTRL_OACS_CCFLS)

/**
 * enum nvme_id_ctrl_frmw - Flags and values indicates capabilities regarding
 *			    firmware updates from &struct nvme_id_ctrl.frmw.
 * @NVME_CTRL_FRMW_1ST_RO:	    If set, the first firmware slot is readonly
 * @NVME_CTRL_FRMW_NR_SLOTS:	    Mask to get the value of the number of
 *				    firmware slots that the controller supports.
 * @NVME_CTRL_FRMW_FW_ACT_NO_RESET: If set, the controller supports firmware
 *				    activation without a reset.
 * @NVME_CTRL_FRMW_MP_UP_DETECTION: If set, the controller is able to detect
 *				    overlapping firmware/boot partition
 *				    image update.
 */
enum nvme_id_ctrl_frmw {
	NVME_CTRL_FRMW_1ST_RO			= 1 << 0,
	NVME_CTRL_FRMW_NR_SLOTS			= 3 << 1,
	NVME_CTRL_FRMW_FW_ACT_NO_RESET		= 1 << 4,
	NVME_CTRL_FRMW_MP_UP_DETECTION		= 1 << 5,
};

/**
 * enum nvme_id_ctrl_lpa - Flags indicating optional attributes for log pages
 *			   that are accessed via the Get Log Page command.
 * @NVME_CTRL_LPA_SMART_PER_NS: If set, controller supports SMART/Health log
 *				page on a per namespace basis.
 * @NVME_CTRL_LPA_CMD_EFFECTS:	If Set, the controller supports the commands
 *				supported and effects log page.
 * @NVME_CTRL_LPA_EXTENDED:	If set, the controller supports extended data
 *				for log page command including extended number
 *				of dwords and log page offset fields.
 * @NVME_CTRL_LPA_TELEMETRY:	If set, the controller supports the telemetry
 *				host-initiated and telemetry controller-initiated
 *				log pages and sending telemetry log notices.
 * @NVME_CTRL_LPA_PERSETENT_EVENT:	If set, the controller supports
 *					persistent event log.
 * @NVME_CTRL_LPA_LI0_LI5_LI12_LI13:	If set, the controller supports
 *					- log pages log page.
 *					- returning scope of each command in
 *					  commands supported and effects log
 *					  page.
 *					- feature identifiers supported and
 *					  effects log page.
 *					- NVMe-MI commands supported and
 *					  effects log page.
 * @NVME_CTRL_LPA_DA4_TELEMETRY:	If set, the controller supports data
 *					area 4 for telemetry host-initiated and
 *					telemetry.
 */
enum nvme_id_ctrl_lpa {
	NVME_CTRL_LPA_SMART_PER_NS		= 1 << 0,
	NVME_CTRL_LPA_CMD_EFFECTS		= 1 << 1,
	NVME_CTRL_LPA_EXTENDED			= 1 << 2,
	NVME_CTRL_LPA_TELEMETRY			= 1 << 3,
	NVME_CTRL_LPA_PERSETENT_EVENT		= 1 << 4,
	NVME_CTRL_LPA_LI0_LI5_LI12_LI13		= 1 << 5,
	NVME_CTRL_LPA_DA4_TELEMETRY		= 1 << 6,
};

/**
 * enum nvme_id_ctrl_avscc - Flags indicating the configuration settings for
 *			     Admin Vendor Specific command handling.
 * @NVME_CTRL_AVSCC_AVS: If set, all Admin Vendor Specific Commands use the
 *			 optional vendor specific command format with NDT and
 *			 NDM fields.
 */
enum nvme_id_ctrl_avscc {
	NVME_CTRL_AVSCC_AVS			= 1 << 0,
};

/**
 * enum nvme_id_ctrl_apsta - Flags indicating the attributes of the autonomous
 *			     power state transition feature.
 * @NVME_CTRL_APSTA_APST: If set, then the controller supports autonomous power
 *			  state transitions.
 */
enum nvme_id_ctrl_apsta {
	NVME_CTRL_APSTA_APST			= 1 << 0,
};

/**
 * enum nvme_id_ctrl_rpmbs - This field indicates if the controller supports
 *			     one or more Replay Protected Memory Blocks, from
 *			     &struct nvme_id_ctrl.rpmbs.
 * @NVME_CTRL_RPMBS_NR_UNITS:	 Mask to get the value of the Number of RPMB Units
 * @NVME_CTRL_RPMBS_AUTH_METHOD: Mask to get the value of the Authentication Method
 * @NVME_CTRL_RPMBS_TOTAL_SIZE:	 Mask to get the value of Total Size
 * @NVME_CTRL_RPMBS_ACCESS_SIZE: Mask to get the value of Access Size
 */
enum nvme_id_ctrl_rpmbs {
	NVME_CTRL_RPMBS_NR_UNITS		= 7 << 0,
	NVME_CTRL_RPMBS_AUTH_METHOD		= 7 << 3,
	NVME_CTRL_RPMBS_TOTAL_SIZE		= 0xff << 16,
	NVME_CTRL_RPMBS_ACCESS_SIZE		= 0xff << 24,
};

/**
 * enum nvme_id_ctrl_dsto - Flags indicating the optional Device Self-test
 *			    command or operation behaviors supported by the
 *			    controller or NVM subsystem.
 * @NVME_CTRL_DSTO_SDSO_SHIFT:	Shift amount to get the value of Single Device Self-test
 *				Operation from Device Self-test Options field.
 * @NVME_CTRL_DSTO_HIRS_SHIFT:	Shift amount to get the value of  Host-Initiated Refresh
 *				Support from Device Self-test Options field.
 * @NVME_CTRL_DSTO_SDSO_MASK:	Mask to get the value of Single Device Self-test Operation
 * @NVME_CTRL_DSTO_HIRS_MASK:	Mask to get the value of Host-Initiated Refresh Support
 * @NVME_CTRL_DSTO_ONE_DST:	If set, then the NVM subsystem supports only one device
 *				self-test operation in progress at a time. If cleared,
 *				then the NVM subsystem supports one device self-test
 *				operation per controller at a time.
 * @NVME_CTRL_DSTO_HIRS:	If set, then the controller supports the Host-Initiated
 *				Refresh capability.
 */
enum nvme_id_ctrl_dsto {
	NVME_CTRL_DSTO_SDSO_SHIFT		= 0,
	NVME_CTRL_DSTO_HIRS_SHIFT		= 1,
	NVME_CTRL_DSTO_SDSO_MASK		= 0x1,
	NVME_CTRL_DSTO_HIRS_MASK		= 0x1,
	NVME_CTRL_DSTO_ONE_DST			= NVME_VAL(CTRL_DSTO_SDSO),
	NVME_CTRL_DSTO_HIRS			= NVME_VAL(CTRL_DSTO_HIRS),
};

#define NVME_CTRL_DSTO_SDSO(dsto)	NVME_GET(dsto, CTRL_DSTO_SDSO)
#define NVME_CTRL_DSTO_HIRS(dsto)	NVME_GET(dsto, CTRL_DSTO_HIRS)

/**
 * enum nvme_id_ctrl_hctm - Flags indicate the attributes of the host
 *			    controlled thermal management feature
 * @NVME_CTRL_HCTMA_HCTM: then the controller supports host controlled thermal
 *			  management, and the Set Features command and Get
 *			  Features command with the Feature Identifier field
 *			  set to %NVME_FEAT_FID_HCTM.
 */
enum nvme_id_ctrl_hctm {
	NVME_CTRL_HCTMA_HCTM			= 1 << 0,
};

/**
 * enum nvme_id_ctrl_sanicap - Indicates attributes for sanitize operations.
 * @NVME_CTRL_SANICAP_CES_SHIFT: Crypto erase support shift
 * @NVME_CTRL_SANICAP_BES_SHIFT: Block erase support shift
 * @NVME_CTRL_SANICAP_OWS_SHIFT: Overwrite support shift
 * @NVME_CTRL_SANICAP_VERS_SHIFT: Verification support shift
 * @NVME_CTRL_SANICAP_NVERS_SHIFT: Namespace verification support shift
 * @NVME_CTRL_SANICAP_NDI_SHIFT: No-deallocate inhibited shift
 * @NVME_CTRL_SANICAP_NODMMAS_SHIFT: No-deallocate modifies media after sanitize
 *				     shift
 * @NVME_CTRL_SANICAP_SPRRS_SHIFT: Sanitize purge request and reporting
 *				    supported shift
 * @NVME_CTRL_SANICAP_CES_MASK: Crypto erase support mask
 * @NVME_CTRL_SANICAP_BES_MASK: Block erase support mask
 * @NVME_CTRL_SANICAP_OWS_MASK: Overwrite support mask
 * @NVME_CTRL_SANICAP_VERS_MASK: Verification support mask
 * @NVME_CTRL_SANICAP_NVERS_MASK: Namespace verification support mask
 * @NVME_CTRL_SANICAP_NDI_MASK: No-deallocate inhibited mask
 * @NVME_CTRL_SANICAP_NODMMAS_MASK: No-deallocate modifies media after sanitize
 *				    mask
 * @NVME_CTRL_SANICAP_SPRRS_MASK: Sanitize purge request and reporting
 *				   supported mask
 * @NVME_CTRL_SANICAP_CES:     Crypto Erase Support. If set, then the
 *			       controller supports the Crypto Erase sanitize operation.
 * @NVME_CTRL_SANICAP_BES:     Block Erase Support. If set, then the controller
 *			       supports the Block Erase sanitize operation.
 * @NVME_CTRL_SANICAP_OWS:     Overwrite Support. If set, then the controller
 *			       supports the Overwrite sanitize operation.
 * @NVME_CTRL_SANICAP_VERS: Verification support
 * @NVME_CTRL_SANICAP_NVERS: Namespace verification support
 * @NVME_CTRL_SANICAP_NDI:     No-Deallocate Inhibited. If set and the No-
 *			       Deallocate Response Mode bit is set, then the
 *			       controller deallocates after the sanitize
 *			       operation even if the No-Deallocate After
 *			       Sanitize bit is set in a Sanitize command.
 * @NVME_CTRL_SANICAP_NODMMAS: No-Deallocate Modifies Media After Sanitize,
 *			       mask to extract value.
 * @NVME_CTRL_SANICAP_SPRRS:   Sanitize Purge Request and Reporting
 *			       Supported. If set, then the controller supports
 *			       the Purged (PRGD) field in the Sanitize Status
 *			       log page and the Purge Required (PREQ) bit in
 *			       the Sanitize command and the Sanitize Namespace
 *			       command.
 */
enum nvme_id_ctrl_sanicap {
	NVME_CTRL_SANICAP_CES_SHIFT	= 0,
	NVME_CTRL_SANICAP_BES_SHIFT	= 1,
	NVME_CTRL_SANICAP_OWS_SHIFT	= 2,
	NVME_CTRL_SANICAP_VERS_SHIFT	= 3,
	NVME_CTRL_SANICAP_NVERS_SHIFT	= 4,
	NVME_CTRL_SANICAP_SPRRS_SHIFT	= 5,
	NVME_CTRL_SANICAP_NDI_SHIFT	= 29,
	NVME_CTRL_SANICAP_NODMMAS_SHIFT	= 30,
	NVME_CTRL_SANICAP_CES_MASK	= 0x1,
	NVME_CTRL_SANICAP_BES_MASK	= 0x1,
	NVME_CTRL_SANICAP_OWS_MASK	= 0x1,
	NVME_CTRL_SANICAP_VERS_MASK	= 0x1,
	NVME_CTRL_SANICAP_NVERS_MASK	= 0x1,
	NVME_CTRL_SANICAP_SPRRS_MASK	= 0x1,
	NVME_CTRL_SANICAP_NDI_MASK	= 0x1,
	NVME_CTRL_SANICAP_NODMMAS_MASK	= 0x3,
	NVME_CTRL_SANICAP_CES		= NVME_VAL(CTRL_SANICAP_CES),
	NVME_CTRL_SANICAP_BES		= NVME_VAL(CTRL_SANICAP_BES),
	NVME_CTRL_SANICAP_OWS		= NVME_VAL(CTRL_SANICAP_OWS),
	NVME_CTRL_SANICAP_VERS		= NVME_VAL(CTRL_SANICAP_VERS),
	NVME_CTRL_SANICAP_NVERS		= NVME_VAL(CTRL_SANICAP_NVERS),
	NVME_CTRL_SANICAP_SPRRS		= NVME_VAL(CTRL_SANICAP_SPRRS),
	NVME_CTRL_SANICAP_NDI		= NVME_VAL(CTRL_SANICAP_NDI),
	NVME_CTRL_SANICAP_NODMMAS	= NVME_VAL(CTRL_SANICAP_NODMMAS),
};

#define NVME_CTRL_SANICAP_CES(sanicap)     NVME_GET(sanicap, CTRL_SANICAP_CES)
#define NVME_CTRL_SANICAP_BES(sanicap)     NVME_GET(sanicap, CTRL_SANICAP_BES)
#define NVME_CTRL_SANICAP_OWS(sanicap)     NVME_GET(sanicap, CTRL_SANICAP_OWS)
#define NVME_CTRL_SANICAP_VERS(sanicap)    NVME_GET(sanicap, CTRL_SANICAP_VERS)
#define NVME_CTRL_SANICAP_NVERS(sanicap)   NVME_GET(sanicap, CTRL_SANICAP_NVERS)
#define NVME_CTRL_SANICAP_SPRRS(sanicap)   NVME_GET(sanicap, CTRL_SANICAP_SPRRS)
#define NVME_CTRL_SANICAP_NDI(sanicap)     NVME_GET(sanicap, CTRL_SANICAP_NDI)
#define NVME_CTRL_SANICAP_NODMMAS(sanicap) \
	NVME_GET(sanicap, CTRL_SANICAP_NODMMAS)

/**
 * enum nvme_id_ctrl_anacap - This field indicates the capabilities associated
 *			      with Asymmetric Namespace Access Reporting.
 * @NVME_CTRL_ANACAP_OPT:	      If set, then the controller is able to
 *				      report ANA Optimized state.
 * @NVME_CTRL_ANACAP_NON_OPT:	      If set, then the controller is able to
 *				      report ANA Non-Optimized state.
 * @NVME_CTRL_ANACAP_INACCESSIBLE:    If set, then the controller is able to
 *				      report ANA Inaccessible state.
 * @NVME_CTRL_ANACAP_PERSISTENT_LOSS: If set, then the controller is able to
 *				      report ANA Persistent Loss state.
 * @NVME_CTRL_ANACAP_CHANGE:	      If set, then the controller is able to
 *				      report ANA Change state.
 * @NVME_CTRL_ANACAP_GRPID_NO_CHG:    If set, then the ANAGRPID field in the
 *				      Identify Namespace data structure
 *				      (&struct nvme_id_ns.anagrpid), does not
 *				      change while the namespace is attached to
 *				      any controller.
 * @NVME_CTRL_ANACAP_GRPID_MGMT:      If set, then the controller supports a
 *				      non-zero value in the ANAGRPID field of
 *				      the Namespace Management command.
 */
enum nvme_id_ctrl_anacap {
	NVME_CTRL_ANACAP_OPT			= 1 << 0,
	NVME_CTRL_ANACAP_NON_OPT		= 1 << 1,
	NVME_CTRL_ANACAP_INACCESSIBLE		= 1 << 2,
	NVME_CTRL_ANACAP_PERSISTENT_LOSS	= 1 << 3,
	NVME_CTRL_ANACAP_CHANGE			= 1 << 4,
	NVME_CTRL_ANACAP_GRPID_NO_CHG		= 1 << 6,
	NVME_CTRL_ANACAP_GRPID_MGMT		= 1 << 7,
};


/**
 * enum nvme_id_ctrl_kpioc - Key Per I/O Capabilities
 * @NVME_CTRL_KPIOC_KPIOS_SHIFT:	Shift amount to get the Key Per I/O Supported from the
 *					&struct nvme_id_ctrl.kpioc field.
 * @NVME_CTRL_KPIOC_KPIOSC_SHIFT:	Shift amount to get the Key Per I/O Scope from the
 *					&struct nvme_id_ctrl.kpioc field.
 * @NVME_CTRL_KPIOC_KPIOS_MASK:		Mask to get the Key Per I/O Supported from the
 *					&struct nvme_id_ctrl.kpioc field.
 * @NVME_CTRL_KPIOC_KPIOSC_MASK:	Mask to get the Key Per I/O Scope from the
 *					&struct nvme_id_ctrl.kpioc field.
 */
enum nvme_id_ctrl_kpioc {
	NVME_CTRL_KPIOC_KPIOS_SHIFT	= 0,
	NVME_CTRL_KPIOC_KPIOSC_SHIFT	= 1,
	NVME_CTRL_KPIOC_KPIOS_MASK	= 0x1,
	NVME_CTRL_KPIOC_KPIOSC_MASK	= 0x1,
};

#define NVME_CTRL_KPIOC_KPIOS(kpioc)	NVME_GET(kpioc, CTRL_KPIOC_KPIOS)
#define NVME_CTRL_KPIOC_KPIOSC(kpioc)	NVME_GET(kpioc, CTRL_KPIOC_KPIOSC)

/**
 * enum nvme_id_ctrl_cdpa - Configurable Device Personality Attributes
 * @NVME_CTRL_CDPA_HMAC_SHA_384:    If set, then the controller supports
 *					the HMAC-SHA-384 standard.
 */
enum nvme_id_ctrl_cdpa {
	NVME_CTRL_CDPA_HMAC_SHA_384		= 1 << 0,
};

/**
 * enum nvme_id_ctrl_ipmsr - Interval Power Measurement Sample Rate
 * @NVME_CTRL_IPMSR_SRS_SHIFT:	Shift amount to get the Sample Rate
 *		Scale from the &struct nvme_id_ctrl.ipmsr field.
 * @NVME_CTRL_IPMSR_SRV_SHIFT:	Shift amount to get the Sample Rate
 *		Value from the &struct nvme_id_ctrl.ipmsr field.
 * @NVME_CTRL_IPMSR_SRS_MASK:	Mask to get the Sample Rate Scale
 *		from the &struct nvme_id_ctrl.ipmsr field.
 * @NVME_CTRL_IPMSR_SRV_MASK:	Mask to get the Sample Rate Value
 *		from the &struct nvme_id_ctrl.ipmsr field.
 */
enum nvme_id_ctrl_ipmsr {
	NVME_CTRL_IPMSR_SRS_SHIFT	= 8,
	NVME_CTRL_IPMSR_SRV_SHIFT	= 0,
	NVME_CTRL_IPMSR_SRS_MASK	= 0x00FF,
	NVME_CTRL_IPMSR_SRV_MASK	= 0x00FF,
};

#define NVME_CTRL_IPMSR_SRS(ipmsr)	NVME_GET(ipmsr, CTRL_IPMSR_SRS)
#define NVME_CTRL_IPMSR_SRV(ipmsr)	NVME_GET(ipmsr, CTRL_IPMSR_SRV)

/**
 * enum nvme_id_ctrl_sqes - Defines the required and maximum Submission Queue
 *			    entry size when using the NVM Command Set.
 * @NVME_CTRL_SQES_MIN: Mask to get the value of the required Submission Queue
 *			Entry size when using the NVM Command Set.
 * @NVME_CTRL_SQES_MAX: Mask to get the value of the maximum Submission Queue
 *			entry size when using the NVM Command Set.
 */
enum nvme_id_ctrl_sqes {
	NVME_CTRL_SQES_MIN			= 0xf << 0,
	NVME_CTRL_SQES_MAX			= 0xf << 4,
};

/**
 * enum nvme_id_ctrl_cqes - Defines the required and maximum Completion Queue
 *			    entry size when using the NVM Command Set.
 * @NVME_CTRL_CQES_MIN: Mask to get the value of the required Completion Queue
 *			Entry size when using the NVM Command Set.
 * @NVME_CTRL_CQES_MAX: Mask to get the value of the maximum Completion Queue
 *			entry size when using the NVM Command Set.
 */
enum nvme_id_ctrl_cqes {
	NVME_CTRL_CQES_MIN			= 0xf << 0,
	NVME_CTRL_CQES_MAX			= 0xf << 4,
};

/**
 * enum nvme_id_ctrl_oncs - This field indicates the optional NVM commands and
 *			    features supported by the controller.
 * @NVME_CTRL_ONCS_COMPARE:		If set, then the controller supports
 *					the Compare command.
 * @NVME_CTRL_ONCS_WRITE_UNCORRECTABLE:	If set, then the controller supports
 *					the Write Uncorrectable command.
 * @NVME_CTRL_ONCS_DSM:			If set, then the controller supports
 *					the Dataset Management command.
 * @NVME_CTRL_ONCS_WRITE_ZEROES:	If set, then the controller supports
 *					the Write Zeroes command.
 * @NVME_CTRL_ONCS_SAVE_FEATURES:	If set, then the controller supports
 *					the Save field set to a non-zero value
 *					in the Set Features command and the
 *					Select field set to a non-zero value in
 *					the Get Features command.
 * @NVME_CTRL_ONCS_RESERVATIONS:	If set, then the controller supports
 *					reservations.
 * @NVME_CTRL_ONCS_TIMESTAMP:		If set, then the controller supports
 *					the Timestamp feature.
 * @NVME_CTRL_ONCS_VERIFY:		If set, then the controller supports
 *					the Verify command.
 * @NVME_CTRL_ONCS_COPY:		If set, then the controller supports
 *					the copy command.
 * @NVME_CTRL_ONCS_COPY_SINGLE_ATOMICITY: If set, then the write portion of a
 *					Copy command is performed as a single
 *					write command to which the same
 *					atomicity requirements that apply to
 *					a write command apply.
 * @NVME_CTRL_ONCS_ALL_FAST_COPY:	If set, then all copy operations for
 *					the Copy command are fast copy
 *					operations.
 * @NVME_CTRL_ONCS_WRITE_ZEROES_DEALLOCATE: If MAXWZD bit set, then the maximum data
 *					size for Write Zeroes command depends on the
 *					value of the Deallocate bit in the Write Zeroes
 *					command and the value in the WZDSL field in the
 *					I/O Command Set specific Identify Controller
 *					data structure.
 * @NVME_CTRL_ONCS_NAMESPACE_ZEROES:	If NSZS bit set, then the controller supports
 *					the Namespace Zeroes (NSZ) bit in the NVM
 *					Command Set Write Zeroes command.
 */
enum nvme_id_ctrl_oncs {
	NVME_CTRL_ONCS_COMPARE			= 1 << 0,
	NVME_CTRL_ONCS_WRITE_UNCORRECTABLE	= 1 << 1,
	NVME_CTRL_ONCS_DSM			= 1 << 2,
	NVME_CTRL_ONCS_WRITE_ZEROES		= 1 << 3,
	NVME_CTRL_ONCS_SAVE_FEATURES		= 1 << 4,
	NVME_CTRL_ONCS_RESERVATIONS		= 1 << 5,
	NVME_CTRL_ONCS_TIMESTAMP		= 1 << 6,
	NVME_CTRL_ONCS_VERIFY			= 1 << 7,
	NVME_CTRL_ONCS_COPY			= 1 << 8,
	NVME_CTRL_ONCS_COPY_SINGLE_ATOMICITY	= 1 << 9,
	NVME_CTRL_ONCS_ALL_FAST_COPY		= 1 << 10,
	NVME_CTRL_ONCS_WRITE_ZEROES_DEALLOCATE	= 1 << 11,
	NVME_CTRL_ONCS_NAMESPACE_ZEROES		= 1 << 12,
};

/**
 * enum nvme_id_ctrl_fuses - This field indicates the fused operations that the
 *			     controller supports.
 * @NVME_CTRL_FUSES_COMPARE_AND_WRITE: If set, then the controller supports the
 *				       Compare and Write fused operation.
 */
enum nvme_id_ctrl_fuses {
	NVME_CTRL_FUSES_COMPARE_AND_WRITE	= 1 << 0,
};

/**
 * enum nvme_id_ctrl_fna - This field indicates attributes for the Format NVM
 *			   command.
 * @NVME_CTRL_FNA_FMT_ALL_NS_SHIFT:   Shift amount to get the format applied to all namespaces
 * @NVME_CTRL_FNA_SEC_ALL_NS_SHIFT:   Shift amount to get the secure erase applied to all namespaces
 * @NVME_CTRL_FNA_CES_SHIFT:          Shift amount to get the cryptographic erase supported
 * @NVME_CTRL_FNA_NSID_ALL_F_SHIFT:   Shift amount to get the format supported an NSID FFFFFFFFh
 * @NVME_CTRL_FNA_FMT_ALL_NS_MASK:    Mask to get the format applied to all namespaces
 * @NVME_CTRL_FNA_SEC_ALL_NS_MASK:    Mask to get the secure erase applied to all namespaces
 * @NVME_CTRL_FNA_CES_MASK:           Mask to get the cryptographic erase supported
 * @NVME_CTRL_FNA_NSID_ALL_F_MASK:    Mask to get the format supported an NSID FFFFFFFFh
 * @NVME_CTRL_FNA_FMT_ALL_NAMESPACES: If set, then all namespaces in an NVM
 *				      subsystem shall be configured with the
 *				      same attributes and a format (excluding
 *				      secure erase) of any namespace results in
 *				      a format of all namespaces in an NVM
 *				      subsystem. If cleared, then the
 *				      controller supports format on a per
 *				      namespace basis.
 * @NVME_CTRL_FNA_SEC_ALL_NAMESPACES: If set, then any secure erase performed
 *				      as part of a format operation results in
 *				      a secure erase of all namespaces in the
 *				      NVM subsystem. If cleared, then any
 *				      secure erase performed as part of a
 *				      format results in a secure erase of the
 *				      particular namespace specified.
 * @NVME_CTRL_FNA_CRYPTO_ERASE:	      If set, then cryptographic erase is
 *				      supported. If cleared, then cryptographic
 *				      erase is not supported.
 * @NVME_CTRL_FNA_NSID_FFFFFFFF:      If set, then format does not support
 *				      nsid value set to FFFFFFFFh. If cleared,
 *				      format supports nsid value set to
 *				      FFFFFFFFh.
 */
enum nvme_id_ctrl_fna {
	NVME_CTRL_FNA_FMT_ALL_NS_SHIFT		= 0,
	NVME_CTRL_FNA_SEC_ALL_NS_SHIFT		= 1,
	NVME_CTRL_FNA_CES_SHIFT			= 2,
	NVME_CTRL_FNA_NSID_ALL_F_SHIFT		= 3,
	NVME_CTRL_FNA_FMT_ALL_NS_MASK		= 0x1,
	NVME_CTRL_FNA_SEC_ALL_NS_MASK		= 0x1,
	NVME_CTRL_FNA_CES_MASK			= 0x1,
	NVME_CTRL_FNA_NSID_ALL_F_MASK		= 0x1,
	NVME_CTRL_FNA_FMT_ALL_NAMESPACES	= NVME_VAL(CTRL_FNA_FMT_ALL_NS),
	NVME_CTRL_FNA_SEC_ALL_NAMESPACES	= NVME_VAL(CTRL_FNA_SEC_ALL_NS),
	NVME_CTRL_FNA_CRYPTO_ERASE		= NVME_VAL(CTRL_FNA_CES),
	NVME_CTRL_FNA_NSID_FFFFFFFF		= NVME_VAL(CTRL_FNA_NSID_ALL_F),
};

#define NVME_CTRL_FNA_FMT_ALL_NS(fna)	NVME_GET(fna, CTRL_FNA_FMT_ALL_NS)
#define NVME_CTRL_FNA_SEC_ALL_NS(fna)	NVME_GET(fna, CTRL_FNA_SEC_ALL_NS)
#define NVME_CTRL_FNA_CES(fna)		NVME_GET(fna, CTRL_FNA_CES)
#define NVME_CTRL_FNA_NSID_ALL_F(fna)	NVME_GET(fna, CTRL_FNA_NSID_ALL_F)

/**
 * enum nvme_id_ctrl_vwc - Volatile write cache
 * @NVME_CTRL_VWC_PRESENT: If set, indicates a volatile write cache is present.
 *			   If a volatile write cache is present, then the host
 *			   controls whether the volatile write cache is enabled
 *			   with a Set Features command specifying the value
 *			   %NVME_FEAT_FID_VOLATILE_WC.
 * @NVME_CTRL_VWC_FLUSH:   Mask to get the value of the flush command behavior.
 */
enum nvme_id_ctrl_vwc {
	NVME_CTRL_VWC_PRESENT			= 1 << 0,
	NVME_CTRL_VWC_FLUSH			= 3 << 1,
};

/**
 * enum nvme_id_ctrl_nvscc - This field indicates the configuration settings
 *			     for NVM Vendor Specific command handling.
 * @NVME_CTRL_NVSCC_FMT: If set, all NVM Vendor Specific Commands use the
 *			 format with NDT and NDM fields.
 */
enum nvme_id_ctrl_nvscc {
	NVME_CTRL_NVSCC_FMT			= 1 << 0,
};

/**
 * enum nvme_id_ctrl_nwpc - This field indicates the optional namespace write
 *			    protection capabilities supported by the
 *			    controller.
 * @NVME_CTRL_NWPC_WRITE_PROTECT:	     If set, then the controller shall
 *					      support the No Write Protect and
 *					      Write Protect namespace write
 *					      protection states and may support
 *					      the Write Protect Until Power
 *					      Cycle state and Permanent Write
 *					      Protect namespace write
 *					      protection states.
 * @NVME_CTRL_NWPC_WRITE_PROTECT_POWER_CYCLE: If set, then the controller
 *					      supports the Write Protect Until
 *					      Power Cycle state.
 * @NVME_CTRL_NWPC_WRITE_PROTECT_PERMANENT:   If set, then the controller
 *					      supports the Permanent Write
 *					      Protect state.
 */
enum nvme_id_ctrl_nwpc {
	NVME_CTRL_NWPC_WRITE_PROTECT		= 1 << 0,
	NVME_CTRL_NWPC_WRITE_PROTECT_POWER_CYCLE= 1 << 1,
	NVME_CTRL_NWPC_WRITE_PROTECT_PERMANENT	= 1 << 2,
};

/**
 * enum nvme_id_ctrl_sgls - This field indicates if SGLs are supported for the
 *			    NVM Command Set and the particular SGL types supported.
 * @NVME_CTRL_SGLS_SUPPORTED:
 * @NVME_CTRL_SGLS_KEYED:
 * @NVME_CTRL_SGLS_BIT_BUCKET:
 * @NVME_CTRL_SGLS_MPTR_BYTE_ALIGNED:
 * @NVME_CTRL_SGLS_OVERSIZE:
 * @NVME_CTRL_SGLS_MPTR_SGL:
 * @NVME_CTRL_SGLS_OFFSET:
 * @NVME_CTRL_SGLS_TPORT:
 */
enum nvme_id_ctrl_sgls {
	NVME_CTRL_SGLS_SUPPORTED		= 3 << 0,
	NVME_CTRL_SGLS_KEYED			= 1 << 2,
	NVME_CTRL_SGLS_BIT_BUCKET		= 1 << 16,
	NVME_CTRL_SGLS_MPTR_BYTE_ALIGNED	= 1 << 17,
	NVME_CTRL_SGLS_OVERSIZE			= 1 << 18,
	NVME_CTRL_SGLS_MPTR_SGL			= 1 << 19,
	NVME_CTRL_SGLS_OFFSET			= 1 << 20,
	NVME_CTRL_SGLS_TPORT			= 1 << 21,
};

/**
 * enum nvme_id_ctrl_trattr - Tracking Attributes
 * @NVME_CTRL_TRATTR_THMCS_SHIFT:	Shift amount to get the Track Host Memory Changes Support
 *					from the &struct nvme_id_ctrl.trattr field.
 * @NVME_CTRL_TRATTR_TUDCS_SHIFT:	Shift amount to get the Track User Data Changes Support
 *					from the &struct nvme_id_ctrl.trattr field.
 * @NVME_CTRL_TRATTR_MRTLL_SHIFT:	Shift amount to get the Memory Range Tracking Length Limit
 *					from the &struct nvme_id_ctrl.trattr field.
 * @NVME_CTRL_TRATTR_THMCS_MASK:	Mask to get the Track Host Memory Changes Support
 *					from the &struct nvme_id_ctrl.trattr field.
 * @NVME_CTRL_TRATTR_TUDCS_MASK:	Mask to get the Track User Data Changes Support
 *					from the &struct nvme_id_ctrl.trattr field.
 * @NVME_CTRL_TRATTR_MRTLL_MASK:	Mask to get the Memory Range Tracking Length Limit
 *					from the &struct nvme_id_ctrl.trattr field.
 */
enum nvme_id_ctrl_trattr {
	NVME_CTRL_TRATTR_THMCS_SHIFT	= 0,
	NVME_CTRL_TRATTR_TUDCS_SHIFT	= 1,
	NVME_CTRL_TRATTR_MRTLL_SHIFT	= 2,
	NVME_CTRL_TRATTR_THMCS_MASK	= 0x1,
	NVME_CTRL_TRATTR_TUDCS_MASK	= 0x1,
	NVME_CTRL_TRATTR_MRTLL_MASK	= 0x1,
};

#define NVME_CTRL_TRATTR_THMCS(trattr)	NVME_GET(trattr, CTRL_TRATTR_THMCS)
#define NVME_CTRL_TRATTR_TUDCS(trattr)	NVME_GET(trattr, CTRL_TRATTR_TUDCS)
#define NVME_CTRL_TRATTR_MRTLL(trattr)	NVME_GET(trattr, CTRL_TRATTR_MRTLL)

/**
 * enum nvme_id_ctrl_fcatt - This field indicates attributes of the controller
 *			     that are specific to NVMe over Fabrics.
 * @NVME_CTRL_FCATT_DYNAMIC: If cleared, then the NVM subsystem uses a dynamic
 *			     controller model. If set, then the NVM subsystem
 *			     uses a static controller model.
 */
enum nvme_id_ctrl_fcatt {
	NVME_CTRL_FCATT_DYNAMIC			= 1 << 0,
};

/**
 * enum nvme_id_ctrl_ofcs - Indicate whether the controller supports optional
 *			    fabric commands.
 * @NVME_CTRL_OFCS_DISCONNECT: If set, then the controller supports the
 *			       Disconnect command and deletion of individual
 *			       I/O Queues.
 */
enum nvme_id_ctrl_ofcs {
	NVME_CTRL_OFCS_DISCONNECT		= 1 << 0,
};

/**
 * struct nvme_lbaf - LBA Format Data Structure
 * @ms: Metadata Size indicates the number of metadata bytes provided per LBA
 *	based on the LBA Data Size indicated.
 * @ds:	LBA Data Size indicates the LBA data size supported, reported as a
 *	power of two.
 * @rp:	Relative Performance, see &enum nvme_lbaf_rp.
 */
struct nvme_lbaf {
	__le16			ms;
	__u8			ds;
	__u8			rp;
};

/**
 * enum nvme_lbaf_rp - This field indicates the relative performance of the LBA
 *		       format indicated relative to other LBA formats supported
 *		       by the controller.
 * @NVME_LBAF_RP_BEST:	   Best performance
 * @NVME_LBAF_RP_BETTER:   Better performance
 * @NVME_LBAF_RP_GOOD:	   Good performance
 * @NVME_LBAF_RP_DEGRADED: Degraded performance
 * @NVME_LBAF_RP_SHIFT: Relative performance shift
 * @NVME_LBAF_RP_MASK:	   Mask to get the relative performance value from the
 *			   field
 */
enum nvme_lbaf_rp {
	NVME_LBAF_RP_BEST	= 0,
	NVME_LBAF_RP_BETTER	= 1,
	NVME_LBAF_RP_GOOD	= 2,
	NVME_LBAF_RP_DEGRADED	= 3,
	NVME_LBAF_RP_SHIFT	= 0,
	NVME_LBAF_RP_MASK	= 3,
};

/**
 * struct nvme_id_ns - Identify Namespace data structure
 * @nsze:     Namespace Size indicates the total size of the namespace in
 *	      logical blocks. The number of logical blocks is based on the
 *	      formatted LBA size.
 * @ncap:     Namespace Capacity indicates the maximum number of logical blocks
 *	      that may be allocated in the namespace at any point in time. The
 *	      number of logical blocks is based on the formatted LBA size.
 * @nuse:     Namespace Utilization indicates the current number of logical
 *	      blocks allocated in the namespace. This field is smaller than or
 *	      equal to the Namespace Capacity. The number of logical blocks is
 *	      based on the formatted LBA size.
 * @nsfeat:   Namespace Features, see &enum nvme_id_nsfeat.
 * @nlbaf:    Number of LBA Formats defines the number of supported LBA data
 *	      size and metadata size combinations supported by the namespace
 *	      and the highest possible index to &struct nvme_id_ns.lbaf.
 * @flbas:    Formatted LBA Size, see &enum nvme_id_ns_flbas.
 * @mc:	      Metadata Capabilities, see &enum nvme_id_ns_mc.
 * @dpc:      End-to-end Data Protection Capabilities, see
 *	      &enum nvme_id_ns_dpc.
 * @dps:      End-to-end Data Protection Type Settings, see
 *	      &enum nvme_id_ns_dps.
 * @nmic:     Namespace Multi-path I/O and Namespace Sharing Capabilities, see
 *	      &enum nvme_id_ns_nmic.
 * @rescap:   Reservation Capabilities, see &enum nvme_id_ns_rescap.
 * @fpi:      Format Progress Indicator, see &enum nvme_nd_ns_fpi.
 * @dlfeat:   Deallocate Logical Block Features, see &enum nvme_id_ns_dlfeat.
 * @nawun:    Namespace Atomic Write Unit Normal indicates the
 *	      namespace specific size of the write operation guaranteed to be
 *	      written atomically to the NVM during normal operation.
 * @nawupf:   Namespace Atomic Write Unit Power Fail indicates the
 *	      namespace specific size of the write operation guaranteed to be
 *	      written atomically to the NVM during a power fail or error
 *	      condition.
 * @nacwu:    Namespace Atomic Compare & Write Unit indicates the namespace
 *	      specific size of the write operation guaranteed to be written
 *	      atomically to the NVM for a Compare and Write fused command.
 * @nabsn:    Namespace Atomic Boundary Size Normal indicates the atomic
 *	      boundary size for this namespace for the NAWUN value. This field
 *	      is specified in logical blocks.
 * @nabo:     Namespace Atomic Boundary Offset indicates the LBA on this
 *	      namespace where the first atomic boundary starts.
 * @nabspf:   Namespace Atomic Boundary Size Power Fail indicates the atomic
 *	      boundary size for this namespace specific to the Namespace Atomic
 *	      Write Unit Power Fail value. This field is specified in logical
 *	      blocks.
 * @noiob:    Namespace Optimal I/O Boundary indicates the optimal I/O boundary
 *	      for this namespace. This field is specified in logical blocks.
 *	      The host should construct Read and Write commands that do not
 *	      cross the I/O boundary to achieve optimal performance.
 * @nvmcap:   NVM Capacity indicates the total size of the NVM allocated to
 *	      this namespace. The value is in bytes.
 * @npwg:     Namespace Preferred Write Granularity indicates the smallest
 *	      recommended write granularity in logical blocks for this
 *	      namespace. This is a 0's based value.
 * @npwa:     Namespace Preferred Write Alignment indicates the recommended
 *	      write alignment in logical blocks for this namespace. This is a
 *	      0's based value.
 * @npdg:     Namespace Preferred Deallocate Granularity indicates the
 *	      recommended granularity in logical blocks for the Dataset
 *	      Management command with the Attribute - Deallocate bit.
 * @npda:     Namespace Preferred Deallocate Alignment indicates the
 *	      recommended alignment in logical blocks for the Dataset
 *	      Management command with the Attribute - Deallocate bit
 * @nows:     Namespace Optimal Write Size indicates the size in logical blocks
 *	      for optimal write performance for this namespace. This is a 0's
 *	      based value.
 * @mssrl:    Maximum Single Source Range Length indicates the maximum number
 *	  of logical blocks that may be specified in each valid Source Range
 *	  field of a Copy command.
 * @mcl:      Maximum Copy Length indicates the maximum number of logical
 *	  blocks that may be specified in a Copy command.
 * @msrc:     Maximum Source Range Count indicates the maximum number of Source
 *	  Range entries that may be used to specify source data in a Copy
 *	  command. This is a 0’s based value.
 * @kpios:    Key Per I/O Status indicates namespace Key Per I/O capability status.
 * @nulbaf:   Number of Unique Capability LBA Formats defines the number of
 *	  supported user data size and metadata size combinations supported
 *	  by the namespace that may not share the same capabilities. LBA
 *	  formats shall be allocated in order and packed sequentially.
 * @rsvd83:   Reserved
 * @kpiodaag: Key Per I/O Data Access Alignment and Granularity indicates the
 *	      alignment and granularity in logical blocks that is required
 *	      for commands that support a KPIOTAG value in the CETYPE field.
 * @rsvd88:   Reserved
 * @anagrpid: ANA Group Identifier indicates the ANA Group Identifier of the
 *	      ANA group of which the namespace is a member.
 * @rsvd96:   Reserved
 * @nsattr:   Namespace Attributes, see &enum nvme_id_ns_attr.
 * @nvmsetid: NVM Set Identifier indicates the NVM Set with which this
 *	      namespace is associated.
 * @endgid:   Endurance Group Identifier indicates the Endurance Group with
 *	      which this namespace is associated.
 * @nguid:    Namespace Globally Unique Identifier contains a 128-bit value
 *	      that is globally unique and assigned to the namespace when the
 *	      namespace is created. This field remains fixed throughout the
 *	      life of the namespace and is preserved across namespace and
 *	      controller operations
 * @eui64:    IEEE Extended Unique Identifier contains a 64-bit IEEE Extended
 *	      Unique Identifier (EUI-64) that is globally unique and assigned
 *	      to the namespace when the namespace is created. This field
 *	      remains fixed throughout the life of the namespace and is
 *	      preserved across namespace and controller operations
 * @lbaf:     LBA Format, see &struct nvme_lbaf.
 * @vs:	      Vendor Specific
 */
struct nvme_id_ns {
	__le64			nsze;
	__le64			ncap;
	__le64			nuse;
	__u8			nsfeat;
	__u8			nlbaf;
	__u8			flbas;
	__u8			mc;
	__u8			dpc;
	__u8			dps;
	__u8			nmic;
	__u8			rescap;
	__u8			fpi;
	__u8			dlfeat;
	__le16			nawun;
	__le16			nawupf;
	__le16			nacwu;
	__le16			nabsn;
	__le16			nabo;
	__le16			nabspf;
	__le16			noiob;
	__u8			nvmcap[16];
	__le16			npwg;
	__le16			npwa;
	__le16			npdg;
	__le16			npda;
	__le16			nows;
	__le16			mssrl;
	__le32			mcl;
	__u8			msrc;
	__u8			kpios;
	__u8			nulbaf;
	__u8			rsvd83;
	__le32			kpiodaag;
	__u8			rsvd88[4];
	__le32			anagrpid;
	__u8			rsvd96[3];
	__u8			nsattr;
	__le16			nvmsetid;
	__le16			endgid;
	__u8			nguid[16];
	__u8			eui64[8];
	struct nvme_lbaf	lbaf[64];
	__u8			vs[3712];
};

/**
 * enum nvme_id_nsfeat - This field defines features of the namespace.
 * @NVME_NS_FEAT_THIN:	   If set, indicates that the namespace supports thin
 *			   provisioning. Specifically, the Namespace Capacity
 *			   reported may be less than the Namespace Size.
 * @NVME_NS_FEAT_NATOMIC:  If set, indicates that the fields NAWUN, NAWUPF, and
 *			   NACWU are defined for this namespace and should be
 *			   used by the host for this namespace instead of the
 *			   AWUN, AWUPF, and ACWU fields in the Identify
 *			   Controller data structure.
 * @NVME_NS_FEAT_DULBE:	   If set, indicates that the controller supports the
 *			   Deallocated or Unwritten Logical Block error for
 *			   this namespace.
 * @NVME_NS_FEAT_ID_REUSE: If set, indicates that the value in the NGUID field
 *			   for this namespace, if non- zero, is never reused by
 *			   the controller and that the value in the EUI64 field
 *			   for this namespace, if non-zero, is never reused by
 *			   the controller.
 * @NVME_NS_FEAT_IO_OPT:   If set, indicates that the fields NPWG, NPWA, NPDG,
 *			   NPDA, and NOWS are defined for this namespace and
 *			   should be used by the host for I/O optimization
 */
enum nvme_id_nsfeat {
	NVME_NS_FEAT_THIN		= 1 << 0,
	NVME_NS_FEAT_NATOMIC		= 1 << 1,
	NVME_NS_FEAT_DULBE		= 1 << 2,
	NVME_NS_FEAT_ID_REUSE		= 1 << 3,
	NVME_NS_FEAT_IO_OPT		= 3 << 4,
};

/**
 * enum nvme_id_ns_flbas - This field indicates the LBA data size & metadata
 *			   size combination that the namespace has been
 *			   formatted with
 * @NVME_NS_FLBAS_LOWER_SHIFT:	Shift to get the lower 4 bits of LBA format index
 * @NVME_NS_FLBAS_LOWER_MASK:	Mask to get the index of one of the supported
 *				LBA Formats's least significant
 *				4bits indicated in
 *				:c:type:`struct nvme_id_ns <nvme_id_ns>`.lbaf.
 * @NVME_NS_FLBAS_META_EXT:	Applicable only if format contains metadata. If
 *				this bit is set, indicates that the metadata is
 *				transferred at the end of the data LBA, creating an
 *				extended data LBA. If cleared, indicates that all
 *				of the metadata for a command is transferred as a
 *				separate contiguous buffer of data.
 * @NVME_NS_FLBAS_HIGHER_SHIFT:	Shift to get the higher 2 bits of LBA format index
 * @NVME_NS_FLBAS_HIGHER_MASK:	Mask to get the index of one of
 *				the supported LBA Formats's most significant
 *				2bits indicated in
 *				:c:type:`struct nvme_id_ns <nvme_id_ns>`.lbaf.
 */
enum nvme_id_ns_flbas {
	NVME_NS_FLBAS_LOWER_SHIFT	= 0,
	NVME_NS_FLBAS_LOWER_MASK	= 0xf,
	NVME_NS_FLBAS_META_EXT		= 1 << 4,
	NVME_NS_FLBAS_HIGHER_SHIFT	= 5,
	NVME_NS_FLBAS_HIGHER_MASK	= 0x3,
};

#define NVME_NS_FLBAS_LOWER(flbas)	NVME_GET(flbas, NS_FLBAS_LOWER)
#define NVME_NS_FLBAS_HIGHER(flbas)	NVME_GET(flbas, NS_FLBAS_HIGHER)


/**
 * enum nvme_id_ns_mc - This field indicates the capabilities for metadata.
 * @NVME_NS_MC_EXTENDED: If set, indicates the namespace supports the metadata
 *			 being transferred as part of a separate buffer that is
 *			 specified in the Metadata Pointer.
 * @NVME_NS_MC_SEPARATE: If set, indicates that the namespace supports the
 *			 metadata being transferred as part of an extended data LBA.
 */
enum nvme_id_ns_mc {
	NVME_NS_MC_EXTENDED		= 1 << 0,
	NVME_NS_MC_SEPARATE		= 1 << 1,
};

/**
 * enum nvme_id_ns_dpc - This field indicates the capabilities for the
 *			 end-to-end data protection feature.
 * @NVME_NS_DPC_PI_TYPE1: If set, indicates that the namespace supports
 *			  Protection Information Type 1.
 * @NVME_NS_DPC_PI_TYPE2: If set, indicates that the namespace supports
 *			  Protection Information Type 2.
 * @NVME_NS_DPC_PI_TYPE3: If set, indicates that the namespace supports
 *			  Protection Information Type 3.
 * @NVME_NS_DPC_PI_FIRST: If set, indicates that the namespace supports
 *			  protection information transferred as the first eight
 *			  bytes of metadata.
 * @NVME_NS_DPC_PI_LAST:  If set, indicates that the namespace supports
 *			  protection information transferred as the last eight
 *			  bytes of metadata.
 */
enum nvme_id_ns_dpc {
	NVME_NS_DPC_PI_TYPE1		= 1 << 0,
	NVME_NS_DPC_PI_TYPE2		= 1 << 1,
	NVME_NS_DPC_PI_TYPE3		= 1 << 2,
	NVME_NS_DPC_PI_FIRST		= 1 << 3,
	NVME_NS_DPC_PI_LAST		= 1 << 4,
};

/**
 * enum nvme_id_ns_dps - This field indicates the Type settings for the
 *			 end-to-end data protection feature.
 * @NVME_NS_DPS_PI_NONE:  Protection information is not enabled
 * @NVME_NS_DPS_PI_TYPE1: Protection information is enabled, Type 1
 * @NVME_NS_DPS_PI_TYPE2: Protection information is enabled, Type 2
 * @NVME_NS_DPS_PI_TYPE3: Protection information is enabled, Type 3
 * @NVME_NS_DPS_PI_SHIFT: Protection information type shift
 * @NVME_NS_DPS_PI_MASK:  Mask to get the value of the PI type
 * @NVME_NS_DPS_PI_FIRST: If set, indicates that the protection information, if
 *			  enabled, is transferred as the first eight bytes of
 *			  metadata.
 * @NVME_NS_DPS_PI_FIRST_SHIFT: Protection information in first bytes shift
 * @NVME_NS_DPS_PI_FIRST_MASK: Protection information in first bytes mask
 */
enum nvme_id_ns_dps {
	NVME_NS_DPS_PI_NONE		= 0,
	NVME_NS_DPS_PI_TYPE1		= 1,
	NVME_NS_DPS_PI_TYPE2		= 2,
	NVME_NS_DPS_PI_TYPE3		= 3,
	NVME_NS_DPS_PI_SHIFT		= 0,
	NVME_NS_DPS_PI_MASK		= 0x7,
	NVME_NS_DPS_PI_FIRST_SHIFT	= 3,
	NVME_NS_DPS_PI_FIRST_MASK	= 0x1,
	NVME_NS_DPS_PI_FIRST		= NVME_VAL(NS_DPS_PI_FIRST),
};

#define NVME_NS_DPS_PI(dps)		NVME_GET(dps, NS_DPS_PI)
#define NVME_NS_DPS_PI_FIRST(dps)	NVME_GET(dps, NS_DPS_PI_FIRST)

/**
 * enum nvme_id_ns_nmic - This field specifies multi-path I/O and namespace
 *			  sharing capabilities of the namespace.
 * @NVME_NS_NMIC_SHARED: If set, then the namespace may be attached to two or
 *			 more controllers in the NVM subsystem concurrently
 */
enum nvme_id_ns_nmic {
	NVME_NS_NMIC_SHARED		= 1 << 0,
};

/**
 * enum nvme_id_ns_rescap - This field indicates the reservation capabilities
 *			    of the namespace.
 * @NVME_NS_RESCAP_PTPL:   If set, indicates that the namespace supports the
 *			   Persist Through Power Loss capability.
 * @NVME_NS_RESCAP_WE:	   If set, indicates that the namespace supports the
 *			   Write Exclusive reservation type.
 * @NVME_NS_RESCAP_EA:	   If set, indicates that the namespace supports the
 *			   Exclusive Access reservation type.
 * @NVME_NS_RESCAP_WERO:   If set, indicates that the namespace supports the
 *			   Write Exclusive - Registrants Only reservation type.
 * @NVME_NS_RESCAP_EARO:   If set, indicates that the namespace supports the
 *			   Exclusive Access - Registrants Only reservation type.
 * @NVME_NS_RESCAP_WEAR:   If set, indicates that the namespace supports the
 *			   Write Exclusive - All Registrants reservation type.
 * @NVME_NS_RESCAP_EAAR:   If set, indicates that the namespace supports the
 *			   Exclusive Access - All Registrants reservation type.
 * @NVME_NS_RESCAP_IEK_13: If set, indicates that Ignore Existing Key is used
 *			   as defined in revision 1.3 or later of this specification.
 */
enum nvme_id_ns_rescap {
	NVME_NS_RESCAP_PTPL		= 1 << 0,
	NVME_NS_RESCAP_WE		= 1 << 1,
	NVME_NS_RESCAP_EA		= 1 << 2,
	NVME_NS_RESCAP_WERO		= 1 << 3,
	NVME_NS_RESCAP_EARO		= 1 << 4,
	NVME_NS_RESCAP_WEAR		= 1 << 5,
	NVME_NS_RESCAP_EAAR		= 1 << 6,
	NVME_NS_RESCAP_IEK_13		= 1 << 7,
};

/**
 * enum nvme_nd_ns_fpi - If a format operation is in progress, this field
 *			 indicates the percentage of the namespace that remains
 *			 to be formatted.
 * @NVME_NS_FPI_REMAINING: Mask to get the format percent remaining value
 * @NVME_NS_FPI_SUPPORTED: If set, indicates that the namespace supports the
 *			   Format Progress Indicator defined for the field.
 */
enum nvme_nd_ns_fpi {
	NVME_NS_FPI_REMAINING		= 0x7f << 0,
	NVME_NS_FPI_SUPPORTED		= 1 << 7,
};

/**
 * enum nvme_id_ns_dlfeat - This field indicates information about features
 *			    that affect deallocating logical blocks for this
 *			    namespace.
 * @NVME_NS_DLFEAT_RB:		 Mask to get the value of the read behavior
 * @NVME_NS_DLFEAT_RB_NR:	 Read behvaior is not reported
 * @NVME_NS_DLFEAT_RB_ALL_0S:	 A deallocated logical block returns all bytes
 * cleared to 0h.
 * @NVME_NS_DLFEAT_RB_ALL_FS:	 A deallocated logical block returns all bytes
 *				 set to FFh.
 * @NVME_NS_DLFEAT_WRITE_ZEROES: If set, indicates that the controller supports
 *				 the Deallocate bit in the Write Zeroes command
 *				 for this namespace.
 * @NVME_NS_DLFEAT_CRC_GUARD:	 If set, indicates that the Guard field for
 *				 deallocated logical blocks that contain
 *				 protection information is set to the CRC for
 *				 the value read from the deallocated logical
 *				 block and its metadata
 */
enum nvme_id_ns_dlfeat {
	NVME_NS_DLFEAT_RB		= 7 << 0,
	NVME_NS_DLFEAT_RB_NR		= 0,
	NVME_NS_DLFEAT_RB_ALL_0S	= 1,
	NVME_NS_DLFEAT_RB_ALL_FS	= 2,
	NVME_NS_DLFEAT_WRITE_ZEROES	= 1 << 3,
	NVME_NS_DLFEAT_CRC_GUARD	= 1 << 4,
};

/**
 * enum nvme_id_ns_attr - Specifies attributes of the namespace.
 * @NVME_NS_NSATTR_WRITE_PROTECTED: If set, then the namespace is currently
 *				    write protected and all write access to the
 *				    namespace shall fail.
 */
enum nvme_id_ns_attr {
	NVME_NS_NSATTR_WRITE_PROTECTED	= 1 << 0
};

/**
 * struct nvme_ns_id_desc - Namespace identifier type descriptor
 * @nidt: Namespace Identifier Type, see &enum nvme_ns_id_desc_nidt
 * @nidl: Namespace Identifier Length contains the length in bytes of the
 *	  &struct nvme_id_ns.nid.
 * @rsvd: Reserved
 * @nid:  Namespace Identifier contains a value that is globally unique and
 *	  assigned to the namespace when the namespace is created. The length
 *	  is defined in &struct nvme_id_ns.nidl.
 */
struct nvme_ns_id_desc {
	__u8	nidt;
	__u8	nidl;
	__le16	rsvd;
	__u8	nid[];
} __attribute__((packed));

/**
 * enum nvme_ns_id_desc_nidt - Known namespace identifier types
 * @NVME_NIDT_EUI64: IEEE Extended Unique Identifier, the NID field contains a
 *		     copy of the EUI64 field in the struct nvme_id_ns.eui64.
 * @NVME_NIDT_NGUID: Namespace Globally Unique Identifier, the NID field
 *		     contains a copy of the NGUID field in struct nvme_id_ns.nguid.
 * @NVME_NIDT_UUID:  The NID field contains a 128-bit Universally Unique
 *		     Identifier (UUID) as specified in RFC 4122.
 * @NVME_NIDT_CSI:   The NID field contains the command set identifier.
 */
enum nvme_ns_id_desc_nidt {
	NVME_NIDT_EUI64		= 1,
	NVME_NIDT_NGUID		= 2,
	NVME_NIDT_UUID		= 3,
	NVME_NIDT_CSI		= 4,
};

/**
 * enum nvme_ns_id_desc_nidt_lens - Namespace Identifier Descriptor Type Lengths
 * @NVME_NIDT_EUI64_LEN:	IEEE Extended Unique Identifier length (8 bytes)
 * @NVME_NIDT_NGUID_LEN:	Namespace Globally Unique Identifier length (16 bytes)
 * @NVME_NIDT_UUID_LEN:		Universally Unique Identifier length (16 bytes)
 * @NVME_NIDT_CSI_LEN:		Command Set Identifier length (1 byte)
 */
enum nvme_ns_id_desc_nidt_lens {
	NVME_NIDT_EUI64_LEN		= 8,
	NVME_NIDT_NGUID_LEN		= 16,
	NVME_NIDT_UUID_LEN		= 16,
	NVME_NIDT_CSI_LEN		= 1,
};

/**
 * struct nvme_nvmset_attr - NVM Set Attributes Entry
 * @nvmsetid:	NVM Set Identifier
 * @endgid:	Endurance Group Identifier
 * @rsvd4:	Reserved
 * @rr4kt:	Random 4 KiB Read Typical indicates the typical
 *		time to complete a 4 KiB random read in 100 nanosecond units
 *		when the NVM Set is in a Predictable Latency Mode Deterministic
 *		Window and there is 1 outstanding command per NVM Set.
 * @ows:	Optimal Write Size
 * @tnvmsetcap:	Total NVM Set Capacity
 * @unvmsetcap:	Unallocated NVM Set Capacity
 * @rsvd48:	Reserved
 */
struct nvme_nvmset_attr {
	__le16			nvmsetid;
	__le16			endgid;
	__u8			rsvd4[4];
	__le32			rr4kt;
	__le32			ows;
	__u8			tnvmsetcap[16];
	__u8			unvmsetcap[16];
	__u8			rsvd48[80];
};

/**
 * struct nvme_id_nvmset_list - NVM set list
 * @nid:	Nvmset id
 * @rsvd1:	Reserved
 * @ent:	nvmset id list
 */
struct nvme_id_nvmset_list {
	__u8			nid;
	__u8			rsvd1[127];
	struct nvme_nvmset_attr	ent[NVME_ID_NVMSET_LIST_MAX];
};

/**
 * struct nvme_id_independent_id_ns - Identify - I/O Command Set Independent Identify Namespace Data Structure
 * @nsfeat:	common namespace features
 * @nmic:	Namespace Multi-path I/O and Namespace
 *		Sharing Capabilities
 * @rescap:	Reservation Capabilities
 * @fpi:	Format Progress Indicator
 * @anagrpid:	ANA Group Identifier
 * @nsattr:	Namespace Attributes
 * @rsvd9:	reserved
 * @nvmsetid:	NVM Set Identifier
 * @endgid:	Endurance Group Identifier
 * @nstat:	Namespace Status
 * @kpios:	Key Per I/O Status
 * @maxkt:	Maximum Key Tag
 * @rsvd18:	Reserved
 * @rgrpid:	Reachability Group Identifier
 * @rsvd24:	Reserved
 */
struct nvme_id_independent_id_ns {
	__u8	nsfeat;
	__u8	nmic;
	__u8	rescap;
	__u8	fpi;
	__le32	anagrpid;
	__u8	nsattr;
	__u8	rsvd9;
	__le16	nvmsetid;
	__le16	endgid;
	__u8	nstat;
	__u8	kpios;
	__le16	maxkt;
	__u8	rsvd18[2];
	__le32	rgrpid;
	__u8	rsvd24[4072];
};

/**
 * struct nvme_id_ns_granularity_desc -	 Namespace Granularity Descriptor
 * @nszegran:	Namespace Size Granularity
 * @ncapgran:	Namespace Capacity Granularity
 */
struct nvme_id_ns_granularity_desc {
	__le64			nszegran;
	__le64			ncapgran;
};

/**
 * struct nvme_id_ns_granularity_list - Namespace Granularity List
 * @attributes:		Namespace Granularity Attributes
 * @num_descriptors:	Number of Descriptors
 * @rsvd5:		reserved
 * @entry:		Namespace Granularity Descriptor
 * @rsvd288:		reserved
 */
struct nvme_id_ns_granularity_list {
	__le32			attributes;
	__u8			num_descriptors;
	__u8			rsvd5[27];
	struct nvme_id_ns_granularity_desc entry[NVME_ID_ND_DESCRIPTOR_MAX];
	__u8			rsvd288[3808];
};

/**
 * struct nvme_id_uuid_list_entry - UUID List Entry
 * @header:	UUID Lists Entry Header
 * @rsvd1:	reserved
 * @uuid:	128-bit Universally Unique Identifier
 */
struct nvme_id_uuid_list_entry {
	__u8			header;
	__u8			rsvd1[15];
	__u8			uuid[16];
};

/**
 * enum nvme_id_uuid - Identifier Association
 * @NVME_ID_UUID_HDR_ASSOCIATION_SHIFT:
 * @NVME_ID_UUID_HDR_ASSOCIATION_MASK:
 * @NVME_ID_UUID_ASSOCIATION_NONE:
 * @NVME_ID_UUID_ASSOCIATION_VENDOR:
 * @NVME_ID_UUID_ASSOCIATION_SUBSYSTEM_VENDOR:
 */
enum nvme_id_uuid {
	NVME_ID_UUID_HDR_ASSOCIATION_SHIFT		= 0,
	NVME_ID_UUID_HDR_ASSOCIATION_MASK		= 0x3,
	NVME_ID_UUID_ASSOCIATION_NONE			= 0,
	NVME_ID_UUID_ASSOCIATION_VENDOR			= 1,
	NVME_ID_UUID_ASSOCIATION_SUBSYSTEM_VENDOR	= 2,
};

#define NVME_ID_UUID_HDR_ASSOCIATION(uuid)	NVME_GET(uuid, ID_UUID_HDR_ASSOCIATION)

/**
 * struct nvme_id_uuid_list - UUID list
 * @rsvd0:	reserved
 * @entry:	UUID list entry
 */
struct nvme_id_uuid_list {
	__u8	rsvd0[32];
	struct nvme_id_uuid_list_entry entry[NVME_ID_UUID_LIST_MAX];
};

/**
 * struct nvme_underlying_ns_entry - Underlying Namespace Entry Data
 *		Structure
 * @unsnqn:	Underlying NVM Subsystem NQN (UNSNQN)
 * @nsid:	Namespace Identifier (NSID) of the Underlying Namespace
 * @cntlid:	Controller ID (CNTLID) of a controller able to attach @nsid
 * @rsvd58:	Reserved
 * @idx:	Index (IDX) into the list of reportable Underlying Namespaces
 */
struct nvme_underlying_ns_entry {
	__u8	unsnqn[NVME_NQN_LENGTH];
	__le32	nsid;
	__le16	cntlid;
	__u8	rsvd58[56];
	__le16	idx;
};

/**
 * struct nvme_underlying_ns_list - Underlying Namespace List Data Structure
 *		(CNS 1Dh)
 * @genctr:	Generation Counter (GENCTR)
 * @nument:	Number Entries (NUMENT)
 * @rsvd10:	Reserved
 * @entries:	Underlying Namespace list, see &struct
 *		nvme_underlying_ns_entry. Reportable up to
 *		%NVME_UNDERLYING_NS_LIST_MAX entries.
 */
struct nvme_underlying_ns_list {
	__le64	genctr;
	__le16	nument;
	__u8	rsvd10[6];
	struct nvme_underlying_ns_entry entries[NVME_UNDERLYING_NS_LIST_MAX];
};

/**
 * struct nvme_fabrics_transport_entry - Underlying Fabrics Transport Entry
 *		Data Structure
 * @traddr:	Transport Address (TRADDR)
 * @tsas:	Transport Specific Address Subtype (TSAS)
 * @pidup:	Port ID of the Underlying Port (PIDUP)
 * @trtype:	Transport Type (TRTYPE), see &enum nvmf_trtype
 * @adrfam:	Transport Address Family (ADRFAM), see &enum nvmf_addr_family
 * @treq:	Transport Requirements (TREQ), see &enum nvmf_treq
 * @rsvd517:	Reserved
 */
struct nvme_fabrics_transport_entry {
	__u8	traddr[NVMF_TRADDR_SIZE];
	__u8	tsas[NVMF_TSAS_SIZE];
	__le16	pidup;
	__u8	trtype;
	__u8	adrfam;
	__u8	treq;
	__u8	rsvd517[59];
};

/**
 * struct nvme_ports_list - Ports List Data Structure (CNS 1Eh)
 * @genctr:	Generation Counter (GENCTR)
 * @nument:	Number Entries (NUMENT)
 * @rsvd10:	Reserved
 * @entries:	Underlying Fabrics Transport Entry list, see &struct
 *		nvme_fabrics_transport_entry
 */
struct nvme_ports_list {
	__le64	genctr;
	__le16	nument;
	__u8	rsvd10[6];
	struct nvme_fabrics_transport_entry entries[];
};

/**
 * struct nvme_supported_ctrl_state_formats - Supported Controller State
 *		Formats Data Structure (CNS 20h)
 * @nv:		Number of Versions (NV) in the NVMe Controller State Version
 *		list at the start of @data
 * @nuuid:	Number of UUIDs (NUUID) in the Vendor Specific Controller
 *		State UUID Supported list, immediately following the NVMe
 *		Controller State Version list in @data
 * @data:	NVMe Controller State Version list (@nv &__le16 entries)
 *		immediately followed by the Vendor Specific Controller State
 *		UUID Supported list (@nuuid 128-bit UUID entries)
 */
struct nvme_supported_ctrl_state_formats {
	__u8	nv;
	__u8	nuuid;
	__u8	data[4094];
};

/**
 * struct nvme_exported_nvm_subsys_template_uuid_list - Exported NVM
 *		Subsystem Template UUID List data structure (CNS 22h)
 * @rsvd0:	Reserved
 * @enst:	Exported NVM Subsystem Template UUID list, up to 255 entries,
 *		listed in ascending order. An entry that is not reserved and
 *		is cleared to 0h indicates the end of the list.
 */
struct nvme_exported_nvm_subsys_template_uuid_list {
	__u8	rsvd0[16];
	__u8	enst[255][16];
};

/**
 * struct nvme_ctrl_list - Controller List
 * @num:	Number of Identifiers
 * @identifier:	NVM subsystem unique controller identifier
 */
struct nvme_ctrl_list {
	__le16 num;
	__le16 identifier[NVME_ID_CTRL_LIST_MAX];
};

/**
 * struct nvme_ns_list - Namespace List
 * @ns:	Namespace Identifier
 */
struct nvme_ns_list {
	__le32 ns[NVME_ID_NS_LIST_MAX];
};

/**
 * enum nvme_id_ctrl_nvm_lbamqf - LBA Migration Queue Format
 * @NVME_ID_CTRL_NVM_LBAMQF_TYPE_0:
 * @NVME_ID_CTRL_NVM_LBAMQF_VENDOR_MIN:
 * @NVME_ID_CTRL_NVM_LBAMQF_VENDOR_MAX:
 */
enum nvme_id_ctrl_nvm_lbamqf {
	NVME_ID_CTRL_NVM_LBAMQF_TYPE_0		= 0x0,
	NVME_ID_CTRL_NVM_LBAMQF_VENDOR_MIN	= 0xc0,
	NVME_ID_CTRL_NVM_LBAMQF_VENDOR_MAX	= 0xff,
};

/**
 * enum nvme_id_ctrl_nvm_rla - Rate Limiting Attributes
 * @NVME_ID_CTRL_NVM_RLA_HLS_SHIFT:	Shift amount to get Hard Limit Support (HLS)
 * @NVME_ID_CTRL_NVM_RLA_HLS_MASK:	Mask to get HLS
 * @NVME_ID_CTRL_NVM_RLA_SLS_SHIFT:	Shift amount to get Soft Limit Support (SLS)
 * @NVME_ID_CTRL_NVM_RLA_SLS_MASK:	Mask to get SLS
 */
enum nvme_id_ctrl_nvm_rla {
	NVME_ID_CTRL_NVM_RLA_HLS_SHIFT	= 0,
	NVME_ID_CTRL_NVM_RLA_HLS_MASK	= 0x1,
	NVME_ID_CTRL_NVM_RLA_SLS_SHIFT	= 1,
	NVME_ID_CTRL_NVM_RLA_SLS_MASK	= 0x1,
};

#define NVME_ID_CTRL_NVM_RLA_HLS(rla)	NVME_GET(rla, ID_CTRL_NVM_RLA_HLS)
#define NVME_ID_CTRL_NVM_RLA_SLS(rla)	NVME_GET(rla, ID_CTRL_NVM_RLA_SLS)

/**
 * struct nvme_id_ctrl_nvm - I/O Command Set Specific Identify Controller data structure
 * @vsl:	Verify Size Limit
 * @wzsl:	Write Zeroes Size Limit
 * @wusl:	Write Uncorrectable Size Limit
 * @dmrl:	Dataset Management Ranges Limit
 * @dmrsl:	Dataset Management Range Size Limit
 * @dmsl:	Dataset Management Size Limit
 * @kpiocap:	Key Per I/O Capabilities
 * @wzdsl:	Write Zeroes With Deallocate Size Limit
 * @aocs:	Admin Optional Command Support
 * @ver:	Version
 * @lbamqf:	LBA Migration Queue Format
 * @rla:	Rate Limiting Attributes, see &enum nvme_id_ctrl_nvm_rla
 * @slmc:	Soft Limit Maximum Controllers (0's based), valid only if SLS is set
 * @rsvd28:	Reserved
 */
struct nvme_id_ctrl_nvm {
	__u8	vsl;
	__u8	wzsl;
	__u8	wusl;
	__u8	dmrl;
	__le32	dmrsl;
	__le64	dmsl;
	__u8	kpiocap;
	__u8	wzdsl;
	__le16	aocs;
	__le32	ver;
	__u8	lbamqf;
	__u8	rla;
	__le16	slmc;
	__u8	rsvd28[4068];
};




/**
 * struct nvme_primary_ctrl_cap -  Identify - Controller Capabilities Structure
 * @cntlid:	Controller Identifier
 * @portid:	Port Identifier
 * @crt:	Controller Resource Types
 * @rsvd5:	reserved
 * @vqfrt:	VQ Resources Flexible Total
 * @vqrfa:	VQ Resources Flexible Assigned
 * @vqrfap:	VQ Resources Flexible Allocated to Primary
 * @vqprt:	VQ Resources Private Total
 * @vqfrsm:	VQ Resources Flexible Secondary Maximum
 * @vqgran:	VQ Flexible Resource Preferred Granularity
 * @rsvd48:	reserved
 * @vifrt:	VI Resources Flexible Total
 * @virfa:	VI Resources Flexible Assigned
 * @virfap:	VI Resources Flexible Allocated to Primary
 * @viprt:	VI Resources Private Total
 * @vifrsm:	VI Resources Flexible Secondary Maximum
 * @vigran:	VI Flexible Resource Preferred Granularity
 * @rsvd80:	reserved
 */
struct nvme_primary_ctrl_cap {
	__le16	cntlid;
	__le16	portid;
	__u8	crt;
	__u8	rsvd5[27];
	__le32	vqfrt;
	__le32	vqrfa;
	__le16	vqrfap;
	__le16	vqprt;
	__le16	vqfrsm;
	__le16	vqgran;
	__u8	rsvd48[16];
	__le32	vifrt;
	__le32	virfa;
	__le16	virfap;
	__le16	viprt;
	__le16	vifrsm;
	__le16	vigran;
	__u8	rsvd80[4016];
};

/**
 * struct nvme_secondary_ctrl -	 Secondary Controller Entry
 * @scid:	Secondary Controller Identifier
 * @pcid:	Primary Controller Identifier
 * @scs:	Secondary Controller State
 * @rsvd5:	Reserved
 * @vfn:	Virtual Function Number
 * @nvq:	Number of VQ Flexible Resources Assigned
 * @nvi:	Number of VI Flexible Resources Assigned
 * @rsvd14:	Reserved
 */
struct nvme_secondary_ctrl {
	__le16 scid;
	__le16 pcid;
	__u8   scs;
	__u8   rsvd5[3];
	__le16 vfn;
	__le16 nvq;
	__le16 nvi;
	__u8   rsvd14[18];
};

/**
 * struct nvme_secondary_ctrl_list - Secondary Controller List
 * @num:	Number of Identifiers
 * @rsvd:	Reserved
 * @sc_entry:	Secondary Controller Entry
 */
struct nvme_secondary_ctrl_list {
	__u8   num;
	__u8   rsvd[31];
	struct nvme_secondary_ctrl sc_entry[NVME_ID_SECONDARY_CTRL_MAX];
};

/**
 * struct nvme_id_iocs - NVMe Identify IO Command Set data structure
 * @iocsc:	List of supported IO Command Set Combination vectors
 */
struct nvme_id_iocs {
	__le64 iocsc[512];
};

/**
 * struct nvme_id_domain_attr - Domain Attributes Entry
 * @dom_id:		Domain Identifier
 * @rsvd2:		Reserved
 * @dom_cap:		Total Domain Capacity
 * @unalloc_dom_cap:	Unallocated Domain Capacity
 * @max_egrp_dom_cap:	Max Endurance Group Domain Capacity
 * @rsvd64:		Reserved
 */
struct nvme_id_domain_attr {
	__le16	dom_id;
	__u8	rsvd2[14];
	__u8	dom_cap[16];
	__u8	unalloc_dom_cap[16];
	__u8	max_egrp_dom_cap[16];
	__u8	rsvd64[64];
};

/**
 * struct nvme_id_domain_list - Domain List
 * @num:		Number of domain attributes
 * @rsvd:		Reserved
 * @domain_attr:	List of domain attributes
 */
struct nvme_id_domain_list {
	__u8	num;
	__u8	rsvd[127];
	struct nvme_id_domain_attr domain_attr[NVME_ID_DOMAIN_LIST_MAX];
};

/**
 * struct nvme_id_endurance_group_list - Endurance Group List
 * @num:	Number of Identifiers
 * @identifier: Endurance Group Identifier
 */
struct nvme_id_endurance_group_list {
	__le16	num;
	__le16	identifier[NVME_ID_ENDURANCE_GROUP_LIST_MAX];
};

/**
 * struct nvme_supported_log_pages - Supported Log Pages - Log
 * @lid_support: Log Page Identifier Supported
 *
 * Supported Log Pages (Log Identifier 00h)
 */
struct nvme_supported_log_pages {
	__le32	lid_support[NVME_LOG_SUPPORTED_LOG_PAGES_MAX];
};

/**
 * struct nvme_error_log_page - Error Information Log Entry (Log Identifier 01h)
 * @error_count:	 Error Count: a 64-bit incrementing error count,
 *			 indicating a unique identifier for this error. The error
 *			 count starts at %1h, is incremented for each unique error
 *			 log entry, and is retained across power off conditions.
 *			 A value of %0h indicates an invalid entry; this value
 *			 is used when there are lost entries or when there are
 *			 fewer errors than the maximum number of entries the
 *			 controller supports. If the value of this field is
 *			 %FFFFFFFFh, then the field shall be set to 1h when
 *			 incremented (i.e., rolls over to %1h). Prior to NVMe
 *			 1.4, processing of incrementing beyond %FFFFFFFFh is
 *			 unspecified.
 * @sqid:		 Submission Queue ID: indicates the Submission Queue
 *			 Identifier of the command that the error information is
 *			 associated with. If the error is not specific to
 *			 a particular command, then this field shall be set to
 *			 %FFFFh.
 * @cmdid:		 Command ID: indicates the Command Identifier of the
 *			 command that the error is associated with. If the error
 *			 is not specific to a particular command, then this field
 *			 shall be set to %FFFFh.
 * @status_field:	 Bits 15-1: Status Field: indicates the Status Field for
 *			 the command that completed. If the error is not specific
 *			 to a particular command, then this field reports the most
 *			 applicable status value.
 *			 Bit 0: Phase Tag: may indicate the Phase Tag posted for
 *			 the command.
 * @parm_error_location: Parameter Error Location: indicates the byte and bit of
 *			 the command parameter that the error is associated with,
 *			 if applicable. If the parameter spans multiple bytes or
 *			 bits, then the location indicates the first byte and bit
 *			 of the parameter.
 *			 Bits 10-8: Bit in command that contained the error.
 *			 Valid values are 0 to 7.
 *			 Bits 7-0: Byte in command that contained the error.
 *			 Valid values are 0 to 63.
 * @lba:		 LBA: This field indicates the first LBA that experienced
 *			 the error condition, if applicable.
 * @nsid:		 Namespace: This field indicates the NSID of the namespace
 *			 that the error is associated with, if applicable.
 * @vs:			 Vendor Specific Information Available: If there is
 *			 additional vendor specific error information available,
 *			 this field provides the log page identifier associated
 *			 with that page. A value of %0h indicates that no additional
 *			 information is available. Valid values are in the range
 *			 of %80h to %FFh.
 * @trtype:		 Transport Type (TRTYPE): indicates the Transport Type of
 *			 the transport associated with the error. The values in
 *			 this field are the same as the TRTYPE values in the
 *			 Discovery Log Page Entry. If the error is not transport
 *			 related, this field shall be cleared to %0h. If the error
 *			 is transport related, this field shall be set to the type
 *			 of the transport - see &enum nvme_trtype.
 * @csi:		 Command Set Indicator: This field contains command set
 *			 indicator for the command that the error is associated
 *			 with.
 * @opcode:		 Opcode: This field contains opcode for the command that
 *			 the error is associated with.
 * @cs:			 Command Specific Information: This field contains command
 *			 specific information. If used, the command definition
 *			 specifies the information returned.
 * @trtype_spec_info:	 Transport Type Specific Information
 * @rsvd:		 Reserved: [62:42]
 * @log_page_version:	 This field shall be set to 1h. If set, @csi and @opcode
 *			 will have valid values.
 */
struct nvme_error_log_page {
	__le64	error_count;
	__le16	sqid;
	__le16	cmdid;
	__le16	status_field;
	__le16	parm_error_location;
	__le64	lba;
	__le32	nsid;
	__u8	vs;
	__u8	trtype;
	__u8	csi;
	__u8	opcode;
	__le64	cs;
	__le16	trtype_spec_info;
	__u8	rsvd[21];
	__u8	log_page_version;
};

/**
 * enum nvme_err_pel - Parameter error location field
 * @NVME_ERR_PEL_BYTE_SHIFT: Byte location shift
 * @NVME_ERR_PEL_BYTE_MASK:	Byte mask for error location
 * @NVME_ERR_PEL_BIT_SHIFT: Bit location shift
 * @NVME_ERR_PEL_BIT_MASK:	Bit mask for error location
 */
enum nvme_err_pel {
	NVME_ERR_PEL_BYTE_SHIFT	= 0,
	NVME_ERR_PEL_BYTE_MASK	= 0xf,
	NVME_ERR_PEL_BIT_SHIFT	= 4,
	NVME_ERR_PEL_BIT_MASK	= 0x7,
};

/**
 * enum nvme_err_status_field - This field indicates the error information log entry status field
 * @NVME_ERR_SF_PHASE_TAG_SHIFT:	Shift amount to get the phase tag
 * @NVME_ERR_SF_STATUS_FIELD_SHIFT:	Shift amount to get the status field
 * @NVME_ERR_SF_PHASE_TAG_MASK:		Mask to get the phase tag
 * @NVME_ERR_SF_STATUS_FIELD_MASK:	Mask to get the status field
 */
enum nvme_err_status_field {
	NVME_ERR_SF_PHASE_TAG_SHIFT	= 0,
	NVME_ERR_SF_STATUS_FIELD_SHIFT	= 1,
	NVME_ERR_SF_PHASE_TAG_MASK	= 1,
	NVME_ERR_SF_STATUS_FIELD_MASK	= 0x7fff,
};

#define NVME_ERR_SF_PHASE_TAG(status_field)	NVME_GET(status_field, ERR_SF_PHASE_TAG)
#define NVME_ERR_SF_STATUS_FIELD(status_field)	NVME_GET(status_field, ERR_SF_STATUS_FIELD)

/**
 * struct nvme_smart_log - SMART / Health Information Log (Log Identifier 02h)
 * @critical_warning:	   This field indicates critical warnings for the state
 *			   of the controller. Critical warnings may result in an
 *			   asynchronous event notification to the host. Bits in
 *			   this field represent the current associated state and
 *			   are not persistent (see &enum nvme_smart_crit).
 * @temperature:	   Composite Temperature: Contains a value corresponding
 *			   to a temperature in Kelvins that represents the current
 *			   composite temperature of the controller and namespace(s)
 *			   associated with that controller. The manner in which
 *			   this value is computed is implementation specific and
 *			   may not represent the actual temperature of any physical
 *			   point in the NVM subsystem. Warning and critical
 *			   overheating composite temperature threshold values are
 *			   reported by the WCTEMP and CCTEMP fields in the Identify
 *			   Controller data structure.
 * @avail_spare:	   Available Spare: Contains a normalized percentage (0%
 *			   to 100%) of the remaining spare capacity available.
 * @spare_thresh:	   Available Spare Threshold: When the Available Spare
 *			   falls below the threshold indicated in this field, an
 *			   asynchronous event completion may occur. The value is
 *			   indicated as a normalized percentage (0% to 100%).
 *			   The values 101 to 255 are reserved.
 * @percent_used:	   Percentage Used: Contains a vendor specific estimate
 *			   of the percentage of NVM subsystem life used based on
 *			   the actual usage and the manufacturer's prediction of
 *			   NVM life. A value of 100 indicates that the estimated
 *			   endurance of the NVM in the NVM subsystem has been
 *			   consumed, but may not indicate an NVM subsystem failure.
 *			   The value is allowed to exceed 100. Percentages greater
 *			   than 254 shall be represented as 255. This value shall
 *			   be updated once per power-on hour (when the controller
 *			   is not in a sleep state).
 * @endu_grp_crit_warn_sumry: Endurance Group Critical Warning Summary: This field
 *			   indicates critical warnings for the state of Endurance
 *			   Groups. Bits in this field represent the current associated
 *			   state and are not persistent (see &enum nvme_smart_egcw).
 * @informative_warning: Informative Warning: This field indicates warnings
 *			   that the host may choose to act upon. Bits in this
 *			   field are not persistent, see &enum
 *			   nvme_smart_infw.
 * @rsvd8:		   Reserved
 * @data_units_read:	   Data Units Read: Contains the number of 512 byte data
 *			   units the host has read from the controller; this value
 *			   does not include metadata. This value is reported in
 *			   thousands (i.e., a value of 1 corresponds to 1000
 *			   units of 512 bytes read) and is rounded up (e.g., one
 *			   indicates the that number of 512 byte data units read
 *			   is from 1 to 1000, three indicates that the number of
 *			   512 byte data units read is from 2001 to 3000). When
 *			   the LBA size is a value other than 512 bytes, the
 *			   controller shall convert the amount of data read to
 *			   512 byte units. For the NVM command set, logical blocks
 *			   read as part of Compare, Read, and Verify operations
 *			   shall be included in this value. A value of %0h in
 *			   this field indicates that the number of Data Units Read
 *			   is not reported.
 * @data_units_written:	   Data Units Written: Contains the number of 512 byte
 *			   data units the host has written to the controller;
 *			   this value does not include metadata. This value is
 *			   reported in thousands (i.e., a value of 1 corresponds
 *			   to 1000 units of 512 bytes written) and is rounded up
 *			   (e.g., one indicates that the number of 512 byte data
 *			   units written is from 1 to 1,000, three indicates that
 *			   the number of 512 byte data units written is from 2001
 *			   to 3000). When the LBA size is a value other than 512
 *			   bytes, the controller shall convert the amount of data
 *			   written to 512 byte units. For the NVM command set,
 *			   logical blocks written as part of Write operations shall
 *			   be included in this value. Write Uncorrectable commands
 *			   and Write Zeroes commands shall not impact this value.
 *			   A value of %0h in this field indicates that the number
 *			   of Data Units Written is not reported.
 * @host_reads:		   Host Read Commands: Contains the number of read commands
 *			   completed by the controller. For the NVM command set,
 *			   this value is the sum of the number of Compare commands
 *			   and the number of Read commands.
 * @host_writes:	   Host Write Commands: Contains the number of write
 *			   commands completed by the controller. For the NVM
 *			   command set, this is the number of Write commands.
 * @ctrl_busy_time:	   Controller Busy Time: Contains the amount of time the
 *			   controller is busy with I/O commands. The controller
 *			   is busy when there is a command outstanding to an I/O
 *			   Queue (specifically, a command was issued via an I/O
 *			   Submission Queue Tail doorbell write and the corresponding
 *			   completion queue entry has not been posted yet to the
 *			   associated I/O Completion Queue). This value is
 *			   reported in minutes.
 * @power_cycles:	   Power Cycles: Contains the number of power cycles.
 * @power_on_hours:	   Power On Hours: Contains the number of power-on hours.
 *			   This may not include time that the controller was
 *			   powered and in a non-operational power state.
 * @unsafe_shutdowns:	   Unsafe Shutdowns: Contains the number of unsafe
 *			   shutdowns. This count is incremented when a Shutdown
 *			   Notification (CC.SHN) is not received prior to loss of power.
 * @media_errors:	   Media and Data Integrity Errors: Contains the number
 *			   of occurrences where the controller detected an
 *			   unrecovered data integrity error. Errors such as
 *			   uncorrectable ECC, CRC checksum failure, or LBA tag
 *			   mismatch are included in this field. Errors introduced
 *			   as a result of a Write Uncorrectable command may or
 *			   may not be included in this field.
 * @num_err_log_entries:   Number of Error Information Log Entries: Contains the
 *			   number of Error Information log entries over the life
 *			   of the controller.
 * @warning_temp_time:	   Warning Composite Temperature Time: Contains the amount
 *			   of time in minutes that the controller is operational
 *			   and the Composite Temperature is greater than or equal
 *			   to the Warning Composite Temperature Threshold (WCTEMP)
 *			   field and less than the Critical Composite Temperature
 *			   Threshold (CCTEMP) field in the Identify Controller
 *			   data structure. If the value of the WCTEMP or CCTEMP
 *			   field is %0h, then this field is always cleared to %0h
 *			   regardless of the Composite Temperature value.
 * @critical_comp_time:	   Critical Composite Temperature Time: Contains the amount
 *			   of time in minutes that the controller is operational
 *			   and the Composite Temperature is greater than or equal
 *			   to the Critical Composite Temperature Threshold (CCTEMP)
 *			   field in the Identify Controller data structure. If
 *			   the value of the CCTEMP field is %0h, then this field
 *			   is always cleared to 0h regardless of the Composite
 *			   Temperature value.
 * @temp_sensor:	   Temperature Sensor 1-8: Contains the current temperature
 *			   in degrees Kelvin reported by temperature sensors 1-8.
 *			   The physical point in the NVM subsystem whose temperature
 *			   is reported by the temperature sensor and the temperature
 *			   accuracy is implementation specific. An implementation
 *			   that does not implement the temperature sensor reports
 *			   a value of %0h.
 * @thm_temp1_trans_count: Thermal Management Temperature 1 Transition Count:
 *			   Contains the number of times the controller transitioned
 *			   to lower power active power states or performed vendor
 *			   specific thermal management actions while minimizing
 *			   the impact on performance in order to attempt to reduce
 *			   the Composite Temperature because of the host controlled
 *			   thermal management feature (i.e., the Composite
 *			   Temperature rose above the Thermal Management
 *			   Temperature 1). This counter shall not wrap once the
 *			   value %FFFFFFFFh is reached. A value of %0h, indicates
 *			   that this transition has never occurred or this field
 *			   is not implemented.
 * @thm_temp2_trans_count: Thermal Management Temperature 2 Transition Count
 * @thm_temp1_total_time:  Total Time For Thermal Management Temperature 1:
 *			   Contains the number of seconds that the controller
 *			   had transitioned to lower power active power states or
 *			   performed vendor specific thermal management actions
 *			   while minimizing the impact on performance in order to
 *			   attempt to reduce the Composite Temperature because of
 *			   the host controlled thermal management feature. This
 *			   counter shall not wrap once the value %FFFFFFFFh is
 *			   reached. A value of %0h, indicates that this transition
 *			   has never occurred or this field is not implemented.
 * @thm_temp2_total_time:  Total Time For Thermal Management Temperature 2
 * @op_lifetime_energy_consumed: Operational Lifetime Energy Consumed: Contains
 *			   the cumulative operational energy consumed by the NVM
 *			   subsystem in watt-hours calculated from all interval
 *			   power measurements collected from the time of
 *			   manufacture to the point that this log page is read.
 *			   This value is rounded up (e.g., two indicates the
 *			   number of watt-hours consumed is greater than 1 and
 *			   less than or equal to 2). This field shall not wrap
 *			   once the value %FFFFFFFFFFFFFFFFh is reached. A value
 *			   of %0h indicates that the cumulative operational energy
 *			   consumed is not reported.
 * @interval_power_measurement: Interval Power Measurement: Contains the average
 *			   of power measurement samples over the most recent one
 *			   second interval at the time of processing the Get Log
 *			   Page command. The power in Watts is equal to the
 *			   Interval Power Measurement Value (bits 15:0) multiplied
 *			   by the scale indicated in the Interval Power Measurement
 *			   Scale field (bits 17:16). A value of %0h indicates that
 *			   the interval power measurement is not reported.
 * @rsvd244:		   Reserved
 */
struct nvme_smart_log {
	__u8			critical_warning;
	__u8			temperature[2];
	__u8			avail_spare;
	__u8			spare_thresh;
	__u8			percent_used;
	__u8			endu_grp_crit_warn_sumry;
	__u8			informative_warning;
	__u8			rsvd8[24];
	__u8			data_units_read[16];
	__u8			data_units_written[16];
	__u8			host_reads[16];
	__u8			host_writes[16];
	__u8			ctrl_busy_time[16];
	__u8			power_cycles[16];
	__u8			power_on_hours[16];
	__u8			unsafe_shutdowns[16];
	__u8			media_errors[16];
	__u8			num_err_log_entries[16];
	__le32			warning_temp_time;
	__le32			critical_comp_time;
	__le16			temp_sensor[8];
	__le32			thm_temp1_trans_count;
	__le32			thm_temp2_trans_count;
	__le32			thm_temp1_total_time;
	__le32			thm_temp2_total_time;
	__le64			op_lifetime_energy_consumed;
	__le32			interval_power_measurement;
	__u8			rsvd244[268];
};

/**
 * enum nvme_smart_crit - Critical Warning
 * @NVME_SMART_CW_ASCBT_SHIFT: Shift amount to get the available spare capacity has fallen
 *			   below the threshold.
 * @NVME_SMART_CW_TTC_SHIFT: Shift amount to get the temperature is either greater
 *			   than or equal to an over temperature threshold; or
 *			   less than or equal to an under temperature threshold.
 * @NVME_SMART_CW_NDR_SHIFT: Shift amount to get the NVM subsystem reliability has
 *			   been degraded due to significant media related errors
 *			   or any internal error that degrades NVM subsystem
 *			   reliability.
 * @NVME_SMART_CW_AMRO_SHIFT: Shift amount to get the all of the media has been placed in read
 *			   only mode. The controller shall not set this bit if
 *			   the read-only condition on the media is a result of
 *			   a change in the write protection state of a namespace.
 * @NVME_SMART_CW_VMBF_SHIFT: Shift amount to get the  volatile memory backup
 *			   device has failed. This field is only valid if the
 *			   controller has a volatile memory backup solution.
 * @NVME_SMART_CW_PMRRO_SHIFT: Shift amount to get the Persistent Memory Region has become
 *			   read-only or unreliable.
 * @NVME_SMART_CW_ASCBT_MASK: If set, then the available spare capacity has fallen
 *			   below the threshold.
 * @NVME_SMART_CW_TTC_MASK: Mask to get the temperature is either greater
 *			   than or equal to an over temperature threshold; or
 *			   less than or equal to an under temperature threshold.
 * @NVME_SMART_CW_NDR_MASK: Mask to get the NVM subsystem reliability has
 *			   been degraded due to significant media related errors
 *			   or any internal error that degrades NVM subsystem
 *			   reliability.
 * @NVME_SMART_CW_AMRO_MASK: Mask to get the all of the media has been placed in read
 *			   only mode. The controller shall not set this bit if
 *			   the read-only condition on the media is a result of
 *			   a change in the write protection state of a namespace.
 * @NVME_SMART_CW_VMBF_MASK: Mask to get the volatile memory backup
 *			   device has failed. This field is only valid if the
 *			   controller has a volatile memory backup solution.
 * @NVME_SMART_CW_PMRRO_MASK: Mask to get the Persistent Memory Region has become
 *			   read-only or unreliable.
 * @NVME_SMART_CRIT_SPARE: If set, then the available spare capacity has fallen
 *			   below the threshold.
 * @NVME_SMART_CRIT_TEMPERATURE: If set, then a temperature is either greater
 *			   than or equal to an over temperature threshold; or
 *			   less than or equal to an under temperature threshold.
 * @NVME_SMART_CRIT_DEGRADED: If set, then the NVM subsystem reliability has
 *			   been degraded due to significant media related errors
 *			   or any internal error that degrades NVM subsystem
 *			   reliability.
 * @NVME_SMART_CRIT_MEDIA: If set, then all of the media has been placed in read
 *			   only mode. The controller shall not set this bit if
 *			   the read-only condition on the media is a result of
 *			   a change in the write protection state of a namespace.
 * @NVME_SMART_CRIT_VOLATILE_MEMORY: If set, then the volatile memory backup
 *			   device has failed. This field is only valid if the
 *			   controller has a volatile memory backup solution.
 * @NVME_SMART_CRIT_PMR_RO: If set, then the Persistent Memory Region has become
 *			   read-only or unreliable.
 * @NVME_SMART_CRIT_INDETERMINATE_PERSONALITY: If set, then a requested change
 *			   to the settings of a Configurable Device Personality
 *			   did not complete successfully and the controller was
 *			   not able to revert to the previous settings of that
 *			   personality.
 */
enum nvme_smart_crit {
	NVME_SMART_CW_ASCBT_SHIFT	= 0,
	NVME_SMART_CW_TTC_SHIFT		= 1,
	NVME_SMART_CW_NDR_SHIFT		= 2,
	NVME_SMART_CW_AMRO_SHIFT	= 3,
	NVME_SMART_CW_VMBF_SHIFT	= 4,
	NVME_SMART_CW_PMRRO_SHIFT	= 5,
	NVME_SMART_CW_IPS_SHIFT		= 6,
	NVME_SMART_CW_ASCBT_MASK	= 0x1,
	NVME_SMART_CW_TTC_MASK		= 0x1,
	NVME_SMART_CW_NDR_MASK		= 0x1,
	NVME_SMART_CW_AMRO_MASK		= 0x1,
	NVME_SMART_CW_VMBF_MASK		= 0x1,
	NVME_SMART_CW_PMRRO_MASK	= 0x1,
	NVME_SMART_CW_IPS_MASK		= 0x1,
	NVME_SMART_CRIT_SPARE		= NVME_VAL(SMART_CW_ASCBT),
	NVME_SMART_CRIT_TEMPERATURE	= NVME_VAL(SMART_CW_TTC),
	NVME_SMART_CRIT_DEGRADED	= NVME_VAL(SMART_CW_NDR),
	NVME_SMART_CRIT_MEDIA		= NVME_VAL(SMART_CW_AMRO),
	NVME_SMART_CRIT_VOLATILE_MEMORY	= NVME_VAL(SMART_CW_VMBF),
	NVME_SMART_CRIT_PMR_RO		= NVME_VAL(SMART_CW_PMRRO),
	NVME_SMART_CRIT_INDETERMINATE_PERSONALITY = NVME_VAL(SMART_CW_IPS),
};

#define NVME_SMART_CW_ASCBT(crit)	NVME_GET(crit, SMART_CW_ASCBT)
#define NVME_SMART_CW_TTC(crit)		NVME_GET(crit, SMART_CW_TTC)
#define NVME_SMART_CW_NDR(crit)		NVME_GET(crit, SMART_CW_NDR)
#define NVME_SMART_CW_AMRO(crit)	NVME_GET(crit, SMART_CW_AMRO)
#define NVME_SMART_CW_VMBF(crit)	NVME_GET(crit, SMART_CW_VMBF)
#define NVME_SMART_CW_PMRRO(crit)	NVME_GET(crit, SMART_CW_PMRRO)
#define NVME_SMART_CW_IPS(crit)		NVME_GET(crit, SMART_CW_IPS)

/**
 * enum nvme_smart_egcw - Endurance Group Critical Warning Summary
 * @NVME_SMART_EGCW_SPARE:    If set, then the available spare capacity of one or
 *			      more Endurance Groups has fallen below the threshold.
 * @NVME_SMART_EGCW_DEGRADED: If set, then the reliability of one or more
 *			      Endurance Groups has been degraded due to significant
 *			      media related errors or any internal error that
 *			      degrades NVM subsystem reliability.
 * @NVME_SMART_EGCW_RO:	      If set, then the namespaces in one or more Endurance
 *			      Groups have been placed in read only mode not as
 *			      a result of a change in the write protection state
 *			      of a namespace.
 */
enum nvme_smart_egcw {
	NVME_SMART_EGCW_SPARE		= 1 << 0,
	NVME_SMART_EGCW_DEGRADED	= 1 << 2,
	NVME_SMART_EGCW_RO		= 1 << 3,
};

/**
 * enum nvme_smart_infw - Informative Warning
 * @NVME_SMART_INFW_VLTHW: Voltage Log Threshold Warning: if set, then the
 *			   Overvoltage Valid (OVV) bit or the Undervoltage
 *			   Valid (UVV) bit in the Voltage Measurement log
 *			   page is set to '1'.
 */
enum nvme_smart_infw {
	NVME_SMART_INFW_VLTHW		= 1 << 0,
};

/**
 * enum nvme_voltage_sensor - Voltage Sensors
 * @NVME_VOLTAGE_SENSOR_1: Voltage Sensor 1 (VSEN1)
 * @NVME_VOLTAGE_SENSOR_2: Voltage Sensor 2 (VSEN2)
 * @NVME_VOLTAGE_SENSOR_3: Voltage Sensor 3 (VSEN3)
 * @NVME_VOLTAGE_SENSOR_4: Voltage Sensor 4 (VSEN4)
 */
enum nvme_voltage_sensor {
	NVME_VOLTAGE_SENSOR_1	= 0x00,
	NVME_VOLTAGE_SENSOR_2	= 0x01,
	NVME_VOLTAGE_SENSOR_3	= 0x02,
	NVME_VOLTAGE_SENSOR_4	= 0x03,
};

/**
 * enum nvme_voltage_threshold_type - Voltage Threshold Type
 * @NVME_VOLTAGE_THRESHOLD_TYPE_OVERVOLTAGE: Overvoltage Threshold
 * @NVME_VOLTAGE_THRESHOLD_TYPE_UNDERVOLTAGE: Undervoltage Threshold
 */
enum nvme_voltage_threshold_type {
	NVME_VOLTAGE_THRESHOLD_TYPE_OVERVOLTAGE		= 0x00,
	NVME_VOLTAGE_THRESHOLD_TYPE_UNDERVOLTAGE		= 0x01,
};

/**
 * enum nvme_id_ctrl_vsen - Identify Controller Voltage Sensor data
 *			    structure (VSEN1-VSEN4)
 * @NVME_CTRL_VSEN_VSRV_SHIFT:  Shift amount to get the Voltage Sample Rate
 *				Value (VSRV)
 * @NVME_CTRL_VSEN_VSRV_MASK:	Mask to get VSRV
 * @NVME_CTRL_VSEN_VSRS_SHIFT:	Shift amount to get the Voltage Sample Rate
 *				Scale (VSRS)
 * @NVME_CTRL_VSEN_VSRS_MASK:	Mask to get VSRS
 * @NVME_CTRL_VSEN_VOLSS_SHIFT: Shift amount to get the Voltage Sample Scale
 *				(VOLSS)
 * @NVME_CTRL_VSEN_VOLSS_MASK:	Mask to get VOLSS
 * @NVME_CTRL_VSEN_PISL_SHIFT:	Shift amount to get the Power Input Supply
 *				Label (PISL)
 * @NVME_CTRL_VSEN_PISL_MASK:	Mask to get PISL
 * @NVME_CTRL_VSEN_PISV_SHIFT:	Shift amount to get the Power Input Supply
 *				Value (PISV), in units of 0.05 V
 * @NVME_CTRL_VSEN_PISV_MASK:	Mask to get PISV
 */
enum nvme_id_ctrl_vsen {
	NVME_CTRL_VSEN_VSRV_SHIFT	= 16,
	NVME_CTRL_VSEN_VSRV_MASK	= 0xff,
	NVME_CTRL_VSEN_VSRS_SHIFT	= 24,
	NVME_CTRL_VSEN_VSRS_MASK	= 0xff,
	NVME_CTRL_VSEN_VOLSS_SHIFT	= 14,
	NVME_CTRL_VSEN_VOLSS_MASK	= 0x3,
	NVME_CTRL_VSEN_PISL_SHIFT	= 12,
	NVME_CTRL_VSEN_PISL_MASK	= 0x3,
	NVME_CTRL_VSEN_PISV_SHIFT	= 0,
	NVME_CTRL_VSEN_PISV_MASK	= 0xfff,
};

#define NVME_CTRL_VSEN_VSRV(vsen)	NVME_GET(vsen, CTRL_VSEN_VSRV)
#define NVME_CTRL_VSEN_VSRS(vsen)	NVME_GET(vsen, CTRL_VSEN_VSRS)
#define NVME_CTRL_VSEN_VOLSS(vsen)	NVME_GET(vsen, CTRL_VSEN_VOLSS)
#define NVME_CTRL_VSEN_PISL(vsen)	NVME_GET(vsen, CTRL_VSEN_PISL)
#define NVME_CTRL_VSEN_PISV(vsen)	NVME_GET(vsen, CTRL_VSEN_PISV)

/**
 * enum nvme_voltage_measurement_vma - Voltage Measurement log page -
 *					Voltage Measurement Attributes (VMA)
 * @NVME_VOLTAGE_MEASUREMENT_VMA_VME:		Voltage Measurement Enable
 * @NVME_VOLTAGE_MEASUREMENT_VMA_IVOLTS:	Interval Voltage Timestamp
 *						Support
 * @NVME_VOLTAGE_MEASUREMENT_VMA_VSM_SHIFT:	Shift amount to get the
 *						Voltage Sensor Measured (VSM),
 *						see &enum nvme_voltage_sensor
 * @NVME_VOLTAGE_MEASUREMENT_VMA_VSM_MASK:	Mask to get VSM
 * @NVME_VOLTAGE_MEASUREMENT_VMA_VMC:		Voltage Measurement Counted
 */
enum nvme_voltage_measurement_vma {
	NVME_VOLTAGE_MEASUREMENT_VMA_VME		= 1 << 0,
	NVME_VOLTAGE_MEASUREMENT_VMA_IVOLTS		= 1 << 1,
	NVME_VOLTAGE_MEASUREMENT_VMA_VSM_SHIFT		= 2,
	NVME_VOLTAGE_MEASUREMENT_VMA_VSM_MASK		= 0x3,
	NVME_VOLTAGE_MEASUREMENT_VMA_VMC		= 1 << 4,
};

#define NVME_VOLTAGE_MEASUREMENT_VMA_VSM(vma) \
	NVME_GET(vma, VOLTAGE_MEASUREMENT_VMA_VSM)

/**
 * enum nvme_voltage_measurement_vsi - Voltage Measurement log page -
 *					Voltage Sensor Info (VSI)
 * @NVME_VOLTAGE_MEASUREMENT_VSI_VSSV_SHIFT: Shift amount to get the Voltage
 *					      Sensor Supply Value (VSSV), in
 *					      units of 0.05 V
 * @NVME_VOLTAGE_MEASUREMENT_VSI_VSSV_MASK:  Mask to get VSSV
 * @NVME_VOLTAGE_MEASUREMENT_VSI_VSSL_SHIFT: Shift amount to get the Voltage
 *					      Sensor Supply Label (VSSL)
 * @NVME_VOLTAGE_MEASUREMENT_VSI_VSSL_MASK:  Mask to get VSSL
 * @NVME_VOLTAGE_MEASUREMENT_VSI_VSSS_SHIFT: Shift amount to get the Voltage
 *					      Sensor Sample Scale (VSSS)
 * @NVME_VOLTAGE_MEASUREMENT_VSI_VSSS_MASK:  Mask to get VSSS
 */
enum nvme_voltage_measurement_vsi {
	NVME_VOLTAGE_MEASUREMENT_VSI_VSSV_SHIFT	= 0,
	NVME_VOLTAGE_MEASUREMENT_VSI_VSSV_MASK		= 0xfff,
	NVME_VOLTAGE_MEASUREMENT_VSI_VSSL_SHIFT	= 12,
	NVME_VOLTAGE_MEASUREMENT_VSI_VSSL_MASK		= 0x3,
	NVME_VOLTAGE_MEASUREMENT_VSI_VSSS_SHIFT	= 14,
	NVME_VOLTAGE_MEASUREMENT_VSI_VSSS_MASK		= 0x3,
};

#define NVME_VOLTAGE_MEASUREMENT_VSI_VSSV(vsi) \
	NVME_GET(vsi, VOLTAGE_MEASUREMENT_VSI_VSSV)
#define NVME_VOLTAGE_MEASUREMENT_VSI_VSSL(vsi) \
	NVME_GET(vsi, VOLTAGE_MEASUREMENT_VSI_VSSL)
#define NVME_VOLTAGE_MEASUREMENT_VSI_VSSS(vsi) \
	NVME_GET(vsi, VOLTAGE_MEASUREMENT_VSI_VSSS)

/**
 * enum nvme_voltage_measurement_ovol - Voltage Measurement log page -
 *					 Overvoltage (OVOL)
 * @NVME_VOLTAGE_MEASUREMENT_OVOL_MOVV_SHIFT: Shift amount to get the
 *					       Maximum Overvoltage Value (MOVV)
 * @NVME_VOLTAGE_MEASUREMENT_OVOL_MOVV_MASK:  Mask to get MOVV
 * @NVME_VOLTAGE_MEASUREMENT_OVOL_OVV:	       Overvoltage Valid
 */
enum nvme_voltage_measurement_ovol {
	NVME_VOLTAGE_MEASUREMENT_OVOL_MOVV_SHIFT	= 0,
	NVME_VOLTAGE_MEASUREMENT_OVOL_MOVV_MASK	= 0x3fff,
	NVME_VOLTAGE_MEASUREMENT_OVOL_OVV		= 1 << 14,
};

#define NVME_VOLTAGE_MEASUREMENT_OVOL_MOVV(ovol) \
	NVME_GET(ovol, VOLTAGE_MEASUREMENT_OVOL_MOVV)

/**
 * enum nvme_voltage_measurement_uvol - Voltage Measurement log page -
 *					 Undervoltage (UVOL)
 * @NVME_VOLTAGE_MEASUREMENT_UVOL_MUVV_SHIFT: Shift amount to get the
 *					       Minimum Undervoltage Value
 *					       (MUVV)
 * @NVME_VOLTAGE_MEASUREMENT_UVOL_MUVV_MASK:  Mask to get MUVV
 * @NVME_VOLTAGE_MEASUREMENT_UVOL_UVV:	       Undervoltage Valid
 */
enum nvme_voltage_measurement_uvol {
	NVME_VOLTAGE_MEASUREMENT_UVOL_MUVV_SHIFT	= 0,
	NVME_VOLTAGE_MEASUREMENT_UVOL_MUVV_MASK	= 0x3fff,
	NVME_VOLTAGE_MEASUREMENT_UVOL_UVV		= 1 << 14,
};

#define NVME_VOLTAGE_MEASUREMENT_UVOL_MUVV(uvol) \
	NVME_GET(uvol, VOLTAGE_MEASUREMENT_UVOL_MUVV)

/**
 * enum nvme_voltage_measurement_ivmd - Voltage Measurement log page -
 *					 Interval Voltage Measurement
 *					 Descriptor (IVMD)
 * @NVME_VOLTAGE_MEASUREMENT_IVMD_VOLV_SHIFT: Shift amount to get the Voltage
 *					       Value (VOLV)
 * @NVME_VOLTAGE_MEASUREMENT_IVMD_VOLV_MASK:  Mask to get VOLV
 * @NVME_VOLTAGE_MEASUREMENT_IVMD_NCVM:	       Non Contiguous Voltage
 *					       Measurement
 */
enum nvme_voltage_measurement_ivmd {
	NVME_VOLTAGE_MEASUREMENT_IVMD_VOLV_SHIFT	= 0,
	NVME_VOLTAGE_MEASUREMENT_IVMD_VOLV_MASK	= 0x3fff,
	NVME_VOLTAGE_MEASUREMENT_IVMD_NCVM		= 1 << 14,
};

#define NVME_VOLTAGE_MEASUREMENT_IVMD_VOLV(ivmd) \
	NVME_GET(ivmd, VOLTAGE_MEASUREMENT_IVMD_VOLV)

/**
 * enum nvme_voltage_measurement_lvolta - Start Voltage Measurements Data
 *					   Structure - Log Voltage Threshold
 *					   Attributes (LVOLTA)
 * @NVME_VOLTAGE_MEASUREMENT_LVOLTA_VSSEL_SHIFT: Shift amount to get the
 *						  Voltage Sensor Selected
 *						  (VSSEL), see &enum
 *						  nvme_voltage_sensor
 * @NVME_VOLTAGE_MEASUREMENT_LVOLTA_VSSEL_MASK:  Mask to get VSSEL
 * @NVME_VOLTAGE_MEASUREMENT_LVOLTA_VMLT:	  Voltage Measurement Log
 *						  Threshold
 */
enum nvme_voltage_measurement_lvolta {
	NVME_VOLTAGE_MEASUREMENT_LVOLTA_VSSEL_SHIFT	= 0,
	NVME_VOLTAGE_MEASUREMENT_LVOLTA_VSSEL_MASK	= 0x3,
	NVME_VOLTAGE_MEASUREMENT_LVOLTA_VMLT		= 1 << 2,
};

#define NVME_VOLTAGE_MEASUREMENT_LVOLTA_VSSEL(lvolta) \
	NVME_GET(lvolta, VOLTAGE_MEASUREMENT_LVOLTA_VSSEL)

/**
 * enum nvme_voltage_measurement_lvolt - Start Voltage Measurements Data
 *					  Structure - Log Voltage Threshold
 *					  (LVOLT)
 * @NVME_VOLTAGE_MEASUREMENT_LVOLT_LUVT_SHIFT: Shift amount to get the Log
 *						Undervoltage Threshold (LUVT)
 * @NVME_VOLTAGE_MEASUREMENT_LVOLT_LUVT_MASK:  Mask to get LUVT
 * @NVME_VOLTAGE_MEASUREMENT_LVOLT_LOVT_SHIFT: Shift amount to get the Log
 *						Overvoltage Threshold (LOVT)
 * @NVME_VOLTAGE_MEASUREMENT_LVOLT_LOVT_MASK:  Mask to get LOVT
 */
enum nvme_voltage_measurement_lvolt {
	NVME_VOLTAGE_MEASUREMENT_LVOLT_LUVT_SHIFT	= 0,
	NVME_VOLTAGE_MEASUREMENT_LVOLT_LUVT_MASK	= 0x3fff,
	NVME_VOLTAGE_MEASUREMENT_LVOLT_LOVT_SHIFT	= 16,
	NVME_VOLTAGE_MEASUREMENT_LVOLT_LOVT_MASK	= 0x3fff,
};

#define NVME_VOLTAGE_MEASUREMENT_LVOLT_LUVT(lvolt) \
	NVME_GET(lvolt, VOLTAGE_MEASUREMENT_LVOLT_LUVT)
#define NVME_VOLTAGE_MEASUREMENT_LVOLT_LOVT(lvolt) \
	NVME_GET(lvolt, VOLTAGE_MEASUREMENT_LVOLT_LOVT)

/**
 * struct nvme_voltage_measurement_start_data - Start Voltage Measurements
 *						 Data Structure
 * @lvolta: Log Voltage Threshold Attributes, see &enum
 *	    nvme_voltage_measurement_lvolta.
 * @svmt:   Stop Voltage Measurement Time, in minutes. A value of 0h
 *	    specifies no stop measurement time value.
 * @lvolt:  Log Voltage Threshold, see &enum nvme_voltage_measurement_lvolt.
 *	    Ignored if the VMLT bit is cleared to '0' in @lvolta.
 * @rsvd8:  Reserved
 */
struct nvme_voltage_measurement_start_data {
	__le16	lvolta;
	__le16	svmt;
	__le32	lvolt;
	__u8	rsvd8[4088];
};

/**
 * enum nvme_aer_one_shot - Asynchronous Event Information - One Shot
 * @NVME_AER_ONE_SHOT_VOLTAGE_THRESHOLD_EVENT: Voltage Threshold Event: the
 *	interval voltage measurement crossed one of the voltage thresholds
 *	configured by the Voltage Threshold feature, see &enum
 *	nvme_aer_voltage_threshold_event for the Event Specific Parameter
 *	field format.
 */
enum nvme_aer_one_shot {
	NVME_AER_ONE_SHOT_VOLTAGE_THRESHOLD_EVENT	= 0x03,
};

/**
 * enum nvme_aer_voltage_threshold_event - Voltage Threshold Event - Event
 *					    Specific Parameter
 * @NVME_AER_VOLTAGE_THRESHOLD_EVENT_IVM_SHIFT:   Shift amount to get the
 *						   Interval Voltage
 *						   Measurement (IVM)
 * @NVME_AER_VOLTAGE_THRESHOLD_EVENT_IVM_MASK:	   Mask to get IVM
 * @NVME_AER_VOLTAGE_THRESHOLD_EVENT_VTHT_SHIFT:  Shift amount to get the
 *						   Voltage Threshold Type
 *						   (VTHT), see &enum
 *						   nvme_voltage_threshold_type
 * @NVME_AER_VOLTAGE_THRESHOLD_EVENT_VTHT_MASK:   Mask to get VTHT
 * @NVME_AER_VOLTAGE_THRESHOLD_EVENT_VSENT_SHIFT: Shift amount to get the
 *						   Voltage Sensor Triggered
 *						   (VSENT), see &enum
 *						   nvme_voltage_sensor
 * @NVME_AER_VOLTAGE_THRESHOLD_EVENT_VSENT_MASK:  Mask to get VSENT
 */
enum nvme_aer_voltage_threshold_event {
	NVME_AER_VOLTAGE_THRESHOLD_EVENT_IVM_SHIFT	= 0,
	NVME_AER_VOLTAGE_THRESHOLD_EVENT_IVM_MASK	= 0x3fff,
	NVME_AER_VOLTAGE_THRESHOLD_EVENT_VTHT_SHIFT	= 14,
	NVME_AER_VOLTAGE_THRESHOLD_EVENT_VTHT_MASK	= 0x3,
	NVME_AER_VOLTAGE_THRESHOLD_EVENT_VSENT_SHIFT	= 16,
	NVME_AER_VOLTAGE_THRESHOLD_EVENT_VSENT_MASK	= 0x3,
};

#define NVME_AER_VOLTAGE_THRESHOLD_EVENT_IVM(esp) \
	NVME_GET(esp, AER_VOLTAGE_THRESHOLD_EVENT_IVM)
#define NVME_AER_VOLTAGE_THRESHOLD_EVENT_VTHT(esp) \
	NVME_GET(esp, AER_VOLTAGE_THRESHOLD_EVENT_VTHT)
#define NVME_AER_VOLTAGE_THRESHOLD_EVENT_VSENT(esp) \
	NVME_GET(esp, AER_VOLTAGE_THRESHOLD_EVENT_VSENT)

/**
 * struct nvme_firmware_slot - Firmware Slot Information Log
 * @afi:	Active Firmware Info
 * @rsvd1:	Reserved
 * @frs:	Firmware Revision for Slot
 * @rsvd2:	Reserved
 */
struct nvme_firmware_slot {
	__u8	afi;
	__u8	rsvd1[7];
	char	frs[7][8];
	__u8	rsvd2[448];
};

/**
 * struct nvme_cmd_effects_log - Commands Supported and Effects Log
 * @acs:	Admin Command Supported
 * @iocs:	I/O Command Supported
 * @rsvd:	Reserved
 */
struct nvme_cmd_effects_log {
	__le32 acs[256];
	__le32 iocs[256];
	__u8   rsvd[2048];
};

/**
 * enum nvme_cmd_effects - Commands Supported and Effects
 * @NVME_CMD_EFFECTS_CSUPP:	Command Supported
 * @NVME_CMD_EFFECTS_LBCC:	Logical Block Content Change
 * @NVME_CMD_EFFECTS_NCC:	Namespace Capability Change
 * @NVME_CMD_EFFECTS_NIC:	Namespace Inventory Change
 * @NVME_CMD_EFFECTS_CCC:	Controller Capability Change
 * @NVME_CMD_EFFECTS_CSER_SHIFT: Command submission and execution relaxations
 *				 shift
 * @NVME_CMD_EFFECTS_CSER_MASK:	Command Submission and Execution Relaxations
 * @NVME_CMD_EFFECTS_CSE_SHIFT: Command submission and execution shift
 * @NVME_CMD_EFFECTS_CSE_MASK:	Command Submission and Execution
 * @NVME_CMD_EFFECTS_UUID_SEL:	UUID Selection Supported
 */
enum nvme_cmd_effects {
	NVME_CMD_EFFECTS_CSUPP			= 1 << 0,
	NVME_CMD_EFFECTS_LBCC			= 1 << 1,
	NVME_CMD_EFFECTS_NCC			= 1 << 2,
	NVME_CMD_EFFECTS_NIC			= 1 << 3,
	NVME_CMD_EFFECTS_CCC			= 1 << 4,
	NVME_CMD_EFFECTS_CSER_SHIFT		= 14,
	NVME_CMD_EFFECTS_CSER_MASK		= 0x3,
	NVME_CMD_EFFECTS_CSE_SHIFT		= 16,
	NVME_CMD_EFFECTS_CSE_MASK		= 0x7,
	NVME_CMD_EFFECTS_UUID_SEL		= 1 << 19,
};

#define NVME_CMD_EFFECTS_CSER(effects)	NVME_GET(effects, CMD_EFFECTS_CSER)
#define NVME_CMD_EFFECTS_CSE(effects)	NVME_GET(effects, CMD_EFFECTS_CSE)

/**
 * struct nvme_st_result - Self-test Result
 * @dsts:  Device Self-test Status: Indicates the device self-test code and the
 *	   status of the operation (see &enum nvme_status_result and &enum nvme_st_code).
 * @seg:   Segment Number: Iindicates the segment number where the first self-test
 *	   failure occurred. If Device Self-test Status (@dsts) is not set to
 *	   #NVME_ST_RESULT_KNOWN_SEG_FAIL, then this field should be ignored.
 * @vdi:   Valid Diagnostic Information: Indicates the diagnostic failure
 *	   information that is reported. See &enum nvme_st_valid_diag_info.
 * @rsvd:  Reserved
 * @poh:   Power On Hours (POH): Indicates the number of power-on hours at the
 *	   time the device self-test operation was completed or aborted. This
 *	   does not include time that the controller was powered and in a low
 *	   power state condition.
 * @nsid:  Namespace Identifier (NSID): Indicates the namespace that the Failing
 *	   LBA occurred on. Valid only when the NSID Valid bit
 *	   (#NVME_ST_VALID_DIAG_INFO_NSID) is set in the Valid Diagnostic
 *	   Information (@vdi) field.
 * @flba:  Failing LBA: indicates the LBA of the logical block that caused the
 *	   test to fail. If the device encountered more than one failed logical
 *	   block during the test, then this field only indicates one of those
 *	   failed logical blocks. Valid only when the NSID Valid bit
 *	   (#NVME_ST_VALID_DIAG_INFO_FLBA) is set in the Valid Diagnostic
 *	   Information (@vdi) field.
 * @sct:   Status Code Type: This field may contain additional information related
 *	   to errors or conditions. Bits 2:0 may contain additional information
 *	   relating to errors or conditions that occurred during the device
 *	   self-test operation represented in the same format used in the Status
 *	   Code Type field of the completion queue entry (refer to &enum nvme_status_field).
 *	   Valid only when the NSID Valid bit (#NVME_ST_VALID_DIAG_INFO_SCT) is
 *	   set in the Valid Diagnostic Information (@vdi) field.
 * @sc:	   Status Code: This field may contain additional information relating
 *	   to errors or conditions that occurred during the device self-test
 *	   operation represented in the same format used in the Status Code field
 *	   of the completion queue entry. Valid only when the SCT Valid bit
 *	   (#NVME_ST_VALID_DIAG_INFO_SC) is set in the Valid Diagnostic
 *	   Information (@vdi) field.
 * @vs:	   Vendor Specific.
 */
struct nvme_st_result {
	__u8			dsts;
	__u8			seg;
	__u8			vdi;
	__u8			rsvd;
	__le64			poh;
	__le32			nsid;
	__le64			flba;
	__u8			sct;
	__u8			sc;
	__u8			vs[2];
} __attribute__((packed));

/**
 * enum nvme_status_result - Result of the device self-test operation
 * @NVME_ST_RESULT_NO_ERR:	     Operation completed without error.
 * @NVME_ST_RESULT_ABORTED:	     Operation was aborted by a Device Self-test command.
 * @NVME_ST_RESULT_CLR:		     Operation was aborted by a Controller Level Reset.
 * @NVME_ST_RESULT_NS_REMOVED:	     Operation was aborted due to a removal of
 *				     a namespace from the namespace inventory.
 * @NVME_ST_RESULT_ABORTED_FORMAT:   Operation was aborted due to the processing
 *				     of a Format NVM command.
 * @NVME_ST_RESULT_FATAL_ERR:	     A fatal error or unknown test error occurred
 *				     while the controller was executing the device
 *				     self-test operation and the operation did
 *				     not complete.
 * @NVME_ST_RESULT_UNKNOWN_SEG_FAIL: Operation completed with a segment that failed
 *				     and the segment that failed is not known.
 * @NVME_ST_RESULT_KNOWN_SEG_FAIL:   Operation completed with one or more failed
 *				     segments and the first segment that failed
 *				     is indicated in the Segment Number field.
 * @NVME_ST_RESULT_ABORTED_UNKNOWN:  Operation was aborted for unknown reason.
 * @NVME_ST_RESULT_ABORTED_SANITIZE: Operation was aborted due to a sanitize operation.
 * @NVME_ST_RESULT_NOT_USED:	     Entry not used (does not contain a test result).
 * @NVME_ST_RESULT_SHIFT: Device self-test result shift
 * @NVME_ST_RESULT_MASK:	     Mask to get the status result value from
 *				     the &struct nvme_st_result.dsts field.
 */
enum nvme_status_result {
	NVME_ST_RESULT_NO_ERR		= 0x0,
	NVME_ST_RESULT_ABORTED		= 0x1,
	NVME_ST_RESULT_CLR		= 0x2,
	NVME_ST_RESULT_NS_REMOVED	= 0x3,
	NVME_ST_RESULT_ABORTED_FORMAT	= 0x4,
	NVME_ST_RESULT_FATAL_ERR	= 0x5,
	NVME_ST_RESULT_UNKNOWN_SEG_FAIL	= 0x6,
	NVME_ST_RESULT_KNOWN_SEG_FAIL	= 0x7,
	NVME_ST_RESULT_ABORTED_UNKNOWN	= 0x8,
	NVME_ST_RESULT_ABORTED_SANITIZE	= 0x9,
	NVME_ST_RESULT_NOT_USED		= 0xf,
	NVME_ST_RESULT_SHIFT		= 0,
	NVME_ST_RESULT_MASK		= 0xf,
};

#define NVME_ST_RESULT(result)	NVME_GET(result, ST_RESULT)

/**
 * enum nvme_st_code - Self-test Code value
 * @NVME_ST_CODE_RESERVED: Reserved.
 * @NVME_ST_CODE_SHORT:	   Short device self-test operation.
 * @NVME_ST_CODE_EXTENDED: Extended device self-test operation.
 * @NVME_ST_CODE_HOST_INIT:Host-Initiated Refresh operation.
 * @NVME_ST_CODE_VS:	   Vendor specific.
 * @NVME_ST_CODE_ABORT:	   Abort device self-test operation.
 * @NVME_ST_CODE_SHIFT:	   Shift amount to get the code value from the
 *			   &struct nvme_st_result.dsts field.
 * @NVME_ST_CODE_MASK: Self-test code mask
 */
enum nvme_st_code {
	NVME_ST_CODE_RESERVED		= 0x0,
	NVME_ST_CODE_SHORT		= 0x1,
	NVME_ST_CODE_EXTENDED		= 0x2,
	NVME_ST_CODE_HOST_INIT		= 0x3,
	NVME_ST_CODE_VS			= 0xe,
	NVME_ST_CODE_ABORT		= 0xf,
	NVME_ST_CODE_SHIFT		= 4,
	NVME_ST_CODE_MASK		= 0xf,
};

#define NVME_ST_CODE(code)	NVME_GET(code, ST_CODE)

/**
 * enum nvme_st_curr_op - Current Device Self-Test Operation
 * @NVME_ST_CURR_OP_NOT_RUNNING: No device self-test operation in progress.
 * @NVME_ST_CURR_OP_SHORT:	 Short device self-test operation in progress.
 * @NVME_ST_CURR_OP_EXTENDED:	 Extended device self-test operation in progress.
 * @NVME_ST_CURR_OP_VS:		 Vendor specific.
 * @NVME_ST_CURR_OP_RESERVED:	 Reserved.
 * @NVME_ST_CURR_OP_SHIFT: Device self-test operation status shift
 * @NVME_ST_CURR_OP_MASK:	 Mask to get the current operation value from the
 *				 &struct nvme_self_test_log.current_operation field.
 * @NVME_ST_CURR_OP_CMPL_SHIFT: Current device self-test completion shift
 * @NVME_ST_CURR_OP_CMPL_MASK:	 Mask to get the current operation completion value
 *				 from the &struct nvme_self_test_log.completion field.
 */
enum nvme_st_curr_op {
	NVME_ST_CURR_OP_NOT_RUNNING	= 0x0,
	NVME_ST_CURR_OP_SHORT		= 0x1,
	NVME_ST_CURR_OP_EXTENDED	= 0x2,
	NVME_ST_CURR_OP_VS		= 0xe,
	NVME_ST_CURR_OP_RESERVED	= 0xf,
	NVME_ST_CURR_OP_SHIFT		= 0,
	NVME_ST_CURR_OP_MASK		= 0xf,
	NVME_ST_CURR_OP_CMPL_SHIFT	= 0,
	NVME_ST_CURR_OP_CMPL_MASK	= 0x7f,
};

#define NVME_ST_CURR_OP(op)		NVME_GET(op, ST_CURR_OP)
#define NVME_ST_CURR_OP_CMPL(op)	NVME_GET(op, ST_CURR_OP_CMPL)

/**
 * enum nvme_st_valid_diag_info - Valid Diagnostic Information
 * @NVME_ST_VALID_DIAG_INFO_NSID:  NSID Valid: if set, then the contents of
 *				   the Namespace Identifier field are valid.
 * @NVME_ST_VALID_DIAG_INFO_FLBA:  FLBA Valid: if set, then the contents of
 *				   the Failing LBA field are valid.
 * @NVME_ST_VALID_DIAG_INFO_SCT:   SCT Valid: if set, then the contents of
 *				   the Status Code Type field are valid.
 * @NVME_ST_VALID_DIAG_INFO_SC:	   SC Valid: if set, then the contents of
 *				   the Status Code field are valid.
 */
enum nvme_st_valid_diag_info {
	NVME_ST_VALID_DIAG_INFO_NSID		= 1 << 0,
	NVME_ST_VALID_DIAG_INFO_FLBA		= 1 << 1,
	NVME_ST_VALID_DIAG_INFO_SCT		= 1 << 2,
	NVME_ST_VALID_DIAG_INFO_SC		= 1 << 3,
};

/**
 * struct nvme_self_test_log - Device Self-test (Log Identifier 06h)
 * @current_operation: Current Device Self-Test Operation: indicates the status
 *		       of the current device self-test operation. If a device
 *		       self-test operation is in process (i.e., this field is set
 *		       to #NVME_ST_CURR_OP_SHORT or #NVME_ST_CURR_OP_EXTENDED),
 *		       then the controller shall not set this field to
 *		       #NVME_ST_CURR_OP_NOT_RUNNING until a new Self-test Result
 *		       Data Structure is created (i.e., if a device self-test
 *		       operation completes or is aborted, then the controller
 *		       shall create a Self-test Result Data Structure prior to
 *		       setting this field to #NVME_ST_CURR_OP_NOT_RUNNING).
 *		       See &enum nvme_st_curr_op.
 * @completion:	       Current Device Self-Test Completion: indicates the percentage
 *		       of the device self-test operation that is complete (e.g.,
 *		       a value of 25 indicates that 25% of the device self-test
 *		       operation is complete and 75% remains to be tested).
 *		       If the @current_operation field is cleared to
 *		       #NVME_ST_CURR_OP_NOT_RUNNING (indicating there is no device
 *		       self-test operation in progress), then this field is ignored.
 * @rsvd:	       Reserved
 * @result:	       Self-test Result Data Structures, see &struct nvme_st_result.
 */
struct nvme_self_test_log {
	__u8			current_operation;
	__u8			completion;
	__u8			rsvd[2];
	struct nvme_st_result	result[NVME_LOG_ST_MAX_RESULTS];
} __attribute__((packed));

/**
 * enum nvme_log_telemetry_host_lsp - Telemetry Host-Initiated log specific field
 * @NVME_LOG_TELEM_HOST_LSP_RETAIN:	Get Telemetry Data Blocks
 * @NVME_LOG_TELEM_HOST_LSP_CREATE:	Create Telemetry Data Blocks
 */
enum nvme_log_telemetry_host_lsp {
	NVME_LOG_TELEM_HOST_LSP_RETAIN			= 0,
	NVME_LOG_TELEM_HOST_LSP_CREATE			= 1,
};

/**
 * enum nvme_telemetry_da - Telemetry Log Data Area
 * @NVME_TELEMETRY_DA_CTRL_DETERMINE:	The controller determines the data areas to be created
 * @NVME_TELEMETRY_DA_1:		Data Area 1
 * @NVME_TELEMETRY_DA_2:		Data Area 2
 * @NVME_TELEMETRY_DA_3:		Data Area 3
 * @NVME_TELEMETRY_DA_4:		Data Area 4
 */
enum nvme_telemetry_da {
	NVME_TELEMETRY_DA_CTRL_DETERMINE	= 0,
	NVME_TELEMETRY_DA_1			= 1,
	NVME_TELEMETRY_DA_2			= 2,
	NVME_TELEMETRY_DA_3			= 3,
	NVME_TELEMETRY_DA_4			= 4,
};

/**
 * struct nvme_telemetry_log - Retrieve internal data specific to the
 *			       manufacturer.
 * @lpi:       Log Identifier, either %NVME_LOG_LID_TELEMETRY_HOST or
 *	       %NVME_LOG_LID_TELEMETRY_CTRL
 * @rsvd1:     Reserved
 * @ieee:      IEEE OUI Identifier is the Organization Unique Identifier (OUI)
 *	       for the controller vendor that is able to interpret the data.
 * @dalb1:     Telemetry Host/Controller Initiated Data Area 1 Last Block is
 *	       the value of the last block in this area.
 * @dalb2:     Telemetry Host/Controller Initiated Data Area 1 Last Block is
 *	       the value of the last block in this area.
 * @dalb3:     Telemetry Host/ControllerInitiated Data Area 1 Last Block is
 *	       the value of the last block in this area.
 * @rsvd14:    Reserved
 * @dalb4:     Telemetry Host/Controller Initiated Data Area 4 Last Block is
 *	       the value of the last block in this area.
 * @rsvd20:    Reserved
 * @ths:       Telemetry Host-Initiated Scope
 * @hostdgn:   Telemetry Host-Initiated Data Generation Number is a
 *	       value that is incremented each time the host initiates a
 *	       capture of its internal controller state in the controller.
 * @tcs:       Telemetry Controller-Initiated Scope
 * @ctrlavail: Telemetry Controller-Initiated Data Available, if cleared,
 *	       then the controller telemetry log does not contain saved
 *	       internal controller state. If this field is set to 1h, the
 *	       controller log contains saved internal controller state. If
 *	       this field is set to 1h, the data will be latched until the
 *	       host releases it by reading the log with RAE cleared.
 * @ctrldgn:   Telemetry Controller-Initiated Data Generation Number is
 *	       a value that is incremented each time the controller initiates a
 *	       capture of its internal controller state in the controller .
 * @rsnident:  Reason Identifiers a vendor specific identifier that describes
 *	       the operating conditions of the controller at the time of
 *	       capture.
 * @data_area: Telemetry data blocks, vendor specific information data.
 *
 * This log consists of a header describing the log and zero or more Telemetry
 * Data Blocks. All Telemetry Data Blocks are %NVME_LOG_TELEM_BLOCK_SIZE, 512
 * bytes, in size. This log captures the controller’s internal state.
 */
struct nvme_telemetry_log {
	__u8	lpi;
	__u8	rsvd1[4];
	__u8	ieee[3];
	__le16	dalb1;
	__le16	dalb2;
	__le16	dalb3;
	__u8	rsvd14[2];
	__le32	dalb4;
	__u8	rsvd20[360];
	__u8	ths;
	union { // [381]
		__u8	hostdgn;
		__u8	tcs;
	};
	__u8	ctrlavail;
	__u8	ctrldgn;
	__u8	rsnident[128];
	__u8	data_area[];
};

/**
 * struct nvme_endurance_group_log -  Endurance Group Information Log
 * @critical_warning:		Critical Warning
 * @endurance_group_features:	Endurance Group Features
 * @rsvd2:			Reserved
 * @avl_spare:			Available Spare
 * @avl_spare_threshold:	Available Spare Threshold
 * @percent_used:		Percentage Used
 * @domain_identifier:		Domain Identifier
 * @rsvd8:			Reserved
 * @endurance_estimate:		Endurance Estimate
 * @data_units_read:		Data Units Read
 * @data_units_written:		Data Units Written
 * @media_units_written:	Media Units Written
 * @host_read_cmds:		Host Read Commands
 * @host_write_cmds:		Host Write Commands
 * @media_data_integrity_err:	Media and Data Integrity Errors
 * @num_err_info_log_entries:	Number of Error Information Log Entries
 * @total_end_grp_cap:		Total Endurance Group Capacity
 * @unalloc_end_grp_cap:	Unallocated Endurance Group Capacity
 * @rsvd192:			Reserved
 */
struct nvme_endurance_group_log {
	__u8	critical_warning;
	__u8	endurance_group_features;
	__u8	rsvd2;
	__u8	avl_spare;
	__u8	avl_spare_threshold;
	__u8	percent_used;
	__le16	domain_identifier;
	__u8	rsvd8[24];
	__u8	endurance_estimate[16];
	__u8	data_units_read[16];
	__u8	data_units_written[16];
	__u8	media_units_written[16];
	__u8	host_read_cmds[16];
	__u8	host_write_cmds[16];
	__u8	media_data_integrity_err[16];
	__u8	num_err_info_log_entries[16];
	__u8	total_end_grp_cap[16];
	__u8	unalloc_end_grp_cap[16];
	__u8	rsvd192[320];
};

/**
 * enum nvme_eg_critical_warning_flags - Endurance Group Information Log - Critical Warning
 * @NVME_EG_CRITICAL_WARNING_SPARE:	Available spare capacity of the Endurance Group
 *					has fallen below the threshold
 * @NVME_EG_CRITICAL_WARNING_DEGRADED:	Endurance Group reliability has been degraded
 * @NVME_EG_CRITICAL_WARNING_READ_ONLY:	Endurance Group have been placed in read only
 *					mode
 */
enum nvme_eg_critical_warning_flags {
	NVME_EG_CRITICAL_WARNING_SPARE		= 1 << 0,
	NVME_EG_CRITICAL_WARNING_DEGRADED	= 1 << 2,
	NVME_EG_CRITICAL_WARNING_READ_ONLY	= 1 << 3,
};

/**
 * struct nvme_aggregate_endurance_group_event -  Endurance Group Event Aggregate
 * @num_entries:	Number or entries
 * @entries:		List of entries
 */
struct nvme_aggregate_endurance_group_event {
	__le64	num_entries;
	__le16	entries[];
};

/**
 * struct nvme_nvmset_predictable_lat_log - Predictable Latency Mode - Deterministic Threshold Configuration Data
 * @status:		Status
 * @rsvd1:		Reserved
 * @event_type:		Event Type
 * @rsvd4:		Reserved
 * @dtwin_rt:		DTWIN Reads Typical
 * @dtwin_wt:		DTWIN Writes Typical
 * @dtwin_tmax:		DTWIN Time Maximum
 * @ndwin_tmin_hi:	NDWIN Time Minimum High
 * @ndwin_tmin_lo:	NDWIN Time Minimum Low
 * @rsvd72:		Reserved
 * @dtwin_re:		DTWIN Reads Estimate
 * @dtwin_we:		DTWIN Writes Estimate
 * @dtwin_te:		DTWIN Time Estimate
 * @rsvd152:		Reserved
 */
struct nvme_nvmset_predictable_lat_log {
	__u8	status;
	__u8	rsvd1;
	__le16	event_type;
	__u8	rsvd4[28];
	__le64	dtwin_rt;
	__le64	dtwin_wt;
	__le64	dtwin_tmax;
	__le64	ndwin_tmin_hi;
	__le64	ndwin_tmin_lo;
	__u8	rsvd72[56];
	__le64	dtwin_re;
	__le64	dtwin_we;
	__le64	dtwin_te;
	__u8	rsvd152[360];
};

/**
 * enum nvme_nvmeset_pl_status -  Predictable Latency Per NVM Set Log - Status
 * @NVME_NVMSET_PL_STATUS_DISABLED:	Not used (Predictable Latency Mode not enabled)
 * @NVME_NVMSET_PL_STATUS_DTWIN:	Deterministic Window (DTWIN)
 * @NVME_NVMSET_PL_STATUS_NDWIN:	Non-Deterministic Window (NDWIN)
 */
enum nvme_nvmeset_pl_status {
	NVME_NVMSET_PL_STATUS_DISABLED	= 0,
	NVME_NVMSET_PL_STATUS_DTWIN	= 1,
	NVME_NVMSET_PL_STATUS_NDWIN	= 2,
};

/**
 * enum nvme_nvmset_pl_events - Predictable Latency Per NVM Set Log - Event Type
 * @NVME_NVMSET_PL_EVENT_DTWIN_READ_WARN:	DTWIN Reads Warning
 * @NVME_NVMSET_PL_EVENT_DTWIN_WRITE_WARN:	DTWIN Writes Warning
 * @NVME_NVMSET_PL_EVENT_DTWIN_TIME_WARN:	DTWIN Time Warning
 * @NVME_NVMSET_PL_EVENT_DTWIN_EXCEEDED:	Autonomous transition from DTWIN
 *						to NDWIN due to typical or
 *						maximum value exceeded
 * @NVME_NVMSET_PL_EVENT_DTWIN_EXCURSION:	Autonomous transition from DTWIN
 *						to NDWIN due to Deterministic
 *						Excursion
 */
enum nvme_nvmset_pl_events {
	NVME_NVMSET_PL_EVENT_DTWIN_READ_WARN	= 1 << 0,
	NVME_NVMSET_PL_EVENT_DTWIN_WRITE_WARN	= 1 << 1,
	NVME_NVMSET_PL_EVENT_DTWIN_TIME_WARN	= 1 << 2,
	NVME_NVMSET_PL_EVENT_DTWIN_EXCEEDED	= 1 << 14,
	NVME_NVMSET_PL_EVENT_DTWIN_EXCURSION	= 1 << 15,
};

/**
 * struct nvme_aggregate_predictable_lat_event - Predictable Latency Event Aggregate Log Page
 * @num_entries:	Number of entries
 * @entries:		Entry list
 */
struct nvme_aggregate_predictable_lat_event {
	__le64	num_entries;
	__le16	entries[];
};

/**
 * struct nvme_ana_group_desc - ANA Group Descriptor
 * @grpid:	ANA group id
 * @nnsids:	Number of namespaces in @nsids
 * @chgcnt:	Change counter
 * @state:	ANA state
 * @rsvd17:	Reserved
 * @nsids:	List of namespaces
 */
struct nvme_ana_group_desc {
	__le32	grpid;
	__le32	nnsids;
	__le64	chgcnt;
	__u8	state;
	__u8	rsvd17[15];
	__le32	nsids[];
};

/**
 * enum nvme_ana_state - ANA Group Descriptor - Asymmetric Namespace Access State
 * @NVME_ANA_STATE_OPTIMIZED:		ANA Optimized state
 * @NVME_ANA_STATE_NONOPTIMIZED:	ANA Non-Optimized state
 * @NVME_ANA_STATE_INACCESSIBLE:	ANA Inaccessible state
 * @NVME_ANA_STATE_PERSISTENT_LOSS:	ANA Persistent Loss state
 * @NVME_ANA_STATE_CHANGE:		ANA Change state
 */
enum nvme_ana_state {
	NVME_ANA_STATE_OPTIMIZED	= 0x1,
	NVME_ANA_STATE_NONOPTIMIZED	= 0x2,
	NVME_ANA_STATE_INACCESSIBLE	= 0x3,
	NVME_ANA_STATE_PERSISTENT_LOSS	= 0x4,
	NVME_ANA_STATE_CHANGE		= 0xf,
};

/**
 * struct nvme_ana_log -  Asymmetric Namespace Access Log
 * @chgcnt:	Change Count
 * @ngrps:	Number of ANA Group Descriptors
 * @rsvd10:	Reserved
 * @descs:	ANA Group Descriptor
 */
struct nvme_ana_log {
	__le64	chgcnt;
	__le16	ngrps;
	__u8	rsvd10[6];
	struct nvme_ana_group_desc descs[];
};

/**
 * struct nvme_persistent_event_log - Persistent Event Log
 * @lid:	Log Identifier
 * @rsvd1:	Reserved
 * @tnev:	Total Number of Events
 * @tll:	Total Log Length
 * @rv:		Log Revision
 * @rsvd17:	Reserved
 * @lhl:	Log Header Length
 * @ts:		Timestamp
 * @poh:	Power on Hours
 * @pcc:	Power Cycle Count
 * @vid:	PCI Vendor ID
 * @ssvid:	PCI Subsystem Vendor ID
 * @sn:		Serial Number
 * @mn:		Model Number
 * @subnqn:	NVM Subsystem NVMe Qualified Name
 * @gen_number: Generation Number
 * @rci:	Reporting Context Information
 * @rsvd378:	Reserved
 * @seb:	Supported Events Bitmap
 */
struct nvme_persistent_event_log {
	__u8	lid;
	__u8	rsvd1[3];
	__le32	tnev;
	__le64	tll;
	__u8	rv;
	__u8	rsvd17;
	__le16	lhl;
	__le64	ts;
	__u8	poh[16];
	__le64	pcc;
	__le16	vid;
	__le16	ssvid;
	char	sn[20];
	char	mn[40];
	char	subnqn[NVME_NQN_LENGTH];
	__le16	gen_number;
	__le32	rci;
	__u8	rsvd378[102];
	__u8	seb[32];
} __attribute__((packed));

/**
 * enum nvme_pel_rci - This field indicates the persistent event log reporting context
 * @NVME_PEL_RCI_RCPID_SHIFT:	Shift amount to get the reporting context port identifier
 *				from the &struct nvme_persistent_event_log.rci field.
 * @NVME_PEL_RCI_RCPIT_SHIFT:	Shift amount to get the reporting context port identifier
 *				type from the &struct nvme_persistent_event_log.rci field.
 * @NVME_PEL_RCI_RCE_SHIFT:	Shift amount to get the reporting context exists
 *				from the &struct nvme_persistent_event_log.rci field.
 * @NVME_PEL_RCI_RSVD_SHIFT:	Shift amount to get the reserved reporting context
 *				from the &struct nvme_persistent_event_log.rci field.
 * @NVME_PEL_RCI_RCPID_MASK:	Mask to get the reporting context port identifier from
 *				the &struct nvme_persistent_event_log.rci field.
 * @NVME_PEL_RCI_RCPIT_MASK:	Mask to get the reporting context port identifier type from
 *				the &struct nvme_persistent_event_log.rci field.
 * @NVME_PEL_RCI_RCE_MASK:	Mask to get the reporting context exists from
 *				the &struct nvme_persistent_event_log.rci field.
 * @NVME_PEL_RCI_RSVD_MASK:	Mask to get the reserved reporting context from
 *				the &struct nvme_persistent_event_log.rci field.
 */
enum nvme_pel_rci {
	NVME_PEL_RCI_RCPID_SHIFT	= 0,
	NVME_PEL_RCI_RCPIT_SHIFT	= 16,
	NVME_PEL_RCI_RCE_SHIFT		= 18,
	NVME_PEL_RCI_RSVD_SHIFT		= 19,
	NVME_PEL_RCI_RCPID_MASK		= 0xffff,
	NVME_PEL_RCI_RCPIT_MASK		= 0x3,
	NVME_PEL_RCI_RCE_MASK		= 0x1,
	NVME_PEL_RCI_RSVD_MASK		= 0x1fff,
};

#define NVME_PEL_RCI_RCPID(rci)	NVME_GET(rci, PEL_RCI_RCPID)
#define NVME_PEL_RCI_RCPIT(rci)	NVME_GET(rci, PEL_RCI_RCPIT)
#define NVME_PEL_RCI_RCE(rci)	NVME_GET(rci, PEL_RCI_RCE)
#define NVME_PEL_RCI_RSVD(rci)	NVME_GET(rci, PEL_RCI_RSVD)

/**
 * enum nvme_pel_rci_rcpit - Persistent Event Log Reporting Context - Port Identifier Type
 * @NVME_PEL_RCI_RCPIT_NOT_EXIST:	Does not already exist
 * @NVME_PEL_RCI_RCPIT_EST_PORT:	Established by an NVM subsystem port
 * @NVME_PEL_RCI_RCPIT_EST_ME:		Established by a Management Endpoint
 */
enum nvme_pel_rci_rcpit {
	NVME_PEL_RCI_RCPIT_NOT_EXIST	= 0,
	NVME_PEL_RCI_RCPIT_EST_PORT	= 1,
	NVME_PEL_RCI_RCPIT_EST_ME	= 2,
};

/**
 * struct nvme_persistent_event_entry - Persistent Event
 * @etype:	Event Type
 * @etype_rev:	Event Type Revision
 * @ehl:	Event Header Length
 * @ehai:	Event Header Additional Info
 * @cntlid:	Controller Identifier
 * @ets:	Event Timestamp
 * @pelpid:	Port Identifier
 * @rsvd16:	Reserved
 * @vsil:	Vendor Specific Information Length
 * @el:		Event Length
 */
struct nvme_persistent_event_entry {
	__u8	etype;
	__u8	etype_rev;
	__u8	ehl;
	__u8	ehai;
	__le16	cntlid;
	__le64	ets;
	__le16	pelpid;
	__u8	rsvd16[4];
	__le16	vsil;
	__le16	el;
} __attribute__((packed));

/**
 * enum nvme_persistent_event_types - Persistent event log events
 * @NVME_PEL_SMART_HEALTH_EVENT:	SMART / Health Log Snapshot Event
 * @NVME_PEL_FW_COMMIT_EVENT:		Firmware Commit Event
 * @NVME_PEL_TIMESTAMP_EVENT:		Timestamp Change Event
 * @NVME_PEL_POWER_ON_RESET_EVENT:	Power-on or Reset Event
 * @NVME_PEL_NSS_HW_ERROR_EVENT:	NVM Subsystem Hardware Error Event
 * @NVME_PEL_CHANGE_NS_EVENT:		Change Namespace Event
 * @NVME_PEL_FORMAT_START_EVENT:	Format NVM Start Event
 * @NVME_PEL_FORMAT_COMPLETION_EVENT:	Format NVM Completion Event
 * @NVME_PEL_SANITIZE_START_EVENT:	Sanitize Start Event
 * @NVME_PEL_SANITIZE_COMPLETION_EVENT:	Sanitize Completion Event
 * @NVME_PEL_SET_FEATURE_EVENT:		Set Feature Event
 * @NVME_PEL_TELEMETRY_CRT:		Telemetry Log Create Event
 * @NVME_PEL_THERMAL_EXCURSION_EVENT:	Thermal Excursion Event
 * @NVME_PEL_SANITIZE_MEDIA_VERIF_EVENT:Sanitize Media Verification Event
 * @NVME_PEL_CONF_DEV_PERSONALITY_CHG_EVENT: Configurable Device Personality
 *					Change Event
 * @NVME_PEL_EXPORT_NVMS_CHG_EVENT:	Exported NVM Subsystem Change Event
 * @NVME_PEL_VENDOR_SPECIFIC_EVENT:	Vendor Specific Event
 * @NVME_PEL_TCG_DEFINED_EVENT:		TCG Defined Event
 */
enum nvme_persistent_event_types {
	NVME_PEL_SMART_HEALTH_EVENT		= 0x01,
	NVME_PEL_FW_COMMIT_EVENT		= 0x02,
	NVME_PEL_TIMESTAMP_EVENT		= 0x03,
	NVME_PEL_POWER_ON_RESET_EVENT		= 0x04,
	NVME_PEL_NSS_HW_ERROR_EVENT		= 0x05,
	NVME_PEL_CHANGE_NS_EVENT		= 0x06,
	NVME_PEL_FORMAT_START_EVENT		= 0x07,
	NVME_PEL_FORMAT_COMPLETION_EVENT	= 0x08,
	NVME_PEL_SANITIZE_START_EVENT		= 0x09,
	NVME_PEL_SANITIZE_COMPLETION_EVENT	= 0x0a,
	NVME_PEL_SET_FEATURE_EVENT		= 0x0b,
	NVME_PEL_TELEMETRY_CRT			= 0x0c,
	NVME_PEL_THERMAL_EXCURSION_EVENT	= 0x0d,
	NVME_PEL_SANITIZE_MEDIA_VERIF_EVENT	= 0x0e,
	NVME_PEL_CONF_DEV_PERSONALITY_CHG_EVENT	= 0x0f,
	NVME_PEL_EXPORT_NVMS_CHG_EVENT		= 0x10,
	NVME_PEL_VENDOR_SPECIFIC_EVENT		= 0xde,
	NVME_PEL_TCG_DEFINED_EVENT		= 0xdf,
};

/**
 * enum nvme_pel_ehai - This field indicates the persistent event header additional information
 * @NVME_PEL_EHAI_PIT_SHIFT:	Shift amount to get the reporting context port identifier
 *				from the &struct nvme_persistent_event_log.rci field.
 * @NVME_PEL_EHAI_RSVD_SHIFT:	Shift amount to get the reserved reporting context
 *				from the &struct nvme_persistent_event_log.rci field.
 * @NVME_PEL_EHAI_PIT_MASK:	Mask to get the reporting context port identifier from
 *				the &struct nvme_st_result.dsts field.
 * @NVME_PEL_EHAI_RSVD_MASK:	Mask to get the reserved reporting context from
 *				the &struct nvme_st_result.dsts field.
 */
enum nvme_pel_ehai {
	NVME_PEL_EHAI_PIT_SHIFT		= 0,
	NVME_PEL_EHAI_RSVD_SHIFT	= 2,
	NVME_PEL_EHAI_PIT_MASK		= 0x3,
	NVME_PEL_EHAI_RSVD_MASK		= 0x3f,
};

#define NVME_PEL_EHAI_PIT(ehai)		NVME_GET(ehai, PEL_EHAI_PIT)
#define NVME_PEL_EHAI_RSVD(ehai)	NVME_GET(ehai, PEL_EHAI_RSVD)

/**
 * enum nvme_pel_ehai_pit - Persistent Event Header Additional Information - Port Identifier Type
 * @NVME_PEL_EHAI_PIT_NOT_REPORTED:	PIT not reported and PELPID does not apply
 * @NVME_PEL_EHAI_PIT_NSS_PORT:		NVM subsystem port
 * @NVME_PEL_EHAI_PIT_NMI_PORT:		NVMe-MI port
 * @NVME_PEL_EHAI_PIT_NOT_ASSOCIATED:	Event not associated with any port and PELPID does not apply
 */
enum nvme_pel_ehai_pit {
	NVME_PEL_EHAI_PIT_NOT_REPORTED		= 0,
	NVME_PEL_EHAI_PIT_NSS_PORT		= 1,
	NVME_PEL_EHAI_PIT_NMI_PORT		= 2,
	NVME_PEL_EHAI_PIT_NOT_ASSOCIATED	= 3,
};

/**
 * enum nvme_pel_vsedt_code - Persistent Event Log - Vendor Specific Event Data Type Code
 * @NVME_PEL_VSEDT_RSVD:		Reserved
 * @NVME_PEL_VSEDT_EVENT_NAME:		Event Name
 * @NVME_PEL_VSEDT_ASCII_STRING:	ASCII String
 * @NVME_PEL_VSEDT_BINARY:		Binary
 * @NVME_PEL_VSEDT_SIGNED_INT:		Signed Integer
 */
enum nvme_pel_vsedt_code {
	NVME_PEL_VSEDT_RSVD		= 0,
	NVME_PEL_VSEDT_EVENT_NAME	= 1,
	NVME_PEL_VSEDT_ASCII_STRING	= 2,
	NVME_PEL_VSEDT_BINARY		= 3,
	NVME_PEL_VSEDT_SIGNED_INT	= 4,
};

/**
 * struct nvme_vs_event_desc -  Vendor Specific Event Descriptor
 * @vsec:	Vendor Specific Event Code
 * @vsedt:	Vendor Specific Event Data Type
 * @uidx:	UUID Index
 * @vsedl:	Vendor Specific Event Data Length
 */
struct nvme_vs_event_desc {
	__le16	vsec;
	__u8	vsedt;
	__u8	uidx;
	__le16	vsedl;
};

/**
 * struct nvme_fw_commit_event - Firmware Commit Event Data
 * @old_fw_rev:			Old Firmware Revision
 * @new_fw_rev:			New Firmware Revision
 * @fw_commit_action:		Firmware Commit Action
 * @fw_slot:			Firmware Slot
 * @sct_fw:			Status Code Type for Firmware Commit Command
 * @sc_fw:			Status Returned for Firmware Commit Command
 * @vndr_assign_fw_commit_rc:	Vendor Assigned Firmware Commit Result Code
 */
struct nvme_fw_commit_event {
	__le64	old_fw_rev;
	__le64	new_fw_rev;
	__u8	fw_commit_action;
	__u8	fw_slot;
	__u8	sct_fw;
	__u8	sc_fw;
	__le16	vndr_assign_fw_commit_rc;
} __attribute__((packed));

#define NVME_TIMESTAMP_ATTR_SYNC(attr)	NVME_GET(attr, TIMESTAMP_ATTR_SYNC)
#define NVME_TIMESTAMP_ATTR_TO(attr)	NVME_GET(attr, TIMESTAMP_ATTR_TO)

/**
 * struct nvme_time_stamp_change_event - Timestamp Change Event
 * @previous_timestamp:		Previous Timestamp
 * @ml_secs_since_reset:	Milliseconds Since Reset
 */
struct nvme_time_stamp_change_event {
	__le64	previous_timestamp;
	__le64	ml_secs_since_reset;
};

/**
 * struct nvme_power_on_reset_info_list - Controller Reset Information
 * @cid:			Controller ID
 * @fw_act:			Firmware Activation
 * @op_in_prog:			Operation in Progress
 * @rsvd4:			Reserved
 * @ctrl_power_cycle:		Controller Power Cycle
 * @power_on_ml_seconds:	Power on milliseconds
 * @ctrl_time_stamp:		Controller Timestamp
 */
struct nvme_power_on_reset_info_list {
	__le16	 cid;
	__u8	 fw_act;
	__u8	 op_in_prog;
	__u8	 rsvd4[12];
	__le32	 ctrl_power_cycle;
	__le64	 power_on_ml_seconds;
	__le64	 ctrl_time_stamp;
} __attribute__((packed));

/**
 * struct nvme_nss_hw_err_event -  NVM Subsystem Hardware Error Event
 * @nss_hw_err_event_code:	NVM Subsystem Hardware Error Event Code
 * @rsvd2:			Reserved
 * @add_hw_err_info:		Additional Hardware Error Information
 */
struct nvme_nss_hw_err_event {
	__le16	nss_hw_err_event_code;
	__u8	rsvd2[2];
	__u8	*add_hw_err_info;
};

/**
 * struct nvme_change_ns_event - Change Namespace Event Data
 * @nsmgt_cdw10:	Namespace Management CDW10
 * @rsvd4:		Reserved
 * @nsze:		Namespace Size
 * @rsvd16:		Reserved
 * @nscap:		Namespace Capacity
 * @flbas:		Formatted LBA Size
 * @dps:		End-to-end Data Protection Type Settings
 * @nmic:		Namespace Multi-path I/O and Namespace Sharing Capabilities
 * @rsvd35:		Reserved
 * @ana_grp_id:		ANA Group Identifier
 * @nvmset_id:		NVM Set Identifier
 * @rsvd42:		Reserved
 * @nsid:		Namespace ID
 */
struct nvme_change_ns_event {
	__le32	nsmgt_cdw10;
	__u8	rsvd4[4];
	__le64	nsze;
	__u8	rsvd16[8];
	__le64	nscap;
	__u8	flbas;
	__u8	dps;
	__u8	nmic;
	__u8	rsvd35;
	__le32	ana_grp_id;
	__le16	nvmset_id;
	__le16	rsvd42;
	__le32	nsid;
};

/**
 * struct nvme_format_nvm_start_event - Format NVM Start Event Data
 * @nsid:		Namespace Identifier
 * @fna:		Format NVM Attributes
 * @rsvd5:		Reserved
 * @format_nvm_cdw10:	Format NVM CDW10
 */
struct nvme_format_nvm_start_event {
	__le32	nsid;
	__u8	fna;
	__u8	rsvd5[3];
	__le32	format_nvm_cdw10;
};

/**
 * struct nvme_format_nvm_compln_event - Format NVM Completion Event Data
 * @nsid:		Namespace Identifier
 * @smallest_fpi:	Smallest Format Progress Indicator
 * @format_nvm_status:	Format NVM Status
 * @compln_info:	Completion Information
 * @status_field:	Status Field
 */
struct nvme_format_nvm_compln_event {
	__le32	nsid;
	__u8	smallest_fpi;
	__u8	format_nvm_status;
	__le16	compln_info;
	__le32	status_field;
};

/**
 * struct nvme_sanitize_start_event - Sanitize Start Event Data
 * @sani_cap:	SANICAP
 * @sani_cdw10:	Sanitize CDW10
 * @sani_cdw11:	Sanitize CDW11
 */
struct nvme_sanitize_start_event {
	__le32	sani_cap;
	__le32	sani_cdw10;
	__le32	sani_cdw11;
};

/**
 * struct nvme_sanitize_compln_event - Sanitize Completion Event Data
 * @sani_prog:		Sanitize Progress
 * @sani_status:	Sanitize Status
 * @cmpln_info:		Completion Information
 * @rsvd6:		Reserved
 */
struct nvme_sanitize_compln_event {
	__le16	sani_prog;
	__le16	sani_status;
	__le16	cmpln_info;
	__u8	rsvd6[2];
};

/**
 * struct nvme_set_feature_event - Set Feature Event Data
 * @layout:	Set Feature Event Layout
 * @cdw_mem:	Command Dwords Memory buffer
 */
struct nvme_set_feature_event {
	__le32	layout;
	__le32	cdw_mem[0];
};

/**
 * enum nvme_set_feat_event_layout - This field indicates the set feature event layout
 * @NVME_SET_FEAT_EVENT_DW_COUNT_SHIFT:	Shift amount to get the Dword count from the
 *					&struct nvme_set_feature_event.layout field.
 * @NVME_SET_FEAT_EVENT_CC_DW0_SHIFT:	Shift amount to get the logged command completion Dword 0
 *					from the &struct nvme_set_feature_event.layout field.
 * @NVME_SET_FEAT_EVENT_MB_COUNT_SHIFT:	Shift amount to get the memory buffer count from
 *					the &struct nvme_set_feature_event.layout field.
 * @NVME_SET_FEAT_EVENT_DW_COUNT_MASK:	Mask to get the Dword count from the &struct
 *					nvme_set_feature_event.layout field.
 * @NVME_SET_FEAT_EVENT_CC_DW0_MASK:	Mask to get the logged command completion Dword 0 from
 *					the &struct nvme_set_feature_event.layout field.
 * @NVME_SET_FEAT_EVENT_MB_COUNT_MASK:	Mask to get the memory buffer count from the &struct
 *					nvme_set_feature_event.layout field.
 */
enum nvme_set_feat_event_layout {
	NVME_SET_FEAT_EVENT_DW_COUNT_SHIFT	= 0,
	NVME_SET_FEAT_EVENT_CC_DW0_SHIFT	= 3,
	NVME_SET_FEAT_EVENT_MB_COUNT_SHIFT	= 16,
	NVME_SET_FEAT_EVENT_DW_COUNT_MASK	= 0x7,
	NVME_SET_FEAT_EVENT_CC_DW0_MASK		= 0x1,
	NVME_SET_FEAT_EVENT_MB_COUNT_MASK	= 0xffff,
};

#define NVME_SET_FEAT_EVENT_DW_COUNT(layout)	NVME_GET(layout, SET_FEAT_EVENT_DW_COUNT)
#define NVME_SET_FEAT_EVENT_CC_DW0(layout)	NVME_GET(layout, SET_FEAT_EVENT_CC_DW0)
#define NVME_SET_FEAT_EVENT_MB_COUNT(layout)	NVME_GET(layout, SET_FEAT_EVENT_MB_COUNT)

/**
 * struct nvme_thermal_exc_event -  Thermal Excursion Event Data
 * @over_temp:	Over Temperature
 * @threshold:	temperature threshold
 */
struct nvme_thermal_exc_event {
	__u8	over_temp;
	__u8	threshold;
};

/**
 * struct nvme_cdp_change_event - CDP Change Event Data Format (Event Type 0Fh)
 * @ps:		Personality Status, see &enum nvme_cdp_change_event_ps.
 * @perid:	Personality Identifier of the personality whose settings a Set
 *		Features command requested to change, see &enum
 *		nvme_personality_identifier.
 * @rsvd2:	Reserved
 * @ped:	Personality Event Data: the data buffer of the Set Features
 *		command corresponding to @perid, if any.
 */
struct nvme_cdp_change_event {
	__u8	ps;
	__u8	perid;
	__u8	rsvd2[10];
	__u8	ped[];
};

/**
 * enum nvme_cdp_change_event_ps - CDP Change Event - Personality Status
 * @NVME_CDP_CHANGE_EVENT_PS_CDPCE:  CDP Change Error: If the change to the
 *				     settings of the specified personality was
 *				     successful, then this bit is cleared to
 *				     '0'; otherwise, this bit is set to '1'.
 * @NVME_CDP_CHANGE_EVENT_PS_CDPRFS: CDP Requested Freeze State: If the
 *				     personality was requested to be frozen,
 *				     then this bit is set to '1'; otherwise,
 *				     this bit is cleared to '0'.
 */
enum nvme_cdp_change_event_ps {
	NVME_CDP_CHANGE_EVENT_PS_CDPCE	= 1 << 0,
	NVME_CDP_CHANGE_EVENT_PS_CDPRFS	= 1 << 1,
};

/**
 * enum nvme_personality_identifier - Personality Identifier List
 * @NVME_PERID_MFG_DEFAULT:		Manufacturing Default Personality
 * @NVME_PERID_SECURITY:		Security Personality
 * @NVME_PERID_LOCKDOWN_PERSISTENCE:	Lockdown Persistence Personality, see
 *					&enum nvme_lockdown_persistence_cdw11
 *					and &enum
 *					nvme_lockdown_persistence_cqe_dw1
 * @NVME_PERID_REVERT_MFG_SETTINGS:	Revert to Subsystem Manufacturing
 *					Settings Personality: reverts all
 *					supported Features (other than CDP
 *					itself), restorable log pages, and
 *					vendor specific settings to their
 *					manufacturing default content for the
 *					current active firmware image. Uses no
 *					data buffer; requires an NVM Subsystem
 *					Reset (see &enum
 *					nvme_personality_mrstt) to take effect.
 * @NVME_PERID_ALL:			All Personalities
 */
enum nvme_personality_identifier {
	NVME_PERID_MFG_DEFAULT		= 0x00,
	NVME_PERID_SECURITY		= 0x01,
	NVME_PERID_LOCKDOWN_PERSISTENCE	= 0x02,
	NVME_PERID_REVERT_MFG_SETTINGS	= 0x03,
	NVME_PERID_ALL			= 0xff,
};

/**
 * enum nvme_lockdown_persistence_cdw11 - Lockdown Persistence Personality -
 *					   Command Dword 11 (Set Features)
 * @NVME_LOCKDOWN_PERSISTENCE_LDPE: Lockdown Persistence Enable: If set to
 *				     '1', then Lockdown Persistence is
 *				     enabled and the prohibitions of the
 *				     Lockdown command that affect all
 *				     controllers in the NVM subsystem persist
 *				     across power cycles of the NVM subsystem.
 *				     If cleared to '0', then Lockdown
 *				     Persistence is disabled.
 */
enum nvme_lockdown_persistence_cdw11 {
	NVME_LOCKDOWN_PERSISTENCE_LDPE	= 1 << 0,
};

/**
 * enum nvme_lockdown_persistence_cqe_dw1 - Lockdown Persistence Personality -
 *					     Get Features Completion Queue
 *					     Entry Dword 1
 * @NVME_LOCKDOWN_PERSISTENCE_LDPS: Lockdown Persistence State: set to '1' if
 *				     Lockdown Persistence is enabled; cleared
 *				     to '0' if disabled.
 */
enum nvme_lockdown_persistence_cqe_dw1 {
	NVME_LOCKDOWN_PERSISTENCE_LDPS	= 1 << 0,
};

/**
 * enum nvme_personality_mrstt - Personality Properties - Minimum Required
 *				  Reset Type (MRSTT)
 * @NVME_PERSONALITY_MRSTT_NONE:		No reset required
 * @NVME_PERSONALITY_MRSTT_CTRL_RESET:		Controller Level Reset required
 * @NVME_PERSONALITY_MRSTT_LIMITED_CTRL_RESET:	Controller Level Reset other
 *						than one initiated by a
 *						Controller Reset required
 * @NVME_PERSONALITY_MRSTT_NVM_SUBSYSTEM_RESET: NVM Subsystem Reset required
 * @NVME_PERSONALITY_MRSTT_POWER_CYCLE:	Main power cycle required
 */
enum nvme_personality_mrstt {
	NVME_PERSONALITY_MRSTT_NONE			= 0x00,
	NVME_PERSONALITY_MRSTT_CTRL_RESET		= 0x01,
	NVME_PERSONALITY_MRSTT_LIMITED_CTRL_RESET	= 0x02,
	NVME_PERSONALITY_MRSTT_NVM_SUBSYSTEM_RESET	= 0x03,
	NVME_PERSONALITY_MRSTT_POWER_CYCLE		= 0x04,
};

/**
 * enum nvme_personality_aus - Personality Properties - Authenticated
 *			       Unfreeze Support (AUS)
 * @NVME_PERSONALITY_AUS_PCAS: Physical Credential Authentication Support
 * @NVME_PERSONALITY_AUS_PKAS: Programmable Key Authentication Support
 */
enum nvme_personality_aus {
	NVME_PERSONALITY_AUS_PCAS	= 1 << 0,
	NVME_PERSONALITY_AUS_PKAS	= 1 << 1,
};

/**
 * enum nvme_personality_attrs - Personality Properties - Personality
 *				  Attributes
 * @NVME_PERSONALITY_ATTRS_PSCUDE: Personality Settings Change User Data
 *				    Effect
 */
enum nvme_personality_attrs {
	NVME_PERSONALITY_ATTRS_PSCUDE	= 1 << 0,
};

/**
 * struct nvme_personality_properties - Personality Properties data structure
 * @pps:	Personality Properties Size: size in bytes of this data
 *		structure.
 * @perid:	Personality Identifier, see &enum nvme_personality_identifier.
 * @mrstt:	Minimum Required Reset Type, see &enum nvme_personality_mrstt.
 * @aus:	Authenticated Unfreeze Support, see &enum
 *		nvme_personality_aus. Cleared to 0h if this personality does
 *		not support an authenticated unfreeze method, in which case a
 *		frozen instance of this personality is permanently frozen.
 * @attrs:	Personality Attributes, see &enum nvme_personality_attrs.
 */
struct nvme_personality_properties {
	__u8	pps;
	__u8	perid;
	__u8	mrstt;
	__u8	aus;
	__u8	attrs;
};

/**
 * struct nvme_dev_personalities_log - Device Personalities Log Page
 *					(Log Identifier 1Dh)
 * @nump:	Number of Personalities: number of &struct
 *		nvme_personality_properties entries in @perprops. This is a
 *		0's based value.
 * @cdplpv:	CDP Log Page Version
 * @dplphl:	Device Personalities Log Page Header Length
 * @cdplps:	Device Personalities Log Page Size: size of this log page in
 *		bytes.
 * @perprops:	CDP Personality list, listed in ascending order of
 *		Personality Identifier.
 */
struct nvme_dev_personalities_log {
	__le16	nump;
	__u8	cdplpv;
	__u8	dplphl;
	__le16	cdplps;
	struct nvme_personality_properties perprops[];
};

/**
 * enum nvme_mfg_default_config_status_mdcs - Manufacturer Default
 *		Configuration Status log page - Manufacturer Default
 *		Configuration Status (MDCS)
 * @NVME_MDCS_DSCS_SHIFT:	Shift amount to get the Default NVM Subsystem
 *				Configuration Status (DSCS)
 * @NVME_MDCS_DSCS_MASK:	Mask to get DSCS
 * @NVME_MDCS_DNCS_SHIFT:	Shift amount to get the Default Namespace
 *				Configuration Status (DNCS)
 * @NVME_MDCS_DNCS_MASK:	Mask to get DNCS
 * @NVME_MDCS_DCCS_SHIFT:	Shift amount to get the Default Capacity
 *				Configuration Status (DCCS)
 * @NVME_MDCS_DCCS_MASK:	Mask to get DCCS
 */
enum nvme_mfg_default_config_status_mdcs {
	NVME_MDCS_DSCS_SHIFT	= 0,
	NVME_MDCS_DSCS_MASK	= 0x1,
	NVME_MDCS_DNCS_SHIFT	= 1,
	NVME_MDCS_DNCS_MASK	= 0x1,
	NVME_MDCS_DCCS_SHIFT	= 2,
	NVME_MDCS_DCCS_MASK	= 0x1,
};

#define NVME_MDCS_DSCS(mdcs)	NVME_GET(mdcs, MDCS_DSCS)
#define NVME_MDCS_DNCS(mdcs)	NVME_GET(mdcs, MDCS_DNCS)
#define NVME_MDCS_DCCS(mdcs)	NVME_GET(mdcs, MDCS_DCCS)

/**
 * struct nvme_mfg_default_config_status_log - Manufacturer Default
 *		Configuration Status log page (Log Page Identifier 24h)
 * @mdcsv:	Manufacturer Default Configuration Status Version: version of
 *		this data structure, shall be cleared to 0h
 * @mdcs:	Manufacturer Default Configuration Status, see &enum
 *		nvme_mfg_default_config_status_mdcs
 */
struct nvme_mfg_default_config_status_log {
	__u8	mdcsv;
	__u8	mdcs;
};

/**
 * enum nvme_security_personality_attrs - Security Personality Attributes
 *					   data structure
 * @NVME_SEC_PERSONALITY_ASP:      Allow Security Protocol: If set, then the
 *				    security protocols specified by this data
 *				    structure shall be allowed; if cleared,
 *				    then they shall be prohibited.
 * @NVME_SEC_PERSONALITY_TCGP:	    TCG Security Protocol: specifies the
 *				    security protocol range 01h to 06h.
 * @NVME_SEC_PERSONALITY_AHATSDP:  Authentication in Host Attachments of
 *				    Transient Storage Devices Protocol:
 *				    specifies the security protocol value EEh.
 * @NVME_SEC_PERSONALITY_VSP_SHIFT: Shift amount to get the Vendor Specific
 *				    Protocol Fx bitmap (security protocols F0h
 *				    to FFh) field.
 * @NVME_SEC_PERSONALITY_VSP_MASK: Mask to get the Vendor Specific Protocol
 *				    Fx bitmap field.
 */
enum nvme_security_personality_attrs {
	NVME_SEC_PERSONALITY_ASP	= 1 << 0,
	NVME_SEC_PERSONALITY_TCGP	= 1 << 1,
	NVME_SEC_PERSONALITY_AHATSDP	= 1 << 2,
	NVME_SEC_PERSONALITY_VSP_SHIFT	= 16,
	NVME_SEC_PERSONALITY_VSP_MASK	= 0xffff,
};

#define NVME_SEC_PERSONALITY_VSP(attrs)	NVME_GET(attrs, SEC_PERSONALITY_VSP)

/**
 * struct nvme_lba_rd - LBA Range Descriptor
 * @rslba:	Range Starting LBA
 * @rnlb:	Range Number of Logical Blocks
 * @rsvd12:	Reserved
 */
struct nvme_lba_rd {
	__le64	rslba;
	__le32	rnlb;
	__u8	rsvd12[4];
};

/**
 * struct nvme_lbas_ns_element - LBA Status Log Namespace Element
 * @neid:	Namespace Element Identifier
 * @nlrd:	Number of LBA Range Descriptors
 * @ratype:	Recommended Action Type. see @enum nvme_lba_status_atype
 * @rsvd8:	Reserved
 * @lba_rd:	LBA Range Descriptor
 */
struct nvme_lbas_ns_element {
	__le32	neid;
	__le32	nlrd;
	__u8	ratype;
	__u8	rsvd8[7];
	struct	nvme_lba_rd lba_rd[];
};

/**
 * enum nvme_lba_status_atype - Action type the controller uses to return LBA status
 * @NVME_LBA_STATUS_ATYPE_ALLOCATED:		Return tracked allocated LBAs status
 * @NVME_LBA_STATUS_ATYPE_SCAN_UNTRACKED:	Perform scan and return Untracked and
 * 						Tracked Potentially Unrecoverable LBAs
 * 						status
 * @NVME_LBA_STATUS_ATYPE_TRACKED:		Return Tracked Potentially Unrecoverable
 * 						LBAs associated with physical storage
 */
enum nvme_lba_status_atype {
	NVME_LBA_STATUS_ATYPE_ALLOCATED		= 0x2,
	NVME_LBA_STATUS_ATYPE_SCAN_UNTRACKED	= 0x10,
	NVME_LBA_STATUS_ATYPE_TRACKED		= 0x11,
};

/**
 * struct nvme_lba_status_log - LBA Status Information Log
 * @lslplen:	LBA Status Log Page Length
 * @nlslne:	Number of LBA Status Log Namespace Elements
 * @estulb:	Estimate of Unrecoverable Logical Blocks
 * @rsvd12:	Reserved
 * @lsgc:	LBA Status Generation Counter
 * @elements:	LBA Status Log Namespace Element List
 */
struct nvme_lba_status_log {
	__le32	lslplen;
	__le32	nlslne;
	__le32	estulb;
	__u8	rsvd12[2];
	__le16	lsgc;
	struct nvme_lbas_ns_element elements[];
};

/**
 * struct nvme_eg_event_aggregate_log - Endurance Group Event Aggregate
 * @nr_entries:	Number of Entries
 * @egids:	Endurance Group Identifier
 */
struct nvme_eg_event_aggregate_log {
	__le64	nr_entries;
	__le16	egids[];
};

/**
 * enum nvme_fid_supported_effects - FID Supported and Effects Data Structure definitions
 * @NVME_FID_SUPPORTED_EFFECTS_FSUPP:		FID Supported
 * @NVME_FID_SUPPORTED_EFFECTS_UDCC:		User Data Content Change
 * @NVME_FID_SUPPORTED_EFFECTS_NCC:		Namespace Capability Change
 * @NVME_FID_SUPPORTED_EFFECTS_NIC:		Namespace Inventory Change
 * @NVME_FID_SUPPORTED_EFFECTS_CCC:		Controller Capability Change
 * @NVME_FID_SUPPORTED_EFFECTS_UUID_SEL:	UUID Selection Supported
 * @NVME_FID_SUPPORTED_EFFECTS_SCOPE_SHIFT:	FID Scope Shift
 * @NVME_FID_SUPPORTED_EFFECTS_SCOPE_MASK:	FID Scope Mask
 * @NVME_FID_SUPPORTED_EFFECTS_SCOPE_NS:	Namespace Scope
 * @NVME_FID_SUPPORTED_EFFECTS_SCOPE_CTRL:	Controller Scope
 * @NVME_FID_SUPPORTED_EFFECTS_SCOPE_NVM_SET:	NVM Set Scope
 * @NVME_FID_SUPPORTED_EFFECTS_SCOPE_ENDGRP:	Endurance Group Scope
 * @NVME_FID_SUPPORTED_EFFECTS_SCOPE_DOMAIN:	Domain Scope
 * @NVME_FID_SUPPORTED_EFFECTS_SCOPE_NSS:	NVM Subsystem Scope
 * @NVME_FID_SUPPORTED_EFFECTS_CDQSCP:		Controller Data Queue
 * @NVME_FID_SUPPORTED_EFFECTS_RUHS:		Reclaim Unit Handle Scope: if
 *						set, then modifying the
 *						attributes of the feature may
 *						impact Reclaim Unit Handles
 */
enum nvme_fid_supported_effects {
	NVME_FID_SUPPORTED_EFFECTS_FSUPP	= 1 << 0,
	NVME_FID_SUPPORTED_EFFECTS_UDCC		= 1 << 1,
	NVME_FID_SUPPORTED_EFFECTS_NCC		= 1 << 2,
	NVME_FID_SUPPORTED_EFFECTS_NIC		= 1 << 3,
	NVME_FID_SUPPORTED_EFFECTS_CCC		= 1 << 4,
	NVME_FID_SUPPORTED_EFFECTS_UUID_SEL	= 1 << 19,
	NVME_FID_SUPPORTED_EFFECTS_SCOPE_SHIFT	= 20,
	NVME_FID_SUPPORTED_EFFECTS_SCOPE_MASK	= 0xfff,
	NVME_FID_SUPPORTED_EFFECTS_SCOPE_NS	= 1 << 0,
	NVME_FID_SUPPORTED_EFFECTS_SCOPE_CTRL	= 1 << 1,
	NVME_FID_SUPPORTED_EFFECTS_SCOPE_NVM_SET= 1 << 2,
	NVME_FID_SUPPORTED_EFFECTS_SCOPE_ENDGRP	= 1 << 3,
	NVME_FID_SUPPORTED_EFFECTS_SCOPE_DOMAIN	= 1 << 4,
	NVME_FID_SUPPORTED_EFFECTS_SCOPE_NSS	= 1 << 5,
	NVME_FID_SUPPORTED_EFFECTS_CDQSCP	= 1 << 6,
	NVME_FID_SUPPORTED_EFFECTS_RUHS	= 1 << 7,
};

#define NVME_FID_SUPPORTED_EFFECTS_SCOPE(effects)	NVME_GET(effects, FID_SUPPORTED_EFFECTS_SCOPE)

/**
 * struct nvme_fid_supported_effects_log - Feature Identifiers Supported and Effects
 * @fid_support: Feature Identifier Supported
 *
 */
struct nvme_fid_supported_effects_log {
	__le32	fid_support[NVME_LOG_FID_SUPPORTED_EFFECTS_MAX];
};


/**
 * struct nvme_boot_partition - Boot Partition Log
 * @lid:			Boot Partition Identifier
 * @rsvd1:			Reserved
 * @bpinfo:			Boot Partition Information
 * @rsvd8:			Reserved
 * @boot_partition_data:	Contains the contents of the
 *				specified Boot Partition
 */
struct nvme_boot_partition {
	__u8	lid;
	__u8	rsvd1[3];
	__le32	bpinfo;
	__u8	rsvd8[8];
	__u8	boot_partition_data[];
};

/**
 * enum nvme_boot_partition_info - This field indicates the boot partition information
 * @NVME_BOOT_PARTITION_INFO_BPSZ_SHIFT:	Shift amount to get the boot partition size from
 *						the &struct nvme_boot_partition.bpinfo field.
 * @NVME_BOOT_PARTITION_INFO_ABPID_SHIFT:	Shift amount to get the active boot partition ID
 *						from the &struct nvme_boot_partition.bpinfo field.
 * @NVME_BOOT_PARTITION_INFO_BPSZ_MASK:		Mask to get the boot partition size from the
 *						&struct nvme_boot_partition.bpinfo field.
 * @NVME_BOOT_PARTITION_INFO_ABPID_MASK:	Mask to get the active boot partition ID from the
 *						&struct nvme_boot_partition.bpinfo field.
 */
enum nvme_boot_partition_info {
	NVME_BOOT_PARTITION_INFO_BPSZ_SHIFT	= 0,
	NVME_BOOT_PARTITION_INFO_ABPID_SHIFT	= 31,
	NVME_BOOT_PARTITION_INFO_BPSZ_MASK	= 0x7fff,
	NVME_BOOT_PARTITION_INFO_ABPID_MASK	= 0x1,
};

#define NVME_BOOT_PARTITION_INFO_BPSZ(bpinfo)	NVME_GET(bpinfo, BOOT_PARTITION_INFO_BPSZ)
#define NVME_BOOT_PARTITION_INFO_ABPID(bpinfo)	NVME_GET(bpinfo, BOOT_PARTITION_INFO_ABPID)

/**
 * struct nvme_rotational_media_info_log - Rotational Media Information Log
 * @endgid:	Endurance Group Identifier
 * @numa:	Number of Actuators
 * @nrs:	Nominal Rotational Speed
 * @rsvd6:	Reserved
 * @spinc:	Spinup Count
 * @fspinc:	Failed Spinup Count
 * @ldc:	Load Count
 * @fldc:	Failed Load Count
 * @rsvd24:	Reserved
 */
struct nvme_rotational_media_info_log {
	__le16	endgid;
	__le16	numa;
	__le16	nrs;
	__u8	rsvd6[2];
	__le32	spinc;
	__le32	fspinc;
	__le32	ldc;
	__le32	fldc;
	__u8	rsvd24[488];
};

/**
 * struct nvme_dispersed_ns_participating_nss_log - Dispersed Namespace Participating NVM Subsystems
 * Log
 * @genctr:		Generation Counter
 * @numpsub:		Number of Participating NVM Subsystems
 * @rsvd16:		Reserved
 * @participating_nss:	Participating NVM Subsystem Entry
 */
struct nvme_dispersed_ns_participating_nss_log {
	__le64	genctr;
	__le64	numpsub;
	__u8	rsvd16[240];
	__u8	participating_nss[];
};

/**
 * struct nvme_mgmt_addr_desc - Management Address Descriptor
 * @mat:	Management Address Type
 * @rsvd1:	Reserved
 * @madrs:	Management Address
 */
struct nvme_mgmt_addr_desc {
	__u8	mat;
	__u8	rsvd1[3];
	__u8	madrs[508];
};

/**
 * struct nvme_mgmt_addr_list_log - Management Address List Log
 * @mad:	Management Address Descriptor
 */
struct nvme_mgmt_addr_list_log {
	struct nvme_mgmt_addr_desc	mad[8];
};

/**
 * struct nvme_eom_lane_desc - EOM Lane Descriptor
 * @rsvd0:	Reserved
 * @mstatus:	Measurement Status
 * @lane:	Lane number
 * @eye:	Eye number
 * @top:	Absolute number of rows from center to top edge of eye
 * @bottom:	Absolute number of rows from center to bottom edge of eye
 * @left:	Absolute number of rows from center to left edge of eye
 * @right:	Absolute number of rows from center to right edge of eye
 * @nrows:	Number of Rows
 * @ncols:	Number of Columns
 * @edlen:	Eye Data Length
 * @rsvd18:	Reserved
 * @eye_desc:	Printable Eye, Eye Data, and any Padding
 */
struct nvme_eom_lane_desc {
	__u8	rsvd0;
	__u8	mstatus;
	__u8	lane;
	__u8	eye;
	__le16	top;
	__le16	bottom;
	__le16	left;
	__le16	right;
	__le16	nrows;
	__le16	ncols;
	__le16	edlen;
	__u8	rsvd18[14];
	__u8	eye_desc[];
};

/**
 * struct nvme_phy_rx_eom_log - Physical Interface Receiver Eye Opening Measurement Log
 * @lid:	Log Identifier
 * @eomip:	EOM In Progress
 * @hsize:	Header Size
 * @rsize:	Result Size
 * @eomdgn:	EOM Data Generation Number
 * @lr:		Log Revision
 * @odp:	Optional Data Present
 * @lanes:	Number of lanes configured for this port
 * @epl:	Eyes Per Lane
 * @lspfc:	Log Specific Parameter Field Copy
 * @li:		Link Information
 * @rsvd15:	Reserved
 * @lsic:	Log Specific Identifier Copy
 * @dsize:	Descriptor Size
 * @nd:		Number of Descriptors
 * @maxtb:	Maximum Top Bottom
 * @maxlr:	Maximum Left Right
 * @etgood:	Estimated Time for Good Quality
 * @etbetter:	Estimated Time for Better Quality
 * @etbest:	Estimated Time for Best Quality
 * @rsvd36:	Reserved
 * @descs:	EOM Lane Descriptors
 */
struct nvme_phy_rx_eom_log {
	__u8	lid;
	__u8	eomip;
	__le16	hsize;
	__le32	rsize;
	__u8	eomdgn;
	__u8	lr;
	__u8	odp;
	__u8	lanes;
	__u8	epl;
	__u8	lspfc;
	__u8	li;
	__u8	rsvd15[3];
	__le16	lsic;
	__le32	dsize;
	__le16	nd;
	__le16	maxtb;
	__le16	maxlr;
	__le16	etgood;
	__le16	etbetter;
	__le16	etbest;
	__u8	rsvd36[28];
	struct nvme_eom_lane_desc descs[];
};

/**
 * enum nvme_eom_optional_data_present - EOM Optional Data Present Fields
 * @NVME_EOM_ODP_PEFP_SHIFT:	Shift amount to get the printable eye field present
 *				from the &struct nvme_phy_rx_eom_log.odp field.
 * @NVME_EOM_ODP_EDFP_SHIFT:	Shift amount to get the eye data field present
 *				from the &struct nvme_phy_rx_eom_log.odp field.
 * @NVME_EOM_ODP_RSVD_SHIFT:	Shift amount to get the reserved optional data present
 *				from the &struct nvme_phy_rx_eom_log.odp field.
 * @NVME_EOM_ODP_PEFP_MASK:	Mask to get the printable eye field present
 *				from the &struct nvme_phy_rx_eom_log.odp field.
 * @NVME_EOM_ODP_EDFP_MASK:	Mask to get the eye data field present
 *				from the &struct nvme_phy_rx_eom_log.odp field.
 * @NVME_EOM_ODP_RSVD_MASK:	Mask to get the reserved data present
 *				from the &struct nvme_phy_rx_eom_log.odp field.
 */
enum nvme_eom_optional_data_present {
	NVME_EOM_ODP_PEFP_SHIFT	= 0,
	NVME_EOM_ODP_EDFP_SHIFT	= 1,
	NVME_EOM_ODP_RSVD_SHIFT	= 2,
	NVME_EOM_ODP_PEFP_MASK	= 0x1,
	NVME_EOM_ODP_EDFP_MASK	= 0x1,
	NVME_EOM_ODP_RSVD_MASK	= 0x3f,
};

#define NVME_EOM_ODP_PEFP(odp)	NVME_GET(odp, EOM_ODP_PEFP)
#define NVME_EOM_ODP_EDFP(odp)	NVME_GET(odp, EOM_ODP_EDFP)
#define NVME_EOM_ODP_RSVD(odp)	NVME_GET(odp, EOM_ODP_RSVD)

/**
 * enum nvme_eom_optional_data - EOM Optional Data Present Fields (Deprecated)
 * @NVME_EOM_PRINTABLE_EYE_PRESENT:	Printable Eye Present
 * @NVME_EOM_EYE_DATA_PRESENT:		Eye Data Present
 */
enum nvme_eom_optional_data {
	NVME_EOM_PRINTABLE_EYE_PRESENT	= NVME_EOM_ODP_PEFP_MASK << NVME_EOM_ODP_PEFP_SHIFT,
	NVME_EOM_EYE_DATA_PRESENT	= NVME_EOM_ODP_EDFP_MASK << NVME_EOM_ODP_EDFP_SHIFT,
};

/**
 * enum nvme_phy_rx_eom_progress - EOM In Progress Values
 * @NVME_PHY_RX_EOM_NOT_STARTED:	EOM Not Started
 * @NVME_PHY_RX_EOM_IN_PROGRESS:	EOM In Progress
 * @NVME_PHY_RX_EOM_COMPLETED:		EOM Completed
 */
enum nvme_phy_rx_eom_progress {
	NVME_PHY_RX_EOM_NOT_STARTED	= 0,
	NVME_PHY_RX_EOM_IN_PROGRESS	= 1,
	NVME_PHY_RX_EOM_COMPLETED	= 2,
};

/**
 * struct nvme_reachability_group_desc - Reachability Group Descriptor
 * @rgid:	Reachability Group ID
 * @nnid:	Number of NSID Values
 * @chngc:	Change Count
 * @rsvd16:	Reserved
 * @nsid:	Namespace Identifier List
 */
struct nvme_reachability_group_desc {
	__le32	rgid;
	__le32	nnid;
	__le64	chngc;
	__u8	rsvd16[16];
	__le32	nsid[];
};

/**
 * struct nvme_reachability_groups_log - Reachability Groups Log
 * @chngc:	Change Count
 * @nrgd:	Number of Reachability Group Descriptors
 * @rsvd10:	Reserved
 * @rgd:	Reachability Group Descriptor List
 */
struct nvme_reachability_groups_log {
	__le64					chngc;
	__le16					nrgd;
	__u8					rsvd10[6];
	struct nvme_reachability_group_desc	rgd[];
};

/**
 * struct nvme_reachability_association_desc - Reachability Association Descriptor
 * @rasid:	Reachability Association ID
 * @nrid:	Number of RGID Values
 * @chngc:	Change Count
 * @rac:	Reachability Association Characteristics
 * @rsvd17:	Reserved
 * @rgid:	Reachability Group Identifier List
 */
struct nvme_reachability_association_desc {
	__le32	rasid;
	__le32	nrid;
	__le64	chngc;
	__u8	rac;
	__u8	rsvd17[15];
	__le32	rgid[];
};

/**
 * struct nvme_reachability_associations_log - Reachability Associations Log
 * @chngc:	Change Count
 * @nrad:	Number of Reachability Association Descriptors
 * @rsvd10:	Reserved
 * @rad:	Reachability Association Descriptor List
 */
struct nvme_reachability_associations_log {
	__le64						chngc;
	__le16						nrad;
	__u8						rsvd10[6];
	struct nvme_reachability_association_desc	rad[];
};

/**
 * struct nvme_media_unit_stat_desc - Media Unit Status Descriptor
 * @muid:	  Media Unit Identifier
 * @domainid:	  Domain Identifier
 * @endgid:	  Endurance Group Identifier
 * @nvmsetid:	  NVM Set Identifier
 * @cap_adj_fctr: Capacity Adjustment Factor
 * @avl_spare:	  Available Spare
 * @percent_used: Percentage Used
 * @mucs:	  Number of Channels attached to media units
 * @cio:	  Channel Identifiers Offset
 */
struct nvme_media_unit_stat_desc {
	__le16	muid;
	__le16	domainid;
	__le16	endgid;
	__le16	nvmsetid;
	__le16	cap_adj_fctr;
	__u8	avl_spare;
	__u8	percent_used;
	__u8	mucs;
	__u8	cio;
};

/**
 * struct nvme_media_unit_stat_log - Media Unit Status
 * @nmu:	Number unit status descriptor
 * @cchans:	Number of Channels
 * @sel_config: Selected Configuration
 * @rsvd6:	Reserved
 * @mus_desc:	Media unit statistic descriptors
 */
struct nvme_media_unit_stat_log {
	__le16	nmu;
	__le16	cchans;
	__le16	sel_config;
	__u8	rsvd6[10];
	struct nvme_media_unit_stat_desc mus_desc[];
};

/**
 * struct nvme_media_unit_config_desc - Media Unit Configuration Descriptor
 * @muid:	Media Unit Identifier
 * @rsvd2:	Reserved
 * @mudl:	Media Unit Descriptor Length
 */
struct nvme_media_unit_config_desc {
	__le16	muid;
	__u8	rsvd2[4];
	__le16	mudl;
};

/**
 * struct nvme_channel_config_desc - Channel Configuration Descriptor
 * @chanid:		Channel Identifier
 * @chmus:		Number Channel Media Units
 * @mu_config_desc:	Channel Unit config descriptors.
 *			See @struct nvme_media_unit_config_desc
 */
struct nvme_channel_config_desc {
	__le16	chanid;
	__le16	chmus;
	struct nvme_media_unit_config_desc mu_config_desc[];
};

/**
 * struct nvme_end_grp_chan_desc - Endurance Group Channel Configuration Descriptor
 * @egchans:		Number of Channels
 * @chan_config_desc:	Channel config descriptors.
 *			See @struct nvme_channel_config_desc
 */
struct nvme_end_grp_chan_desc {
	__le16	egchans;
	struct nvme_channel_config_desc chan_config_desc[];
};

/**
 * struct nvme_end_grp_config_desc -  Endurance Group Configuration Descriptor
 * @endgid:		Endurance Group Identifier
 * @cap_adj_factor:	Capacity Adjustment Factor
 * @rsvd4:		Reserved
 * @tegcap:		Total Endurance Group Capacity
 * @segcap:		Spare Endurance Group Capacity
 * @end_est:		Endurance Estimate
 * @egsets:		Number of NVM Sets
 * @rsvd64:		Reserved
 * @nvmsetid:		NVM Set Identifier
 */
struct nvme_end_grp_config_desc {
	__le16	endgid;
	__le16	cap_adj_factor;
	__u8	rsvd4[12];
	__u8	tegcap[16];
	__u8	segcap[16];
	__u8	end_est[16];
	__u8	rsvd64[16];
	__le16	egsets;
	__le16	nvmsetid[];
};

/**
 * struct nvme_capacity_config_desc - Capacity Configuration structure definitions
 * @cap_config_id:	Capacity Configuration Identifier
 * @domainid:		Domain Identifier
 * @egcn:		Number Endurance Group Configuration
 *			Descriptors
 * @rsvd6:		Reserved
 * @egcd:		Endurance Group Config descriptors.
 *			See @struct nvme_end_grp_config_desc
 */
struct nvme_capacity_config_desc {
	__le16	cap_config_id;
	__le16	domainid;
	__le16	egcn;
	__u8	rsvd6[26];
	struct nvme_end_grp_config_desc egcd[];
};

/**
 * struct nvme_supported_cap_config_list_log - Supported Capacity Configuration list log page
 * @sccn:		Number of capacity configuration
 * @rsvd1:		Reserved
 * @cap_config_desc:	Capacity configuration descriptor.
 *			See @struct nvme_capacity_config_desc
 */
struct nvme_supported_cap_config_list_log {
	__u8	sccn;
	__u8	rsvd1[15];
	struct nvme_capacity_config_desc cap_config_desc[];
};

/**
 * struct nvme_lockdown_log - Command and Feature Lockdown Log
 * @cfila:	Contents of the Command and Feature Identifier List field in the log page.
 * @rsvd1:	Reserved
 * @lngth:	Length of Command and Feature Identifier List field
 * @cfil:	Command and Feature Identifier List
 */
struct nvme_lockdown_log {
	__u8	cfila;
	__u8	rsvd1[2];
	__u8	lngth;
	__u8	cfil[508];
};

/**
 * enum nvme_lockdown_csel - Lockdown Command Dword 10 - Controller Select
 *			     (CSEL)
 * @NVME_LOCKDOWN_CSEL_NVM_SUBSYSTEM:	NVM Subsystem: this command affects
 *					all controllers in the NVM subsystem.
 * @NVME_LOCKDOWN_CSEL_SPECIFIC_CTRL:	Specific Controller: this command
 *					affects the controller specified in
 *					the Controller Select Specific (CSS)
 *					field of Command Dword 14.
 * @NVME_LOCKDOWN_CSEL_SECONDARY_CTRLS: Secondary Controllers for a Specific
 *					 Primary Controller: this command
 *					 affects all secondary controllers
 *					 associated with the primary
 *					 controller specified in the CSS
 *					 field of Command Dword 14.
 * @NVME_LOCKDOWN_CSEL_VENDOR_SPECIFIC: Vendor Specific
 */
enum nvme_lockdown_csel {
	NVME_LOCKDOWN_CSEL_NVM_SUBSYSTEM	= 0x0,
	NVME_LOCKDOWN_CSEL_SPECIFIC_CTRL	= 0x1,
	NVME_LOCKDOWN_CSEL_SECONDARY_CTRLS	= 0x2,
	NVME_LOCKDOWN_CSEL_VENDOR_SPECIFIC	= 0xf,
};

/**
 * enum nvme_lockdown_log_lsp - Command and Feature Lockdown Log Specific
 *				 Parameter field (Get Log Page Command Dword
 *				 10 LSP field)
 * @NVME_LOCKDOWN_LOG_LSP_SCP_SHIFT:	Shift amount to get the Scope (SCP)
 * @NVME_LOCKDOWN_LOG_LSP_SCP_MASK:	Mask to get SCP
 * @NVME_LOCKDOWN_LOG_LSP_CNTTS_SHIFT:	Shift amount to get the Contents
 *					(CNTTS)
 * @NVME_LOCKDOWN_LOG_LSP_CNTTS_MASK:	Mask to get CNTTS
 * @NVME_LOCKDOWN_LOG_LSP_ELPF:		Enhanced Log Page Format: if set,
 *					then the Controller-scoped Enhanced
 *					log page format (see &struct
 *					nvme_lockdown_log_enhanced) is
 *					requested instead of &struct
 *					nvme_lockdown_log. The Controller
 *					Identifier is specified via the Log
 *					Specific Identifier field of Command
 *					Dword 11 (%NVME_LOG_CDW11_LSI_SHIFT).
 */
enum nvme_lockdown_log_lsp {
	NVME_LOCKDOWN_LOG_LSP_SCP_SHIFT		= 0,
	NVME_LOCKDOWN_LOG_LSP_SCP_MASK		= 0xf,
	NVME_LOCKDOWN_LOG_LSP_CNTTS_SHIFT	= 4,
	NVME_LOCKDOWN_LOG_LSP_CNTTS_MASK	= 0x3,
	NVME_LOCKDOWN_LOG_LSP_ELPF		= 1 << 6,
};

#define NVME_LOCKDOWN_LOG_LSP_SCP(lsp)	 NVME_GET(lsp, LOCKDOWN_LOG_LSP_SCP)
#define NVME_LOCKDOWN_LOG_LSP_CNTTS(lsp) NVME_GET(lsp, LOCKDOWN_LOG_LSP_CNTTS)

/**
 * struct nvme_lockdown_cfi_desc - Command and Feature Identifier Descriptor
 * @cfi:   Command and Feature Identifier: contents depend on the Contents
 *	   Selected (CS) and Scope Selected (SS) fields of @struct
 *	   nvme_lockdown_log_enhanced.cfia.
 * @cfia:  Command and Feature Identifier Attributes, see &enum
 *	   nvme_lockdown_cfi_desc_cfia.
 */
struct nvme_lockdown_cfi_desc {
	__u8	cfi;
	__u8	cfia;
};

/**
 * enum nvme_lockdown_cfi_desc_cfia - Command and Feature Identifier
 *				       Descriptor - Command and Feature
 *				       Identifier Attributes (CFIA)
 * @NVME_LOCKDOWN_CFI_DESC_CFIA_ACNTL: All Controllers: if set, then @cfi is
 *				       reported by all controllers in the NVM
 *				       subsystem; if cleared, then @cfi is
 *				       reported by at least one but not all
 *				       controllers in the NVM subsystem.
 */
enum nvme_lockdown_cfi_desc_cfia {
	NVME_LOCKDOWN_CFI_DESC_CFIA_ACNTL	= 1 << 0,
};

/**
 * enum nvme_lockdown_log_enhanced_cfia - Command and Feature Lockdown Log
 *					   Page - Enhanced - Command and
 *					   Feature Identifier Attributes
 *					   (CFIA)
 * @NVME_LOCKDOWN_LOG_ENHANCED_CFIA_SS_SHIFT:    Shift amount to get the
 *						  Scope Selected (SS)
 * @NVME_LOCKDOWN_LOG_ENHANCED_CFIA_SS_MASK:	  Mask to get SS
 * @NVME_LOCKDOWN_LOG_ENHANCED_CFIA_CS_SHIFT:    Shift amount to get the
 *						  Contents Selected (CS)
 * @NVME_LOCKDOWN_LOG_ENHANCED_CFIA_CS_MASK:	  Mask to get CS
 */
enum nvme_lockdown_log_enhanced_cfia {
	NVME_LOCKDOWN_LOG_ENHANCED_CFIA_SS_SHIFT	= 0,
	NVME_LOCKDOWN_LOG_ENHANCED_CFIA_SS_MASK	= 0xf,
	NVME_LOCKDOWN_LOG_ENHANCED_CFIA_CS_SHIFT	= 4,
	NVME_LOCKDOWN_LOG_ENHANCED_CFIA_CS_MASK	= 0x3,
};

#define NVME_LOCKDOWN_LOG_ENHANCED_CFIA_SS(cfia) \
	NVME_GET(cfia, LOCKDOWN_LOG_ENHANCED_CFIA_SS)
#define NVME_LOCKDOWN_LOG_ENHANCED_CFIA_CS(cfia) \
	NVME_GET(cfia, LOCKDOWN_LOG_ENHANCED_CFIA_CS)

/**
 * struct nvme_lockdown_log_enhanced - Command and Feature Lockdown Log Page
 *					- Enhanced
 * @ver:    Version: cleared to 0h.
 * @cfia:   Command and Feature Identifier Attributes, see &enum
 *	    nvme_lockdown_log_enhanced_cfia.
 * @cntlid: Controller Identifier this log page applies to. FFFFh indicates
 *	    the descriptor list entries are each reported by one or more
 *	    controllers in the NVM subsystem, rather than a single
 *	    controller.
 * @sze:    Size of this log page in bytes.
 * @ncfid:  Number of Command and Feature Identifier Descriptors in @cfid.
 * @cfids:  Command and Feature Identifier Descriptors Size: size in bytes
 *	    of each entry in @cfid.
 * @rsvd12: Reserved
 * @cfid:   Command and Feature Identifier Descriptor list, see &struct
 *	    nvme_lockdown_cfi_desc.
 */
struct nvme_lockdown_log_enhanced {
	__u8				ver;
	__u8				cfia;
	__le16				cntlid;
	__le32				sze;
	__le16				ncfid;
	__le16				cfids;
	__u8				rsvd12[4];
	struct nvme_lockdown_cfi_desc	cfid[];
};

/**
 * struct nvme_sanitize_log_page - Sanitize Status (Log Identifier 81h)
 * @sprog:	Sanitize Progress (SPROG): indicates the fraction complete of the
 *		sanitize operation. The value is a numerator of the fraction
 *		complete that has 65,536 (10000h) as its denominator. This value
 *		shall be set to FFFFh if the @sstat field is not set to
 *		%NVME_SANITIZE_SSTAT_STATUS_IN_PROGRESS.
 * @sstat:	Sanitize Status (SSTAT): indicates the status associated with
 *		the most recent sanitize operation. See &enum nvme_sanitize_sstat.
 * @scdw10:	Sanitize Command Dword 10 Information (SCDW10): contains the value
 *		of the Command Dword 10 field of the Sanitize command that started
 *		the sanitize operation.
 * @eto:	Estimated Time For Overwrite: indicates the number of seconds required
 *		to complete an Overwrite sanitize operation with 16 passes in
 *		the background when the No-Deallocate Modifies Media After Sanitize
 *		field is not set to 10b. A value of 0h indicates that the sanitize
 *		operation is expected to be completed in the background when the
 *		Sanitize command that started that operation is completed. A value
 *		of FFFFFFFFh indicates that no time period is reported.
 * @etbe:	Estimated Time For Block Erase: indicates the number of seconds
 *		required to complete a Block Erase sanitize operation in the
 *		background when the No-Deallocate Modifies Media After Sanitize
 *		field is not set to 10b. A value of 0h indicates that the sanitize
 *		operation is expected to be completed in the background when the
 *		Sanitize command that started that operation is completed.
 *		A value of FFFFFFFFh indicates that no time period is reported.
 * @etce:	Estimated Time For Crypto Erase: indicates the number of seconds
 *		required to complete a Crypto Erase sanitize operation in the
 *		background when the No-Deallocate Modifies Media After Sanitize
 *		field is not set to 10b. A value of 0h indicates that the sanitize
 *		operation is expected to be completed in the background when the
 *		Sanitize command that started that operation is completed.
 *		A value of FFFFFFFFh indicates that no time period is reported.
 * @etond:	Estimated Time For Overwrite With No-Deallocate Media Modification:
 *		indicates the number of seconds required to complete an Overwrite
 *		sanitize operation and the associated additional media modification
 *		after the Overwrite sanitize operation in the background when
 *		the No-Deallocate After Sanitize bit was set to 1 in the Sanitize
 *		command that requested the Overwrite sanitize operation; and
 *		the No-Deallocate Modifies Media After Sanitize field is set to 10b.
 *		A value of 0h indicates that the sanitize operation is expected
 *		to be completed in the background when the Sanitize command that
 *		started that operation is completed. A value of FFFFFFFFh indicates
 *		that no time period is reported.
 * @etbend:	Estimated Time For Block Erase With No-Deallocate Media Modification:
 *		indicates the number of seconds required to complete a Block Erase
 *		sanitize operation and the associated additional media modification
 *		after the Block Erase sanitize operation in the background when
 *		the No-Deallocate After Sanitize bit was set to 1 in the Sanitize
 *		command that requested the Overwrite sanitize operation; and
 *		the No-Deallocate Modifies Media After Sanitize field is set to 10b.
 *		A value of 0h indicates that the sanitize operation is expected
 *		to be completed in the background when the Sanitize command that
 *		started that operation is completed. A value of FFFFFFFFh indicates
 *		that no time period is reported.
 * @etcend:	Estimated Time For Crypto Erase With No-Deallocate Media Modification:
 *		indicates the number of seconds required to complete a Crypto Erase
 *		sanitize operation and the associated additional media modification
 *		after the Crypto Erase sanitize operation in the background when
 *		the No-Deallocate After Sanitize bit was set to 1 in the Sanitize
 *		command that requested the Overwrite sanitize operation; and
 *		the No-Deallocate Modifies Media After Sanitize field is set to 10b.
 *		A value of 0h indicates that the sanitize operation is expected
 *		to be completed in the background when the Sanitize command that
 *		started that operation is completed. A value of FFFFFFFFh indicates
 *		that no time period is reported.
 * @etpvds:	Estimated Time For Post-Verification Deallocation State: indicates the
 *		number of seconds required to deallocate all media allocated for user data
 *		after exiting the Media Verification state (i.e., the time difference between
 *		entering and exiting the Post-Verification Deallocation state), if that state
 *		is entered as part of the sanitize operation. A value of FFFFFFFFh indicates
 *		that no time period is reported.
 * @ssi:	Sanitize State Information: indicate the state of the Sanitize Operation
 *		State Machine.
 * @rsvd37:	Reserved
 */
struct nvme_sanitize_log_page {
	__le16	sprog;
	__le16	sstat;
	__le32	scdw10;
	__le32	eto;
	__le32	etbe;
	__le32	etce;
	__le32	etond;
	__le32	etbend;
	__le32	etcend;
	__le32	etpvds;
	__u8	ssi;
	__u8	rsvd37[475];
};

/**
 * enum nvme_sanitize_sstat - Sanitize Status (SSTAT)
 * @NVME_SANITIZE_SSTAT_STATUS_SHIFT:	 Shift amount to get the status value of
 *					 the most recent sanitize operation from
 *					 the &struct nvme_sanitize_log_page.sstat
 *					 field.
 * @NVME_SANITIZE_SSTAT_STATUS_MASK:	 Mask to get the status value of the most
 *					 recent sanitize operation.
 * @NVME_SANITIZE_SSTAT_STATUS_NEVER_SANITIZED: The NVM subsystem has never been
 *					 sanitized.
 * @NVME_SANITIZE_SSTAT_STATUS_COMPLETE_SUCCESS: The most recent sanitize operation
 *					 completed successfully including any
 *					 additional media modification.
 * @NVME_SANITIZE_SSTAT_STATUS_IN_PROGRESS: A sanitize operation is currently in
 *					 progress.
 * @NVME_SANITIZE_SSTAT_STATUS_COMPLETED_FAILED: The most recent sanitize operation
 *					 failed.
 * @NVME_SANITIZE_SSTAT_STATUS_ND_COMPLETE_SUCCESS: The most recent sanitize operation
 *					 for which No-Deallocate After Sanitize was
 *					 requested has completed successfully with
 *					 deallocation of all user data.
 * @NVME_SANITIZE_SSTAT_COMPLETED_PASSES_SHIFT: Shift amount to get the number
 *					 of completed passes if the most recent
 *					 sanitize operation was an Overwrite. This
 *					 value shall be cleared to 0h if the most
 *					 recent sanitize operation was not
 *					 an Overwrite.
 * @NVME_SANITIZE_SSTAT_COMPLETED_PASSES_MASK: Mask to get the number of completed
 *					 passes.
 * @NVME_SANITIZE_SSTAT_GLOBAL_DATA_ERASED_SHIFT: Shift amount to get the Global
 *					 Data Erased value from the
 *					 &struct nvme_sanitize_log_page.sstat field.
 * @NVME_SANITIZE_SSTAT_GLOBAL_DATA_ERASED_MASK: Mask to get the Global Data Erased
 *					 value.
 * @NVME_SANITIZE_SSTAT_GLOBAL_DATA_ERASED: Global Data Erased: if set, then no
 *					 namespace user data in the NVM subsystem
 *					 has been written to and no Persistent
 *					 Memory Region in the NVM subsystem has
 *					 been enabled since being manufactured and
 *					 the NVM subsystem has never been sanitized;
 *					 or since the most recent successful sanitize
 *					 operation.
 * @NVME_SANITIZE_SSTAT_MVCNCLD_SHIFT:	Shift amount to get the value of Media Verification
 *					Canceled bit of Sanitize status field.
 * @NVME_SANITIZE_SSTAT_MVCNCLD_MASK:	Mask to get the value of Media Verification Canceled
 *					bit of Sanitize status field.
 * @NVME_SANITIZE_SSTAT_PRGD_SHIFT:	Shift amount to get the Purged (PRGD)
 *					bit of Sanitize status field.
 * @NVME_SANITIZE_SSTAT_PRGD_MASK:	Mask to get the Purged (PRGD) bit of
 *					Sanitize status field.
 * @NVME_SANITIZE_SSTAT_PRGD:		Purged: if set, then the most recent
 *					sanitize operation purged user data, as
 *					defined by IEEE Std 2883, because the
 *					Purge Required (PREQ) bit was set to
 *					'1' in the command that started that
 *					sanitize operation.
 */
enum nvme_sanitize_sstat {
	NVME_SANITIZE_SSTAT_STATUS_SHIFT		= 0,
	NVME_SANITIZE_SSTAT_STATUS_MASK			= 0x7,
	NVME_SANITIZE_SSTAT_STATUS_NEVER_SANITIZED	= 0,
	NVME_SANITIZE_SSTAT_STATUS_COMPLETE_SUCCESS	= 1,
	NVME_SANITIZE_SSTAT_STATUS_IN_PROGRESS		= 2,
	NVME_SANITIZE_SSTAT_STATUS_COMPLETED_FAILED	= 3,
	NVME_SANITIZE_SSTAT_STATUS_ND_COMPLETE_SUCCESS	= 4,
	NVME_SANITIZE_SSTAT_COMPLETED_PASSES_SHIFT	= 3,
	NVME_SANITIZE_SSTAT_COMPLETED_PASSES_MASK	= 0x1f,
	NVME_SANITIZE_SSTAT_GLOBAL_DATA_ERASED_SHIFT	= 8,
	NVME_SANITIZE_SSTAT_GLOBAL_DATA_ERASED_MASK	= 0x1,
	NVME_SANITIZE_SSTAT_GLOBAL_DATA_ERASED		= 1 << NVME_SANITIZE_SSTAT_GLOBAL_DATA_ERASED_SHIFT,
	NVME_SANITIZE_SSTAT_MVCNCLD_SHIFT		= 9,
	NVME_SANITIZE_SSTAT_MVCNCLD_MASK		= 0x1,
	NVME_SANITIZE_SSTAT_PRGD_SHIFT			= 11,
	NVME_SANITIZE_SSTAT_PRGD_MASK			= 0x1,
	NVME_SANITIZE_SSTAT_PRGD			= 1 << NVME_SANITIZE_SSTAT_PRGD_SHIFT,
};

#define NVME_SANITIZE_SSTAT_STATUS(sstat)		NVME_GET(sstat, SANITIZE_SSTAT_STATUS)
#define NVME_SANITIZE_SSTAT_COMPLETED_PASSES(sstat)	NVME_GET(sstat, SANITIZE_SSTAT_COMPLETED_PASSES)
#define NVME_SANITIZE_SSTAT_GLOBAL_DATA_ERASED(sstat)	NVME_GET(sstat, SANITIZE_SSTAT_GLOBAL_DATA_ERASED)
#define NVME_SANITIZE_SSTAT_MVCNCLD(sstat)		NVME_GET(sstat, SANITIZE_SSTAT_MVCNCLD)

/**
 * enum nvme_sanitize_ssi - Sanitize State Information (SSI)
 * @NVME_SANITIZE_SSI_SANS_SHIFT:		Shift amount to get the value of Sanitize State
 *						from Sanitize State Information (SSI) field.
 * @NVME_SANITIZE_SSI_SANS_MASK:		Mask to get the value of Sanitize State from
 *						Sanitize State Information (SSI) field.
 * @NVME_SANITIZE_SSI_FAILS_SHIFT:		Shift amount to get the value of Failure State
 *						from Sanitize State Information (SSI) field.
 * @NVME_SANITIZE_SSI_FAILS_MASK:		Mask to get the value of Failure State from
 *						Sanitize State Information (SSI) field.
 * @NVME_SANITIZE_SSI_IDLE:			No sanitize operation is in process.
 * @NVME_SANITIZE_SSI_RESTRICT_PROCESSING:	The Sanitize operation is in Restricted Processing
 *						State.
 * @NVME_SANITIZE_SSI_RESTRICT_FAILURE:		The Sanitize operation is in Restricted Failure
 *						State. This state is entered if sanitize processing
 *						was performed in the Restricted Processing state and
 *						sanitize processing failed or a failure occurred
 *						during deallocation of media allocated for user data
 *						in the Post-Verification Deallocation state.
 * @NVME_SANITIZE_SSI_UNRESTRICT_PROCESSING:	The Sanitize operation is in Unrestricted Processing
 *						State.
 * @NVME_SANITIZE_SSI_UNRESTRICT_FAILURE:	The Sanitize operation is in Unrestricted Failure
 *						State. This state is entered if sanitize processing
 *						was performed in the Unrestricted Processing state
 *						and sanitize processing failed or a failure occurred
 *						during deallocation of media allocated for user data
 *						in the Post-Verification.
 * @NVME_SANITIZE_SSI_MEDIA_VERIFICATION:	The Sanitize operation is in Media Verification
 *						State. In this state, the sanitize processing
 *						completed successfully, and all media allocated for
 *						user data in the sanitization target is readable by
 *						the host for purposes of verifying sanitization.
 * @NVME_SANITIZE_SSI_POST_VERIF_DEALLOC:	The Sanitize operation is in Post-Verification
 *						Deallocation State. In this state, the controller
 *						shall deallocate all media allocated for user data
 *						in the sanitization target.
 */
enum nvme_sanitize_ssi {
	NVME_SANITIZE_SSI_SANS_SHIFT		= 0,
	NVME_SANITIZE_SSI_SANS_MASK		= 0xf,
	NVME_SANITIZE_SSI_FAILS_SHIFT		= 4,
	NVME_SANITIZE_SSI_FAILS_MASK		= 0xf,
	NVME_SANITIZE_SSI_IDLE			= 0,
	NVME_SANITIZE_SSI_RESTRICT_PROCESSING	= 1,
	NVME_SANITIZE_SSI_RESTRICT_FAILURE	= 2,
	NVME_SANITIZE_SSI_UNRESTRICT_PROCESSING	= 3,
	NVME_SANITIZE_SSI_UNRESTRICT_FAILURE	= 4,
	NVME_SANITIZE_SSI_MEDIA_VERIFICATION	= 5,
	NVME_SANITIZE_SSI_POST_VERIF_DEALLOC	= 6,
};

#define NVME_SANITIZE_SSI_SANS(ssi)	NVME_GET(ssi, SANITIZE_SSI_SANS)
#define NVME_SANITIZE_SSI_FAILS(ssi)	NVME_GET(ssi, SANITIZE_SSI_FAILS)

/**
 * enum nvme_lockdown_log_scope - lockdown log page scope attributes
 * @NVME_LOCKDOWN_ADMIN_CMD:		Scope value for Admin commandS
 * @NVME_LOCKDOWN_FEATURE_ID:		Scope value for Feature ID
 * @NVME_LOCKDOWN_MI_CMD_SET:		Scope value for Management Interface commands
 * @NVME_LOCKDOWN_PCI_CMD_SET:		Scope value for PCI commands
 */
enum nvme_lockdown_log_scope {
	NVME_LOCKDOWN_ADMIN_CMD		= 0x0,
	NVME_LOCKDOWN_FEATURE_ID	= 0x2,
	NVME_LOCKDOWN_MI_CMD_SET	= 0x3,
	NVME_LOCKDOWN_PCI_CMD_SET	= 0x4,
};

/**
 * enum nvme_lockdown_log_contents - lockdown log page content attributes
 * @NVME_LOCKDOWN_SUPPORTED_CMD:		Content value for Supported commands
 * @NVME_LOCKDOWN_PROHIBITED_CMD:		Content value for prohibited commands
 * @NVME_LOCKDOWN_PROHIBITED_OUTOFBAND_CMD:	Content value for prohibited side band commands
 */
enum nvme_lockdown_log_contents {
	NVME_LOCKDOWN_SUPPORTED_CMD		= 0x0,
	NVME_LOCKDOWN_PROHIBITED_CMD		= 0x1,
	NVME_LOCKDOWN_PROHIBITED_OUTOFBAND_CMD	= 0x2,
};

/**
 * enum nvme_lockdown_scope_contents - Lockdown Log shift and mask
 * @NVME_LOCKDOWN_SS_SHIFT:	Lockdown log scope select Shift
 * @NVME_LOCKDOWN_SS_MASK:	Lockdown log scope select Mask
 * @NVME_LOCKDOWN_CS_SHIFT:	Lockdown log contents Shift
 * @NVME_LOCKDOWN_CS_MASK:	Lockdown log contents Mask
 */
enum nvme_lockdown_scope_contents {
	NVME_LOCKDOWN_SS_SHIFT	= 0,
	NVME_LOCKDOWN_SS_MASK	= 0xf,
	NVME_LOCKDOWN_CS_SHIFT	= 4,
	NVME_LOCKDOWN_CS_MASK	= 0x3,
};

/**
 * enum nvme_pma - Power Measurement Attributes (PMA) field
 * @NVME_PMA_PME_SHIFT:		Shift amount to get the power measurement enable
 * @NVME_PMA_NCPDF_SHIFT:	Shift amount to get the non-contiguous power data flag
 * @NVME_PMA_EPF_SHIFT:		Shift amount to get the estimated power flag
 * @NVME_PMA_MIPWRTS_SHIFT:	Shift amount to get the maximum interval power timestamp support
 * @NVME_PMA_PHDO_SHIFT:	Shift amount to get the power histogram descriptor overflow
 * @NVME_PMA_PMT_SHIFT:		Shift amount to get the power measurement type
 * @NVME_PMA_PME_MASK:		Mask to get the power measurement enable
 * @NVME_PMA_NCPDF_MASK:	Mask to get the non-contiguous power data flag
 * @NVME_PMA_EPF_MASK:		Mask to get the estimated power flag
 * @NVME_PMA_MIPWRTS_MASK:	Mask to get the maximum interval power timestamp support
 * @NVME_PMA_PHDO_MASK:		Mask to get the power histogram descriptor overflow
 * @NVME_PMA_PMT_MASK:		Mask to get the power measurement type
 */
enum nvme_pma {
	NVME_PMA_PME_SHIFT	= 0,
	NVME_PMA_NCPDF_SHIFT	= 1,
	NVME_PMA_EPF_SHIFT	= 2,
	NVME_PMA_MIPWRTS_SHIFT	= 3,
	NVME_PMA_PHDO_SHIFT	= 4,
	NVME_PMA_PMT_SHIFT	= 12,
	NVME_PMA_PME_MASK	= 0x1,
	NVME_PMA_NCPDF_MASK	= 0x1,
	NVME_PMA_EPF_MASK	= 0x1,
	NVME_PMA_MIPWRTS_MASK	= 0x1,
	NVME_PMA_PHDO_MASK	= 0x1,
	NVME_PMA_PMT_MASK	= 0xf,
};

#define NVME_PMA_PME(pma)	NVME_GET(pma, PMA_PME)
#define NVME_PMA_NCPDF(pma)	NVME_GET(pma, PMA_NCPDF)
#define NVME_PMA_EPF(pma)	NVME_GET(pma, PMA_EPF)
#define NVME_PMA_MIPWRTS(pma)	NVME_GET(pma, PMA_MIPWRTS)
#define NVME_PMA_PHDO(pma)	NVME_GET(pma, PMA_PHDO)
#define NVME_PMA_PMT(pma)	NVME_GET(pma, PMA_PMT)

/**
 * struct nvme_power_histogram_desc - Power Histogram Descriptor
 * @phbc:	Power Histogram Bin Count. Does not wrap after %FFFFFFFFh.
 *		Cleared to %0h if PMC is %0h.
 * @phblt:	Power Histogram Bin Lower Threshold. Bits 17:16 are PWRS
 *		(see &enum nvme_psd_ps), bits 15:0 are PWRV.
 */
struct nvme_power_histogram_desc {
	__le32	phbc;
	__le32	phblt;
};

/**
 * struct nvme_timestamp - Timestamp - Data Structure for Get Features
 * @timestamp:	Timestamp value based on origin and synch field
 * @attr:	Attribute
 * @rsvd:	Reserved
 */
struct nvme_timestamp {
	__u8 timestamp[6];
	__u8 attr;
	__u8 rsvd;
};

/**
 * struct nvme_voltage_measurement_log - Voltage Measurement Log Page
 *					  (Log Identifier 27h)
 * @vmgn:   Voltage Measurement Generation Number: incremented each time a
 *	    Set Features command starts Voltage Measurements.
 * @vma:    Voltage Measurement Attributes, see &enum
 *	    nvme_voltage_measurement_vma.
 * @vsi:    Voltage Sensor Info, see &enum nvme_voltage_measurement_vsi.
 *	    Meaningless if the VMC bit is cleared to '0' in @vma.
 * @vmlsz:  Voltage Measurement Log Size: size of this log page in bytes.
 * @nvmds:  Number of Voltage Measurement Descriptors Supported: maximum
 *	    number of entries in the Interval Voltage Measurement Descriptor
 *	    list.
 * @nvmde:  Number of Voltage Measurement Descriptors Entries: number of
 *	    entries in @ivmd.
 * @svmtr:  Stop Voltage Measurement Time Remaining, in minutes rounded up.
 * @svmts:  Stop Voltage Measurement Timestamp: time at which interval
 *	    voltage measurements stopped being collected. See &struct
 *	    nvme_timestamp.
 * @cntlid: Controller Identifier associated with @vsi, @svmts, @ovts, and
 *	    @uvts.
 * @vlvss:  Voltage Log Vendor Specific Size: size in bytes of the Vendor
 *	    Specific field following @ivmd.
 * @rsvd26: Reserved
 * @ovol:   Overvoltage, see &enum nvme_voltage_measurement_ovol.
 * @ovc:    Overvoltage Count.
 * @ovlt:   Overvoltage Log Threshold, in units of the Voltage Sensor Sample
 *	    Scale.
 * @ovts:   Overvoltage Timestamp. See &struct nvme_timestamp.
 * @iovpe:  Interval Overvoltage Percent Error (0 to 100). 255 indicates a
 *	    value is not reported.
 * @uvol:   Undervoltage, see &enum nvme_voltage_measurement_uvol.
 * @uvc:    Undervoltage Count.
 * @uvlt:   Undervoltage Log Threshold, in units of the Voltage Sensor
 *	    Sample Scale.
 * @uvts:   Undervoltage Timestamp. See &struct nvme_timestamp.
 * @iuvpe:  Interval Undervoltage Percent Error (0 to 100). 255 indicates a
 *	    value is not reported.
 * @rsvd62: Reserved
 * @ivmd:   Interval Voltage Measurement Descriptor list, see &enum
 *	    nvme_voltage_measurement_ivmd. Followed by a Vendor Specific
 *	    field of @vlvss bytes, if non-zero.
 */
struct nvme_voltage_measurement_log {
	__u8			vmgn;
	__u8			vma;
	__le16			vsi;
	__le32			vmlsz;
	__le16			nvmds;
	__le16			nvmde;
	__le16			svmtr;
	struct nvme_timestamp	svmts;
	__le16			cntlid;
	__le16			vlvss;
	__u8			rsvd26[6];
	__le16			ovol;
	__le16			ovc;
	__le16			ovlt;
	struct nvme_timestamp	ovts;
	__u8			iovpe;
	__le16			uvol;
	__le16			uvc;
	__le16			uvlt;
	struct nvme_timestamp	uvts;
	__u8			iuvpe;
	__u8			rsvd62[2];
	__le16			ivmd[];
} __attribute__((packed));

/**
 * enum nvme_timestamp_attr - Timestamp Attribute field
 * @NVME_TIMESTAMP_ATTR_SYNC_SHIFT:	Shift amount to get the timestamp synch
 * @NVME_TIMESTAMP_ATTR_TO_SHIFT:	Shift amount to get the timestamp origin
 * @NVME_TIMESTAMP_ATTR_SYNC_MASK:	Mask to get the timestamp synch
 * @NVME_TIMESTAMP_ATTR_TO_MASK:	Mask to get the timestamp origin
 */
enum nvme_timestamp_attr {
	NVME_TIMESTAMP_ATTR_SYNC_SHIFT	= 0,
	NVME_TIMESTAMP_ATTR_TO_SHIFT	= 1,
	NVME_TIMESTAMP_ATTR_SYNC_MASK	= 0x1,
	NVME_TIMESTAMP_ATTR_TO_MASK	= 0x7,
};


/**
 * struct nvme_power_meas_log - Power Measurement Log Page (Log Identifier 25h)
 * @ver:	Version. Shall be cleared to %0h.
 * @pmgn:	Power Measurement Generation Number. Incremented each time a
 *		Set Features command with Action = %1h (Start Power Measurements)
 *		is successfully completed. Rolls over from %FFh to %0h.
 * @pma:	Power Measurement Attributes. See &enum nvme_pma.
 * @sze:	Size. Indicates the size of this log page in bytes.
 * @pmc:	Power Measurement Count. Number of interval power measurements
 *		collected. Does not wrap after %FFFFFFFFh. Cleared to %0h when
 *		Start Power Measurements succeeds or if no measurement has occurred.
 * @nphd:	Number of Power Histogram Descriptors in this log page.
 * @smtr:	Stop Measurement Time Remaining. Time remaining in minutes until
 *		controller stops collecting interval power measurements.
 *		%0h means not specified.
 * @smts:	Stop Measurement Timestamp. Timestamp of when interval power
 *		measurements stopped being collected. See &struct nvme_timestamp.
 * @phds:	Power Histogram Descriptor Size. Size in bytes of each descriptor.
 * @phbs:	Power Histogram Bin Size. Size in milliwatts of each bin.
 *		Shall be set to 250 milliwatts.
 * @nphds:	Number of Power Histogram Descriptors Supported. Maximum number
 *		of descriptors that can be reported. If %0h, NPHD shall be
 *		cleared to %0h and no descriptors are reported.
 * @vss:	Vendor Specific Size. Size in bytes of the Vendor Specific field.
 * @phdoc:	Power Histogram Descriptor Overflow Count. Number of interval
 *		power measurements greater than the maximum power indicated by
 *		the last Power Histogram Descriptor. Does not wrap after %FFFFFFFFh.
 * @rsvd36:	Reserved.
 * @aipwr:	Average Interval Power. Bits 31:18 are reserved. Bits 17:16
 *		contain the Power Scale (PWRS); see &enum nvme_psd_ps. Bits 15:0
 *		contain the Power Value (PWRV).
 * @mipwr:	Maximum Interval Power. Bits 31:18 are reserved. Bits 17:16
 *		contain the Power Scale (PWRS); see &enum nvme_psd_ps. Bits 15:0
 *		contain the Power Value (PWRV).
 * @mipwrt:	Maximum Interval Power Timestamp. Timestamp of when the maximum
 *		interval power was collected. See &struct nvme_timestamp.
 * @ipwrpe:	Interval Power Percent Error. Maximum percent error (0-100%).
 *		Values 101-254 reserved. 255 indicates not reported.
 * @rsvd57:	Reserved.
 * @descs:	Power Histogram Descriptors (&struct nvme_power_histogram_desc).
 */
struct nvme_power_meas_log {
	__u8	ver;
	__u8	pmgn;
	__le16	pma;
	__le32	sze;
	__le32	pmc;
	__le16	nphd;
	__le16	smtr;
	struct nvme_timestamp	smts;
	__le16	phds;
	__le16	phbs;
	__le16	nphds;
	__le16	vss;
	__le32	phdoc;
	__u8	rsvd36[4];
	__le32	aipwr;
	__le32	mipwr;
	struct nvme_timestamp	mipwrt;
	__u8	ipwrpe;
	__u8	rsvd57[7];
	struct nvme_power_histogram_desc descs[];
};


/**
 * struct nvme_lba_status_desc - LBA Status Descriptor Entry
 * @dslba:	Descriptor Starting LBA
 * @nlb:	Number of Logical Blocks
 * @rsvd12:	Reserved
 * @status:	Additional status about this LBA range
 * @rsvd14:	Reserved
 */
struct nvme_lba_status_desc {
	__le64	dslba;
	__le32	nlb;
	__u8	rsvd12;
	__u8	status;
	__u8	rsvd14[2];
};

/**
 * struct nvme_lba_status - LBA Status Descriptor List
 * @nlsd:	Number of LBA Status Descriptors
 * @cmpc:	Completion Condition
 * @rsvd5:	Reserved
 * @descs:	LBA status descriptor Entry
 */
struct nvme_lba_status {
	__le32	nlsd;
	__u8	cmpc;
	__u8	rsvd5[3];
	struct nvme_lba_status_desc descs[];
};

/**
 * enum nvme_lba_status_cmpc - Get LBA Status Command Completion Condition
 * @NVME_LBA_STATUS_CMPC_NO_CMPC:	No indication of the completion condition
 * @NVME_LBA_STATUS_CMPC_INCOMPLETE:	Command completed, but additional LBA Status
 *					Descriptor Entries are available to transfer
 *					or scan did not complete (if ATYPE = 10h)
 * @NVME_LBA_STATUS_CMPC_COMPLETE:	Completed the specified action over the number
 *					of LBAs specified in the Range Length field and
 *					transferred all available LBA Status Descriptors
 */
enum nvme_lba_status_cmpc {
	NVME_LBA_STATUS_CMPC_NO_CMPC	= 0x0,
	NVME_LBA_STATUS_CMPC_INCOMPLETE	= 0x1,
	NVME_LBA_STATUS_CMPC_COMPLETE	= 0x2,
};

/**
 * struct nvme_feat_auto_pst - Autonomous Power State Transition
 * @apst_entry: See &enum nvme_apst_entry
 */
struct nvme_feat_auto_pst {
	__le64	apst_entry[32];
};

/**
 * enum nvme_apst_entry - Autonomous Power State Transition
 * @NVME_APST_ENTRY_ITPS_SHIFT:	Idle Transition Power State Shift
 * @NVME_APST_ENTRY_ITPT_SHIFT:	Idle Time Prior to Transition Shift
 * @NVME_APST_ENTRY_ITPS_MASK:	Idle Transition Power State Mask
 * @NVME_APST_ENTRY_ITPT_MASK:	Idle Time Prior to Transition Mask
 */
enum nvme_apst_entry {
	NVME_APST_ENTRY_ITPS_SHIFT = 3,
	NVME_APST_ENTRY_ITPT_SHIFT = 8,
	NVME_APST_ENTRY_ITPS_MASK = 0x1f,
	NVME_APST_ENTRY_ITPT_MASK = 0xffffff,
};

/**
 * struct nvme_std_perf_attr - Standard performance attribute structure
 * @rsvd0:	Reserved
 * @r4karl:	Random 4 KiB average read latency
 * @rsvd5:	Reserved
 */
struct nvme_std_perf_attr {
	__u8 rsvd0[4];
	__u8 r4karl;
	__u8 rsvd5[4091];
};

/**
 * struct nvme_perf_attr_id - Performance attribute identifier structure
 * @id:	Performance attribute identifier
 */
struct nvme_perf_attr_id {
	__u8 id[NVME_UUID_LEN];
};

/**
 * struct nvme_perf_attr_id_list - Performance attribute identifier list structure
 * @attrtyp:	Bits 7-3: Reserved
 *		Bits 2-0: Attribute type
 * @msvspa:	Maximum saveable vendor specific performance attributes
 * @usvspa:	Unused saveable vendor specific performance attributes
 * @rsvd3:	Reserved
 * @id_list:	Performance attribute identifier list
 * @rsvd1024:	Reserved
 */
struct nvme_perf_attr_id_list {
	__u8 attrtyp;
	__u8 msvspa;
	__u8 usvspa;
	__u8 rsvd3[13];
	struct nvme_perf_attr_id id_list[63];
	__u8 rsvd1024[3072];
};

/**
 * struct nvme_vs_perf_attr - Vendor specific performance attribute structure
 * @paid:	Performance attribute identifier
 * @rsvd16:	Reserved
 * @attrl:	Attribute Length
 * @vs:		Vendor specific
 */
struct nvme_vs_perf_attr {
	__u8 paid[16];
	__u8 rsvd16[14];
	__le16 attrl;
	__u8 vs[4064];
};

/**
 * struct nvme_perf_characteristics - Performance attribute structure
 * @std_perf:	Standard performance attribute
 * @id_list:	Performance attribute identifier list
 * @vs_perf:	Vendor specific performance attribute
 * @attr_buf:	Attribute buffer
 */
struct nvme_perf_characteristics {
	union {
		struct nvme_std_perf_attr std_perf[0];
		struct nvme_perf_attr_id_list id_list[0];
		struct nvme_vs_perf_attr vs_perf[0];
		__u8 attr_buf[4096];
	};
};

/**
 * struct nvme_metadata_element_desc - Metadata Element Descriptor
 * @type:	Element Type (ET)
 * @rev:	Element Revision (ER)
 * @len:	Element Length (ELEN)
 * @val:	Element Value (EVAL), UTF-8 string
 */
struct nvme_metadata_element_desc {
	__u8	type;
	__u8	rev;
	__le16	len;
	__u8	val[0];
};

/**
 * struct nvme_host_metadata - Host Metadata Data Structure
 * @ndesc:	Number of metadata element descriptors
 * @rsvd1:	Reserved
 * @descs:	Metadata element descriptors
 * @descs_buf:	Metadata element descriptor buffer
 */
struct nvme_host_metadata {
	__u8	ndesc;
	__u8	rsvd1;
	union {
		struct nvme_metadata_element_desc descs[0];
		__u8 descs_buf[4094];
	};
};

/**
 * enum nvme_host_metadata_cdw11 - Host Metadata Features (7Dh/7Eh/7Fh) -
 *				    Command Dword 11
 * @NVME_HOST_METADATA_GDHM: Generate Default Host Metadata (Get Features
 *			     Command Dword 11 only)
 * @NVME_HOST_METADATA_EA_SHIFT: Shift amount to set the Element Action (EA)
 *				 field (Set Features Command Dword 11 only)
 * @NVME_HOST_METADATA_EA_MASK: Mask to set EA
 */
enum nvme_host_metadata_cdw11 {
	NVME_HOST_METADATA_GDHM	= 1 << 0,
	NVME_HOST_METADATA_EA_SHIFT	= 13,
	NVME_HOST_METADATA_EA_MASK	= 0x3,
};

#define NVME_HOST_METADATA_EA(cdw11)	NVME_GET(cdw11, HOST_METADATA_EA)

/**
 * enum nvme_host_metadata_ea - Host Metadata Features - Element Action (EA)
 * @NVME_HOST_METADATA_EA_ADD_REPLACE: Add or Replace Entry
 * @NVME_HOST_METADATA_EA_DELETE_MULTIPLE: Delete Entry Multiple
 * @NVME_HOST_METADATA_EA_ADD_MULTIPLE: Add Entry Multiple
 */
enum nvme_host_metadata_ea {
	NVME_HOST_METADATA_EA_ADD_REPLACE	= 0,
	NVME_HOST_METADATA_EA_DELETE_MULTIPLE	= 1,
	NVME_HOST_METADATA_EA_ADD_MULTIPLE	= 2,
};

/**
 * enum nvme_ctrl_metadata_type - Controller Metadata Element Types
 * @NVME_CTRL_METADATA_OS_CTRL_NAME:		Name of the controller in
 *						the operating system.
 * @NVME_CTRL_METADATA_OS_DRIVER_NAME:		Name of the driver in the
 *						operating system.
 * @NVME_CTRL_METADATA_OS_DRIVER_VER:		Version of the driver in
 *						the operating system.
 * @NVME_CTRL_METADATA_PRE_BOOT_CTRL_NAME:	Name of the controller in
 *						the pre-boot environment.
 * @NVME_CTRL_METADATA_PRE_BOOT_DRIVER_NAME:	Name of the driver in the
 *						pre-boot environment.
 * @NVME_CTRL_METADATA_PRE_BOOT_DRIVER_VER:	Version of the driver in the
 *						pre-boot environment.
 * @NVME_CTRL_METADATA_SYS_PROC_MODEL:		Model of the processor.
 * @NVME_CTRL_METADATA_CHIPSET_DRV_NAME:	Chipset driver name.
 * @NVME_CTRL_METADATA_CHIPSET_DRV_VERSION:	Chipset driver version.
 * @NVME_CTRL_METADATA_OS_NAME_AND_BUILD:	Operating system name and build.
 * @NVME_CTRL_METADATA_SYS_PROD_NAME:		System product name.
 * @NVME_CTRL_METADATA_FIRMWARE_VERSION:	Host firmware (e.g UEFI) version.
 * @NVME_CTRL_METADATA_OS_DRIVER_FILENAME:	Operating system driver filename.
 * @NVME_CTRL_METADATA_DISPLAY_DRV_NAME:	Display driver name.
 * @NVME_CTRL_METADATA_DISPLAY_DRV_VERSION:	Display driver version.
 * @NVME_CTRL_METADATA_HOST_DET_FAIL_REC:	Failure record.
 */
enum nvme_ctrl_metadata_type {
	NVME_CTRL_METADATA_OS_CTRL_NAME		= 0x01,
	NVME_CTRL_METADATA_OS_DRIVER_NAME	= 0x02,
	NVME_CTRL_METADATA_OS_DRIVER_VER	= 0x03,
	NVME_CTRL_METADATA_PRE_BOOT_CTRL_NAME	= 0x04,
	NVME_CTRL_METADATA_PRE_BOOT_DRIVER_NAME	= 0x05,
	NVME_CTRL_METADATA_PRE_BOOT_DRIVER_VER	= 0x06,
	NVME_CTRL_METADATA_SYS_PROC_MODEL	= 0x07,
	NVME_CTRL_METADATA_CHIPSET_DRV_NAME	= 0x08,
	NVME_CTRL_METADATA_CHIPSET_DRV_VERSION	= 0x09,
	NVME_CTRL_METADATA_OS_NAME_AND_BUILD	= 0x0a,
	NVME_CTRL_METADATA_SYS_PROD_NAME	= 0x0b,
	NVME_CTRL_METADATA_FIRMWARE_VERSION	= 0x0c,
	NVME_CTRL_METADATA_OS_DRIVER_FILENAME	= 0x0d,
	NVME_CTRL_METADATA_DISPLAY_DRV_NAME	= 0x0e,
	NVME_CTRL_METADATA_DISPLAY_DRV_VERSION	= 0x0f,
	NVME_CTRL_METADATA_HOST_DET_FAIL_REC	= 0x10,
};

/**
 * enum nvme_ns_metadata_type - Namespace Metadata Element Types
 * @NVME_NS_METADATA_OS_NS_NAME:	Name of the namespace in the
 *					operating system
 * @NVME_NS_METADATA_PRE_BOOT_NS_NAME:	Name of the namespace in the pre-boot
 *					environment.
 * @NVME_NS_METADATA_OS_NS_QUAL_1:	First qualifier of the Operating System
 *					Namespace Name.
 * @NVME_NS_METADATA_OS_NS_QUAL_2:	Second qualifier of the Operating System
 *					Namespace Name.
 */
enum nvme_ns_metadata_type {
	NVME_NS_METADATA_OS_NS_NAME		= 0x01,
	NVME_NS_METADATA_PRE_BOOT_NS_NAME	= 0x02,
	NVME_NS_METADATA_OS_NS_QUAL_1		= 0x03,
	NVME_NS_METADATA_OS_NS_QUAL_2		= 0x04,
};

/**
 * struct nvme_lba_range_type_entry - LBA Range Type - Data Structure Entry
 * @type:	Specifies the Type of the LBA range
 * @attributes: Specifies attributes of the LBA range
 * @rsvd2:	Reserved
 * @slba:	Starting LBA
 * @nlb:	Number of Logical Blocks
 * @guid:	Unique Identifier
 * @rsvd48:	Reserved
 */
struct nvme_lba_range_type_entry {
	__u8	type;
	__u8	attributes;
	__u8	rsvd2[14];
	__le64	slba;
	__le64	nlb;
	__u8	guid[16];
	__u8	rsvd48[16];
};

/**
 * enum nvme_lbart - LBA Range Type - Data Structure Entry
 * @NVME_LBART_TYPE_GP:		General Purpose
 * @NVME_LBART_TYPE_FS:		Filesystem
 * @NVME_LBART_TYPE_RAID:	RAID
 * @NVME_LBART_TYPE_CACHE:	Cache
 * @NVME_LBART_TYPE_SWAP:	Page / swap file
 * @NVME_LBART_ATTRB_LBARO_SHIFT: LBA range overwriteable shift
 * @NVME_LBART_ATTRB_HLBAR_SHIFT: Hide LBA range shift
 * @NVME_LBART_ATTRB_LBARO_MASK: LBA range overwriteable mask
 * @NVME_LBART_ATTRB_HLBAR_MASK: Hide LBA range mask
 * @NVME_LBART_ATTRIB_TEMP:	Temp
 * @NVME_LBART_ATTRIB_HIDE:	Hidden
 */
enum nvme_lbart {
	NVME_LBART_TYPE_GP		= 0,
	NVME_LBART_TYPE_FS		= 1,
	NVME_LBART_TYPE_RAID		= 2,
	NVME_LBART_TYPE_CACHE		= 3,
	NVME_LBART_TYPE_SWAP		= 0,
	NVME_LBART_ATTRB_LBARO_SHIFT	= 0,
	NVME_LBART_ATTRB_HLBAR_SHIFT	= 1,
	NVME_LBART_ATTRB_LBARO_MASK	= 0x1,
	NVME_LBART_ATTRB_HLBAR_MASK	= 0x1,
	NVME_LBART_ATTRIB_TEMP		= NVME_VAL(LBART_ATTRB_LBARO),
	NVME_LBART_ATTRIB_HIDE		= NVME_VAL(LBART_ATTRB_HLBAR),
};

#define NVME_LBART_ATTRB_LBARO(attrb)	NVME_GET(attrb, LBART_ATTRB_LBARO)
#define NVME_LBART_ATTRB_HLBAR(attrb)	NVME_GET(attrb, LBART_ATTRB_HLBAR)

/**
 * struct nvme_lba_range_type - LBA Range Type
 * @entry:	LBA range type entry. See @struct nvme_lba_range_type_entry
 */
struct nvme_lba_range_type {
	struct nvme_lba_range_type_entry entry[NVME_FEAT_LBA_RANGE_MAX];
};

/**
 * struct nvme_plm_config - Predictable Latency Mode - Deterministic Threshold Configuration Data Structure
 * @ee:		Enable Event
 * @rsvd2:	Reserved
 * @dtwinrt:	DTWIN Reads Threshold
 * @dtwinwt:	DTWIN Writes Threshold
 * @dtwintt:	DTWIN Time Threshold
 * @rsvd56:	Reserved
 */
struct nvme_plm_config {
	__le16	ee;
	__u8	rsvd2[30];
	__le64	dtwinrt;
	__le64	dtwinwt;
	__le64	dtwintt;
	__u8	rsvd56[456];
};

/**
 * struct nvme_feat_host_behavior - Host Behavior Support - Data Structure
 * @acre:	Advanced Command Retry Enable
 * @etdas:	Extended Telemetry Data Area 4 Supported
 * @lbafee:	LBA Format Extension Enable
 * @hdisns:	Host Dispersed Namespace Support
 * @cdfe:	Copy Descriptor Formats Enable
 * @rsvd6:	Reserved
 */
struct nvme_feat_host_behavior {
	__u8 acre;
	__u8 etdas;
	__u8 lbafee;
	__u8 hdisns;
	__le16 cdfe;
	__u8 rsvd6[506];
};

/**
 * enum nvme_host_behavior_support - Enable Advanced Command
 * @NVME_ENABLE_ACRE:	Enable Advanced Command Retry Enable
 */
enum nvme_host_behavior_support {
	NVME_ENABLE_ACRE	= 1 << 0,
};

/**
 * struct nvme_streams_directive_params -  Streams Directive - Return Parameters Data Structure
 * @msl:	Max Streams Limit
 * @nssa:	NVM Subsystem Streams Available
 * @nsso:	NVM Subsystem Streams Open
 * @nssc:	NVM Subsystem Stream Capability
 * @rsvd:	Reserved
 * @sws:	Stream Write Size
 * @sgs:	Stream Granularity Size
 * @nsa:	Namespace Streams Allocated
 * @nso:	Namespace Streams Open
 * @rsvd2:	Reserved
 */
struct nvme_streams_directive_params {
	__le16	msl;
	__le16	nssa;
	__le16	nsso;
	__u8	nssc;
	__u8	rsvd[9];
	__le32	sws;
	__le16	sgs;
	__le16	nsa;
	__le16	nso;
	__u8	rsvd2[6];
};

/**
 * struct nvme_streams_directive_status - Streams Directive - Get Status Data Structure
 * @osc: Open Stream Count
 * @sid: Stream Identifier
 */
struct nvme_streams_directive_status {
	__le16	osc;
	__le16	sid[];
};

/**
 * struct nvme_id_directives -	Identify Directive - Return Parameters Data Structure
 * @supported:	Identify directive is supported
 * @enabled:	Identify directive is Enabled
 * @rsvd64:	Reserved
 */
struct nvme_id_directives {
	__u8	supported[32];
	__u8	enabled[32];
	__u8	rsvd64[4032];
};

/**
 * enum nvme_directive_types - Directives Supported or Enabled
 * @NVME_ID_DIR_ID_BIT: Identify directive is supported
 * @NVME_ID_DIR_SD_BIT: Streams directive is supported
 * @NVME_ID_DIR_DP_BIT: Direct Placement directive is supported
 */
enum nvme_directive_types {
	NVME_ID_DIR_ID_BIT	= 0,
	NVME_ID_DIR_SD_BIT	= 1,
	NVME_ID_DIR_DP_BIT	= 2,
};

/**
 * struct nvme_host_mem_buf_attrs - Host Memory Buffer - Attributes Data Structure
 * @hsize:	Host Memory Buffer Size
 * @hmdlal:	Host Memory Descriptor List Lower Address
 * @hmdlau:	Host Memory Descriptor List Upper Address
 * @hmdlec:	Host Memory Descriptor List Entry Count
 * @rsvd16:	Reserved
 */
struct nvme_host_mem_buf_attrs {
	__le32	hsize;
	__le32	hmdlal;
	__le32	hmdlau;
	__le32	hmdlec;
	__u8	rsvd16[4080];

};

/**
 * enum nvme_ae_type - Asynchronous Event Type
 * @NVME_AER_ERROR:	Error event
 * @NVME_AER_SMART:	SMART / Health Status event
 * @NVME_AER_NOTICE:	Notice event
 * @NVME_AER_IMMEDIATE:	Immediate
 * @NVME_AER_ONESHOT:	One-Shot
 * @NVME_AER_CSS:	NVM Command Set Specific events
 * @NVME_AER_VS:	Vendor Specific event
 */
enum nvme_ae_type {
	NVME_AER_ERROR				= 0,
	NVME_AER_SMART				= 1,
	NVME_AER_NOTICE				= 2,
	NVME_AER_IMMEDIATE			= 3,
	NVME_AER_ONESHOT			= 4,
	NVME_AER_CSS				= 6,
	NVME_AER_VS				= 7,
};

/**
 * enum nvme_ae_info_error - Asynchronous Event Information - Error Status
 * @NVME_AER_ERROR_INVALID_DB_REG:		Write to Invalid Doorbell Register
 * @NVME_AER_ERROR_INVALID_DB_VAL:		Invalid Doorbell Write Value
 * @NVME_AER_ERROR_DIAG_FAILURE:		Diagnostic Failure
 * @NVME_AER_ERROR_PERSISTENT_INTERNAL_ERROR:	Persistent Internal Error
 * @NVME_AER_ERROR_TRANSIENT_INTERNAL_ERROR:	Transient Internal Error
 * @NVME_AER_ERROR_FW_IMAGE_LOAD_ERROR:		Firmware Image Load Error
 */
enum nvme_ae_info_error {
	NVME_AER_ERROR_INVALID_DB_REG			= 0x00,
	NVME_AER_ERROR_INVALID_DB_VAL			= 0x01,
	NVME_AER_ERROR_DIAG_FAILURE			= 0x02,
	NVME_AER_ERROR_PERSISTENT_INTERNAL_ERROR	= 0x03,
	NVME_AER_ERROR_TRANSIENT_INTERNAL_ERROR		= 0x04,
	NVME_AER_ERROR_FW_IMAGE_LOAD_ERROR		= 0x05,
};

/**
 * enum nvme_ae_info_smart - Asynchronous Event Information - SMART / Health Status
 * @NVME_AER_SMART_SUBSYSTEM_RELIABILITY:	NVM subsystem Reliability
 * @NVME_AER_SMART_TEMPERATURE_THRESHOLD:	Temperature Threshold
 * @NVME_AER_SMART_SPARE_THRESHOLD:		Spare Below Threshold
 */
enum nvme_ae_info_smart {
	NVME_AER_SMART_SUBSYSTEM_RELIABILITY		= 0x00,
	NVME_AER_SMART_TEMPERATURE_THRESHOLD		= 0x01,
	NVME_AER_SMART_SPARE_THRESHOLD			= 0x02,
};

/**
 * enum nvme_ae_info_css_nvm - Asynchronous Event Information - I/O Command Specific Status
 * @NVME_AER_CSS_NVM_RESERVATION:			Reservation Log Page Available
 * @NVME_AER_CSS_NVM_SANITIZE_COMPLETED:		Sanitize Operation Completed
 * @NVME_AER_CSS_NVM_UNEXPECTED_SANITIZE_DEALLOC:	Sanitize Operation Completed
 *							With Unexpected Deallocation
 */
enum nvme_ae_info_css_nvm {
	NVME_AER_CSS_NVM_RESERVATION			= 0x00,
	NVME_AER_CSS_NVM_SANITIZE_COMPLETED		= 0x01,
	NVME_AER_CSS_NVM_UNEXPECTED_SANITIZE_DEALLOC	= 0x02,
};

/**
 * enum nvme_ae_info_notice - Asynchronous Event Information - Notice
 * @NVME_AER_NOTICE_ATTACHED_NS_CHANGED:	Attached Namespace Attribute Changed
 * @NVME_AER_NOTICE_FW_ACT_STARTING:	Firmware Activation Starting
 * @NVME_AER_NOTICE_TELEMETRY:		Telemetry Log Changed
 * @NVME_AER_NOTICE_ANA:		Asymmetric Namespace Access Change
 * @NVME_AER_NOTICE_PL_EVENT:		Predictable Latency Event Aggregate Log Change
 * @NVME_AER_NOTICE_LBA_STATUS_ALERT:	LBA Status Information Alert
 * @NVME_AER_NOTICE_EG_EVENT:		Endurance Group Event Aggregate Log Page Change
 * @NVME_AER_NOTICE_RATE_LIMITING_CFG_CHANGE:	Rate Limiting Configuration Change
 * @NVME_AER_NOTICE_DISC_CHANGED:	Discovery Log Page Change
 */
enum nvme_ae_info_notice {
	NVME_AER_NOTICE_ATTACHED_NS_CHANGED		= 0x00,
	NVME_AER_NOTICE_FW_ACT_STARTING			= 0x01,
	NVME_AER_NOTICE_TELEMETRY			= 0x02,
	NVME_AER_NOTICE_ANA				= 0x03,
	NVME_AER_NOTICE_PL_EVENT			= 0x04,
	NVME_AER_NOTICE_LBA_STATUS_ALERT		= 0x05,
	NVME_AER_NOTICE_EG_EVENT			= 0x06,
	NVME_AER_NOTICE_RATE_LIMITING_CFG_CHANGE	= 0x0a,
	NVME_AER_NOTICE_DISC_CHANGED			= 0xf0,
};


/**
 * enum nvme_cross_ctrl_reset_cdw10 - Cross-Controller Reset - Command
 *				       Dword 10
 * @NVME_CROSS_CTRL_RESET_CDW10_ICID_SHIFT: Shift amount to set Impacted
 *					     Controller ID (ICID)
 * @NVME_CROSS_CTRL_RESET_CDW10_ICID_MASK:  Mask to set ICID
 * @NVME_CROSS_CTRL_RESET_CDW10_CIU_SHIFT:  Shift amount to set Controller
 *					     Instance Uniquifier (CIU)
 * @NVME_CROSS_CTRL_RESET_CDW10_CIU_MASK:   Mask to set CIU
 */
enum nvme_cross_ctrl_reset_cdw10 {
	NVME_CROSS_CTRL_RESET_CDW10_ICID_SHIFT	= 0,
	NVME_CROSS_CTRL_RESET_CDW10_ICID_MASK	= 0xffff,
	NVME_CROSS_CTRL_RESET_CDW10_CIU_SHIFT	= 16,
	NVME_CROSS_CTRL_RESET_CDW10_CIU_MASK	= 0xff,
};

/**
 * enum nvme_cross_ctrl_reset_cqe_dw0 - Cross-Controller Reset Command -
 *					 Completion Queue Entry Dword 0
 * @NVME_CROSS_CTRL_RESET_CQE_IRS:  Immediate Reset Successful (IRS)
 * @NVME_CROSS_CTRL_RESET_CQE_V:    Validated (V). Undefined if IRS is
 *				    cleared to '0'.
 * @NVME_CROSS_CTRL_RESET_CQE_CLRI: Controller Level Reset Initiated (CLRI).
 *				    Undefined if IRS is cleared to '0'.
 */
enum nvme_cross_ctrl_reset_cqe_dw0 {
	NVME_CROSS_CTRL_RESET_CQE_IRS	= 1 << 0,
	NVME_CROSS_CTRL_RESET_CQE_V	= 1 << 1,
	NVME_CROSS_CTRL_RESET_CQE_CLRI	= 1 << 2,
};

/**
 * enum nvme_cross_ctrl_reset_lsp - Cross-Controller Reset Log Specific
 *				     Parameter Field
 * @NVME_CROSS_CTRL_RESET_LSP_RMC: Remove Completed (RMC)
 */
enum nvme_cross_ctrl_reset_lsp {
	NVME_CROSS_CTRL_RESET_LSP_RMC	= 1 << 0,
};

/**
 * enum nvme_fabric_zoning_recv_cdw12 - Fabric Zoning Receive - Command
 *					 Dword 12
 * @NVME_FABRIC_ZONING_RECV_CDW12_NUMD_SHIFT: Shift amount to set Number of
 *					       Dwords (NUMD)
 * @NVME_FABRIC_ZONING_RECV_CDW12_NUMD_MASK:  Mask to set NUMD
 * @NVME_FABRIC_ZONING_RECV_CDW12_ZDKC:	     ZDK Context (ZDKC)
 */
enum nvme_fabric_zoning_recv_cdw12 {
	NVME_FABRIC_ZONING_RECV_CDW12_NUMD_SHIFT	= 0,
	NVME_FABRIC_ZONING_RECV_CDW12_NUMD_MASK	= 0xfffffff,
	NVME_FABRIC_ZONING_RECV_CDW12_ZDKC		= 1 << 28,
};

/**
 * enum nvme_fabric_zoning_recv_cqe_dw0 - Fabric Zoning Receive - Completion
 *					   Queue Entry Dword 0
 * @NVME_FABRIC_ZONING_RECV_CQE_LF: Last Fragment (LF)
 */
enum nvme_fabric_zoning_recv_cqe_dw0 {
	NVME_FABRIC_ZONING_RECV_CQE_LF	= 1 << 31,
};

/**
 * enum nvme_fabric_zoning_send_cdw12 - Fabric Zoning Send - Command
 *					 Dword 12
 * @NVME_FABRIC_ZONING_SEND_CDW12_NUMD_SHIFT: Shift amount to set Number of
 *					       Dwords (NUMD)
 * @NVME_FABRIC_ZONING_SEND_CDW12_NUMD_MASK:  Mask to set NUMD
 * @NVME_FABRIC_ZONING_SEND_CDW12_ZDKC:	     ZDK Context (ZDKC)
 * @NVME_FABRIC_ZONING_SEND_CDW12_LF:	     Last Fragment (LF)
 */
enum nvme_fabric_zoning_send_cdw12 {
	NVME_FABRIC_ZONING_SEND_CDW12_NUMD_SHIFT	= 0,
	NVME_FABRIC_ZONING_SEND_CDW12_NUMD_MASK	= 0xfffffff,
	NVME_FABRIC_ZONING_SEND_CDW12_ZDKC		= 1 << 28,
	NVME_FABRIC_ZONING_SEND_CDW12_LF		= 1 << 31,
};

/**
 * enum nvme_manage_export_nvms_recv_sel - Manage Exported NVM Subsystem
 *		       Receive - Select (SEL)
 * @NVME_MANAGE_EXPORT_NVMS_RECV_SEL_CREATE:	    Create Exported NVM
 *						    Subsystem
 * @NVME_MANAGE_EXPORT_NVMS_RECV_SEL_LIST_SUBSYSTEMS: List Exported NVM
 *						    Subsystems
 * @NVME_MANAGE_EXPORT_NVMS_RECV_SEL_LIST_NAMESPACES: List Exported
 *						    Namespaces
 * @NVME_MANAGE_EXPORT_NVMS_RECV_SEL_LIST_CONTROLLERS: List Exported
 *						    Controllers (message-based
 *						    transports only)
 * @NVME_MANAGE_EXPORT_NVMS_RECV_SEL_LIST_PORTS: List Exported Ports
 *						    (memory-based transports
 *						    only)
 * @NVME_MANAGE_EXPORT_NVMS_RECV_SEL_GET_CONFIG_STATE: Get Exported NVM
 *						    Subsystem Configuration
 *						    State
 */
enum nvme_manage_export_nvms_recv_sel {
	NVME_MANAGE_EXPORT_NVMS_RECV_SEL_CREATE		= 0x00,
	NVME_MANAGE_EXPORT_NVMS_RECV_SEL_LIST_SUBSYSTEMS	= 0x01,
	NVME_MANAGE_EXPORT_NVMS_RECV_SEL_LIST_NAMESPACES	= 0x02,
	NVME_MANAGE_EXPORT_NVMS_RECV_SEL_LIST_CONTROLLERS	= 0x03,
	NVME_MANAGE_EXPORT_NVMS_RECV_SEL_LIST_PORTS		= 0x04,
	NVME_MANAGE_EXPORT_NVMS_RECV_SEL_GET_CONFIG_STATE	= 0x05,
};

/**
 * enum nvme_manage_export_nvms_recv_cdw10 - Manage Exported NVM Subsystem
 *		       Receive - Command Dword 10
 * @NVME_MANAGE_EXPORT_NVMS_RECV_CDW10_SEL_SHIFT:  Shift amount to set Select
 *						    (SEL), see &enum
 *						    nvme_manage_export_nvms_recv_sel
 * @NVME_MANAGE_EXPORT_NVMS_RECV_CDW10_SEL_MASK:   Mask to set SEL
 * @NVME_MANAGE_EXPORT_NVMS_RECV_CDW10_MOS_SHIFT:  Shift amount to set
 *						    Management Operation
 *						    Specific (MOS)
 * @NVME_MANAGE_EXPORT_NVMS_RECV_CDW10_MOS_MASK:   Mask to set MOS
 * @NVME_MANAGE_EXPORT_NVMS_RECV_CDW10_MOSE_SHIFT: Shift amount to set
 *						    Management Operation
 *						    Specific Extended (MOSE)
 * @NVME_MANAGE_EXPORT_NVMS_RECV_CDW10_MOSE_MASK:  Mask to set MOSE
 */
enum nvme_manage_export_nvms_recv_cdw10 {
	NVME_MANAGE_EXPORT_NVMS_RECV_CDW10_SEL_SHIFT	= 0,
	NVME_MANAGE_EXPORT_NVMS_RECV_CDW10_SEL_MASK	= 0xff,
	NVME_MANAGE_EXPORT_NVMS_RECV_CDW10_MOS_SHIFT	= 8,
	NVME_MANAGE_EXPORT_NVMS_RECV_CDW10_MOS_MASK	= 0xff,
	NVME_MANAGE_EXPORT_NVMS_RECV_CDW10_MOSE_SHIFT	= 16,
	NVME_MANAGE_EXPORT_NVMS_RECV_CDW10_MOSE_MASK	= 0xffff,
};

/**
 * enum nvme_manage_export_nvms_recv_cdw14 - Manage Exported NVM Subsystem
 *		       Receive - Command Dword 14
 * @NVME_MANAGE_EXPORT_NVMS_RECV_CDW14_MOSI_SHIFT: Shift amount to set
 *						    Management Operation
 *						    Specific Identifier (MOSI)
 * @NVME_MANAGE_EXPORT_NVMS_RECV_CDW14_MOSI_MASK:  Mask to set MOSI
 */
enum nvme_manage_export_nvms_recv_cdw14 {
	NVME_MANAGE_EXPORT_NVMS_RECV_CDW14_MOSI_SHIFT	= 16,
	NVME_MANAGE_EXPORT_NVMS_RECV_CDW14_MOSI_MASK	= 0xffff,
};

/**
 * enum nvme_export_nvms_create_cdw11 - Manage Exported NVM Subsystem Receive
 *		       - Create Exported NVM Subsystem - Command Dword 11
 * @NVME_EXPORT_NVMS_CREATE_CDW11_ENSTI_SHIFT: Shift amount to set Exported
 *		       NVM Subsystem Template Index (ENSTI), see the Identify
 *		       CNS value %NVME_IDENTIFY_CNS_EXPORTED_NVM_SUBSYS_TEMPLATE_UUID_LIST
 * @NVME_EXPORT_NVMS_CREATE_CDW11_ENSTI_MASK:  Mask to set ENSTI
 * @NVME_EXPORT_NVMS_CREATE_CDW11_TR:	       Template Required (TR)
 */
enum nvme_export_nvms_create_cdw11 {
	NVME_EXPORT_NVMS_CREATE_CDW11_ENSTI_SHIFT	= 0,
	NVME_EXPORT_NVMS_CREATE_CDW11_ENSTI_MASK	= 0xff,
	NVME_EXPORT_NVMS_CREATE_CDW11_TR		= 1 << 31,
};

/**
 * enum nvme_export_nvms_create_mos - Manage Exported NVM Subsystem Receive -
 *		       Create Exported NVM Subsystem - Management Operation
 *		       Specific (MOS) field, message-based transports only
 * @NVME_EXPORT_NVMS_CREATE_MOS_RA: Restricted Access (RA)
 */
enum nvme_export_nvms_create_mos {
	NVME_EXPORT_NVMS_CREATE_MOS_RA	= 1 << 0,
};

/**
 * enum nvme_export_nvms_create_cqe_dw0 - Manage Exported NVM Subsystem
 *		       Receive - Create Exported NVM Subsystem - Completion
 *		       Queue Entry Dword 0
 * @NVME_EXPORT_NVMS_CREATE_CQE_ESUBID_SHIFT: Shift amount to get Exported
 *		       NVM Subsystem Identifier (ESUBID)
 * @NVME_EXPORT_NVMS_CREATE_CQE_ESUBID_MASK:  Mask to get ESUBID
 */
enum nvme_export_nvms_create_cqe_dw0 {
	NVME_EXPORT_NVMS_CREATE_CQE_ESUBID_SHIFT	= 0,
	NVME_EXPORT_NVMS_CREATE_CQE_ESUBID_MASK		= 0xffff,
};

#define NVME_EXPORT_NVMS_CREATE_CQE_ESUBID(dw0) \
	NVME_GET(dw0, EXPORT_NVMS_CREATE_CQE_ESUBID)

/**
 * struct nvme_exported_nvm_subsys_create_data - Create Exported NVM
 *		       Subsystem Data Buffer
 * @esubnqn:	Exported NVM Subsystem NQN (ESUBNQN): the host may leave this
 *		field cleared to request an NQN be assigned by the
 *		controller; the assigned/confirmed NQN is returned in this
 *		same buffer on successful completion.
 */
struct nvme_exported_nvm_subsys_create_data {
	__u8	esubnqn[256];
};

/**
 * struct nvme_exported_nvm_subsys_descriptor - Exported NVM Subsystem
 *		       Descriptor
 * @esubnqn:	Exported NVM Subsystem NQN (ESUBNQN)
 * @rsvd256:	Reserved
 * @esubid:	Exported NVM Subsystem Identifier (ESUBID)
 */
struct nvme_exported_nvm_subsys_descriptor {
	__u8	esubnqn[256];
	__u8	rsvd256[2];
	__le16	esubid;
};

/**
 * struct nvme_exported_nvm_subsys_list - Exported NVM Subsystems List Data
 *		       Structure, returned by the Manage Exported NVM
 *		       Subsystem Receive command's List Exported NVM
 *		       Subsystems management operation
 * @n:		Number of Exported NVM Subsystem Descriptors (N)
 * @rsvd2:	Reserved
 * @gn:		Generation Number (GN)
 * @entries:	Exported NVM Subsystem Descriptor list, see &struct
 *		nvme_exported_nvm_subsys_descriptor
 */
struct nvme_exported_nvm_subsys_list {
	__le16	n;
	__u8	rsvd2;
	__u8	gn;
	struct nvme_exported_nvm_subsys_descriptor entries[];
};

/**
 * struct nvme_exported_ns_descriptor - Exported Namespace Descriptor
 * @ensid:	Exported Namespace ID (ENSID)
 * @unsid:	Underlying Namespace ID (UNSID)
 */
struct nvme_exported_ns_descriptor {
	__le32	ensid;
	__le32	unsid;
};

/**
 * struct nvme_exported_ns_list - Exported Namespace List Data Structure,
 *		       returned by the Manage Exported NVM Subsystem Receive
 *		       command's List Exported Namespaces management
 *		       operation
 * @n:		Number of Exported Namespaces (N)
 * @rsvd2:	Reserved
 * @gn:		Generation Number (GN)
 * @rsvd4:	Reserved
 * @entries:	Exported Namespace Descriptor list, see &struct
 *		nvme_exported_ns_descriptor
 */
struct nvme_exported_ns_list {
	__le16	n;
	__u8	rsvd2;
	__u8	gn;
	__u8	rsvd4[4];
	struct nvme_exported_ns_descriptor entries[];
};

/**
 * struct nvme_exported_ctrl_descriptor - Exported Controller Descriptor
 * @ecntlid:	Exported Controller Identifier (ECNTLID)
 * @cntlid:	Controller Identifier (CNTLID) of the associated Underlying
 *		Controller
 */
struct nvme_exported_ctrl_descriptor {
	__le16	ecntlid;
	__le16	cntlid;
};

/**
 * struct nvme_exported_ctrl_list - Exported Controller List Data Structure,
 *		       returned by the Manage Exported NVM Subsystem Receive
 *		       command's List Exported Controllers management
 *		       operation (message-based transports only)
 * @n:		Number of Exported Controllers (N)
 * @rsvd2:	Reserved
 * @gn:		Generation Number (GN)
 * @entries:	Exported Controller Descriptor list, see &struct
 *		nvme_exported_ctrl_descriptor
 */
struct nvme_exported_ctrl_list {
	__le16	n;
	__u8	rsvd2;
	__u8	gn;
	struct nvme_exported_ctrl_descriptor entries[];
};

/**
 * struct nvme_exported_port_descriptor - Exported Port Descriptor
 * @epid:	Exported Port ID (EPID)
 * @pidud:	Port ID of the Underlying Port (PIDUD)
 * @rsvd4:	Reserved
 * @trsvcid:	Transport Service ID (TRSVCID), ASCII string
 */
struct nvme_exported_port_descriptor {
	__le16	epid;
	__le16	pidud;
	__u8	rsvd4[4];
	__u8	trsvcid[32];
};

/**
 * struct nvme_exported_port_list - Exported Ports List Data Structure,
 *		       returned by the Manage Exported NVM Subsystem Receive
 *		       command's List Exported Ports management operation
 *		       (memory-based transports only)
 * @n:		Number of Exported Ports (N)
 * @rsvd2:	Reserved
 * @entries:	Exported Port Descriptor list, see &struct
 *		nvme_exported_port_descriptor
 */
struct nvme_exported_port_list {
	__le16	n;
	__u8	rsvd2[6];
	struct nvme_exported_port_descriptor entries[];
};

/**
 * enum nvme_manage_export_ns_sel - Manage Exported Namespace - Select (SEL)
 * @NVME_MANAGE_EXPORT_NS_SEL_ASSOCIATE:    Associate Namespace
 * @NVME_MANAGE_EXPORT_NS_SEL_DISASSOCIATE: Disassociate Namespace
 */
enum nvme_manage_export_ns_sel {
	NVME_MANAGE_EXPORT_NS_SEL_ASSOCIATE	= 0x01,
	NVME_MANAGE_EXPORT_NS_SEL_DISASSOCIATE	= 0x02,
};

/**
 * enum nvme_manage_export_ns_cdw10 - Manage Exported Namespace - Command
 *		       Dword 10
 * @NVME_MANAGE_EXPORT_NS_CDW10_SEL_SHIFT: Shift amount to set Select (SEL),
 *		       see &enum nvme_manage_export_ns_sel
 * @NVME_MANAGE_EXPORT_NS_CDW10_SEL_MASK:  Mask to set SEL
 * @NVME_MANAGE_EXPORT_NS_CDW10_MOS_SHIFT: Shift amount to set Management
 *		       Operation Specific (MOS)
 * @NVME_MANAGE_EXPORT_NS_CDW10_MOS_MASK:  Mask to set MOS
 */
enum nvme_manage_export_ns_cdw10 {
	NVME_MANAGE_EXPORT_NS_CDW10_SEL_SHIFT	= 0,
	NVME_MANAGE_EXPORT_NS_CDW10_SEL_MASK	= 0xff,
	NVME_MANAGE_EXPORT_NS_CDW10_MOS_SHIFT	= 8,
	NVME_MANAGE_EXPORT_NS_CDW10_MOS_MASK	= 0xff,
};

/**
 * enum nvme_manage_export_ns_cdw14 - Manage Exported Namespace - Command
 *		       Dword 14
 * @NVME_MANAGE_EXPORT_NS_CDW14_ESUBIDV: Exported NVM Subsystem Identifier
 *		       Valid (ESUBIDV)
 * @NVME_MANAGE_EXPORT_NS_CDW14_ESUBID_SHIFT: Shift amount to set Exported
 *		       NVM Subsystem Identifier (ESUBID), used if ESUBIDV is
 *		       set
 * @NVME_MANAGE_EXPORT_NS_CDW14_ESUBID_MASK: Mask to set ESUBID
 */
enum nvme_manage_export_ns_cdw14 {
	NVME_MANAGE_EXPORT_NS_CDW14_ESUBIDV		= 1 << 7,
	NVME_MANAGE_EXPORT_NS_CDW14_ESUBID_SHIFT	= 16,
	NVME_MANAGE_EXPORT_NS_CDW14_ESUBID_MASK		= 0xffff,
};

/**
 * struct nvme_associate_ns_data - Associate Namespace Data Structure
 * @pad:	Padding (PAD), shall be cleared to 0h
 * @ensid:	Exported Namespace ID (ENSID) to associate
 * @ensnqn:	Exported NVM Subsystem NQN (ENSNQN). Ignored for a
 *		memory-based controller, or if ESUBIDV is set.
 * @unsid:	Underlying Namespace ID (UNSID) to associate with @ensid
 * @uctrlid:	Underlying Controller ID (UCTRLID). Ignored for a
 *		memory-based controller.
 * @unsnqn:	Underlying NVM Subsystem NQN (UNSNQN). Ignored for a
 *		memory-based controller.
 * @rsvd554:	Reserved
 */
struct nvme_associate_ns_data {
	__u8	pad[32];
	__le32	ensid;
	__u8	ensnqn[256];
	__le32	unsid;
	__le16	uctrlid;
	__u8	unsnqn[256];
	__u8	rsvd554[22];
};

/**
 * struct nvme_disassociate_ns_data - Disassociate Namespace Data Structure
 * @pad:	Padding (PAD), shall be cleared to 0h
 * @ensid:	Exported Namespace ID (ENSID) to disassociate
 * @ensnqn:	Exported NVM Subsystem NQN (ENSNQN). Ignored for a
 *		memory-based controller, or if ESUBIDV is set.
 * @rsvd292:	Reserved
 */
struct nvme_disassociate_ns_data {
	__u8	pad[32];
	__le32	ensid;
	__u8	ensnqn[256];
	__u8	rsvd292[28];
};

/**
 * enum nvme_export_nvms_change_access_mode_mos - Manage Exported NVM
 *		       Subsystem Send - Change Access Mode - Management
 *		       Operation Specific (MOS) field, message-based
 *		       transports only
 * @NVME_EXPORT_NVMS_CHANGE_ACCESS_MODE_MOS_RA: Restricted Access (RA)
 */
enum nvme_export_nvms_change_access_mode_mos {
	NVME_EXPORT_NVMS_CHANGE_ACCESS_MODE_MOS_RA	= 1 << 0,
};

/**
 * struct nvme_exported_subsys_mgmt_host_entry - Host Entry Data Structure,
 *		       used by the Manage Exported NVM Subsystem Send Grant
 *		       Host Access and Revoke Host Access operations
 * @rsvd0:	Reserved
 * @hostid:	Host Identifier (HOSTID)
 * @hostnqn:	Host NVMe Qualified Name (HOSTNQN)
 * @rsvd280:	Reserved
 */
struct nvme_exported_subsys_mgmt_host_entry {
	__u8	rsvd0[8];
	__u8	hostid[16];
	__u8	hostnqn[256];
	__u8	rsvd280[40];
};

/**
 * struct nvme_exported_subsys_mgmt_subsys_entry - Exported NVM Subsystem
 *		       Entry Data Structure, used by the Manage Exported NVM
 *		       Subsystem Send Grant Host Access and Revoke Host
 *		       Access operations
 * @rsvd0:	Reserved
 * @subnqn:	NVM Subsystem NVMe Qualified Name (SUBNQN) of an Exported NVM
 *		Subsystem
 * @pidup:	Port ID of the Underlying Port (PIDUP)
 * @rsvd282:	Reserved
 */
struct nvme_exported_subsys_mgmt_subsys_entry {
	__u8	rsvd0[24];
	__u8	subnqn[256];
	__le16	pidup;
	__u8	rsvd282[38];
};

/**
 * struct nvme_exported_subsys_mgmt_data - Subsystem Management Data
 *		       Structure, used by the Manage Exported NVM Subsystem
 *		       Send Grant Host Access and Revoke Host Access
 *		       operations
 * @rsvd0:	Reserved
 * @numhent:	Number of Host Entries (NUMHENT), shall be greater than 0h
 * @numense:	Number of Exported NVM Subsystem Entries (NUMENSE), shall be
 *		greater than 0h
 * @rsvd68:	Reserved
 * @entries:	@numhent entries of &struct nvme_exported_subsys_mgmt_host_entry
 *		followed by @numense entries of &struct
 *		nvme_exported_subsys_mgmt_subsys_entry. Left as a raw byte
 *		buffer since the two variable-length lists have different
 *		element sizes and cannot both be expressed as fixed struct
 *		members - the caller walks @entries using the sizes of those
 *		two struct types.
 */
struct nvme_exported_subsys_mgmt_data {
	__u8	rsvd0[64];
	__le16	numhent;
	__le16	numense;
	__u8	rsvd68[188];
	__u8	entries[];
};

/**
 * struct nvme_exported_ctrl_assoc_descriptor - Exported Controller
 *		       Association Descriptor
 * @cntlid:	Controller Identifier (CNTLID) of the Underlying Controller
 * @ecntlid:	Exported Controller Identifier (ECNTLID) to associate with
 *		@cntlid
 */
struct nvme_exported_ctrl_assoc_descriptor {
	__le16	cntlid;
	__le16	ecntlid;
};

/**
 * struct nvme_exported_ctrl_assoc_data - Associate Controllers Management
 *		       Operation Data Buffer
 * @n:		Number of Associated Exported Controller Descriptors (N),
 *		0's based
 * @rsvd2:	Reserved
 * @entries:	Exported Controller Association Descriptor list, see &struct
 *		nvme_exported_ctrl_assoc_descriptor
 */
struct nvme_exported_ctrl_assoc_data {
	__le16	n;
	__u8	rsvd2[2];
	struct nvme_exported_ctrl_assoc_descriptor entries[];
};

/**
 * enum nvme_export_nvms_set_config_state_cqe_dw0 - Manage Exported NVM
 *		       Subsystem Send - Set Exported Configuration State -
 *		       Completion Queue Entry Dword 0, valid when the command
 *		       fails with %NVME_SC_INVALID_EXPORTED_CONFIG_STATE
 * @NVME_EXPORT_NVMS_SET_CONFIG_STATE_CQE_DWLOC_SHIFT: Shift amount to get
 *		       Dword Location (DWLOC): offset in the data buffer to
 *		       the Dword that contained an invalid bit
 * @NVME_EXPORT_NVMS_SET_CONFIG_STATE_CQE_DWLOC_MASK:  Mask to get DWLOC
 * @NVME_EXPORT_NVMS_SET_CONFIG_STATE_CQE_BITLOC_SHIFT: Shift amount to get
 *		       Bit Location (BITLOC): offset of the invalid bit
 *		       within the Dword indicated by DWLOC
 * @NVME_EXPORT_NVMS_SET_CONFIG_STATE_CQE_BITLOC_MASK: Mask to get BITLOC
 */
enum nvme_export_nvms_set_config_state_cqe_dw0 {
	NVME_EXPORT_NVMS_SET_CONFIG_STATE_CQE_DWLOC_SHIFT	= 0,
	NVME_EXPORT_NVMS_SET_CONFIG_STATE_CQE_DWLOC_MASK	= 0x7ffffff,
	NVME_EXPORT_NVMS_SET_CONFIG_STATE_CQE_BITLOC_SHIFT	= 27,
	NVME_EXPORT_NVMS_SET_CONFIG_STATE_CQE_BITLOC_MASK	= 0x1f,
};

/**
 * struct nvme_exported_nvm_subsys_nqn_data - Exported NVM Subsystem NQN
 *		       Data Buffer, used by Manage Exported NVM Subsystem
 *		       Send operations that identify the target Exported NVM
 *		       Subsystem by NQN instead of by Exported NVM Subsystem
 *		       Identifier (ESUBID)
 * @esubnqn:	Exported NVM Subsystem NQN (ESUBNQN)
 */
struct nvme_exported_nvm_subsys_nqn_data {
	__u8	esubnqn[256];
};

/**
 * enum nvme_manage_export_nvms_send_sel - Manage Exported NVM Subsystem
 *		       Send - Select (SEL)
 * @NVME_MANAGE_EXPORT_NVMS_SEND_SEL_DELETE:  Delete
 * @NVME_MANAGE_EXPORT_NVMS_SEND_SEL_CHANGE_ACCESS_MODE: Change Access Mode
 *		       (message-based transports only)
 * @NVME_MANAGE_EXPORT_NVMS_SEND_SEL_GRANT_HOST_ACCESS: Grant Host Access
 *		       (message-based transports only)
 * @NVME_MANAGE_EXPORT_NVMS_SEND_SEL_REVOKE_HOST_ACCESS: Revoke Host Access
 *		       (message-based transports only)
 * @NVME_MANAGE_EXPORT_NVMS_SEND_SEL_ASSOCIATE_CONTROLLERS: Associate
 *		       Controllers (memory-based transports only)
 * @NVME_MANAGE_EXPORT_NVMS_SEND_SEL_SET_CONFIG_STATE: Set Exported
 *		       Configuration State
 */
enum nvme_manage_export_nvms_send_sel {
	NVME_MANAGE_EXPORT_NVMS_SEND_SEL_DELETE		= 0x01,
	NVME_MANAGE_EXPORT_NVMS_SEND_SEL_CHANGE_ACCESS_MODE	= 0x02,
	NVME_MANAGE_EXPORT_NVMS_SEND_SEL_GRANT_HOST_ACCESS	= 0x03,
	NVME_MANAGE_EXPORT_NVMS_SEND_SEL_REVOKE_HOST_ACCESS	= 0x04,
	NVME_MANAGE_EXPORT_NVMS_SEND_SEL_ASSOCIATE_CONTROLLERS	= 0x05,
	NVME_MANAGE_EXPORT_NVMS_SEND_SEL_SET_CONFIG_STATE	= 0x06,
};

/**
 * enum nvme_manage_export_nvms_send_cdw10 - Manage Exported NVM Subsystem
 *		       Send - Command Dword 10
 * @NVME_MANAGE_EXPORT_NVMS_SEND_CDW10_SEL_SHIFT:  Shift amount to set Select
 *		       (SEL), see &enum nvme_manage_export_nvms_send_sel
 * @NVME_MANAGE_EXPORT_NVMS_SEND_CDW10_SEL_MASK:   Mask to set SEL
 * @NVME_MANAGE_EXPORT_NVMS_SEND_CDW10_MOS_SHIFT:  Shift amount to set
 *		       Management Operation Specific (MOS)
 * @NVME_MANAGE_EXPORT_NVMS_SEND_CDW10_MOS_MASK:   Mask to set MOS
 * @NVME_MANAGE_EXPORT_NVMS_SEND_CDW10_MOSE_SHIFT: Shift amount to set
 *		       Management Operation Specific Extended (MOSE)
 * @NVME_MANAGE_EXPORT_NVMS_SEND_CDW10_MOSE_MASK:  Mask to set MOSE
 */
enum nvme_manage_export_nvms_send_cdw10 {
	NVME_MANAGE_EXPORT_NVMS_SEND_CDW10_SEL_SHIFT	= 0,
	NVME_MANAGE_EXPORT_NVMS_SEND_CDW10_SEL_MASK	= 0xff,
	NVME_MANAGE_EXPORT_NVMS_SEND_CDW10_MOS_SHIFT	= 8,
	NVME_MANAGE_EXPORT_NVMS_SEND_CDW10_MOS_MASK	= 0xff,
	NVME_MANAGE_EXPORT_NVMS_SEND_CDW10_MOSE_SHIFT	= 16,
	NVME_MANAGE_EXPORT_NVMS_SEND_CDW10_MOSE_MASK	= 0xffff,
};

/**
 * enum nvme_manage_export_nvms_send_cdw14 - Manage Exported NVM Subsystem
 *		       Send - Command Dword 14
 * @NVME_MANAGE_EXPORT_NVMS_SEND_CDW14_ESUBIDV: Exported NVM Subsystem
 *		       Identifier Valid (ESUBIDV)
 * @NVME_MANAGE_EXPORT_NVMS_SEND_CDW14_ESUBID_SHIFT: Shift amount to set
 *		       Exported NVM Subsystem Identifier (ESUBID), used if
 *		       ESUBIDV is set
 * @NVME_MANAGE_EXPORT_NVMS_SEND_CDW14_ESUBID_MASK: Mask to set ESUBID
 */
enum nvme_manage_export_nvms_send_cdw14 {
	NVME_MANAGE_EXPORT_NVMS_SEND_CDW14_ESUBIDV		= 1 << 7,
	NVME_MANAGE_EXPORT_NVMS_SEND_CDW14_ESUBID_SHIFT	= 16,
	NVME_MANAGE_EXPORT_NVMS_SEND_CDW14_ESUBID_MASK		= 0xffff,
};

/**
 * enum nvme_send_discovery_log_page_rlps - Send Discovery Log Page (SDLP) -
 *					     Requested Log Page Status (RLPS)
 * @NVME_SDLP_RLPS_VALID:	 Valid Log Page: the requested log page is
 *				 carried in the command.
 * @NVME_SDLP_RLPS_INVALID:	 Invalid Log Page: the requested log page is
 *				 invalid or not supported.
 * @NVME_SDLP_RLPS_NOT_ALLOWED: Not Allowed Log Page: the requested log page
 *				 is not allowed to be transferred by an SDLP
 *				 command.
 * @NVME_SDLP_RLPS_NOT_SUCCESSFUL: Not Successful: retrieving the requested
 *				 log page failed. Further details are
 *				 provided in the SCT and SC fields.
 */
enum nvme_send_discovery_log_page_rlps {
	NVME_SDLP_RLPS_VALID		= 0x0,
	NVME_SDLP_RLPS_INVALID		= 0x1,
	NVME_SDLP_RLPS_NOT_ALLOWED	= 0x2,
	NVME_SDLP_RLPS_NOT_SUCCESSFUL	= 0x3,
};

/**
 * enum nvme_send_discovery_log_page_cdw10 - Send Discovery Log Page (SDLP) -
 *					      Command Dword 10
 * @NVME_SDLP_CDW10_TLID_SHIFT: Shift amount to set Transferred Log Page
 *				Identifier (TLID)
 * @NVME_SDLP_CDW10_TLID_MASK:	Mask to set TLID
 * @NVME_SDLP_CDW10_TLSP_SHIFT: Shift amount to set Transferred Log Specific
 *				Parameter (TLSP)
 * @NVME_SDLP_CDW10_TLSP_MASK:	Mask to set TLSP
 * @NVME_SDLP_CDW10_SC_SHIFT:	Shift amount to set Status Code (SC)
 * @NVME_SDLP_CDW10_SC_MASK:	Mask to set SC
 * @NVME_SDLP_CDW10_SCT_SHIFT:	Shift amount to set Status Code Type (SCT)
 * @NVME_SDLP_CDW10_SCT_MASK:	Mask to set SCT
 * @NVME_SDLP_CDW10_RLPS_SHIFT:	Shift amount to set Requested Log Page
 *				Status (RLPS), see &enum
 *				nvme_send_discovery_log_page_rlps
 * @NVME_SDLP_CDW10_RLPS_MASK:	Mask to set RLPS
 */
enum nvme_send_discovery_log_page_cdw10 {
	NVME_SDLP_CDW10_TLID_SHIFT	= 0,
	NVME_SDLP_CDW10_TLID_MASK	= 0xff,
	NVME_SDLP_CDW10_TLSP_SHIFT	= 8,
	NVME_SDLP_CDW10_TLSP_MASK	= 0x7f,
	NVME_SDLP_CDW10_SC_SHIFT	= 17,
	NVME_SDLP_CDW10_SC_MASK		= 0xff,
	NVME_SDLP_CDW10_SCT_SHIFT	= 25,
	NVME_SDLP_CDW10_SCT_MASK	= 0x7,
	NVME_SDLP_CDW10_RLPS_SHIFT	= 30,
	NVME_SDLP_CDW10_RLPS_MASK	= 0x3,
};

/**
 * enum nvme_send_discovery_log_page_cqe_dw0 - Send Discovery Log Page (SDLP)
 *					 Completion Queue Entry Dword 0
 * @NVME_SDLP_CQE_LPUR: Log Page Update Registration (LPUR)
 */
enum nvme_send_discovery_log_page_cqe_dw0 {
	NVME_SDLP_CQE_LPUR	= 1 << 31,
};

/**
 * enum nvme_cross_ctrl_reset_ccrs - Cross-Controller Reset Entry - Cross-
 *				      Controller Reset Status (CCRS)
 * @NVME_CROSS_CTRL_RESET_CCRS_IN_PROGRESS: In Progress
 * @NVME_CROSS_CTRL_RESET_CCRS_SUCCESS:	   Success
 * @NVME_CROSS_CTRL_RESET_CCRS_FAILED:	   Failed
 */
enum nvme_cross_ctrl_reset_ccrs {
	NVME_CROSS_CTRL_RESET_CCRS_IN_PROGRESS	= 0x00,
	NVME_CROSS_CTRL_RESET_CCRS_SUCCESS	= 0x01,
	NVME_CROSS_CTRL_RESET_CCRS_FAILED	= 0x02,
};

/**
 * enum nvme_cross_ctrl_reset_ccrf - Cross-Controller Reset Entry - Cross-
 *				      Controller Reset Flags (CCRF)
 * @NVME_CROSS_CTRL_RESET_CCRF_V:	    Validated (V)
 * @NVME_CROSS_CTRL_RESET_CCRF_CLRI:	    Controller Level Reset Initiated
 *					    (CLRI)
 * @NVME_CROSS_CTRL_RESET_CCRF_RETRY_SHIFT: Shift amount to get the Retry
 *					     (RETRY) field
 * @NVME_CROSS_CTRL_RESET_CCRF_RETRY_MASK:  Mask to get RETRY
 */
enum nvme_cross_ctrl_reset_ccrf {
	NVME_CROSS_CTRL_RESET_CCRF_V		= 1 << 0,
	NVME_CROSS_CTRL_RESET_CCRF_CLRI		= 1 << 1,
	NVME_CROSS_CTRL_RESET_CCRF_RETRY_SHIFT	= 2,
	NVME_CROSS_CTRL_RESET_CCRF_RETRY_MASK	= 0x3,
};

#define NVME_CROSS_CTRL_RESET_CCRF_RETRY(ccrf) \
	NVME_GET(ccrf, CROSS_CTRL_RESET_CCRF_RETRY)

/**
 * struct nvme_cross_ctrl_reset_entry - Cross-Controller Reset Entry Data
 *					 Structure
 * @icid:	Impacted Controller ID (ICID)
 * @ciu:	Controller Instance Uniquifier (CIU)
 * @rsvd3:	Reserved
 * @acid:	Alternate Controller ID (ACID)
 * @ccrs:	Cross-Controller Reset Status (CCRS), see &enum
 *		nvme_cross_ctrl_reset_ccrs
 * @ccrf:	Cross-Controller Reset Flags (CCRF), see &enum
 *		nvme_cross_ctrl_reset_ccrf
 */
struct nvme_cross_ctrl_reset_entry {
	__le16	icid;
	__u8	ciu;
	__u8	rsvd3;
	__le16	acid;
	__u8	ccrs;
	__u8	ccrf;
};

/**
 * struct nvme_cross_ctrl_reset_log - Cross-Controller Reset Log Page
 *				       (Log Identifier 1Eh)
 * @ne:		Number of Entries (NE)
 * @rsvd2:	Reserved
 * @entries:	Cross-Controller Reset Entry list, see &struct
 *		nvme_cross_ctrl_reset_entry
 */
struct nvme_cross_ctrl_reset_log {
	__le16	ne;
	__u8	rsvd2[6];
	struct nvme_cross_ctrl_reset_entry entries[];
};

/**
 * struct nvme_lost_host_comm_entry - Lost Host Communication Entry Data
 *				       Structure
 * @cntlid:	Controller ID (CNTLID) of the LHC Controller
 * @lc:		Loss Count (LC)
 * @ciu:	Controller Instance Uniquifier (CIU)
 * @rsvd4:	Reserved
 */
struct nvme_lost_host_comm_entry {
	__le16	cntlid;
	__u8	lc;
	__u8	ciu;
	__u8	rsvd4[4];
};

/**
 * struct nvme_lost_host_comm_log - Lost Host Communication Log Page
 *				     (Log Identifier 1Fh)
 * @ne:		Number of Entries (NE)
 * @rsvd2:	Reserved
 * @entries:	Lost Host Communication Entry list, see &struct
 *		nvme_lost_host_comm_entry
 */
struct nvme_lost_host_comm_log {
	__le16	ne;
	__u8	rsvd2[6];
	struct nvme_lost_host_comm_entry entries[];
};

/**
 * struct nvme_pull_model_ddc_req_log - Pull Model DDC Request Log
 * @ori:	Operation Request Identifier
 * @rsvd1:	Reserved
 * @tpdrpl:	Total Pull Model DDC Request Log Page Length
 * @osp:	Operation Specific Parameters
 */
struct nvme_pull_model_ddc_req_log {
	__u8	ori;
	__u8	rsvd1[3];
	__le32	tpdrpl;
	__u8	osp[];
};

/**
 * enum nvme_status_field - Defines all parts of the nvme status field: status
 *			    code, status code type, and additional flags.
 * @NVME_SCT_GENERIC:		      Generic errors applicable to multiple opcodes
 * @NVME_SCT_CMD_SPECIFIC:	      Errors associated to a specific opcode
 * @NVME_SCT_MEDIA:		      Errors associated with media and data integrity
 * @NVME_SCT_PATH:		      Errors associated with the paths connection
 * @NVME_SCT_VS:		      Vendor specific errors
 * @NVME_SCT_MASK:		      Mask to get the value of the Status Code Type
 * @NVME_SCT_SHIFT:		      Shift value to get the value of the Status
 *				      Code Type
 * @NVME_SC_MASK:		      Mask to get the value of the status code.
 * @NVME_SC_SHIFT:		      Shift value to get the value of the status
 *				      code.
 * @NVME_SC_SUCCESS:		      Successful Completion: The command
 *				      completed without error.
 * @NVME_SC_INVALID_OPCODE:	      Invalid Command Opcode: A reserved coded
 *				      value or an unsupported value in the
 *				      command opcode field.
 * @NVME_SC_INVALID_FIELD:	      Invalid Field in Command: A reserved
 *				      coded value or an unsupported value in a
 *				      defined field.
 * @NVME_SC_CMDID_CONFLICT:	      Command ID Conflict: The command
 *				      identifier is already in use.
 * @NVME_SC_DATA_XFER_ERROR:	      Data Transfer Error: Transferring the
 *				      data or metadata associated with a
 *				      command experienced an error.
 * @NVME_SC_POWER_LOSS:		      Commands Aborted due to Power Loss
 *				      Notification: Indicates that the command
 *				      was aborted due to a power loss
 *				      notification.
 * @NVME_SC_INTERNAL:		      Internal Error: The command was not
 *				      completed successfully due to an internal error.
 * @NVME_SC_ABORT_REQ:		      Command Abort Requested: The command was
 *				      aborted due to an Abort command being
 *				      received that specified the Submission
 *				      Queue Identifier and Command Identifier
 *				      of this command.
 * @NVME_SC_ABORT_QUEUE:	      Command Aborted due to SQ Deletion: The
 *				      command was aborted due to a Delete I/O
 *				      Submission Queue request received for the
 *				      Submission Queue to which the command was
 *				      submitted.
 * @NVME_SC_FUSED_FAIL:		      Command Aborted due to Failed Fused Command:
 *				      The command was aborted due to the other
 *				      command in a fused operation failing.
 * @NVME_SC_FUSED_MISSING:	      Aborted due to Missing Fused Command: The
 *				      fused command was aborted due to the
 *				      adjacent submission queue entry not
 *				      containing a fused command that is the
 *				      other command.
 * @NVME_SC_INVALID_NS:		      Invalid Namespace or Format: The
 *				      namespace or the format of that namespace
 *				      is invalid.
 * @NVME_SC_CMD_SEQ_ERROR:	      Command Sequence Error: The command was
 *				      aborted due to a protocol violation in a
 *				      multi-command sequence.
 * @NVME_SC_SGL_INVALID_LAST:	      Invalid SGL Segment Descriptor: The
 *				      command includes an invalid SGL Last
 *				      Segment or SGL Segment descriptor.
 * @NVME_SC_SGL_INVALID_COUNT:	      Invalid Number of SGL Descriptors: There
 *				      is an SGL Last Segment descriptor or an
 *				      SGL Segment descriptor in a location
 *				      other than the last descriptor of a
 *				      segment based on the length indicated.
 * @NVME_SC_SGL_INVALID_DATA:	      Data SGL Length Invalid: This may occur
 *				      if the length of a Data SGL is too short.
 *				      This may occur if the length of a Data
 *				      SGL is too long and the controller does
 *				      not support SGL transfers longer than the
 *				      amount of data to be transferred as
 *				      indicated in the SGL Support field of the
 *				      Identify Controller data structure.
 * @NVME_SC_SGL_INVALID_METADATA:     Metadata SGL Length Invalid: This may
 *				      occur if the length of a Metadata SGL is
 *				      too short. This may occur if the length
 *				      of a Metadata SGL is too long and the
 *				      controller does not support SGL transfers
 *				      longer than the amount of data to be
 *				      transferred as indicated in the SGL
 *				      Support field of the Identify Controller
 *				      data structure.
 * @NVME_SC_SGL_INVALID_TYPE:	      SGL Descriptor Type Invalid: The type of
 *				      an SGL Descriptor is a type that is not
 *				      supported by the controller.
 * @NVME_SC_CMB_INVALID_USE:	      Invalid Use of Controller Memory Buffer:
 *				      The attempted use of the Controller
 *				      Memory Buffer is not supported by the
 *				      controller.
 * @NVME_SC_PRP_INVALID_OFFSET:	      PRP Offset Invalid: The Offset field for
 *				      a PRP entry is invalid.
 * @NVME_SC_AWU_EXCEEDED:	      Atomic Write Unit Exceeded: The length
 *				      specified exceeds the atomic write unit size.
 * @NVME_SC_OP_DENIED:		      Operation Denied: The command was denied
 *				      due to lack of access rights. Refer to
 *				      the appropriate security specification.
 * @NVME_SC_SGL_INVALID_OFFSET:	      SGL Offset Invalid: The offset specified
 *				      in a descriptor is invalid. This may
 *				      occur when using capsules for data
 *				      transfers in NVMe over Fabrics
 *				      implementations and an invalid offset in
 *				      the capsule is specified.
 * @NVME_SC_HOSTID_FORMAT:	      Host Identifier Inconsistent Format: The
 *				      NVM subsystem detected the simultaneous
 *				      use of 64- bit and 128-bit Host
 *				      Identifier values on different
 *				      controllers.
 * @NVME_SC_KAT_EXPIRED:	      Keep Alive Timer Expired: The Keep Alive
 *				      Timer expired.
 * @NVME_SC_KAT_INVALID:	      Keep Alive Timeout Invalid: The Keep
 *				      Alive Timeout value specified is invalid.
 * @NVME_SC_CMD_ABORTED_PREMEPT:      Command Aborted due to Preempt and Abort:
 *				      The command was aborted due to a
 *				      Reservation Acquire command.
 * @NVME_SC_SANITIZE_FAILED:	      Sanitize Failed: The most recent sanitize
 *				      operation failed and no recovery action
 *				      has been successfully completed.
 * @NVME_SC_SANITIZE_IN_PROGRESS:     Sanitize In Progress: The requested
 *				      function (e.g., command) is prohibited
 *				      while a sanitize operation is in
 *				      progress.
 * @NVME_SC_SGL_INVALID_GRANULARITY:  SGL Data Block Granularity Invalid: The
 *				      Address alignment or Length granularity
 *				      for an SGL Data Block descriptor is
 *				      invalid.
 * @NVME_SC_CMD_IN_CMBQ_NOT_SUPP:     Command Not Supported for Queue in CMB:
 *				      The implementation does not support
 *				      submission of the command to a Submission
 *				      Queue in the Controller Memory Buffer or
 *				      command completion to a Completion Queue
 *				      in the Controller Memory Buffer.
 * @NVME_SC_NS_WRITE_PROTECTED:	      Namespace is Write Protected: The command
 *				      is prohibited while the namespace is
 *				      write protected as a result of a change
 *				      in the namespace write protection state
 *				      as defined by the Namespace Write
 *				      Protection State Machine.
 * @NVME_SC_CMD_INTERRUPTED:	      Command Interrupted: Command processing
 *				      was interrupted and the controller is
 *				      unable to successfully complete the
 *				      command. The host should retry the
 *				      command.
 * @NVME_SC_TRAN_TPORT_ERROR:	      Transient Transport Error: A transient
 *				      transport error was detected. If the
 *				      command is retried on the same
 *				      controller, the command is likely to
 *				      succeed. A command that fails with a
 *				      transient transport error four or more
 *				      times should be treated as a persistent
 *				      transport error that is not likely to
 *				      succeed if retried on the same
 *				      controller.
 * @NVME_SC_PROHIBITED_BY_CMD_AND_FEAT: Command Prohibited by Command and Feature
 *				      Lockdown: The command was aborted due to
 *				      command execution being prohibited by
 *				      the Command and Feature Lockdown.
 * @NVME_SC_ADMIN_CMD_MEDIA_NOT_READY: Admin Command Media Not Ready: The Admin
 *				      command requires access to media and
 *				      the media is not ready.
 * @NVME_SC_INVALID_KEY_TAG:	      The command was aborted due to an invalid KEYTAG
 *				      field value.
 * @NVME_SC_HOST_DISPERSED_NS_NOT_ENABLED: The command is prohibited while the
 *				      Host Disperesed Namespace Support (HDISNS) field is not
 *				      set to 1h in the Host Behavior Support feature.
 * @NVME_SC_HOST_ID_NOT_INITIALIZED:  Host Identifier Not Initialized.
 * @NVME_SC_INCORRECT_KEY:	      The command was aborted due to the key associated
 *				      with the KEYTAG field being incorrect.
 * @NVME_SC_FDP_DISABLED:	      Command is not allowed when
 *				      Flexible Data Placement is disabled.
 * @NVME_SC_INVALID_PLACEMENT_HANDLE_LIST: The Placement Handle List is invalid
 *				      due to invalid Reclaim Unit Handle Identifier or
 *				      valid Reclaim Unit Handle Identifier but restricted or
 *				      the Placement Handle List number of entries exceeded the
 *				      maximum number allowed.
 * @NVME_SC_SANITIZE_NS_FAILED:	      Sanitize Namespace Failed: The most
 *				      recent namespace sanitize operation failed
 *				      and no recovery action has been
 *				      successfully completed.
 * @NVME_SC_SANITIZE_NS_IN_PROGRESS:  Sanitize Namespace In Progress: The
 *				      requested function (e.g., command) is
 *				      prohibited while a namespace sanitize
 *				      operation is in progress.
 * @NVME_SC_FAILED_TO_RESTORE_CONFIG:  Failed to Restore Configuration: The
 *				      command was aborted due to the command
 *				      failing to restore configuration.
 * @NVME_SC_LBA_RANGE:		      LBA Out of Range: The command references
 *				      an LBA that exceeds the size of the namespace.
 * @NVME_SC_CAP_EXCEEDED:	      Capacity Exceeded: Execution of the
 *				      command has caused the capacity of the
 *				      namespace to be exceeded.
 * @NVME_SC_NS_NOT_READY:	      Namespace Not Ready: The namespace is not
 *				      ready to be accessed as a result of a
 *				      condition other than a condition that is
 *				      reported as an Asymmetric Namespace
 *				      Access condition.
 * @NVME_SC_RESERVATION_CONFLICT:     Reservation Conflict: The command was
 *				      aborted due to a conflict with a
 *				      reservation held on the accessed
 *				      namespace.
 * @NVME_SC_FORMAT_IN_PROGRESS:	      Format In Progress: A Format NVM command
 *				      is in progress on the namespace.
 * @NVME_SC_INVALID_VALUE_SIZE:	      The value size is not valid.
 * @NVME_SC_INVALID_KEY_SIZE:	      The KV key size is not valid.
 * @NVME_SC_KV_KEY_NOT_EXISTS:	      The Store If Key Exists (SIKE) bit is set to
 *				      '1' in the Store Option field and the KV key does not
 *				      exists.
 * @NVME_SC_UNRECOVERED_ERROR:	      There was an unrecovered error when reading
 *				      from the meidum.
 * @NVME_SC_KEY_EXISTS:		      The Store If No Key Exists (SINKE) bit is set to '1'
 *				      in the Store Option field and the KV key exists.
 * @NVME_SC_CQ_INVALID:		      Completion Queue Invalid: The Completion
 *				      Queue identifier specified in the command
 *				      does not exist.
 * @NVME_SC_QID_INVALID:	      Invalid Queue Identifier: The creation of
 *				      the I/O Completion Queue failed due to an
 *				      invalid queue identifier specified as
 *				      part of the command. An invalid queue
 *				      identifier is one that is currently in
 *				      use or one that is outside the range
 *				      supported by the controller.
 * @NVME_SC_QUEUE_SIZE:		      Invalid Queue Size: The host attempted to
 *				      create an I/O Completion Queue with an
 *				      invalid number of entries.
 * @NVME_SC_ABORT_LIMIT:	      Abort Command Limit Exceeded: The number
 *				      of concurrently outstanding Abort commands
 *				      has exceeded the limit indicated in the
 *				      Identify Controller data structure.
 * @NVME_SC_ABORT_MISSING:	      Abort Command is missing: The abort
 *				      command is missing.
 * @NVME_SC_ASYNC_LIMIT:	      Asynchronous Event Request Limit
 *				      Exceeded: The number of concurrently
 *				      outstanding Asynchronous Event Request
 *				      commands has been exceeded.
 * @NVME_SC_FIRMWARE_SLOT:	      Invalid Firmware Slot: The firmware slot
 *				      indicated is invalid or read only. This
 *				      error is indicated if the firmware slot
 *				      exceeds the number supported.
 * @NVME_SC_FIRMWARE_IMAGE:	      Invalid Firmware Image: The firmware
 *				      image specified for activation is invalid
 *				      and not loaded by the controller.
 * @NVME_SC_INVALID_VECTOR:	      Invalid Interrupt Vector: The creation of
 *				      the I/O Completion Queue failed due to an
 *				      invalid interrupt vector specified as
 *				      part of the command.
 * @NVME_SC_INVALID_LOG_PAGE:	      Invalid Log Page: The log page indicated
 *				      is invalid. This error condition is also
 *				      returned if a reserved log page is
 *				      requested.
 * @NVME_SC_INVALID_FORMAT:	      Invalid Format: The LBA Format specified
 *				      is not supported.
 * @NVME_SC_FW_NEEDS_CONV_RESET:      Firmware Activation Requires Conventional Reset:
 *				      The firmware commit was successful,
 *				      however, activation of the firmware image
 *				      requires a conventional reset.
 * @NVME_SC_INVALID_QUEUE:	      Invalid Queue Deletion: Invalid I/O
 *				      Completion Queue specified to delete.
 * @NVME_SC_FEATURE_NOT_SAVEABLE:     Feature Identifier Not Saveable: The
 *				      Feature Identifier specified does not
 *				      support a saveable value.
 * @NVME_SC_FEATURE_NOT_CHANGEABLE:   Feature Not Changeable: The Feature
 *				      Identifier is not able to be changed.
 * @NVME_SC_FEATURE_NOT_PER_NS:	      Feature Not Namespace Specific: The
 *				      Feature Identifier specified is not
 *				      namespace specific. The Feature
 *				      Identifier settings apply across all
 *				      namespaces.
 * @NVME_SC_FW_NEEDS_SUBSYS_RESET:    Firmware Activation Requires NVM
 *				      Subsystem Reset: The firmware commit was
 *				      successful, however, activation of the
 *				      firmware image requires an NVM Subsystem.
 * @NVME_SC_FW_NEEDS_RESET:	      Firmware Activation Requires Controller
 *				      Level Reset: The firmware commit was
 *				      successful; however, the image specified
 *				      does not support being activated without
 *				      a reset.
 * @NVME_SC_FW_NEEDS_MAX_TIME:	      Firmware Activation Requires Maximum Time
 *				      Violation: The image specified if
 *				      activated immediately would exceed the
 *				      Maximum Time for Firmware Activation
 *				      (MTFA) value reported in Identify
 *				      Controller.
 * @NVME_SC_FW_ACTIVATE_PROHIBITED:   Firmware Activation Prohibited: The image
 *				      specified is being prohibited from
 *				      activation by the controller for vendor
 *				      specific reasons.
 * @NVME_SC_OVERLAPPING_RANGE:	      Overlapping Range: The downloaded
 *				      firmware image has overlapping ranges.
 * @NVME_SC_NS_INSUFFICIENT_CAP:      Namespace Insufficient Capacity: Creating
 *				      the namespace requires more free space
 *				      than is currently available.
 * @NVME_SC_NS_ID_UNAVAILABLE:	      Namespace Identifier Unavailable: The
 *				      number of namespaces supported has been
 *				      exceeded.
 * @NVME_SC_NS_ALREADY_ATTACHED:      Namespace Already Attached: The
 *				      controller is already attached to the
 *				      namespace specified.
 * @NVME_SC_NS_IS_PRIVATE:	      Namespace Is Private: The namespace is
 *				      private and is already attached to one
 *				      controller.
 * @NVME_SC_NS_NOT_ATTACHED:	      Namespace Not Attached: The request to
 *				      detach the controller could not be
 *				      completed because the controller is not
 *				      attached to the namespace.
 * @NVME_SC_THIN_PROV_NOT_SUPP:	      Thin Provisioning Not Supported: Thin
 *				      provisioning is not supported by the
 *				      controller.
 * @NVME_SC_CTRL_LIST_INVALID:	      Controller List Invalid: The controller
 *				      list provided contains invalid controller
 *				      ids.
 * @NVME_SC_SELF_TEST_IN_PROGRESS:    Device Self-test In Progress: The controller
 *				      or NVM subsystem already has a device
 *				      self-test operation in process.
 * @NVME_SC_BP_WRITE_PROHIBITED:      Boot Partition Write Prohibited: The
 *				      command is trying to modify a locked Boot
 *				      Partition.
 * @NVME_SC_INVALID_CTRL_ID:	      Invalid Controller Identifier:
 * @NVME_SC_INVALID_SEC_CTRL_STATE:   Invalid Secondary Controller State
 * @NVME_SC_INVALID_CTRL_RESOURCES:   Invalid Number of Controller Resources
 * @NVME_SC_INVALID_RESOURCE_ID:      Invalid Resource Identifier
 * @NVME_SC_PMR_SAN_PROHIBITED:	      Sanitize Prohibited While Persistent
 *				      Memory Region is Enabled
 * @NVME_SC_ANA_GROUP_ID_INVALID:     ANA Group Identifier Invalid: The specified
 *				      ANA Group Identifier (ANAGRPID) is not
 *				      supported in the submitted command.
 * @NVME_SC_ANA_ATTACH_FAILED:	      ANA Attach Failed: The controller is not
 *				      attached to the namespace as a result
 *				      of an ANA condition.
 * @NVME_SC_INSUFFICIENT_CAP:	      Insufficient Capacity: Requested operation
 *				      requires more free space than is currently
 *				      available.
 * @NVME_SC_NS_ATTACHMENT_LIMIT_EXCEEDED: Namespace Attachment Limit Exceeded:
 *				      Attaching the ns to a controller causes
 *				      max number of ns attachments allowed
 *				      to be exceeded.
 * @NVME_SC_PROHIBIT_CMD_EXEC_NOT_SUPPORTED: Prohibition of Command Execution
 *				      Not Supported
 * @NVME_SC_IOCS_NOT_SUPPORTED:	      I/O Command Set Not Supported
 * @NVME_SC_IOCS_NOT_ENABLED:	      I/O Command Set Not Enabled
 * @NVME_SC_IOCS_COMBINATION_REJECTED:	I/O Command Set Combination Rejected
 * @NVME_SC_INVALID_IOCS:	      Invalid I/O Command Set
 * @NVME_SC_ID_UNAVAILABLE:	      Identifier Unavailable
 * @NVME_SC_INVALID_DISCOVERY_INFO:   The discovery information provided in
 *				      one or more extended discovery
 *				      information entries is not applicable
 *				      for the type of entity selected in
 *				      the Entity Type (ETYPE) field of the
 *				      Discovery Information Management
 *				      command data portion’s header.
 * @NVME_SC_ZONING_DATA_STRUCT_LOCKED:The requested Zoning data structure
 *				      is locked on the CDC.
 * @NVME_SC_ZONING_DATA_STRUCT_NOTFND:The requested Zoning data structure
 *				      does not exist on the CDC.
 * @NVME_SC_INSUFFICIENT_DISC_RES:    The number of discover information
 *				      entries provided in the data portion
 *				      of the Discovery Information
 *				      Management command for a registration
 *				      task (i.e., TAS field cleared to 0h)
 *				      exceeds the available capacity for
 *				      new discovery information entries on
 *				      the CDC or DDC. This may be a
 *				      transient condition.
 * @NVME_SC_REQSTD_FUNCTION_DISABLED: Fabric Zoning is not enabled on the
 *				      CDC
 * @NVME_SC_ZONEGRP_ORIGINATOR_INVLD:  The NQN contained in the ZoneGroup
 *				      Originator field does not match the
 *				      Host NQN used by the DDC to connect
 *				      to the CDC.
 * @NVME_SC_INVALID_HOST:	      Invalid Host: the Manage Exported NVM
 *				      Subsystem Send Grant/Revoke Host Access
 *				      operation specified a host entry that
 *				      could not be processed.
 * @NVME_SC_INVALID_NVM_SUBSYSTEM:    Invalid NVM Subsystem: the Manage
 *				      Exported NVM Subsystem Send Grant/Revoke
 *				      Host Access operation specified an
 *				      Exported NVM Subsystem entry that could
 *				      not be processed.
 * @NVME_SC_INVALID_CONTROLER_DATA_QUEUE: This error indicates that the
 *				      specified Controller Data Queue
 *				      Identifier is invalid for the controller
 *				      processing the command.
 * @NVME_SC_NOT_ENOUGH_RESOURCES:     This error indicates that there is not
 *				      enough resources in the controller to
 *				      process the command.
 * @NVME_SC_CONTROLLER_SUSPENDED:     The operation requested is not allowed if
 *				      the specified controller is suspended.
 * @NVME_SC_CONTROLLER_NOT_SUSPENDED: The operation requested is not allowed if
 *				      the specified controller is not
 *				      suspended.
 * @NVME_SC_CONTROLLER_DATA_QUEUE_FULL: The controller detected that a
 *				      Controller Data Queue became full.
 * @NVME_SC_EXCEEDS_MAX_NS_SANITIZE:  Request Exceeds Maximum Namespace
 *				      Sanitize Operations In Progress
 *				      (Sanitize Namespace command specific
 *				      status). Numerically identical to
 *				      %NVME_SC_FW_NEEDS_MAX_TIME (Firmware
 *				      Commit) - command specific status is
 *				      scoped per opcode, so this collision is
 *				      expected; use only when decoding the
 *				      completion of a Sanitize Namespace
 *				      command.
 * @NVME_SC_MFG_DEFAULT_PERSONALITY_REQUIRED: Manufacturing Default Personality
 *				      Required: The Firmware Commit command was
 *				      aborted due to the firmware image being
 *				      incompatible with the current personality
 *				      settings; the settings of each affected
 *				      personality are required to be compatible
 *				      with the current personality settings for
 *				      the firmware image to be committed.
 * @NVME_SC_INVALID_POWER_LIMIT:      Invalid Power Limit: The power limit
 *				      specified for the Power Limit feature is
 *				      invalid because that power limit prohibits
 *				      all operational power states.
 * @NVME_SC_CROSS_CTRL_RESET_IN_PROGRESS: Cross-Controller Reset in Progress:
 *				      there is already an in-progress
 *				      Cross-Controller Reset operation that
 *				      this controller caused to be initiated
 *				      for the Impacted Controller.
 * @NVME_SC_CROSS_CTRL_RESET_LOG_FULL: Cross-Controller Reset Log Page Full:
 *				      the Cross-Controller Reset log page
 *				      already contains the maximum number of
 *				      entries.
 * @NVME_SC_CROSS_CTRL_RESET_LIMIT_EXCEEDED: Cross-Controller Reset Limit
 *				      Exceeded: the number of simultaneous
 *				      in-progress Cross-Controller Reset
 *				      operations this controller caused to be
 *				      initiated is greater than or equal to
 *				      the Cross-Controller Reset Limit field
 *				      in the Identify Controller data
 *				      structure.
 * @NVME_SC_CONTROLLER_ACTIVE:	      Controller Active: for a Manage Exported
 *				      NVM Subsystem Send Delete operation, an
 *				      Underlying Controller in the specified
 *				      Exported NVM Subsystem is able to
 *				      process commands. For an Associate
 *				      Controllers operation, an Underlying
 *				      Controller being associated with an
 *				      Exported NVM Subsystem was in a state
 *				      that could process commands.
 * @NVME_SC_INVALID_EXPORTED_ASSOCIATION: Invalid Exported Association: an
 *				      Underlying Controller being associated
 *				      with an Exported NVM Subsystem has
 *				      Underlying Namespaces attached that are
 *				      not associated with that Exported NVM
 *				      Subsystem, or the association otherwise
 *				      conflicts with an existing one.
 * @NVME_SC_INVALID_EXPORTED_CONFIG_STATE: Invalid Exported Configuration
 *				      State: invalid data was found in the
 *				      Exported Configuration State provided
 *				      with the Set Exported Configuration
 *				      State management operation.
 * @NVME_SC_BAD_ATTRIBUTES:	      Conflicting Dataset Management Attributes
 * @NVME_SC_INVALID_PI:		      Invalid Protection Information
 * @NVME_SC_READ_ONLY:		      Attempted Write to Read Only Range
 * @NVME_SC_CMD_SIZE_LIMIT_EXCEEDED:  Command Size Limit Exceeded
 * @NVME_SC_INCOMPATIBLE_NS:	      Incompatible Namespace or Format: At
 *				      least one source namespace and the
 *				      destination namespace have incompatible
 *				      formats.
 * @NVME_SC_FAST_COPY_NOT_POSSIBLE:   Fast Copy Not Possible: The Fast Copy
 *				      Only (FCO) bit was set to ‘1’ in a Source
 *				      Range entry and the controller was not
 *				      able to use fast copy operations to copy
 *				      the specified data.
 * @NVME_SC_OVERLAPPING_IO_RANGE:     Overlapping I/O Range: A source logical
 *				      block range overlaps the destination
 *				      logical block range.
 * @NVME_SC_INSUFFICIENT_RESOURCES:   Insufficient Resources: A resource
 *				      shortage prevented the controller from
 *				      performing the requested copy.
 * @NVME_SC_CONNECT_FORMAT:	      Incompatible Format: The NVM subsystem
 *				      does not support the record format
 *				      specified by the host.
 * @NVME_SC_CONNECT_CTRL_BUSY:	      Controller Busy: The controller is
 *				      already associated with a host.
 * @NVME_SC_CONNECT_INVALID_PARAM:    Connect Invalid Parameters: One or more
 *				      of the command parameters.
 * @NVME_SC_CONNECT_RESTART_DISC:     Connect Restart Discovery: The NVM
 *				      subsystem requested is not available.
 * @NVME_SC_CONNECT_INVALID_HOST:     Connect Invalid Host: The host is either
 *				      not allowed to establish an association
 *				      to any controller in the NVM subsystem or
 *				      the host is not allowed to establish an
 *				      association to the specified controller
 * @NVME_SC_DISCONNECT_INVALID_QTYPE: Invalid Queue Type: The command was sent
 *				      on the wrong queue type.
 * @NVME_SC_DISCOVERY_RESTART:	      Discover Restart: The snapshot of the
 *				      records is now invalid or out of date.
 * @NVME_SC_AUTH_REQUIRED:	      Authentication Required: NVMe in-band
 *				      authentication is required and the queue
 *				      has not yet been authenticated.
 * @NVME_SC_WRITE_FAULT:	      Write Fault: The write data could not be
 *				      committed to the media.
 * @NVME_SC_READ_ERROR:		      Unrecovered Read Error: The read data
 *				      could not be recovered from the media.
 * @NVME_SC_GUARD_CHECK:	      End-to-end Guard Check Error: The command
 *				      was aborted due to an end-to-end guard
 *				      check failure.
 * @NVME_SC_APPTAG_CHECK:	      End-to-end Application Tag Check Error:
 *				      The command was aborted due to an
 *				      end-to-end application tag check failure.
 * @NVME_SC_REFTAG_CHECK:	      End-to-end Reference Tag Check Error: The
 *				      command was aborted due to an end-to-end
 *				      reference tag check failure.
 * @NVME_SC_COMPARE_FAILED:	      Compare Failure: The command failed due
 *				      to a miscompare during a Compare command.
 * @NVME_SC_ACCESS_DENIED:	      Access Denied: Access to the namespace
 *				      and/or LBA range is denied due to lack of
 *				      access rights.
 * @NVME_SC_UNWRITTEN_BLOCK:	      Deallocated or Unwritten Logical Block:
 *				      The command failed due to an attempt to
 *				      read from or verify an LBA range
 *				      containing a deallocated or unwritten
 *				      logical block.
 * @NVME_SC_STORAGE_TAG_CHECK:	      End-to-End Storage Tag Check Error: The
 *				      command was aborted due to an end-to-end
 *				      storage tag check failure.
 * @NVME_SC_ANA_INTERNAL_PATH_ERROR:  Internal Path Error: The command was not
 *				      completed as the result of a controller
 *				      internal error that is specific to the
 *				      controller processing the command.
 * @NVME_SC_ANA_PERSISTENT_LOSS:      Asymmetric Access Persistent Loss: The
 *				      requested function (e.g., command) is not
 *				      able to be performed as a result of the
 *				      relationship between the controller and
 *				      the namespace being in the ANA Persistent
 *				      Loss state.
 * @NVME_SC_ANA_INACCESSIBLE:	      Asymmetric Access Inaccessible: The
 *				      requested function (e.g., command) is not
 *				      able to be performed as a result of the
 *				      relationship between the controller and
 *				      the namespace being in the ANA
 *				      Inaccessible state.
 * @NVME_SC_ANA_TRANSITION:	      Asymmetric Access Transition: The
 *				      requested function (e.g., command) is not
 *				      able to be performed as a result of the
 *				      relationship between the controller and
 *				      the namespace transitioning between
 *				      Asymmetric Namespace Access states.
 * @NVME_SC_CTRL_PATH_ERROR:	      Controller Pathing Error: A pathing error
 *				      was detected by the controller.
 * @NVME_SC_HOST_PATH_ERROR:	      Host Pathing Error: A pathing error was
 *				      detected by the host.
 * @NVME_SC_CMD_ABORTED_BY_HOST:      Command Aborted By Host: The command was
 *				      aborted as a result of host action.
 * @NVME_SC_CRD:		      Mask to get value of Command Retry Delay
 *				      index
 * @NVME_SC_MORE:		      More bit. If set, more status information
 *				      for this command as part of the Error
 *				      Information log that may be retrieved with
 *				      the Get Log Page command.
 * @NVME_SC_DNR:		      Do Not Retry bit. If set, if the same
 *				      command is re-submitted to any controller
 *				      in the NVM subsystem, then that
 *				      re-submitted command is expected to fail.
 * @NVME_SC_ZNS_INVALID_OP_REQUEST:	Invalid Zone Operation Request:
 *				      The operation requested is invalid. This may be due to
 *				      various conditions, including: attempting to allocate a
 *				      ZRWA when a zone is not in the ZSE:Empty state; or
 *				      invalid Flush Explicit ZRWA Range Send Zone Action
 *				      operation.
 * @NVME_SC_ZNS_ZRWA_RESOURCES_UNAVAILABLE: ZRWA Resources Unavailable:
 *				      No ZRWAs are available.
 * @NVME_SC_ZNS_BOUNDARY_ERROR:	      Zone Boundary Error: The command specifies
 *				      logical blocks in more than one zone.
 * @NVME_SC_ZNS_FULL:		      Zone Is Full: The accessed zone is in the
 *				      ZSF:Full state.
 * @NVME_SC_ZNS_READ_ONLY:	      Zone Is Read Only: The accessed zone is
 *				      in the ZSRO:Read Only state.
 * @NVME_SC_ZNS_OFFLINE:	      Zone Is Offline: The accessed zone is
 *				      in the ZSO:Offline state.
 * @NVME_SC_ZNS_INVALID_WRITE:	      Zone Invalid Write: The write to a zone
 *				      was not at the write pointer.
 * @NVME_SC_ZNS_TOO_MANY_ACTIVE:      Too Many Active Zones: The controller
 *				      does not allow additional active zones.
 * @NVME_SC_ZNS_TOO_MANY_OPENS:	      Too Many Open Zones: The controller does
 *				      not allow additional open zones.
 * @NVME_SC_ZNS_INVAL_TRANSITION:     Invalid Zone State Transition: The request
 *				      is not a valid zone state transition.
 */
enum nvme_status_field {
	/*
	 * Status Code Type indicators
	 */
	NVME_SCT_GENERIC		= 0x0,
	NVME_SCT_CMD_SPECIFIC		= 0x1,
	NVME_SCT_MEDIA			= 0x2,
	NVME_SCT_PATH			= 0x3,
	NVME_SCT_VS			= 0x7,
	NVME_SCT_MASK			= 0x7,
	NVME_SCT_SHIFT			= 0x8,

	/*
	 * Status Code inidicators
	 */
	NVME_SC_MASK			= 0xff,
	NVME_SC_SHIFT			= 0x0,

	/*
	 * Generic Command Status Codes:
	 */
	NVME_SC_SUCCESS				= 0x0,
	NVME_SC_INVALID_OPCODE			= 0x1,
	NVME_SC_INVALID_FIELD			= 0x2,
	NVME_SC_CMDID_CONFLICT			= 0x3,
	NVME_SC_DATA_XFER_ERROR			= 0x4,
	NVME_SC_POWER_LOSS			= 0x5,
	NVME_SC_INTERNAL			= 0x6,
	NVME_SC_ABORT_REQ			= 0x7,
	NVME_SC_ABORT_QUEUE			= 0x8,
	NVME_SC_FUSED_FAIL			= 0x9,
	NVME_SC_FUSED_MISSING			= 0xa,
	NVME_SC_INVALID_NS			= 0xb,
	NVME_SC_CMD_SEQ_ERROR			= 0xc,
	NVME_SC_SGL_INVALID_LAST		= 0xd,
	NVME_SC_SGL_INVALID_COUNT		= 0xe,
	NVME_SC_SGL_INVALID_DATA		= 0xf,
	NVME_SC_SGL_INVALID_METADATA		= 0x10,
	NVME_SC_SGL_INVALID_TYPE		= 0x11,
	NVME_SC_CMB_INVALID_USE			= 0x12,
	NVME_SC_PRP_INVALID_OFFSET		= 0x13,
	NVME_SC_AWU_EXCEEDED			= 0x14,
	NVME_SC_OP_DENIED			= 0x15,
	NVME_SC_SGL_INVALID_OFFSET		= 0x16,
	NVME_SC_HOSTID_FORMAT			= 0x18,
	NVME_SC_KAT_EXPIRED			= 0x19,
	NVME_SC_KAT_INVALID			= 0x1a,
	NVME_SC_CMD_ABORTED_PREMEPT		= 0x1b,
	NVME_SC_SANITIZE_FAILED			= 0x1c,
	NVME_SC_SANITIZE_IN_PROGRESS		= 0x1d,
	NVME_SC_SGL_INVALID_GRANULARITY		= 0x1e,
	NVME_SC_CMD_IN_CMBQ_NOT_SUPP		= 0x1f,
	NVME_SC_NS_WRITE_PROTECTED		= 0x20,
	NVME_SC_CMD_INTERRUPTED			= 0x21,
	NVME_SC_TRAN_TPORT_ERROR		= 0x22,
	NVME_SC_PROHIBITED_BY_CMD_AND_FEAT	= 0x23,
	NVME_SC_ADMIN_CMD_MEDIA_NOT_READY	= 0x24,
	NVME_SC_INVALID_KEY_TAG			= 0x25,
	NVME_SC_HOST_DISPERSED_NS_NOT_ENABLED	= 0x26,
	NVME_SC_HOST_ID_NOT_INITIALIZED		= 0x27,
	NVME_SC_INCORRECT_KEY			= 0x28,
	NVME_SC_FDP_DISABLED			= 0x29,
	NVME_SC_INVALID_PLACEMENT_HANDLE_LIST	= 0x2A,
	NVME_SC_SANITIZE_NS_FAILED		= 0x2B,
	NVME_SC_SANITIZE_NS_IN_PROGRESS		= 0x2C,
	NVME_SC_FAILED_TO_RESTORE_CONFIG	= 0x2D,
	NVME_SC_LBA_RANGE			= 0x80,
	NVME_SC_CAP_EXCEEDED			= 0x81,
	NVME_SC_NS_NOT_READY			= 0x82,
	NVME_SC_RESERVATION_CONFLICT		= 0x83,
	NVME_SC_FORMAT_IN_PROGRESS		= 0x84,
	NVME_SC_INVALID_VALUE_SIZE		= 0x85,
	NVME_SC_INVALID_KEY_SIZE		= 0x86,
	NVME_SC_KV_KEY_NOT_EXISTS		= 0x87,
	NVME_SC_UNRECOVERED_ERROR		= 0x88,
	NVME_SC_KEY_EXISTS			= 0x89,

	/*
	 * Command Specific Status Codes:
	 */
	NVME_SC_CQ_INVALID			= 0x00,
	NVME_SC_QID_INVALID			= 0x01,
	NVME_SC_QUEUE_SIZE			= 0x02,
	NVME_SC_ABORT_LIMIT			= 0x03,
	NVME_SC_ABORT_MISSING			= 0x04,
	NVME_SC_ASYNC_LIMIT			= 0x05,
	NVME_SC_FIRMWARE_SLOT			= 0x06,
	NVME_SC_FIRMWARE_IMAGE			= 0x07,
	NVME_SC_INVALID_VECTOR			= 0x08,
	NVME_SC_INVALID_LOG_PAGE		= 0x09,
	NVME_SC_INVALID_FORMAT			= 0x0a,
	NVME_SC_FW_NEEDS_CONV_RESET		= 0x0b,
	NVME_SC_INVALID_QUEUE			= 0x0c,
	NVME_SC_FEATURE_NOT_SAVEABLE		= 0x0d,
	NVME_SC_FEATURE_NOT_CHANGEABLE		= 0x0e,
	NVME_SC_FEATURE_NOT_PER_NS		= 0x0f,
	NVME_SC_FW_NEEDS_SUBSYS_RESET		= 0x10,
	NVME_SC_FW_NEEDS_RESET			= 0x11,
	NVME_SC_FW_NEEDS_MAX_TIME		= 0x12,
	NVME_SC_FW_ACTIVATE_PROHIBITED		= 0x13,
	NVME_SC_OVERLAPPING_RANGE		= 0x14,
	NVME_SC_NS_INSUFFICIENT_CAP		= 0x15,
	NVME_SC_NS_ID_UNAVAILABLE		= 0x16,
	NVME_SC_NS_ALREADY_ATTACHED		= 0x18,
	NVME_SC_NS_IS_PRIVATE			= 0x19,
	NVME_SC_NS_NOT_ATTACHED			= 0x1a,
	NVME_SC_THIN_PROV_NOT_SUPP		= 0x1b,
	NVME_SC_CTRL_LIST_INVALID		= 0x1c,
	NVME_SC_SELF_TEST_IN_PROGRESS		= 0x1d,
	NVME_SC_BP_WRITE_PROHIBITED		= 0x1e,
	NVME_SC_INVALID_CTRL_ID			= 0x1f,
	NVME_SC_INVALID_SEC_CTRL_STATE		= 0x20,
	NVME_SC_INVALID_CTRL_RESOURCES		= 0x21,
	NVME_SC_INVALID_RESOURCE_ID		= 0x22,
	NVME_SC_PMR_SAN_PROHIBITED		= 0x23,
	NVME_SC_ANA_GROUP_ID_INVALID		= 0x24,
	NVME_SC_ANA_ATTACH_FAILED		= 0x25,
	NVME_SC_INSUFFICIENT_CAP		= 0x26,
	NVME_SC_NS_ATTACHMENT_LIMIT_EXCEEDED	= 0x27,
	NVME_SC_PROHIBIT_CMD_EXEC_NOT_SUPPORTED = 0x28,

	/*
	 * Command Set Specific - Namespace Types commands:
	 */
	NVME_SC_IOCS_NOT_SUPPORTED		= 0x29,
	NVME_SC_IOCS_NOT_ENABLED		= 0x2a,
	NVME_SC_IOCS_COMBINATION_REJECTED	= 0x2b,
	NVME_SC_INVALID_IOCS			= 0x2c,
	NVME_SC_ID_UNAVAILABLE			= 0x2d,

	/*
	 * Discovery Information Management
	 */
	NVME_SC_INVALID_DISCOVERY_INFO		= 0x2f,
	NVME_SC_ZONING_DATA_STRUCT_LOCKED	= 0x30,
	NVME_SC_ZONING_DATA_STRUCT_NOTFND	= 0x31,
	NVME_SC_INSUFFICIENT_DISC_RES		= 0x32,
	NVME_SC_REQSTD_FUNCTION_DISABLED	= 0x33,
	NVME_SC_ZONEGRP_ORIGINATOR_INVLD	= 0x34,
	NVME_SC_INVALID_HOST			= 0x35,
	NVME_SC_INVALID_NVM_SUBSYSTEM		= 0x36,

	/*
	 * Command Set Specific - Live Migration
	 */
	NVME_SC_INVALID_CONTROLER_DATA_QUEUE	= 0x37,
	NVME_SC_NOT_ENOUGH_RESOURCES		= 0x38,
	NVME_SC_CONTROLLER_SUSPENDED		= 0x39,
	NVME_SC_CONTROLLER_NOT_SUSPENDED	= 0x3A,
	NVME_SC_CONTROLLER_DATA_QUEUE_FULL	= 0x3B,

	/*
	 * Command Set Specific - Sanitize Namespace
	 */
	NVME_SC_EXCEEDS_MAX_NS_SANITIZE		= 0x12,

	/*
	 * Command Set Specific - Firmware Commit
	 */
	NVME_SC_MFG_DEFAULT_PERSONALITY_REQUIRED = 0x3d,

	/*
	 * Command Set Specific - Set Features
	 */
	NVME_SC_INVALID_POWER_LIMIT		= 0x3e,
	NVME_SC_CROSS_CTRL_RESET_IN_PROGRESS	= 0x3f,
	NVME_SC_CROSS_CTRL_RESET_LOG_FULL	= 0x40,
	NVME_SC_CROSS_CTRL_RESET_LIMIT_EXCEEDED = 0x41,

	/*
	 * Command Set Specific - Manage Exported NVM Subsystem Send
	 */
	NVME_SC_CONTROLLER_ACTIVE		= 0x42,
	NVME_SC_INVALID_EXPORTED_ASSOCIATION	= 0x43,
	NVME_SC_INVALID_EXPORTED_CONFIG_STATE	= 0x44,

	/*
	 * I/O Command Set Specific - NVM commands:
	 */
	NVME_SC_BAD_ATTRIBUTES		= 0x80,
	NVME_SC_INVALID_PI		= 0x81,
	NVME_SC_READ_ONLY		= 0x82,
	NVME_SC_CMD_SIZE_LIMIT_EXCEEDED = 0x83,
	NVME_SC_INCOMPATIBLE_NS		= 0x85,
	NVME_SC_FAST_COPY_NOT_POSSIBLE	= 0x86,
	NVME_SC_OVERLAPPING_IO_RANGE	= 0x87,
	NVME_SC_INSUFFICIENT_RESOURCES	= 0x89,

	/*
	 * I/O Command Set Specific - Fabrics commands:
	 */
	NVME_SC_CONNECT_FORMAT		= 0x80,
	NVME_SC_CONNECT_CTRL_BUSY	= 0x81,
	NVME_SC_CONNECT_INVALID_PARAM	= 0x82,
	NVME_SC_CONNECT_RESTART_DISC	= 0x83,
	NVME_SC_CONNECT_INVALID_HOST	= 0x84,
	NVME_SC_DISCONNECT_INVALID_QTYPE= 0x85,
	NVME_SC_DISCOVERY_RESTART	= 0x90,
	NVME_SC_AUTH_REQUIRED		= 0x91,

	/*
	 * I/O Command Set Specific - ZNS commands:
	 */
	NVME_SC_ZNS_INVALID_OP_REQUEST	       = 0xb6,
	NVME_SC_ZNS_ZRWA_RESOURCES_UNAVAILABLE = 0xb7,
	NVME_SC_ZNS_BOUNDARY_ERROR	       = 0xb8,
	NVME_SC_ZNS_FULL		       = 0xb9,
	NVME_SC_ZNS_READ_ONLY		       = 0xba,
	NVME_SC_ZNS_OFFLINE		       = 0xbb,
	NVME_SC_ZNS_INVALID_WRITE	       = 0xbc,
	NVME_SC_ZNS_TOO_MANY_ACTIVE	       = 0xbd,
	NVME_SC_ZNS_TOO_MANY_OPENS	       = 0xbe,
	NVME_SC_ZNS_INVAL_TRANSITION	       = 0xbf,

	/*
	 * Media and Data Integrity Errors:
	 */
	NVME_SC_WRITE_FAULT		= 0x80,
	NVME_SC_READ_ERROR		= 0x81,
	NVME_SC_GUARD_CHECK		= 0x82,
	NVME_SC_APPTAG_CHECK		= 0x83,
	NVME_SC_REFTAG_CHECK		= 0x84,
	NVME_SC_COMPARE_FAILED		= 0x85,
	NVME_SC_ACCESS_DENIED		= 0x86,
	NVME_SC_UNWRITTEN_BLOCK		= 0x87,
	NVME_SC_STORAGE_TAG_CHECK	= 0x88,

	/*
	 * Path-related Errors:
	 */
	NVME_SC_ANA_INTERNAL_PATH_ERROR	= 0x00,
	NVME_SC_ANA_PERSISTENT_LOSS	= 0x01,
	NVME_SC_ANA_INACCESSIBLE	= 0x02,
	NVME_SC_ANA_TRANSITION		= 0x03,
	NVME_SC_CTRL_PATH_ERROR		= 0x60,
	NVME_SC_HOST_PATH_ERROR		= 0x70,
	NVME_SC_CMD_ABORTED_BY_HOST	= 0x71,

	/*
	 * Additional status field flags
	 */
	NVME_SC_CRD			= 0x1800,
	NVME_SC_MORE			= 0x2000,
	NVME_SC_DNR			= 0x4000,
};

/**
 * nvme_status_code_type() - Returns the NVMe Status Code Type
 * @status_field:	The NVMe Completion Queue Entry's Status Field
 *			See &enum nvme_status_field
 *
 * Return: status code type
 */
static inline __u16 nvme_status_code_type(__u16 status_field)
{
	return NVME_GET(status_field, SCT);
}

/**
 * nvme_status_code() - Returns the NVMe Status Code
 * @status_field:	The NVMe Completion Queue Entry's Status Field
 *			See &enum nvme_status_field
 *
 * Return: status code
 */
static inline __u16 nvme_status_code(__u16 status_field)
{
	return NVME_GET(status_field, SC);
}

/**
 * enum nvme_status_type - type encoding for NVMe return values, when
 * represented as an int.
 *
 * The nvme_* api returns an int, with negative values indicating an internal
 * or syscall error, zero signifying success, positive values representing
 * the NVMe status.
 *
 * That latter case (the NVMe status) may represent status values from
 * different parts of the transport/controller/etc, and are at most 16 bits of
 * data. So, we use the most-significant 3 bits of the signed int to indicate
 * which type of status this is.
 *
 * @NVME_STATUS_TYPE_SHIFT: shift value for status bits
 * @NVME_STATUS_TYPE_MASK:  mask value for status bits
 *
 * @NVME_STATUS_TYPE_NVME:  NVMe command status value, typically from CDW3
 * @NVME_STATUS_TYPE_MI:    NVMe-MI header status
 */
enum nvme_status_type {
	NVME_STATUS_TYPE_SHIFT		= 27,
	NVME_STATUS_TYPE_MASK		= 0x7,

	NVME_STATUS_TYPE_NVME		= 0,
	NVME_STATUS_TYPE_MI		= 1,
};

#define NVME_STATUS_TYPE(type)	NVME_GET(type, STATUS_TYPE)

/**
 * nvme_status_get_type() - extract the type from a nvme_* return value
 * @status: the (non-negative) return value from the NVMe API
 *
 * Return: the type component of the status.
 */
static inline __u32 nvme_status_get_type(int status)
{
	return NVME_GET(status, STATUS_TYPE);
}

/**
 * nvme_status_get_value() - extract the status value from a nvme_* return
 * value
 * @status: the (non-negative) return value from the NVMe API
 *
 * Return: the value component of the status; the set of values will depend
 * on the status type.
 */
static inline __u32 nvme_status_get_value(int status)
{
	return status & ~NVME_SET(NVME_STATUS_TYPE_MASK, STATUS_TYPE);
}

/**
 * nvme_status_equals() - helper to check a status against a type and value
 * @status: the (non-negative) return value from the NVMe API
 * @type: the status type
 * @value: the status value
 *
 * Return: true if @status is of the specified type and value
 */
static inline __u32 nvme_status_equals(int status, enum nvme_status_type type,
				       unsigned int value)
{
	if (status < 0)
		return false;

	return nvme_status_get_type(status) == type &&
		nvme_status_get_value(status) == value;
}

/**
 * enum nvme_admin_opcode - Known NVMe admin opcodes
 * @nvme_admin_delete_sq:		Delete I/O Submission Queue
 * @nvme_admin_create_sq:		Create I/O Submission Queue
 * @nvme_admin_get_log_page:		Get Log Page
 * @nvme_admin_delete_cq:		Delete I/O Completion Queue
 * @nvme_admin_create_cq:		Create I/O Completion Queue
 * @nvme_admin_identify:		Identify
 * @nvme_admin_abort_cmd:		Abort
 * @nvme_admin_set_features:		Set Features
 * @nvme_admin_get_features:		Get Features
 * @nvme_admin_async_event:		Asynchronous Event Request
 * @nvme_admin_ns_mgmt:			Namespace Management
 * @nvme_admin_fw_activate:		Firmware Commit
 * @nvme_admin_fw_commit:		Firmware Commit
 * @nvme_admin_fw_download:		Firmware Image Download
 * @nvme_admin_dev_self_test:		Device Self-test
 * @nvme_admin_ns_attach:		Namespace Attachment
 * @nvme_admin_keep_alive:		Keep Alive
 * @nvme_admin_directive_send:		Directive Send
 * @nvme_admin_directive_recv:		Directive Receive
 * @nvme_admin_virtual_mgmt:		Virtualization Management
 * @nvme_admin_nvme_mi_send:		NVMe-MI Send
 * @nvme_admin_nvme_mi_recv:		NVMe-MI Receive
 * @nvme_admin_capacity_mgmt:		Capacity Management
 * @nvme_admin_discovery_info_mgmt:	Discovery Information Management (DIM)
 * @nvme_admin_fabric_zoning_recv:	Fabric Zoning Receive
 * @nvme_admin_lockdown:		Lockdown
 * @nvme_admin_fabric_zoning_lookup:	Fabric Zoning Lookup
 * @nvme_admin_clear_export_nvm_res:	Clear Exported NVM Resource Configuration
 * @nvme_admin_fabric_zoning_send:	Fabric Zoning Send
 * @nvme_admin_manage_export_nvms_receive:	Manage Exported NVM Subsystem Receive
 * @nvme_admin_manage_export_nvms_send:	Manage Exported NVM Subsystem Send
 * @nvme_admin_manage_export_ns:	Manage Exported Namespace
 * @nvme_admin_manage_export_port:	Manage Exported Port
 * @nvme_admin_cross_ctrl_reset:	Cross-Controller Reset
 * @nvme_admin_send_disc_log_page:	Send Discovery Log Page
 * @nvme_admin_track_send:		Track Send
 * @nvme_admin_track_receive:		Track Receive
 * @nvme_admin_migration_send:		Migration Send
 * @nvme_admin_migration_receive:	Migration Receive
 * @nvme_admin_ctrl_data_queue:		Controller Data Queue
 * @nvme_admin_dbbuf:			Doorbell Buffer Config
 * @nvme_admin_fabrics:			Fabrics Commands
 * @nvme_admin_format_nvm:		Format NVM
 * @nvme_admin_security_send:		Security Send
 * @nvme_admin_security_recv:		Security Receive
 * @nvme_admin_sanitize_nvm:		Sanitize
 * @nvme_admin_load_program:		Load Program
 * @nvme_admin_get_lba_status:		Get LBA Status
 * @nvme_admin_program_act_mgmt:	Program Activation Management
 * @nvme_admin_mem_range_set_mgmt:	Memory Range Set Management
 * @nvme_admin_sanitize_ns:		Sanitize Namespace
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
	nvme_admin_capacity_mgmt	= 0x20,
	nvme_admin_discovery_info_mgmt	= 0x21,
	nvme_admin_fabric_zoning_recv	= 0x22,
	nvme_admin_lockdown		= 0x24,
	nvme_admin_fabric_zoning_lookup	= 0x25,
	nvme_admin_clear_export_nvm_res	= 0x28,
	nvme_admin_fabric_zoning_send	= 0x29,
	nvme_admin_manage_export_nvms_receive	= 0x2a,
	nvme_admin_manage_export_nvms_send	= 0x2d,
	nvme_admin_manage_export_ns	= 0x31,
	nvme_admin_manage_export_port	= 0x35,
	nvme_admin_cross_ctrl_reset	= 0x38,
	nvme_admin_send_disc_log_page	= 0x39,
	nvme_admin_track_send		= 0x3d,
	nvme_admin_track_receive	= 0x3e,
	nvme_admin_migration_send	= 0x41,
	nvme_admin_migration_receive	= 0x42,
	nvme_admin_ctrl_data_queue	= 0x45,
	nvme_admin_dbbuf		= 0x7c,
	nvme_admin_fabrics		= 0x7f,
	nvme_admin_format_nvm		= 0x80,
	nvme_admin_security_send	= 0x81,
	nvme_admin_security_recv	= 0x82,
	nvme_admin_sanitize_nvm		= 0x84,
	nvme_admin_load_program		= 0x85,
	nvme_admin_get_lba_status	= 0x86,
	nvme_admin_program_act_mgmt	= 0x88,
	nvme_admin_mem_range_set_mgmt	= 0x89,
	nvme_admin_sanitize_ns		= 0x8c,
};

/**
 * enum nvme_abort_cqe_dw0 - Abort Command – Completion Queue Entry Dword 0
 * @NVME_ABORT_CQE_DW0_IANP: Immediate Abort Not Performed: if set to '1',
 *			     then an immediate abort was not performed for
 *			     any reason. If cleared to '0', then an
 *			     immediate abort was performed.
 */
enum nvme_abort_cqe_dw0 {
	NVME_ABORT_CQE_DW0_IANP	= 1 << 0,
};

/**
 * enum nvme_identify_cns -			Identify - CNS Values
 * @NVME_IDENTIFY_CNS_NS:			Identify Namespace data structure
 * @NVME_IDENTIFY_CNS_CTRL:			Identify Controller data structure
 * @NVME_IDENTIFY_CNS_NS_ACTIVE_LIST:		Active Namespace ID list
 * @NVME_IDENTIFY_CNS_NS_DESC_LIST:		Namespace Identification Descriptor list
 * @NVME_IDENTIFY_CNS_NVMSET_LIST:		NVM Set List
 * @NVME_IDENTIFY_CNS_CSI_NS:			I/O Command Set specific Identify
 *						Namespace data structure
 * @NVME_IDENTIFY_CNS_CSI_CTRL:			I/O Command Set specific Identify
 *						Controller data structure
 * @NVME_IDENTIFY_CNS_CSI_NS_ACTIVE_LIST:	Active Namespace ID list associated
 *						with the specified I/O Command Set
 * @NVME_IDENTIFY_CNS_CSI_INDEPENDENT_ID_NS:	I/O Command Set Independent Identify
 * @NVME_IDENTIFY_CNS_NS_USER_DATA_FORMAT:	Namespace user data format
 * @NVME_IDENTIFY_CNS_CSI_NS_USER_DATA_FORMAT:	I/O Command Set specific user data
 *						format
 *						Namespace data structure
 * @NVME_IDENTIFY_CNS_ALLOCATED_NS_LIST:	Allocated Namespace ID list
 * @NVME_IDENTIFY_CNS_ALLOCATED_NS:		Identify Namespace data structure for
 *						the specified allocated NSID
 * @NVME_IDENTIFY_CNS_NS_CTRL_LIST:		Controller List of controllers attached
 *						to the specified NSID
 * @NVME_IDENTIFY_CNS_CTRL_LIST:		Controller List of controllers that exist
 *						in the NVM subsystem
 * @NVME_IDENTIFY_CNS_PRIMARY_CTRL_CAP:		Primary Controller Capabilities data
 *						structure for the specified primary controller
 * @NVME_IDENTIFY_CNS_SECONDARY_CTRL_LIST:	Secondary Controller list of controllers
 *						associated with the primary controller
 *						processing the command
 * @NVME_IDENTIFY_CNS_NS_GRANULARITY:		A Namespace Granularity List
 * @NVME_IDENTIFY_CNS_UUID_LIST:		A UUID List
 * @NVME_IDENTIFY_CNS_DOMAIN_LIST:		Domain List
 * @NVME_IDENTIFY_CNS_ENDURANCE_GROUP_ID:	Endurance Group List
 * @NVME_IDENTIFY_CNS_CSI_ALLOCATED_NS_LIST:	I/O Command Set specific Allocated Namespace
 *						ID list
 * @NVME_IDENTIFY_CNS_CSI_ID_NS_DATA_STRUCTURE:	I/O Command Set specific ID Namespace
 *						Data Structure for Allocated Namespace ID
 * @NVME_IDENTIFY_CNS_COMMAND_SET_STRUCTURE:	I/O Command Set data structure
 * @NVME_IDENTIFY_CNS_UNDERLYING_NS_LIST:	Get Underlying Namespace List
 * @NVME_IDENTIFY_CNS_PORTS_LIST:		Get Ports List
 * @NVME_IDENTIFY_CNS_IOCS_IND_ID_ALLOC_NS:	I/O Command Set Independent Identify Namespace data
 *						structure for the specified allocated NSID
 * @NVME_IDENTIFY_CNS_SUPPORTED_CTRL_STATE_FORMATS:	Supported Controller State Formats
 *							identifying the supported NVMe Controller
 *							State data structures
 * @NVME_IDENTIFY_CNS_UNDERLYING_CTRL_LIST:		Get Underlying Controller List
 * @NVME_IDENTIFY_CNS_EXPORTED_NVM_SUBSYS_TEMPLATE_UUID_LIST: Exported NVM
 *							Subsystem Template UUID List
 */
enum nvme_identify_cns {
	NVME_IDENTIFY_CNS_NS					= 0x00,
	NVME_IDENTIFY_CNS_CTRL					= 0x01,
	NVME_IDENTIFY_CNS_NS_ACTIVE_LIST			= 0x02,
	NVME_IDENTIFY_CNS_NS_DESC_LIST				= 0x03,
	NVME_IDENTIFY_CNS_NVMSET_LIST				= 0x04,
	NVME_IDENTIFY_CNS_CSI_NS				= 0x05,
	NVME_IDENTIFY_CNS_CSI_CTRL				= 0x06,
	NVME_IDENTIFY_CNS_CSI_NS_ACTIVE_LIST			= 0x07,
	NVME_IDENTIFY_CNS_CSI_INDEPENDENT_ID_NS			= 0x08,
	NVME_IDENTIFY_CNS_NS_USER_DATA_FORMAT			= 0x09,
	NVME_IDENTIFY_CNS_CSI_NS_USER_DATA_FORMAT		= 0x0A,
	NVME_IDENTIFY_CNS_ALLOCATED_NS_LIST			= 0x10,
	NVME_IDENTIFY_CNS_ALLOCATED_NS				= 0x11,
	NVME_IDENTIFY_CNS_NS_CTRL_LIST				= 0x12,
	NVME_IDENTIFY_CNS_CTRL_LIST				= 0x13,
	NVME_IDENTIFY_CNS_PRIMARY_CTRL_CAP			= 0x14,
	NVME_IDENTIFY_CNS_SECONDARY_CTRL_LIST			= 0x15,
	NVME_IDENTIFY_CNS_NS_GRANULARITY			= 0x16,
	NVME_IDENTIFY_CNS_UUID_LIST				= 0x17,
	NVME_IDENTIFY_CNS_DOMAIN_LIST				= 0x18,
	NVME_IDENTIFY_CNS_ENDURANCE_GROUP_ID			= 0x19,
	NVME_IDENTIFY_CNS_CSI_ALLOCATED_NS_LIST			= 0x1A,
	NVME_IDENTIFY_CNS_CSI_ID_NS_DATA_STRUCTURE		= 0x1B,
	NVME_IDENTIFY_CNS_COMMAND_SET_STRUCTURE			= 0x1C,
	NVME_IDENTIFY_CNS_UNDERLYING_NS_LIST			= 0x1D,
	NVME_IDENTIFY_CNS_PORTS_LIST				= 0x1E,
	NVME_IDENTIFY_CNS_IOCS_IND_ID_ALLOC_NS			= 0x1F,
	NVME_IDENTIFY_CNS_SUPPORTED_CTRL_STATE_FORMATS		= 0x20,
	NVME_IDENTIFY_CNS_UNDERLYING_CTRL_LIST			= 0x21,
	NVME_IDENTIFY_CNS_EXPORTED_NVM_SUBSYS_TEMPLATE_UUID_LIST = 0x22,
};

/**
 * enum nvme_cmd_get_log_lid -			Get Log Page -Log Page Identifiers
 * @NVME_LOG_LID_SUPPORTED_LOG_PAGES:		Supported Log Pages
 * @NVME_LOG_LID_ERROR:				Error Information
 * @NVME_LOG_LID_SMART:				SMART / Health Information
 * @NVME_LOG_LID_FW_SLOT:			Firmware Slot Information
 * @NVME_LOG_LID_CHANGED_ATTACHED_NS:		Changed Attached Namespace List
 * @NVME_LOG_LID_CMD_EFFECTS:			Commands Supported and Effects
 * @NVME_LOG_LID_DEVICE_SELF_TEST:		Device Self-test
 * @NVME_LOG_LID_TELEMETRY_HOST:		Telemetry Host-Initiated
 * @NVME_LOG_LID_TELEMETRY_CTRL:		Telemetry Controller-Initiated
 * @NVME_LOG_LID_ENDURANCE_GROUP:		Endurance Group Information
 * @NVME_LOG_LID_PREDICTABLE_LAT_NVMSET:	Predictable Latency Per NVM Set
 * @NVME_LOG_LID_PREDICTABLE_LAT_AGG:		Predictable Latency Event Aggregate
 * @NVME_LOG_LID_ANA:				Asymmetric Namespace Access
 * @NVME_LOG_LID_PERSISTENT_EVENT:		Persistent Event Log
 * @NVME_LOG_LID_LBA_STATUS:			LBA Status Information
 * @NVME_LOG_LID_ENDURANCE_GRP_EVT:		Endurance Group Event Aggregate
 * @NVME_LOG_LID_MEDIA_UNIT_STATUS:		Media Unit Status
 * @NVME_LOG_LID_SUPPORTED_CAP_CONFIG_LIST:	Supported Capacity Configuration Lis
 * @NVME_LOG_LID_FID_SUPPORTED_EFFECTS:		Feature Identifiers Supported and Effects
 * @NVME_LOG_LID_MI_CMD_SUPPORTED_EFFECTS:	NVMe-MI Commands Supported and Effects
 * @NVME_LOG_LID_CMD_AND_FEAT_LOCKDOWN:		Command and Feature Lockdown
 * @NVME_LOG_LID_BOOT_PARTITION:		Boot Partition
 * @NVME_LOG_LID_ROTATIONAL_MEDIA_INFO:		Rotational Media Information
 * @NVME_LOG_LID_DISPERSED_NS_PARTICIPATING_NSS:Dispersed Namespace Participating NVM Subsystems
 * @NVME_LOG_LID_MGMT_ADDR_LIST:		Management Address List
 * @NVME_LOG_LID_PHY_RX_EOM:			Physical Interface Receiver Eye Opening Measurement
 * @NVME_LOG_LID_REACHABILITY_GROUPS:		Reachability Groups
 * @NVME_LOG_LID_REACHABILITY_ASSOCIATIONS:	Reachability Associations
 * @NVME_LOG_LID_CHANGED_ALLOC_NS:		Changed Allocated Namespace List
 * @NVME_LOG_LID_DEV_PERSONALITY:		Device Personalities, see &struct
 *						nvme_dev_personalities_log
 * @NVME_LOG_LID_CROSS_CTRL_RESET:		Cross-Controller Reset
 * @NVME_LOG_LID_LOST_HOST_COMMUNICATION:	Lost Host Communication
 * @NVME_LOG_LID_FDP_CONFIGS:			FDP Configurations
 * @NVME_LOG_LID_FDP_RUH_USAGE:			Reclaim Unit Handle Usage
 * @NVME_LOG_LID_FDP_STATS:			FDP Statistics
 * @NVME_LOG_LID_FDP_EVENTS:			FDP Events
 * @NVME_LOG_LID_MFG_DEFAULT_CONFIG:		Manufacturer Default Configuration
 *						Status, see &struct
 *						nvme_mfg_default_config_status_log
 * @NVME_LOG_LID_POWER_MEASUREMENT:		Power Measurement
 * @NVME_LOG_LID_VOLTAGE_MEASUREMENT:		Voltage Measurement, see
 *						&struct
 *						nvme_voltage_measurement_log
 * @NVME_LOG_LID_RATE_LIMITING:			Rate Limiting
 * @NVME_LOG_LID_DISCOVERY:			Discovery
 * @NVME_LOG_LID_HOST_DISCOVERY:		Host Discovery
 * @NVME_LOG_LID_AVE_DISCOVERY:			AVE Discovery
 * @NVME_LOG_LID_PULL_MODEL_DDC_REQ:		Pull Model DDC Request
 * @NVME_LOG_LID_SANITIZE_NS_STATUS_LIST:	Sanitize Namespace Status List
 * @NVME_LOG_LID_RESERVATION:			Reservation Notification
 * @NVME_LOG_LID_SANITIZE:			Sanitize Status
 * @NVME_LOG_LID_HOST_ADDRESSABLE_NS:		Host Addressable Namespaces, see
 *						&struct nvme_host_addressable_ns_log
 * @NVME_LOG_LID_ZNS_CHANGED_ZONES:		Changed Zone List
 */
enum nvme_cmd_get_log_lid {
	NVME_LOG_LID_SUPPORTED_LOG_PAGES			= 0x00,
	NVME_LOG_LID_ERROR					= 0x01,
	NVME_LOG_LID_SMART					= 0x02,
	NVME_LOG_LID_FW_SLOT					= 0x03,
	NVME_LOG_LID_CHANGED_ATTACHED_NS			= 0x04,
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
	NVME_LOG_LID_MEDIA_UNIT_STATUS				= 0x10,
	NVME_LOG_LID_SUPPORTED_CAP_CONFIG_LIST			= 0x11,
	NVME_LOG_LID_FID_SUPPORTED_EFFECTS			= 0x12,
	NVME_LOG_LID_MI_CMD_SUPPORTED_EFFECTS			= 0x13,
	NVME_LOG_LID_CMD_AND_FEAT_LOCKDOWN			= 0x14,
	NVME_LOG_LID_BOOT_PARTITION				= 0x15,
	NVME_LOG_LID_ROTATIONAL_MEDIA_INFO			= 0x16,
	NVME_LOG_LID_DISPERSED_NS_PARTICIPATING_NSS		= 0x17,
	NVME_LOG_LID_MGMT_ADDR_LIST				= 0x18,
	NVME_LOG_LID_PHY_RX_EOM					= 0x19,
	NVME_LOG_LID_REACHABILITY_GROUPS			= 0x1a,
	NVME_LOG_LID_REACHABILITY_ASSOCIATIONS			= 0x1b,
	NVME_LOG_LID_CHANGED_ALLOC_NS				= 0x1c,
	NVME_LOG_LID_DEV_PERSONALITY				= 0x1d,
	NVME_LOG_LID_CROSS_CTRL_RESET				= 0x1e,
	NVME_LOG_LID_LOST_HOST_COMMUNICATION			= 0x1f,
	NVME_LOG_LID_FDP_CONFIGS				= 0x20,
	NVME_LOG_LID_FDP_RUH_USAGE				= 0x21,
	NVME_LOG_LID_FDP_STATS					= 0x22,
	NVME_LOG_LID_FDP_EVENTS					= 0x23,
	NVME_LOG_LID_MFG_DEFAULT_CONFIG				= 0x24,
	NVME_LOG_LID_POWER_MEASUREMENT				= 0x25,
	NVME_LOG_LID_VOLTAGE_MEASUREMENT			= 0x27,
	NVME_LOG_LID_RATE_LIMITING				= 0x28,
	NVME_LOG_LID_DISCOVERY					= 0x70,
	NVME_LOG_LID_HOST_DISCOVERY				= 0x71,
	NVME_LOG_LID_AVE_DISCOVERY				= 0x72,
	NVME_LOG_LID_PULL_MODEL_DDC_REQ				= 0x73,
	NVME_LOG_LID_SANITIZE_NS_STATUS_LIST			= 0x7f,
	NVME_LOG_LID_RESERVATION				= 0x80,
	NVME_LOG_LID_SANITIZE					= 0x81,
	NVME_LOG_LID_HOST_ADDRESSABLE_NS			= 0x85,
	NVME_LOG_LID_ZNS_CHANGED_ZONES				= 0xbf,
};

/**
 * enum nvme_features_id -		Features - Feature Identifiers
 * @NVME_FEAT_FID_ARBITRATION:		Arbitration
 * @NVME_FEAT_FID_POWER_MGMT:		Power Management
 * @NVME_FEAT_FID_LBA_RANGE:		LBA Range Type
 * @NVME_FEAT_FID_TEMP_THRESH:		Temperature Threshold
 * @NVME_FEAT_FID_ERR_RECOVERY:		Error Recovery
 * @NVME_FEAT_FID_VOLATILE_WC:		Volatile Write Cache
 * @NVME_FEAT_FID_NUM_QUEUES:		Number of Queues
 * @NVME_FEAT_FID_IRQ_COALESCE:		Interrupt Coalescing
 * @NVME_FEAT_FID_IRQ_CONFIG:		Interrupt Vector Configuration
 * @NVME_FEAT_FID_WRITE_ATOMIC:		Write Atomicity Normal
 * @NVME_FEAT_FID_ASYNC_EVENT:		Asynchronous Event Configuration
 * @NVME_FEAT_FID_AUTO_PST:		Autonomous Power State Transition
 * @NVME_FEAT_FID_HOST_MEM_BUF:		Host Memory Buffer
 * @NVME_FEAT_FID_TIMESTAMP:		Timestamp
 * @NVME_FEAT_FID_KATO:			Keep Alive Timer
 * @NVME_FEAT_FID_HCTM:			Host Controlled Thermal Management
 * @NVME_FEAT_FID_NOPSC:		Non-Operational Power State Config
 * @NVME_FEAT_FID_RRL:			Read Recovery Level Config
 * @NVME_FEAT_FID_PLM_CONFIG:		Predictable Latency Mode Config
 * @NVME_FEAT_FID_PLM_WINDOW:		Predictable Latency Mode Window
 * @NVME_FEAT_FID_LBA_STS_INTERVAL:	LBA Status Information Report Interval
 * @NVME_FEAT_FID_HOST_BEHAVIOR:	Host Behavior Support
 * @NVME_FEAT_FID_SANITIZE:		Sanitize Config
 * @NVME_FEAT_FID_ENDURANCE_EVT_CFG:	Endurance Group Event Configuration
 * @NVME_FEAT_FID_IOCS_PROFILE:		I/O Command Set Profile
 * @NVME_FEAT_FID_SPINUP_CONTROL:	Spinup Control
 * @NVME_FEAT_FID_POWER_LOSS_SIGNAL:	Power Loss Signaling Config
 * @NVME_FEAT_FID_PERF_CHARACTERISTICS:	Performance Characteristics
 * @NVME_FEAT_FID_FDP:			Flexible Data Placement
 * @NVME_FEAT_FID_FDP_EVENTS:		FDP Events
 * @NVME_FEAT_FID_NS_ADMIN_LABEL:	Namespace Admin Label
 * @NVME_FEAT_FID_KEY_VALUE:		Key Value Configuration
 * @NVME_FEAT_FID_CTRL_DATA_QUEUE:	Controller Data Queue
 * @NVME_FEAT_FID_CONF_DEV_PERSONALITY: Configurable Device Personality, see
 *					&enum nvme_cdp_cdw13_fields (Set/Get
 *					Features Command Dword 13), &enum
 *					nvme_cdp_cqe_dw0_fields (Get Features
 *					Completion Queue Entry Dword 0), and
 *					&enum nvme_personality_identifier
 * @NVME_FEAT_FID_POWER_LIMIT:		Power Limit
 * @NVME_FEAT_FID_POWER_THRESH:		Power Threshold
 * @NVME_FEAT_FID_POWER_MEASUREMENT:	Power Measurement
 * @NVME_FEAT_FID_VOLTAGE_THRESHOLD:	Voltage Threshold, see &enum
 *					nvme_voltage_sensor
 * @NVME_FEAT_FID_VOLTAGE_MEASUREMENT:	Voltage Measurement, see &enum
 *					nvme_voltage_measurement_act and
 *					&struct
 *					nvme_voltage_measurement_start_data
 * @NVME_FEAT_FID_RATE_LIMITING:	Rate Limiting
 * @NVME_FEAT_FID_EMB_MGMT_CTRL_ADDR:	Embedded Management Controller Address
 * @NVME_FEAT_FID_HOST_MGMT_AGENT_ADDR:	Host Management Agent Address
 * @NVME_FEAT_FID_ENH_CTRL_METADATA:	Enhanced Controller Metadata
 * @NVME_FEAT_FID_CTRL_METADATA:	Controller Metadata
 * @NVME_FEAT_FID_NS_METADATA:		Namespace Metadata
 * @NVME_FEAT_FID_SW_PROGRESS:		Software Progress Marker
 * @NVME_FEAT_FID_HOST_ID:		Host Identifier
 * @NVME_FEAT_FID_RESV_NF_MASK:		Reservation Notification Mask
 * @NVME_FEAT_FID_RESV_PERSIST:		Reservation Persistence
 * @NVME_FEAT_FID_WRITE_PROTECT:	Namespace Write Protection Config
 * @NVME_FEAT_FID_BP_WRITE_PROTECT:	Boot Partition Write Protection Config
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
	NVME_FEAT_FID_IOCS_PROFILE				= 0x19,
	NVME_FEAT_FID_SPINUP_CONTROL				= 0x1a,
	NVME_FEAT_FID_POWER_LOSS_SIGNAL				= 0x1b,
	NVME_FEAT_FID_PERF_CHARACTERISTICS			= 0x1c,
	NVME_FEAT_FID_FDP					= 0x1d,
	NVME_FEAT_FID_FDP_EVENTS				= 0x1e,
	NVME_FEAT_FID_NS_ADMIN_LABEL				= 0x1f,
	NVME_FEAT_FID_KEY_VALUE					= 0x20,
	NVME_FEAT_FID_CTRL_DATA_QUEUE				= 0x21,
	NVME_FEAT_FID_CONF_DEV_PERSONALITY			= 0x22,
	NVME_FEAT_FID_POWER_LIMIT				= 0x23,
	NVME_FEAT_FID_POWER_THRESH				= 0x24,
	NVME_FEAT_FID_POWER_MEASUREMENT				= 0x25,
	NVME_FEAT_FID_VOLTAGE_THRESHOLD				= 0x26,
	NVME_FEAT_FID_VOLTAGE_MEASUREMENT			= 0x27,
	NVME_FEAT_FID_RATE_LIMITING				= 0x28,
	NVME_FEAT_FID_EMB_MGMT_CTRL_ADDR			= 0x78,
	NVME_FEAT_FID_HOST_MGMT_AGENT_ADDR			= 0x79,
	NVME_FEAT_FID_ENH_CTRL_METADATA				= 0x7d,
	NVME_FEAT_FID_CTRL_METADATA				= 0x7e,
	NVME_FEAT_FID_NS_METADATA				= 0x7f,
	NVME_FEAT_FID_SW_PROGRESS				= 0x80,
	NVME_FEAT_FID_HOST_ID					= 0x81,
	NVME_FEAT_FID_RESV_NF_MASK				= 0x82,
	NVME_FEAT_FID_RESV_PERSIST				= 0x83,
	NVME_FEAT_FID_WRITE_PROTECT				= 0x84,
	NVME_FEAT_FID_BP_WRITE_PROTECT				= 0x85,
};

/**
 * enum nvme_feat - Features Access Shifts/Masks values
 * @NVME_FEAT_ARBITRATION_BURST_SHIFT:
 * @NVME_FEAT_ARBITRATION_BURST_MASK:
 * @NVME_FEAT_ARBITRATION_LPW_SHIFT:
 * @NVME_FEAT_ARBITRATION_LPW_MASK:
 * @NVME_FEAT_ARBITRATION_MPW_SHIFT:
 * @NVME_FEAT_ARBITRATION_MPW_MASK:
 * @NVME_FEAT_ARBITRATION_HPW_SHIFT:
 * @NVME_FEAT_ARBITRATION_HPW_MASK:
 * @NVME_FEAT_PWRMGMT_PS_SHIFT:
 * @NVME_FEAT_PWRMGMT_PS_MASK:
 * @NVME_FEAT_PWRMGMT_WH_SHIFT:
 * @NVME_FEAT_PWRMGMT_WH_MASK:
 * @NVME_FEAT_PWRMGMT_IIELL_SHIFT: Shift amount to set/get the Idle I/O Exit
 *				    Latency Limit (IIELL), in units of 100
 *				    microseconds
 * @NVME_FEAT_PWRMGMT_IIELL_MASK: Mask to set/get IIELL
 * @NVME_FEAT_LBAR_NR_SHIFT:
 * @NVME_FEAT_LBAR_NR_MASK:
 * @NVME_FEAT_TT_TMPTH_SHIFT:
 * @NVME_FEAT_TT_TMPTH_MASK:
 * @NVME_FEAT_TT_TMPSEL_SHIFT:
 * @NVME_FEAT_TT_TMPSEL_MASK:
 * @NVME_FEAT_TT_THSEL_SHIFT:
 * @NVME_FEAT_TT_THSEL_MASK:
 * @NVME_FEAT_TT_TMPTHH_SHIFT:
 * @NVME_FEAT_TT_TMPTHH_MASK:
 * @NVME_FEAT_ERROR_RECOVERY_TLER_SHIFT:
 * @NVME_FEAT_ERROR_RECOVERY_TLER_MASK:
 * @NVME_FEAT_ERROR_RECOVERY_DULBE_SHIFT:
 * @NVME_FEAT_ERROR_RECOVERY_DULBE_MASK:
 * @NVME_FEAT_VWC_WCE_SHIFT:
 * @NVME_FEAT_VWC_WCE_MASK:
 * @NVME_FEAT_NRQS_NSQR_SHIFT:
 * @NVME_FEAT_NRQS_NSQR_MASK:
 * @NVME_FEAT_NRQS_NCQR_SHIFT:
 * @NVME_FEAT_NRQS_NCQR_MASK:
 * @NVME_FEAT_IRQC_THR_SHIFT:
 * @NVME_FEAT_IRQC_THR_MASK:
 * @NVME_FEAT_IRQC_TIME_SHIFT:
 * @NVME_FEAT_IRQC_TIME_MASK:
 * @NVME_FEAT_ICFG_IV_SHIFT:
 * @NVME_FEAT_ICFG_IV_MASK:
 * @NVME_FEAT_ICFG_CD_SHIFT:
 * @NVME_FEAT_ICFG_CD_MASK:
 * @NVME_FEAT_WA_DN_SHIFT:
 * @NVME_FEAT_WA_DN_MASK:
 * @NVME_FEAT_AE_SMART_SHIFT:
 * @NVME_FEAT_AE_SMART_MASK:
 * @NVME_FEAT_AE_NAN_SHIFT:
 * @NVME_FEAT_AE_NAN_MASK:
 * @NVME_FEAT_AE_FW_SHIFT:
 * @NVME_FEAT_AE_FW_MASK:
 * @NVME_FEAT_AE_TELEM_SHIFT:
 * @NVME_FEAT_AE_TELEM_MASK:
 * @NVME_FEAT_AE_ANA_SHIFT:
 * @NVME_FEAT_AE_ANA_MASK:
 * @NVME_FEAT_AE_PLA_SHIFT:
 * @NVME_FEAT_AE_PLA_MASK:
 * @NVME_FEAT_AE_LBAS_SHIFT:
 * @NVME_FEAT_AE_LBAS_MASK:
 * @NVME_FEAT_AE_EGA_SHIFT:
 * @NVME_FEAT_AE_EGA_MASK:
 * @NVME_FEAT_AE_NNSSHDN_SHIFT:
 * @NVME_FEAT_AE_NNSSHDN_MASK:
 * @NVME_FEAT_AE_TTHRY_SHIFT:
 * @NVME_FEAT_AE_TTHRY_MASK:
 * @NVME_FEAT_AE_RASSN_SHIFT:
 * @NVME_FEAT_AE_RASSN_MASK:
 * @NVME_FEAT_AE_RGRP0_SHIFT:
 * @NVME_FEAT_AE_RGRP0_MASK:
 * @NVME_FEAT_AE_ANSAN_SHIFT:
 * @NVME_FEAT_AE_ANSAN_MASK:
 * @NVME_FEAT_AE_ZDCN_SHIFT:
 * @NVME_FEAT_AE_ZDCN_MASK:
 * @NVME_FEAT_AE_PMDRLPCN_SHIFT:
 * @NVME_FEAT_AE_PMDRLPCN_MASK:
 * @NVME_FEAT_AE_ADLPCN_SHIFT:
 * @NVME_FEAT_AE_ADLPCN_MASK:
 * @NVME_FEAT_AE_HDLPCN_SHIFT:
 * @NVME_FEAT_AE_HDLPCN_MASK:
 * @NVME_FEAT_AE_DLPCN_SHIFT:
 * @NVME_FEAT_AE_DLPCN_MASK:
 * @NVME_FEAT_APST_APSTE_SHIFT:
 * @NVME_FEAT_APST_APSTE_MASK:
 * @NVME_FEAT_HMEM_EHM_SHIFT:
 * @NVME_FEAT_HMEM_EHM_MASK:
 * @NVME_FEAT_HCTM_TMT2_SHIFT:
 * @NVME_FEAT_HCTM_TMT2_MASK:
 * @NVME_FEAT_HCTM_TMT1_SHIFT:
 * @NVME_FEAT_HCTM_TMT1_MASK:
 * @NVME_FEAT_NOPS_NOPPME_SHIFT:
 * @NVME_FEAT_NOPS_NOPPME_MASK:
 * @NVME_FEAT_RRL_RRL_SHIFT:
 * @NVME_FEAT_RRL_RRL_MASK:
 * @NVME_FEAT_PLM_LPE_SHIFT:
 * @NVME_FEAT_PLM_LPE_MASK:
 * @NVME_FEAT_PLMW_WS_SHIFT:
 * @NVME_FEAT_PLMW_WS_MASK:
 * @NVME_FEAT_LBAS_LSIRI_SHIFT:
 * @NVME_FEAT_LBAS_LSIRI_MASK:
 * @NVME_FEAT_LBAS_LSIPI_SHIFT:
 * @NVME_FEAT_LBAS_LSIPI_MASK:
 * @NVME_FEAT_SC_NODRM_SHIFT:
 * @NVME_FEAT_SC_NODRM_MASK:
 * @NVME_FEAT_EG_ENDGID_SHIFT:
 * @NVME_FEAT_EG_ENDGID_MASK:
 * @NVME_FEAT_EG_EGCW_SHIFT:
 * @NVME_FEAT_EG_EGCW_MASK:
 * @NVME_FEAT_FDPE_PHNDL_SHIFT:
 * @NVME_FEAT_FDPE_PHNDL_MASK:
 * @NVME_FEAT_FDPE_NOET_SHIFT:
 * @NVME_FEAT_FDPE_NOET_MASK:
 * @NVME_FEAT_SPM_PBSLC_SHIFT:
 * @NVME_FEAT_SPM_PBSLC_MASK:
 * @NVME_FEAT_HOSTID_EXHID_SHIFT:
 * @NVME_FEAT_HOSTID_EXHID_MASK:
 * @NVME_FEAT_RM_REGPRE_SHIFT:
 * @NVME_FEAT_RM_REGPRE_MASK:
 * @NVME_FEAT_RM_RESREL_SHIFT:
 * @NVME_FEAT_RM_RESREL_MASK:
 * @NVME_FEAT_RM_RESPRE_SHIFT:
 * @NVME_FEAT_RM_RESPRE_MASK:
 * @NVME_FEAT_RP_PTPL_SHIFT:
 * @NVME_FEAT_RP_PTPL_MASK:
 * @NVME_FEAT_WP_WPS_SHIFT:
 * @NVME_FEAT_WP_WPS_MASK:
 * @NVME_FEAT_IOCSP_IOCSCI_SHIFT:
 * @NVME_FEAT_IOCSP_IOCSCI_MASK:
 * @NVME_FEAT_SPINUP_CONTROL_SHIFT:
 * @NVME_FEAT_SPINUP_CONTROL_MASK:
 * @NVME_FEAT_PLS_MODE_SHIFT:
 * @NVME_FEAT_PLS_MODE_MASK:
 * @NVME_FEAT_PERFC_ATTRI_SHIFT:
 * @NVME_FEAT_PERFC_ATTRI_MASK:
 * @NVME_FEAT_PERFC_RVSPA_SHIFT:
 * @NVME_FEAT_PERFC_RVSPA_MASK:
 * @NVME_FEAT_PERFC_ATTRTYP_SHIFT:
 * @NVME_FEAT_PERFC_ATTRTYP_MASK:
 * @NVME_FEAT_FDP_ENABLED_SHIFT:
 * @NVME_FEAT_FDP_ENABLED_MASK:
 * @NVME_FEAT_FDP_INDEX_SHIFT:
 * @NVME_FEAT_FDP_INDEX_MASK:
 * @NVME_FEAT_FDP_EVENTS_ENABLE_SHIFT:
 * @NVME_FEAT_FDP_EVENTS_ENABLE_MASK:
 * @NVME_FEAT_HOST_ID_EXHID_SHIFT:
 * @NVME_FEAT_HOST_ID_EXHID_MASK:
 * @NVME_FEAT_BPWPC_BP0WPS_SHIFT:
 * @NVME_FEAT_BPWPC_BP0WPS_MASK:
 * @NVME_FEAT_BPWPC_BP1WPS_SHIFT:
 * @NVME_FEAT_BPWPC_BP1WPS_MASK:
 * @NVME_FEAT_SANITIZE_NODRM_SHIFT:
 * @NVME_FEAT_SANITIZE_NODRM_MASK:
 * @NVME_FEAT_RESP_PTPL_SHIFT:
 * @NVME_FEAT_RESP_PTPL_MASK:
 * @NVME_FEAT_RRL_NVMSETID_SHIFT:
 * @NVME_FEAT_RRL_NVMSETID_MASK:
 * @NVME_FEAT_PLM_NVMSETID_SHIFT:
 * @NVME_FEAT_PLM_NVMSETID_MASK:
 * @NVME_FEAT_CDP_CHPS:		Change Personality Settings (Set Features
 *				Command Dword 13 only)
 * @NVME_FEAT_CDP_PERFS:	Personality Freeze State (Set Features
 *				Command Dword 13, and Get Features Completion
 *				Queue Entry Dword 0)
 * @NVME_FEAT_CDP_PERID_SHIFT:	Shift amount to set/get the Personality
 *				Identifier (Set Features Command Dword 13, and
 *				Get Features Completion Queue Entry Dword 0)
 * @NVME_FEAT_CDP_PERID_MASK:	Mask to set/get the Personality Identifier
 * @NVME_FEAT_CDP_PMDSS:	Personality Manufacturing Default Settings
 *				State (Get Features Completion Queue Entry
 *				Dword 0 only)
 * @NVME_FEAT_CDP_PPSC:		Pending Personality Settings Change (Get
 *				Features Completion Queue Entry Dword 0 only)
 * @NVME_FEAT_POWER_LIMIT_PLV_SHIFT:
 * @NVME_FEAT_POWER_LIMIT_PLV_MASK:
 * @NVME_FEAT_POWER_LIMIT_PLS_SHIFT:
 * @NVME_FEAT_POWER_LIMIT_PLS_MASK:
 * @NVME_FEAT_POWER_THRESH_PTV_SHIFT:
 * @NVME_FEAT_POWER_THRESH_PTV_MASK:
 * @NVME_FEAT_POWER_THRESH_PTS_SHIFT:
 * @NVME_FEAT_POWER_THRESH_PTS_MASK:
 * @NVME_FEAT_POWER_THRESH_PMTS_SHIFT:
 * @NVME_FEAT_POWER_THRESH_PMTS_MASK:
 * @NVME_FEAT_POWER_THRESH_EPT_SHIFT:
 * @NVME_FEAT_POWER_THRESH_EPT_MASK:
 * @NVME_FEAT_POWER_MEAS_ACT_SHIFT:
 * @NVME_FEAT_POWER_MEAS_ACT_MASK:
 * @NVME_FEAT_POWER_MEAS_PMTS_SHIFT:
 * @NVME_FEAT_POWER_MEAS_PMTS_MASK:
 * @NVME_FEAT_POWER_MEAS_SMT_SHIFT:
 * @NVME_FEAT_POWER_MEAS_SMT_MASK:
 * @NVME_FEAT_VOLTAGE_THRESHOLD_UVT_SHIFT:	Shift amount to set/get the
 *						Undervoltage Threshold (UVT)
 * @NVME_FEAT_VOLTAGE_THRESHOLD_UVT_MASK:	Mask to set/get UVT
 * @NVME_FEAT_VOLTAGE_THRESHOLD_OVT_SHIFT:	Shift amount to set/get the
 *						Overvoltage Threshold (OVT)
 * @NVME_FEAT_VOLTAGE_THRESHOLD_OVT_MASK:	Mask to set/get OVT
 * @NVME_FEAT_VOLTAGE_THRESHOLD_EVT:		Enable Voltage Threshold
 * @NVME_FEAT_VOLTAGE_THRESHOLD_VSENS_SHIFT:	Shift amount to set/get the
 *						Voltage Sensor Select (VSENS),
 *						see &enum nvme_voltage_sensor
 * @NVME_FEAT_VOLTAGE_THRESHOLD_VSENS_MASK:	Mask to set/get VSENS
 * @NVME_FEAT_VOLTAGE_MEASUREMENT_ACT_SHIFT:	Shift amount to set the
 *						Action (ACT), see &enum
 *						nvme_voltage_measurement_act
 * @NVME_FEAT_VOLTAGE_MEASUREMENT_ACT_MASK:	Mask to set ACT
 * @NVME_FEAT_AE_RLCCN_SHIFT:	Shift amount to get/set the Rate Limiting
 *				Configuration Change Notices (RLCCN)
 * @NVME_FEAT_AE_RLCCN_MASK:	Mask to get/set RLCCN
 * @NVME_FEAT_RATE_LIMITING_TID_SHIFT:	Shift amount to set/get the Target
 *					Identifier (TID)
 * @NVME_FEAT_RATE_LIMITING_TID_MASK:	Mask to set/get TID
 * @NVME_FEAT_RATE_LIMITING_TGT_SHIFT:	Shift amount to set/get the Target
 *					(TGT), see &enum nvme_rate_limiting_target
 * @NVME_FEAT_RATE_LIMITING_TGT_MASK:	Mask to set/get TGT
 **/
enum nvme_feat {
	NVME_FEAT_ARBITRATION_BURST_SHIFT	= 0,
	NVME_FEAT_ARBITRATION_BURST_MASK	= 0x7,
	NVME_FEAT_ARBITRATION_LPW_SHIFT		= 8,
	NVME_FEAT_ARBITRATION_LPW_MASK		= 0xff,
	NVME_FEAT_ARBITRATION_MPW_SHIFT		= 16,
	NVME_FEAT_ARBITRATION_MPW_MASK		= 0xff,
	NVME_FEAT_ARBITRATION_HPW_SHIFT		= 24,
	NVME_FEAT_ARBITRATION_HPW_MASK		= 0xff,
	NVME_FEAT_PWRMGMT_PS_SHIFT		= 0,
	NVME_FEAT_PWRMGMT_PS_MASK		= 0x1f,
	NVME_FEAT_PWRMGMT_WH_SHIFT		= 5,
	NVME_FEAT_PWRMGMT_WH_MASK		= 0x7,
	NVME_FEAT_PWRMGMT_IIELL_SHIFT		= 16,
	NVME_FEAT_PWRMGMT_IIELL_MASK		= 0xffff,
	NVME_FEAT_LBAR_NR_SHIFT			= 0,
	NVME_FEAT_LBAR_NR_MASK			= 0x3f,
	NVME_FEAT_TT_TMPTH_SHIFT		= 0,
	NVME_FEAT_TT_TMPTH_MASK			= 0xffff,
	NVME_FEAT_TT_TMPSEL_SHIFT		= 16,
	NVME_FEAT_TT_TMPSEL_MASK		= 0xf,
	NVME_FEAT_TT_THSEL_SHIFT		= 20,
	NVME_FEAT_TT_THSEL_MASK			= 0x3,
	NVME_FEAT_TT_TMPTHH_SHIFT		= 22,
	NVME_FEAT_TT_TMPTHH_MASK		= 0x7,
	NVME_FEAT_ERROR_RECOVERY_TLER_SHIFT	= 0,
	NVME_FEAT_ERROR_RECOVERY_TLER_MASK	= 0xffff,
	NVME_FEAT_ERROR_RECOVERY_DULBE_SHIFT	= 16,
	NVME_FEAT_ERROR_RECOVERY_DULBE_MASK	= 0x1,
	NVME_FEAT_VWC_WCE_SHIFT		= 0,
	NVME_FEAT_VWC_WCE_MASK		= 0x1,
	NVME_FEAT_NRQS_NSQR_SHIFT	= 0,
	NVME_FEAT_NRQS_NSQR_MASK	= 0xffff,
	NVME_FEAT_NRQS_NCQR_SHIFT	= 16,
	NVME_FEAT_NRQS_NCQR_MASK	= 0xffff,
	NVME_FEAT_IRQC_THR_SHIFT	= 0,
	NVME_FEAT_IRQC_THR_MASK	= 0xff,
	NVME_FEAT_IRQC_TIME_SHIFT	= 8,
	NVME_FEAT_IRQC_TIME_MASK	= 0xff,
	NVME_FEAT_ICFG_IV_SHIFT		= 0,
	NVME_FEAT_ICFG_IV_MASK		= 0xffff,
	NVME_FEAT_ICFG_CD_SHIFT		= 16,
	NVME_FEAT_ICFG_CD_MASK		= 0x1,
	NVME_FEAT_WA_DN_SHIFT		= 0,
	NVME_FEAT_WA_DN_MASK		= 0x1,
	NVME_FEAT_AE_SMART_SHIFT	= 0,
	NVME_FEAT_AE_SMART_MASK		= 0xff,
	NVME_FEAT_AE_NAN_SHIFT		= 8,
	NVME_FEAT_AE_NAN_MASK		= 0x1,
	NVME_FEAT_AE_FW_SHIFT		= 9,
	NVME_FEAT_AE_FW_MASK		= 0x1,
	NVME_FEAT_AE_TELEM_SHIFT	= 10,
	NVME_FEAT_AE_TELEM_MASK		= 0x1,
	NVME_FEAT_AE_ANA_SHIFT		= 11,
	NVME_FEAT_AE_ANA_MASK		= 0x1,
	NVME_FEAT_AE_PLA_SHIFT		= 12,
	NVME_FEAT_AE_PLA_MASK		= 0x1,
	NVME_FEAT_AE_LBAS_SHIFT		= 13,
	NVME_FEAT_AE_LBAS_MASK		= 0x1,
	NVME_FEAT_AE_EGA_SHIFT		= 14,
	NVME_FEAT_AE_EGA_MASK		= 0x1,
	NVME_FEAT_AE_NNSSHDN_SHIFT	= 15,
	NVME_FEAT_AE_NNSSHDN_MASK	= 0x1,
	NVME_FEAT_AE_TTHRY_SHIFT	= 16,
	NVME_FEAT_AE_TTHRY_MASK		= 0x1,
	NVME_FEAT_AE_RASSN_SHIFT	= 17,
	NVME_FEAT_AE_RASSN_MASK		= 0x1,
	NVME_FEAT_AE_RGRP0_SHIFT	= 18,
	NVME_FEAT_AE_RGRP0_MASK		= 0x1,
	NVME_FEAT_AE_ANSAN_SHIFT	= 19,
	NVME_FEAT_AE_ANSAN_MASK		= 0x1,
	NVME_FEAT_AE_ZDCN_SHIFT		= 27,
	NVME_FEAT_AE_ZDCN_MASK		= 0x1,
	NVME_FEAT_AE_PMDRLPCN_SHIFT	= 28,
	NVME_FEAT_AE_PMDRLPCN_MASK	= 0x1,
	NVME_FEAT_AE_ADLPCN_SHIFT	= 29,
	NVME_FEAT_AE_ADLPCN_MASK	= 0x1,
	NVME_FEAT_AE_HDLPCN_SHIFT	= 30,
	NVME_FEAT_AE_HDLPCN_MASK	= 0x1,
	NVME_FEAT_AE_DLPCN_SHIFT	= 31,
	NVME_FEAT_AE_DLPCN_MASK		= 0x1,
	NVME_FEAT_APST_APSTE_SHIFT	= 0,
	NVME_FEAT_APST_APSTE_MASK	= 0x1,
	NVME_FEAT_HMEM_EHM_SHIFT	= 0,
	NVME_FEAT_HMEM_EHM_MASK		= 0x1,
	NVME_FEAT_HCTM_TMT2_SHIFT	= 0,
	NVME_FEAT_HCTM_TMT2_MASK	= 0xffff,
	NVME_FEAT_HCTM_TMT1_SHIFT	= 16,
	NVME_FEAT_HCTM_TMT1_MASK	= 0xffff,
	NVME_FEAT_NOPS_NOPPME_SHIFT	= 0,
	NVME_FEAT_NOPS_NOPPME_MASK	= 0x1,
	NVME_FEAT_RRL_NVMSETID_SHIFT	= 0,
	NVME_FEAT_RRL_NVMSETID_MASK	= 0xffff,
	NVME_FEAT_RRL_RRL_SHIFT		= 0,
	NVME_FEAT_RRL_RRL_MASK		= 0xff,
	NVME_FEAT_PLM_NVMSETID_SHIFT	= 0,
	NVME_FEAT_PLM_NVMSETID_MASK	= 0xffff,
	NVME_FEAT_PLM_LPE_SHIFT		= 0,
	NVME_FEAT_PLM_LPE_MASK		= 0x1,
	NVME_FEAT_PLMW_WS_SHIFT		= 0,
	NVME_FEAT_PLMW_WS_MASK		= 0x7,
	NVME_FEAT_LBAS_LSIRI_SHIFT	= 0,
	NVME_FEAT_LBAS_LSIRI_MASK	= 0xffff,
	NVME_FEAT_LBAS_LSIPI_SHIFT	= 16,
	NVME_FEAT_LBAS_LSIPI_MASK	= 0xffff,
	NVME_FEAT_SC_NODRM_SHIFT	= 0,
	NVME_FEAT_SC_NODRM_MASK		= 0x1,
	NVME_FEAT_EG_ENDGID_SHIFT	= 0,
	NVME_FEAT_EG_ENDGID_MASK	= 0xffff,
	NVME_FEAT_EG_EGCW_SHIFT		= 16,
	NVME_FEAT_EG_EGCW_MASK		= 0xff,
	NVME_FEAT_FDPE_PHNDL_SHIFT	= 0,
	NVME_FEAT_FDPE_PHNDL_MASK	= 0xffff,
	NVME_FEAT_FDPE_NOET_SHIFT	= 16,
	NVME_FEAT_FDPE_NOET_MASK	= 0xff,
	NVME_FEAT_SPM_PBSLC_SHIFT	= 0,
	NVME_FEAT_SPM_PBSLC_MASK	= 0xff,
	NVME_FEAT_HOSTID_EXHID_SHIFT	= 0,
	NVME_FEAT_HOSTID_EXHID_MASK	= 0x1,
	NVME_FEAT_RM_REGPRE_SHIFT	= 1,
	NVME_FEAT_RM_REGPRE_MASK	= 0x1,
	NVME_FEAT_RM_RESREL_SHIFT	= 2,
	NVME_FEAT_RM_RESREL_MASK	= 0x1,
	NVME_FEAT_RM_RESPRE_SHIFT	= 0x3,
	NVME_FEAT_RM_RESPRE_MASK	= 0x1,
	NVME_FEAT_RP_PTPL_SHIFT		= 0,
	NVME_FEAT_RP_PTPL_MASK		= 0x1,
	NVME_FEAT_WP_WPS_SHIFT		= 0,
	NVME_FEAT_WP_WPS_MASK		= 0x7,
	NVME_FEAT_IOCSP_IOCSCI_SHIFT	= 0,
	NVME_FEAT_IOCSP_IOCSCI_MASK	= 0x1ff,
	NVME_FEAT_SPINUP_CONTROL_SHIFT	= 0,
	NVME_FEAT_SPINUP_CONTROL_MASK	= 0x1,
	NVME_FEAT_PLS_MODE_SHIFT	= 0,
	NVME_FEAT_PLS_MODE_MASK		= 0x3,
	NVME_FEAT_PERFC_ATTRI_SHIFT	= 0,
	NVME_FEAT_PERFC_ATTRI_MASK	= 0xff,
	NVME_FEAT_PERFC_RVSPA_SHIFT	= 8,
	NVME_FEAT_PERFC_RVSPA_MASK	= 0x1,
	NVME_FEAT_PERFC_ATTRTYP_SHIFT	= 0,
	NVME_FEAT_PERFC_ATTRTYP_MASK	= 0x3,
	NVME_FEAT_FDP_ENABLED_SHIFT	= 0,
	NVME_FEAT_FDP_ENABLED_MASK	= 0x1,
	NVME_FEAT_FDP_INDEX_SHIFT	= 8,
	NVME_FEAT_FDP_INDEX_MASK	= 0xff,
	NVME_FEAT_FDP_EVENTS_ENABLE_SHIFT = 0,
	NVME_FEAT_FDP_EVENTS_ENABLE_MASK  = 0x1,
	NVME_FEAT_HOST_ID_EXHID_SHIFT	= 0,
	NVME_FEAT_HOST_ID_EXHID_MASK	= 0x1,
	NVME_FEAT_BPWPC_BP0WPS_SHIFT	= 0,
	NVME_FEAT_BPWPC_BP0WPS_MASK	= 0x7,
	NVME_FEAT_BPWPC_BP1WPS_SHIFT	= 3,
	NVME_FEAT_BPWPC_BP1WPS_MASK	= 0x7,
	NVME_FEAT_SANITIZE_NODRM_SHIFT	= 0,
	NVME_FEAT_SANITIZE_NODRM_MASK	= 0x1,
	NVME_FEAT_RESP_PTPL_SHIFT	= 0,
	NVME_FEAT_RESP_PTPL_MASK	= 0x1,
	NVME_FEAT_CDP_CHPS		= 1 << 9,
	NVME_FEAT_CDP_PERFS		= 1 << 8,
	NVME_FEAT_CDP_PERID_SHIFT	= 0,
	NVME_FEAT_CDP_PERID_MASK	= 0xff,
	NVME_FEAT_CDP_PMDSS		= 1 << 10,
	NVME_FEAT_CDP_PPSC		= 1 << 9,
	NVME_FEAT_POWER_LIMIT_PLV_SHIFT	= 0,
	NVME_FEAT_POWER_LIMIT_PLV_MASK	= 0xffff,
	NVME_FEAT_POWER_LIMIT_PLS_SHIFT	= 16,
	NVME_FEAT_POWER_LIMIT_PLS_MASK	= 0x3,
	NVME_FEAT_POWER_THRESH_PTV_SHIFT = 0,
	NVME_FEAT_POWER_THRESH_PTV_MASK	= 0xffff,
	NVME_FEAT_POWER_THRESH_PTS_SHIFT = 16,
	NVME_FEAT_POWER_THRESH_PTS_MASK	= 0x3,
	NVME_FEAT_POWER_THRESH_PMTS_SHIFT = 20,
	NVME_FEAT_POWER_THRESH_PMTS_MASK = 0xf,
	NVME_FEAT_POWER_THRESH_EPT_SHIFT = 31,
	NVME_FEAT_POWER_THRESH_EPT_MASK	= 0x1,
	NVME_FEAT_POWER_MEAS_ACT_SHIFT	= 0,
	NVME_FEAT_POWER_MEAS_ACT_MASK	= 0xf,
	NVME_FEAT_POWER_MEAS_PMTS_SHIFT	= 4,
	NVME_FEAT_POWER_MEAS_PMTS_MASK	= 0xf,
	NVME_FEAT_POWER_MEAS_SMT_SHIFT	= 16,
	NVME_FEAT_POWER_MEAS_SMT_MASK	= 0xffff,
	NVME_FEAT_VOLTAGE_THRESHOLD_UVT_SHIFT	= 0,
	NVME_FEAT_VOLTAGE_THRESHOLD_UVT_MASK	= 0x3fff,
	NVME_FEAT_VOLTAGE_THRESHOLD_OVT_SHIFT	= 14,
	NVME_FEAT_VOLTAGE_THRESHOLD_OVT_MASK	= 0x3fff,
	NVME_FEAT_VOLTAGE_THRESHOLD_EVT		= 1 << 28,
	NVME_FEAT_VOLTAGE_THRESHOLD_VSENS_SHIFT	= 29,
	NVME_FEAT_VOLTAGE_THRESHOLD_VSENS_MASK	= 0x3,
	NVME_FEAT_VOLTAGE_MEASUREMENT_ACT_SHIFT	= 0,
	NVME_FEAT_VOLTAGE_MEASUREMENT_ACT_MASK	= 0xf,
	NVME_FEAT_AE_RLCCN_SHIFT		= 22,
	NVME_FEAT_AE_RLCCN_MASK			= 0x1,
	NVME_FEAT_RATE_LIMITING_TID_SHIFT	= 0,
	NVME_FEAT_RATE_LIMITING_TID_MASK	= 0xffff,
	NVME_FEAT_RATE_LIMITING_TGT_SHIFT	= 16,
	NVME_FEAT_RATE_LIMITING_TGT_MASK	= 0xff,
};

/**
 * enum nvme_get_features_sel - Get Features - Select
 * @NVME_GET_FEATURES_SEL_CURRENT:	Current value
 * @NVME_GET_FEATURES_SEL_DEFAULT:	Default value
 * @NVME_GET_FEATURES_SEL_SAVED:	Saved value
 * @NVME_GET_FEATURES_SEL_SUPPORTED:	Supported capabilities
 */
enum nvme_get_features_sel {
	NVME_GET_FEATURES_SEL_CURRENT				= 0,
	NVME_GET_FEATURES_SEL_DEFAULT				= 1,
	NVME_GET_FEATURES_SEL_SAVED				= 2,
	NVME_GET_FEATURES_SEL_SUPPORTED				= 3,
};

/**
 * enum nvme_get_features_supported_cqe_dw0 - Get Features Completion Queue
 *		Entry Dword 0 when the Select field is set to
 *		%NVME_GET_FEATURES_SEL_SUPPORTED
 * @NVME_GET_FEATURES_SUPPORTED_SVBL:  Saveable: the feature values are
 *				       saveable if set to '1'.
 * @NVME_GET_FEATURES_SUPPORTED_NSSPEC: NS Specific: the Feature Identifier
 *				       has a namespace scope if set to '1'.
 * @NVME_GET_FEATURES_SUPPORTED_CHANG: Changeable: the feature values are
 *				       changeable if set to '1'.
 */
enum nvme_get_features_supported_cqe_dw0 {
	NVME_GET_FEATURES_SUPPORTED_SVBL	= 1 << 0,
	NVME_GET_FEATURES_SUPPORTED_NSSPEC	= 1 << 1,
	NVME_GET_FEATURES_SUPPORTED_CHANG	= 1 << 2,
};

/**
 * enum nvme_cmd_format_mset - Format NVM - Metadata Settings
 * @NVME_FORMAT_MSET_SEPARATE:	indicates that the metadata is transferred
 *				as part of a separate buffer.
 * @NVME_FORMAT_MSET_EXTENDED:	indicates that the metadata is transferred
 *				as part of an extended data LBA.
 */
enum nvme_cmd_format_mset {
	NVME_FORMAT_MSET_SEPARATE				= 0,
	NVME_FORMAT_MSET_EXTENDED				= 1,
};

/**
 * enum nvme_cmd_format_pi - Format NVM - Protection Information
 * @NVME_FORMAT_PI_DISABLE: Protection information is not enabled.
 * @NVME_FORMAT_PI_TYPE1:   Protection information is enabled, Type 1.
 * @NVME_FORMAT_PI_TYPE2:   Protection information is enabled, Type 2.
 * @NVME_FORMAT_PI_TYPE3:   Protection information is enabled, Type 3.
 */
enum nvme_cmd_format_pi {
	NVME_FORMAT_PI_DISABLE					= 0,
	NVME_FORMAT_PI_TYPE1					= 1,
	NVME_FORMAT_PI_TYPE2					= 2,
	NVME_FORMAT_PI_TYPE3					= 3,
};

/**
 * enum nvme_cmd_format_pil - Format NVM - Protection Information Location
 * @NVME_FORMAT_PIL_LAST:  Protection information is transferred as the last
 *			   bytes of metadata.
 * @NVME_FORMAT_PIL_FIRST: Protection information is transferred as the first
 *			   bytes of metadata.
 */
enum nvme_cmd_format_pil {
	NVME_FORMAT_PIL_LAST					= 0,
	NVME_FORMAT_PIL_FIRST					= 1,
};

/**
 * enum nvme_cmd_format_ses - Format NVM - Secure Erase Settings
 * @NVME_FORMAT_SES_NONE:	     No secure erase operation requested.
 * @NVME_FORMAT_SES_USER_DATA_ERASE: User Data Erase: All user data shall be erased,
 *				     contents of the user data after the erase is
 *				     indeterminate (e.g. the user data may be zero
 *				     filled, one filled, etc.). If a User Data Erase
 *				     is requested and all affected user data is
 *				     encrypted, then the controller is allowed
 *				     to use a cryptographic erase to perform
 *				     the requested User Data Erase.
 * @NVME_FORMAT_SES_CRYPTO_ERASE:    Cryptographic Erase: All user data shall
 *				     be erased cryptographically. This is
 *				     accomplished by deleting the encryption key.
 */
enum nvme_cmd_format_ses {
	NVME_FORMAT_SES_NONE					= 0,
	NVME_FORMAT_SES_USER_DATA_ERASE				= 1,
	NVME_FORMAT_SES_CRYPTO_ERASE				= 2,
};

/**
 * enum nvme_ns_mgmt_sel - Namespace Management - Select
 * @NVME_NS_MGMT_SEL_CREATE:	Namespace Create selection
 * @NVME_NS_MGMT_SEL_DELETE:	Namespace Delete selection
 * @NVME_NS_MGMT_SEL_RESTORE_DEFAULT_CONFIG:	Restore Default Namespace
 *						Configuration selection
 */
enum nvme_ns_mgmt_sel {
	NVME_NS_MGMT_SEL_CREATE					= 0,
	NVME_NS_MGMT_SEL_DELETE					= 1,
	NVME_NS_MGMT_SEL_RESTORE_DEFAULT_CONFIG			= 2,
};

/**
 * enum nvme_ns_attach_sel - Namespace Attachment - Select
 * @NVME_NS_ATTACH_SEL_CTRL_ATTACH:	Namespace attach selection
 * @NVME_NS_ATTACH_SEL_CTRL_DEATTACH:	Namespace detach selection
 */
enum nvme_ns_attach_sel {
	NVME_NS_ATTACH_SEL_CTRL_ATTACH				= 0,
	NVME_NS_ATTACH_SEL_CTRL_DEATTACH			= 1,
};

/**
 * enum nvme_fw_commit_ca - Firmware Commit - Commit Action
 * @NVME_FW_COMMIT_CA_REPLACE:				Downloaded image replaces the existing
 *							image, if any, in the specified Firmware
 *							Slot. The newly placed image is not
 *							activated.
 * @NVME_FW_COMMIT_CA_REPLACE_AND_ACTIVATE:		Downloaded image replaces the existing
 *							image, if any, in the specified Firmware
 *							Slot. The newly placed image is activated
 *							at the next Controller Level Reset.
 * @NVME_FW_COMMIT_CA_SET_ACTIVE:			The existing image in the specified
 *							Firmware Slot is activated at the
 *							next Controller Level Reset.
 * @NVME_FW_COMMIT_CA_REPLACE_AND_ACTIVATE_IMMEDIATE:	Downloaded image replaces the existing
 *							image, if any, in the specified Firmware
 *							Slot and is then activated immediately.
 *							If there is not a newly downloaded image,
 *							then the existing image in the specified
 *							firmware slot is activated immediately.
 * @NVME_FW_COMMIT_CA_REPLACE_BOOT_PARTITION:		Downloaded image replaces the Boot
 *							Partition specified by the Boot
 *							Partition ID field.
 * @NVME_FW_COMMIT_CA_ACTIVATE_BOOT_PARTITION:		Mark the Boot Partition specified in
 *							the BPID field as active and update
 *							BPINFO.ABPID.
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
 * enum nvme_directive_dtype - Directive Types
 * @NVME_DIRECTIVE_DTYPE_IDENTIFY:	Identify directive type
 * @NVME_DIRECTIVE_DTYPE_STREAMS:	Streams directive type
 */
enum nvme_directive_dtype {
	NVME_DIRECTIVE_DTYPE_IDENTIFY				= 0,
	NVME_DIRECTIVE_DTYPE_STREAMS				= 1,
};

/**
 * enum nvme_directive_receive_doper - Directive Receive Directive Operation
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
 * enum nvme_directive_send_doper - Directive Send Directive Operation
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
 * enum nvme_directive_send_identify_endir - Enable Directive
 * @NVME_DIRECTIVE_SEND_IDENTIFY_ENDIR_DISABLE:
 * @NVME_DIRECTIVE_SEND_IDENTIFY_ENDIR_ENABLE:
 */
enum nvme_directive_send_identify_endir {
	NVME_DIRECTIVE_SEND_IDENTIFY_ENDIR_DISABLE		= 0,
	NVME_DIRECTIVE_SEND_IDENTIFY_ENDIR_ENABLE		= 1,
};

/**
 * enum nvme_sanitize_sanact - Sanitize Action
 * @NVME_SANITIZE_SANACT_EXIT_FAILURE:	     Exit Failure Mode.
 * @NVME_SANITIZE_SANACT_START_BLOCK_ERASE:  Start a Block Erase sanitize operation.
 * @NVME_SANITIZE_SANACT_START_OVERWRITE:    Start an Overwrite sanitize operation.
 * @NVME_SANITIZE_SANACT_START_CRYPTO_ERASE: Start a Crypto Erase sanitize operation.
 * @NVME_SANITIZE_SANACT_EXIT_MEDIA_VERIF:   Exit Media Verification State
 */
enum nvme_sanitize_sanact {
	NVME_SANITIZE_SANACT_EXIT_FAILURE			= 1,
	NVME_SANITIZE_SANACT_START_BLOCK_ERASE			= 2,
	NVME_SANITIZE_SANACT_START_OVERWRITE			= 3,
	NVME_SANITIZE_SANACT_START_CRYPTO_ERASE			= 4,
	NVME_SANITIZE_SANACT_EXIT_MEDIA_VERIF			= 5,
};

/**
 * enum nvme_dst_stc - Action taken by the Device Self-test command
 * @NVME_DST_STC_SHORT:	 Start a short device self-test operation
 * @NVME_DST_STC_LONG:	 Start an extended device self-test operation
 * @NVME_DST_STC_HOST_INIT:Start a Host-Initiated Refresh operation
 * @NVME_DST_STC_VS:	 Start a vendor specific device self-test operation
 * @NVME_DST_STC_ABORT:	 Abort device self-test operation
 */
enum nvme_dst_stc {
	NVME_DST_STC_SHORT					= 0x1,
	NVME_DST_STC_LONG					= 0x2,
	NVME_DST_STC_HOST_INIT					= 0x3,
	NVME_DST_STC_VS						= 0xe,
	NVME_DST_STC_ABORT					= 0xf,
};

/**
 * enum nvme_virt_mgmt_act - Virtualization Management - Action
 * @NVME_VIRT_MGMT_ACT_PRIM_CTRL_FLEX_ALLOC:	Primary Controller Flexible
 *						Allocation
 * @NVME_VIRT_MGMT_ACT_OFFLINE_SEC_CTRL:	Secondary Controller Offline
 * @NVME_VIRT_MGMT_ACT_ASSIGN_SEC_CTRL:		Secondary Controller Assign
 * @NVME_VIRT_MGMT_ACT_ONLINE_SEC_CTRL:		Secondary Controller Online
 */
enum nvme_virt_mgmt_act {
	NVME_VIRT_MGMT_ACT_PRIM_CTRL_FLEX_ALLOC			= 1,
	NVME_VIRT_MGMT_ACT_OFFLINE_SEC_CTRL			= 7,
	NVME_VIRT_MGMT_ACT_ASSIGN_SEC_CTRL			= 8,
	NVME_VIRT_MGMT_ACT_ONLINE_SEC_CTRL			= 9,
};

/**
 * enum nvme_capacity_mgmt_oper - Capacity Management - Operation (OPER)
 * @NVME_CAPACITY_MGMT_OPER_RESTORE_DEFAULT_CONFIG:	Restore Default
 *		Capacity Management Configuration: restores the default
 *		Endurance Groups and NVM Sets configuration in the NVM
 *		subsystem. The Element Identifier field should be set to
 *		0h and shall be ignored by the controller.
 */
enum nvme_capacity_mgmt_oper {
	NVME_CAPACITY_MGMT_OPER_RESTORE_DEFAULT_CONFIG		= 0x5,
};

/**
 * enum nvme_virt_mgmt_rt - Virtualization Management - Resource Type
 * @NVME_VIRT_MGMT_RT_VQ_RESOURCE:	VQ Resources
 * @NVME_VIRT_MGMT_RT_VI_RESOURCE:	VI Resources
 */
enum nvme_virt_mgmt_rt {
	NVME_VIRT_MGMT_RT_VQ_RESOURCE				= 0,
	NVME_VIRT_MGMT_RT_VI_RESOURCE				= 1,
};

/**
 * enum nvme_ns_write_protect_cfg - Write Protection - Write Protection State
 * @NVME_NS_WP_CFG_NONE:		No Write Protect
 * @NVME_NS_WP_CFG_PROTECT:		Write Protect
 * @NVME_NS_WP_CFG_PROTECT_POWER_CYCLE:	Write Protect Until Power Cycle
 * @NVME_NS_WP_CFG_PROTECT_PERMANENT:	Permanent Write Protect
 */
enum nvme_ns_write_protect_cfg {
	NVME_NS_WP_CFG_NONE					= 0,
	NVME_NS_WP_CFG_PROTECT					= 1,
	NVME_NS_WP_CFG_PROTECT_POWER_CYCLE			= 2,
	NVME_NS_WP_CFG_PROTECT_PERMANENT			= 3,
};

/**
 * enum nvme_log_ana_lsp - Asymmetric Namespace Access - Return Groups Only
 * @NVME_LOG_ANA_LSP_RGO_NAMESPACES:
 * @NVME_LOG_ANA_LSP_RGO_GROUPS_ONLY:
 */
enum nvme_log_ana_lsp {
	NVME_LOG_ANA_LSP_RGO_NAMESPACES				= 0,
	NVME_LOG_ANA_LSP_RGO_GROUPS_ONLY			= 1,
};

/**
 * enum nvme_log_phy_rx_eom_action - Physical Interface Receiver Eye Opening Measurement Action
 * @NVME_LOG_PHY_RX_EOM_READ:		Read Log Data
 * @NVME_LOG_PHY_RX_EOM_START_READ:	Start Measurement and Read Log Data
 * @NVME_LOG_PHY_RX_EOM_ABORT_CLEAR:	Abort Measurement and Clear Log Data
 */
enum nvme_log_phy_rx_eom_action {
	NVME_LOG_PHY_RX_EOM_READ				= 0,
	NVME_LOG_PHY_RX_EOM_START_READ				= 1,
	NVME_LOG_PHY_RX_EOM_ABORT_CLEAR				= 2,
};

/**
 * enum nvme_log_phy_rx_eom_quality - Physical Interface Receiver Eye Opening Measurement Quality
 * @NVME_LOG_PHY_RX_EOM_GOOD:		<= Better Quality
 * @NVME_LOG_PHY_RX_EOM_BETTER:		<= Best Quality, >= Good Quality
 * @NVME_LOG_PHY_RX_EOM_BEST:		>= Better Quality
 */
enum nvme_log_phy_rx_eom_quality {
	NVME_LOG_PHY_RX_EOM_GOOD				= 0,
	NVME_LOG_PHY_RX_EOM_BETTER				= 1,
	NVME_LOG_PHY_RX_EOM_BEST				= 2,
};

/**
 * enum nvme_pevent_log_action - Persistent Event Log - Action
 * @NVME_PEVENT_LOG_READ:		Read Log Data
 * @NVME_PEVENT_LOG_EST_CTX_AND_READ:	Establish Context and Read Log Data
 * @NVME_PEVENT_LOG_RELEASE_CTX:	Release Context
 */
enum nvme_pevent_log_action {
	NVME_PEVENT_LOG_READ			= 0x0,
	NVME_PEVENT_LOG_EST_CTX_AND_READ	= 0x1,
	NVME_PEVENT_LOG_RELEASE_CTX		= 0x2,
};

/**
 * enum nvme_feat_tmpthresh_thsel - Temperature Threshold - Threshold Type Select
 * @NVME_FEATURE_TEMPTHRESH_THSEL_OVER:		Over temperature threshold select
 * @NVME_FEATURE_TEMPTHRESH_THSEL_UNDER:	Under temperature threshold select
 */
enum nvme_feat_tmpthresh_thsel {
	NVME_FEATURE_TEMPTHRESH_THSEL_OVER			= 0,
	NVME_FEATURE_TEMPTHRESH_THSEL_UNDER			= 1,
};

/**
 * enum nvme_features_async_event_config_flags - Asynchronous Event Configuration configuration flags
 * @NVME_FEATURE_AENCFG_SMART_CRIT_SPARE:
 * @NVME_FEATURE_AENCFG_SMART_CRIT_TEMPERATURE:
 * @NVME_FEATURE_AENCFG_SMART_CRIT_DEGRADED:
 * @NVME_FEATURE_AENCFG_SMART_CRIT_READ_ONLY:
 * @NVME_FEATURE_AENCFG_SMART_CRIT_VOLATILE_BACKUP:
 * @NVME_FEATURE_AENCFG_SMART_CRIT_READ_ONLY_PMR:
 * @NVME_FEATURE_AENCFG_NOTICE_NAMESPACE_ATTRIBUTES:
 * @NVME_FEATURE_AENCFG_NOTICE_FIRMWARE_ACTIVATION:
 * @NVME_FEATURE_AENCFG_NOTICE_TELEMETRY_LOG:
 * @NVME_FEATURE_AENCFG_NOTICE_ANA_CHANGE:
 * @NVME_FEATURE_AENCFG_NOTICE_PL_EVENT:
 * @NVME_FEATURE_AENCFG_NOTICE_LBA_STATUS:
 * @NVME_FEATURE_AENCFG_NOTICE_EG_EVENT:
 * @NVME_FEATURE_AENCFG_NOTICE_DISCOVERY_CHANGE:
 */
enum nvme_features_async_event_config_flags {
	NVME_FEATURE_AENCFG_SMART_CRIT_SPARE			= NVME_SMART_CRIT_SPARE,
	NVME_FEATURE_AENCFG_SMART_CRIT_TEMPERATURE		= NVME_SMART_CRIT_TEMPERATURE,
	NVME_FEATURE_AENCFG_SMART_CRIT_DEGRADED			= NVME_SMART_CRIT_DEGRADED,
	NVME_FEATURE_AENCFG_SMART_CRIT_READ_ONLY		= NVME_SMART_CRIT_MEDIA,
	NVME_FEATURE_AENCFG_SMART_CRIT_VOLATILE_BACKUP		= NVME_SMART_CRIT_VOLATILE_MEMORY,
	NVME_FEATURE_AENCFG_SMART_CRIT_READ_ONLY_PMR		= NVME_SMART_CRIT_PMR_RO,
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
 * enum nvme_feat_plm_window_select - Predictable Latency Per NVM Set Log
 * @NVME_FEATURE_PLM_DTWIN:	Deterministic Window select
 * @NVME_FEATURE_PLM_NDWIN:	Non-Deterministic Window select
 */
enum nvme_feat_plm_window_select {
	NVME_FEATURE_PLM_DTWIN					= 1,
	NVME_FEATURE_PLM_NDWIN					= 2,
};

/**
 * enum nvme_feat_nswpcfg_state - Write Protection - Write Protection State
 * @NVME_FEAT_NS_NO_WRITE_PROTECT:		No Write Protect
 * @NVME_FEAT_NS_WRITE_PROTECT:			Write Protect
 * @NVME_FEAT_NS_WRITE_PROTECT_PWR_CYCLE:	Write Protect Until Power Cycle
 * @NVME_FEAT_NS_WRITE_PROTECT_PERMANENT:	Permanent Write Protect
 */
enum nvme_feat_nswpcfg_state {
	NVME_FEAT_NS_NO_WRITE_PROTECT		= 0,
	NVME_FEAT_NS_WRITE_PROTECT		= 1,
	NVME_FEAT_NS_WRITE_PROTECT_PWR_CYCLE	= 2,
	NVME_FEAT_NS_WRITE_PROTECT_PERMANENT	= 3,
};

/**
 * enum nvme_feat_perfc_attri - performance characteristics attribute index
 * @NVME_FEAT_PERFC_ATTRI_STD:		standard performance attribute
 * @NVME_FEAT_PERFC_ATTRI_ID_LIST:	performance attribute identifier list
 * @NVME_FEAT_PERFC_ATTRI_VS_MIN:	vendor specific performance attribute minimum index
 * @NVME_FEAT_PERFC_ATTRI_VS_MAX:	vendor specific performance attribute maximum index
 */
enum nvme_feat_perfc_attri {
	NVME_FEAT_PERFC_ATTRI_STD	= 0,
	NVME_FEAT_PERFC_ATTRI_ID_LIST	= 0xc0,
	NVME_FEAT_PERFC_ATTRI_VS_MIN	= 0xc1,
	NVME_FEAT_PERFC_ATTRI_VS_MAX	= 0xff,
};

/**
 * enum nvme_feat_perfc_r4karl - standard performance attribute random 4 kib average latency
 * @NVME_FEAT_PERFC_R4KARL_NO_REPORT:	not reported
 * @NVME_FEAT_PERFC_R4KARL_GE_100_SEC:	greater than or equal to 100 secs
 * @NVME_FEAT_PERFC_R4KARL_GE_50_SEC:	greater than or equal to 50 secs and less than 100 secs
 * @NVME_FEAT_PERFC_R4KARL_GE_10_SEC:	greater than or equal to 10 secs and less than 50 secs
 * @NVME_FEAT_PERFC_R4KARL_GE_5_SEC:	greater than or equal to 5 secs and less than 10 secs
 * @NVME_FEAT_PERFC_R4KARL_GE_1_SEC:	greater than or equal to 1 sec and less than 5 secs
 * @NVME_FEAT_PERFC_R4KARL_GE_500_MS:	greater than or equal to 500 msecs and less than 1 sec
 * @NVME_FEAT_PERFC_R4KARL_GE_100_MS:	greater than or equal to 100 msecs and less than 500 msecs
 * @NVME_FEAT_PERFC_R4KARL_GE_50_MS:	greater than or equal to 50 msecs and less than 100 msecs
 * @NVME_FEAT_PERFC_R4KARL_GE_10_MS:	greater than or equal to 10 msecs and less than 50 msecs
 * @NVME_FEAT_PERFC_R4KARL_GE_5_MS:	greater than or equal to 5 msecs and less than 10 msecs
 * @NVME_FEAT_PERFC_R4KARL_GE_1_MS:	greater than or equal to 1 msec and less than 5 msecs
 * @NVME_FEAT_PERFC_R4KARL_GE_500_US:	greater than or equal to 500 usecs and less than 1 msec
 * @NVME_FEAT_PERFC_R4KARL_GE_100_US:	greater than or equal to 100 usecs and less than 500 usecs
 * @NVME_FEAT_PERFC_R4KARL_GE_50_US:	greater than or equal to 50 usecs and less than 100 usecs
 * @NVME_FEAT_PERFC_R4KARL_GE_10_US:	greater than or equal to 10 usecs and less than 50 usecs
 * @NVME_FEAT_PERFC_R4KARL_GE_5_US:	greater than or equal to 5 usecs and less than 10 usecs
 * @NVME_FEAT_PERFC_R4KARL_GE_1_US:	greater than or equal to 1 usec and less than 5 usecs
 * @NVME_FEAT_PERFC_R4KARL_GE_500_NS:	greater than or equal to 500 nsecs and less than 1 usec
 * @NVME_FEAT_PERFC_R4KARL_GE_100_NS:	greater than or equal to 100 nsecs and less than 500 nsecs
 * @NVME_FEAT_PERFC_R4KARL_GE_50_NS:	greater than or equal to 50 nsecs and less than 100 nsecs
 * @NVME_FEAT_PERFC_R4KARL_GE_10_NS:	greater than or equal to 10 nsecs and less than 50 nsecs
 * @NVME_FEAT_PERFC_R4KARL_GE_5_NS:	greater than or equal to 5 nsecs and less than 10 nsecs
 * @NVME_FEAT_PERFC_R4KARL_GE_1_NS:	greater than or equal to 1 nsec and less than 5 nsecs
 */
enum nvme_feat_perfc_r4karl {
	NVME_FEAT_PERFC_R4KARL_NO_REPORT	= 0x0,
	NVME_FEAT_PERFC_R4KARL_GE_100_SEC	= 0x1,
	NVME_FEAT_PERFC_R4KARL_GE_50_SEC	= 0x2,
	NVME_FEAT_PERFC_R4KARL_GE_10_SEC	= 0x3,
	NVME_FEAT_PERFC_R4KARL_GE_5_SEC		= 0x4,
	NVME_FEAT_PERFC_R4KARL_GE_1_SEC		= 0x5,
	NVME_FEAT_PERFC_R4KARL_GE_500_MS	= 0x6,
	NVME_FEAT_PERFC_R4KARL_GE_100_MS	= 0x7,
	NVME_FEAT_PERFC_R4KARL_GE_50_MS		= 0x8,
	NVME_FEAT_PERFC_R4KARL_GE_10_MS		= 0x9,
	NVME_FEAT_PERFC_R4KARL_GE_5_MS		= 0xa,
	NVME_FEAT_PERFC_R4KARL_GE_1_MS		= 0xb,
	NVME_FEAT_PERFC_R4KARL_GE_500_US	= 0xc,
	NVME_FEAT_PERFC_R4KARL_GE_100_US	= 0xd,
	NVME_FEAT_PERFC_R4KARL_GE_50_US		= 0xe,
	NVME_FEAT_PERFC_R4KARL_GE_10_US		= 0xf,
	NVME_FEAT_PERFC_R4KARL_GE_5_US		= 0x10,
	NVME_FEAT_PERFC_R4KARL_GE_1_US		= 0x11,
	NVME_FEAT_PERFC_R4KARL_GE_500_NS	= 0x12,
	NVME_FEAT_PERFC_R4KARL_GE_100_NS	= 0x13,
	NVME_FEAT_PERFC_R4KARL_GE_50_NS		= 0x14,
	NVME_FEAT_PERFC_R4KARL_GE_10_NS		= 0x15,
	NVME_FEAT_PERFC_R4KARL_GE_5_NS		= 0x16,
	NVME_FEAT_PERFC_R4KARL_GE_1_NS		= 0x17,
};

/**
 * enum nvme_feat_bpwp_state - Boot Partition Write Protection State
 * @NVME_FEAT_BPWPS_CHANGE_NOT_REQUESTED:	Change in state not requested
 * @NVME_FEAT_BPWPS_WRITE_UNLOCKED:		Write Unlocked
 * @NVME_FEAT_BPWPS_WRITE_LOCKED:		Write Locked
 * @NVME_FEAT_BPWPS_WRITE_LOCKED_PWR_CYCLE:	Write Locked Until Power Cycle
 * @NVME_FEAT_BPWPS_WRITE_PROTECTION_RPMB:	Write Protection controlled by RPMB
 */
enum nvme_feat_bpwp_state {
	NVME_FEAT_BPWPS_CHANGE_NOT_REQUESTED	= 0,
	NVME_FEAT_BPWPS_WRITE_UNLOCKED		= 1,
	NVME_FEAT_BPWPS_WRITE_LOCKED		= 2,
	NVME_FEAT_BPWPS_WRITE_LOCKED_PWR_CYCLE	= 3,
	NVME_FEAT_BPWPS_WRITE_PROTECTION_RPMB	= 4,
};

/**
 * enum nvme_fctype - Fabrics Command Types
 * @nvme_fabrics_type_property_set:	Property set
 * @nvme_fabrics_type_connect:		Connect
 * @nvme_fabrics_type_property_get:	Property Get
 * @nvme_fabrics_type_auth_send:	Authentication Send
 * @nvme_fabrics_type_auth_receive:	Authentication Receive
 * @nvme_fabrics_type_disconnect:	Disconnect
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
 * enum nvme_data_tfr - Data transfer direction of the command
 * @NVME_DATA_TFR_NO_DATA_TFR:		No data transfer
 * @NVME_DATA_TFR_HOST_TO_CTRL:		Host to controller
 * @NVME_DATA_TFR_CTRL_TO_HOST:		Controller to host
 * @NVME_DATA_TFR_BIDIRECTIONAL:	Bidirectional
 */
enum nvme_data_tfr {
	NVME_DATA_TFR_NO_DATA_TFR	= 0x0,
	NVME_DATA_TFR_HOST_TO_CTRL	= 0x1,
	NVME_DATA_TFR_CTRL_TO_HOST	= 0x2,
	NVME_DATA_TFR_BIDIRECTIONAL	= 0x3,
};

/**
 * enum nvme_io_opcode - Opcodes for I/O Commands
 * @nvme_cmd_flush:		Flush
 * @nvme_cmd_write:		Write
 * @nvme_cmd_read:		Read
 * @nvme_cmd_write_uncor:	Write Uncorrectable
 * @nvme_cmd_compare:		Compare
 * @nvme_cmd_write_zeroes:	write Zeros
 * @nvme_cmd_dsm:		Dataset Management
 * @nvme_cmd_verify:		Verify
 * @nvme_cmd_resv_register:	Reservation Register
 * @nvme_cmd_resv_report:	Reservation Report
 * @nvme_cmd_resv_acquire:	Reservation Acquire
 * @nvme_cmd_io_mgmt_recv:	I/O Management Receive
 * @nvme_cmd_resv_release:	Reservation Release
 * @nvme_cmd_cancel:		Cancel
 * @nvme_cmd_copy:		Copy
 * @nvme_cmd_io_mgmt_send:	I/O Management Send
 * @nvme_zns_cmd_mgmt_send:	Zone Management Send
 * @nvme_zns_cmd_mgmt_recv:	Zone Management Receive
 * @nvme_zns_cmd_append:	Zone Append
 * @nvme_cmd_fabric:		Fabric Commands
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
	nvme_cmd_io_mgmt_recv	= 0x12,
	nvme_cmd_resv_release	= 0x15,
	nvme_cmd_cancel		= 0x18,
	nvme_cmd_copy		= 0x19,
	nvme_cmd_io_mgmt_send	= 0x1d,
	nvme_zns_cmd_mgmt_send	= 0x79,
	nvme_zns_cmd_mgmt_recv	= 0x7a,
	nvme_zns_cmd_append	= 0x7d,
	nvme_cmd_fabric		= 0x7f,
};

/**
 * enum nvme_kv_opcode - Opcodes for KV Commands
 * @nvme_kv_cmd_flush:				Flush
 * @nvme_kv_cmd_store:				Store
 * @nvme_kv_cmd_retrieve:			Retrieve
 * @nvme_kv_cmd_list:				List
 * @nvme_kv_cmd_resv_register:			Reservation Register
 * @nvme_kv_cmd_resv_report:			Reservation Report
 * @nvme_kv_cmd_delete:				Delete
 * @nvme_kv_cmd_resv_acquire:			Reservation Acquire
 * @nvme_kv_cmd_exist:				Exist
 * @nvme_kv_cmd_resv_release:			Reservation Release
 */
enum nvme_kv_opcode {
	nvme_kv_cmd_flush			= 0x00,
	nvme_kv_cmd_store			= 0x01,
	nvme_kv_cmd_retrieve			= 0x02,
	nvme_kv_cmd_list			= 0x06,
	nvme_kv_cmd_resv_register		= 0x0d,
	nvme_kv_cmd_resv_report			= 0x0e,
	nvme_kv_cmd_delete			= 0x10,
	nvme_kv_cmd_resv_acquire		= 0x11,
	nvme_kv_cmd_exist			= 0x14,
	nvme_kv_cmd_resv_release		= 0x15,
};

#ifndef SWIG
/**
 * struct nvme_ns_mgmt_host_sw_specified - Namespace management Host Software
 * Specified Fields.
 * @nsze:     Namespace Size indicates the total size of the namespace in
 *	      logical blocks. The number of logical blocks is based on the
 *	      formatted LBA size.
 * @ncap:     Namespace Capacity indicates the maximum number of logical blocks
 *	      that may be allocated in the namespace at any point in time. The
 *	      number of logical blocks is based on the formatted LBA size.
 * @rsvd16:   Reserved
 * @flbas:    Formatted LBA Size, see &enum nvme_id_ns_flbas.
 * @rsvd27:   Reserved
 * @dps:      End-to-end Data Protection Type Settings, see
 *	      &enum nvme_id_ns_dps.
 * @nmic:     Namespace Multi-path I/O and Namespace Sharing Capabilities, see
 *	      &enum nvme_id_ns_nmic.
 * @rsvd31:   Reserved
 * @anagrpid: ANA Group Identifier indicates the ANA Group Identifier of the
 *	      ANA group of which the namespace is a member.
 * @rsvd96:   Reserved
 * @nvmsetid: NVM Set Identifier indicates the NVM Set with which this
 *	      namespace is associated.
 * @endgid:   Endurance Group Identifier indicates the Endurance Group with
 *	      which this namespace is associated.
 * @rsvd104:  Reserved
 * @lbstm:    Logical Block Storage Tag Mask Identifies the mask for the
 *        Storage Tag field for the protection information
 * @nphndls:  Number of Placement Handles specifies the number of Placement
 *        Handles included in the Placement Handle List
 * @rsvd394:  Reserved
 * @rsvd499:  Reserved for I/O Command Sets that extend this specification.
 * @zns:      rsvd499( Zoned Namespace Command Set specific field )
 * @znsco:    Zoned Namespace Create Options
 *	      Bits 7-1: Reserved.
 *	      Bits 0: Allocate ZRWA Resources (AZR): If set to ‘1’, then the
 *	      namespace is to be created with the number of ZRWA resource specified
 *	      in the RNUMZRWA field of this data structure. If cleared to ‘0’, then
 *	      no ZRWA resources are allocated to the namespace to be created. If
 *	      the ZRWASUP bit is cleared to ‘0’, then this field shall be ignored
 *	      by the controller.
 * @rar:      Requested Active Resources specifies the number of active
 *	      resources to be allocated to the created namespace.
 * @ror:      Requested Open Resources specifies the number of open resources
 *	      to be allocated to the created namespace.
 * @rnumzrwa: Requested Number of ZRWA Resources specifies the number of ZRWA
 *	      resources to be allocated to the created namespace.
 *        see &struct nvme_ns_mgmt_host_sw_specified_zns.
 * @phndl:    Placement Handle Associated RUH : This field specifies the Reclaim
 *        Unit Handle Identifier to be associated with the Placement Handle
 *        value. If the Flexible Data Placement capability is not supported or
 *        not enabled in specified Endurance Group, then the controller shall
 *        ignore this field.
 * @rsvd768:   Reserved
 */
struct nvme_ns_mgmt_host_sw_specified {
	__le64			nsze;
	__le64			ncap;
	__u8			rsvd16[10];
	__u8			flbas;
	__u8			rsvd27[2];
	__u8			dps;
	__u8			nmic;
	__u8			rsvd31[61];
	__le32			anagrpid;
	__u8			rsvd96[4];
	__le16			nvmsetid;
	__le16			endgid;
	__u8			rsvd104[280];
	__le64			lbstm;
	__le16			nphndls;
	__u8			rsvd394[105];
	union {
		__u8		rsvd499[13];
		struct {
			__u8	znsco;
			__le32	rar;
			__le32	ror;
			__le32	rnumzrwa;
		} __attribute__((packed)) zns;
	};
	__le16			phndl[128];
	__u8			rsvd768[3328];
};
#endif /* SWIG */

/**
 * enum nvme_lm_cdq_fields - Controller Data Queue command fields
 *
 * @NVME_LM_CDQ_MOS_SHIFT:		Shift to set Management Operation Specific (MOS) field
 * @NVME_LM_CDQ_MOS_MASK:		Mask to set MOS field
 * @NVME_LM_CDQ_SEL_SHIFT:		Shift to set Select (SEL) field
 * @NVME_LM_CDQ_SEL_MASK:		Mask to set SEL field
 * @NVME_LM_SEL_CREATE_CDQ:		Create CDQ select option
 * @NVME_LM_SEL_DELETE_CDQ:		Delete CDQ select option
 * @NVME_LM_QT_SHIFT:			Shift amount to set Queue Type (QT) field relative to MOS
 * @NVME_LM_QT_MASK:			Mask to set QT field relative to MOS
 * @NVME_LM_QT_USER_DATA_MIGRATION_QUEUE: User Data Migration Queue type
 * @NVME_LM_CQS_SHIFT:			Shift amount for Create Queue Specific (CQS) field
 * @NVME_LM_CQS_MASK:			Mask to set CQS field
 * @NVME_LM_CREATE_CDQ_PC:		Physically Contiguous (PC)
 * @NVME_LM_CREATE_CDQ_PC_SHIFT:	Shift amount to set the PC field
 * @NVME_LM_CREATE_CDQ_PC_MASK:		Mask to set PC field
 * @NVME_LM_CREATE_CDQ_CNTLID_SHIFT:	Shift amount to set CNTLID field relative to MOS
 * @NVME_LM_CREATE_CDQ_CNTLID_MASK:	Mask to set CNTLID field relative to MOS
 * @NVME_LM_DELETE_CDQ_CDQID_SHIFT:	Shift amount to set CDQID field for deletion
 * @NVME_LM_DELETE_CDQ_CDQID_MASK:	Mask to set CDQID field for deletion
 * @NVME_LM_CREATE_CDQ_CDQID_SHIFT:	Shift amount to get CDQID field from Create response in
 *					completion dword0
 * @NVME_LM_CREATE_CDQ_CDQID_MASK:	Mask to get CNTLID field from Create response in
 *					completion dword0
 */
enum nvme_lm_cdq_fields {
	NVME_LM_CDQ_MOS_SHIFT			= 16,
	NVME_LM_CDQ_MOS_MASK			= 0xffff,
	NVME_LM_CDQ_SEL_SHIFT			= 0,
	NVME_LM_CDQ_SEL_MASK			= 0xff,
	NVME_LM_SEL_CREATE_CDQ			= 0,
	NVME_LM_SEL_DELETE_CDQ			= 1,

	/* Controller Data Queue - Create CDQ */
	NVME_LM_QT_SHIFT			= 0,
	NVME_LM_QT_MASK				= 0xff,
	NVME_LM_CQS_SHIFT			= 16,
	NVME_LM_CQS_MASK			= 0xffff,
	NVME_LM_QT_USER_DATA_MIGRATION_QUEUE	= 0,
	NVME_LM_CREATE_CDQ_PC			= 1,
	NVME_LM_CREATE_CDQ_PC_SHIFT		= 0,
	NVME_LM_CREATE_CDQ_PC_MASK		= 0x1,
	NVME_LM_CREATE_CDQ_CNTLID_SHIFT		= 0,
	NVME_LM_CREATE_CDQ_CNTLID_MASK		= 0xffff,

	/* Controller Data Queue - Delete CDQ */
	NVME_LM_DELETE_CDQ_CDQID_SHIFT		= 0,
	NVME_LM_DELETE_CDQ_CDQID_MASK		= 0xffff,

	/* Controller Data Queue - Create CDQ - Completion Queue Entry Dword 0 */
	NVME_LM_CREATE_CDQ_CDQID_SHIFT		= 0,
	NVME_LM_CREATE_CDQ_CDQID_MASK		= 0xffff,
};

#define NVME_LM_CDQ_MOS(fields)			NVME_GET(fields, LM_CDQ_MOS)
#define NVME_LM_CDQ_SEL(fields)		 	NVME_GET(fields, LM_CDQ_SEL)

#define NVME_LM_QT(fields)			NVME_GET(fields, LM_QT)
#define NVME_LM_CQS(fields)			NVME_GET(fields, LM_CQS)

#define NVME_LM_CREATE_CDQ_PC(fields)		NVME_GET(fields, LM_CREATE_CDQ_PC)
#define NVME_LM_CREATE_CDQ_CNTLID(fields)	NVME_GET(fields, LM_CREATE_CDQ_CNTLID)

#define NVME_LM_DELETE_CDQ_CDQID(fields)	NVME_GET(fields, LM_DELETE_CDQ_CDQID)
#define NVME_LM_CREATE_CDQ_CDQID(fields)	NVME_GET(fields, LM_CREATE_CDQ_CDQID)

/**
 * enum nvme_lm_track_send_fields - Track Send command fields
 *
 * @NVME_LM_TRACK_SEND_MOS_SHIFT:	Shift to set Management Operation Specific (MOS) field
 * @NVME_LM_TRACK_SEND_MOS_MASK:	Mask to set MOS field
 * @NVME_LM_TRACK_SEND_SEL_SHIFT:	Shift to set Select (SEL) field
 * @NVME_LM_TRACK_SEND_SEL_MASK:	Mask to set SEL field
 * @NVME_LM_SEL_LOG_USER_DATA_CHANGES:	Log User Data Changes select option
 * @NVME_LM_SEL_TRACK_MEMORY_CHANGES:	Track Memory Changes select option
 * @NVME_LM_LACT_SHIFT:			Shift to set Logging Action (LACT) relative to MOS
 * @NVME_LM_LACT_MASK:			Mask to set LACT relative to MOS
 * @NVME_LM_LACT_STOP_LOGGING:		The controller shall stop logging user data changes to
 *					namespaces attached to the controller associated with the
 *					User Data Migration Queue specified in the CDQ ID.
 * @NVME_LM_LACT_START_LOGGING:		The controller shall start logging user data changes to
 *					namespaces attached to the controller associated with the
 *					User Data Migration Queue into that User Data Migration
 *					Queue where those user data changes are caused by the
 *					controller associated with that User Data Migration Queue
 *					processing commands.
 */
enum nvme_lm_track_send_fields {
	NVME_LM_TRACK_SEND_MOS_SHIFT		= 16,
	NVME_LM_TRACK_SEND_MOS_MASK		= 0xffff,
	NVME_LM_TRACK_SEND_SEL_SHIFT		= 0,
	NVME_LM_TRACK_SEND_SEL_MASK		= 0xff,
	NVME_LM_SEL_LOG_USER_DATA_CHANGES	= 0,
	NVME_LM_SEL_TRACK_MEMORY_CHANGES	= 1,

	/* Track Send - Log User Data Changes */
	NVME_LM_LACT_SHIFT			= 0,
	NVME_LM_LACT_MASK			= 0xf,
	NVME_LM_LACT_STOP_LOGGING		= 0,
	NVME_LM_LACT_START_LOGGING		= 1,
};

#define NVME_LM_TRACK_SEND_MOS(fields)	NVME_GET(fields, LM_TRACK_SEND_MOS)
#define NVME_LM_TRACK_SEND_SEL(fields)	NVME_GET(fields, LM_TRACK_SEND_SEL)

#define NVME_LM_LACT(fields)		NVME_GET(fields, LM_LACT)

/**
 * enum nvme_lm_tact - Track Send - Track Memory Changes - Management
 *		       Operation Specific field - Tracking Action (TACT)
 * @NVME_LM_TACT_STOP_TRACKING:  Stop tracking host memory changes
 * @NVME_LM_TACT_START_TRACKING: Start tracking host memory changes; the
 *		       data buffer contains a Track Memory Changes data
 *		       structure, see &struct nvme_lm_track_memory_changes_data
 */
enum nvme_lm_tact {
	NVME_LM_TACT_STOP_TRACKING	= 0,
	NVME_LM_TACT_START_TRACKING	= 1,
};

/**
 * enum nvme_lm_track_memory_changes_cqe - Track Send - Track Memory Changes -
 *		       Completion Queue Entry Dword 0
 * @NVME_LM_TRACK_MEMORY_CHANGES_CQE_MRTG_SHIFT: Shift amount to get Memory
 *		       Range Tracking Granularity (MRTG)
 * @NVME_LM_TRACK_MEMORY_CHANGES_CQE_MRTG_MASK:  Mask to get MRTG
 */
enum nvme_lm_track_memory_changes_cqe {
	NVME_LM_TRACK_MEMORY_CHANGES_CQE_MRTG_SHIFT	= 0,
	NVME_LM_TRACK_MEMORY_CHANGES_CQE_MRTG_MASK	= 0xffff,
};

#define NVME_LM_TRACK_MEMORY_CHANGES_CQE_MRTG(dw0) \
	NVME_GET(dw0, LM_TRACK_MEMORY_CHANGES_CQE_MRTG)

/**
 * struct nvme_lm_memory_range_tracking_descriptor - Memory Range Tracking
 *		       Descriptor
 * @saddr:	Address (SADDR): starting host memory address of the range,
 *		aligned to the granularity specified by @rmrtg in &struct
 *		nvme_lm_track_memory_changes_data
 * @len:	Length (LEN), in units of the tracking granularity specified
 *		by @rmrtg
 */
struct nvme_lm_memory_range_tracking_descriptor {
	__le64	saddr;
	__le32	len;
} __attribute__((packed));

/**
 * struct nvme_lm_track_memory_changes_data - Track Memory Changes Data
 *		       Structure, supplied by the host in the data buffer of a
 *		       Track Send command's Track Memory Changes management
 *		       operation when starting tracking (TACT set to
 *		       %NVME_LM_TACT_START_TRACKING)
 * @ver:	Version (VER), shall be cleared to 0h
 * @rsvd1:	Reserved
 * @rmrtg:	Requested Memory Range Tracking Granularity (RMRTG)
 * @rnmrtd:	Number of Memory Range Tracking Descriptors (RNMRTD), a 1's
 *		based value
 * @desc:	Memory Range Tracking Descriptor list, see &struct
 *		nvme_lm_memory_range_tracking_descriptor
 */
struct nvme_lm_track_memory_changes_data {
	__u8	ver;
	__u8	rsvd1[2];
	__u8	rmrtg;
	__le32	rnmrtd;
	struct nvme_lm_memory_range_tracking_descriptor desc[];
};

/**
 * enum nvme_lm_track_receive_fields - Track Receive command fields
 *
 * @NVME_LM_TRACK_RECV_SEL_SHIFT:		Shift to set Select (SEL) field
 * @NVME_LM_TRACK_RECV_SEL_MASK:		Mask to set SEL field
 * @NVME_LM_SEL_TRACKED_MEMORY_CHANGES:	Tracked Memory Changes select option
 * @NVME_LM_TRACKED_MEMORY_CHANGES_CNTLID_SHIFT: Shift amount to set Controller
 *						Identifier (CNTLID)
 * @NVME_LM_TRACKED_MEMORY_CHANGES_CNTLID_MASK: Mask to set CNTLID
 */
enum nvme_lm_track_receive_fields {
	NVME_LM_TRACK_RECV_SEL_SHIFT			= 0,
	NVME_LM_TRACK_RECV_SEL_MASK			= 0xff,
	NVME_LM_SEL_TRACKED_MEMORY_CHANGES		= 0,

	NVME_LM_TRACKED_MEMORY_CHANGES_CNTLID_SHIFT	= 0,
	NVME_LM_TRACKED_MEMORY_CHANGES_CNTLID_MASK	= 0xffff,
};

#define NVME_LM_TRACK_RECV_SEL(fields)	NVME_GET(fields, LM_TRACK_RECV_SEL)

/**
 * enum nvme_lm_tracked_memory_change_attrb - Tracked Memory Change Data
 * Structure Attributes (ATTRB) field
 *
 * @NVME_LM_TMC_ATTRB_MTR_SHIFT:	Shift to get More To Report (MTR)
 * @NVME_LM_TMC_ATTRB_MTR_MASK:	Mask to get MTR
 * @NVME_LM_TMC_ATTRB_SUSP_SHIFT:	Shift to get Suspended (SUSP)
 * @NVME_LM_TMC_ATTRB_SUSP_MASK:	Mask to get SUSP
 */
enum nvme_lm_tracked_memory_change_attrb {
	NVME_LM_TMC_ATTRB_MTR_SHIFT	= 0,
	NVME_LM_TMC_ATTRB_MTR_MASK	= 0x1,
	NVME_LM_TMC_ATTRB_SUSP_SHIFT	= 1,
	NVME_LM_TMC_ATTRB_SUSP_MASK	= 0x1,
};

#define NVME_LM_TMC_ATTRB_MTR(attrb)	NVME_GET(attrb, LM_TMC_ATTRB_MTR)
#define NVME_LM_TMC_ATTRB_SUSP(attrb)	NVME_GET(attrb, LM_TMC_ATTRB_SUSP)

/**
 * struct nvme_lm_tracked_memory_changed_descriptor - Tracked Memory Changed
 * Descriptor
 *
 * @saddr:	Start Address (SADDR)
 * @len:	Length (LEN), in units of the tracking granularity indicated
 *		by @rpmpg in &struct nvme_lm_tracked_memory_change_data
 * @rsvd12:	Reserved
 */
struct nvme_lm_tracked_memory_changed_descriptor {
	__le64	saddr;
	__le32	len;
	__u8	rsvd12[4];
};

/**
 * struct nvme_lm_tracked_memory_change_data - Tracked Memory Change Data
 * Structure returned by the Track Receive command's Tracked Memory Changes
 * management operation
 *
 * @ver:	Version (VER)
 * @attrb:	Attributes (ATTRB), see &enum nvme_lm_tracked_memory_change_attrb
 * @cntlid:	Controller Identifier (CNTLID) whose memory modifications are
 *		being tracked and reported
 * @ntmcd:	Number of Tracked Memory Changed Descriptors (NTMCD)
 * @rpmpg:	Reported Memory Range Granularity (RPMPG)
 * @rsvd10:	Reserved
 * @desc:	Tracked Memory Changed Descriptor list
 */
struct nvme_lm_tracked_memory_change_data {
	__u8	ver;
	__u8	attrb;
	__le16	cntlid;
	__le32	ntmcd;
	__le16	rpmpg;
	__u8	rsvd10[6];
	struct nvme_lm_tracked_memory_changed_descriptor desc[];
};

/**
 * enum nvme_lm_migration_send_fields - Migration Send command fields
 *
 * @NVME_LM_MIGRATION_SEND_MOS_SHIFT:		Shift to set Management Operation Specific (MOS)
 *						field
 * @NVME_LM_MIGRATION_SEND_MOS_MASK:		Mask to set MOS field
 * @NVME_LM_MIGRATION_SEND_SEL_SHIFT:		Shift amount to set Select (SEL) field
 * @NVME_LM_MIGRATION_SEND_SEL_MASK:		Mask to set SEL field
 * @NVME_LM_SEL_SUSPEND:			Migration Send - Suspend
 * @NVME_LM_SEL_RESUME:				Migration Send - Resume
 * @NVME_LM_SEL_SET_CONTROLLER_STATE:		Migration Send - Set Controller State
 * @NVME_LM_MIGRATION_SEND_UIDX_SHIFT:		Shift to set UUID Index (UIDX)
 * @NVME_LM_MIGRATION_SEND_UIDX_MASK:		Mask to set UIDX
 * @NVME_LM_DUDMQ:				Delete User Data Migration Queue
 * @NVME_LM_STYPE_SHIFT:			Shift amount to set Suspend Type (STYPE)
 * @NVME_LM_STYPE_MASK:				Mask to set STYPE
 * @NVME_LM_STYPE_SUSPEND_NOTIFICATION:		Suspend Notification - The specified controller is
 *						going to be suspended in the future with a
 *						subsequent Migration Send command
 * @NVME_LM_STYPE_SUSPEND:			Suspend - Suspend the controller
 * @NVME_LM_SUSPEND_CNTLID_SHIFT:		Shift amount to set Controller ID (CNTLID) when SEL
 *						is Suspend
 * @NVME_LM_SUSPEND_CNTLID_MASK:		Mask to set CNTLID with SEL Suspend
 * @NVME_LM_RESUME_CNTLID_SHIFT:		Shift amount to set Controller ID (CNTLID) when SEL
 *						is Resume
 * @NVME_LM_RESUME_CNTLID_MASK:			Mask to set CNTLID when SEL is Resume
 * @NVME_LM_SEQIND_SHIFT:			Shift amount to set Sequence Indicator (SEQIND)
 *						field relative to MOS
 * @NVME_LM_SEQIND_MASK:			Mask to set SEQIND field relative to MOS
 * @NVME_LM_SEQIND_NOT_FIRST_NOT_LAST:		This command is not the first or last of a sequence
 *						of two or more Migration Send commands with this
 *						management operation used to transfer the controller
 *						state from host to controller
 * @NVME_LM_SEQIND_FIRST:			This command is the first of a sequence of two or
 *						more Migration Send commands
 * @NVME_LM_SEQIND_LAST:			This command is the last command of a sequence of
 *						two or more Migration Send commands
 * @NVME_LM_SEQIND_ENTIRE:			This Migration Send command is the only command and
 *						contains the entire controller state for this
 *						management operation
 * @NVME_LM_SET_CONTROLLER_STATE_CSUUIDI_SHIFT:	Shift amount to set Controller State UUID Index
 *						(CSUUIDI)
 * @NVME_LM_SET_CONTROLLER_STATE_CSUUIDI_MASK:	Mask to set CSUUIDI
 * @NVME_LM_SET_CONTROLLER_STATE_CSVI_SHIFT:	Shift amount to set Controller State Version Index
 *						(CSVI)
 * @NVME_LM_SET_CONTROLLER_STATE_CSVI_MASK:	Mask to set CSVI
 * @NVME_LM_SET_CONTROLLER_STATE_CNTLID_SHIFT:	Shift amount to set Controller ID (CNTLID) when SEL
 *						is Set Controller State
 * @NVME_LM_SET_CONTROLLER_STATE_CNTLID_MASK:	Mask to set CNTLID when SEL is Set Controller State
 */
enum nvme_lm_migration_send_fields {
	NVME_LM_MIGRATION_SEND_MOS_SHIFT		= 16,
	NVME_LM_MIGRATION_SEND_MOS_MASK			= 0xffff,
	NVME_LM_MIGRATION_SEND_SEL_SHIFT		= 0,
	NVME_LM_MIGRATION_SEND_SEL_MASK			= 0xff,
	NVME_LM_SEL_SUSPEND				= 0,
	NVME_LM_SEL_RESUME				= 1,
	NVME_LM_SEL_SET_CONTROLLER_STATE		= 2,
	NVME_LM_MIGRATION_SEND_UIDX_SHIFT		= 0,
	NVME_LM_MIGRATION_SEND_UIDX_MASK		= 0x7f,

	/* Migration Send - Suspend */
	NVME_LM_DUDMQ					= 1 << 31,
	NVME_LM_STYPE_SHIFT				= 16,
	NVME_LM_STYPE_MASK				= 0xff,
	NVME_LM_STYPE_SUSPEND_NOTIFICATION		= 0,
	NVME_LM_STYPE_SUSPEND				= 1,
	NVME_LM_SUSPEND_CNTLID_SHIFT			= 0,
	NVME_LM_SUSPEND_CNTLID_MASK			= 0Xffff,

	/* Migration Send - Resume */
	NVME_LM_RESUME_CNTLID_SHIFT			= 0,
	NVME_LM_RESUME_CNTLID_MASK			= 0xffff,

	/* Migration Send - Set Controller State */
	NVME_LM_SEQIND_SHIFT				= 0,
	NVME_LM_SEQIND_MASK				= 0x3,
	NVME_LM_SEQIND_NOT_FIRST_NOT_LAST		= 0,
	NVME_LM_SEQIND_FIRST				= 1,
	NVME_LM_SEQIND_LAST				= 2,
	NVME_LM_SEQIND_ENTIRE				= 3,
	NVME_LM_SET_CONTROLLER_STATE_CSUUIDI_SHIFT	= 24,
	NVME_LM_SET_CONTROLLER_STATE_CSUUIDI_MASK	= 0xff,
	NVME_LM_SET_CONTROLLER_STATE_CSVI_SHIFT		= 16,
	NVME_LM_SET_CONTROLLER_STATE_CSVI_MASK		= 0xff,
	NVME_LM_SET_CONTROLLER_STATE_CNTLID_SHIFT	= 0,
	NVME_LM_SET_CONTROLLER_STATE_CNTLID_MASK	= 0xffff,
};

#define NVME_LM_MIGRATION_SEND_MOS(fields)	NVME_GET(fields, LM_MIGRATION_SEND_MOS)
#define NVME_LM_MIGRATION_SEND_SEL(fields)	NVME_GET(fields, LM_MIGRATION_SEND_SEL)
#define NVME_LM_MIGRATION_SEND_UIDX(fields)	NVME_GET(fields, LM_MIGRATION_SEND_UIDX)

#define NVME_LM_STYPE(fields)			NVME_GET(fields, LM_STYPE)
#define NVME_LM_SUSPEND_CNTLID(fields)		NVME_GET(fields, LM_SUSPEND_CNTLID)

#define NVME_LM_RESUME_CNTLID(fields)		NVME_GET(fields, LM_RESUME_CNTLID)

#define NVME_LM_SEQIND(fields)			NVME_GET(fields, LM_SEQIND)

#define NVME_LM_SET_CONTROLLER_STATE_CSUUIDI(fields)	NVME_GET(fields, LM_SET_CONTROLLER_STATE_CSUUIDI)
#define NVME_LM_SET_CONTROLLER_STATE_CSVI(fields)	NVME_GET(fields, LM_SET_CONTROLLER_STATE_CSVI)
#define NVME_LM_SET_CONTROLLER_STATE_CNTLID(fields)	NVME_GET(fields, LM_SET_CONTROLLER_STATE_CNTLID)

/**
 * enum nvme_lm_migration_recv_fields - Migration Receive command fields
 *
 * @NVME_LM_MIGRATION_RECV_MOS_SHIFT:		Shift amount to set Management Specific Operation
 *						(MOS) field
 * @NVME_LM_MIGRATION_RECV_MOS_MASK:		Mask to set MOS field
 * @NVME_LM_MIGRATION_RECV_SEL_SHIFT:		Shift amount to set Select (SEL) field
 * @NVME_LM_MIGRATION_RECV_SEL_MASK:		Mask to set SEL field
 * @NVME_LM_SEL_GET_CONTROLLER_STATE:		Get Controller State select option
 * @NVME_LM_MIGRATION_RECV_UIDX_SHIFT:		Shift to set UUID Index (UIDX)
 * @NVME_LM_MIGRATION_RECV_UIDX_MASK:		Mask to set UIDX
 * @NVME_LM_GET_CONTROLLER_STATE_CSVI_SHIFT:	Shift amount to set Controller State Version Index
 *						(CSVI) relative to MOS
 * @NVME_LM_GET_CONTROLLER_STATE_CSVI_MASK:	Mask to set CSVI relative to MOS
 * @NVME_LM_GET_CONTROLLER_STATE_CSUIDXP_SHIFT:	Shift amount to set Controller State UUID Index
 *						Parameter (CSUIDXP)
 * @NVME_LM_GET_CONTROLLER_STATE_CSUIDXP_MASK:	Mask to set CSUIDXP
 * @NVME_LM_GET_CONTROLLER_STATE_CSUUIDI_SHIFT:	Shift amount to set Controller State UUID Index
 *						(CSUUIDI)
 * @NVME_LM_GET_CONTROLLER_STATE_CSUUIDI_MASK:	Mask to set CSUUIDI
 * @NVME_LM_GET_CONTROLLER_STATE_CNTLID_SHIFT:	Shift amount to set Controller ID (CNTLID)
 * @NVME_LM_GET_CONTROLLER_STATE_CNTLID_MASK:	Mask to set CNTLID
 * @NVME_LM_GET_CONTROLLER_STATE_CSUP:		Controller Suspended
 */
enum nvme_lm_migration_recv_fields {
	NVME_LM_MIGRATION_RECV_MOS_SHIFT		= 16,
	NVME_LM_MIGRATION_RECV_MOS_MASK			= 0xffff,
	NVME_LM_MIGRATION_RECV_SEL_SHIFT		= 0,
	NVME_LM_MIGRATION_RECV_SEL_MASK			= 0xff,
	NVME_LM_SEL_GET_CONTROLLER_STATE		= 0,
	NVME_LM_MIGRATION_RECV_UIDX_SHIFT		= 0,
	NVME_LM_MIGRATION_RECV_UIDX_MASK		= 0x7f,

	/* Migration Receive - Get Controller State */
	NVME_LM_GET_CONTROLLER_STATE_CSVI_SHIFT		= 0,
	NVME_LM_GET_CONTROLLER_STATE_CSVI_MASK		= 0xff,
	NVME_LM_GET_CONTROLLER_STATE_CSUIDXP_SHIFT	= 24,
	NVME_LM_GET_CONTROLLER_STATE_CSUIDXP_MASK	= 0xff,
	NVME_LM_GET_CONTROLLER_STATE_CSUUIDI_SHIFT	= 16,
	NVME_LM_GET_CONTROLLER_STATE_CSUUIDI_MASK	= 0xff,
	NVME_LM_GET_CONTROLLER_STATE_CNTLID_SHIFT	= 0,
	NVME_LM_GET_CONTROLLER_STATE_CNTLID_MASK	= 0xffff,

	/* Migration Receive - Get Controller State - Completion Queue Entry Dword 0 */
	NVME_LM_GET_CONTROLLER_STATE_CSUP		= 1 << 0,
};

#define NVME_LM_MIGRATION_RECV_MOS(fields)	NVME_GET(fields, LM_MIGRATION_RECV_MOS)
#define NVME_LM_MIGRATION_RECV_SEL(fields)	NVME_GET(fields, LM_MIGRATION_RECV_SEL)
#define NVME_LM_MIGRATION_RECV_UIDX(fields)	NVME_GET(fields, LM_MIGRATION_RECV_UIDX)

#define NVME_LM_GET_CONTROLLER_STATE_CSVI(fields)	NVME_GET(fields, LM_GET_CONTROLLER_STATE_CSVI)
#define NVME_LM_GET_CONTROLLER_STATE_CSUIDXP(fields)	NVME_GET(fields, LM_GET_CONTROLLER_STATE_CSUIDXP)
#define NVME_LM_GET_CONTROLLER_STATE_CSUUIDI(fields)	NVME_GET(fields, LM_GET_CONTROLLER_STATE_CSUUIDI)
#define NVME_LM_GET_CONTROLLER_STATE_CNTLID(fields)	NVME_GET(fields, LM_GET_CONTROLLER_STATE_CNTLID)

/**
 * struct nvme_lm_io_submission_queue_data - I/O Submission Queue data structure. Fields related to
 * the contents of Create I/O Submission Queue command that created an I/O Submission Queue.
 *
 * @iosqprp1:	I/O Submission PRP Entry 1 (IOSQPRP1)
 * @iosqqsize:	I/O Submission Queue Size (IOSQQSIZE)
 * @iosqqid:	I/O Submission Queue Identifier (IOSQQID)
 * @iosqcqid:	I/O Completion Queue Identifier (IOSQCQID)
 * @iosqa:	I/O Submission Queue Attributes (IOSQA)
 * @iosqhp:	I/O Submission Queue Head Pointer (IOSQHP)
 * @iosqtp:	I/O Submission Queue Tail Pointer (IOSQTP)
 * @rsvd20:	Reserved
 */
struct nvme_lm_io_submission_queue_data {
	__le64 iosqprp1;
	__le16 iosqqsize;
	__le16 iosqqid;
	__le16 iosqcqid;
	__le16 iosqa;
	__le16 iosqhp;
	__le16 iosqtp;
	__u8   rsvd20[4];
};

/**
 * struct nvme_lm_io_completion_queue_data - I/O Completion Queue data structure. Fields related to
 * the contents of Create I/O Completion Queue command that created an I/O Completion Queue.
 *
 * @iocqprp1:	I/O Completion Queue PRP Entry 1 (IOCQPRP1)
 * @iocqqsize:	I/O Completion Queue Size (IOCQQSIZE)
 * @iocqqid:	I/O Completion Queue Identifier (IOCQQID)
 * @iocqhp:	I/O Completion Queue Head Pointer (IOCQHP)
 * @iocqtp:	I/O Completion Queue Tail Pointer (IOCQTP)
 * @iocqa:	I/O Completion Queue Attributes (IOCQA)
 * @rsvd20:	Reserved
 */
struct nvme_lm_io_completion_queue_data {
	__le64 iocqprp1;
	__le16 iocqqsize;
	__le16 iocqqid;
	__le16 iocqhp;
	__le16 iocqtp;
	__le32 iocqa;
	__u8   rsvd20[4];
};

/**
 * struct nvme_lm_nvme_controller_state_data_header - Controller State data structure header
 *
 * @ver:   The version of this data structure.
 * @niosq: The number of I/O Submission Queues contained in this data structure.
 * @niocq: The number of I/O Completion Queues contained in this data structure.
 * @rsvd6: Reserved
 */
struct nvme_lm_nvme_controller_state_data_header {
	__le16 ver;
	__le16 niosq;
	__le16 niocq;
	__le16 rsvd6;
};

/**
 * struct nvme_lm_nvme_controller_state_data - NVMe Controller State data structure describes the
 * state of a NVMe Controller's I/O Submission and I/O Completion queues
 *
 * @hdr: Header
 * @sqs: I/O Submission Queue list
 * @cqs: I/O Completion Queue list
 * @queue_data_buf: Queue data buffer
 */
struct nvme_lm_nvme_controller_state_data {
	struct nvme_lm_nvme_controller_state_data_header hdr;
	union {
		struct nvme_lm_io_submission_queue_data sqs[0];
		struct nvme_lm_io_completion_queue_data cqs[0];
		__u8 queue_data_buf[4088];
	};
};

/**
 * struct nvme_lm_controller_state_data_header - Controller State data header structure describes
 * the contents of the Controller State data
 *
 * @ver:     Version of this data structure
 * @csattr:  Controller state attributes
 * @rsvd3:   Reserved
 * @nvmecss: NVMe Controller state size in dwords
 * @vss:     Vendor specific size in dowrds
 */
struct nvme_lm_controller_state_data_header {
	__le16 ver;
	__u8   csattr;
	__u8   rsvd3[13];
	__u8   nvmecss[16];
	__u8   vss[16];
};

/**
 * struct nvme_lm_controller_state_data - Controller State data structure contains data on the
 * controller's state.
 *
 * @hdr:  Header
 * @data: Data
 */
struct nvme_lm_controller_state_data {
	struct nvme_lm_controller_state_data_header hdr;
	struct nvme_lm_nvme_controller_state_data   data;
};

#define NVME_TDISP_NVME_IDENTIFIER 0x4e564d65

/**
 * enum nvme_tdisp_ti - NVMe TDISP DEVICE_INTERFACE_REPORT - TDISP Information (TI)
 * @NVME_TDISP_TI_VER_SHIFT:	Shift amount to get the Version (VER)
 * @NVME_TDISP_TI_VER_MASK:	Mask to get VER
 * @NVME_TDISP_TI_ACPS_SHIFT:	Shift amount to get the Admin Command Processing
 *				Status (ACPS)
 * @NVME_TDISP_TI_ACPS_MASK:	Mask to get ACPS
 * @NVME_TDISP_TI_ENV_SHIFT:	Shift amount to get the Enable Value (ENV)
 * @NVME_TDISP_TI_ENV_MASK:	Mask to get ENV
 * @NVME_TDISP_TI_SHNV_SHIFT:	Shift amount to get the Shutdown Notification
 *				Value (SHNV)
 * @NVME_TDISP_TI_SHNV_MASK:	Mask to get SHNV
 * @NVME_TDISP_TI_SHSTV_SHIFT:	Shift amount to get the Shutdown Status Value
 *				(SHSTV)
 * @NVME_TDISP_TI_SHSTV_MASK:	Mask to get SHSTV
 * @NVME_TDISP_TI_STV_SHIFT:	Shift amount to get the Shutdown Type Value (STV)
 * @NVME_TDISP_TI_STV_MASK:	Mask to get STV
 * @NVME_TDISP_TI_CSSV_SHIFT:	Shift amount to get the Command Sets Supported
 *				Value (CSSV)
 * @NVME_TDISP_TI_CSSV_MASK:	Mask to get CSSV
 * @NVME_TDISP_TI_MPSV_SHIFT:	Shift amount to get the Memory Page Size Value
 *				(MPSV)
 * @NVME_TDISP_TI_MPSV_MASK:	Mask to get MPSV
 * @NVME_TDISP_TI_IOSQESV_SHIFT: Shift amount to get the I/O Submission Queue
 *				 Entry Size Value (IOSQESV)
 * @NVME_TDISP_TI_IOSQESV_MASK: Mask to get IOSQESV
 * @NVME_TDISP_TI_IOCQESV_SHIFT: Shift amount to get the I/O Completion Queue
 *				 Entry Size Value (IOCQESV)
 * @NVME_TDISP_TI_IOCQESV_MASK: Mask to get IOCQESV
 */
enum nvme_tdisp_ti {
	NVME_TDISP_TI_VER_SHIFT		= 0,
	NVME_TDISP_TI_VER_MASK		= 0xff,
	NVME_TDISP_TI_ACPS_SHIFT	= 8,
	NVME_TDISP_TI_ACPS_MASK		= 0x1,
	NVME_TDISP_TI_ENV_SHIFT		= 9,
	NVME_TDISP_TI_ENV_MASK		= 0x1,
	NVME_TDISP_TI_SHNV_SHIFT	= 10,
	NVME_TDISP_TI_SHNV_MASK		= 0x3,
	NVME_TDISP_TI_SHSTV_SHIFT	= 12,
	NVME_TDISP_TI_SHSTV_MASK	= 0x3,
	NVME_TDISP_TI_STV_SHIFT		= 14,
	NVME_TDISP_TI_STV_MASK		= 0x1,
	NVME_TDISP_TI_CSSV_SHIFT	= 16,
	NVME_TDISP_TI_CSSV_MASK		= 0x7,
	NVME_TDISP_TI_MPSV_SHIFT	= 20,
	NVME_TDISP_TI_MPSV_MASK		= 0xf,
	NVME_TDISP_TI_IOSQESV_SHIFT	= 24,
	NVME_TDISP_TI_IOSQESV_MASK	= 0xf,
	NVME_TDISP_TI_IOCQESV_SHIFT	= 28,
	NVME_TDISP_TI_IOCQESV_MASK	= 0xf,
};

#define NVME_TDISP_TI_VER(ti)		NVME_GET(ti, TDISP_TI_VER)
#define NVME_TDISP_TI_ACPS(ti)		NVME_GET(ti, TDISP_TI_ACPS)
#define NVME_TDISP_TI_ENV(ti)		NVME_GET(ti, TDISP_TI_ENV)
#define NVME_TDISP_TI_SHNV(ti)		NVME_GET(ti, TDISP_TI_SHNV)
#define NVME_TDISP_TI_SHSTV(ti)		NVME_GET(ti, TDISP_TI_SHSTV)
#define NVME_TDISP_TI_STV(ti)		NVME_GET(ti, TDISP_TI_STV)
#define NVME_TDISP_TI_CSSV(ti)		NVME_GET(ti, TDISP_TI_CSSV)
#define NVME_TDISP_TI_MPSV(ti)		NVME_GET(ti, TDISP_TI_MPSV)
#define NVME_TDISP_TI_IOSQESV(ti)	NVME_GET(ti, TDISP_TI_IOSQESV)
#define NVME_TDISP_TI_IOCQESV(ti)	NVME_GET(ti, TDISP_TI_IOCQESV)

/**
 * struct nvme_tdisp_device_interface_report - NVMe TDISP
 *		DEVICE_INTERFACE_REPORT Reporting Structure
 *
 * This is the NVMe class-specific DEVICE_SPECIFIC_INFO payload that a PCIe
 * Function returns in response to a PCIe TDISP GET_DEVICE_INTERFACE_REPORT
 * request (refer to the NVM Express over PCIe Transport Specification).
 * There is no NVMe Admin, I/O, or MI command that transfers this structure
 * -- it is produced by the device's Device Security Module and consumed by
 * a platform TEE Security Module entirely via the PCIe TDISP protocol,
 * outside of any NVMe command/response mechanism. This type is provided
 * purely so that software which has otherwise obtained a
 * DEVICE_INTERFACE_REPORT (e.g., from a TDISP/SPDM stack) can decode its
 * NVMe-specific portion.
 *
 * @tni:    TDISP NVMe Identifier, shall be %NVME_TDISP_NVME_IDENTIFIER
 * @ti:     TDISP Information, see &enum nvme_tdisp_ti
 * @cu:     CSVL Used, the Controller State Version Index of the NVMe
 *	    Controller State data structure used to generate @qh
 * @vu:     VER Used, the Version field in the NVMe Controller State data
 *	    structure used to generate @qh
 * @rsvd10: Reserved
 * @aqv:    AQA Value
 * @asv:    ASQ Value
 * @acv:    ACQ Value
 * @cv:     CMBMSC Value
 * @pmv:    PMRMSC Value
 * @pcv:    PMRCTL Value
 * @qh:     Queue Hash, a SHA-384 hash of all the fields in the NVMe
 *	    Controller State data structure, see
 *	    &struct nvme_lm_controller_state_data
 * @rsvd84: Reserved
 */
struct nvme_tdisp_device_interface_report {
	__le32	tni;
	__le32	ti;
	__u8	cu;
	__u8	vu;
	__u8	rsvd10[2];
	__le32	aqv;
	__le32	asv;
	__le32	acv;
	__le32	cv;
	__le32	pmv;
	__le32	pcv;
	__u8	qh[48];
	__u8	rsvd84[44];
};

/**
 * enum nvme_lm_queue_attributes - I/O Submission and I/O Completion Queue Attributes
 *
 * @NVME_LM_IOSQPC_MASK:	Mask to get the Physically Contiguous (PC) bit for this I/O
 *				submission queue.
 * @NVME_LM_IOSQPC_SHIFT:	Shift to get the PC bit for this I/O submission queue
 * @NVME_LM_IOSQPRIO_MASK:	Mask to get the Priority for this I/O submission queue.
 * @NVME_LM_IOSQPRIO_SHIFT:	Shift to get the Priority for this I/O submission queue.
 * @NVME_LM_IOCQPC_MASK:	Mask to get the Physicaly Contiguous (PC) bit for this I/O
 *				completion queue.
 * @NVME_LM_IOCQPC_SHIFT:	Shift to get the PC bit for this I/O completion queue.
 * @NVME_LM_IOCQIEN_MASK:	Mask to get the Interrupts Enabled bit for this I/O completion
 *				queue
 * @NVME_LM_IOCQIEN_SHIFT:	Shift to get the Interrupts Enabled bit for this I/O completion
 * @NVME_LM_S0PT_MASK:		Mask to get the value of the Phase Tag bit for Slot 0 of this I/O
 *				completion queue.
 * @NVME_LM_S0PT_SHIFT:		Shift to get the value of the Phase Tag bit for Slot 0 of this I/O
 *				completion queue.
 * @NVME_LM_IOCQIV_MASK:	Mask to get the Interrupt Vector (IV) for this I/O completion
 *				queue.
 * @NVME_LM_IOCQIV_SHIFT:	Shift to get the IV for this I/O completion queue.
 */
enum nvme_lm_queue_attributes {
	/* I/O Submission Queue */
	NVME_LM_IOSQPC_MASK	= 0x1,
	NVME_LM_IOSQPC_SHIFT	= 0,
	NVME_LM_IOSQPRIO_MASK	= 0x3,
	NVME_LM_IOSQPRIO_SHIFT	= 1,
	/* I/O Completion Queue */
	NVME_LM_IOCQPC_MASK	= 0x1,
	NVME_LM_IOCQPC_SHIFT	= 0,
	NVME_LM_IOCQIEN_MASK	= 0x1,
	NVME_LM_IOCQIEN_SHIFT	= 1,
	NVME_LM_S0PT_MASK	= 0x1,
	NVME_LM_S0PT_SHIFT	= 2,
	NVME_LM_IOCQIV_MASK	= 0xffff,
	NVME_LM_IOCQIV_SHIFT	= 16,
};

#define NVME_LM_IOSQPC(attributes)	NVME_GET(attributes, LM_IOSQPC)
#define NVME_LM_IOSQPRIO(attributes)	NVME_GET(attributes, LM_IOSQPRIO)

#define NVME_LM_IOCQPC(fid)	NVME_GET(fid, LM_IOCQPC)
#define NVME_LM_IOCQIEN(fid)	NVME_GET(fid, LM_IOCQIEN)
#define NVME_LM_S0PT(fid)	NVME_GET(fid, LM_S0PT)
#define NVME_LM_IOCQIV(fid)	NVME_GET(fid, LM_IOCQIV)

/**
 * enum nvme_lm_ctrl_data_queue_fid - Controller Data Queue - Set Feature
 *
 * @NVME_LM_CTRL_DATA_QUEUE_ETPT_MASK:	Mask to set Enable Tail Pointer Trigger (ETPT)
 * @NVME_LM_CTRL_DATA_QUEUE_ETPT_SHIFT: Shift to set ETPT
 */
enum nvme_lm_ctrl_data_queue_fid {
	NVME_LM_CTRL_DATA_QUEUE_ETPT_MASK	= 0x1,
	NVME_LM_CTRL_DATA_QUEUE_ETPT_SHIFT	= 31,
};

#define NVME_LM_CTRL_DATA_QUEUE_ETPT(fid)	NVME_GET(fid, LM_CTRL_DATA_QUEUE_ETPT)

/**
 * struct nvme_lm_ctrl_data_queue_fid_data - Get Controller Data Queue feature data
 *
 * @hp:		Head Pointer
 * @tpt:	Tail Pointer Trigger
 */
struct nvme_lm_ctrl_data_queue_fid_data {
	__le32 hp;
	__le32 tpt;
};

#define NVME_FEAT_ARB_BURST(v)		NVME_GET(v, FEAT_ARBITRATION_BURST)
#define NVME_FEAT_ARB_LPW(v)		NVME_GET(v, FEAT_ARBITRATION_LPW)
#define NVME_FEAT_ARB_MPW(v)		NVME_GET(v, FEAT_ARBITRATION_MPW)
#define NVME_FEAT_ARB_HPW(v)		NVME_GET(v, FEAT_ARBITRATION_HPW)

static inline void nvme_feature_decode_arbitration(__u32 value, __u8 *ab,
						   __u8 *lpw, __u8 *mpw,
						   __u8 *hpw)
{
	*ab  = NVME_FEAT_ARB_BURST(value);
	*lpw = NVME_FEAT_ARB_LPW(value);
	*mpw = NVME_FEAT_ARB_MPW(value);
	*hpw = NVME_FEAT_ARB_HPW(value);
};

#define NVME_FEAT_PM_PS(v)		NVME_GET(v, FEAT_PWRMGMT_PS)
#define NVME_FEAT_PM_WH(v)		NVME_GET(v, FEAT_PWRMGMT_WH)
#define NVME_FEAT_PM_IIELL(v)		NVME_GET(v, FEAT_PWRMGMT_IIELL)

#define NVME_FEAT_CDP_PERID(v)		NVME_GET(v, FEAT_CDP_PERID)

#define NVME_FEAT_POWER_LIMIT_PLV(v)	NVME_GET(v, FEAT_POWER_LIMIT_PLV)
#define NVME_FEAT_POWER_LIMIT_PLS(v)	NVME_GET(v, FEAT_POWER_LIMIT_PLS)

#define NVME_FEAT_POWER_THRESH_PTV(v)	NVME_GET(v, FEAT_POWER_THRESH_PTV)
#define NVME_FEAT_POWER_THRESH_PTS(v)	NVME_GET(v, FEAT_POWER_THRESH_PTS)
#define NVME_FEAT_POWER_THRESH_PMTS(v)	NVME_GET(v, FEAT_POWER_THRESH_PMTS)
#define NVME_FEAT_POWER_THRESH_EPT(v)	NVME_GET(v, FEAT_POWER_THRESH_EPT)

#define NVME_FEAT_POWER_MEAS_ACT(v)	NVME_GET(v, FEAT_POWER_MEAS_ACT)
#define NVME_FEAT_POWER_MEAS_PMTS(v)	NVME_GET(v, FEAT_POWER_MEAS_PMTS)
#define NVME_FEAT_POWER_MEAS_SMT(v)	NVME_GET(v, FEAT_POWER_MEAS_SMT)

#define NVME_FEAT_VOLTAGE_THRESHOLD_UVT(v) \
	NVME_GET(v, FEAT_VOLTAGE_THRESHOLD_UVT)
#define NVME_FEAT_VOLTAGE_THRESHOLD_OVT(v) \
	NVME_GET(v, FEAT_VOLTAGE_THRESHOLD_OVT)
#define NVME_FEAT_VOLTAGE_THRESHOLD_VSENS(v) \
	NVME_GET(v, FEAT_VOLTAGE_THRESHOLD_VSENS)

#define NVME_FEAT_VOLTAGE_MEASUREMENT_ACT(v) \
	NVME_GET(v, FEAT_VOLTAGE_MEASUREMENT_ACT)

#define NVME_FEAT_RATE_LIMITING_TID(v)	NVME_GET(v, FEAT_RATE_LIMITING_TID)
#define NVME_FEAT_RATE_LIMITING_TGT(v)	NVME_GET(v, FEAT_RATE_LIMITING_TGT)

/**
 * enum nvme_rate_limiting_target - Rate Limiting Feature Command Dword 11
 *				     Target (TGT)
 * @NVME_RATE_LIMITING_TARGET_CONTROLLER:	Target Identifier field specifies
 *						the controller identifier
 * @NVME_RATE_LIMITING_TARGET_VENDOR_MIN:	Start of vendor specific range
 * @NVME_RATE_LIMITING_TARGET_VENDOR_MAX:	End of vendor specific range
 */
enum nvme_rate_limiting_target {
	NVME_RATE_LIMITING_TARGET_CONTROLLER	= 0x00,
	NVME_RATE_LIMITING_TARGET_VENDOR_MIN	= 0xc0,
	NVME_RATE_LIMITING_TARGET_VENDOR_MAX	= 0xff,
};

/**
 * enum nvme_voltage_measurement_act - Voltage Measurement Feature -
 *					Command Dword 11 Action (ACT)
 * @NVME_VOLTAGE_MEASUREMENT_ACT_STOP:  Stop Voltage Measurements
 * @NVME_VOLTAGE_MEASUREMENT_ACT_START: Start Voltage Measurements
 * @NVME_VOLTAGE_MEASUREMENT_ACT_CLEAR: Clear Overvoltage Valid and
 *					 Undervoltage Valid
 */
enum nvme_voltage_measurement_act {
	NVME_VOLTAGE_MEASUREMENT_ACT_STOP	= 0x0,
	NVME_VOLTAGE_MEASUREMENT_ACT_START	= 0x1,
	NVME_VOLTAGE_MEASUREMENT_ACT_CLEAR	= 0x2,
};

static inline void
nvme_feature_decode_power_mgmt(__u32 value, __u8 *ps, __u8 *wh, __u16 *iiell)
{
	*ps = NVME_FEAT_PM_PS(value);
	*wh = NVME_FEAT_PM_WH(value);
	*iiell = NVME_FEAT_PM_IIELL(value);
}

#define NVME_FEAT_LBAR_NR(v)		NVME_GET(v, FEAT_LBAR_NR)

static inline void
nvme_feature_decode_lba_range(__u32 value, __u8 *num)
{
	*num = NVME_FEAT_LBAR_NR(value);
}

#define NVME_FEAT_TT_TMPTH(v)		NVME_GET(v, FEAT_TT_TMPTH)
#define NVME_FEAT_TT_TMPSEL(v)		NVME_GET(v, FEAT_TT_TMPSEL)
#define NVME_FEAT_TT_THSEL(v)		NVME_GET(v, FEAT_TT_THSEL)
#define NVME_FEAT_TT_TMPTHH(v)		NVME_GET(v, FEAT_TT_TMPTHH)

static inline void
nvme_feature_decode_temp_threshold(__u32 value, __u16 *tmpth,
		__u8 *tmpsel, __u8 *thsel, __u8 *tmpthh)
{
	*tmpth	= NVME_FEAT_TT_TMPTH(value);
	*tmpsel	= NVME_FEAT_TT_TMPSEL(value);
	*thsel	= NVME_FEAT_TT_THSEL(value);
	*tmpthh	= NVME_FEAT_TT_TMPTHH(value);
}

#define NVME_FEAT_ER_TLER(v)		NVME_GET(v, FEAT_ERROR_RECOVERY_TLER)
#define NVME_FEAT_ER_DULBE(v)		NVME_GET(v, FEAT_ERROR_RECOVERY_DULBE)

static inline void
nvme_feature_decode_error_recovery(__u32 value, __u16 *tler, bool *dulbe)
{
	*tler	= NVME_FEAT_ER_TLER(value);
	*dulbe	= NVME_FEAT_ER_DULBE(value);
}

#define NVME_FEAT_VWC_WCE(v)		NVME_GET(v, FEAT_VWC_WCE)

static inline void
nvme_feature_decode_volatile_write_cache(__u32 value, bool *wce)
{
	*wce	= NVME_FEAT_VWC_WCE(value);
}

#define NVME_FEAT_NRQS_NSQR(v)		NVME_GET(v, FEAT_NRQS_NSQR)
#define NVME_FEAT_NRQS_NCQR(v)		NVME_GET(v, FEAT_NRQS_NCQR)

static inline void
nvme_feature_decode_number_of_queues(__u32 value, __u16 *nsqr, __u16 *ncqr)
{
	*nsqr	= NVME_FEAT_NRQS_NSQR(value);
	*ncqr	= NVME_FEAT_NRQS_NCQR(value);
}

#define NVME_FEAT_IRQC_THR(v)		NVME_GET(v, FEAT_IRQC_THR)
#define NVME_FEAT_IRQC_TIME(v)		NVME_GET(v, FEAT_IRQC_TIME)

static inline void
nvme_feature_decode_interrupt_coalescing(__u32 value, __u8 *thr, __u8 *time)
{
	*thr	= NVME_FEAT_IRQC_THR(value);
	*time	= NVME_FEAT_IRQC_TIME(value);
}

#define NVME_FEAT_ICFG_IV(v)		NVME_GET(v, FEAT_ICFG_IV)
#define NVME_FEAT_ICFG_CD(v)		NVME_GET(v, FEAT_ICFG_CD)

static inline void
nvme_feature_decode_interrupt_config(__u32 value, __u16 *iv, bool *cd)
{
	*iv	= NVME_FEAT_ICFG_IV(value);
	*cd	= NVME_FEAT_ICFG_CD(value);
}

#define NVME_FEAT_WA_DN(v)		NVME_GET(v, FEAT_WA_DN)

static inline void
nvme_feature_decode_write_atomicity(__u32 value, bool *dn)
{
	*dn	= NVME_FEAT_WA_DN(value);
}

#define NVME_FEAT_AE_SMART(v)		NVME_GET(v, FEAT_AE_SMART)
#define NVME_FEAT_AE_NAN(v)		NVME_GET(v, FEAT_AE_NAN)
#define NVME_FEAT_AE_FW(v)		NVME_GET(v, FEAT_AE_FW)
#define NVME_FEAT_AE_TELEM(v)		NVME_GET(v, FEAT_AE_TELEM)
#define NVME_FEAT_AE_ANA(v)		NVME_GET(v, FEAT_AE_ANA)
#define NVME_FEAT_AE_PLA(v)		NVME_GET(v, FEAT_AE_PLA)
#define NVME_FEAT_AE_LBAS(v)		NVME_GET(v, FEAT_AE_LBAS)
#define NVME_FEAT_AE_EGA(v)		NVME_GET(v, FEAT_AE_EGA)
#define NVME_FEAT_AE_NNSSHDN(v)		NVME_GET(v, FEAT_AE_NNSSHDN)
#define NVME_FEAT_AE_TTHRY(v)		NVME_GET(v, FEAT_AE_TTHRY)
#define NVME_FEAT_AE_RASSN(v)		NVME_GET(v, FEAT_AE_RASSN)
#define NVME_FEAT_AE_RGRP0(v)		NVME_GET(v, FEAT_AE_RGRP0)
#define NVME_FEAT_AE_ANSAN(v)		NVME_GET(v, FEAT_AE_ANSAN)
#define NVME_FEAT_AE_ZDCN(v)		NVME_GET(v, FEAT_AE_ZDCN)
#define NVME_FEAT_AE_PMDRLPCN(v)	NVME_GET(v, FEAT_AE_PMDRLPCN)
#define NVME_FEAT_AE_ADLPCN(v)		NVME_GET(v, FEAT_AE_ADLPCN)
#define NVME_FEAT_AE_HDLPCN(v)		NVME_GET(v, FEAT_AE_HDLPCN)
#define NVME_FEAT_AE_DLPCN(v)		NVME_GET(v, FEAT_AE_DLPCN)
#define NVME_FEAT_AE_RLCCN(v)		NVME_GET(v, FEAT_AE_RLCCN)

static inline void
nvme_feature_decode_async_event_config(__u32 value, __u8 *smart, bool *nan,
		bool *fw, bool *telem, bool *ana, bool *pla,
		bool *lbas, bool *ega)
{
	*smart	= NVME_FEAT_AE_SMART(value);
	*nan	= NVME_FEAT_AE_NAN(value);
	*fw	= NVME_FEAT_AE_FW(value);
	*telem	= NVME_FEAT_AE_TELEM(value);
	*ana	= NVME_FEAT_AE_ANA(value);
	*pla	= NVME_FEAT_AE_PLA(value);
	*lbas	= NVME_FEAT_AE_LBAS(value);
	*ega	= NVME_FEAT_AE_EGA(value);
}

#define NVME_FEAT_APST_APSTE(v)		NVME_GET(v, FEAT_APST_APSTE)

static inline void
nvme_feature_decode_auto_power_state(__u32 value, bool *apste)
{
	*apste	= NVME_FEAT_APST_APSTE(value);
}

#define NVME_FEAT_HMEM_EHM(v)		NVME_GET(v, FEAT_HMEM_EHM)

static inline void
nvme_feature_decode_host_memory_buffer(__u32 value, bool *ehm)
{
	*ehm	= NVME_FEAT_HMEM_EHM(value);
}

#define NVME_FEAT_HCTM_TMT2(v)		NVME_GET(v, FEAT_HCTM_TMT2)
#define NVME_FEAT_HCTM_TMT1(v)		NVME_GET(v, FEAT_HCTM_TMT1)

static inline void
nvme_feature_decode_host_thermal_mgmt(__u32 value, __u16 *tmt2, __u16 *tmt1)
{
	*tmt2	= NVME_FEAT_HCTM_TMT2(value);
	*tmt1	= NVME_FEAT_HCTM_TMT1(value);
}

#define NVME_FEAT_NOPS_NOPPME(v)	NVME_GET(v, FEAT_NOPS_NOPPME)

static inline void
nvme_feature_decode_non_op_power_config(__u32 value, bool *noppme)
{
	*noppme	= NVME_FEAT_NOPS_NOPPME(value);
}

#define NVME_FEAT_RRL_RRL(v)		NVME_GET(v, FEAT_RRL_RRL)

static inline void
nvme_feature_decode_read_recovery_level_config(__u32 value, __u8 *rrl)
{
	*rrl	= NVME_FEAT_RRL_RRL(value);
}

#define NVME_FEAT_PLM_LPE(v)		NVME_GET(v, FEAT_PLM_LPE)

static inline void
nvme_feature_decode_predictable_latency_mode_config(__u32 value, bool *lpe)
{
	*lpe	= NVME_FEAT_PLM_LPE(value);
}

#define NVME_FEAT_PLMW_WS(v)		NVME_GET(v, FEAT_PLMW_WS)

static inline void
nvme_feature_decode_predictable_latency_mode_window(__u32 value, __u8 *ws)
{
	*ws	= NVME_FEAT_PLMW_WS(value);
}

#define NVME_FEAT_LBAS_LSIRI(v)		NVME_GET(v, FEAT_LBAS_LSIRI)
#define NVME_FEAT_LBAS_LSIPI(v)		NVME_GET(v, FEAT_LBAS_LSIPI)

static inline void
nvme_feature_decode_lba_status_attributes(__u32 value, __u16 *lsiri,
		__u16 *lsipi)
{
	*lsiri	= NVME_FEAT_LBAS_LSIRI(value);
	*lsipi	= NVME_FEAT_LBAS_LSIPI(value);
}

#define NVME_FEAT_SC_NODRM(v)		NVME_GET(v, FEAT_SC_NODRM)

static inline void
nvme_feature_decode_sanitize_config(__u32 value, bool *nodrm)
{
	*nodrm	= NVME_FEAT_SC_NODRM(value);
}

#define NVME_FEAT_EG_ENDGID(v)		NVME_GET(v, FEAT_EG_ENDGID)
#define NVME_FEAT_EG_EGCW(v)		NVME_GET(v, FEAT_EG_EGCW)

static inline void
nvme_feature_decode_endurance_group_event_config(__u32 value,
		__u16 *endgid, __u8 *endgcw)
{
	*endgid	= NVME_FEAT_EG_ENDGID(value);
	*endgcw	= NVME_FEAT_EG_EGCW(value);
}

#define NVME_FEAT_PERFC_ATTRI(v) NVME_GET(v, FEAT_PERFC_ATTRI)
#define NVME_FEAT_PERFC_RVSPA(v) NVME_GET(v, FEAT_PERFC_RVSPA)

static inline void
nvme_feature_decode_perf_characteristics(__u32 value, __u8 *attri, bool *rvspa)
{
	*attri = NVME_FEAT_PERFC_ATTRI(value);
	*rvspa = NVME_FEAT_PERFC_RVSPA(value);
}

#define NVME_FEAT_FDPE(v) NVME_GET(v, FEAT_FDP_ENABLED)
#define NVME_FEAT_FDPCIDX(v) NVME_GET(v, FEAT_FDP_INDEX)

#define NVME_FEAT_HOST_ID_EXHID(v) NVME_GET(v, FEAT_HOST_ID_EXHID)

static inline void
nvme_feature_decode_host_id(__u32 value, bool *exhid)
{
	*exhid = NVME_FEAT_HOST_ID_EXHID(value);
}

#define NVME_FEAT_SPM_PBSLC(v)		NVME_GET(v, FEAT_SPM_PBSLC)

static inline void
nvme_feature_decode_software_progress_marker(__u32 value, __u8 *pbslc)
{
	*pbslc	= NVME_FEAT_SPM_PBSLC(value);
}

#define NVME_FEAT_HOSTID_EXHID(v)	NVME_GET(v, FEAT_HOSTID_EXHID)

static inline void
nvme_feature_decode_host_identifier(__u32 value, bool *exhid)
{
	*exhid = NVME_FEAT_HOSTID_EXHID(value);
}

#define NVME_FEAT_RM_REGPRE(v)		NVME_GET(v, FEAT_RM_REGPRE)
#define NVME_FEAT_RM_RESREL(v)		NVME_GET(v, FEAT_RM_RESREL)
#define NVME_FEAT_RM_RESPRE(v)		NVME_GET(v, FEAT_RM_RESPRE)

static inline void
nvme_feature_decode_reservation_notification(__u32 value, bool *regpre,
		bool *resrel, bool *respre)
{
	*regpre	= NVME_FEAT_RM_REGPRE(value);
	*resrel	= NVME_FEAT_RM_RESREL(value);
	*respre	= NVME_FEAT_RM_RESPRE(value);
}

#define NVME_FEAT_RP_PTPL(v)		NVME_GET(v, FEAT_RP_PTPL)

static inline void
nvme_feature_decode_reservation_persistance(__u32 value, bool *ptpl)
{
	*ptpl	= NVME_FEAT_RP_PTPL(value);
}

#define NVME_FEAT_WP_WPS(v)		NVME_GET(v, FEAT_WP_WPS)

static inline void
nvme_feature_decode_namespace_write_protect(__u32 value, __u8 *wps)
{
	*wps	= NVME_FEAT_WP_WPS(value);
}

#define NVME_FEAT_BPWPC_BP0WPS(v)	NVME_GET(v, FEAT_BPWPC_BP0WPS)
#define NVME_FEAT_BPWPC_BP1WPS(v)	NVME_GET(v, FEAT_BPWPC_BP1WPS)

static inline void
nvme_id_ns_flbas_to_lbaf_inuse(__u8 flbas, __u8 *lbaf_inuse)
{
	*lbaf_inuse = ((NVME_FLBAS_HIGHER(flbas) << 4) |
			NVME_FLBAS_LOWER(flbas));
}
