// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 *	    Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 */

#ifndef _LIBNVME_TYPES_H
#define _LIBNVME_TYPES_H

#include <stdbool.h>
#include <stdint.h>

#include <linux/types.h>

/**
 * DOC: types.h
 *
 * NVMe standard definitions
 */

/**
 * NVME_GET() - extract field from complex value
 * @value: The original value of a complex field
 * @name: The name of the sub-field within an nvme value
 *
 * By convention, this library defines _SHIFT and _MASK such that mask can be
 * applied after the shift to isolate a specific set of bits that decode to a
 * sub-field.
 *
 * Returns: The 'name' field from 'value'
 */
#define NVME_GET(value, name) \
	(((value) >> NVME_##name##_SHIFT) & NVME_##name##_MASK)

/**
 * NVME_SET() - set field into complex value
 * @value: The value to be set in its completed position
 * @name: The name of the sub-field within an nvme value
 *
 * Returns: The 'name' field from 'value'
 */
#define NVME_SET(value, name) \
	(((__u32)(value) & NVME_##name##_MASK) << NVME_##name##_SHIFT)

/**
 * NVME_CHECK() - check value to compare field value
 * @value: The value to be checked
 * @name: The name of the sub-field within an nvme value
 * @check: The sub-field value to check
 *
 * Returns: The result of compare the value and the sub-field value
 */
#define NVME_CHECK(value, name, check) ((value) == NVME_##name##_##check)

/**
 * NVME_VAL() - get mask value shifted
 * @name: The name of the sub-field within an nvme value
 *
 * Returns: The mask value shifted
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
};

/**
 * enum nvme_csi - Defined command set indicators
 * @NVME_CSI_NVM:	NVM Command Set Indicator
 * @NVME_CSI_KV:	Key Value Command Set
 * @NVME_CSI_ZNS:	Zoned Namespace Command Set
 */
enum nvme_csi {
	NVME_CSI_NVM			= 0,
	NVME_CSI_KV			= 1,
	NVME_CSI_ZNS			= 2,
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
 * Returns: true if given offset is 64bit register, otherwise it returns false.
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
 * @NVME_CSTS_SHN_MASK:		Deprecated mask to get the shutdown status
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
	NVME_CSTS_SHN_MASK	= NVME_CSTS_SHST_MASK, /* Deprecated */
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
 * Returns: size of controller memory buffer in bytes
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
 * Returns: size of controller persistent memory buffer in bytes
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
 * Returns: throughput of controller persistent memory buffer in bytes/second
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
 * nvme_psd_power_scale() - power scale occupies the upper 3 bits
 * @ps: power scale value
 *
 * Returns: power scale value
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
 * @rsvd23: Reserved
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
	__u8			rsvd23[9];
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
 * @rsvd102:	Reserved
 * @cntrltype: Controller Type, see &enum nvme_id_ctrl_cntrltype
 * @fguid:     FRU GUID, a 128-bit value that is globally unique for a given
 *	       Field Replaceable Unit
 * @crdt1:     Controller Retry Delay time in 100 millisecond units if CQE CRD
 *	       field is 1
 * @crdt2:     Controller Retry Delay time in 100 millisecond units if CQE CRD
 *	       field is 2
 * @crdt3:     Controller Retry Delay time in 100 millisecond units if CQE CRD
 *	       field is 3
 * @rsvd134:   Reserved
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
 * @rsvd358:   Reserved
 * @megcap:    Max Endurance Group Capacity indicates the maximum capacity
 *	       of a single Endurance Group.
 * @tmpthha:   Temperature Threshold Hysteresis Attributes
 * @rsvd385:   Reserved
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
 * @rsvd568:   Reserved
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
 * @trattr:    Tracking Attributes indicates supported attributes for the
 *             Track Send command and Track Receive command.
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
 * @rsvd1807:  Reserved
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
	__u8			rsvd102[9];
	__u8			cntrltype;
	__u8			fguid[16];
	__le16			crdt1;
	__le16			crdt2;
	__le16			crdt3;
	__u8			rsvd134[119];
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
	__u8			rsvd358[10];
	__u8			megcap[16];
	__u8			tmpthha;
	__u8			rsvd385[127];
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
	__u8			rsvd568[2];
	__u16			cmmrtd;
	__u16			nmmrtd;
	__u8			minmrtg;
	__u8			maxmrtg;
	__u8			trattr;
	__u8			rsvd577;
	__u16			mcudmq;
	__u16			mnsudmq;
	__u16			mcmr;
	__u16			nmcmr;
	__u16			mcdqpc;
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
	__u8			rsvd1807[241];

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
 * @NVME_CTRL_OAES_NA_SHIFT: Shift amount to get the Namespace Attribute Notices event supported
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
 * @NVME_CTRL_OAES_ZD_SHIFT: Shift amount to get the Zone Descriptor Change Notifications supported
 * @NVME_CTRL_OAES_DL_SHIFT: Shift amount to get the Discover Log Page Change Notifications
 *                           supported
 * @NVME_CTRL_OAES_NA_MASK: Mask to get the Namespace Attribute Notices event supported
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
 * @NVME_CTRL_OAES_ZD_MASK: Mask to get the Zone Descriptor Change Notifications supported
 * @NVME_CTRL_OAES_DL_MASK: Mask to get the Discover Log Page Change Notifications supported
 * @NVME_CTRL_OAES_NA: Namespace Attribute Notices event supported
 * @NVME_CTRL_OAES_FA: Firmware Activation Notices event supported
 * @NVME_CTRL_OAES_ANA: ANA Change Notices supported
 * @NVME_CTRL_OAES_PLEA: Predictable Latency Event Aggregate Log Change Notices event supported
 * @NVME_CTRL_OAES_LBAS: LBA Status Information Notices event supported
 * @NVME_CTRL_OAES_EGE: Endurance Group Events Aggregate Log Change Notices event supported
 * @NVME_CTRL_OAES_NS: Normal NVM Subsystem Shutdown event supported
 * @NVME_CTRL_OAES_TTH: Temperature Threshold Hysteresis Recovery event supported
 * @NVME_CTRL_OAES_ZD: Zone Descriptor Change Notifications supported
 * @NVME_CTRL_OAES_DL: Discover Log Page Change Notifications supported
 */
enum nvme_id_ctrl_oaes {
	NVME_CTRL_OAES_NA_SHIFT		= 8,
	NVME_CTRL_OAES_FA_SHIFT		= 9,
	NVME_CTRL_OAES_ANA_SHIFT	= 11,
	NVME_CTRL_OAES_PLEA_SHIFT	= 12,
	NVME_CTRL_OAES_LBAS_SHIFT	= 13,
	NVME_CTRL_OAES_EGE_SHIFT	= 14,
	NVME_CTRL_OAES_NS_SHIFT		= 15,
	NVME_CTRL_OAES_TTH_SHIFT	= 16,
	NVME_CTRL_OAES_ZD_SHIFT		= 27,
	NVME_CTRL_OAES_DL_SHIFT		= 31,
	NVME_CTRL_OAES_NA_MASK		= 0x1,
	NVME_CTRL_OAES_FA_MASK		= 0x1,
	NVME_CTRL_OAES_ANA_MASK		= 0x1,
	NVME_CTRL_OAES_PLEA_MASK	= 0x1,
	NVME_CTRL_OAES_LBAS_MASK	= 0x1,
	NVME_CTRL_OAES_EGE_MASK		= 0x1,
	NVME_CTRL_OAES_NS_MASK		= 0x1,
	NVME_CTRL_OAES_TTH_MASK		= 0x1,
	NVME_CTRL_OAES_ZD_MASK		= 0x1,
	NVME_CTRL_OAES_DL_MASK		= 0x1,
	NVME_CTRL_OAES_NA		= NVME_VAL(CTRL_OAES_NA),
	NVME_CTRL_OAES_FA		= NVME_VAL(CTRL_OAES_FA),
	NVME_CTRL_OAES_ANA		= NVME_VAL(CTRL_OAES_ANA),
	NVME_CTRL_OAES_PLEA		= NVME_VAL(CTRL_OAES_PLEA),
	NVME_CTRL_OAES_LBAS		= NVME_VAL(CTRL_OAES_LBAS),
	NVME_CTRL_OAES_EGE		= NVME_VAL(CTRL_OAES_EGE),
	NVME_CTRL_OAES_NS		= NVME_VAL(CTRL_OAES_NS),
	NVME_CTRL_OAES_TTH		= NVME_VAL(CTRL_OAES_TTH),
	NVME_CTRL_OAES_ZD		= NVME_VAL(CTRL_OAES_ZD),
	NVME_CTRL_OAES_DL		= NVME_VAL(CTRL_OAES_DL),
};

#define NVME_CTRL_OAES_NAN(oaes)	NVME_GET(oaes, CTRL_OAES_NA)
#define NVME_CTRL_OAES_FAN(oaes)	NVME_GET(oaes, CTRL_OAES_FA)
#define NVME_CTRL_OAES_ANACN(oaes)	NVME_GET(oaes, CTRL_OAES_ANA)
#define NVME_CTRL_OAES_PLEALCN(oaes)	NVME_GET(oaes, CTRL_OAES_PLEA)
#define NVME_CTRL_OAES_LBASIAN(oaes)	NVME_GET(oaes, CTRL_OAES_LBAS)
#define NVME_CTRL_OAES_EGEALPCN(oaes)	NVME_GET(oaes, CTRL_OAES_EGE)
#define NVME_CTRL_OAES_NNVMSS(oaes)	NVME_GET(oaes, CTRL_OAES_NS)
#define NVME_CTRL_OAES_TTHR(oaes)	NVME_GET(oaes, CTRL_OAES_TTH)
#define NVME_CTRL_OAES_ZDCN(oaes)	NVME_GET(oaes, CTRL_OAES_ZD)
#define NVME_CTRL_OAES_DLPCN(oaes)	NVME_GET(oaes, CTRL_OAES_DL)

/**
 * enum nvme_id_ctrl_ctratt - Controller attributes
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
 * @NVME_CTRL_CTRATT_FDPS: Flexible Data Placement supported
 */
enum nvme_id_ctrl_ctratt {
	NVME_CTRL_CTRATT_128_ID			= 1 << 0,
	NVME_CTRL_CTRATT_NON_OP_PSP		= 1 << 1,
	NVME_CTRL_CTRATT_NVM_SETS		= 1 << 2,
	NVME_CTRL_CTRATT_READ_RECV_LVLS		= 1 << 3,
	NVME_CTRL_CTRATT_ENDURANCE_GROUPS	= 1 << 4,
	NVME_CTRL_CTRATT_PREDICTABLE_LAT	= 1 << 5,
	NVME_CTRL_CTRATT_TBKAS			= 1 << 6,
	NVME_CTRL_CTRATT_NAMESPACE_GRANULARITY	= 1 << 7,
	NVME_CTRL_CTRATT_SQ_ASSOCIATIONS	= 1 << 8,
	NVME_CTRL_CTRATT_UUID_LIST		= 1 << 9,
	NVME_CTRL_CTRATT_MDS			= 1 << 10,
	NVME_CTRL_CTRATT_FIXED_CAP		= 1 << 11,
	NVME_CTRL_CTRATT_VARIABLE_CAP		= 1 << 12,
	NVME_CTRL_CTRATT_DEL_ENDURANCE_GROUPS	= 1 << 13,
	NVME_CTRL_CTRATT_DEL_NVM_SETS		= 1 << 14,
	NVME_CTRL_CTRATT_ELBAS			= 1 << 15,
	NVME_CTRL_CTRATT_MEM			= 1 << 16,
	NVME_CTRL_CTRATT_HMBR			= 1 << 17,
	NVME_CTRL_CTRATT_FDPS			= 1 << 19,
};

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
 * @NVME_CTRL_NVMSR_NVMESD: If set, then the NVM Subsystem is part of an NVMe
 *			    Storage Device; if cleared, then the NVM Subsystem
 *			    is not part of an NVMe Storage Device.
 * @NVME_CTRL_NVMSR_NVMEE:  If set’, then the NVM Subsystem is part of an NVMe
 *			    Enclosure; if cleared, then the NVM Subsystem is
 *			    not part of an NVMe Enclosure.
 */
enum nvme_id_ctrl_nvmsr {
	NVME_CTRL_NVMSR_NVMESD			= 1 << 0,
	NVME_CTRL_NVMSR_NVMEE			= 1 << 1,
};

/**
 * enum nvme_id_ctrl_vwci - This field indicates information about remaining
 *			    number of times that VPD contents are able to be
 *			    updated using the VPD Write command, see &struct
 *			    nvme_id_ctrl.vwci.
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
	NVME_CTRL_VWCI_VWCR			= 0x7f << 0,
	NVME_CTRL_VWCI_VWCRV			= 1 << 7,
};

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
 * @NVME_CTRL_OACS_CMD_FEAT_LD: If set, then the controller supports the command
 *				and feature lockdown capability.
 */
enum nvme_id_ctrl_oacs {
	NVME_CTRL_OACS_SECURITY			= 1 << 0,
	NVME_CTRL_OACS_FORMAT			= 1 << 1,
	NVME_CTRL_OACS_FW			= 1 << 2,
	NVME_CTRL_OACS_NS_MGMT			= 1 << 3,
	NVME_CTRL_OACS_SELF_TEST		= 1 << 4,
	NVME_CTRL_OACS_DIRECTIVES		= 1 << 5,
	NVME_CTRL_OACS_NVME_MI			= 1 << 6,
	NVME_CTRL_OACS_VIRT_MGMT		= 1 << 7,
	NVME_CTRL_OACS_DBBUF_CFG		= 1 << 8,
	NVME_CTRL_OACS_LBA_STATUS		= 1 << 9,
	NVME_CTRL_OACS_CMD_FEAT_LD		= 1 << 10,
};

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
 * @NVME_CTRL_DSTO_ONE_DST: If set,  then the NVM subsystem supports only one
 *			    device self-test operation in progress at a time.
 */
enum nvme_id_ctrl_dsto {
	NVME_CTRL_DSTO_ONE_DST			= 1 << 0,
};

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
 * @NVME_CTRL_SANICAP_CES:     Crypto Erase Support. If set, then the
 *			       controller supports the Crypto Erase sanitize operation.
 * @NVME_CTRL_SANICAP_BES:     Block Erase Support. If set, then the controller
 *			       supports the Block Erase sanitize operation.
 * @NVME_CTRL_SANICAP_OWS:     Overwrite Support. If set, then the controller
 *			       supports the Overwrite sanitize operation.
 * @NVME_CTRL_SANICAP_NDI:     No-Deallocate Inhibited. If set and the No-
 *			       Deallocate Response Mode bit is set, then the
 *			       controller deallocates after the sanitize
 *			       operation even if the No-Deallocate After
 *			       Sanitize bit is set in a Sanitize command.
 * @NVME_CTRL_SANICAP_NODMMAS: No-Deallocate Modifies Media After Sanitize,
 *			       mask to extract value.
 */
enum nvme_id_ctrl_sanicap {
	NVME_CTRL_SANICAP_CES			= 1 << 0,
	NVME_CTRL_SANICAP_BES			= 1 << 1,
	NVME_CTRL_SANICAP_OWS			= 1 << 2,
	NVME_CTRL_SANICAP_NDI			= 1 << 29,
	NVME_CTRL_SANICAP_NODMMAS		= 3 << 30,
};

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
 * @NVME_LBAF_RP_MASK:	   Mask to get the relative performance value from the
 *			   field
 */
enum nvme_lbaf_rp {
	NVME_LBAF_RP_BEST	= 0,
	NVME_LBAF_RP_BETTER	= 1,
	NVME_LBAF_RP_GOOD	= 2,
	NVME_LBAF_RP_DEGRADED	= 3,
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
 * @rsvd81:   Reserved
 * @nulbaf:   Number of Unique Capability LBA Formats defines the number of
 *	  supported user data size and metadata size combinations supported
 *	  by the namespace that may not share the same capabilities. LBA
 *	  formats shall be allocated in order and packed sequentially.
 * @rsvd83:   Reserved
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
	__u8			rsvd81;
	__u8			nulbaf;
	__u8			rsvd83[9];
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
 * @NVME_NS_FLBAS_HIGHER_MASK:	Mask to get the index of one of
 *				the supported LBA Formats's most significant
 *				2bits indicated in
 *				:c:type:`struct nvme_id_ns <nvme_id_ns>`.lbaf.
 */
enum nvme_id_ns_flbas {
	NVME_NS_FLBAS_LOWER_MASK	= 15 << 0,
	NVME_NS_FLBAS_META_EXT		= 1 << 4,
	NVME_NS_FLBAS_HIGHER_MASK	= 3 << 5,
};

/**
 * enum nvme_nvm_id_ns_elbaf - This field indicates the extended LBA format
 * @NVME_NVM_ELBAF_STS_MASK:	Mask to get the storage tag size used to determine
 *				the variable-sized storage tag/reference tag fields
 * @NVME_NVM_ELBAF_PIF_MASK:	Mask to get the protection information format for
 *				the extended LBA format.
 * @NVME_NVM_ELBAF_QPIF_MASK:	Mask to get the Qualified Protection Information
 *				Format.
 */
enum nvme_nvm_id_ns_elbaf {
	NVME_NVM_ELBAF_STS_MASK		= 127 << 0,
	NVME_NVM_ELBAF_PIF_MASK		= 3 << 7,
	NVME_NVM_ELBAF_QPIF_MASK	= 15 << 9,
};

/**
 * enum nvme_nvm_id_ns_pif - This field indicates the type of the Protection
 *			     Information Format
 * @NVME_NVM_PIF_16B_GUARD:	16-bit Guard Protection Information Format
 * @NVME_NVM_PIF_32B_GUARD:	32-bit Guard Protection Information Format
 * @NVME_NVM_PIF_64B_GUARD:	64-bit Guard Protection Information Format
 * @NVME_NVM_PIF_QTYPE:		If Qualified Protection Information Format Supports
 *				and Protection Information Format is set to 3, then
 *				protection information format is taken from Qualified
 *				Protection Information Format field.
 */
enum nvme_nvm_id_ns_pif {
	NVME_NVM_PIF_16B_GUARD		= 0,
	NVME_NVM_PIF_32B_GUARD		= 1,
	NVME_NVM_PIF_64B_GUARD		= 2,
	NVME_NVM_PIF_QTYPE		= 3,
};

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
 * @NVME_NS_DPS_PI_MASK:  Mask to get the value of the PI type
 * @NVME_NS_DPS_PI_FIRST: If set, indicates that the protection information, if
 *			  enabled, is transferred as the first eight bytes of
 *			  metadata.
 */
enum nvme_id_ns_dps {
	NVME_NS_DPS_PI_NONE		= 0,
	NVME_NS_DPS_PI_TYPE1		= 1,
	NVME_NS_DPS_PI_TYPE2		= 2,
	NVME_NS_DPS_PI_TYPE3		= 3,
	NVME_NS_DPS_PI_MASK		= 7 << 0,
	NVME_NS_DPS_PI_FIRST		= 1 << 3,
};

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
};

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
 * @rsvd15:	reserved
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
	__u8	rsvd15[4081];
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
 * @NVME_ID_UUID_HDR_ASSOCIATION_MASK:
 * @NVME_ID_UUID_ASSOCIATION_NONE:
 * @NVME_ID_UUID_ASSOCIATION_VENDOR:
 * @NVME_ID_UUID_ASSOCIATION_SUBSYSTEM_VENDOR:
 */
enum nvme_id_uuid {
	NVME_ID_UUID_HDR_ASSOCIATION_MASK		= 0x3,
	NVME_ID_UUID_ASSOCIATION_NONE			= 0,
	NVME_ID_UUID_ASSOCIATION_VENDOR			= 1,
	NVME_ID_UUID_ASSOCIATION_SUBSYSTEM_VENDOR	= 2,
};

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
 * struct nvme_id_ctrl_nvm - I/O Command Set Specific Identify Controller data structure
 * @vsl:	Verify Size Limit
 * @wzsl:	Write Zeroes Size Limit
 * @wusl:	Write Uncorrectable Size Limit
 * @dmrl:	Dataset Management Ranges Limit
 * @dmrsl:	Dataset Management Range Size Limit
 * @dmsl:	Dataset Management Size Limit
 * @rsvd16:	Reserved
 * @aocs:	Admin Optional Command Support
 * @rsvd20:	Reserved
 */
struct nvme_id_ctrl_nvm {
	__u8	vsl;
	__u8	wzsl;
	__u8	wusl;
	__u8	dmrl;
	__le32	dmrsl;
	__le64	dmsl;
	__u8	rsvd16[2];
	__le16	aocs;
	__u8	rsvd20[4076];
};

/**
 * struct nvme_nvm_id_ns - NVME Command Set I/O Command Set Specific Identify Namespace Data Structure
 * @lbstm:	Logical Block Storage Tag Mask
 * @pic:	Protection Information Capabilities
 * @pifa:	Protection Information Format Attribute
 * @rsvd10:	Reserved
 * @elbaf:	List of Extended LBA Format Support
 * @npdgl:	Namespace Preferred Deallocate Granularity Large
 * @nprg:	Namespace Preferred Read Granularity
 * @npra:	Namespace Preferred Read Alignment
 * @nors:	Namespace Optimal Read Size
 * @npdal:	Namespace Preferred Deallocate Alignment Large
 * @lbapss:	LBA Format Placement Shard Size
 * @tlbaag:	Tracked LBA Allocation Granularity
 * @rsvd296:	Reserved
 */
struct nvme_nvm_id_ns {
	__le64	lbstm;
	__u8	pic;
	__u8	pifa;
	__u8	rsvd10[2];
	__le32	elbaf[64];
	__le32	npdgl;
	__le32	nprg;
	__le32	npra;
	__le32	nors;
	__le32	npdal;
	__le32	lbapss;
	__le32	tlbaag;
	__u8	rsvd296[3800];
};

/**
 * struct nvme_zns_lbafe - LBA Format Extension Data Structure
 * @zsze:	Zone Size
 * @zdes:	Zone Descriptor Extension Size
 * @rsvd9:	reserved
 */
struct nvme_zns_lbafe {
	__le64	zsze;
	__u8	zdes;
	__u8	rsvd9[7];
};

/**
 * struct nvme_zns_id_ns -  Zoned Namespace Command Set Specific  Identify Namespace Data Structure
 * @zoc:     Zone Operation Characteristics
 * @ozcs:    Optional Zoned Command Support
 * @mar:     Maximum Active Resources
 * @mor:     Maximum Open Resources
 * @rrl:     Reset Recommended Limit
 * @frl:     Finish Recommended Limit
 * @rrl1:    Reset Recommended Limit 1
 * @rrl2:    Reset Recommended Limit 2
 * @rrl3:    Reset Recommended Limit 3
 * @frl1:    Finish Recommended Limit 1
 * @frl2:    Finish Recommended Limit 2
 * @frl3:    Finish Recommended Limit 3
 * @numzrwa: Number of ZRWA Resources
 * @zrwafg:  ZRWA Flush Granularity
 * @zrwasz:  ZRWA Size
 * @zrwacap: ZRWA Capability
 * @rsvd53:  Reserved
 * @lbafe:   LBA Format Extension
 * @vs:	     Vendor Specific
 */
struct nvme_zns_id_ns {
	__le16			zoc;
	__le16			ozcs;
	__le32			mar;
	__le32			mor;
	__le32			rrl;
	__le32			frl;
	__le32			rrl1;
	__le32			rrl2;
	__le32			rrl3;
	__le32			frl1;
	__le32			frl2;
	__le32			frl3;
	__le32			numzrwa;
	__le16			zrwafg;
	__le16			zrwasz;
	__u8			zrwacap;
	__u8			rsvd53[2763];
	struct nvme_zns_lbafe	lbafe[64];
	__u8			vs[256];
};

/**
 * struct nvme_zns_id_ctrl -  I/O Command Set Specific Identify Controller Data Structure for the Zoned Namespace Command Set
 * @zasl:	Zone Append Size Limit
 * @rsvd1:	Reserved
 */
struct nvme_zns_id_ctrl {
	__u8	zasl;
	__u8	rsvd1[4095];
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

enum nvme_err_pel {
	NVME_ERR_PEL_BYTE_MASK	= 0xf,
	NVME_ERR_PEL_BIT_MASK	= 0x70,
};

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
 * @rsvd7:		   Reserved
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
 * @rsvd232:		   Reserved
 */
struct nvme_smart_log {
	__u8			critical_warning;
	__u8			temperature[2];
	__u8			avail_spare;
	__u8			spare_thresh;
	__u8			percent_used;
	__u8			endu_grp_crit_warn_sumry;
	__u8			rsvd7[25];
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
	__u8			rsvd232[280];
};

/**
 * enum nvme_smart_crit - Critical Warning
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
 */
enum nvme_smart_crit {
	NVME_SMART_CRIT_SPARE		= 1 << 0,
	NVME_SMART_CRIT_TEMPERATURE	= 1 << 1,
	NVME_SMART_CRIT_DEGRADED	= 1 << 2,
	NVME_SMART_CRIT_MEDIA		= 1 << 3,
	NVME_SMART_CRIT_VOLATILE_MEMORY	= 1 << 4,
	NVME_SMART_CRIT_PMR_RO		= 1 << 5,
};

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
 * @NVME_CMD_EFFECTS_CSER_MASK:	Command Submission and Execution Relaxations
 * @NVME_CMD_EFFECTS_CSE_MASK:	Command Submission and Execution
 * @NVME_CMD_EFFECTS_UUID_SEL:	UUID Selection Supported
 */
enum nvme_cmd_effects {
	NVME_CMD_EFFECTS_CSUPP		= 1 << 0,
	NVME_CMD_EFFECTS_LBCC		= 1 << 1,
	NVME_CMD_EFFECTS_NCC		= 1 << 2,
	NVME_CMD_EFFECTS_NIC		= 1 << 3,
	NVME_CMD_EFFECTS_CCC		= 1 << 4,
	NVME_CMD_EFFECTS_CSER_MASK	= 3 << 14,
	NVME_CMD_EFFECTS_CSE_MASK	= 7 << 16,
	NVME_CMD_EFFECTS_UUID_SEL	= 1 << 19,
};

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
	NVME_ST_RESULT_MASK		= 0xf,
};

/**
 * enum nvme_st_code - Self-test Code value
 * @NVME_ST_CODE_RESERVED: Reserved.
 * @NVME_ST_CODE_SHORT:	   Short device self-test operation.
 * @NVME_ST_CODE_EXTENDED: Extended device self-test operation.
 * @NVME_ST_CODE_VS:	   Vendor specific.
 * @NVME_ST_CODE_ABORT:	   Abort device self-test operation.
 * @NVME_ST_CODE_SHIFT:	   Shift amount to get the code value from the
 *			   &struct nvme_st_result.dsts field.
 */
enum nvme_st_code {
	NVME_ST_CODE_RESERVED		= 0x0,
	NVME_ST_CODE_SHORT		= 0x1,
	NVME_ST_CODE_EXTENDED		= 0x2,
	NVME_ST_CODE_VS			= 0xe,
	NVME_ST_CODE_ABORT		= 0xf,
	NVME_ST_CODE_SHIFT		= 4,
};

/**
 * enum nvme_st_curr_op - Current Device Self-Test Operation
 * @NVME_ST_CURR_OP_NOT_RUNNING: No device self-test operation in progress.
 * @NVME_ST_CURR_OP_SHORT:	 Short device self-test operation in progress.
 * @NVME_ST_CURR_OP_EXTENDED:	 Extended device self-test operation in progress.
 * @NVME_ST_CURR_OP_VS:		 Vendor specific.
 * @NVME_ST_CURR_OP_RESERVED:	 Reserved.
 * @NVME_ST_CURR_OP_MASK:	 Mask to get the current operation value from the
 *				 &struct nvme_self_test_log.current_operation field.
 * @NVME_ST_CURR_OP_CMPL_MASK:	 Mask to get the current operation completion value
 *				 from the &struct nvme_self_test_log.completion field.
 */
enum nvme_st_curr_op {
	NVME_ST_CURR_OP_NOT_RUNNING	= 0x0,
	NVME_ST_CURR_OP_SHORT		= 0x1,
	NVME_ST_CURR_OP_EXTENDED	= 0x2,
	NVME_ST_CURR_OP_VS		= 0xe,
	NVME_ST_CURR_OP_RESERVED	= 0xf,
	NVME_ST_CURR_OP_MASK		= 0xf,
	NVME_ST_CURR_OP_CMPL_MASK	= 0x7f,
};

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
 * enum nvme_cmd_get_log_telemetry_host_lsp - Telemetry Host-Initiated log specific field
 * @NVME_LOG_TELEM_HOST_LSP_RETAIN:	Get Telemetry Data Blocks
 * @NVME_LOG_TELEM_HOST_LSP_CREATE:	Create Telemetry Data Blocks
 */
enum nvme_cmd_get_log_telemetry_host_lsp {
	NVME_LOG_TELEM_HOST_LSP_RETAIN			= 0,
	NVME_LOG_TELEM_HOST_LSP_CREATE			= 1,
};

/**
 * struct nvme_telemetry_log - Retrieve internal data specific to the
 *			       manufacturer.
 * @lpi:       Log Identifier, either %NVME_LOG_LID_TELEMETRY_HOST or
 *	       %NVME_LOG_LID_TELEMETRY_CTRL
 * @rsvd1:     Reserved
 * @ieee:      IEEE OUI Identifier is the Organization Unique Identifier (OUI)
 *	       for the controller vendor that is able to interpret the data.
 * @dalb1:     Telemetry Controller-Initiated Data Area 1 Last Block is
 *	       the value of the last block in this area.
 * @dalb2:     Telemetry Controller-Initiated Data Area 1 Last Block is
 *	       the value of the last block in this area.
 * @dalb3:     Telemetry Controller-Initiated Data Area 1 Last Block is
 *	       the value of the last block in this area.
 * @rsvd14:    Reserved
 * @dalb4:     Telemetry Controller-Initiated Data Area 4 Last Block is
 *	       the value of the last block in this area.
 * @rsvd20:    Reserved
 * @hostdgn:   Telemetry Host-Initiated Data Generation Number is a
 *	       value that is incremented each time the host initiates a
 *	       capture of its internal controller state in the controller .
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
	__u8	rsvd20[361];
	__u8	hostdgn;
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
};

/**
 * struct nvme_fid_supported_effects_log - Feature Identifiers Supported and Effects
 * @fid_support: Feature Identifier Supported
 *
 */
struct nvme_fid_supported_effects_log {
	__le32	fid_support[NVME_LOG_FID_SUPPORTED_EFFECTS_MAX];
};

/**
 * enum nvme_mi_cmd_supported_effects - MI Command Supported and Effects Data Structure
 * @NVME_MI_CMD_SUPPORTED_EFFECTS_CSUPP:	Command Supported
 * @NVME_MI_CMD_SUPPORTED_EFFECTS_UDCC:		User Data Content Change
 * @NVME_MI_CMD_SUPPORTED_EFFECTS_NCC:		Namespace Capability Change
 * @NVME_MI_CMD_SUPPORTED_EFFECTS_NIC:		Namespace Inventory Change
 * @NVME_MI_CMD_SUPPORTED_EFFECTS_CCC:		Controller Capability Change
 * @NVME_MI_CMD_SUPPORTED_EFFECTS_SCOPE_SHIFT:	20 bit shift
 * @NVME_MI_CMD_SUPPORTED_EFFECTS_SCOPE_MASK:	12 bit mask - 0xfff
 * @NVME_MI_CMD_SUPPORTED_EFFECTS_SCOPE_NS:	Namespace Scope
 * @NVME_MI_CMD_SUPPORTED_EFFECTS_SCOPE_CTRL:	Controller Scope
 * @NVME_MI_CMD_SUPPORTED_EFFECTS_SCOPE_NVM_SET: NVM Set Scope
 * @NVME_MI_CMD_SUPPORTED_EFFECTS_SCOPE_ENDGRP:	Endurance Group Scope
 * @NVME_MI_CMD_SUPPORTED_EFFECTS_SCOPE_DOMAIN:	Domain Scope
 * @NVME_MI_CMD_SUPPORTED_EFFECTS_SCOPE_NSS:	NVM Subsystem Scope
 */
enum nvme_mi_cmd_supported_effects {
	NVME_MI_CMD_SUPPORTED_EFFECTS_CSUPP	    = 1 << 0,
	NVME_MI_CMD_SUPPORTED_EFFECTS_UDCC	    = 1 << 1,
	NVME_MI_CMD_SUPPORTED_EFFECTS_NCC	    = 1 << 2,
	NVME_MI_CMD_SUPPORTED_EFFECTS_NIC	    = 1 << 3,
	NVME_MI_CMD_SUPPORTED_EFFECTS_CCC	    = 1 << 4,
	NVME_MI_CMD_SUPPORTED_EFFECTS_SCOPE_SHIFT   = 20,
	NVME_MI_CMD_SUPPORTED_EFFECTS_SCOPE_MASK    = 0xfff,
	NVME_MI_CMD_SUPPORTED_EFFECTS_SCOPE_NS	    = 1 << 0,
	NVME_MI_CMD_SUPPORTED_EFFECTS_SCOPE_CTRL    = 1 << 1,
	NVME_MI_CMD_SUPPORTED_EFFECTS_SCOPE_NVM_SET = 1 << 2,
	NVME_MI_CMD_SUPPORTED_EFFECTS_SCOPE_ENDGRP  = 1 << 3,
	NVME_MI_CMD_SUPPORTED_EFFECTS_SCOPE_DOMAIN  = 1 << 4,
	NVME_MI_CMD_SUPPORTED_EFFECTS_SCOPE_NSS	    = 1 << 5,
};

/**
 * struct nvme_mi_cmd_supported_effects_log - NVMe-MI Commands Supported and Effects Log
 * @mi_cmd_support:	NVMe-MI Commands Supported
 * @reserved1:		Reserved
 */
struct nvme_mi_cmd_supported_effects_log {
	__le32	mi_cmd_support[NVME_LOG_MI_CMD_SUPPORTED_EFFECTS_MAX];
	__le32	reserved1[NVME_LOG_MI_CMD_SUPPORTED_EFFECTS_RESERVED];
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
 * struct nvme_resv_notification_log - Reservation Notification Log
 * @lpc:	Log Page Count
 * @rnlpt:	See &enum nvme_resv_notify_rnlpt.
 * @nalp:	Number of Available Log Pages
 * @rsvd9:	Reserved
 * @nsid:	Namespace ID
 * @rsvd16:	Reserved
 */
struct nvme_resv_notification_log {
	__le64	lpc;
	__u8	rnlpt;
	__u8	nalp;
	__u8	rsvd9[2];
	__le32	nsid;
	__u8	rsvd16[48];
};

/**
 * enum nvme_resv_notify_rnlpt -  Reservation Notification Log - Reservation Notification Log Page Type
 * @NVME_RESV_NOTIFY_RNLPT_EMPTY:			Empty Log Page
 * @NVME_RESV_NOTIFY_RNLPT_REGISTRATION_PREEMPTED:	Registration Preempted
 * @NVME_RESV_NOTIFY_RNLPT_RESERVATION_RELEASED:	Reservation Released
 * @NVME_RESV_NOTIFY_RNLPT_RESERVATION_PREEMPTED:	Reservation Preempted
 */
enum nvme_resv_notify_rnlpt {
	NVME_RESV_NOTIFY_RNLPT_EMPTY			= 0,
	NVME_RESV_NOTIFY_RNLPT_REGISTRATION_PREEMPTED	= 1,
	NVME_RESV_NOTIFY_RNLPT_RESERVATION_RELEASED	= 2,
	NVME_RESV_NOTIFY_RNLPT_RESERVATION_PREEMPTED	= 3,
};

/**
 * struct nvme_sanitize_log_page - Sanitize Status (Log Identifier 81h)
 * @sprog:	Sanitize Progress (SPROG): indicates the fraction complete of the
 *		sanitize operation. The value is a numerator of the fraction
 *		complete that has 65,536 (10000h) as its denominator. This value
 *		shall be set to FFFFh if the @sstat field is not set to
 *		%NVME_SANITIZE_SSTAT_STATUS_IN_PROGESS.
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
 * @rsvd32:	Reserved
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
	__u8	rsvd32[480];
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
 * @NVME_SANITIZE_SSTAT_STATUS_IN_PROGESS: A sanitize operation is currently in progress.
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
 */
enum nvme_sanitize_sstat {
	NVME_SANITIZE_SSTAT_STATUS_SHIFT		= 0,
	NVME_SANITIZE_SSTAT_STATUS_MASK			= 0x7,
	NVME_SANITIZE_SSTAT_STATUS_NEVER_SANITIZED	= 0,
	NVME_SANITIZE_SSTAT_STATUS_COMPLETE_SUCCESS	= 1,
	NVME_SANITIZE_SSTAT_STATUS_IN_PROGESS		= 2,
	NVME_SANITIZE_SSTAT_STATUS_COMPLETED_FAILED	= 3,
	NVME_SANITIZE_SSTAT_STATUS_ND_COMPLETE_SUCCESS	= 4,
	NVME_SANITIZE_SSTAT_COMPLETED_PASSES_SHIFT	= 3,
	NVME_SANITIZE_SSTAT_COMPLETED_PASSES_MASK	= 0x1f,
	NVME_SANITIZE_SSTAT_GLOBAL_DATA_ERASED_SHIFT	= 8,
	NVME_SANITIZE_SSTAT_GLOBAL_DATA_ERASED_MASK	= 0x1,
	NVME_SANITIZE_SSTAT_GLOBAL_DATA_ERASED		= 1 << NVME_SANITIZE_SSTAT_GLOBAL_DATA_ERASED_SHIFT,
};

/**
 * struct nvme_zns_changed_zone_log - ZNS Changed Zone List log
 * @nrzid:	Number of Zone Identifiers
 * @rsvd2:	Reserved
 * @zid:	Zone Identifier
 */
struct nvme_zns_changed_zone_log {
	__le16		nrzid;
	__u8		rsvd2[6];
	__le64		zid[NVME_ZNS_CHANGED_ZONES_MAX];
};

/**
 * enum nvme_zns_zt - Zone Descriptor Data Structure - Zone Type
 * @NVME_ZONE_TYPE_SEQWRITE_REQ:	Sequential Write Required
 */
enum nvme_zns_zt {
	NVME_ZONE_TYPE_SEQWRITE_REQ	= 0x2,
};

/**
 * enum nvme_zns_za - Zone Descriptor Data Structure
 * @NVME_ZNS_ZA_ZFC:	Zone Finished by Controller
 * @NVME_ZNS_ZA_FZR:	Finish Zone Recommended
 * @NVME_ZNS_ZA_RZR:	Reset Zone Recommended
 * @NVME_ZNS_ZA_ZRWAV:
 * @NVME_ZNS_ZA_ZDEV:	Zone Descriptor Extension Valid
 */
enum nvme_zns_za {
	NVME_ZNS_ZA_ZFC			= 1 << 0,
	NVME_ZNS_ZA_FZR			= 1 << 1,
	NVME_ZNS_ZA_RZR			= 1 << 2,
	NVME_ZNS_ZA_ZRWAV		= 1 << 3,
	NVME_ZNS_ZA_ZDEV		= 1 << 7,
};

/**
 * enum nvme_zns_zs - Zone Descriptor Data Structure - Zone State
 * @NVME_ZNS_ZS_EMPTY:		Empty state
 * @NVME_ZNS_ZS_IMPL_OPEN:	Implicitly open state
 * @NVME_ZNS_ZS_EXPL_OPEN:	Explicitly open state
 * @NVME_ZNS_ZS_CLOSED:		Closed state
 * @NVME_ZNS_ZS_READ_ONLY:	Read only state
 * @NVME_ZNS_ZS_FULL:		Full state
 * @NVME_ZNS_ZS_OFFLINE:	Offline state
 */
enum nvme_zns_zs {
	NVME_ZNS_ZS_EMPTY		= 0x1,
	NVME_ZNS_ZS_IMPL_OPEN		= 0x2,
	NVME_ZNS_ZS_EXPL_OPEN		= 0x3,
	NVME_ZNS_ZS_CLOSED		= 0x4,
	NVME_ZNS_ZS_READ_ONLY		= 0xd,
	NVME_ZNS_ZS_FULL		= 0xe,
	NVME_ZNS_ZS_OFFLINE		= 0xf,
};

/**
 * struct nvme_zns_desc - Zone Descriptor Data Structure
 * @zt:		Zone Type
 * @zs:		Zone State
 * @za:		Zone Attributes
 * @zai:	Zone Attributes Information
 * @rsvd4:	Reserved
 * @zcap:	Zone Capacity
 * @zslba:	Zone Start Logical Block Address
 * @wp:		Write Pointer
 * @rsvd32:	Reserved
 */
struct nvme_zns_desc {
	__u8	zt;
	__u8	zs;
	__u8	za;
	__u8	zai;
	__u8	rsvd4[4];
	__le64	zcap;
	__le64	zslba;
	__le64	wp;
	__u8	rsvd32[32];
};

/**
 * struct nvme_zone_report - Report Zones Data Structure
 * @nr_zones: Number of descriptors in @entries
 * @rsvd8:    Reserved
 * @entries:  Zoned namespace descriptors
 */
struct nvme_zone_report {
	__le64			nr_zones;
	__u8			rsvd8[56];
	struct nvme_zns_desc	entries[];
};

/**
 * enum nvme_fdp_ruh_type - Reclaim Unit Handle Type
 * @NVME_FDP_RUHT_INITIALLY_ISOLATED:		Initially Isolated
 * @NVME_FDP_RUHT_PERSISTENTLY_ISOLATED:	Persistently Isolated
 */
enum nvme_fdp_ruh_type {
	NVME_FDP_RUHT_INITIALLY_ISOLATED = 1,
	NVME_FDP_RUHT_PERSISTENTLY_ISOLATED = 2,
};

/**
 * struct nvme_fdp_ruh_desc - Reclaim Unit Handle Descriptor
 * @ruht:	Reclaim Unit Handle Type
 * @rsvd1:	Reserved
 */
struct nvme_fdp_ruh_desc {
	__u8 ruht;
	__u8 rsvd1[3];
};

/**
 * enum nvme_fdp_config_fdpa - FDP Attributes
 * @NVME_FDP_CONFIG_FDPA_RGIF_SHIFT:	Reclaim Group Identifier Format Shift
 * @NVME_FDP_CONFIG_FDPA_RGIF_MASK:	Reclaim Group Identifier Format Mask
 * @NVME_FDP_CONFIG_FDPA_FDPVWC_SHIFT:	FDP Volatile Write Cache Shift
 * @NVME_FDP_CONFIG_FDPA_FDPVWC_MASK:	FDP Volatile Write Cache Mask
 * @NVME_FDP_CONFIG_FDPA_VALID_SHIFT:	FDP Configuration Valid Shift
 * @NVME_FDP_CONFIG_FDPA_VALID_MASK:	FDP Configuration Valid Mask
 */
enum nvme_fdp_config_fdpa {
	NVME_FDP_CONFIG_FDPA_RGIF_SHIFT = 0,
	NVME_FDP_CONFIG_FDPA_RGIF_MASK = 0xf,
	NVME_FDP_CONFIG_FDPA_FDPVWC_SHIFT = 4,
	NVME_FDP_CONFIG_FDPA_FDPVWC_MASK = 0x1,
	NVME_FDP_CONFIG_FDPA_VALID_SHIFT = 7,
	NVME_FDP_CONFIG_FDPA_VALID_MASK = 0x1,
};

/**
 * struct nvme_fdp_config_desc - FDP Configuration Descriptor
 * @size:	Descriptor size
 * @fdpa:	FDP Attributes (&enum nvme_fdp_config_fdpa)
 * @vss:	Vendor Specific Size
 * @nrg:	Number of Reclaim Groups
 * @nruh:	Number of Reclaim Unit Handles
 * @maxpids:	Max Placement Identifiers
 * @nnss:	Number of Namespaces Supported
 * @runs:	Reclaim Unit Nominal Size
 * @erutl:	Estimated Reclaim Unit Time Limit
 * @rsvd28:	Reserved
 * @ruhs:	Reclaim Unit Handle descriptors (&struct nvme_fdp_ruh_desc)
 */
struct nvme_fdp_config_desc {
	__le16 size;
	__u8  fdpa;
	__u8  vss;
	__le32 nrg;
	__le16 nruh;
	__le16 maxpids;
	__le32 nnss;
	__le64 runs;
	__le32 erutl;
	__u8  rsvd28[36];
	struct nvme_fdp_ruh_desc ruhs[];
};

/**
 * struct nvme_fdp_config_log - FDP Configurations Log Page
 * @n:		Number of FDP Configurations
 * @version:	Log page version
 * @rsvd3:	Reserved
 * @size:	Log page size in bytes
 * @rsvd8:	Reserved
 * @configs:	FDP Configuration descriptors (&struct nvme_fdp_config_desc)
 */
struct nvme_fdp_config_log {
	__le16 n;
	__u8  version;
	__u8  rsvd3;
	__le32 size;
	__u8  rsvd8[8];
	struct nvme_fdp_config_desc configs[];
};

/**
 * enum nvme_fdp_ruha - Reclaim Unit Handle Attributes
 * @NVME_FDP_RUHA_HOST_SHIFT:	Host Specified Reclaim Unit Handle Shift
 * @NVME_FDP_RUHA_HOST_MASK:	Host Specified Reclaim Unit Handle Mask
 * @NVME_FDP_RUHA_CTRL_SHIFT:	Controller Specified Reclaim Unit Handle Shift
 * @NVME_FDP_RUHA_CTRL_MASK:	Controller Specified Reclaim Unit Handle Mask
 */
enum nvme_fdp_ruha {
	NVME_FDP_RUHA_HOST_SHIFT	= 0,
	NVME_FDP_RUHA_HOST_MASK		= 0x1,
	NVME_FDP_RUHA_CTRL_SHIFT	= 1,
	NVME_FDP_RUHA_CTRL_MASK		= 0x1,
};

/**
 * struct nvme_fdp_ruhu_desc - Reclaim Unit Handle Usage Descriptor
 * @ruha:	Reclaim Unit Handle Attributes (&enum nvme_fdp_ruha)
 * @rsvd1:	Reserved
 */
struct nvme_fdp_ruhu_desc {
	__u8 ruha;
	__u8 rsvd1[7];
};

/**
 * struct nvme_fdp_ruhu_log - Reclaim Unit Handle Usage Log Page
 * @nruh:	Number of Reclaim Unit Handles
 * @rsvd2:	Reserved
 * @ruhus:	Reclaim Unit Handle Usage descriptors
 */
struct nvme_fdp_ruhu_log {
	__le16 nruh;
	__u8  rsvd2[6];
	struct nvme_fdp_ruhu_desc ruhus[];
};

/**
 * struct nvme_fdp_stats_log - FDP Statistics Log Page
 * @hbmw:	Host Bytes with Metadata Written
 * @mbmw:	Media Bytes with Metadata Written
 * @mbe:	Media Bytes Erased
 * @rsvd48:	Reserved
 */
struct nvme_fdp_stats_log {
	__u8 hbmw[16];
	__u8 mbmw[16];
	__u8 mbe[16];
	__u8 rsvd48[16];
};

/**
 * enum nvme_fdp_event_type - FDP Event Types
 * @NVME_FDP_EVENT_RUNFW:	Reclaim Unit Not Fully Written
 * @NVME_FDP_EVENT_RUTLE:	Reclaim Unit Time Limit Exceeded
 * @NVME_FDP_EVENT_RESET:	Controller Level Reset Modified Reclaim Unit Handles
 * @NVME_FDP_EVENT_PID:		Invalid Placement Identifier
 * @NVME_FDP_EVENT_REALLOC:	Media Reallocated
 * @NVME_FDP_EVENT_MODIFY:	Implicitly Modified Reclaim Unit Handle
 */
enum nvme_fdp_event_type {
	/* Host Events */
	NVME_FDP_EVENT_RUNFW	= 0x0,
	NVME_FDP_EVENT_RUTLE	= 0x1,
	NVME_FDP_EVENT_RESET	= 0x2,
	NVME_FDP_EVENT_PID	= 0x3,

	/* Controller Events */
	NVME_FDP_EVENT_REALLOC	= 0x80,
	NVME_FDP_EVENT_MODIFY	= 0x81,
};

/**
 * enum nvme_fdp_event_realloc_flags - Media Reallocated Event Type Specific Flags
 * @NVME_FDP_EVENT_REALLOC_F_LBAV:	LBA Valid
 */
enum nvme_fdp_event_realloc_flags {
	NVME_FDP_EVENT_REALLOC_F_LBAV = 1 << 0,
};

/**
 * struct nvme_fdp_event_realloc - Media Reallocated Event Type Specific Information
 * @flags:	Event Type Specific flags (&enum nvme_fdp_event_realloc_flags)
 * @rsvd1:	Reserved
 * @nlbam:	Number of LBAs Moved
 * @lba:	Logical Block Address
 * @rsvd12:	Reserved
 */
struct nvme_fdp_event_realloc {
	__u8  flags;
	__u8  rsvd1;
	__le16 nlbam;
	__le64 lba;
	__u8  rsvd12[4];
};

/**
 * enum nvme_fdp_event_flags - FDP Event Flags
 * @NVME_FDP_EVENT_F_PIV:	Placement Identifier Valid
 * @NVME_FDP_EVENT_F_NSIDV:	Namespace Identifier Valid
 * @NVME_FDP_EVENT_F_LV:	Location Valid
 */
enum nvme_fdp_event_flags {
	NVME_FDP_EVENT_F_PIV	= 1 << 0,
	NVME_FDP_EVENT_F_NSIDV	= 1 << 1,
	NVME_FDP_EVENT_F_LV	= 1 << 2,
};

/**
 * struct nvme_fdp_event - FDP Event
 * @type:		Event Type (&enum nvme_fdp_event_type)
 * @flags:		Event Flags (&enum nvme_fdp_event_flags)
 * @pid:		Placement Identifier
 * @ts:			Timestamp
 * @nsid:		Namespace Identifier
 * @type_specific:	Event Type Specific Information
 * @rgid:		Reclaim Group Identifier
 * @ruhid:		Reclaim Unit Handle Identifier
 * @rsvd35:		Reserved
 * @vs:			Vendor Specific
 */
struct nvme_fdp_event {
	__u8  type;
	__u8  flags;
	__le16 pid;
	struct nvme_timestamp ts;
	__le32 nsid;
	__u8  type_specific[16];
	__le16 rgid;
	__u8  ruhid;
	__u8  rsvd35[5];
	__u8  vs[24];
};

/**
 * struct nvme_fdp_events_log - FDP Events Log Page
 * @n:		Number of FDP Events
 * @rsvd4:	Reserved
 * @events:	FDP Events (&struct nvme_fdp_event)
 */
struct nvme_fdp_events_log {
	__le32 n;
	__u8  rsvd4[60];
	struct nvme_fdp_event events[63];
};

/**
 * struct nvme_feat_fdp_events_cdw11 - FDP Events Feature Command Dword 11
 * @phndl:	Placement Handle
 * @noet:	Number of FDP Event Types
 * @rsvd24:	Reserved
 */
struct nvme_feat_fdp_events_cdw11 {
	__le16 phndl;
	__u8  noet;
	__u8  rsvd24;
};

/**
 * enum nvme_fdp_supported_event_attributes - Supported FDP Event Attributes
 * @NVME_FDP_SUPP_EVENT_ENABLED_SHIFT:	FDP Event Enable Shift
 * @NVME_FDP_SUPP_EVENT_ENABLED_MASK:	FDP Event Enable Mask
 */
enum nvme_fdp_supported_event_attributes {
	NVME_FDP_SUPP_EVENT_ENABLED_SHIFT = 0,
	NVME_FDP_SUPP_EVENT_ENABLED_MASK  = 0x1,
};

/**
 * struct nvme_fdp_supported_event_desc - Supported FDP Event Descriptor
 * @evt:	FDP Event Type
 * @evta:	FDP Event Type Attributes (&enum nvme_fdp_supported_event_attributes)
 */
struct nvme_fdp_supported_event_desc {
	__u8 evt;
	__u8 evta;
};

/**
 * struct nvme_fdp_ruh_status_desc - Reclaim Unit Handle Status Descriptor
 * @pid:	Placement Identifier
 * @ruhid:	Reclaim Unit Handle Identifier
 * @earutr:	Estimated Active Reclaim Unit Time Remaining
 * @ruamw:	Reclaim Unit Available Media Writes
 * @rsvd16:	Reserved
 */
struct nvme_fdp_ruh_status_desc {
	__le16 pid;
	__le16 ruhid;
	__le32 earutr;
	__le64 ruamw;
	__u8  rsvd16[16];
};

/**
 * struct nvme_fdp_ruh_status - Reclaim Unit Handle Status
 * @rsvd0:	Reserved
 * @nruhsd:	Number of Reclaim Unit Handle Status Descriptors
 * @ruhss:	Reclaim Unit Handle Status descriptors
 */
struct nvme_fdp_ruh_status {
	__u8  rsvd0[14];
	__le16 nruhsd;
	struct nvme_fdp_ruh_status_desc ruhss[];
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
 * @NVME_LBART_ATTRIB_TEMP:	Temp
 * @NVME_LBART_ATTRIB_HIDE:	Hidden
 */
enum nvme_lbart {
	NVME_LBART_TYPE_GP	= 0,
	NVME_LBART_TYPE_FS	= 1,
	NVME_LBART_TYPE_RAID	= 2,
	NVME_LBART_TYPE_CACHE	= 3,
	NVME_LBART_TYPE_SWAP	= 4,
	NVME_LBART_ATTRIB_TEMP	= 1 << 0,
	NVME_LBART_ATTRIB_HIDE	= 1 << 1,
};

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
 * @rsvd3:	Reserved
 * @cdfe:       Copy Descriptor Formats Enable
 * @rsvd6:	Reserved
 */
struct nvme_feat_host_behavior {
	__u8 acre;
	__u8 etdas;
	__u8 lbafee;
	__u8 rsvd3;
        __u16 cdfe;
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
 * struct nvme_dsm_range - Dataset Management - Range Definition
 * @cattr:	Context Attributes
 * @nlb:	Length in logical blocks
 * @slba:	Starting LBA
 */
struct nvme_dsm_range {
	__le32	cattr;
	__le32	nlb;
	__le64	slba;
};

/**
 * struct nvme_copy_range - Copy - Source Range Entries Descriptor Format
 * @rsvd0:	Reserved
 * @slba:	Starting LBA
 * @nlb:	Number of Logical Blocks
 * @rsvd18:	Reserved
 * @eilbrt:	Expected Initial Logical Block Reference Tag /
 *		Expected Logical Block Storage Tag
 * @elbatm:	Expected Logical Block Application Tag Mask
 * @elbat:	Expected Logical Block Application Tag
 */
struct nvme_copy_range {
	__u8			rsvd0[8];
	__le64			slba;
	__le16			nlb;
	__u8			rsvd18[6];
	__le32			eilbrt;
	__le16			elbat;
	__le16			elbatm;
};

/**
 * struct nvme_copy_range_f1 - Copy - Source Range Entries Descriptor Format 1h
 * @rsvd0:	Reserved
 * @slba:	Starting LBA
 * @nlb:	Number of Logical Blocks
 * @rsvd18:	Reserved
 * @elbt:	Expected Initial Logical Block Reference Tag /
 *		Expected Logical Block Storage Tag
 * @elbatm:	Expected Logical Block Application Tag Mask
 * @elbat:	Expected Logical Block Application Tag
 */
struct nvme_copy_range_f1 {
	__u8			rsvd0[8];
	__le64			slba;
	__le16			nlb;
	__u8			rsvd18[8];
	__u8			elbt[10];
	__le16			elbat;
	__le16			elbatm;
};

/**
 * enum nvme_copy_range_sopt - NVMe Copy Range Source Options
 * @NVME_COPY_SOPT_FCO:	NVMe Copy Source Option Fast Copy Only
 */
enum nvme_copy_range_sopt {
        NVME_COPY_SOPT_FCO = 1 << 15,
};

/**
 * struct nvme_copy_range_f2 - Copy - Source Range Entries Descriptor Format 2h
 * @snsid:	Source Namespace Identifier
 * @rsvd4:	Reserved
 * @slba:	Starting LBA
 * @nlb:	Number of Logical Blocks
 * @rsvd18:	Reserved
 * @sopt:	Source Options
 * @eilbrt:	Expected Initial Logical Block Reference Tag /
 *		Expected Logical Block Storage Tag
 * @elbatm:	Expected Logical Block Application Tag Mask
 * @elbat:	Expected Logical Block Application Tag
 */
struct nvme_copy_range_f2 {
	__le32			snsid;
	__u8			rsvd4[4];
	__le64			slba;
	__le16			nlb;
	__u8			rsvd18[4];
	__le16			sopt;
	__le32			eilbrt;
	__le16			elbat;
	__le16			elbatm;
};

/**
 * struct nvme_copy_range_f3 - Copy - Source Range Entries Descriptor Format 3h
 * @snsid:	Source Namespace Identifier
 * @rsvd4:	Reserved
 * @slba:	Starting LBA
 * @nlb:	Number of Logical Blocks
 * @rsvd18:	Reserved
 * @sopt:	Source Options
 * @rsvd24:	Reserved
 * @elbt:	Expected Initial Logical Block Reference Tag /
 *		Expected Logical Block Storage Tag
 * @elbatm:	Expected Logical Block Application Tag Mask
 * @elbat:	Expected Logical Block Application Tag
 */
struct nvme_copy_range_f3 {
	__le32			snsid;
	__u8			rsvd4[4];
	__le64			slba;
	__le16			nlb;
	__u8			rsvd18[4];
	__le16			sopt;
	__u8			rsvd24[2];
	__u8			elbt[10];
	__le16			elbat;
	__le16			elbatm;
};

/**
 * struct nvme_registered_ctrl - Registered Controller Data Structure
 * @cntlid:	Controller ID
 * @rcsts:	Reservation Status
 * @rsvd3:	Reserved
 * @hostid:	Host Identifier
 * @rkey:	Reservation Key
 */
struct nvme_registered_ctrl {
	__le16	cntlid;
	__u8	rcsts;
	__u8	rsvd3[5];
	__le64	hostid;
	__le64	rkey;
};

/**
 * struct nvme_registered_ctrl_ext - Registered Controller Extended Data Structure
 * @cntlid:	Controller ID
 * @rcsts:	Reservation Status
 * @rsvd3:	Reserved
 * @rkey:	Reservation Key
 * @hostid:	Host Identifier
 * @rsvd32:	Reserved
 */
struct nvme_registered_ctrl_ext {
	__le16	cntlid;
	__u8	rcsts;
	__u8	rsvd3[5];
	__le64	rkey;
	__u8	hostid[16];
	__u8	rsvd32[32];
};

/**
 * struct nvme_resv_status - Reservation Status Data Structure
 * @gen:	Generation
 * @rtype:	Reservation Type
 * @regctl:	Number of Registered Controllers
 * @rsvd7:	Reserved
 * @ptpls:	Persist Through Power Loss State
 * @rsvd10:	Reserved
 * @rsvd24:	Reserved
 * @regctl_eds: Registered Controller Extended Data Structure
 * @regctl_ds:	Registered Controller Data Structure
 */
struct nvme_resv_status {
	__le32	gen;
	__u8	rtype;
	__u8	regctl[2];
	__u8	rsvd7[2];
	__u8	ptpls;
	__u8	rsvd10[14];
	union {
		struct {
			__u8	rsvd24[40];
			struct nvme_registered_ctrl_ext regctl_eds[0];
		};
		struct nvme_registered_ctrl regctl_ds[0];
	};
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
 * @NVME_AER_CSS:	NVM Command Set Specific events
 * @NVME_AER_VS:	Vendor Specific event
 */
enum nvme_ae_type {
	NVME_AER_ERROR				= 0,
	NVME_AER_SMART				= 1,
	NVME_AER_NOTICE				= 2,
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
 * @NVME_AER_NOTICE_NS_CHANGED:		Namespace Attribute Changed
 * @NVME_AER_NOTICE_FW_ACT_STARTING:	Firmware Activation Starting
 * @NVME_AER_NOTICE_TELEMETRY:		Telemetry Log Changed
 * @NVME_AER_NOTICE_ANA:		Asymmetric Namespace Access Change
 * @NVME_AER_NOTICE_PL_EVENT:		Predictable Latency Event Aggregate Log Change
 * @NVME_AER_NOTICE_LBA_STATUS_ALERT:	LBA Status Information Alert
 * @NVME_AER_NOTICE_EG_EVENT:		Endurance Group Event Aggregate Log Page Change
 * @NVME_AER_NOTICE_DISC_CHANGED:	Discovery Log Page Change
 */
enum nvme_ae_info_notice {
	NVME_AER_NOTICE_NS_CHANGED			= 0x00,
	NVME_AER_NOTICE_FW_ACT_STARTING			= 0x01,
	NVME_AER_NOTICE_TELEMETRY			= 0x02,
	NVME_AER_NOTICE_ANA				= 0x03,
	NVME_AER_NOTICE_PL_EVENT			= 0x04,
	NVME_AER_NOTICE_LBA_STATUS_ALERT		= 0x05,
	NVME_AER_NOTICE_EG_EVENT			= 0x06,
	NVME_AER_NOTICE_DISC_CHANGED			= 0xf0,
};

/**
 * enum nvme_subsys_type - Type of the NVM subsystem.
 * @NVME_NQN_DISC: Discovery type target subsystem. Describes a referral to another
 *		   Discovery Service composed of Discovery controllers that provide
 *		   additional discovery records. Multiple Referral entries may
 *		   be reported for each Discovery Service (if that Discovery Service
 *		   has multiple NVM subsystem ports or supports multiple protocols).
 * @NVME_NQN_NVME: NVME type target subsystem. Describes an NVM subsystem whose
 *		   controllers may have attached namespaces (an NVM subsystem
 *		   that is not composed of Discovery controllers). Multiple NVM
 *		   Subsystem entries may be reported for each NVM subsystem if
 *		   that NVM subsystem has multiple NVM subsystem ports.
 * @NVME_NQN_CURR: Current Discovery type target subsystem. Describes this Discovery
 *		   subsystem (the Discovery Service that contains the controller
 *		   processing the Get Log Page command). Multiple Current Discovery
 *		   Subsystem entries may be reported for this Discovery subsystem
 *		   if the current Discovery subsystem has multiple NVM subsystem
 *		   ports.
 */
enum nvme_subsys_type {
	NVME_NQN_DISC	= 1,
	NVME_NQN_NVME	= 2,
	NVME_NQN_CURR	= 3,
};

#define NVME_DISC_SUBSYS_NAME	"nqn.2014-08.org.nvmexpress.discovery"
#define NVME_RDMA_IP_PORT	4420
#define NVME_DISC_IP_PORT	8009

/* However the max length of a qualified name is another size */
#define NVMF_NQN_SIZE		223
#define NVMF_TRSVCID_SIZE	32

/**
 * enum nvmf_disc_eflags - Discovery Log Page entry flags.
 * @NVMF_DISC_EFLAGS_NONE:	 Indicates that none of the DUPRETINFO or EPCSD
 *				 features are supported.
 * @NVMF_DISC_EFLAGS_DUPRETINFO: Duplicate Returned Information (DUPRETINFO):
 *				 Indicates that using the content of this entry
 *				 to access this Discovery Service returns the same
 *				 information that is returned by using the content
 *				 of other entries in this log page that also have
 *				 this flag set.
 * @NVMF_DISC_EFLAGS_EPCSD:	 Explicit Persistent Connection Support for Discovery (EPCSD):
 *				 Indicates that Explicit Persistent Connections are
 *      			 supported for the Discovery controller.
 * @NVMF_DISC_EFLAGS_NCC:	 No CDC Connectivity (NCC): If set to
 *      			 '1', then no DDC that describes this entry
 *      			 is currently connected to the CDC. If
 *      			 cleared to '0', then at least one DDC that
 *      			 describes this entry is currently
 *      			 connected to the CDC. If the Discovery
 *      			 controller returning this log page is not
 *      			 a CDC, then this bit shall be cleared to
 *      			 '0' and should be ignored by the host.
 */
enum nvmf_disc_eflags {
	NVMF_DISC_EFLAGS_NONE		= 0,
	NVMF_DISC_EFLAGS_DUPRETINFO	= 1 << 0,
	NVMF_DISC_EFLAGS_EPCSD		= 1 << 1,
	NVMF_DISC_EFLAGS_NCC		= 1 << 2,
};

/* Backwards compatibility. Will be removed with next major release */
#define NVMF_DISC_EFLAGS_BOTH (NVMF_DISC_EFLAGS_DUPRETINFO | NVMF_DISC_EFLAGS_EPCSD)

/**
 * union nvmf_tsas - Transport Specific Address Subtype
 * @common:  Common transport specific attributes
 * @rdma:    RDMA transport specific attribute settings
 * @qptype:  RDMA QP Service Type (RDMA_QPTYPE): Specifies the type of RDMA
 *	     Queue Pair. See &enum nvmf_rdma_qptype.
 * @prtype:  RDMA Provider Type (RDMA_PRTYPE): Specifies the type of RDMA
 *	     provider. See &enum nvmf_rdma_prtype.
 * @cms:     RDMA Connection Management Service (RDMA_CMS): Specifies the type
 *	     of RDMA IP Connection Management Service. See &enum nvmf_rdma_cms.
 * @pkey:    RDMA_PKEY: Specifies the Partition Key when AF_IB (InfiniBand)
 *	     address family type is used.
 * @tcp:     TCP transport specific attribute settings
 * @sectype: Security Type (SECTYPE): Specifies the type of security used by the
 *	     NVMe/TCP port. If SECTYPE is a value of 0h (No Security), then the
 *	     host shall set up a normal TCP connection. See &enum nvmf_tcp_sectype.
 */
union nvmf_tsas {
	char		common[NVMF_TSAS_SIZE];
	struct rdma {
		__u8	qptype;
		__u8	prtype;
		__u8	cms;
		__u8	rsvd3[5];
		__le16	pkey;
		__u8	rsvd10[246];
	} rdma;
	struct tcp {
		__u8	sectype;
	} tcp;
};

/**
 * struct nvmf_disc_log_entry - Discovery Log Page entry
 * @trtype:  Transport Type (TRTYPE): Specifies the NVMe Transport type.
 *	     See &enum nvmf_trtype.
 * @adrfam:  Address Family (ADRFAM): Specifies the address family.
 *	     See &enum nvmf_addr_family.
 * @subtype: Subsystem Type (SUBTYPE): Specifies the type of the NVM subsystem
 *	     that is indicated in this entry. See &enum nvme_subsys_type.
 * @treq:    Transport Requirements (TREQ): Indicates requirements for the NVMe
 *	     Transport. See &enum nvmf_treq.
 * @portid:  Port ID (PORTID): Specifies a particular NVM subsystem port.
 *	     Different NVMe Transports or address families may utilize the same
 *	     Port ID value (e.g. a Port ID may support both iWARP and RoCE).
 * @cntlid:  Controller ID (CNTLID): Specifies the controller ID. If the NVM
 *	     subsystem uses a dynamic controller model, then this field shall
 *	     be set to FFFFh. If the NVM subsystem uses a static controller model,
 *	     then this field may be set to a specific controller ID (values 0h
 *	     to FFEFh are valid). If the NVM subsystem uses a static controller
 *	     model and the value indicated is FFFEh, then the host should remember
 *	     the Controller ID returned as part of the Fabrics Connect command
 *	     in order to re-establish an association in the future with the same
 *	     controller.
 * @asqsz:   Admin Max SQ Size (ASQSZ): Specifies the maximum size of an Admin
 *	     Submission Queue. This applies to all controllers in the NVM
 *	     subsystem. The value shall be a minimum of 32 entries.
 * @eflags:  Entry Flags (EFLAGS): Indicates additional information related to
 *	     the current entry. See &enum nvmf_disc_eflags.
 * @rsvd12:  Reserved
 * @trsvcid: Transport Service Identifier (TRSVCID): Specifies the NVMe Transport
 *	     service identifier as an ASCII string. The NVMe Transport service
 *	     identifier is specified by the associated NVMe Transport binding
 *	     specification.
 * @rsvd64:  Reserved
 * @subnqn:  NVM Subsystem Qualified Name (SUBNQN): NVMe Qualified Name (NQN)
 *	     that uniquely identifies the NVM subsystem. For a subsystem, if that
 *	     Discovery subsystem has a unique NQN (i.e., the NVM Subsystem NVMe
 *	     Qualified Name (SUBNQN) field in that Discovery subsystem's Identify
 *	     Controller data structure contains a unique NQN value), then the
 *	     value returned shall be that unique NQN. If the Discovery subsystem
 *	     does not have a unique NQN, then the value returned shall be the
 *	     well-known Discovery Service NQN (nqn.2014-08.org.nvmexpress.discovery).
 * @traddr:  Transport Address (TRADDR): Specifies the address of the NVM subsystem
 *	     that may be used for a Connect command as an ASCII string. The
 *	     Address Family field describes the reference for parsing this field.
 * @tsas:    Transport specific attribute settings
 */
struct nvmf_disc_log_entry {
	__u8		trtype;
	__u8		adrfam;
	__u8		subtype;
	__u8		treq;
	__le16		portid;
	__le16		cntlid;
	__le16		asqsz;
	__le16		eflags;
	__u8		rsvd12[20];
	char		trsvcid[NVMF_TRSVCID_SIZE];
	__u8		rsvd64[192];
	char		subnqn[NVME_NQN_LENGTH];
	char		traddr[NVMF_TRADDR_SIZE];
	union nvmf_tsas	tsas;
};

/**
 * enum nvmf_trtype - Transport Type codes for Discovery Log Page entry TRTYPE field
 * @NVMF_TRTYPE_UNSPECIFIED:	Not indicated
 * @NVMF_TRTYPE_RDMA:		RDMA
 * @NVMF_TRTYPE_FC:		Fibre Channel
 * @NVMF_TRTYPE_TCP:		TCP
 * @NVMF_TRTYPE_LOOP:		Intra-host Transport (i.e., loopback), reserved
 *				for host usage.
 * @NVMF_TRTYPE_MAX:		Maximum value for &enum nvmf_trtype
 */
enum nvmf_trtype {
	NVMF_TRTYPE_UNSPECIFIED	= 0,
	NVMF_TRTYPE_RDMA	= 1,
	NVMF_TRTYPE_FC		= 2,
	NVMF_TRTYPE_TCP		= 3,
	NVMF_TRTYPE_LOOP	= 254,
	NVMF_TRTYPE_MAX,
};

/**
 * enum nvmf_addr_family - Address Family codes for Discovery Log Page entry ADRFAM field
 * @NVMF_ADDR_FAMILY_PCI:	PCIe
 * @NVMF_ADDR_FAMILY_IP4:	AF_INET: IPv4 address family.
 * @NVMF_ADDR_FAMILY_IP6:	AF_INET6: IPv6 address family.
 * @NVMF_ADDR_FAMILY_IB:	AF_IB: InfiniBand address family.
 * @NVMF_ADDR_FAMILY_FC:	Fibre Channel address family.
 * @NVMF_ADDR_FAMILY_LOOP:	Intra-host Transport (i.e., loopback), reserved
 *				for host usage.
 */
enum nvmf_addr_family {
	NVMF_ADDR_FAMILY_PCI	= 0,
	NVMF_ADDR_FAMILY_IP4	= 1,
	NVMF_ADDR_FAMILY_IP6	= 2,
	NVMF_ADDR_FAMILY_IB	= 3,
	NVMF_ADDR_FAMILY_FC	= 4,
	NVMF_ADDR_FAMILY_LOOP	= 254,
};

/**
 * enum nvmf_treq - Transport Requirements codes for Discovery Log Page entry TREQ field
 * @NVMF_TREQ_NOT_SPECIFIED:	Not specified
 * @NVMF_TREQ_REQUIRED:		Required
 * @NVMF_TREQ_NOT_REQUIRED:	Not Required
 * @NVMF_TREQ_DISABLE_SQFLOW:	SQ flow control disable supported
 */
enum nvmf_treq {
	NVMF_TREQ_NOT_SPECIFIED		= 0,
	NVMF_TREQ_REQUIRED		= 1,
	NVMF_TREQ_NOT_REQUIRED		= 2,
	NVMF_TREQ_DISABLE_SQFLOW	= 4,
};

/**
 * enum nvmf_rdma_qptype - RDMA QP Service Type codes for Discovery Log Page
 *	   entry TSAS RDMA_QPTYPE field
 * @NVMF_RDMA_QPTYPE_CONNECTED:	Reliable Connected
 * @NVMF_RDMA_QPTYPE_DATAGRAM:	Reliable Datagram
 */
enum nvmf_rdma_qptype {
	NVMF_RDMA_QPTYPE_CONNECTED	= 1,
	NVMF_RDMA_QPTYPE_DATAGRAM	= 2,
};

/**
 * enum nvmf_rdma_prtype - RDMA Provider Type codes for Discovery Log Page
 *	  entry TSAS RDMA_PRTYPE field
 * @NVMF_RDMA_PRTYPE_NOT_SPECIFIED: No Provider Specified
 * @NVMF_RDMA_PRTYPE_IB:	    InfiniBand
 * @NVMF_RDMA_PRTYPE_ROCE:	    InfiniBand RoCE
 * @NVMF_RDMA_PRTYPE_ROCEV2:	    InfiniBand RoCEV2
 * @NVMF_RDMA_PRTYPE_IWARP:	    iWARP
 */
enum nvmf_rdma_prtype {
	NVMF_RDMA_PRTYPE_NOT_SPECIFIED	= 1,
	NVMF_RDMA_PRTYPE_IB		= 2,
	NVMF_RDMA_PRTYPE_ROCE		= 3,
	NVMF_RDMA_PRTYPE_ROCEV2		= 4,
	NVMF_RDMA_PRTYPE_IWARP		= 5,
};

/**
 * enum nvmf_rdma_cms - RDMA Connection Management Service Type codes for
 *	  Discovery Log Page entry TSAS RDMA_CMS field
 * @NVMF_RDMA_CMS_RDMA_CM: Sockets based endpoint addressing
 *
 */
enum nvmf_rdma_cms {
	NVMF_RDMA_CMS_RDMA_CM	= 1,
};

/**
 * enum nvmf_tcp_sectype - Transport Specific Address Subtype Definition for
 *	  NVMe/TCP Transport
 * @NVMF_TCP_SECTYPE_NONE:  No Security
 * @NVMF_TCP_SECTYPE_TLS:   Transport Layer Security version 1.2
 * @NVMF_TCP_SECTYPE_TLS13: Transport Layer Security version 1.3 or a subsequent
 *			    version. The TLS protocol negotiates the version and
 *			    cipher suite for each TCP connection.
 */
enum nvmf_tcp_sectype {
	NVMF_TCP_SECTYPE_NONE	= 0,
	NVMF_TCP_SECTYPE_TLS	= 1,
	NVMF_TCP_SECTYPE_TLS13	= 2,
};

/**
 * enum nvmf_log_discovery_lid_support - Discovery log specific support
 * @NVMF_LOG_DISC_LID_NONE:	None
 * @NVMF_LOG_DISC_LID_EXTDLPES:	Extended Discovery Log Page Entries Supported
 * @NVMF_LOG_DISC_LID_PLEOS:	Port Local Entries Only Supported
 * @NVMF_LOG_DISC_LID_ALLSUBES:	All NVM Subsystem Entries Supported
 */
enum nvmf_log_discovery_lid_support {
	NVMF_LOG_DISC_LID_NONE		= 0,
	NVMF_LOG_DISC_LID_EXTDLPES	= (1 << 0),
	NVMF_LOG_DISC_LID_PLEOS		= (1 << 1),
	NVMF_LOG_DISC_LID_ALLSUBES	= (1 << 2),
};

/**
 * enum nvmf_log_discovery_lsp - Discovery log specific field
 * @NVMF_LOG_DISC_LSP_NONE:	None
 * @NVMF_LOG_DISC_LSP_EXTDLPE:	Extended Discovery Log Page Entries
 * @NVMF_LOG_DISC_LSP_PLEO:	Port Local Entries Only
 * @NVMF_LOG_DISC_LSP_ALLSUBE:	All NVM Subsystem Entries
 */
enum nvmf_log_discovery_lsp {
	NVMF_LOG_DISC_LSP_NONE		= 0,
	NVMF_LOG_DISC_LSP_EXTDLPE	= (1 << 0),
	NVMF_LOG_DISC_LSP_PLEO		= (1 << 1),
	NVMF_LOG_DISC_LSP_ALLSUBE	= (1 << 2),
};

/**
 * struct nvmf_discovery_log - Discovery Log Page (Log Identifier 70h)
 * @genctr:  Generation Counter (GENCTR): Indicates the version of the discovery
 *	     information, starting at a value of 0h. For each change in the
 *	     Discovery Log Page, this counter is incremented by one. If the value
 *	     of this field is FFFFFFFF_FFFFFFFFh, then the field shall be cleared
 *	     to 0h when incremented (i.e., rolls over to 0h).
 * @numrec:  Number of Records (NUMREC): Indicates the number of records
 *	     contained in the log.
 * @recfmt:  Record Format (RECFMT): Specifies the format of the Discovery Log
 *	     Page. If a new format is defined, this value is incremented by one.
 *	     The format of the record specified in this definition shall be 0h.
 * @rsvd14:  Reserved
 * @entries: Discovery Log Page Entries - see &struct nvmf_disc_log_entry.
 */
struct nvmf_discovery_log {
	__le64		genctr;
	__le64		numrec;
	__le16		recfmt;
	__u8		rsvd14[1006];
	struct nvmf_disc_log_entry entries[];
};

/*
 * Discovery Information Management (DIM) command. This is sent by a
 * host to a Discovery Controller (DC) to perform explicit registration.
 */
#define NVMF_ENAME_LEN	256
#define NVMF_EVER_LEN	64

/**
 * enum nvmf_dim_tas - Discovery Information Management Task
 * @NVMF_DIM_TAS_REGISTER:   Register
 * @NVMF_DIM_TAS_DEREGISTER: Deregister
 * @NVMF_DIM_TAS_UPDATE:     Update
 */
enum nvmf_dim_tas {
	NVMF_DIM_TAS_REGISTER	= 0x00,
	NVMF_DIM_TAS_DEREGISTER	= 0x01,
	NVMF_DIM_TAS_UPDATE	= 0x02,
};

/**
 * enum nvmf_dim_entfmt - Discovery Information Management Entry Format
 * @NVMF_DIM_ENTFMT_BASIC:    Basic discovery information entry
 * @NVMF_DIM_ENTFMT_EXTENDED: Extended discovery information entry
 */
enum nvmf_dim_entfmt {
	NVMF_DIM_ENTFMT_BASIC		= 0x01,
	NVMF_DIM_ENTFMT_EXTENDED	= 0x02,
};

/**
 * enum nvmf_dim_etype -Discovery Information Management Entity Type
 * @NVMF_DIM_ETYPE_HOST: Host
 * @NVMF_DIM_ETYPE_DDC:	 Direct Discovery controller
 * @NVMF_DIM_ETYPE_CDC:	 Centralized Discovery controller
 */
enum nvmf_dim_etype {
	NVMF_DIM_ETYPE_HOST	= 0x01,
	NVMF_DIM_ETYPE_DDC	= 0x02,
	NVMF_DIM_ETYPE_CDC	= 0x03,
};

/**
 * enum nvmf_exattype - Extended Attribute Type
 * @NVMF_EXATTYPE_HOSTID:  Host Identifier
 * @NVMF_EXATTYPE_SYMNAME: Symblic Name
 */
enum nvmf_exattype {
	NVMF_EXATTYPE_HOSTID	= 0x01,
	NVMF_EXATTYPE_SYMNAME	= 0x02,
};

/**
 * struct nvmf_ext_attr - Extended Attribute (EXAT)
 * @exattype: Extended Attribute Type (EXATTYPE) - see @enum nvmf_exattype
 * @exatlen:  Extended Attribute Length (EXATLEN)
 * @exatval:  Extended Attribute Value (EXATVAL) - size allocated for array
 *	      must be a multiple of 4 bytes
 */
struct nvmf_ext_attr {
	__le16	exattype;
	__le16	exatlen;
	__u8	exatval[];
};

/**
 * struct nvmf_ext_die - Extended Discovery Information Entry (DIE)
 * @trtype:   Transport Type (&enum nvmf_trtype)
 * @adrfam:   Address Family (&enum nvmf_addr_family)
 * @subtype:  Subsystem Type (&enum nvme_subsys_type)
 * @treq:     Transport Requirements (&enum nvmf_treq)
 * @portid:   Port ID
 * @cntlid:   Controller ID
 * @asqsz:    Admin Max SQ Size
 * @rsvd10:   Reserved
 * @trsvcid:  Transport Service Identifier
 * @resv64:   Reserved
 * @nqn:      NVM Qualified Name
 * @traddr:   Transport Address
 * @tsas:     Transport Specific Address Subtype (&union nvmf_tsas)
 * @tel:      Total Entry Length
 * @numexat:  Number of Extended Attributes
 * @resv1030: Reserved
 * @exat:     Extended Attributes 0 (&struct nvmf_ext_attr)
 */
struct nvmf_ext_die {
	__u8			trtype;
	__u8			adrfam;
	__u8			subtype;
	__u8			treq;
	__le16			portid;
	__le16			cntlid;
	__le16			asqsz;
	__u8			rsvd10[22];
	char			trsvcid[NVMF_TRSVCID_SIZE];
	__u8			resv64[192];
	char			nqn[NVME_NQN_LENGTH];
	char			traddr[NVMF_TRADDR_SIZE];
	union nvmf_tsas		tsas;
	__le32			tel;
	__le16			numexat;
	__u8			resv1030[2];
	struct nvmf_ext_attr	exat[];
};

/**
 * union nvmf_die - Discovery Information Entry (DIE)
 * @basic:    Basic format (&struct nvmf_disc_log_entry)
 * @extended: Extended format (&struct nvmf_ext_die)
 *
 * Depending on the ENTFMT specified in the DIM, DIEs can be entered
 * with the Basic or Extended formats. For Basic format, each entry
 * has a fixed length. Therefore, the "basic" field defined below can
 * be accessed as a C array. For the Extended format, however, each
 * entry is of variable length (TEL). Therefore, the "extended" field
 * defined below cannot be accessed as a C array. Instead, the
 * "extended" field is akin to a linked-list, where one can "walk"
 * through the list. To move to the next entry, one simply adds the
 * current entry's length (TEL) to the "walk" pointer. The number of
 * entries in the list is specified by NUMENT.	Although extended
 * entries are of a variable lengths (TEL), TEL is always a multiple of
 * 4 bytes.
 */
union nvmf_die {
	struct nvmf_disc_log_entry	basic[0];
	struct nvmf_ext_die		extended;
};

/**
 * struct nvmf_dim_data - Discovery Information Management (DIM) - Data
 * @tdl:     Total Data Length
 * @rsvd4:   Reserved
 * @nument:  Number of entries
 * @entfmt:  Entry Format (&enum nvmf_dim_entfmt)
 * @etype:   Entity Type (&enum nvmf_dim_etype)
 * @portlcl: Port Local
 * @rsvd21:  Reserved
 * @ektype:  Entry Key Type
 * @eid:     Entity Identifier (e.g. Host NQN)
 * @ename:   Entity Name (e.g. hostname)
 * @ever:    Entity Version (e.g. OS Name/Version)
 * @rsvd600: Reserved
 * @die:     Discovery Information Entry (see @nument above)
 */
struct nvmf_dim_data {
	__le32		tdl;
	__u8		rsvd4[4];
	__le64		nument;
	__le16		entfmt;
	__le16		etype;
	__u8		portlcl;
	__u8		rsvd21;
	__le16		ektype;
	char		eid[NVME_NQN_LENGTH];
	char		ename[NVMF_ENAME_LEN];
	char		ever[NVMF_EVER_LEN];
	__u8		rsvd600[424];
	union nvmf_die	die[];
};

/**
 * struct nvmf_connect_data - Data payload for the 'connect' command
 * @hostid:	Host ID of the connecting host
 * @cntlid:	Requested controller ID
 * @rsvd4:	Reserved
 * @subsysnqn:	Subsystem NQN to connect to
 * @hostnqn:	Host NQN of the connecting host
 * @rsvd5:	Reserved
 */
struct nvmf_connect_data {
	__u8		hostid[16];
	__le16		cntlid;
	char		rsvd4[238];
	char		subsysnqn[NVME_NQN_LENGTH];
	char		hostnqn[NVME_NQN_LENGTH];
	char		rsvd5[256];
};

/**
 * struct nvme_mi_read_nvm_ss_info - NVM Subsystem Information Data Structure
 * @nump:	Number of Ports
 * @mjr:	NVMe-MI Major Version Number
 * @mnr:	NVMe-MI Minor Version Number
 * @rsvd3:	Reserved
 */
struct nvme_mi_read_nvm_ss_info {
	__u8	nump;
	__u8	mjr;
	__u8	mnr;
	__u8	rsvd3[29];
};

/**
 * struct nvme_mi_port_pcie - PCIe Port Specific Data
 * @mps:	PCIe Maximum Payload Size
 * @sls:	PCIe Supported Link Speeds Vector
 * @cls:	PCIe Current Link Speed
 * @mlw:	PCIe Maximum Link Width
 * @nlw:	PCIe Negotiated Link Width
 * @pn:		PCIe Port Number
 * @rsvd14:	Reserved
 */
struct nvme_mi_port_pcie {
	__u8	mps;
	__u8	sls;
	__u8	cls;
	__u8	mlw;
	__u8	nlw;
	__u8	pn;
	__u8	rsvd14[18];
};

/**
 * struct nvme_mi_port_smb - SMBus Port Specific Data
 * @vpd_addr:	Current VPD SMBus/I2C Address
 * @mvpd_freq:	Maximum VPD Access SMBus/I2C Frequency
 * @mme_addr:	Current Management Endpoint SMBus/I2C Address
 * @mme_freq:	Maximum Management Endpoint SMBus/I2C Frequency
 * @nvmebm:	NVMe Basic Management
 * @rsvd13:	Reserved
 */
struct nvme_mi_port_smb {
	__u8	vpd_addr;
	__u8	mvpd_freq;
	__u8	mme_addr;
	__u8	mme_freq;
	__u8	nvmebm;
	__u8	rsvd13[19];
};

/**
 * struct nvme_mi_read_port_info - Port Information Data Structure
 * @portt:	Port Type
 * @rsvd1:	Reserved
 * @mmctptus:	Maximum MCTP Transmission Unit Size
 * @meb:	Management Endpoint Buffer Size
 * @pcie:	PCIe Port Specific Data
 * @smb:	SMBus Port Specific Data
 */
struct nvme_mi_read_port_info {
	__u8	portt;
	__u8	rsvd1;
	__le16	mmctptus;
	__le32	meb;
	union {
		struct nvme_mi_port_pcie pcie;
		struct nvme_mi_port_smb smb;
	};
};

/**
 * struct nvme_mi_read_ctrl_info - Controller Information Data Structure
 * @portid:	Port Identifier
 * @rsvd1:	Reserved
 * @prii:	PCIe Routing ID Information
 * @pri:	PCIe Routing ID
 * @vid:	PCI Vendor ID
 * @did:	PCI Device ID
 * @ssvid:	PCI Subsystem Vendor ID
 * @ssid:	PCI Subsystem Device ID
 * @rsvd16:	Reserved
 */
struct nvme_mi_read_ctrl_info {
	__u8	portid;
	__u8	rsvd1[4];
	__u8	prii;
	__le16	pri;
	__le16	vid;
	__le16	did;
	__le16	ssvid;
	__le16	ssid;
	__u8	rsvd16[16];
};

/**
 * struct nvme_mi_osc - Optionally Supported Command Data Structure
 * @type:	Command Type
 * @opc:	Opcode
 */
struct nvme_mi_osc {
	__u8	type;
	__u8	opc;
};

/**
 * struct nvme_mi_read_sc_list -  Management Endpoint Buffer Supported Command List Data Structure
 * @numcmd:	Number of Commands
 * @cmds:	MEB supported Command Data Structure.
 *		See @struct nvme_mi_osc
 */
struct nvme_mi_read_sc_list {
	__le16	numcmd;
	struct nvme_mi_osc cmds[];
};

/**
 * struct nvme_mi_nvm_ss_health_status - Subsystem Management Data Structure
 * @nss:	NVM Subsystem Status
 * @sw:		Smart Warnings
 * @ctemp:	Composite Temperature
 * @pdlu:	Percentage Drive Life Used
 * @ccs:	Composite Controller Status
 * @rsvd8:	Reserved
 */
struct nvme_mi_nvm_ss_health_status {
	__u8	nss;
	__u8	sw;
	__u8	ctemp;
	__u8	pdlu;
	__le16	ccs;
	__u8	rsvd8[2];
};

/**
 * enum nvme_mi_ccs - Get State Control Primitive Success Response Fields - Control Primitive Specific Response
 * @NVME_MI_CCS_RDY:	Ready
 * @NVME_MI_CCS_CFS:	Controller Fatal Status
 * @NVME_MI_CCS_SHST:	Shutdown Status
 * @NVME_MI_CCS_NSSRO:	NVM Subsystem Reset Occurred
 * @NVME_MI_CCS_CECO:	Controller Enable Change Occurred
 * @NVME_MI_CCS_NAC:	Namespace Attribute Changed
 * @NVME_MI_CCS_FA:	Firmware Activated
 * @NVME_MI_CCS_CSTS:	Controller Status Change
 * @NVME_MI_CCS_CTEMP:	Composite Temperature Change
 * @NVME_MI_CCS_PDLU:	Percentage Used
 * @NVME_MI_CCS_SPARE:	Available Spare
 * @NVME_MI_CCS_CCWARN:	Critical Warning
 */
enum nvme_mi_ccs {
	NVME_MI_CCS_RDY		= 1 << 0,
	NVME_MI_CCS_CFS		= 1 << 1,
	NVME_MI_CCS_SHST	= 1 << 2,
	NVME_MI_CCS_NSSRO	= 1 << 4,
	NVME_MI_CCS_CECO	= 1 << 5,
	NVME_MI_CCS_NAC		= 1 << 6,
	NVME_MI_CCS_FA		= 1 << 7,
	NVME_MI_CCS_CSTS	= 1 << 8,
	NVME_MI_CCS_CTEMP	= 1 << 9,
	NVME_MI_CCS_PDLU	= 1 << 10,
	NVME_MI_CCS_SPARE	= 1 << 11,
	NVME_MI_CCS_CCWARN	= 1 << 12,
};

/* backwards compat for old "CCS" definitions */
#define nvme_mi_css		nvme_mi_ccs
#define NVME_MI_CSS_CFS		NVME_MI_CCS_CFS
#define NVME_MI_CSS_SHST	NVME_MI_CCS_SHST
#define NVME_MI_CSS_NSSRO	NVME_MI_CCS_NSSRO
#define NVME_MI_CSS_CECO	NVME_MI_CCS_CECO
#define NVME_MI_CSS_NAC		NVME_MI_CCS_NAC
#define NVME_MI_CSS_FA		NVME_MI_CCS_FA
#define NVME_MI_CSS_CSTS	NVME_MI_CCS_CSTS
#define NVME_MI_CSS_CTEMP	NVME_MI_CCS_CTEMP
#define NVME_MI_CSS_PDLU	NVME_MI_CCS_PDLU
#define NVME_MI_CSS_SPARE	NVME_MI_CCS_SPARE
#define NVME_MI_CSS_CCWARN	NVME_MI_CCS_CCWARN

/**
 * struct nvme_mi_ctrl_health_status - Controller Health Data Structure (CHDS)
 * @ctlid:	Controller Identifier
 * @csts:	Controller Status
 * @ctemp:	Composite Temperature
 * @pdlu:	Percentage Used
 * @spare:	Available Spare
 * @cwarn:	Critical Warning
 * @rsvd9:	Reserved
 */
struct nvme_mi_ctrl_health_status {
	__le16	ctlid;
	__le16	csts;
	__le16	ctemp;
	__u8	pdlu;
	__u8	spare;
	__u8	cwarn;
	__u8	rsvd9[7];
};

/**
 * enum nvme_mi_csts - Controller Health Data Structure (CHDS) - Controller Status (CSTS)
 * @NVME_MI_CSTS_RDY:	Ready
 * @NVME_MI_CSTS_CFS:	Controller Fatal Status
 * @NVME_MI_CSTS_SHST:	Shutdown Status
 * @NVME_MI_CSTS_NSSRO:	NVM Subsystem Reset Occurred
 * @NVME_MI_CSTS_CECO:	Controller Enable Change Occurred
 * @NVME_MI_CSTS_NAC:	Namespace Attribute Changed
 * @NVME_MI_CSTS_FA:	Firmware Activated
 */
enum nvme_mi_csts {
	NVME_MI_CSTS_RDY	= 1 << 0,
	NVME_MI_CSTS_CFS	= 1 << 1,
	NVME_MI_CSTS_SHST	= 1 << 2,
	NVME_MI_CSTS_NSSRO	= 1 << 4,
	NVME_MI_CSTS_CECO	= 1 << 5,
	NVME_MI_CSTS_NAC	= 1 << 6,
	NVME_MI_CSTS_FA		= 1 << 7,
};

/**
 * enum nvme_mi_cwarn - Controller Health Data Structure (CHDS) - Critical Warning (CWARN)
 * @NVME_MI_CWARN_ST:	Spare Threshold
 * @NVME_MI_CWARN_TAUT:	Temperature Above or Under Threshold
 * @NVME_MI_CWARN_RD:	Reliability Degraded
 * @NVME_MI_CWARN_RO:	Read Only
 * @NVME_MI_CWARN_VMBF:	Volatile Memory Backup Failed
 */
enum nvme_mi_cwarn {
	NVME_MI_CWARN_ST	= 1 << 0,
	NVME_MI_CWARN_TAUT	= 1 << 1,
	NVME_MI_CWARN_RD	= 1 << 2,
	NVME_MI_CWARN_RO	= 1 << 3,
	NVME_MI_CWARN_VMBF	= 1 << 4,
};

/**
 * struct nvme_mi_vpd_mra - NVMe MultiRecord Area
 * @nmravn:	NVMe MultiRecord Area Version Number
 * @ff:		Form Factor
 * @rsvd7:	Reserved
 * @i18vpwr:	Initial 1.8 V Power Supply Requirements
 * @m18vpwr:	Maximum 1.8 V Power Supply Requirements
 * @i33vpwr:	Initial 3.3 V Power Supply Requirements
 * @m33vpwr:	Maximum 3.3 V Power Supply Requirements
 * @rsvd17:	Reserved
 * @m33vapsr:	Maximum 3.3 Vi aux Power Supply Requirements
 * @i5vapsr:	Initial 5 V Power Supply Requirements
 * @m5vapsr:	Maximum 5 V Power Supply Requirements
 * @i12vapsr:	Initial 12 V Power Supply Requirements
 * @m12vapsr:	Maximum 12 V Power Supply Requirements
 * @mtl:	Maximum Thermal Load
 * @tnvmcap:	Total NVM Capacity
 * @rsvd37:	Reserved
 */
struct nvme_mi_vpd_mra {
	__u8	nmravn;
	__u8	ff;
	__u8	rsvd7[6];
	__u8	i18vpwr;
	__u8	m18vpwr;
	__u8	i33vpwr;
	__u8	m33vpwr;
	__u8	rsvd17;
	__u8	m33vapsr;
	__u8	i5vapsr;
	__u8	m5vapsr;
	__u8	i12vapsr;
	__u8	m12vapsr;
	__u8	mtl;
	__u8	tnvmcap[16];
	__u8	rsvd37[27];
};

/**
 * struct nvme_mi_vpd_ppmra -  NVMe PCIe Port MultiRecord Area
 * @nppmravn:	NVMe PCIe Port MultiRecord Area Version Number
 * @pn:		PCIe Port Number
 * @ppi:	Port Information
 * @ls:		PCIe Link Speed
 * @mlw:	PCIe Maximum Link Width
 * @mctp:	MCTP Support
 * @refccap:	Ref Clk Capability
 * @pi:		Port Identifier
 * @rsvd13:	Reserved
 */
struct nvme_mi_vpd_ppmra {
	__u8	nppmravn;
	__u8	pn;
	__u8	ppi;
	__u8	ls;
	__u8	mlw;
	__u8	mctp;
	__u8	refccap;
	__u8	pi;
	__u8	rsvd13[3];
};

/**
 * struct nvme_mi_vpd_telem - Vital Product Data Element Descriptor
 * @type:	Type of the Element Descriptor
 * @rev:	Revision of the Element Descriptor
 * @len:	Number of bytes in the Element Descriptor
 * @data:	Type-specific information associated with
 *		the Element Descriptor
 */
struct nvme_mi_vpd_telem {
	__u8	type;
	__u8	rev;
	__u8	len;
	__u8	data[0];
};

/**
 * enum nvme_mi_elem - Element Descriptor Types
 * @NVME_MI_ELEM_EED:		Extended Element Descriptor
 * @NVME_MI_ELEM_USCE:		Upstream Connector Element Descriptor
 * @NVME_MI_ELEM_ECED:		Expansion Connector Element Descriptor
 * @NVME_MI_ELEM_LED:		Label Element Descriptor
 * @NVME_MI_ELEM_SMBMED:	SMBus/I2C Mux Element Descriptor
 * @NVME_MI_ELEM_PCIESED:	PCIe Switch Element Descriptor
 * @NVME_MI_ELEM_NVMED:		NVM Subsystem Element Descriptor
 */
enum nvme_mi_elem {
	NVME_MI_ELEM_EED	= 1,
	NVME_MI_ELEM_USCE	= 2,
	NVME_MI_ELEM_ECED	= 3,
	NVME_MI_ELEM_LED	= 4,
	NVME_MI_ELEM_SMBMED	= 5,
	NVME_MI_ELEM_PCIESED	= 6,
	NVME_MI_ELEM_NVMED	= 7,
};

/**
 * struct nvme_mi_vpd_tra - Vital Product Data Topology MultiRecord
 * @vn:		Version Number
 * @rsvd6:	Reserved
 * @ec:		Element Count
 * @elems:	Element Descriptor
 */
struct nvme_mi_vpd_tra {
	__u8	vn;
	__u8	rsvd6;
	__u8	ec;
	struct nvme_mi_vpd_telem elems[0];
};

/**
 * struct nvme_mi_vpd_mr_common -  NVMe MultiRecord Area
 * @type:	NVMe Record Type ID
 * @rf:		Record Format
 * @rlen:	Record Length
 * @rchksum:	Record Checksum
 * @hchksum:	Header Checksum
 * @nmra:	NVMe MultiRecord Area
 * @ppmra:	NVMe PCIe Port MultiRecord Area
 * @tmra:	Topology MultiRecord Area
 */
struct nvme_mi_vpd_mr_common {
	__u8	type;
	__u8	rf;
	__u8	rlen;
	__u8	rchksum;
	__u8	hchksum;

	union {
		struct nvme_mi_vpd_mra nmra;
		struct nvme_mi_vpd_ppmra ppmra;
		struct nvme_mi_vpd_tra tmra;
	};
};

/**
 * struct nvme_mi_vpd_hdr - Vital Product Data Common Header
 * @ipmiver:	IPMI Format Version Number
 * @iuaoff:	Internal Use Area Starting Offset
 * @ciaoff:	Chassis Info Area Starting Offset
 * @biaoff:	Board Info Area Starting Offset
 * @piaoff:	Product Info Area Starting Offset
 * @mrioff:	MultiRecord Info Area Starting Offset
 * @rsvd6:	Reserved
 * @chchk:	Common Header Checksum
 * @vpd:	Vital Product Data
 */
struct nvme_mi_vpd_hdr {
	__u8	ipmiver;
	__u8	iuaoff;
	__u8	ciaoff;
	__u8	biaoff;
	__u8	piaoff;
	__u8	mrioff;
	__u8	rsvd6;
	__u8	chchk;
	__u8	vpd[];
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
 * @NVME_SC_FDP_DISABLED:	      Command is not allowed when
 *				      Flexible Data Placement is disabled.
 * @NVME_SC_INVALID_PLACEMENT_HANDLE_LIST: The Placement Handle List is invalid
 *				      due to invalid Reclaim Unit Handle Identifier or
 *				      valid Reclaim Unit Handle Identifier but restricted or
 *				      the Placement Handle List number of entries exceeded the
 *				      maximum number allowed.
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
	NVME_SC_FDP_DISABLED			= 0x29,
	NVME_SC_INVALID_PLACEMENT_HANDLE_LIST	= 0x2A,
	NVME_SC_LBA_RANGE			= 0x80,
	NVME_SC_CAP_EXCEEDED			= 0x81,
	NVME_SC_NS_NOT_READY			= 0x82,
	NVME_SC_RESERVATION_CONFLICT		= 0x83,
	NVME_SC_FORMAT_IN_PROGRESS		= 0x84,

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

	/*
	 * Command Set Specific - Live Migration
	 */
	NVME_SC_INVALID_CONTROLER_DATA_QUEUE	= 0x37,
	NVME_SC_NOT_ENOUGH_RESOURCES		= 0x38,
	NVME_SC_CONTROLLER_SUSPENDED		= 0x39,
	NVME_SC_CONTROLLER_NOT_SUSPENDED	= 0x3A,
	NVME_SC_CONTROLLER_DATA_QUEUE_FULL	= 0x3B,

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
 * Returns: status code type
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
 * Returns: status code
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

/**
 * nvme_status_get_type() - extract the type from a nvme_* return value
 * @status: the (non-negative) return value from the NVMe API
 *
 * Returns: the type component of the status.
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
 * Returns: the value component of the status; the set of values will depend
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
 * Returns: true if @status is of the specified type and value
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
 * @nvme_admin_fabric_zoning_send:	Fabric Zoning Send
 * @nvme_admin_dbbuf:			Doorbell Buffer Config
 * @nvme_admin_fabrics:			Fabrics Commands
 * @nvme_admin_format_nvm:		Format NVM
 * @nvme_admin_security_send:		Security Send
 * @nvme_admin_security_recv:		Security Receive
 * @nvme_admin_sanitize_nvm:		Sanitize
 * @nvme_admin_get_lba_status:		Get LBA Status
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
	nvme_admin_fabric_zoning_send	= 0x29,
	nvme_admin_dbbuf		= 0x7c,
	nvme_admin_fabrics		= 0x7f,
	nvme_admin_format_nvm		= 0x80,
	nvme_admin_security_send	= 0x81,
	nvme_admin_security_recv	= 0x82,
	nvme_admin_sanitize_nvm		= 0x84,
	nvme_admin_get_lba_status	= 0x86,
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
 * @NVME_IDENTIFY_CNS_COMMAND_SET_STRUCTURE:	Base Specification 2.0a section 5.17.2.21
 * @NVME_IDENTIFY_CNS_SUPPORTED_CTRL_STATE_FORMATS:	Supported Controller State Formats
 *							identifying the supported NVMe Controller
 *							State data structures
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
	NVME_IDENTIFY_CNS_SUPPORTED_CTRL_STATE_FORMATS		= 0x20,
};

/**
 * enum nvme_cmd_get_log_lid -			Get Log Page -Log Page Identifiers
 * @NVME_LOG_LID_SUPPORTED_LOG_PAGES:		Supported Log Pages
 * @NVME_LOG_LID_ERROR:				Error Information
 * @NVME_LOG_LID_SMART:				SMART / Health Information
 * @NVME_LOG_LID_FW_SLOT:			Firmware Slot Information
 * @NVME_LOG_LID_CHANGED_NS:			Changed Namespace List
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
 * @NVME_LOG_LID_PHY_RX_EOM:			Physical Interface Receiver Eye Opening Measurement
 * @NVME_LOG_LID_FDP_CONFIGS:			FDP Configurations
 * @NVME_LOG_LID_FDP_RUH_USAGE:			Reclaim Unit Handle Usage
 * @NVME_LOG_LID_FDP_STATS:			FDP Statistics
 * @NVME_LOG_LID_FDP_EVENTS:			FDP Events
 * @NVME_LOG_LID_DISCOVER:			Discovery
 * @NVME_LOG_LID_RESERVATION:			Reservation Notification
 * @NVME_LOG_LID_SANITIZE:			Sanitize Status
 * @NVME_LOG_LID_ZNS_CHANGED_ZONES:		Changed Zone List
 */
enum nvme_cmd_get_log_lid {
	NVME_LOG_LID_SUPPORTED_LOG_PAGES			= 0x00,
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
	NVME_LOG_LID_MEDIA_UNIT_STATUS				= 0x10,
	NVME_LOG_LID_SUPPORTED_CAP_CONFIG_LIST			= 0x11,
	NVME_LOG_LID_FID_SUPPORTED_EFFECTS			= 0x12,
	NVME_LOG_LID_MI_CMD_SUPPORTED_EFFECTS			= 0x13,
	NVME_LOG_LID_CMD_AND_FEAT_LOCKDOWN			= 0x14,
	NVME_LOG_LID_BOOT_PARTITION				= 0x15,
	NVME_LOG_LID_PHY_RX_EOM					= 0x19,
	NVME_LOG_LID_FDP_CONFIGS				= 0x20,
	NVME_LOG_LID_FDP_RUH_USAGE				= 0x21,
	NVME_LOG_LID_FDP_STATS					= 0x22,
	NVME_LOG_LID_FDP_EVENTS					= 0x23,
	NVME_LOG_LID_DISCOVER					= 0x70,
	NVME_LOG_LID_RESERVATION				= 0x80,
	NVME_LOG_LID_SANITIZE					= 0x81,
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
 * @NVME_FEAT_FID_SANITIZE:		Endurance Group Event Configuration
 * @NVME_FEAT_FID_ENDURANCE_EVT_CFG:	Endurance Group Event Configuration
 * @NVME_FEAT_FID_IOCS_PROFILE:		I/O Command Set Profile
 * @NVME_FEAT_FID_SPINUP_CONTROL:	Spinup Control
 * @NVME_FEAT_FID_FDP:			Flexible Data Placement
 * @NVME_FEAT_FID_FDP_EVENTS:		FDP Events
 * @NVME_FEAT_FID_ENH_CTRL_METADATA:	Enhanced Controller Metadata
 * @NVME_FEAT_FID_CTRL_METADATA:	Controller Metadata
 * @NVME_FEAT_FID_NS_METADATA:		Namespace Metadata
 * @NVME_FEAT_FID_SW_PROGRESS:		Software Progress Marker
 * @NVME_FEAT_FID_HOST_ID:		Host Identifier
 * @NVME_FEAT_FID_RESV_MASK:		Reservation Notification Mask
 * @NVME_FEAT_FID_RESV_PERSIST:		Reservation Persistence
 * @NVME_FEAT_FID_WRITE_PROTECT:	Namespace Write Protection Config
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
	NVME_FEAT_FID_SPINUP_CONTROL				= 0x1a,
	NVME_FEAT_FID_FDP					= 0x1d,
	NVME_FEAT_FID_FDP_EVENTS				= 0x1e,
	NVME_FEAT_FID_ENH_CTRL_METADATA				= 0x7d,
	NVME_FEAT_FID_CTRL_METADATA				= 0x7e,
	NVME_FEAT_FID_NS_METADATA				= 0x7f,
	NVME_FEAT_FID_SW_PROGRESS				= 0x80,
	NVME_FEAT_FID_HOST_ID					= 0x81,
	NVME_FEAT_FID_RESV_MASK					= 0x82,
	NVME_FEAT_FID_RESV_PERSIST				= 0x83,
	NVME_FEAT_FID_WRITE_PROTECT				= 0x84,
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
 * @NVME_FEAT_LBAR_NR_SHIFT:
 * @NVME_FEAT_LBAR_NR_MASK:
 * @NVME_FEAT_TT_TMPTH_SHIFT:
 * @NVME_FEAT_TT_TMPTH_MASK:
 * @NVME_FEAT_TT_TMPSEL_SHIFT:
 * @NVME_FEAT_TT_TMPSEL_MASK:
 * @NVME_FEAT_TT_THSEL_SHIFT:
 * @NVME_FEAT_TT_THSEL_MASK:
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
 * @NVME_FEAT_PLM_PLME_SHIFT:
 * @NVME_FEAT_PLM_PLME_MASK:
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
 * @NVME_FEAT_FDP_ENABLED_SHIFT:
 * @NVME_FEAT_FDP_ENABLED_MASK:
 * @NVME_FEAT_FDP_INDEX_SHIFT:
 * @NVME_FEAT_FDP_INDEX_MASK:
 * @NVME_FEAT_FDP_EVENTS_ENABLE_SHIFT:
 * @NVME_FEAT_FDP_EVENTS_ENABLE_MASK:
 */
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
	NVME_FEAT_LBAR_NR_SHIFT			= 0,
	NVME_FEAT_LBAR_NR_MASK			= 0x3f,
	NVME_FEAT_TT_TMPTH_SHIFT		= 0,
	NVME_FEAT_TT_TMPTH_MASK			= 0xffff,
	NVME_FEAT_TT_TMPSEL_SHIFT		= 16,
	NVME_FEAT_TT_TMPSEL_MASK		= 0xf,
	NVME_FEAT_TT_THSEL_SHIFT		= 20,
	NVME_FEAT_TT_THSEL_MASK			= 0x3,
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
	NVME_FEAT_RRL_RRL_SHIFT		= 0,
	NVME_FEAT_RRL_RRL_MASK		= 0xff,
	NVME_FEAT_PLM_PLME_SHIFT	= 0,
	NVME_FEAT_PLM_PLME_MASK		= 0x1,
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
	NVME_FEAT_FDP_ENABLED_SHIFT	= 0,
	NVME_FEAT_FDP_ENABLED_MASK	= 0x1,
	NVME_FEAT_FDP_INDEX_SHIFT	= 8,
	NVME_FEAT_FDP_INDEX_MASK	= 0xf,
	NVME_FEAT_FDP_EVENTS_ENABLE_SHIFT = 0,
	NVME_FEAT_FDP_EVENTS_ENABLE_MASK  = 0x1,
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
 */
enum nvme_ns_mgmt_sel {
	NVME_NS_MGMT_SEL_CREATE					= 0,
	NVME_NS_MGMT_SEL_DELETE					= 1,
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
 * enum nvme_feat_plm_window_select - Predictable Latency Per NVM Set Log
 * @NVME_FEATURE_PLM_DTWIN:	Deterministic Window select
 * @NVME_FEATURE_PLM_NDWIN:	Non-Deterministic Window select
 */
enum nvme_feat_plm_window_select {
	NVME_FEATURE_PLM_DTWIN					= 1,
	NVME_FEATURE_PLM_NDWIN					= 2,
};

/**
 * enum nvme_feat_resv_notify_flags - Reservation Notification Configuration
 * @NVME_FEAT_RESV_NOTIFY_REGPRE:	Mask Registration Preempted Notification
 * @NVME_FEAT_RESV_NOTIFY_RESREL:	Mask Reservation Released Notification
 * @NVME_FEAT_RESV_NOTIFY_RESPRE:	Mask Reservation Preempted Notification
 */
enum nvme_feat_resv_notify_flags {
	NVME_FEAT_RESV_NOTIFY_REGPRE		= 1 << 1,
	NVME_FEAT_RESV_NOTIFY_RESREL		= 1 << 2,
	NVME_FEAT_RESV_NOTIFY_RESPRE		= 1 << 3,
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

/**
 * enum nvme_io_control_flags - I/O control flags
 * @NVME_IO_DTYPE_STREAMS:	Directive Type Streams
 * @NVME_IO_STC:		Storage Tag Check
 * @NVME_IO_DEAC:		Deallocate
 * @NVME_IO_ZNS_APPEND_PIREMAP:	Protection Information Remap
 * @NVME_IO_PRINFO_PRCHK_REF:	Protection Information Check Reference Tag
 * @NVME_IO_PRINFO_PRCHK_APP:	Protection Information Check Application Tag
 * @NVME_IO_PRINFO_PRCHK_GUARD: Protection Information Check Guard field
 * @NVME_IO_PRINFO_PRACT:	Protection Information Action
 * @NVME_IO_FUA:		Force Unit Access
 * @NVME_IO_LR:			Limited Retry
 */
enum nvme_io_control_flags {
	NVME_IO_DTYPE_STREAMS		= 1 << 4,
	NVME_IO_STC			= 1 << 8,
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
 * enum nvme_io_dsm_flags -  Dataset Management flags
 * @NVME_IO_DSM_FREQ_UNSPEC:	No frequency information provided
 * @NVME_IO_DSM_FREQ_TYPICAL:	Typical number of reads and writes
 *				expected for this LBA range
 * @NVME_IO_DSM_FREQ_RARE:	Infrequent writes and infrequent
 *				reads to the LBA range indicated
 * @NVME_IO_DSM_FREQ_READS:	Infrequent writes and frequent
 *				reads to the LBA range indicated
 * @NVME_IO_DSM_FREQ_WRITES:	Frequent writes and infrequent
 *				reads to the LBA range indicated
 * @NVME_IO_DSM_FREQ_RW:	Frequent writes and frequent reads
 *				to the LBA range indicated
 * @NVME_IO_DSM_FREQ_ONCE:
 * @NVME_IO_DSM_FREQ_PREFETCH:
 * @NVME_IO_DSM_FREQ_TEMP:
 * @NVME_IO_DSM_LATENCY_NONE:	No latency information provided
 * @NVME_IO_DSM_LATENCY_IDLE:	Longer latency acceptable
 * @NVME_IO_DSM_LATENCY_NORM:	Typical latency
 * @NVME_IO_DSM_LATENCY_LOW:	Smallest possible latency
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
 * enum nvme_dsm_attributes - Dataset Management attributes
 * @NVME_DSMGMT_IDR:	Attribute -Integral Dataset for Read
 * @NVME_DSMGMT_IDW:	Attribute - Integral Dataset for Write
 * @NVME_DSMGMT_AD:	Attribute - Deallocate
 */
enum nvme_dsm_attributes {
	NVME_DSMGMT_IDR			= 1 << 0,
	NVME_DSMGMT_IDW			= 1 << 1,
	NVME_DSMGMT_AD			= 1 << 2,
};

/**
 * enum nvme_resv_rtype - Reservation Type Encoding
 * @NVME_RESERVATION_RTYPE_WE:		Write Exclusive Reservation
 * @NVME_RESERVATION_RTYPE_EA:		Exclusive Access Reservation
 * @NVME_RESERVATION_RTYPE_WERO:	Write Exclusive - Registrants Only Reservation
 * @NVME_RESERVATION_RTYPE_EARO:	Exclusive Access - Registrants Only Reservation
 * @NVME_RESERVATION_RTYPE_WEAR:	Write Exclusive - All Registrants Reservation
 * @NVME_RESERVATION_RTYPE_EAAR:	Exclusive Access - All Registrants Reservation
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
 * enum nvme_resv_racqa - Reservation Acquire - Reservation Acquire Action
 * @NVME_RESERVATION_RACQA_ACQUIRE:		Acquire
 * @NVME_RESERVATION_RACQA_PREEMPT:		Preempt
 * @NVME_RESERVATION_RACQA_PREEMPT_AND_ABORT:	Preempt and Abort
 */
enum nvme_resv_racqa {
	NVME_RESERVATION_RACQA_ACQUIRE			= 0,
	NVME_RESERVATION_RACQA_PREEMPT			= 1,
	NVME_RESERVATION_RACQA_PREEMPT_AND_ABORT	= 2,
};

/**
 * enum nvme_resv_rrega - Reservation Register - Reservation Register Action
 * @NVME_RESERVATION_RREGA_REGISTER_KEY:	Register Reservation Key
 * @NVME_RESERVATION_RREGA_UNREGISTER_KEY:	Unregister Reservation Key
 * @NVME_RESERVATION_RREGA_REPLACE_KEY:		Replace Reservation Key
 */
enum nvme_resv_rrega {
	NVME_RESERVATION_RREGA_REGISTER_KEY		= 0,
	NVME_RESERVATION_RREGA_UNREGISTER_KEY		= 1,
	NVME_RESERVATION_RREGA_REPLACE_KEY		= 2,
};

/**
 * enum nvme_resv_cptpl - Reservation Register - Change Persist Through Power Loss State
 * @NVME_RESERVATION_CPTPL_NO_CHANGE:	No change to PTPL state
 * @NVME_RESERVATION_CPTPL_CLEAR:	Reservations are released and
 *					registrants are cleared on a power on
 * @NVME_RESERVATION_CPTPL_PERSIST:	Reservations and registrants persist
 *					across a power loss
 */
enum nvme_resv_cptpl {
	NVME_RESERVATION_CPTPL_NO_CHANGE		= 0,
	NVME_RESERVATION_CPTPL_CLEAR			= 2,
	NVME_RESERVATION_CPTPL_PERSIST			= 3,
};

/**
 * enum nvme_resv_rrela - Reservation Release - Reservation Release Action
 * @NVME_RESERVATION_RRELA_RELEASE:	Release
 * @NVME_RESERVATION_RRELA_CLEAR:	Clear
 */
enum nvme_resv_rrela {
	NVME_RESERVATION_RRELA_RELEASE			= 0,
	NVME_RESERVATION_RRELA_CLEAR			= 1
};

/**
 * enum nvme_zns_send_action - Zone Management Send - Zone Send Action
 * @NVME_ZNS_ZSA_CLOSE:		Close Zone
 * @NVME_ZNS_ZSA_FINISH:	Finish Zone
 * @NVME_ZNS_ZSA_OPEN:		Open Zone
 * @NVME_ZNS_ZSA_RESET:		Reset Zone
 * @NVME_ZNS_ZSA_OFFLINE:	Offline Zone
 * @NVME_ZNS_ZSA_SET_DESC_EXT:	Set Zone Descriptor Extension
 * @NVME_ZNS_ZSA_ZRWA_FLUSH:	Flush
 */
enum nvme_zns_send_action {
	NVME_ZNS_ZSA_CLOSE		= 0x1,
	NVME_ZNS_ZSA_FINISH		= 0x2,
	NVME_ZNS_ZSA_OPEN		= 0x3,
	NVME_ZNS_ZSA_RESET		= 0x4,
	NVME_ZNS_ZSA_OFFLINE		= 0x5,
	NVME_ZNS_ZSA_SET_DESC_EXT	= 0x10,
	NVME_ZNS_ZSA_ZRWA_FLUSH		= 0x11,
};

/**
 * enum nvme_zns_recv_action - Zone Management Receive - Zone Receive Action Specific Features
 * @NVME_ZNS_ZRA_REPORT_ZONES:		Report Zones
 * @NVME_ZNS_ZRA_EXTENDED_REPORT_ZONES:	Extended Report Zones
 */
enum nvme_zns_recv_action {
	NVME_ZNS_ZRA_REPORT_ZONES		= 0x0,
	NVME_ZNS_ZRA_EXTENDED_REPORT_ZONES	= 0x1,
};

/**
 * enum nvme_zns_report_options - Zone Management Receive - Zone Receive Action Specific Field
 * @NVME_ZNS_ZRAS_REPORT_ALL:		List all zones
 * @NVME_ZNS_ZRAS_REPORT_EMPTY:		List the zones in the ZSE:Empty state
 * @NVME_ZNS_ZRAS_REPORT_IMPL_OPENED:	List the zones in the ZSIO:Implicitly Opened state
 * @NVME_ZNS_ZRAS_REPORT_EXPL_OPENED:	List the zones in the ZSEO:Explicitly Opened state
 * @NVME_ZNS_ZRAS_REPORT_CLOSED:	List the zones in the ZSC:Closed state
 * @NVME_ZNS_ZRAS_REPORT_FULL:		List the zones in the ZSF:Full state
 * @NVME_ZNS_ZRAS_REPORT_READ_ONLY:	List the zones in the ZSRO:Read Only state
 * @NVME_ZNS_ZRAS_REPORT_OFFLINE:	List the zones in the ZSO:Offline state
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

/**
 * enum nvme_io_mgmt_recv_mo - I/O Management Receive - Management Operation
 * @NVME_IO_MGMT_RECV_RUH_STATUS:	Reclaim Unit Handle Status
 */
enum nvme_io_mgmt_recv_mo {
	NVME_IO_MGMT_RECV_RUH_STATUS = 0x1,
};

/**
 * enum nvme_io_mgmt_send_mo - I/O Management Send - Management Operation
 * @NVME_IO_MGMT_SEND_RUH_UPDATE:	Reclaim Unit Handle Update
 */
enum nvme_io_mgmt_send_mo {
	NVME_IO_MGMT_SEND_RUH_UPDATE = 0x1,
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

#endif /* _LIBNVME_TYPES_H */
