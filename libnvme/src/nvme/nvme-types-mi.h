// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 *          Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 *          Daniel Wagner <dwagner@suse.de>
 *
 * NVMe Management Interface type definitions
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <nvme/types.h>
#include <nvme/nvme-types-base.h>

/**
 * DOC: nvme-types-mi.h - NVMe-MI data structure type definitions
 *
 * NVMe Management Interface type definitions
 *
 * Based on NVM Express Management Interface Specification,
 * Revision 2.1, August 1, 2025 (Ratified)
 *
 * This file contains core NVMe types organized by functional area:
 * - MI command data structures (controller info, port info, etc.)
 * - Health status structures (subsystem and controller health)
 * - VPD (Vital Product Data) structures
 * - MI log page structures
 * - Command effects and capabilities
 * - Spec-defined data payloads
 */

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

#define NVME_MI_CMD_SUPPORTED_EFFECTS_SCOPE(effects)	NVME_GET(effects, MI_CMD_SUPPORTED_EFFECTS_SCOPE)

/**
 * struct nvme_mi_cmd_supported_effects_log - NVMe-MI Commands Supported and Effects Log
 * @mi_cmd_support:	NVMe-MI Commands Supported
 * @rsvd128:		Reserved
 */
struct nvme_mi_cmd_supported_effects_log {
	__le32	mi_cmd_support[NVME_LOG_MI_CMD_SUPPORTED_EFFECTS_MAX];
	__le32	rsvd128[NVME_LOG_MI_CMD_SUPPORTED_EFFECTS_RESERVED];
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
 * enum nvme_mi_nss - NVM Subsystem Status
 * @NVME_MI_NSS_NRDY_SHIFT:	Shift amount to get Not Ready
 * @NVME_MI_NSS_NRDY_MASK:	Mask to get Not Ready
 * @NVME_MI_NSS_DRV_SHIFT:	Shift amount to get Drive Ready
 * @NVME_MI_NSS_DRV_MASK:	Mask to get Drive Ready
 */
enum nvme_mi_nss {
	NVME_MI_NSS_NRDY_SHIFT		= 0,
	NVME_MI_NSS_NRDY_MASK		= 0x1,
	NVME_MI_NSS_DRV_SHIFT		= 1,
	NVME_MI_NSS_DRV_MASK		= 0x1,
};

#define NVME_MI_NSS_NRDY(nss)	NVME_GET(nss, MI_NSS_NRDY)
#define NVME_MI_NSS_DRV(nss)	NVME_GET(nss, MI_NSS_DRV)

/**
 * enum nvme_mi_sw - Smart Warnings
 * @NVME_MI_SW_ST_SHIFT:	Shift amount to get Spare Threshold
 * @NVME_MI_SW_ST_MASK:		Mask to get Spare Threshold
 * @NVME_MI_SW_TAUT_SHIFT:	Shift amount to get Temperature Above or Under Threshold
 * @NVME_MI_SW_TAUT_MASK:	Mask to get Temperature Above or Under Threshold
 * @NVME_MI_SW_RD_SHIFT:	Shift amount to get Reliability Degraded
 * @NVME_MI_SW_RD_MASK:		Mask to get Reliability Degraded
 * @NVME_MI_SW_RO_SHIFT:	Shift amount to get Read Only
 * @NVME_MI_SW_RO_MASK:		Mask to get Read Only
 * @NVME_MI_SW_VMBF_SHIFT:	Shift amount to get Volatile Memory Backup Failed
 * @NVME_MI_SW_VMBF_MASK:	Mask to get Volatile Memory Backup Failed
 */
enum nvme_mi_sw {
	NVME_MI_SW_ST_SHIFT		= 0,
	NVME_MI_SW_ST_MASK		= 0x1,
	NVME_MI_SW_TAUT_SHIFT		= 1,
	NVME_MI_SW_TAUT_MASK		= 0x1,
	NVME_MI_SW_RD_SHIFT		= 2,
	NVME_MI_SW_RD_MASK		= 0x1,
	NVME_MI_SW_RO_SHIFT		= 3,
	NVME_MI_SW_RO_MASK		= 0x1,
	NVME_MI_SW_VMBF_SHIFT		= 4,
	NVME_MI_SW_VMBF_MASK		= 0x1,
};

#define NVME_MI_SW_ST(sw)	NVME_GET(sw, MI_SW_ST)
#define NVME_MI_SW_TAUT(sw)	NVME_GET(sw, MI_SW_TAUT)
#define NVME_MI_SW_RD(sw)	NVME_GET(sw, MI_SW_RD)
#define NVME_MI_SW_RO(sw)	NVME_GET(sw, MI_SW_RO)
#define NVME_MI_SW_VMBF(sw)	NVME_GET(sw, MI_SW_VMBF)

/**
 * struct nvme_mi_nvm_ss_health_status - Subsystem Management Data Structure
 * @nss:	NVM Subsystem Status (see &enum nvme_mi_nss)
 * @sw:		Smart Warnings (see &enum nvme_mi_sw)
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
