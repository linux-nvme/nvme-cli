// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 *          Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 *          Daniel Wagner <dwagner@suse.de>
 *
 * NVM Command Set type definitions
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <nvme/types.h>
#include <nvme/nvme-types-base.h>

/**
 * DOC: nvme-types-nvm.h
 *
 * NVM Command Set type definitions
 *
 * Based on NVM Express NVM Command Set Specification,
 * Revision 1.2, August 1, 2025 (Ratified)
 *
 * This file is organized into functional groups:
 * - NVM Namespace Identification: Extended LBA formats and namespace-specific data
 * - I/O Command Set Support: Command set identification and capabilities
 * - Reservation Notifications: Log pages for reservation events
 * - Flexible Data Placement (FDP): Comprehensive FDP feature support including
 *   configuration, events, statistics, and status reporting
 * - Data Set Management & Copy: DSM ranges and copy operation formats
 * - Reservation Support: Controller registration and reservation management
 * - I/O Management: Control flags and management operations
 */

/**
 * enum nvme_nvm_id_ns_elbaf - This field indicates the extended LBA format
 * @NVME_NVM_ELBAF_STS_SHIFT:	Shift to get the storage tag size
 * @NVME_NVM_ELBAF_STS_MASK:	Mask to get the storage tag size used to determine
 *				the variable-sized storage tag/reference tag fields
 * @NVME_NVM_ELBAF_PIF_SHIFT:	Shift to get the protection information format
 * @NVME_NVM_ELBAF_PIF_MASK:	Mask to get the protection information format for
 *				the extended LBA format.
 * @NVME_NVM_ELBAF_QPIF_SHIFT:	Shift to get the Qualified Protection Information Format
 * @NVME_NVM_ELBAF_QPIF_MASK:	Mask to get the Qualified Protection Information
 *				Format.
 */
enum nvme_nvm_id_ns_elbaf {
	NVME_NVM_ELBAF_STS_SHIFT	= 0,
	NVME_NVM_ELBAF_STS_MASK		= 0x7f,
	NVME_NVM_ELBAF_PIF_SHIFT	= 7,
	NVME_NVM_ELBAF_PIF_MASK		= 0x3,
	NVME_NVM_ELBAF_QPIF_SHIFT	= 9,
	NVME_NVM_ELBAF_QPIF_MASK	= 0xf,
};

#define NVME_NVM_ELBAF_STS(elbaf)	NVME_GET(elbaf, NVM_ELBAF_STS)
#define NVME_NVM_ELBAF_PIF(elbaf)	NVME_GET(elbaf, NVM_ELBAF_PIF)
#define NVME_NVM_ELBAF_QPIF(elbaf)	NVME_GET(elbaf, NVM_ELBAF_QPIF)

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
 * enum nvme_nvm_id_ns_lbstm - Logical Block Storage Tag Mask
 * @NVME_NVM_LBSTM_DEALLOCATED_SHIFT:	Shift amount to get Deallocated/Unwritten Logical Block error time
 * @NVME_NVM_LBSTM_DEALLOCATED_MASK:	Mask to get Deallocated/Unwritten Logical Block error time
 * @NVME_NVM_LBSTM_WRITTEN_SHIFT:	Shift amount to get Written Logical Block error time
 * @NVME_NVM_LBSTM_WRITTEN_MASK:	Mask to get Written Logical Block error time
 */
enum nvme_nvm_id_ns_lbstm {
	NVME_NVM_LBSTM_DEALLOCATED_SHIFT	= 0,
	NVME_NVM_LBSTM_DEALLOCATED_MASK		= 0xffff,
	NVME_NVM_LBSTM_WRITTEN_SHIFT		= 16,
	NVME_NVM_LBSTM_WRITTEN_MASK		= 0xffff,
};

#define NVME_NVM_LBSTM_DEALLOCATED(lbstm)	NVME_GET(lbstm, NVM_LBSTM_DEALLOCATED)
#define NVME_NVM_LBSTM_WRITTEN(lbstm)		NVME_GET(lbstm, NVM_LBSTM_WRITTEN)

/**
 * enum nvme_nvm_id_ns_pic - Protection Information Capabilities
 * @NVME_NVM_PIC_PITPS16B_SHIFT:Shift amount to get 16b Guard Protection Information Storage Tag Support
 * @NVME_NVM_PIC_PITPS16B_MASK:	Mask to get 16b Guard Protection Information Storage Tag Support
 * @NVME_NVM_PIC_PISTM16B_SHIFT:Shift amount to get 16b Guard Protection Information Storage Tag Mask
 * @NVME_NVM_PIC_PISTM16B_MASK:	Mask to get 16b Guard Protection Information Storage Tag Mask
 * @NVME_NVM_PIC_STCRS_SHIFT:	Shift amount to get Storage Tag Check Read Support
 * @NVME_NVM_PIC_STCRS_MASK:	Mask to get Storage Tag Check Read Support
 * @NVME_NVM_PIC_QPIFS_SHIFT:Shift amount to get Qualified Protection Information Format Support
 * @NVME_NVM_PIC_QPIFS_MASK:	Mask to get Qualified Protection Information Format Support
 */
enum nvme_nvm_id_ns_pic {
	NVME_NVM_PIC_PITPS16B_SHIFT	= 0,
	NVME_NVM_PIC_PITPS16B_MASK	= 0x1,
	NVME_NVM_PIC_PISTM16B_SHIFT	= 1,
	NVME_NVM_PIC_PISTM16B_MASK	= 0x1,
	NVME_NVM_PIC_STCRS_SHIFT	= 2,
	NVME_NVM_PIC_STCRS_MASK		= 0x1,
	NVME_NVM_PIC_QPIFS_SHIFT	= 3,
	NVME_NVM_PIC_QPIFS_MASK		= 0x1,
};

#define NVME_NVM_PIC_PITPS16B(pic)	NVME_GET(pic, NVM_PIC_PITPS16B)
#define NVME_NVM_PIC_PISTM16B(pic)	NVME_GET(pic, NVM_PIC_PISTM16B)
#define NVME_NVM_PIC_STCRS(pic)		NVME_GET(pic, NVM_PIC_STCRS)
#define NVME_NVM_PIC_QPIFS(pic)		NVME_GET(pic, NVM_PIC_QPIFS)

/**
 * enum nvme_nvm_id_ns_pifa - Protection Information Format Attribute
 * @NVME_NVM_PIFA_STMLA_SHIFT:			Shift amount to get Storage Tag Masking Level Attribute
 * @NVME_NVM_PIFA_STMLA_MASK:			Mask to get Storage Tag Masking Level Attribute
 * @NVME_NVM_PIFA_BIT_GRANULARITY_MASKING:	Bit Granularity Masking
 * @NVME_NVM_PIFA_BYTE_GRANULARITY_MASKING:	Byte Granularity Masking
 * @NVME_NVM_PIFA_MASKING_NOT_SUPPORTED:	Masking Not Supported
 */
enum nvme_nvm_id_ns_pifa {
	NVME_NVM_PIFA_STMLA_SHIFT		= 0,
	NVME_NVM_PIFA_STMLA_MASK		= 0xf,
	NVME_NVM_PIFA_BIT_GRANULARITY_MASKING	= 0x0,
	NVME_NVM_PIFA_BYTE_GRANULARITY_MASKING	= 0x1,
	NVME_NVM_PIFA_MASKING_NOT_SUPPORTED	= 0x2,
};

#define NVME_NVM_PIFA_STMLA(pifa)	NVME_GET(pifa, NVM_PIFA_STMLA)

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
 * enum nvme_id_iocs_iocsc - This field indicates the Identify I/O Command Set Data Structure
 * @NVME_IOCS_IOCSC_NVMCS_SHIFT:	Shift amount to get the value of NVM Command Set
 * @NVME_IOCS_IOCSC_NVMCS_MASK:		Mask to get the value of NVM Command Set
 * @NVME_IOCS_IOCSC_KVCS_SHIFT:		Shift amount to get the value of Key Value Command Set
 * @NVME_IOCS_IOCSC_KVCS_MASK:		Mask to get the value of Key Value Command Set
 * @NVME_IOCS_IOCSC_ZNSCS_SHIFT:	Shift amount to get the value of Zoned Namespace Command
 *					Set
 * @NVME_IOCS_IOCSC_ZNSCS_MASK:		Mask to get the value of Zoned Namespace Command Set
 * @NVME_IOCS_IOCSC_SLMCS_SHIFT:	Shift amount to get the value of Subsystem Local Memory
 *					Command Set
 * @NVME_IOCS_IOCSC_SLMCS_MASK:		Mask to get the value of Subsystem Local Memory Command Set
 * @NVME_IOCS_IOCSC_CPNCS_SHIFT:	Shift amount to get the value of Computational Programs
 *					Namespace Command Set
 * @NVME_IOCS_IOCSC_CPNCS_MASK:         Mask to get the value of Computational Programs Namespace
 *					Command Set
 */
enum nvme_id_iocs_iocsc {
	NVME_IOCS_IOCSC_NVMCS_SHIFT	= 0,
	NVME_IOCS_IOCSC_NVMCS_MASK	= 0x1,
	NVME_IOCS_IOCSC_KVCS_SHIFT	= 1,
	NVME_IOCS_IOCSC_KVCS_MASK	= 0x1,
	NVME_IOCS_IOCSC_ZNSCS_SHIFT	= 2,
	NVME_IOCS_IOCSC_ZNSCS_MASK	= 0x1,
	NVME_IOCS_IOCSC_SLMCS_SHIFT	= 3,
	NVME_IOCS_IOCSC_SLMCS_MASK	= 0x1,
	NVME_IOCS_IOCSC_CPNCS_SHIFT	= 4,
	NVME_IOCS_IOCSC_CPNCS_MASK	= 0x1,
};

#define NVME_IOCS_IOCSC_NVMCS(iocsc)	NVME_GET(iocsc, IOCS_IOCSC_NVMCS)
#define NVME_IOCS_IOCSC_KVCS(iocsc)	NVME_GET(iocsc, IOCS_IOCSC_KVCS)
#define NVME_IOCS_IOCSC_ZNSCS(iocsc)	NVME_GET(iocsc, IOCS_IOCSC_ZNSCS)
#define NVME_IOCS_IOCSC_SLMCS(iocsc)	NVME_GET(iocsc, IOCS_IOCSC_SLMCS)
#define NVME_IOCS_IOCSC_CPNCS(iocsc)	NVME_GET(iocsc, IOCS_IOCSC_CPNCS)

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

#define NVME_FDP_CONFIG_FDPA_RGIF(fdpa)		NVME_GET(fdpa, FDP_CONFIG_FDPA_RGIF)
#define NVME_FDP_CONFIG_FDPA_FDPVWC(fdpa)	NVME_GET(fdpa, FDP_CONFIG_FDPA_FDPVWC)
#define NVME_FDP_CONFIG_FDPA_VALID(fdpa)	NVME_GET(fdpa, FDP_CONFIG_FDPA_VALID)

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

#define NVME_FDP_RUHA_HOST(ruha)	NVME_GET(ruha, FDP_RUHA_HOST)
#define NVME_FDP_RUHA_CTRL(ruha)	NVME_GET(ruha, FDP_RUHA_CTRL)

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
 * Deprecated: doesn't support this struct.
 * Use NVME_FEAT_FDPE_*** definitions instead.
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

#define NVME_FDP_SUPP_EVENT_ENABLED(evta)	NVME_GET(evta, FDP_SUPP_EVENT_ENABLED)

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
 * struct nvme_copy_range_f0 - Copy - Source Range Entries Descriptor Format 0h
 * @rsvd0:	Reserved
 * @slba:	Starting LBA
 * @nlb:	Number of Logical Blocks
 * @cetype:	Bits 3-0: Command Extension Type
 * @rsvd19:	Reserved
 * @cev:	Command Extension Value
 * @rsvd22:	Reserved
 * @elbt:	Expected Initial Logical Block Reference Tag /
 *		Expected Logical Block Storage Tag
 * @elbatm:	Expected Logical Block Application Tag Mask
 * @elbat:	Expected Logical Block Application Tag
 */
struct nvme_copy_range_f0 {
	__u8			rsvd0[8];
	__le64			slba;
	__le16			nlb;
	__u8			cetype;
	__u8			rsvd19;
	__le16			cev;
	__u8			rsvd22[2];
	__be32			elbt;
	__be16			elbat;
	__be16			elbatm;
};

/**
 * struct nvme_copy_range_f1 - Copy - Source Range Entries Descriptor Format 1h
 * @rsvd0:	Reserved
 * @slba:	Starting LBA
 * @nlb:	Number of Logical Blocks
 * @cetype:	Bits 3-0: Command Extension Type
 * @rsvd19:	Reserved
 * @cev:	Command Extension Value
 * @rsvd22:	Reserved
 * @elbt:	Expected Initial Logical Block Reference Tag /
 *		Expected Logical Block Storage Tag
 * @elbatm:	Expected Logical Block Application Tag Mask
 * @elbat:	Expected Logical Block Application Tag
 */
struct nvme_copy_range_f1 {
	__u8			rsvd0[8];
	__le64			slba;
	__le16			nlb;
	__u8			cetype;
	__u8			rsvd19;
	__le16			cev;
	__u8			rsvd22[4];
	__u8			elbt[10];
	__be16			elbat;
	__be16			elbatm;
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
 * @cetype:	Bits 3-0: Command Extension Type
 * @rsvd19:	Reserved
 * @cev:	Command Extension Value
 * @sopt:	Source Options
 * @elbt:	Expected Initial Logical Block Reference Tag /
 *		Expected Logical Block Storage Tag
 * @elbatm:	Expected Logical Block Application Tag Mask
 * @elbat:	Expected Logical Block Application Tag
 */
struct nvme_copy_range_f2 {
	__le32			snsid;
	__u8			rsvd4[4];
	__le64			slba;
	__le16			nlb;
	__u8			cetype;
	__u8			rsvd19;
	__le16			cev;
	__le16			sopt;
	__be32			elbt;
	__be16			elbat;
	__be16			elbatm;
};

/**
 * struct nvme_copy_range_f3 - Copy - Source Range Entries Descriptor Format 3h
 * @snsid:	Source Namespace Identifier
 * @rsvd4:	Reserved
 * @slba:	Starting LBA
 * @nlb:	Number of Logical Blocks
 * @cetype:	Bits 3-0: Command Extension Type
 * @rsvd19:	Reserved
 * @sopt:	Source Options
 * @cev:	Command Extension Value
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
	__u8			cetype;
	__u8			rsvd19;
	__le16			cev;
	__le16			sopt;
	__u8			rsvd24[2];
	__u8			elbt[10];
	__be16			elbat;
	__be16			elbatm;
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
 * enum nvme_io_control_flags - I/O control flags
 * @NVME_IO_DTYPE_STREAMS:	Directive Type Streams
 * @NVME_IO_NSZ:		Namespace Zeroes
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
	NVME_IO_NSZ			= 1 << 7,
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

