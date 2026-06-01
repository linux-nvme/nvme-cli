// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 *          Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 *          Daniel Wagner <dwagner@suse.de>
 *
 * Zoned Namespace Command Set type definitions
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <nvme/types.h>
#include <nvme/nvme-types-base.h>

/**
 * DOC: nvme-types-zns.h
 *
 * Zoned Namespace Command Set type definitions
 *
 * Based on NVM Express Zoned Namespace Command Set Specification,
 * Revision 1.4, August 1, 2025 (Ratified)
 */

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

