/*
 * Definitions for the NVM Express interface
 * Copyright (c) 2011-2014, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */

#ifndef _LINUX_NVME_H
#define _LINUX_NVME_H

#include <linux/types.h>

#ifdef LIBUUID
#include <uuid/uuid.h>
#else
typedef struct {
	uint8_t b[16];
} uuid_t;
#endif

#ifdef __CHECKER__
#define __force       __attribute__((force))
#else
#define __force
#endif

static inline __le16 cpu_to_le16(uint16_t x)
{
	return (__force __le16)htole16(x);
}
static inline __le32 cpu_to_le32(uint32_t x)
{
	return (__force __le32)htole32(x);
}
static inline __le64 cpu_to_le64(uint64_t x)
{
	return (__force __le64)htole64(x);
}

static inline uint16_t le16_to_cpu(__le16 x)
{
	return le16toh((__force __u16)x);
}
static inline uint32_t le32_to_cpu(__le32 x)
{
	return le32toh((__force __u32)x);
}
static inline uint64_t le64_to_cpu(__le64 x)
{
	return le64toh((__force __u64)x);
}

/* NQN names in commands fields specified one size */
#define NVMF_NQN_FIELD_LEN	256

/* However the max length of a qualified name is another size */
#define NVMF_NQN_SIZE		223

#define NVMF_TRSVCID_SIZE	32
#define NVMF_TRADDR_SIZE	256
#define NVMF_TSAS_SIZE		256

#define NVME_DISC_SUBSYS_NAME	"nqn.2014-08.org.nvmexpress.discovery"

#define NVME_RDMA_IP_PORT	4420
#define NVME_DISC_IP_PORT	8009

#define NVME_NSID_ALL		0xffffffff

enum nvme_subsys_type {
	NVME_NQN_DISC	= 1,		/* Discovery type target subsystem */
	NVME_NQN_NVME	= 2,		/* NVME type target subsystem */
};

/* Address Family codes for Discovery Log Page entry ADRFAM field */
enum {
	NVMF_ADDR_FAMILY_PCI	= 0,	/* PCIe */
	NVMF_ADDR_FAMILY_IP4	= 1,	/* IP4 */
	NVMF_ADDR_FAMILY_IP6	= 2,	/* IP6 */
	NVMF_ADDR_FAMILY_IB	= 3,	/* InfiniBand */
	NVMF_ADDR_FAMILY_FC	= 4,	/* Fibre Channel */
	NVMF_ADDR_FAMILY_LOOP	= 254,	/* Reserved for host usage */
	NVMF_ADDR_FAMILY_MAX,
};

/* Transport Type codes for Discovery Log Page entry TRTYPE field */
enum {
	NVMF_TRTYPE_RDMA	= 1,	/* RDMA */
	NVMF_TRTYPE_FC		= 2,	/* Fibre Channel */
	NVMF_TRTYPE_TCP		= 3,	/* TCP */
	NVMF_TRTYPE_LOOP	= 254,	/* Reserved for host usage */
	NVMF_TRTYPE_MAX,
};

/* Transport Requirements codes for Discovery Log Page entry TREQ field */
enum {
	NVMF_TREQ_NOT_SPECIFIED	= 0,		/* Not specified */
	NVMF_TREQ_REQUIRED	= 1,		/* Required */
	NVMF_TREQ_NOT_REQUIRED	= 2,		/* Not Required */
	NVMF_TREQ_DISABLE_SQFLOW = (1 << 2),	/* SQ flow control disable supported */
};

/* RDMA QP Service Type codes for Discovery Log Page entry TSAS
 * RDMA_QPTYPE field
 */
enum {
	NVMF_RDMA_QPTYPE_CONNECTED	= 1, /* Reliable Connected */
	NVMF_RDMA_QPTYPE_DATAGRAM	= 2, /* Reliable Datagram */
};

/* RDMA QP Service Type codes for Discovery Log Page entry TSAS
 * RDMA_QPTYPE field
 */
enum {
	NVMF_RDMA_PRTYPE_NOT_SPECIFIED	= 1, /* No Provider Specified */
	NVMF_RDMA_PRTYPE_IB		= 2, /* InfiniBand */
	NVMF_RDMA_PRTYPE_ROCE		= 3, /* InfiniBand RoCE */
	NVMF_RDMA_PRTYPE_ROCEV2		= 4, /* InfiniBand RoCEV2 */
	NVMF_RDMA_PRTYPE_IWARP		= 5, /* IWARP */
};

/* RDMA Connection Management Service Type codes for Discovery Log Page
 * entry TSAS RDMA_CMS field
 */
enum {
	NVMF_RDMA_CMS_RDMA_CM	= 1, /* Sockets based endpoint addressing */
};

/* TCP port security type for  Discovery Log Page entry TSAS
 */
enum {
	NVMF_TCP_SECTYPE_NONE	= 0, /* No Security */
	NVMF_TCP_SECTYPE_TLS	= 1, /* Transport Layer Security */
};

/* I/O Command Sets
 */
enum {
	NVME_IOCS_NVM   = 0x00,
	NVME_IOCS_ZONED = 0x02,
};

#define NVME_AQ_DEPTH		32
#define NVME_NR_AEN_COMMANDS	1
#define NVME_AQ_BLK_MQ_DEPTH	(NVME_AQ_DEPTH - NVME_NR_AEN_COMMANDS)

/*
 * Subtract one to leave an empty queue entry for 'Full Queue' condition. See
 * NVM-Express 1.2 specification, section 4.1.2.
 */
#define NVME_AQ_MQ_TAG_DEPTH	(NVME_AQ_BLK_MQ_DEPTH - 1)

enum {
	NVME_REG_CAP	= 0x0000,	/* Controller Capabilities */
	NVME_REG_VS	= 0x0008,	/* Version */
	NVME_REG_INTMS	= 0x000c,	/* Interrupt Mask Set */
	NVME_REG_INTMC	= 0x0010,	/* Interrupt Mask Clear */
	NVME_REG_CC	= 0x0014,	/* Controller Configuration */
	NVME_REG_CSTS	= 0x001c,	/* Controller Status */
	NVME_REG_NSSR	= 0x0020,	/* NVM Subsystem Reset */
	NVME_REG_AQA	= 0x0024,	/* Admin Queue Attributes */
	NVME_REG_ASQ	= 0x0028,	/* Admin SQ Base Address */
	NVME_REG_ACQ	= 0x0030,	/* Admin CQ Base Address */
	NVME_REG_CMBLOC = 0x0038,	/* Controller Memory Buffer Location */
	NVME_REG_CMBSZ	= 0x003c,	/* Controller Memory Buffer Size */
	NVME_REG_BPINFO	= 0x0040,	/* Boot Partition Information */
	NVME_REG_BPRSEL	= 0x0044,	/* Boot Partition Read Select */
	NVME_REG_BPMBL	= 0x0048,	/* Boot Partition Memory Buffer Location */
	NVME_REG_CMBMSC	= 0x0050,	/* Controller Memory Buffer Memory Space Control */
	NVME_REG_CMBSTS	= 0x0058,	/* Controller Memory Buffer Status */
	NVME_REG_PMRCAP = 0x0e00,	/* Persistent Memory Capabilities */
	NVME_REG_PMRCTL = 0x0e04,	/* Persistent Memory Region Control */
	NVME_REG_PMRSTS = 0x0e08,	/* Persistent Memory Region Status */
	NVME_REG_PMREBS = 0x0e0c,	/* Persistent Memory Region Elasticity Buffer Size */
	NVME_REG_PMRSWTP= 0x0e10,	/* Persistent Memory Region Sustained Write Throughput */
	NVME_REG_PMRMSC = 0x0e14,	/* Persistent Memory Region Controller Memory Space Control */
	NVME_REG_DBS	= 0x1000,	/* SQ 0 Tail Doorbell */
};

#define NVME_CAP_MQES(cap)	((cap) & 0xffff)
#define NVME_CAP_TIMEOUT(cap)	(((cap) >> 24) & 0xff)
#define NVME_CAP_STRIDE(cap)	(((cap) >> 32) & 0xf)
#define NVME_CAP_NSSRC(cap)	(((cap) >> 36) & 0x1)
#define NVME_CAP_MPSMIN(cap)	(((cap) >> 48) & 0xf)
#define NVME_CAP_MPSMAX(cap)	(((cap) >> 52) & 0xf)

#define NVME_CMB_BIR(cmbloc)	((cmbloc) & 0x7)
#define NVME_CMB_OFST(cmbloc)	(((cmbloc) >> 12) & 0xfffff)
#define NVME_CMB_SZ(cmbsz)	(((cmbsz) >> 12) & 0xfffff)
#define NVME_CMB_SZU(cmbsz)	(((cmbsz) >> 8) & 0xf)

#define NVME_CMB_WDS(cmbsz)	((cmbsz) & 0x10)
#define NVME_CMB_RDS(cmbsz)	((cmbsz) & 0x8)
#define NVME_CMB_LISTS(cmbsz)	((cmbsz) & 0x4)
#define NVME_CMB_CQS(cmbsz)	((cmbsz) & 0x2)
#define NVME_CMB_SQS(cmbsz)	((cmbsz) & 0x1)

/*
 * Submission and Completion Queue Entry Sizes for the NVM command set.
 * (In bytes and specified as a power of two (2^n)).
 */
#define NVME_NVM_IOSQES		6
#define NVME_NVM_IOCQES		4

enum {
	NVME_CC_ENABLE		= 1 << 0,
	NVME_CC_CSS_NVM		= 0 << 4,
	NVME_CC_EN_SHIFT	= 0,
	NVME_CC_CSS_SHIFT	= 4,
	NVME_CC_MPS_SHIFT	= 7,
	NVME_CC_AMS_SHIFT	= 11,
	NVME_CC_SHN_SHIFT	= 14,
	NVME_CC_IOSQES_SHIFT	= 16,
	NVME_CC_IOCQES_SHIFT	= 20,
	NVME_CC_AMS_RR		= 0 << NVME_CC_AMS_SHIFT,
	NVME_CC_AMS_WRRU	= 1 << NVME_CC_AMS_SHIFT,
	NVME_CC_AMS_VS		= 7 << NVME_CC_AMS_SHIFT,
	NVME_CC_SHN_NONE	= 0 << NVME_CC_SHN_SHIFT,
	NVME_CC_SHN_NORMAL	= 1 << NVME_CC_SHN_SHIFT,
	NVME_CC_SHN_ABRUPT	= 2 << NVME_CC_SHN_SHIFT,
	NVME_CC_SHN_MASK	= 3 << NVME_CC_SHN_SHIFT,
	NVME_CC_IOSQES		= NVME_NVM_IOSQES << NVME_CC_IOSQES_SHIFT,
	NVME_CC_IOCQES		= NVME_NVM_IOCQES << NVME_CC_IOCQES_SHIFT,
	NVME_CSTS_RDY		= 1 << 0,
	NVME_CSTS_CFS		= 1 << 1,
	NVME_CSTS_NSSRO		= 1 << 4,
	NVME_CSTS_PP		= 1 << 5,
	NVME_CSTS_SHST_NORMAL	= 0 << 2,
	NVME_CSTS_SHST_OCCUR	= 1 << 2,
	NVME_CSTS_SHST_CMPLT	= 2 << 2,
	NVME_CSTS_SHST_MASK	= 3 << 2,
};

struct nvme_id_power_state {
	__le16			max_power;	/* centiwatts */
	__u8			rsvd2;
	__u8			flags;
	__le32			entry_lat;	/* microseconds */
	__le32			exit_lat;	/* microseconds */
	__u8			read_tput;
	__u8			read_lat;
	__u8			write_tput;
	__u8			write_lat;
	__le16			idle_power;
	__u8			idle_scale;
	__u8			rsvd19;
	__le16			active_power;
	__u8			active_work_scale;
	__u8			rsvd23[9];
};

/* idle and active power scales occupy the last 2 bits of the field */
#define POWER_SCALE(s) ((s) >> 6)

enum {
	NVME_PS_FLAGS_MAX_POWER_SCALE	= 1 << 0,
	NVME_PS_FLAGS_NON_OP_STATE	= 1 << 1,
};

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
	char			fguid[16];
	__le16			crdt1;
	__le16			crdt2;
	__le16			crdt3;
	__u8			rsvd134[122];
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
	__u8			rsvd356[156];
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
	__u8			rsvd544[224];
	char			subnqn[256];
	__u8			rsvd1024[768];
	__le32			ioccsz;
	__le32			iorcsz;
	__le16			icdoff;
	__u8			ctrattr;
	__u8			msdbd;
	__u8			rsvd1804[244];
	struct nvme_id_power_state	psd[32];
	__u8			vs[1024];
};

enum {
	NVME_CTRL_ONCS_COMPARE			= 1 << 0,
	NVME_CTRL_ONCS_WRITE_UNCORRECTABLE	= 1 << 1,
	NVME_CTRL_ONCS_DSM			= 1 << 2,
	NVME_CTRL_ONCS_WRITE_ZEROES		= 1 << 3,
	NVME_CTRL_ONCS_TIMESTAMP		= 1 << 6,
	NVME_CTRL_VWC_PRESENT			= 1 << 0,
	NVME_CTRL_OACS_SEC_SUPP                 = 1 << 0,
	NVME_CTRL_OACS_DIRECTIVES		= 1 << 5,
	NVME_CTRL_OACS_DBBUF_SUPP		= 1 << 8,
	NVME_CTRL_LPA_CMD_EFFECTS_LOG		= 1 << 1,
	NVME_CTRL_CTRATT_128_ID			= 1 << 0,
	NVME_CTRL_CTRATT_NON_OP_PSP		= 1 << 1,
	NVME_CTRL_CTRATT_NVM_SETS		= 1 << 2,
	NVME_CTRL_CTRATT_READ_RECV_LVLS		= 1 << 3,
	NVME_CTRL_CTRATT_ENDURANCE_GROUPS	= 1 << 4,
	NVME_CTRL_CTRATT_PREDICTABLE_LAT	= 1 << 5,
	NVME_CTRL_CTRATT_NAMESPACE_GRANULARITY	= 1 << 7,
	NVME_CTRL_CTRATT_UUID_LIST		= 1 << 9,
};

struct nvme_lbaf {
	__le16			ms;
	__u8			ds;
	__u8			rp;
};

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
	__u8			rsvd81[11];
	__le32			anagrpid;
	__u8			rsvd96[3];
	__u8			nsattr;
	__le16			nvmsetid;
	__le16			endgid;
	__u8			nguid[16];
	__u8			eui64[8];
	struct nvme_lbaf	lbaf[16];
	__u8			rsvd192[192];
	__u8			vs[3712];
};

struct nvme_id_iocs {
	__le64 iocs[512];
};

enum {
	NVME_ID_CNS_NS			= 0x00,
	NVME_ID_CNS_CTRL		= 0x01,
	NVME_ID_CNS_NS_ACTIVE_LIST	= 0x02,
	NVME_ID_CNS_NS_DESC_LIST	= 0x03,
	NVME_ID_CNS_NVMSET_LIST		= 0x04,
	NVME_ID_CNS_CSI_ID_NS		= 0x05,
	NVME_ID_CNS_CSI_ID_CTRL		= 0x06,
	NVME_ID_CNS_CSI_NS_ACTIVE_LIST = 0x07,
	NVME_ID_CNS_NS_PRESENT_LIST	= 0x10,
	NVME_ID_CNS_NS_PRESENT		= 0x11,
	NVME_ID_CNS_CTRL_NS_LIST	= 0x12,
	NVME_ID_CNS_CTRL_LIST		= 0x13,
	NVME_ID_CNS_SCNDRY_CTRL_LIST	= 0x15,
	NVME_ID_CNS_NS_GRANULARITY	= 0x16,
	NVME_ID_CNS_UUID_LIST		= 0x17,
	NVME_ID_CNS_CSI_NS_PRESENT_LIST = 0x1a,
	NVME_ID_CNS_CSI_NS_PRESENT  = 0x1b,
	NVME_ID_CNS_CSI             = 0x1c,
};

enum {
	NVME_DIR_IDENTIFY		= 0x00,
	NVME_DIR_STREAMS		= 0x01,
	NVME_DIR_SND_ID_OP_ENABLE	= 0x01,
	NVME_DIR_SND_ST_OP_REL_ID	= 0x01,
	NVME_DIR_SND_ST_OP_REL_RSC	= 0x02,
	NVME_DIR_RCV_ID_OP_PARAM	= 0x01,
	NVME_DIR_RCV_ST_OP_PARAM	= 0x01,
	NVME_DIR_RCV_ST_OP_STATUS	= 0x02,
	NVME_DIR_RCV_ST_OP_RESOURCE	= 0x03,
	NVME_DIR_ENDIR			= 0x01,
};

enum {
	NVME_NS_FEAT_THIN	= 1 << 0,
	NVME_NS_FLBAS_LBA_MASK	= 0xf,
	NVME_NS_FLBAS_META_EXT	= 0x10,
	NVME_LBAF_RP_BEST	= 0,
	NVME_LBAF_RP_BETTER	= 1,
	NVME_LBAF_RP_GOOD	= 2,
	NVME_LBAF_RP_DEGRADED	= 3,
	NVME_NS_DPC_PI_LAST	= 1 << 4,
	NVME_NS_DPC_PI_FIRST	= 1 << 3,
	NVME_NS_DPC_PI_TYPE3	= 1 << 2,
	NVME_NS_DPC_PI_TYPE2	= 1 << 1,
	NVME_NS_DPC_PI_TYPE1	= 1 << 0,
	NVME_NS_DPS_PI_FIRST	= 1 << 3,
	NVME_NS_DPS_PI_MASK	= 0x7,
	NVME_NS_DPS_PI_TYPE1	= 1,
	NVME_NS_DPS_PI_TYPE2	= 2,
	NVME_NS_DPS_PI_TYPE3	= 3,
};

struct nvme_ns_id_desc {
	__u8 nidt;
	__u8 nidl;
	__le16 reserved;
};

#define NVME_NIDT_EUI64_LEN	8
#define NVME_NIDT_NGUID_LEN	16
#define NVME_NIDT_UUID_LEN	16
#define NVME_NIDT_CSI_LEN	1

enum {
	NVME_NIDT_EUI64		= 0x01,
	NVME_NIDT_NGUID		= 0x02,
	NVME_NIDT_UUID		= 0x03,
	NVME_NIDT_CSI		= 0x04,
};

#define NVME_MAX_NVMSET		31

struct nvme_nvmset_attr_entry {
	__le16			id;
	__le16			endurance_group_id;
	__u8			rsvd4[4];
	__le32			random_4k_read_typical;
	__le32			opt_write_size;
	__u8			total_nvmset_cap[16];
	__u8			unalloc_nvmset_cap[16];
	__u8			rsvd48[80];
};

struct nvme_id_nvmset {
	__u8				nid;
	__u8				rsvd1[127];
	struct nvme_nvmset_attr_entry	ent[NVME_MAX_NVMSET];
};

struct nvme_id_ns_granularity_list_entry {
	__le64			namespace_size_granularity;
	__le64			namespace_capacity_granularity;
};

struct nvme_id_ns_granularity_list {
	__le32			attributes;
	__u8			num_descriptors;
	__u8			rsvd[27];
	struct nvme_id_ns_granularity_list_entry entry[16];
};

#define NVME_MAX_UUID_ENTRIES	128
struct nvme_id_uuid_list_entry {
	__u8			header;
	__u8			rsvd1[15];
	__u8			uuid[16];
};

struct nvme_id_uuid_list {
	struct nvme_id_uuid_list_entry	entry[NVME_MAX_UUID_ENTRIES];
};

/**
 * struct nvme_telemetry_log_page_hdr - structure for telemetry log page
 * @lpi: Log page identifier
 * @iee_oui: IEEE OUI Identifier
 * @dalb1: Data area 1 last block
 * @dalb2: Data area 2 last block
 * @dalb3: Data area 3 last block
 * @ctrlavail: Controller initiated data available
 * @ctrldgn: Controller initiated telemetry Data Generation Number
 * @rsnident: Reason Identifier
 * @telemetry_dataarea: Contains telemetry data block
 *
 * This structure can be used for both telemetry host-initiated log page
 * and controller-initiated log page.
 */
struct nvme_telemetry_log_page_hdr {
	__u8	lpi;
	__u8	rsvd[4];
	__u8	iee_oui[3];
	__le16	dalb1;
	__le16	dalb2;
	__le16	dalb3;
	__u8	rsvd1[368];
	__u8	ctrlavail;
	__u8	ctrldgn;
	__u8	rsnident[128];
	__u8	telemetry_dataarea[0];
};

struct nvme_endurance_group_log {
	__u8	critical_warning;
	__u8	rsvd1[2];
	__u8	avl_spare;
	__u8	avl_spare_threshold;
	__u8	percent_used;
	__u8	rsvd6[26];
	__u8	endurance_estimate[16];
	__u8	data_units_read[16];
	__u8	data_units_written[16];
	__u8	media_units_written[16];
	__u8	host_read_cmds[16];
	__u8	host_write_cmds[16];
	__u8	media_data_integrity_err[16];
	__u8	num_err_info_log_entries[16];
	__u8	rsvd160[352];
};

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

struct nvme_self_test_res {
	__u8 			dsts;
	__u8			seg;
	__u8			vdi;
	__u8			rsvd3;
	__le64			poh;
	__le32			nsid;
	__le64			flba;
	__u8			sct;
	__u8			sc;
	__u8			vs[2];
} __attribute__((packed));

enum {
	NVME_ST_CODE_SHIFT    		= 4,
	NVME_ST_CODE_SHORT_OP 		= 0x1,
	NVME_ST_CODE_EXT_OP   		= 0x2,
	NVME_ST_CODE_VS	      		= 0xe,
	NVME_ST_RES_MASK      		= 0xf,
	NVME_ST_RES_NO_ERR    		= 0x0,
	NVME_ST_RES_ABORTED   		= 0x1,
	NVME_ST_RES_CLR	      		= 0x2,
	NVME_ST_RES_NS_REMOVED		= 0x3,
	NVME_ST_RES_ABORTED_FORMAT	= 0x4,
	NVME_ST_RES_FATAL_ERR		= 0x5,
	NVME_ST_RES_UNKNOWN_SEG_FAIL	= 0x6,
	NVME_ST_RES_KNOWN_SEG_FAIL	= 0x7,
	NVME_ST_RES_ABORTED_UNKNOWN	= 0x8,
	NVME_ST_RES_ABORTED_SANITIZE	= 0x9,
	NVME_ST_RES_NOT_USED		= 0xf,
	NVME_ST_VALID_NSID		= 1 << 0,
	NVME_ST_VALID_FLBA		= 1 << 1,
	NVME_ST_VALID_SCT		= 1 << 2,
	NVME_ST_VALID_SC		= 1 << 3,
	NVME_ST_REPORTS			= 20,
};

struct nvme_self_test_log {
	__u8                      crnt_dev_selftest_oprn;
	__u8                      crnt_dev_selftest_compln;
	__u8                      rsvd[2];
	struct nvme_self_test_res result[20];
} __attribute__((packed));

struct nvme_fw_slot_info_log {
	__u8			afi;
	__u8			rsvd1[7];
	__le64			frs[7];
	__u8			rsvd64[448];
};

struct nvme_lba_status_desc {
	__u64 dslba;
	__u32 nlb;
	__u8 rsvd_12;
	__u8 status;
	__u8 rsvd_15_14[2];
};

struct nvme_lba_status {
	__u32 nlsd;
	__u8 cmpc;
	__u8 rsvd_7_5[3];
	struct nvme_lba_status_desc descs[0];
};

/* NVMe Namespace Write Protect State */
enum {
	NVME_NS_NO_WRITE_PROTECT = 0,
	NVME_NS_WRITE_PROTECT,
	NVME_NS_WRITE_PROTECT_POWER_CYCLE,
	NVME_NS_WRITE_PROTECT_PERMANENT,
};

#define NVME_MAX_CHANGED_NAMESPACES     1024

struct nvme_changed_ns_list_log {
	__le32			log[NVME_MAX_CHANGED_NAMESPACES];
};

enum {
	NVME_CMD_EFFECTS_CSUPP		= 1 << 0,
	NVME_CMD_EFFECTS_LBCC		= 1 << 1,
	NVME_CMD_EFFECTS_NCC		= 1 << 2,
	NVME_CMD_EFFECTS_NIC		= 1 << 3,
	NVME_CMD_EFFECTS_CCC		= 1 << 4,
	NVME_CMD_EFFECTS_CSE_MASK	= 3 << 16,
	NVME_CMD_EFFECTS_UUID_SEL	= 1 << 19,
};

struct nvme_effects_log {
	__le32 acs[256];
	__le32 iocs[256];
	__u8   resv[2048];
};

enum nvme_ana_state {
	NVME_ANA_OPTIMIZED		= 0x01,
	NVME_ANA_NONOPTIMIZED		= 0x02,
	NVME_ANA_INACCESSIBLE		= 0x03,
	NVME_ANA_PERSISTENT_LOSS	= 0x04,
	NVME_ANA_CHANGE			= 0x0f,
};

struct nvme_ana_group_desc {
	__le32  grpid;
	__le32  nnsids;
	__le64  chgcnt;
	__u8    state;
	__u8    rsvd17[15];
	__le32  nsids[];
};

/* flag for the log specific field of the ANA log */
#define NVME_ANA_LOG_RGO   (1 << 0)

struct nvme_ana_rsp_hdr {
	__le64  chgcnt;
	__le16  ngrps;
	__le16  rsvd10[3];
};

/* persistent event type 02h */
struct nvme_fw_commit_event {
    __le64	old_fw_rev;
    __le64 	new_fw_rev;
    __u8 	fw_commit_action;
    __u8 	fw_slot;
    __u8 	sct_fw;
    __u8 	sc_fw;
    __le16 	vndr_assign_fw_commit_rc;
} __attribute__((packed));

/* persistent event type 03h */
struct nvme_time_stamp_change_event {
    __le64 	previous_timestamp;
    __le64 	ml_secs_since_reset;
};

/* persistent event type 04h */
struct nvme_power_on_reset_info_list {
    __le16   cid;
    __u8     fw_act;
    __u8     op_in_prog;
    __u8     rsvd4[12];
    __le32   ctrl_power_cycle;
    __le64   power_on_ml_seconds;
    __le64   ctrl_time_stamp;
} __attribute__((packed));

/* persistent event type 05h */
struct nvme_nss_hw_err_event {
    __le16 	nss_hw_err_event_code;
    __u8 	rsvd2[2];
    __u8 	*add_hw_err_info;
};

/* persistent event type 06h */
struct nvme_change_ns_event {
	__le32	nsmgt_cdw10;
	__u8	rsvd4[4];
	__le64	nsze;
	__u8	nscap[16];
	__u8	flbas;
	__u8	dps;
	__u8	nmic;
	__u8	rsvd35;
	__le32	ana_grp_id;
	__le16	nvmset_id;
	__le16	rsvd42;
	__le32	nsid;
};

/* persistent event type 07h */
struct nvme_format_nvm_start_event {
    __le32 	nsid;
    __u8 	fna;
    __u8 	rsvd5[3];
    __le32 	format_nvm_cdw10;
};

/* persistent event type 08h */
struct nvme_format_nvm_compln_event {
    __le32 	nsid;
    __u8 	smallest_fpi;
    __u8 	format_nvm_status;
    __le16 	compln_info;
    __le32 	status_field;
};

/* persistent event type 09h */
struct nvme_sanitize_start_event {
    __le32 	sani_cap;
    __le32 	sani_cdw10;
    __le32 	sani_cdw11;
};

/* persistent event type 0Ah */
struct nvme_sanitize_compln_event {
    __le16 	sani_prog;
    __le16 	sani_status;
    __le16 	cmpln_info;
	__u8 	rsvd6[2];
};

/* persistent event type 0Dh */
struct nvme_thermal_exc_event {
    __u8 	over_temp;
    __u8 	threshold;
};

/* persistent event entry head */
struct nvme_persistent_event_entry_head {
	__u8	etype;
	__u8	etype_rev;
	__u8	ehl;
	__u8	rsvd3;
	__le16	ctrl_id;
	__le64	etimestamp;
	__u8	rsvd14[6];
	__le16	vsil;
	__le16	el;
} __attribute__((packed));

/* persistent event log head */
struct nvme_persistent_event_log_head {
	__u8	log_id;
	__u8	rsvd1[3];
	__le32	tnev;
	__le64	tll;
	__u8	log_rev;
	__u8	rsvd17;
	__le16	head_len;
	__le64	timestamp;
	__u8	poh[16];
	__le64	pcc;
	__le16	vid;
	__le16	ssvid;
	__u8	sn[20];
	__u8	mn[40];
	__u8	subnqn[256];
	__u8    rsvd372[108];
	__u8	supp_event_bm[32];
} __attribute__((packed));

enum nvme_persistent_event_types {
    NVME_SMART_HEALTH_EVENT         = 0x01,
    NVME_FW_COMMIT_EVENT            = 0x02,
    NVME_TIMESTAMP_EVENT            = 0x03,
    NVME_POWER_ON_RESET_EVENT       = 0x04,
    NVME_NSS_HW_ERROR_EVENT         = 0x05,
    NVME_CHANGE_NS_EVENT            = 0x06,
    NVME_FORMAT_START_EVENT         = 0x07,
    NVME_FORMAT_COMPLETION_EVENT    = 0x08,
    NVME_SANITIZE_START_EVENT       = 0x09,
    NVME_SANITIZE_COMPLETION_EVENT  = 0x0a,
    NVME_THERMAL_EXCURSION_EVENT    = 0x0d
};

enum nvme_persistent_event_log_actions {
	NVME_PEVENT_LOG_READ				= 0x0,
	NVME_PEVENT_LOG_EST_CTX_AND_READ	= 0x1,
	NVME_PEVENT_LOG_RELEASE_CTX			= 0x2,
};

struct nvme_predlat_event_agg_log_page {
	__le64	num_entries;
	__le16	entries[];
};

struct nvme_predlat_per_nvmset_log_page {
	__u8	status;
	__u8	rsvd1;
	__le16	event_type;
	__u8	rsvd4[28];
	__le64	dtwin_rtyp;
	__le64	dtwin_wtyp;
	__le64	dtwin_timemax;
	__le64	ndwin_timemin_high;
	__le64	ndwin_timemin_low;
	__u8	rsvd72[56];
	__le64	dtwin_restimate;
	__le64	dtwin_westimate;
	__le64	dtwin_testimate;
	__u8	rsvd152[360];
};

enum {
	NVME_SMART_CRIT_SPARE		= 1 << 0,
	NVME_SMART_CRIT_TEMPERATURE	= 1 << 1,
	NVME_SMART_CRIT_RELIABILITY	= 1 << 2,
	NVME_SMART_CRIT_MEDIA		= 1 << 3,
	NVME_SMART_CRIT_VOLATILE_MEMORY	= 1 << 4,
};

enum {
	NVME_AER_ERROR			= 0,
	NVME_AER_SMART			= 1,
	NVME_AER_CSS			= 6,
	NVME_AER_VS			= 7,
};

struct nvme_lba_range_type {
	__u8			type;
	__u8			attributes;
	__u8			rsvd2[14];
	__u64			slba;
	__u64			nlb;
	__u8			guid[16];
	__u8			rsvd48[16];
};

enum {
	NVME_LBART_TYPE_FS	= 0x01,
	NVME_LBART_TYPE_RAID	= 0x02,
	NVME_LBART_TYPE_CACHE	= 0x03,
	NVME_LBART_TYPE_SWAP	= 0x04,

	NVME_LBART_ATTRIB_TEMP	= 1 << 0,
	NVME_LBART_ATTRIB_HIDE	= 1 << 1,
};

/* Predictable Latency Mode - Deterministic Threshold Configuration Data */
struct nvme_plm_config {
	__le16	enable_event;
	__u8	rsvd2[30];
	__le64	dtwin_reads_thresh;
	__le64	dtwin_writes_thresh;
	__le64	dtwin_time_thresh;
	__u8	rsvd56[456];
};

struct nvme_reservation_status {
	__le32	gen;
	__u8	rtype;
	__u8	regctl[2];
	__u8	resv5[2];
	__u8	ptpls;
	__u8	resv10[13];
	struct {
		__le16	cntlid;
		__u8	rcsts;
		__u8	resv3[5];
		__le64	hostid;
		__le64	rkey;
	} regctl_ds[];
};

struct nvme_reservation_status_ext {
	__le32	gen;
	__u8	rtype;
	__u8	regctl[2];
	__u8	resv5[2];
	__u8	ptpls;
	__u8	resv10[14];
	__u8	resv24[40];
	struct {
		__le16	cntlid;
		__u8	rcsts;
		__u8	resv3[5];
		__le64	rkey;
		__u8	hostid[16];
		__u8	resv32[32];
	} regctl_eds[];
};

enum nvme_async_event_type {
	NVME_AER_TYPE_ERROR	= 0,
	NVME_AER_TYPE_SMART	= 1,
	NVME_AER_TYPE_NOTICE	= 2,
};

/* I/O commands */

enum nvme_opcode {
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
	nvme_cmd_resv_release	= 0x15,
	nvme_cmd_copy		= 0x19,
	nvme_zns_cmd_mgmt_send	= 0x79,
	nvme_zns_cmd_mgmt_recv	= 0x7a,
	nvme_zns_cmd_append	= 0x7d,
};

/*
 * Descriptor subtype - lower 4 bits of nvme_(keyed_)sgl_desc identifier
 *
 * @NVME_SGL_FMT_ADDRESS:     absolute address of the data block
 * @NVME_SGL_FMT_OFFSET:      relative offset of the in-capsule data block
 * @NVME_SGL_FMT_TRANSPORT_A: transport defined format, value 0xA
 * @NVME_SGL_FMT_INVALIDATE:  RDMA transport specific remote invalidation
 *                            request subtype
 */
enum {
	NVME_SGL_FMT_ADDRESS		= 0x00,
	NVME_SGL_FMT_OFFSET		= 0x01,
	NVME_SGL_FMT_TRANSPORT_A	= 0x0A,
	NVME_SGL_FMT_INVALIDATE		= 0x0f,
};

/*
 * Descriptor type - upper 4 bits of nvme_(keyed_)sgl_desc identifier
 *
 * For struct nvme_sgl_desc:
 *   @NVME_SGL_FMT_DATA_DESC:		data block descriptor
 *   @NVME_SGL_FMT_SEG_DESC:		sgl segment descriptor
 *   @NVME_SGL_FMT_LAST_SEG_DESC:	last sgl segment descriptor
 *
 * For struct nvme_keyed_sgl_desc:
 *   @NVME_KEY_SGL_FMT_DATA_DESC:	keyed data block descriptor
 *
 * Transport-specific SGL types:
 *   @NVME_TRANSPORT_SGL_DATA_DESC:	Transport SGL data dlock descriptor
 */
enum {
	NVME_SGL_FMT_DATA_DESC		= 0x00,
	NVME_SGL_FMT_SEG_DESC		= 0x02,
	NVME_SGL_FMT_LAST_SEG_DESC	= 0x03,
	NVME_KEY_SGL_FMT_DATA_DESC	= 0x04,
	NVME_TRANSPORT_SGL_DATA_DESC	= 0x05,
};

struct nvme_sgl_desc {
	__le64	addr;
	__le32	length;
	__u8	rsvd[3];
	__u8	type;
};

struct nvme_keyed_sgl_desc {
	__le64	addr;
	__u8	length[3];
	__u8	key[4];
	__u8	type;
};

union nvme_data_ptr {
	struct {
		__le64	prp1;
		__le64	prp2;
	};
	struct nvme_sgl_desc	sgl;
	struct nvme_keyed_sgl_desc ksgl;
};

/*
 * Lowest two bits of our flags field (FUSE field in the spec):
 *
 * @NVME_CMD_FUSE_FIRST:   Fused Operation, first command
 * @NVME_CMD_FUSE_SECOND:  Fused Operation, second command
 *
 * Highest two bits in our flags field (PSDT field in the spec):
 *
 * @NVME_CMD_PSDT_SGL_METABUF:	Use SGLS for this transfer,
 *	If used, MPTR contains addr of single physical buffer (byte aligned).
 * @NVME_CMD_PSDT_SGL_METASEG:	Use SGLS for this transfer,
 *	If used, MPTR contains an address of an SGL segment containing
 *	exactly 1 SGL descriptor (qword aligned).
 */
enum {
	NVME_CMD_FUSE_FIRST	= (1 << 0),
	NVME_CMD_FUSE_SECOND	= (1 << 1),

	NVME_CMD_SGL_METABUF	= (1 << 6),
	NVME_CMD_SGL_METASEG	= (1 << 7),
	NVME_CMD_SGL_ALL	= NVME_CMD_SGL_METABUF | NVME_CMD_SGL_METASEG,
};

enum {
	NVME_RW_LR			= 1 << 15,
	NVME_RW_FUA			= 1 << 14,
	NVME_RW_DEAC			= 1 << 9,
	NVME_RW_DSM_FREQ_UNSPEC		= 0,
	NVME_RW_DSM_FREQ_TYPICAL	= 1,
	NVME_RW_DSM_FREQ_RARE		= 2,
	NVME_RW_DSM_FREQ_READS		= 3,
	NVME_RW_DSM_FREQ_WRITES		= 4,
	NVME_RW_DSM_FREQ_RW		= 5,
	NVME_RW_DSM_FREQ_ONCE		= 6,
	NVME_RW_DSM_FREQ_PREFETCH	= 7,
	NVME_RW_DSM_FREQ_TEMP		= 8,
	NVME_RW_DSM_LATENCY_NONE	= 0 << 4,
	NVME_RW_DSM_LATENCY_IDLE	= 1 << 4,
	NVME_RW_DSM_LATENCY_NORM	= 2 << 4,
	NVME_RW_DSM_LATENCY_LOW		= 3 << 4,
	NVME_RW_DSM_SEQ_REQ		= 1 << 6,
	NVME_RW_DSM_COMPRESSED		= 1 << 7,
	NVME_RW_PRINFO_PRCHK_REF	= 1 << 10,
	NVME_RW_PRINFO_PRCHK_APP	= 1 << 11,
	NVME_RW_PRINFO_PRCHK_GUARD	= 1 << 12,
	NVME_RW_PRINFO_PRACT		= 1 << 13,
	NVME_RW_DTYPE_STREAMS		= 1 << 4,
};

enum {
	NVME_DSMGMT_IDR		= 1 << 0,
	NVME_DSMGMT_IDW		= 1 << 1,
	NVME_DSMGMT_AD		= 1 << 2,
};

#define NVME_DSM_MAX_RANGES	256

struct nvme_dsm_range {
	__le32			cattr;
	__le32			nlb;
	__le64			slba;
};

struct nvme_copy_range {
	__u8			rsvd0[8];
	__le64			slba;
	__le16			nlb;
	__u8			rsvd18[6];
	__le32			eilbrt;
	__le16			elbatm;
	__le16			elbat;
};

/* Features */
struct nvme_feat_auto_pst {
	__le64 entries[32];
};

enum {
	NVME_HOST_MEM_ENABLE	= (1 << 0),
	NVME_HOST_MEM_RETURN	= (1 << 1),
};

/* Admin commands */

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
	nvme_admin_activate_fw		= 0x10,
	nvme_admin_download_fw		= 0x11,
	nvme_admin_dev_self_test	= 0x14,
	nvme_admin_ns_attach		= 0x15,
	nvme_admin_keep_alive		= 0x18,
	nvme_admin_directive_send	= 0x19,
	nvme_admin_directive_recv	= 0x1a,
	nvme_admin_virtual_mgmt		= 0x1c,
	nvme_admin_nvme_mi_send		= 0x1d,
	nvme_admin_nvme_mi_recv		= 0x1e,
	nvme_admin_dbbuf		= 0x7C,
	nvme_admin_format_nvm		= 0x80,
	nvme_admin_security_send	= 0x81,
	nvme_admin_security_recv	= 0x82,
	nvme_admin_sanitize_nvm		= 0x84,
	nvme_admin_get_lba_status	= 0x86,
};

enum {
	NVME_QUEUE_PHYS_CONTIG	= (1 << 0),
	NVME_CQ_IRQ_ENABLED	= (1 << 1),
	NVME_SQ_PRIO_URGENT	= (0 << 1),
	NVME_SQ_PRIO_HIGH	= (1 << 1),
	NVME_SQ_PRIO_MEDIUM	= (2 << 1),
	NVME_SQ_PRIO_LOW	= (3 << 1),
	NVME_LOG_ERROR		= 0x01,
	NVME_LOG_SMART		= 0x02,
	NVME_LOG_FW_SLOT	= 0x03,
	NVME_LOG_CHANGED_NS	= 0x04,
	NVME_LOG_CMD_EFFECTS	= 0x05,
	NVME_LOG_DEVICE_SELF_TEST = 0x06,
	NVME_LOG_TELEMETRY_HOST = 0x07,
	NVME_LOG_TELEMETRY_CTRL = 0x08,
	NVME_LOG_ENDURANCE_GROUP = 0x09,
	NVME_LOG_PRELAT_PER_NVMSET	= 0x0a,
	NVME_LOG_ANA		= 0x0c,
	NVME_LOG_PRELAT_EVENT_AGG	= 0x0b,
	NVME_LOG_PERSISTENT_EVENT   = 0x0d,
	NVME_LOG_DISC		= 0x70,
	NVME_LOG_RESERVATION	= 0x80,
	NVME_LOG_SANITIZE	= 0x81,
	NVME_LOG_ZONE_CHANGED_LIST = 0xbf,
	NVME_FWACT_REPL		= (0 << 3),
	NVME_FWACT_REPL_ACTV	= (1 << 3),
	NVME_FWACT_ACTV		= (2 << 3),
};

enum nvme_feat {
	NVME_FEAT_NONE = 0x0,
	NVME_FEAT_ARBITRATION	= 0x01,
	NVME_FEAT_POWER_MGMT	= 0x02,
	NVME_FEAT_LBA_RANGE	= 0x03,
	NVME_FEAT_TEMP_THRESH	= 0x04,
	NVME_FEAT_ERR_RECOVERY	= 0x05,
	NVME_FEAT_VOLATILE_WC	= 0x06,
	NVME_FEAT_NUM_QUEUES	= 0x07,
	NVME_FEAT_IRQ_COALESCE	= 0x08,
	NVME_FEAT_IRQ_CONFIG	= 0x09,
	NVME_FEAT_WRITE_ATOMIC	= 0x0a,
	NVME_FEAT_ASYNC_EVENT	= 0x0b,
	NVME_FEAT_AUTO_PST	= 0x0c,
	NVME_FEAT_HOST_MEM_BUF	= 0x0d,
	NVME_FEAT_TIMESTAMP	= 0x0e,
	NVME_FEAT_KATO		= 0x0f,
	NVME_FEAT_HCTM		= 0X10,
	NVME_FEAT_NOPSC		= 0X11,
	NVME_FEAT_RRL		= 0x12,
	NVME_FEAT_PLM_CONFIG	= 0x13,
	NVME_FEAT_PLM_WINDOW	= 0x14,
	NVME_FEAT_HOST_BEHAVIOR	= 0x16,
	NVME_FEAT_SANITIZE	= 0x17,
	NVME_FEAT_IOCS_PROFILE	= 0x19,
	NVME_FEAT_SW_PROGRESS	= 0x80,
	NVME_FEAT_HOST_ID	= 0x81,
	NVME_FEAT_RESV_MASK	= 0x82,
	NVME_FEAT_RESV_PERSIST	= 0x83,
	NVME_FEAT_WRITE_PROTECT	= 0x84,
} __attribute__ ((__packed__));

enum {
	NVME_NO_LOG_LSP       = 0x0,
	NVME_NO_LOG_LPO       = 0x0,
	NVME_LOG_ANA_LSP_RGO  = 0x1,
	NVME_TELEM_LSP_CREATE = 0x1,
};

/* Sanitize and Sanitize Monitor/Log */
enum {
	/* Sanitize */
	NVME_SANITIZE_NO_DEALLOC	= 0x00000200,
	NVME_SANITIZE_OIPBP		= 0x00000100,
	NVME_SANITIZE_OWPASS_SHIFT	= 0x00000004,
	NVME_SANITIZE_AUSE		= 0x00000008,
	NVME_SANITIZE_ACT_CRYPTO_ERASE	= 0x00000004,
	NVME_SANITIZE_ACT_OVERWRITE	= 0x00000003,
	NVME_SANITIZE_ACT_BLOCK_ERASE	= 0x00000002,
	NVME_SANITIZE_ACT_EXIT		= 0x00000001,

	/* Sanitize Monitor/Log */
	NVME_SANITIZE_LOG_DATA_LEN		= 0x0014,
	NVME_SANITIZE_LOG_GLOBAL_DATA_ERASED	= 0x0100,
	NVME_SANITIZE_LOG_NUM_CMPLTED_PASS_MASK	= 0x00F8,
	NVME_SANITIZE_LOG_STATUS_MASK		= 0x0007,
	NVME_SANITIZE_LOG_NEVER_SANITIZED	= 0x0000,
	NVME_SANITIZE_LOG_COMPLETED_SUCCESS	= 0x0001,
	NVME_SANITIZE_LOG_IN_PROGESS		= 0x0002,
	NVME_SANITIZE_LOG_COMPLETED_FAILED	= 0x0003,
	NVME_SANITIZE_LOG_ND_COMPLETED_SUCCESS	= 0x0004,
};

#define NVME_IDENTIFY_DATA_SIZE 4096

struct nvme_host_mem_buf_desc {
	__le64			addr;
	__le32			size;
	__u32			rsvd;
};

/* Sanitize Log Page */
struct nvme_sanitize_log_page {
	__le16			progress;
	__le16			status;
	__le32			cdw10_info;
	__le32			est_ovrwrt_time;
	__le32			est_blk_erase_time;
	__le32			est_crypto_erase_time;
	__le32			est_ovrwrt_time_with_no_deallocate;
	__le32			est_blk_erase_time_with_no_deallocate;
	__le32			est_crypto_erase_time_with_no_deallocate;
};

/*
 * Fabrics subcommands.
 */
enum nvmf_fabrics_opcode {
	nvme_fabrics_command		= 0x7f,
};

enum nvmf_capsule_command {
	nvme_fabrics_type_property_set	= 0x00,
	nvme_fabrics_type_connect	= 0x01,
	nvme_fabrics_type_property_get	= 0x04,
};

/*
 * The legal cntlid range a NVMe Target will provide.
 * Note that cntlid of value 0 is considered illegal in the fabrics world.
 * Devices based on earlier specs did not have the subsystem concept;
 * therefore, those devices had their cntlid value set to 0 as a result.
 */
#define NVME_CNTLID_MIN		1
#define NVME_CNTLID_MAX		0xffef
#define NVME_CNTLID_DYNAMIC	0xffff

#define MAX_DISC_LOGS	255

/* Discovery log page entry */
struct nvmf_disc_rsp_page_entry {
	__u8		trtype;
	__u8		adrfam;
	__u8		subtype;
	__u8		treq;
	__le16		portid;
	__le16		cntlid;
	__le16		asqsz;
	__u8		resv8[22];
	char		trsvcid[NVMF_TRSVCID_SIZE];
	__u8		resv64[192];
	char		subnqn[NVMF_NQN_FIELD_LEN];
	char		traddr[NVMF_TRADDR_SIZE];
	union tsas {
		char		common[NVMF_TSAS_SIZE];
		struct rdma {
			__u8	qptype;
			__u8	prtype;
			__u8	cms;
			__u8	resv3[5];
			__u16	pkey;
			__u8	resv10[246];
		} rdma;
		struct tcp {
			__u8	sectype;
		} tcp;
	} tsas;
};

/* Discovery log page header */
struct nvmf_disc_rsp_page_hdr {
	__le64		genctr;
	__le64		numrec;
	__le16		recfmt;
	__u8		resv14[1006];
	struct nvmf_disc_rsp_page_entry entries[0];
};

struct nvmf_connect_data {
	uuid_t		hostid;
	__le16		cntlid;
	char		resv4[238];
	char		subsysnqn[NVMF_NQN_FIELD_LEN];
	char		hostnqn[NVMF_NQN_FIELD_LEN];
	char		resv5[256];
};

struct streams_directive_params {
	__le16	msl;
	__le16	nssa;
	__le16	nsso;
	__u8	rsvd[10];
	__le32	sws;
	__le16	sgs;
	__le16	nsa;
	__le16	nso;
	__u8	rsvd2[6];
};

struct nvme_effects_log_page {
	__le32 acs[256];
	__le32 iocs[256];
	__u8   resv[2048];
};

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
	__u8	resv[2];
	__le64	cs;
	__le16	trtype_spec_info;
	__u8	resv2[22];
};

struct nvme_firmware_log_page {
	__u8	afi;
	__u8	resv[7];
	__u64	frs[7];
	__u8	resv2[448];
};

struct nvme_host_mem_buffer {
	__u32			hsize;
	__u32			hmdlal;
	__u32			hmdlau;
	__u32			hmdlec;
	__u8			rsvd16[4080];
};

struct nvme_auto_pst {
	__u32	data;
	__u32	rsvd32;
};

struct nvme_timestamp {
	__u8 timestamp[6];
	__u8 attr;
	__u8 rsvd;
};

struct nvme_controller_list {
	__le16 num;
	__le16 identifier[2047];
};

struct nvme_secondary_controller_entry {
	__le16 scid;	/* Secondary Controller Identifier */
	__le16 pcid;	/* Primary Controller Identifier */
	__u8   scs;	/* Secondary Controller State */
	__u8   rsvd5[3];
	__le16 vfn;	/* Virtual Function Number */
	__le16 nvq;	/* Number of VQ Flexible Resources Assigned */
	__le16 nvi;	/* Number of VI Flexible Resources Assigned */
	__u8   rsvd14[18];
};

struct nvme_secondary_controllers_list {
	__u8   num;
	__u8   rsvd[31];
	struct nvme_secondary_controller_entry sc_entry[127];
};

struct nvme_bar_cap {
	__u16	mqes;
	__u8	ams_cqr;
	__u8	to;
	__u16	bps_css_nssrs_dstrd;
	__u8	mpsmax_mpsmin;
	__u8	rsvd_cmbs_pmrs;
};

/*
 * is_64bit_reg - It checks whether given offset of the controller register is
 *                64bit or not.
 * @offset: offset of controller register field in bytes
 *
 * It gives true if given offset is 64bit register, otherwise it returns false.
 *
 * Notes:  This function does not care about transport so that the offset is
 * not going to be checked inside of this function for the unsupported fields
 * in a specific transport.  For example, BPMBL(Boot Partition Memory Buffer
 * Location) register is not supported by fabrics, but it can be chcked here.
 */
static inline bool is_64bit_reg(__u32 offset)
{
	if (offset == NVME_REG_CAP ||
			offset == NVME_REG_ASQ ||
			offset == NVME_REG_ACQ ||
			offset == NVME_REG_BPMBL)
		return true;

	return false;
}

enum {
	NVME_SCT_GENERIC		= 0x0,
	NVME_SCT_CMD_SPECIFIC		= 0x1,
	NVME_SCT_MEDIA			= 0x2,
};

enum {
	/*
	 * Generic Command Status:
	 */
	NVME_SC_SUCCESS			= 0x0,
	NVME_SC_INVALID_OPCODE		= 0x1,
	NVME_SC_INVALID_FIELD		= 0x2,
	NVME_SC_CMDID_CONFLICT		= 0x3,
	NVME_SC_DATA_XFER_ERROR		= 0x4,
	NVME_SC_POWER_LOSS		= 0x5,
	NVME_SC_INTERNAL		= 0x6,
	NVME_SC_ABORT_REQ		= 0x7,
	NVME_SC_ABORT_QUEUE		= 0x8,
	NVME_SC_FUSED_FAIL		= 0x9,
	NVME_SC_FUSED_MISSING		= 0xa,
	NVME_SC_INVALID_NS		= 0xb,
	NVME_SC_CMD_SEQ_ERROR		= 0xc,
	NVME_SC_SGL_INVALID_LAST	= 0xd,
	NVME_SC_SGL_INVALID_COUNT	= 0xe,
	NVME_SC_SGL_INVALID_DATA	= 0xf,
	NVME_SC_SGL_INVALID_METADATA	= 0x10,
	NVME_SC_SGL_INVALID_TYPE	= 0x11,
	NVME_SC_CMB_INVALID_USE		= 0x12,
	NVME_SC_PRP_INVALID_OFFSET	= 0x13,
	NVME_SC_ATOMIC_WRITE_UNIT_EXCEEDED= 0x14,
	NVME_SC_OPERATION_DENIED	= 0x15,
	NVME_SC_SGL_INVALID_OFFSET	= 0x16,

	NVME_SC_INCONSISTENT_HOST_ID= 0x18,
	NVME_SC_KEEP_ALIVE_EXPIRED	= 0x19,
	NVME_SC_KEEP_ALIVE_INVALID	= 0x1A,
	NVME_SC_PREEMPT_ABORT		= 0x1B,
	NVME_SC_SANITIZE_FAILED		= 0x1C,
	NVME_SC_SANITIZE_IN_PROGRESS	= 0x1D,

	NVME_SC_NS_WRITE_PROTECTED	= 0x20,
	NVME_SC_CMD_INTERRUPTED		= 0x21,
	NVME_SC_TRANSIENT_TRANSPORT	= 0x22,	

	NVME_SC_LBA_RANGE		= 0x80,
	NVME_SC_CAP_EXCEEDED		= 0x81,
	NVME_SC_NS_NOT_READY		= 0x82,
	NVME_SC_RESERVATION_CONFLICT	= 0x83,
	NVME_SC_FORMAT_IN_PROGRESS	= 0x84,

	/*
	 * Command Specific Status:
	 */
	NVME_SC_CQ_INVALID		= 0x100,
	NVME_SC_QID_INVALID		= 0x101,
	NVME_SC_QUEUE_SIZE		= 0x102,
	NVME_SC_ABORT_LIMIT		= 0x103,
	NVME_SC_ABORT_MISSING		= 0x104,
	NVME_SC_ASYNC_LIMIT		= 0x105,
	NVME_SC_FIRMWARE_SLOT		= 0x106,
	NVME_SC_FIRMWARE_IMAGE		= 0x107,
	NVME_SC_INVALID_VECTOR		= 0x108,
	NVME_SC_INVALID_LOG_PAGE	= 0x109,
	NVME_SC_INVALID_FORMAT		= 0x10a,
	NVME_SC_FW_NEEDS_CONV_RESET	= 0x10b,
	NVME_SC_INVALID_QUEUE		= 0x10c,
	NVME_SC_FEATURE_NOT_SAVEABLE	= 0x10d,
	NVME_SC_FEATURE_NOT_CHANGEABLE	= 0x10e,
	NVME_SC_FEATURE_NOT_PER_NS	= 0x10f,
	NVME_SC_FW_NEEDS_SUBSYS_RESET	= 0x110,
	NVME_SC_FW_NEEDS_RESET		= 0x111,
	NVME_SC_FW_NEEDS_MAX_TIME	= 0x112,
	NVME_SC_FW_ACTIVATE_PROHIBITED	= 0x113,
	NVME_SC_OVERLAPPING_RANGE	= 0x114,
	NVME_SC_NS_INSUFFICIENT_CAP	= 0x115,
	NVME_SC_NS_ID_UNAVAILABLE	= 0x116,
	NVME_SC_NS_ALREADY_ATTACHED	= 0x118,
	NVME_SC_NS_IS_PRIVATE		= 0x119,
	NVME_SC_NS_NOT_ATTACHED		= 0x11a,
	NVME_SC_THIN_PROV_NOT_SUPP	= 0x11b,
	NVME_SC_CTRL_LIST_INVALID	= 0x11c,
	NVME_SC_DEVICE_SELF_TEST_IN_PROGRESS= 0x11d,
	NVME_SC_BP_WRITE_PROHIBITED	= 0x11e,
	NVME_SC_INVALID_CTRL_ID		= 0x11f,
	NVME_SC_INVALID_SECONDARY_CTRL_STATE= 0x120,
	NVME_SC_INVALID_NUM_CTRL_RESOURCE	= 0x121,
	NVME_SC_INVALID_RESOURCE_ID	= 0x122,
	NVME_SC_PMR_SAN_PROHIBITED	= 0x123,
	NVME_SC_ANA_INVALID_GROUP_ID= 0x124,
	NVME_SC_ANA_ATTACH_FAIL		= 0x125,

	/*
	 * Command Set Specific - Namespace Types commands:
	 */
	NVME_SC_IOCS_NOT_SUPPORTED		= 0x129,
	NVME_SC_IOCS_NOT_ENABLED		= 0x12A,
	NVME_SC_IOCS_COMBINATION_REJECTED	= 0x12B,
	NVME_SC_INVALID_IOCS			= 0x12C,

	/*
	 * I/O Command Set Specific - NVM commands:
	 */
	NVME_SC_BAD_ATTRIBUTES		= 0x180,
	NVME_SC_INVALID_PI		= 0x181,
	NVME_SC_READ_ONLY		= 0x182,
	NVME_SC_CMD_SIZE_LIMIT_EXCEEDED = 0x183,

	/*
	 * I/O Command Set Specific - Fabrics commands:
	 */
	NVME_SC_CONNECT_FORMAT		= 0x180,
	NVME_SC_CONNECT_CTRL_BUSY	= 0x181,
	NVME_SC_CONNECT_INVALID_PARAM	= 0x182,
	NVME_SC_CONNECT_RESTART_DISC	= 0x183,
	NVME_SC_CONNECT_INVALID_HOST	= 0x184,

	NVME_SC_DISCOVERY_RESTART	= 0x190,
	NVME_SC_AUTH_REQUIRED		= 0x191,

	/*
	 * I/O Command Set Specific - Zoned Namespace commands:
	 */
	NVME_SC_ZONE_BOUNDARY_ERROR		= 0x1B8,
	NVME_SC_ZONE_IS_FULL			= 0x1B9,
	NVME_SC_ZONE_IS_READ_ONLY		= 0x1BA,
	NVME_SC_ZONE_IS_OFFLINE			= 0x1BB,
	NVME_SC_ZONE_INVALID_WRITE		= 0x1BC,
	NVME_SC_TOO_MANY_ACTIVE_ZONES		= 0x1BD,
	NVME_SC_TOO_MANY_OPEN_ZONES		= 0x1BE,
	NVME_SC_ZONE_INVALID_STATE_TRANSITION	= 0x1BF,

	/*
	 * Media and Data Integrity Errors:
	 */
	NVME_SC_WRITE_FAULT		= 0x280,
	NVME_SC_READ_ERROR		= 0x281,
	NVME_SC_GUARD_CHECK		= 0x282,
	NVME_SC_APPTAG_CHECK		= 0x283,
	NVME_SC_REFTAG_CHECK		= 0x284,
	NVME_SC_COMPARE_FAILED		= 0x285,
	NVME_SC_ACCESS_DENIED		= 0x286,
	NVME_SC_UNWRITTEN_BLOCK		= 0x287,

	/*
	 * Path-related Errors:
	 */
	NVME_SC_ANA_PERSISTENT_LOSS	= 0x301,
	NVME_SC_ANA_INACCESSIBLE	= 0x302,
	NVME_SC_ANA_TRANSITION		= 0x303,

	NVME_SC_CRD			= 0x1800,
	NVME_SC_DNR			= 0x4000,
};

#define NVME_VS(major, minor, tertiary) \
	(((major) << 16) | ((minor) << 8) | (tertiary))

#define NVME_MAJOR(ver)		((ver) >> 16)
#define NVME_MINOR(ver)		(((ver) >> 8) & 0xff)
#define NVME_TERTIARY(ver)	((ver) & 0xff)


/**
 * struct nvme_zns_lbafe -
 * zsze:
 * zdes:
 */
struct nvme_zns_lbafe {
	__le64	zsze;
	__u8	zdes;
	__u8	rsvd9[7];
};

/**
 * struct nvme_zns_id_ns -
 * @zoc:
 * @ozcs:
 * @mar:
 * @mor:
 * @rrl:
 * @frl:
 * @lbafe:
 * @vs:
 */
struct nvme_zns_id_ns {
	__le16			zoc;
	__le16			ozcs;
	__le32			mar;
	__le32			mor;
	__le32			rrl;
	__le32			frl;
	__u8			rsvd20[2796];
	struct nvme_zns_lbafe	lbafe[16];
	__u8			rsvd3072[768];
	__u8			vs[256];
};

/**
 * struct nvme_zns_id_ctrl -
 * @zasl:
 */
struct nvme_zns_id_ctrl {
	__u8	zasl;
	__u8	rsvd1[4095];
};

#define NVME_ZNS_CHANGED_ZONES_MAX	511

/**
 * struct nvme_zns_changed_zone_log - ZNS Changed Zone List log
 * @nrzid:
 * @zid:
 */
struct nvme_zns_changed_zone_log {
	__le16		nrzid;
	__u8		rsvd2[6];
	__le64		zid[NVME_ZNS_CHANGED_ZONES_MAX];
};

/**
 * enum nvme_zns_zt -
 */
enum nvme_zns_zt {
	NVME_ZONE_TYPE_SEQWRITE_REQ	= 0x2,
};

/**
 * enum nvme_zns_za -
 */
enum nvme_zns_za {
	NVME_ZNS_ZA_ZFC			= 1 << 0,
	NVME_ZNS_ZA_FZR			= 1 << 1,
	NVME_ZNS_ZA_RZR			= 1 << 2,
	NVME_ZNS_ZA_ZDEV		= 1 << 7,
};

/**
 * enum nvme_zns_zs -
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
 * struct nvme_zns_desc -
 */
struct nvme_zns_desc {
	__u8	zt;
	__u8	zs;
	__u8	za;
	__u8	rsvd3[5];
	__le64	zcap;
	__le64	zslba;
	__le64	wp;
	__u8	rsvd32[32];
};

/**
 * struct nvme_zone_report -
 */
struct nvme_zone_report {
	__le64			nr_zones;
	__u8			resv8[56];
	struct nvme_zns_desc	entries[];
};

enum nvme_zns_send_action {
	NVME_ZNS_ZSA_CLOSE		= 0x1,
	NVME_ZNS_ZSA_FINISH		= 0x2,
	NVME_ZNS_ZSA_OPEN		= 0x3,
	NVME_ZNS_ZSA_RESET		= 0x4,
	NVME_ZNS_ZSA_OFFLINE		= 0x5,
	NVME_ZNS_ZSA_SET_DESC_EXT	= 0x10,
};

enum nvme_zns_recv_action {
	NVME_ZNS_ZRA_REPORT_ZONES		= 0x0,
	NVME_ZNS_ZRA_EXTENDED_REPORT_ZONES	= 0x1,
};

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
#endif /* _LINUX_NVME_H */
