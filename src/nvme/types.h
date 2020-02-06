#ifndef _LIBNVME_TYPES_H
#define _LIBNVME_TYPES_H

#include <endian.h>
#include <stdbool.h>
#include <stdint.h>

#include <linux/types.h>

#ifdef __CHECKER__
#define __force       __attribute__((force))
#else
#define __force
#endif

static inline __le16 cpu_to_le16(uint16_t x) { return (__force __le16)htole16(x); }
static inline __le32 cpu_to_le32(uint32_t x) { return (__force __le32)htole32(x); }
static inline __le64 cpu_to_le64(uint64_t x) { return (__force __le64)htole64(x); }
static inline uint16_t le16_to_cpu(__le16 x) { return le16toh((__force __u16)x); }
static inline uint32_t le32_to_cpu(__le32 x) { return le32toh((__force __u32)x); }
static inline uint64_t le64_to_cpu(__le64 x) { return le64toh((__force __u64)x); }

/**
 * enum nvme_constants -
 * @NVME_NSID_ALL:
 * @NVME_NSID_NONE:
 * @NVME_UUID_NONE:
 * @NVME_CNTLID_NONE:
 * @NVME_NVMSETID_NONE:
 * @NVME_LOG_LSP_NONE:
 * @NVME_LOG_LSI_NONE:
 * @NVME_IDENTIFY_DATA_SIZE:
 * @NVME_ID_NVMSET_LIST_MAX:
 * @NVME_ID_UUID_LIST_MAX:
 * @NVME_ID_CTRL_LIST_MAX:
 * @NVME_ID_NS_LIST_MAX:
 * @NVME_ID_SECONDARY_CTRL_MAX:
 * @NVME_FEAT_LBA_RANGE_MAX:
 * @NVME_LOG_ST_MAX_RESULTS:
 * @NVME_DSM_MAX_RANGES:
 */
enum nvme_constants {
	NVME_NSID_ALL			= 0xffffffff,
	NVME_NSID_NONE			= 0,
	NVME_UUID_NONE			= 0,
	NVME_CNTLID_NONE		= 0,
	NVME_NVMSETID_NONE		= 0,
	NVME_LOG_LSP_NONE		= 0,
	NVME_LOG_LSI_NONE		= 0,
	NVME_IDENTIFY_DATA_SIZE		= 4096,
	NVME_ID_NVMSET_LIST_MAX		= 31,
	NVME_ID_UUID_LIST_MAX		= 127,
	NVME_ID_CTRL_LIST_MAX		= 2047,
	NVME_ID_NS_LIST_MAX		= 1024,
	NVME_ID_SECONDARY_CTRL_MAX	= 127,
	NVME_FEAT_LBA_RANGE_MAX		= 64,
	NVME_LOG_ST_MAX_RESULTS		= 20,
	NVME_DSM_MAX_RANGES		= 256,
};

/**
 * DOC: NVMe controller registers/properties
 */

/**
 * enum nvme_registers -
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
 * @NVME_REG_PMRCAP:	Persistent Memory Capabilities
 * @NVME_REG_PMRCTL:	Persistent Memory Region Control
 * @NVME_REG_PMRSTS:	Persistent Memory Region Status
 * @NVME_REG_PMREBS:	Persistent Memory Region Elasticity Buffer Size
 * @NVME_REG_PMRSWTP:	Memory Region Sustained Write Throughput
 * @NVME_REG_PMRMSC:	Persistent Memory Region Controller Memory Space Control
 * @NVME_REG_DBS:	SQ 0 Tail Doorbell
 */
enum nvme_registers {
	NVME_REG_CAP	= 0x0000,
	NVME_REG_VS	= 0x0008,
	NVME_REG_INTMS	= 0x000c,
	NVME_REG_INTMC	= 0x0010,
	NVME_REG_CC	= 0x0014,
	NVME_REG_CSTS	= 0x001c,
	NVME_REG_NSSR	= 0x0020,
	NVME_REG_AQA	= 0x0024,
	NVME_REG_ASQ	= 0x0028,
	NVME_REG_ACQ	= 0x0030,
	NVME_REG_CMBLOC = 0x0038,
	NVME_REG_CMBSZ	= 0x003c,
	NVME_REG_BPINFO	= 0x0040,
	NVME_REG_BPRSEL	= 0x0044,
	NVME_REG_BPMBL	= 0x0048,
	NVME_REG_CMBMSC	= 0x0050,
	NVME_REG_CMBSTS	= 0x0058,
	NVME_REG_PMRCAP = 0x0e00,
	NVME_REG_PMRCTL = 0x0e04,
	NVME_REG_PMRSTS = 0x0e08,
	NVME_REG_PMREBS = 0x0e0c,
	NVME_REG_PMRSWTP= 0x0e10,
	NVME_REG_PMRMSC = 0x0e14,
	NVME_REG_DBS	= 0x1000,
};

#define NVME_CAP_MQES(cap)	((cap) & 0xffff)
#define NVME_CAP_CQR(cap)	(((cap) >> 16) & 0x1)
#define NVME_CAP_AMS(cap)	(((cap) >> 17) & 0x3)
#define NVME_CAP_TIMEOUT(cap)	(((cap) >> 24) & 0xff)
#define NVME_CAP_STRIDE(cap)	(((cap) >> 32) & 0xf)
#define NVME_CAP_NSSRC(cap)	(((cap) >> 36) & 0x1)
#define NVME_CAP_CSS(cap)	(((cap) >> 37) & 0xff)
#define NVME_CAP_BPS(cap)	(((cap) >> 45) & 0x1)
#define NVME_CAP_MPSMIN(cap)	(((cap) >> 48) & 0xf)
#define NVME_CAP_MPSMAX(cap)	(((cap) >> 52) & 0xf)
#define NVME_CAP_CMBS(cap)	(((cap) >> 57) & 1)
#define NVME_CAP_PMRS(cap)	(((cap) >> 56) & 1)

#define NVME_CMB_BIR(cmbloc)	((cmbloc) & 0x7)
#define NVME_CMB_OFST(cmbloc)	(((cmbloc) >> 12) & 0xfffff)
#define NVME_CMB_SZ(cmbsz)	(((cmbsz) >> 12) & 0xfffff)
#define NVME_CMB_SZU(cmbsz)	(((cmbsz) >> 8) & 0xf)

#define NVME_CMB_WDS(cmbsz)	((cmbsz) & 0x10)
#define NVME_CMB_RDS(cmbsz)	((cmbsz) & 0x8)
#define NVME_CMB_LISTS(cmbsz)	((cmbsz) & 0x4)
#define NVME_CMB_CQS(cmbsz)	((cmbsz) & 0x2)
#define NVME_CMB_SQS(cmbsz)	((cmbsz) & 0x1)

/**
 * enum -
 */
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
	NVME_CSTS_RDY		= 1 << 0,
	NVME_CSTS_CFS		= 1 << 1,
	NVME_CSTS_NSSRO		= 1 << 4,
	NVME_CSTS_PP		= 1 << 5,
	NVME_CSTS_SHST_NORMAL	= 0 << 2,
	NVME_CSTS_SHST_OCCUR	= 1 << 2,
	NVME_CSTS_SHST_CMPLT	= 2 << 2,
	NVME_CSTS_SHST_MASK	= 3 << 2,
};

/*
 * is_64bit_reg() - Checks if offset of the controller register is 64bit or not.
 * @offset:	Offset of controller register field in bytes
 *
 * This function does not care about transport so that the offset is not going
 * to be checked inside of this function for the unsupported fields in a
 * specific transport. For example, BPMBL(Boot Partition Memory Buffer
 * Location) register is not supported by fabrics, but it can be chcked here.
 *
 * Returns true if given offset is 64bit register, otherwise it returns false.
 */
static inline bool is_64bit_reg(__u32 offset)
{
	switch (offset) {
	case NVME_REG_CAP:
	case NVME_REG_ASQ:
	case NVME_REG_ACQ:
	case NVME_REG_BPMBL:
		return true;
	default:
		return false;
	}
}

/**
 * DOC: NVMe Identify
 */

/**
 * struct nvme_id_psd -
 * @mp:		
 * @flags:	
 * @enlat:	
 * @exlat:	
 * @rrt:	
 * @rrl:	
 * @rwt:	
 * @rwl:	
 * @idlp:	
 * @ips:	
 * @actp:	
 * @apw:	
 * @aps:	
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
	__u8			apw;
	__u8			aps;
	__u8			rsvd23[8];
};

/**
 * nvme_psd_power_scale() - power scale occupies the upper 3 bits
 */
static inline unsigned nvme_psd_power_scale(__u8 ps)
{
	return ps >> 6;
}

/**
 * enum -
 * @NVME_PSD_FLAGS_MAX_POWER_SCALE:
 * @NVME_PSD_FLAGS_NON_OP_STATE:
 * @NVME_PSD_RELATIVE_MASK:
 * @NVME_PSD_APW_MASK:
 */
enum {
	NVME_PSD_FLAGS_MAX_POWER_SCALE	= 1 << 0,
	NVME_PSD_FLAGS_NON_OP_STATE	= 1 << 1,
	NVME_PSD_RELATIVE_MASK		= 0x1f,
	NVME_PSD_APW_MASK		= 0x7,
};

/**
 * struct nvme_id_ctrl - Identify Controller data structure
 * @vid:	Vendor ID
 * @ssvid:	Subsystem Vendor Id
 * @sn:		Serial Number
 * @mn:		Model Number
 * @fr:		Firmware Revision
 * @rab:	Recommended Arbitration Burst
 * @ieee:	IEEE
 * @cmic:	Controller Mulitpathing Capabilities
 * @mdts:	Max Data Transfer Size
 * @cntlid:	Controller Identifier
 * @ver:	Version
 * @rtd3r:	Runtime D3 Resume
 * @rtd3e:	Runtime D3 Exit
 * @oaes:	Optional Async Events Supported
 * @ctratt:	Controller Attributes
 * @rrls:	Read Recovery Levels
 * @cntrltype:	Controller Type
 * @fguid:	FRU GUID
 * @crdt1:	Controller Retry Delay 1
 * @crdt2:	Controller Retry Delay 2
 * @crdt3:	Controller Retry Delay 3
 * @nvmsr:	
 * @vwci:	
 * @mec:	
 * @oacs:	Optional Admin Commands Supported
 * @acl:	Abort Command Limit
 * @aerl:	Async Event Request Limit
 * @frmw:	
 * @lpa:	Log Page Attributes
 * @elpe:	
 * @npss:	Number of Power States Supported
 * @avscc:	
 * @apsta:	
 * @wctemp:	
 * @cctemp:	
 * @mtfa:	
 * @hmpre:	
 * @hmmin:	
 * @tnvmcap:	
 * @unvmcap:	
 * @rpmbs:	
 * @edstt:	
 * @dsto:	
 * @fwug:	
 * @kas:	
 * @hctma:	
 * @mntmt:	
 * @mxtmt:	
 * @sanicap:	
 * @hmminds:	
 * @hmmaxd:	
 * @nsetidmax:	
 * @endgidmax:	
 * @anatt:	
 * @anacap:	
 * @anagrpmax:	
 * @nanagrpid:	
 * @pels:	
 * @sqes:	
 * @cqes:	
 * @maxcmd:	
 * @nn:	
 * @onc:	
 * @fuses:	
 * @fna:	
 * @vwc:	
 * @awun:	
 * @awupf:	
 * @nvscc:	
 * @nwpc:	
 * @acwu:	
 * @sgls:	
 * @mnan:	
 * @subnqn:	
 * @ioccsz:	
 * @iorcsz:	
 * @icdoff:	
 * @fcatt:	
 * @msdbd:	
 * @ofcs:	
 * @psd:	
 * @vs:	
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
	__u8			nvscc;
	__u8			nwpc;
	__le16			acwu;
	__u8			rsvd534[2];
	__le32			sgls;
	__le32			mnan;
	__u8			rsvd544[224];
	char			subnqn[256];
	__u8			rsvd1024[768];

	/* Fabrics Only */
	__le32			ioccsz;
	__le32			iorcsz;
	__le16			icdoff;
	__u8			fcatt;
	__u8			msdbd;
	__le16			ofcs;
	__u8			rsvd1806[242];

	struct nvme_id_psd	psd[32];
	__u8			vs[1024];
};

/**
 * enum -
 */
enum {
	NVME_CTRL_CMIC_MULTI_PORT		= 1 << 0,
	NVME_CTRL_CMIC_MULTI_CTRL		= 1 << 1,
	NVME_CTRL_CMIC_MULTI_SRIOV		= 1 << 2,
	NVME_CTRL_CMIC_MULTI_ANA_REPORTING	= 1 << 3,
};

/**
 * enum -
 */
enum {
	NVME_CTRL_OAES_NA			= 1 << 8,
	NVME_CTRL_OAES_FA			= 1 << 9,
	NVME_CTRL_OAES_ANA			= 1 << 11,
	NVME_CTRL_OAES_PLEA			= 1 << 12,
	NVME_CTRL_OAES_LBAS			= 1 << 13,
	NVME_CTRL_OAES_EGE			= 1 << 14,
};

/**
 * enum -
 */
enum {
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
};

/**
 * enum -
 */
enum {
	NVME_CTRL_CNTRLTYPE_RESERVED		= 0,
	NVME_CTRL_CNTRLTYPE_IO			= 1,
	NVME_CTRL_CNTRLTYPE_DISCOVERY		= 2,
	NVME_CTRL_CNTRLTYPE_ADMIN		= 3,
};

/**
 * enum -
 */
enum {
	NVME_CTRL_NVMSR_NVMESD			= 1 << 0,
	NVME_CTRL_NVMSR_NVMEE			= 1 << 1,
};

/**
 * enum -
 */
enum {
	NVME_CTRL_VWCI_VWCR			= 0x7f << 0,
	NVME_CTRL_VWCI_VWCRV			= 1 << 7,
};

/**
 * enum -
 */
enum {
	NVME_CTRL_MEC_SMBUSME			= 1 << 0,
	NVME_CTRL_MEC_PCIEME			= 1 << 1,
};

/**
 * enum -
 */
enum {
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
};

/**
 * enum -
 */
enum {
	NVME_CTRL_FRMW_1ST_RO			= 1 << 0,
	NVME_CTRL_FRMW_NR_SLOTS			= 3 << 1,
	NVME_CTRL_FRMW_FW_ACT_NO_RESET		= 1 << 4,
};

/**
 * enum -
 */
enum {
	NVME_CTRL_LPA_SMART_PER_NS		= 1 << 0,
	NVME_CTRL_LPA_CMD_EFFECTS		= 1 << 1,
	NVME_CTRL_LPA_EXTENDED			= 1 << 2,
	NVME_CTRL_LPA_TELEMETRY			= 1 << 3,
	NVME_CTRL_LPA_PERSETENT_EVENT		= 1 << 4,
};

/**
 * enum -
 */
enum {
	NVME_CTRL_AVSCC_AVS			= 1 << 0,
};

/**
 * enum -
 */
enum {
	NVME_CTRL_APSTA_APST			= 1 << 0,
};

/**
 * enum -
 */
enum {
	NVME_CTRL_RPMBS_NR_UNITS		= 7 << 0,
	NVME_CTRL_RPMBS_AUTH_METHOD		= 7 << 3,
	NVME_CTRL_RPMBS_TOTAL_SIZE		= 255 << 16,
	NVME_CTRL_RPMBS_ACCESS_SIZE		= 255 << 24,
};

/**
 * enum -
 */
enum {
	NVME_CTRL_DSTO_ONE_DST			= 1 << 0,
};

/**
 * enum -
 */
enum {
	NVME_CTRL_HCTMA_HCTM			= 1 << 0,
};

/**
 * enum -
 */
enum {
	NVME_CTRL_SANICAP_CES			= 1 << 0,
	NVME_CTRL_SANICAP_BES			= 1 << 1,
	NVME_CTRL_SANICAP_OWS			= 1 << 2,
	NVME_CTRL_SANICAP_NDI			= 1 << 29,
	NVME_CTRL_SANICAP_NODMMAS		= 3 << 30,
};

/**
 * enum -
 */
enum {
	NVME_CTRL_ANACAP_OPT			= 1 << 0,
	NVME_CTRL_ANACAP_NON_OPT		= 1 << 1,
	NVME_CTRL_ANACAP_INACCESSIBLE		= 1 << 2,
	NVME_CTRL_ANACAP_PERSISTENT_LOSS	= 1 << 3,
	NVME_CTRL_ANACAP_CHANGE			= 1 << 4,
	NVME_CTRL_ANACAP_GRPID_NO_CHG		= 1 << 6,
	NVME_CTRL_ANACAP_GRPID_MGMT		= 1 << 7,
};

/**
 * enum -
 */
enum {
	NVME_CTRL_SQES_MIN			= 15 << 0,
	NVME_CTRL_SQES_MAX			= 15 << 4,
};

/**
 * enum -
 */
enum {
	NVME_CTRL_CQES_MIN			= 15 << 0,
	NVME_CTRL_CQES_MAX			= 15 << 4,
};

/**
 * enum -
 */
enum {
	NVME_CTRL_ONCS_COMPARE			= 1 << 0,
	NVME_CTRL_ONCS_WRITE_UNCORRECTABLE	= 1 << 1,
	NVME_CTRL_ONCS_DSM			= 1 << 2,
	NVME_CTRL_ONCS_WRITE_ZEROES		= 1 << 3,
	NVME_CTRL_ONCS_SAVE_FEATURES		= 1 << 4,
	NVME_CTRL_ONCS_RESERVATIONS		= 1 << 5,
	NVME_CTRL_ONCS_TIMESTAMP		= 1 << 6,
	NVME_CTRL_ONCS_VERIFY			= 1 << 7,
};

/**
 * enum -
 */
enum {
	NVME_CTRL_FUSES_COMPARE_AND_WRITE	= 1 << 0,
};

/**
 * enum -
 */
enum {
	NVME_CTRL_FNA_FMT_ALL_NAMESPACES	= 1 << 0,
	NVME_CTRL_FNA_SEC_ALL_NAMESPACES	= 1 << 1,
	NVME_CTRL_FNA_CRYPTO_ERASE		= 1 << 2,
};

/**
 * enum -
 */
enum {
	NVME_CTRL_VWC_PRESENT			= 1 << 0,
	NVME_CTRL_VWC_FLUSH			= 3 << 1,
};

/**
 * enum -
 */
enum {
	NVME_CTRL_NVSCC_FMT			= 1 << 0,
};

/**
 * enum -
 */
enum {
	NVME_CTRL_NWPC_WRITE_PROTECT		= 1 << 0,
	NVME_CTRL_NWPC_WRITE_PROTECT_POWER_CYCLE= 1 << 1,
	NVME_CTRL_NWPC_WRITE_PROTECT_PERMANENT	= 1 << 2,
};

/**
 * enum -
 */
enum {
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
 * enum -
 */
enum {
	NVME_CTRL_FCATT_DYNAMIC			= 1 << 0,
};

/**
 * enum -
 */
enum {
	NVME_CTRL_OFCS_DISCONNECT		= 1 << 0,
};

/**
 * struct nvme_lbaf -
 * @ms:	
 * @ds:	
 * @rp:	
 */
struct nvme_lbaf {
	__le16			ms;
	__u8			ds;
	__u8			rp;
};

/**
 * enum -
 * @NVME_LBAF_RP_BEST:
 * @NVME_LBAF_RP_BETTER:
 * @NVME_LBAF_RP_GOOD:
 * @NVME_LBAF_RP_DEGRADED:
 */
enum {
	NVME_LBAF_RP_BEST	= 0,
	NVME_LBAF_RP_BETTER	= 1,
	NVME_LBAF_RP_GOOD	= 2,
	NVME_LBAF_RP_DEGRADED	= 3,
	NVME_LBAF_RP_MASK	= 3,
};

/**
 * struct nvme_id_ns -
 * @nsze:	
 * @ncap:	
 * @nuse:	
 * @nsfeat:	
 * @nlbaf:	
 * @flbas:	
 * @mc:	
 * @dpc:	
 * @dps:	
 * @nmic:	
 * @rescap:	
 * @fpi:	
 * @dlfeat:	
 * @nawun:	
 * @nawupf:	
 * @nacwu:	
 * @nabsn:	
 * @nabo:	
 * @nabspf:	
 * @noiob:	
 * @nvmcap:	
 * @npwg:	
 * @npwa:	
 * @npdg:	
 * @npda:	
 * @nows:	
 * @anagrpid:	
 * @nsattr:	
 * @nvmsetid:	
 * @endgid:	
 * @nguid:	
 * @eui64:	
 * @lbaf:	
 * @vs:
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
	__u8			rsvd74[18];
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

/**
 * enum -
 */
enum {
	NVME_NS_FEAT_THIN		= 1 << 0,
	NVME_NS_FEAT_NATOMIC		= 1 << 1,
	NVME_NS_FEAT_DULBE		= 1 << 2,
	NVME_NS_FEAT_ID_REUSE		= 1 << 3,
	NVME_NS_FEAT_IO_OPT		= 1 << 4,
};

/**
 * enum -
 */
enum {
	NVME_NS_FLBAS_LBA_MASK		= 15 << 0,
	NVME_NS_FLBAS_META_EXT		= 1 << 4,
};

/**
 * enum -
 */
enum {
	NVME_NS_MC_EXTENDED		= 1 << 0,
	NVME_NS_MC_SEPARATE		= 1 << 1,
};

/**
 * enum -
 */
enum {
	NVME_NS_DPC_PI_TYPE1		= 1 << 0,
	NVME_NS_DPC_PI_TYPE2		= 1 << 1,
	NVME_NS_DPC_PI_TYPE3		= 1 << 2,
	NVME_NS_DPC_PI_FIRST		= 1 << 3,
	NVME_NS_DPC_PI_LAST		= 1 << 4,
};

/**
 * enum -
 */
enum {
	NVME_NS_DPS_PI_NONE		= 0,
	NVME_NS_DPS_PI_TYPE1		= 1,
	NVME_NS_DPS_PI_TYPE2		= 2,
	NVME_NS_DPS_PI_TYPE3		= 3,
	NVME_NS_DPS_PI_MASK		= 7 << 0,
	NVME_NS_DPS_PI_FIRST		= 1 << 3,
};

/**
 * enum -
 */
enum {
	NVME_NS_NMIC_SHARED		= 1 << 0,
};

/**
 * enum -
 */
enum {
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
 * enum -
 */
enum {
	NVME_NS_FPI_REMAINING		= 127 << 0,
	NVME_NS_FPI_SUPPORTED		= 1 << 7,
};

/**
 * enum -
 */
enum {
	NVME_NS_DLFEAT_RB		= 7 << 0,
	NVME_NS_DLFEAT_RB_NR		= 0,
	NVME_NS_DLFEAT_RB_ALL_0S	= 1,
	NVME_NS_DLFEAT_RB_ALL_FS	= 2,
	NVME_NS_DLFEAT_WRITE_ZEROES	= 1 << 3,
	NVME_NS_DLFEAT_CRC_GUARD	= 1 << 4,
};

/**
 * enum -
 */
enum {
	NVME_NS_NSATTR_WRITE_PROTECTED	= 1 << 0
};

/**
 * struct nvme_ns_id_desc -
 */
struct nvme_ns_id_desc {
	__u8	nidt;
	__u8	nidl;
	__le16	reserved;
	__u8	nid[];
};

/**
 * enum -
 */
enum {
	NVME_NIDT_EUI64		= 1,
	NVME_NIDT_NGUID		= 2,
	NVME_NIDT_UUID		= 3,
};

/**
 * struct nvme_nvmset_attr -
 */
struct nvme_nvmset_attr {
	__le16			id;
	__le16			endurance_group_id;
	__u8			rsvd4[4];
	__le32			random_4k_read_typical;
	__le32			opt_write_size;
	__u8			total_nvmset_cap[16];
	__u8			unalloc_nvmset_cap[16];
	__u8			rsvd48[80];
};

/**
 * struct nvme_id_nvmset_list -
 */
struct nvme_id_nvmset_list {
	__u8			nid;
	__u8			rsvd1[127];
	struct nvme_nvmset_attr	ent[NVME_ID_NVMSET_LIST_MAX];
};

/**
 * struct nvme_id_ns_granularity_list_entry -
 */
struct nvme_id_ns_granularity_list_entry {
	__le64			namespace_size_granularity;
	__le64			namespace_capacity_granularity;
};

/**
 * struct nvme_id_ns_granularity_list -
 */
struct nvme_id_ns_granularity_list {
	__le32			attributes;
	__u8			num_descriptors;
	__u8			rsvd[27];
	struct nvme_id_ns_granularity_list_entry entry[16];
};

/**
 * struct nvme_id_uuid_list_entry -
 */
struct nvme_id_uuid_list_entry {
	__u8			header;
	__u8			rsvd1[15];
	__u8			uuid[16];
};

/**
 * enum -
 */
enum {
	NVME_ID_UUID_HDR_ASSOCIATION_MASK		= 0x3,
	NVME_ID_UUID_ASSOCIATION_NONE			= 0,
	NVME_ID_UUID_ASSOCIATION_VENDOR			= 1,
	NVME_ID_UUID_ASSOCIATION_SUBSYSTEM_VENDOR	= 2,
};

/**
 * struct nvme_id_uuid_list -
 */
struct nvme_id_uuid_list {
	__u8	rsvd0[32];
	struct nvme_id_uuid_list_entry entry[NVME_ID_UUID_LIST_MAX];
};

/**
 * struct nvme_ctrl_list -
 */
struct nvme_ctrl_list {
	__le16 num;
	__le16 identifier[NVME_ID_CTRL_LIST_MAX];
};

/**
 * struct nvme_ns_list -
 */
struct nvme_ns_list {
	__le32 ns[NVME_ID_NS_LIST_MAX];
};

/**
 * struct nvme_primary_ctrl_cap -
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
 * struct nvme_secondary_ctrl -
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
 * struct nvme_secondary_ctrl_list -
 */
struct nvme_secondary_ctrl_list {
	__u8   num;
	__u8   rsvd[31];
	struct nvme_secondary_ctrl sc_entry[NVME_ID_SECONDARY_CTRL_MAX];
};

/**
 * DOC: NVMe Logs
 */

/**
 * struct nvme_error_log_page -
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
	__u8	resv[2];
	__le64	cs;
	__le16	trtype_spec_info;
	__u8	resv2[22];
};

/**
 * enum -
 */
enum {
	NVME_ERR_PEL_BYTE_MASK	= 0xf,
	NVME_ERR_PEL_BIT_MASK	= 0x70,
};

/**
 * struct nvme_smart_log -
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
 * enum -
 */
enum {
	NVME_SMART_CRIT_SPARE		= 1 << 0,
	NVME_SMART_CRIT_TEMPERATURE	= 1 << 1,
	NVME_SMART_CRIT_DEGRADED	= 1 << 2,
	NVME_SMART_CRIT_MEDIA		= 1 << 3,
	NVME_SMART_CRIT_VOLATILE_MEMORY	= 1 << 4,
	NVME_SMART_CRIT_PMR_RO		= 1 << 5,
};

/**
 * enum -
 */
enum {
	NVME_SMART_EGCW_SPARE		= 1 << 0,
	NVME_SMART_EGCW_DEGRADED	= 1 << 2,
	NVME_SMART_EGCW_RO		= 1 << 3,
};

/**
 * struct nvme_frs -
 */
struct nvme_frs {
	char frs[8];
};

/**
 * struct nvme_firmware_slot -
 */
struct nvme_firmware_slot {
	__u8		afi;
	__u8		resv[7];
	struct nvme_frs	frs[7];
	__u8		resv2[448];
};

/**
 * struct nvme_cmd_effects_log -
 */
struct nvme_cmd_effects_log {
	__le32 acs[256];
	__le32 iocs[256];
	__u8   resv[2048];
};

/**
 * enum -
 */
enum {
	NVME_CMD_EFFECTS_CSUPP		= 1 << 0,
	NVME_CMD_EFFECTS_LBCC		= 1 << 1,
	NVME_CMD_EFFECTS_NCC		= 1 << 2,
	NVME_CMD_EFFECTS_NIC		= 1 << 3,
	NVME_CMD_EFFECTS_CCC		= 1 << 4,
	NVME_CMD_EFFECTS_CSE_MASK	= 3 << 16,
	NVME_CMD_EFFECTS_UUID_SEL	= 1 << 19,
};

/**
 * struct nvme_st_result -
 */
struct nvme_st_result {
	__u8 			dsts;
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
 * enum -
 */
enum {
	NVME_ST_RESULT_NO_ERR    	= 0x0,
	NVME_ST_RESULT_ABORTED   	= 0x1,
	NVME_ST_RESULT_CLR	      	= 0x2,
	NVME_ST_RESULT_NS_REMOVED	= 0x3,
	NVME_ST_RESULT_ABORTED_FORMAT	= 0x4,
	NVME_ST_RESULT_FATAL_ERR	= 0x5,
	NVME_ST_RESULT_UNKNOWN_SEG_FAIL	= 0x6,
	NVME_ST_RESULT_KNOWN_SEG_FAIL	= 0x7,
	NVME_ST_RESULT_ABORTED_UNKNOWN	= 0x8,
	NVME_ST_RESULT_ABORTED_SANITIZE	= 0x9,
	NVME_ST_RESULT_NOT_USED		= 0xf,
};

/**
 * enum -
 */
enum {
	NVME_ST_OPERATION_NONE		= 0x0,
	NVME_ST_OPERATION_SHORT		= 0x1,
	NVME_ST_OPERATION_EXTENDED	= 0x2,
	NVME_ST_OPERATION_VS		= 0xe,
};

/**
 * enum -
 */
enum {
	NVME_ST_VALID_DIAG_INFO_NSID		= 1 << 0,
	NVME_ST_VALID_DIAG_INFO_FLBA		= 1 << 1,
	NVME_ST_VALID_DIAG_INFO_SCT		= 1 << 2,
	NVME_ST_VALID_DIAG_INFO_SC		= 1 << 3,
};


/**
 * struct nvme_self_test_log -
 */
struct nvme_self_test_log {
	__u8			current_operation;
	__u8			completion;
	__u8			rsvd[2];
	struct nvme_st_result	result[NVME_LOG_ST_MAX_RESULTS];
} __attribute__((packed));

/**
 * struct nvme_telemetry_log -
 */
struct nvme_telemetry_log {
	__u8	lpi;
	__u8	rsvd[4];
	__u8	ieee[3];
	__le16	dalb1;
	__le16	dalb2;
	__le16	dalb3;
	__u8	rsvd1[368];
	__u8	ctrlavail;
	__u8	ctrldgn;
	__u8	rsnident[128];
	__u8	telemetry_dataarea[];
};

/**
 * struct nvme_endurance_group_log -
 */
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

/**
 * enum -
 */
enum nvme_eg_critical_warning_flags {
	NVME_EG_CRITICAL_WARNING_SPARE		= 1 << 0,
	NVME_EG_CRITICAL_WARNING_DEGRADED	= 1 << 2,
	NVME_EG_CRITICAL_WARNING_READ_ONLY	= 1 << 3,
};

/**
 * struct nvme_aggregate_endurance_group_event -
 */
struct nvme_aggregate_endurance_group_event {
	__le64	num_entries;
	__le16	entries[];
};

/**
 * struct nvme_nvmset_predictable_lat_log -
 */
struct nvme_nvmset_predictable_lat_log {
	__u8	status;
	__u8	rsvd1;
	__le16	event_type;
	__u8	rsvd4[28];
	__le64	dtwin_rt;
	__le64	dtwin_wt;
	__le64	dtwin_tmax;
	__le64	dtwin_tmin_hi;
	__le64	dtwin_tmin_lo;
	__u8	rsvd72[56];
	__le64	dtwin_re;
	__le64	dtwin_we;
	__le64	dtwin_te;
	__u8	rsvd152[360];
};

/**
 * enum -
 */
enum {
	NVME_NVMSET_PL_STATUS_DISABLED	= 0,
	NVME_NVMSET_PL_STATUS_DTWIN	= 1,
	NVME_NVMSET_PL_STATUS_NDWIN	= 2,
};

/**
 * enum -
 */
enum {
	NVME_NVMSET_PL_EVENT_DTWIN_READ_WARN	= 1 << 0,
	NVME_NVMSET_PL_EVENT_DTWIN_WRITE_WARN	= 1 << 1,
	NVME_NVMSET_PL_EVENT_DTWIN_TIME_WARN	= 1 << 2,
	NVME_NVMSET_PL_EVENT_DTWIN_EXCEEDED	= 1 << 14,
	NVME_NVMSET_PL_EVENT_DTWIN_EXCURSION	= 1 << 15,
};

/**
 * struct nvme_aggregate_predictable_lat_event -
 */
struct nvme_aggregate_predictable_lat_event {
	__le64	num_entries;
	__le16	entries[];
};

/**
 * struct nvme_ana_group_desc -
 */
struct nvme_ana_group_desc {
	__le32  grpid;
	__le32  nnsids;
	__le64  chgcnt;
	__u8    state;
	__u8    rsvd17[15];
	__le32  nsids[];
};

/**
 * enum -
 */
enum {
	NVME_ANA_STATE_OPTIMIZED	= 0x1,
	NVME_ANA_STATE_NONOPTIMIZED	= 0x2,
	NVME_ANA_STATE_INACCESSIBLE	= 0x3,
	NVME_ANA_STATE_PERSISTENT_LOSS	= 0x4,
	NVME_ANA_STATE_CHANGE		= 0xf,
};

/**
 * struct nvme_ana_log -
 */
struct nvme_ana_log {
	__le64	chgcnt;
	__le16	ngrps;
	__u8	rsvd10[6];
	struct nvme_ana_group_desc descs[];
};

/**
 * struct nvme_persistent_event_log -
 */
struct nvme_persistent_event_log {
	__u8	lid;
	__u8	rsvd1[3];
	__le32	ttl;
	__u8	rv;
	__u8	rsvd17;
	__le16	lht;
	__le64	ts;
	__u8	poh[16];
	__le64	pcc;
	__le16	vid;
	__le16	ssvid;
	char	sn[20];
	char	mn[40];
	char	subnqn[256];
	__u8	rsvd372;
	__u8	seb[32];
};

/**
 * struct nvme_lba_rd -
 */
struct nvme_lba_rd {
	__le64	rslba;
	__le32	rnlb;
	__u8	rsvd12[4];
};

/**
 * struct nvme_lbas_ns_element -
 */
struct nvme_lbas_ns_element {
	__le32	neid;
	__le32	nrld;
	__u8	ratype;
	__u8	rsvd8[7];
	struct	nvme_lba_rd lba_rd[];
};

/**
 * enum nvme_lba_status_atype -
 * @NVME_LBA_STATUS_ATYPE_SCAN_UNTRACKED:
 * @NVME_LBA_STATUS_ATYPE_SCAN_TRACKED:
 */
enum nvme_lba_status_atype {
	NVME_LBA_STATUS_ATYPE_SCAN_UNTRACKED			= 0x10,
	NVME_LBA_STATUS_ATYPE_SCAN_TRACKED			= 0x11,
};

/**
 * struct nvme_lba_status_log -
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
 * struct nvme_eg_event_aggregate_log -
 */
struct nvme_eg_event_aggregate_log {
	__le64	nr_entries;
	__le16	egids[];
};

/**
 * struct nvme_resv_notification_log -
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
 * enum -
 */
enum {
	NVME_RESV_NOTIFY_RNLPT_EMPTY			= 0,
	NVME_RESV_NOTIFY_RNLPT_REGISTRATION_PREEMPTED	= 1,
	NVME_RESV_NOTIFY_RNLPT_RESERVATION_RELEASED	= 2,
	NVME_RESV_NOTIFY_RNLPT_RESERVATION_PREEMPTED	= 3,
};

/**
 * struct nvme_sanitize_log_page -
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
 * DOC: NVMe Directives
 */

/**
 * enum -
 */
enum {
	NVME_SANITIZE_SSTAT_NEVER_SANITIZED	= 0,
	NVME_SANITIZE_SSTAT_COMPLETE_SUCCESS	= 1,
	NVME_SANITIZE_SSTAT_IN_PROGESS		= 2,
	NVME_SANITIZE_SSTAT_COMPLETED_FAILED	= 3,
	NVME_SANITIZE_SSTAT_ND_COMPLETE_SUCCESS	= 4,
};

/**
 * struct nvme_lba_status_desc -
 */
struct nvme_lba_status_desc {
	__le64 dslba;
	__le32 nlb;
	__u8 rsvd12;
	__u8 status;
	__u8 rsvd14[2];
};

/**
 * struct nvme_lba_status -
 */
struct nvme_lba_status {
	__le32	nlsd;
	__u8	cmpc;
	__u8	rsvd5[3];
	struct nvme_lba_status_desc descs[];
};


/**
 * DOC: NVMe Management Interface
 */

/**
 * struct nvme_mi_read_nvm_ss_info -
 */
struct nvme_mi_read_nvm_ss_info {
	__u8	nump;
	__u8	mjr;
	__u8	mnr;
	__u8	rsvd3[29];
};

/**
 * struct nvme_mi_port_pcie -
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
 * struct nvme_mi_port_smb -
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
 * struct nvme_mi_read_port_info -
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
 * struct nvme_mi_read_ctrl_info -
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
 * struct nvme_mi_osc -
 */
struct nvme_mi_osc {
	__u8	type;
	__u8	opc;
};

/**
 * struct nvme_mi_read_sc_list -
 */
struct nvme_mi_read_sc_list {
	__le16	numcmd;
	struct nvme_mi_osc cmds[];
};

/**
 * struct nvme_mi_nvm_ss_health_status -
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
 * enum  -
 */
enum {
	NVME_MI_CCS_RDY		= 1 << 0,
	NVME_MI_CSS_CFS		= 1 << 1,
	NVME_MI_CSS_SHST	= 1 << 2,
	NVME_MI_CSS_NSSRO	= 1 << 4,
	NVME_MI_CSS_CECO	= 1 << 5,
	NVME_MI_CSS_NAC		= 1 << 6,
	NVME_MI_CSS_FA		= 1 << 7,
	NVME_MI_CSS_CSTS	= 1 << 8,
	NVME_MI_CSS_CTEMP	= 1 << 9,
	NVME_MI_CSS_PDLU	= 1 << 10,
	NVME_MI_CSS_SPARE	= 1 << 11,
	NVME_MI_CSS_CCWARN	= 1 << 12,
};

/**
 * struct nvme_mi_ctrl_heal_status -
 */
struct nvme_mi_ctrl_heal_status {
	__le16	ctlid;
	__le16	csts;
	__le16	ctemp;
	__u8	pdlu;
	__u8	spare;
	__u8	cwarn;
	__u8	rsvd9[7];
};

/**
 * enum -
 */
enum {
	NVME_MI_CSTS_RDY	= 1 << 0,
	NVME_MI_CSTS_CFS	= 1 << 1,
	NVME_MI_CSTS_SHST	= 1 << 2,
	NVME_MI_CSTS_NSSRO	= 1 << 4,
	NVME_MI_CSTS_CECO	= 1 << 5,
	NVME_MI_CSTS_NAC	= 1 << 6,
	NVME_MI_CSTS_FA		= 1 << 7,
	NVME_MI_CWARN_ST	= 1 << 0,
	NVME_MI_CWARN_TAUT	= 1 << 1,
	NVME_MI_CWARN_RD	= 1 << 2,
	NVME_MI_CWARN_RO	= 1 << 3,
	NVME_MI_CWARN_VMBF	= 1 << 4,
};

/**
 * struct nvme_mi_vpd_mra -
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
 * struct nvme_mi_vpd_ppmra -
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
 * struct nvme_mi_vpd_telem -
 */
struct nvme_mi_vpd_telem {
	__u8	type;
	__u8	rev;
	__u8	len;
	__u8	data[0];
};

/**
 * enum -
 */
enum {
	NVME_MI_ELEM_EED	= 1,
	NVME_MI_ELEM_USCE	= 2,
	NVME_MI_ELEM_ECED	= 3,
	NVME_MI_ELEM_LED	= 4,
	NVME_MI_ELEM_SMBMED	= 5,
	NVME_MI_ELEM_PCIESED	= 6,
	NVME_MI_ELEM_NVMED	= 7,
};

/**
 * struct nvme_mi_vpd_tra -
 */
struct nvme_mi_vpd_tra {
	__u8	vn;
	__u8	rsvd6;
	__u8	ec;
	struct nvme_mi_vpd_telem elems[0];
};

/**
 * struct nvme_mi_vpd_mr_common -
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
 * struct nvme_mi_vpd_hdr -
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
 * DOC: NVMe Features
 */

/**
 * struct nvme_feat_auto_pst -
 */
struct nvme_feat_auto_pst {
	__le64	apst_entry[32];
};

/**
 * struct nvme_timestamp -
 */
struct nvme_timestamp {
	__u8 timestamp[6];
	__u8 attr;
	__u8 rsvd;
};

/**
 * struct nvme_lba_range_type_entry -
 */
struct nvme_lba_range_type_entry {
	__u8			type;
	__u8			attributes;
	__u8			rsvd2[14];
	__u64			slba;
	__u64			nlb;
	__u8			guid[16];
	__u8			rsvd48[16];
};

/**
 * enum -
 */
enum {
	NVME_LBART_TYPE_GP	= 0,
	NVME_LBART_TYPE_FS	= 1,
	NVME_LBART_TYPE_RAID	= 2,
	NVME_LBART_TYPE_CACHE	= 3,
	NVME_LBART_TYPE_SWAP	= 4,
	NVME_LBART_ATTRIB_TEMP	= 1 << 0,
	NVME_LBART_ATTRIB_HIDE	= 1 << 1,
};

/**
 * struct nvme_lba_range_type -
 */
struct nvme_lba_range_type {
	struct nvme_lba_range_type_entry entry[NVME_FEAT_LBA_RANGE_MAX];
};

/**
 * struct nvme_plm_config -
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
 * struct nvme_feat_host_behavior -
 */
struct nvme_feat_host_behavior {
	__u8 acre;
	__u8 resv1[511];
};

/**
 * enum -
 */
enum {
	NVME_ENABLE_ACRE        = 1 << 0,
};

/**
 * struct nvme_dsm_range -
 */
struct nvme_dsm_range {
	__le32			cattr;
	__le32			nlb;
	__le64			slba;
};

/**
 * struct nvme_registered_ctrl -
 */
struct nvme_registered_ctrl {
	__le16	cntlid;
	__u8	rcsts;
	__u8	rsvd3[5];
	__le64	hostid;
	__le64	rkey;
};

/**
 * struct nvme_registered_ctrl_ext -
 */
struct nvme_registered_ctrl_ext {
	__le16	cntlid;
	__u8	rcsts;
	__u8	resv3[5];
	__le64	rkey;
	__u8	hostid[16];
	__u8	resv32[32];
};

/**
 * struct nvme_reservation_status -
 */
struct nvme_reservation_status {
	__le32	gen;
	__u8	rtype;
	__u8	regctl[2];
	__u8	rsvd7[2];
	__u8	ptpls;
	__u8	rsvd10[14];
	union {
		struct {
			__u8	resv24[40];
			struct nvme_registered_ctrl_ext regctl_eds[0];
		};
		struct nvme_registered_ctrl regctl_ds[0];
	};
};

enum {
	NVME_FEAT_ARB_BURST_MASK	= 0x00000007,
	NVME_FEAT_ARB_LPW_MASK		= 0x0000ff00,
	NVME_FEAT_ARB_MPW_MASK		= 0x00ff0000,
	NVME_FEAT_ARB_HPW_MASK		= 0xff000000,
	NVME_FEAT_PM_PS_MASK		= 0x0000001f,
	NVME_FEAT_PM_WH_MASK		= 0x000000e0,	
	NVME_FEAT_LBAR_NR_MASK		= 0x0000003f,
	NVME_FEAT_TT_TMPTH_MASK		= 0x0000ffff,
	NVME_FEAT_TT_TMPSEL_MASK	= 0x000f0000,
	NVME_FEAT_TT_THSEL_MASK		= 0x00300000,
	NVME_FEAT_ER_TLER_MASK		= 0x0000ffff,
	NVME_FEAT_ER_DULBE_MASK		= 0x00010000,
	NVME_FEAT_VWC_WCE_MASK		= 0x00000001,
	NVME_FEAT_NRQS_NSQR_MASK	= 0x0000ffff,
	NVME_FEAT_NRQS_NCQR_MASK	= 0xffff0000,
	NVME_FEAT_ICOAL_THR_MASK	= 0x000000ff,
	NVME_FEAT_ICOAL_TIME_MASK	= 0x0000ff00,
	NVME_FEAT_ICFG_IV_MASK		= 0x0000ffff,
	NVME_FEAT_ICFG_CD_MASK		= 0x00010000,
	NVME_FEAT_WA_DN_MASK		= 0x00000001,
	NVME_FEAT_AE_SMART_MASK		= 0x000000ff,
	NVME_FEAT_AE_NAN_MASK		= 0x00000100,
	NVME_FEAT_AE_FW_MASK		= 0x00000200,
	NVME_FEAT_AE_TELEM_MASK		= 0x00000400,
	NVME_FEAT_AE_ANA_MASK		= 0x00000800,
	NVME_FEAT_AE_PLA_MASK		= 0x00001000,
	NVME_FEAT_AE_LBAS_MASK		= 0x00002000,
	NVME_FEAT_AE_EGA_MASK		= 0x00004000,
	NVME_FEAT_APST_APSTE_MASK	= 0x00000001,
	NVME_FEAT_HMEM_EHM_MASK		= 0x00000001,
	NVME_FEAT_TS_SYNCH_MASK		= 0x00000001,
	NVME_FEAT_TS_ORIGIN_MASK	= 0x0000000e,
	NVME_FEAT_TS_ORIGIN_CLR		= 0x00000001,
	NVME_FEAT_TS_ORIGIN_SF		= 0x00000002,
	NVME_FEAT_HCTM_TMT2_MASK	= 0x0000ffff,
	NVME_FEAT_HCTM_TMT1_MASK	= 0xffff0000,
	NVME_FEAT_NOPS_NOPPME_MASK	= 0x00000001,
	NVME_FEAT_RRL_RRL_MASK		= 0x000000ff,
	NVME_FEAT_PLM_PLME_MASK		= 0x00000001,
	NVME_FEAT_PLMW_WS_MASK		= 0x00000007,
	NVME_FEAT_LBAS_LSIRI_MASK	= 0x0000ffff,
	NVME_FEAT_LBAS_LSIPI_MASK	= 0xffff0000,
	NVME_FEAT_SC_NODRM_MASK		= 0x00000001,
	NVME_FEAT_EG_ENDGID_MASK	= 0x0000ffff,
	NVME_FEAT_EG_EGCW_MASK		= 0x00ff0000,
	NVME_FEAT_SPM_PBSLC_MASK	= 0x000000ff,
	NVME_FEAT_HOSTID_EXHID_MASK	= 0x00000001,
	NVME_FEAT_RM_REGPRE_MASK	= 0x00000002,
	NVME_FEAT_RM_RESREL_MASK	= 0x00000004,
	NVME_FEAT_RM_RESPRE_MASK	= 0x00000008,
	NVME_FEAT_RP_PTPL_MASK		= 0x00000001,
	NVME_FEAT_WP_WPS_MASK		= 0x00000007,
};

#define shift(v, s, m)  ((v & m) >> s)

#define NVME_FEAT_ARB_BURST(v)		shift(v, 0, NVME_FEAT_ARB_BURST_MASK)
#define NVME_FEAT_ARB_LPW(v)		shift(v, 8, NVME_FEAT_ARB_LPW_MASK)
#define NVME_FEAT_ARB_MPW(v)		shift(v, 16, NVME_FEAT_ARB_MPW_MASK)
#define NVME_FEAT_ARB_HPW(v)		shift(v, 24, NVME_FEAT_ARB_HPW_MASK)
#define NVME_FEAT_PM_PS(v)		shift(v, 0, NVME_FEAT_PM_PS_MASK)
#define NVME_FEAT_PM_WH(v)		shift(v, 5, NVME_FEAT_PM_WH_MASK)
#define NVME_FEAT_LBAR_NR(v)		shift(v, 0, NVME_FEAT_LBAR_NR_MASK)
#define NVME_FEAT_TT_TMPTH(v)		shift(v, 0, NVME_FEAT_TT_TMPTH_MASK)
#define NVME_FEAT_TT_TMPSEL(v)		shift(v, 16, NVME_FEAT_TT_TMPSEL_MASK)
#define NVME_FEAT_TT_THSEL(v)		shift(v, 20, NVME_FEAT_TT_THSEL_MASK)
#define NVME_FEAT_ER_TLER(v)		shift(v, 0, NVME_FEAT_ER_TLER_MASK)
#define NVME_FEAT_ER_DULBE(v)		shift(v, 16, NVME_FEAT_ER_DULBE_MASK)
#define NVME_FEAT_VWC_WCE(v)		shift(v, 0, NVME_FEAT_VWC_WCE_MASK)
#define NVME_FEAT_NRQS_NSQR(v)		shift(v, 0, NVME_FEAT_NRQS_NSQR_MASK)
#define NVME_FEAT_NRQS_NCQR(v)		shift(v, 16, NVME_FEAT_NRQS_NCQR_MASK)
#define NVME_FEAT_ICOAL_THR(v)		shift(v, 0, NVME_FEAT_ICOAL_THR_MASK)
#define NVME_FEAT_ICOAL_TIME(v)		shift(v, 8, NVME_FEAT_ICOAL_TIME_MASK)
#define NVME_FEAT_ICFG_IV(v)		shift(v, 0, NVME_FEAT_ICFG_IV_MASK)
#define NVME_FEAT_ICFG_CD(v)		shift(v, 16, NVME_FEAT_ICFG_CD_MASK)
#define NVME_FEAT_WA_DN(v)		shift(v, 0, NVME_FEAT_WA_DN_MASK)
#define NVME_FEAT_AE_SMART(v)		shift(v, 0, NVME_FEAT_AE_SMART_MASK)
#define NVME_FEAT_AE_NAN(v)		shift(v, 8, NVME_FEAT_AE_NAN_MASK)
#define NVME_FEAT_AE_FW(v)		shift(v, 9, NVME_FEAT_AE_FW_MASK)
#define NVME_FEAT_AE_TELEM(v)		shift(v, 10, NVME_FEAT_AE_TELEM_MASK)
#define NVME_FEAT_AE_ANA(v)		shift(v, 11, NVME_FEAT_AE_ANA_MASK)
#define NVME_FEAT_AE_PLA(v)		shift(v, 12, NVME_FEAT_AE_PLA_MASK)
#define NVME_FEAT_AE_LBAS(v)		shift(v, 13, NVME_FEAT_AE_LBAS_MASK)
#define NVME_FEAT_AE_EGA(v)		shift(v, 14, NVME_FEAT_AE_EGA_MASK)
#define NVME_FEAT_APST_APSTE(v)		shift(v, 0, NVME_FEAT_APST_APSTE_MASK)
#define NVME_FEAT_HMEM_EHM(v)		shift(v, 0, NVME_FEAT_HMEM_EHM_MASK)
#define NVME_FEAT_TS_SYNC(v)		shift(v, 0, NVME_FEAT_TS_SYNCH_MASK)
#define NVME_FEAT_TS_ORIGIN(v)		shift(v, 1, NVME_FEAT_TS_ORIGIN_MASK)
#define NVME_FEAT_HCTM_TMT2(v)		shift(v, 0, NVME_FEAT_HCTM_TMT2_MASK)
#define NVME_FEAT_HCTM_TMT1(v)		shift(v, 16, NVME_FEAT_HCTM_TMT1_MASK)
#define NVME_FEAT_NOPS_NOPPME(v)	shift(v, 0, NVME_FEAT_NOPS_NOPPME_MASK)
#define NVME_FEAT_RRL_RRL(v)		shift(v, 0, NVME_FEAT_RRL_RRL_MASK)
#define NVME_FEAT_PLM_PLME(v)		shift(v, 0, NVME_FEAT_PLM_PLME_MASK)
#define NVME_FEAT_PLMW_WS(v)		shift(v, 0, NVME_FEAT_PLMW_WS_MASK)
#define NVME_FEAT_LBAS_LSIRI(v)		shift(v, 0, NVME_FEAT_LBAS_LSIRI_MASK)
#define NVME_FEAT_LBAS_LSIPI(v)		shift(v, 16, NVME_FEAT_LBAS_LSIPI_MASK)
#define NVME_FEAT_SC_NODRM(v)		shift(v, 0, NVME_FEAT_SC_NODRM_MASK)
#define NVME_FEAT_EG_ENDGID(v)		shift(v, 0, NVME_FEAT_EG_ENDGID_MASK)
#define NVME_FEAT_EG_EGCW(v)		shift(v, 16, NVME_FEAT_EG_EGCW_MASK)
#define NVME_FEAT_SPM_PBSLC(v)		shift(v, 0, NVME_FEAT_SPM_PBSLC_MASK)
#define NVME_FEAT_HOSTID_EXHID(v)	shift(v, 0, NVME_FEAT_HOSTID_EXHID_MASK)
#define NVME_FEAT_RM_REGPRE(v)		shift(v, 1, NVME_FEAT_RM_REGPRE_MASK)
#define NVME_FEAT_RM_RESREL(v)		shift(v, 2, NVME_FEAT_RM_RESREL_MASK)
#define NVME_FEAT_RM_RESPRE(v)		shift(v, 3, NVME_FEAT_RM_RESPRE_MASK)
#define NVME_FEAT_RP_PTPL(v)		shift(v, 0, NVME_FEAT_RP_PTPL_MASK)
#define NVME_FEAT_WP_WPS(v)		shift(v, 0, NVME_FEAT_WP_WPS_MASK)

/**
 * struct nvme_streams_directive_params -
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
 * struct nvme_streams_directive_status -
 */
struct nvme_streams_directive_status {
	__le16	osc;
	__le16	sid[];
};

/**
 * struct nvme_id_directives -
 */
struct nvme_id_directives {
	__u8	supported[32];
	__u8	enabled[32];
	__u8	rsvd64[4032];
};

/**
 * enum -
 */
enum {
	NVME_ID_DIR_ID_BIT	= 0,
	NVME_ID_DIR_SD_BIT	= 1,
};

/**
 * struct nvme_host_mem_buf_desc -
 */
struct nvme_host_mem_buf_desc {
	__le64			addr;
	__le32			size;
	__u32			rsvd;
};

/**
 * enum nvme_ae_type -
 * @NVME_AER_ERROR:
 * @NVME_AER_SMART:
 * @NVME_AER_NOTICE:
 * @NVME_AER_CSS:
 * @NVME_AER_VS:
 */
enum nvme_ae_type {
        NVME_AER_ERROR				= 0,
        NVME_AER_SMART				= 1,
        NVME_AER_NOTICE				= 2,
        NVME_AER_CSS				= 6,
        NVME_AER_VS				= 7,
};
/**
 * enum nvme_ae_info_error -
 * @NVME_AER_ERROR_INVALID_DB_REG:
 * @NVME_AER_ERROR_INVALID_DB_VAL:
 * @NVME_AER_ERROR_DIAG_FAILURE:
 * @NVME_AER_ERROR_PERSISTENT_INTERNAL_ERROR:
 * @NVME_AER_ERROR_TRANSIENT_INTERNAL_ERROR:
 * @NVME_AER_ERROR_FW_IMAGE_LOAD_ERROR:
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
 * enum nvme_ae_info_smart -
 * @NVME_AER_SMART_SUBSYSTEM_RELIABILITY:
 * @NVME_AER_SMART_TEMPERATURE_THRESHOLD:
 * @NVME_AER_SMART_SPARE_THRESHOLD:
 */
enum nvme_ae_info_smart {
	NVME_AER_SMART_SUBSYSTEM_RELIABILITY		= 0x00,
	NVME_AER_SMART_TEMPERATURE_THRESHOLD		= 0x01,
	NVME_AER_SMART_SPARE_THRESHOLD			= 0x02,
};

/**
 * enum nvme_ae_info_css_nvm -
 * @NVME_AER_CSS_NVM_RESERVATION:
 * @NVME_AER_CSS_NVM_SANITIZE_COMPLETED:
 * @NVME_AER_CSS_NVM_UNEXPECTED_SANITIZE_DEALLOC:
 */
enum nvme_ae_info_css_nvm {
	NVME_AER_CSS_NVM_RESERVATION			= 0x00,
	NVME_AER_CSS_NVM_SANITIZE_COMPLETED		= 0x01,
	NVME_AER_CSS_NVM_UNEXPECTED_SANITIZE_DEALLOC	= 0x02,
};

/**
 * enum nvme_ae_info_notice -
 * @NVME_AER_NOTICE_NS_CHANGED:
 * @NVME_AER_NOTICE_FW_ACT_STARTING:
 * @NVME_AER_NOTICE_TELEMETRY:
 * @NVME_AER_NOTICE_ANA:
 * @NVME_AER_NOTICE_PL_EVENT:
 * @NVME_AER_NOTICE_LBA_STATUS_ALERT:
 * @NVME_AER_NOTICE_EG_EVENT:
 * @NVME_AER_NOTICE_DISC_CHANGED:
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
 * enum nvme_subsys_type -
 * @NVME_NQN_DISC:		Discovery type target subsystem
 * @NVME_NQN_NVME:		NVME type target subsystem
 */
enum nvme_subsys_type {
	NVME_NQN_DISC	= 1,
	NVME_NQN_NVME	= 2,
};

#define NVME_DISC_SUBSYS_NAME	"nqn.2014-08.org.nvmexpress.discovery"
#define NVME_RDMA_IP_PORT	4420

/* NQN names in commands fields specified one size */
#define NVMF_NQN_FIELD_LEN	256

/* However the max length of a qualified name is another size */
#define NVMF_NQN_SIZE		223
#define NVMF_TRSVCID_SIZE	32
#define NVMF_TRADDR_SIZE	256
#define NVMF_TSAS_SIZE		256

/**
 * struct nvmf_disc_log_entry -
 *
 * Discovery log page entry
 */
struct nvmf_disc_log_entry {
	__u8		trtype;
	__u8		adrfam;
	__u8		subtype;
	__u8		treq;
	__le16		portid;
	__le16		cntlid;
	__le16		asqsz;
	__u8		resv10[22];
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

/**
 * enum -
 * @NVMF_TRTYPE_UNSPECIFIED:	Not indicated
 * @NVMF_TRTYPE_RDMA:		RDMA
 * @NVMF_TRTYPE_FC:		Fibre Channel
 * @NVMF_TRTYPE_TCP:		TCP
 * @NVMF_TRTYPE_LOOP:		Reserved for host usage
 *
 * Transport Type codes for Discovery Log Page entry TRTYPE field
 */
enum {
	NVMF_TRTYPE_UNSPECIFIED	= 0,
	NVMF_TRTYPE_RDMA	= 1,
	NVMF_TRTYPE_FC		= 2,
	NVMF_TRTYPE_TCP		= 3,
	NVMF_TRTYPE_LOOP	= 254,
	NVMF_TRTYPE_MAX,
};

/**
 * enum -
 * @NVMF_ADDR_FAMILY_PCI:	PCIe
 * @NVMF_ADDR_FAMILY_IP4:	IPv4
 * @NVMF_ADDR_FAMILY_IP6:	IPv6
 * @NVMF_ADDR_FAMILY_IB:	InfiniBand
 * @NVMF_ADDR_FAMILY_FC:	Fibre Channel
 *
 * Address Family codes for Discovery Log Page entry ADRFAM field
 */
enum {
	NVMF_ADDR_FAMILY_PCI	= 0,
	NVMF_ADDR_FAMILY_IP4	= 1,
	NVMF_ADDR_FAMILY_IP6	= 2,
	NVMF_ADDR_FAMILY_IB	= 3,
	NVMF_ADDR_FAMILY_FC	= 4,
};

/**
 * enum -
 * @NVMF_TREQ_NOT_SPECIFIED:	Not specified
 * @NVMF_TREQ_REQUIRED:		Required
 * @NVMF_TREQ_NOT_REQUIRED:	Not Required
 * @NVMF_TREQ_DISABLE_SQFLOW:	SQ flow control disable supported
 *
 * Transport Requirements codes for Discovery Log Page entry TREQ field
 */
enum {
	NVMF_TREQ_NOT_SPECIFIED		= 0,
	NVMF_TREQ_REQUIRED		= 1,
	NVMF_TREQ_NOT_REQUIRED		= 2,
	NVMF_TREQ_DISABLE_SQFLOW	= 4,
};

/**
 * enum -
 * @NVMF_RDMA_QPTYPE_CONNECTED:	Reliable Connected
 * @NVMF_RDMA_QPTYPE_DATAGRAM:	Reliable Datagram
 *
 * RDMA QP Service Type codes for Discovery Log Page entry TSAS
 * RDMA_QPTYPE field
 */
enum {
	NVMF_RDMA_QPTYPE_CONNECTED	= 1,
	NVMF_RDMA_QPTYPE_DATAGRAM	= 2,
};

/**
 * enum -
 * @NVMF_RDMA_PRTYPE_NOT_SPECIFIED:	No Provider Specified
 * @NVMF_RDMA_PRTYPE_IB: 		InfiniBand
 * @NVMF_RDMA_PRTYPE_ROCE: 		InfiniBand RoCE
 * @NVMF_RDMA_PRTYPE_ROCEV2: 		InfiniBand RoCEV2
 * @NVMF_RDMA_PRTYPE_IWARP: 		iWARP
 *
 * RDMA Provider Type codes for Discovery Log Page entry TSAS
 * RDMA_PRTYPE field
 */
enum {
	NVMF_RDMA_PRTYPE_NOT_SPECIFIED	= 1,
	NVMF_RDMA_PRTYPE_IB		= 2,
	NVMF_RDMA_PRTYPE_ROCE		= 3,
	NVMF_RDMA_PRTYPE_ROCEV2		= 4,
	NVMF_RDMA_PRTYPE_IWARP		= 5,
};

/**
 * enum -
 * @NVMF_RDMA_CMS_RDMA_CM:	 Sockets based endpoint addressing
 *
 * RDMA Connection Management Service Type codes for Discovery Log Page
 * entry TSAS RDMA_CMS field
 */
enum {
	NVMF_RDMA_CMS_RDMA_CM	= 1,
};

/**
 * enum -
 * @NVMF_TCP_SECTYPE_NONE:	No Security
 * @NVMF_TCP_SECTYPE_TLS:	Transport Layer Security
 */
enum {
	NVMF_TCP_SECTYPE_NONE	= 0,
	NVMF_TCP_SECTYPE_TLS	= 1,
};

/**
 * struct nvmf_discovery_log -
 */
struct nvmf_discovery_log {
	__le64		genctr;
	__le64		numrec;
	__le16		recfmt;
	__u8		resv14[1006];
	struct nvmf_disc_log_entry entries[0];
};

/**
 * struct nvmf_connect_data -
 */
struct nvmf_connect_data {
	__u8		hostid[16];
	__le16		cntlid;
	char		resv4[238];
	char		subsysnqn[NVMF_NQN_FIELD_LEN];
	char		hostnqn[NVMF_NQN_FIELD_LEN];
	char		resv5[256];
};

/**
 * enum -
 */
enum {
	/*
	 * Status code type
	 */
	NVME_SCT_GENERIC		= 0x000,
	NVME_SCT_CMD_SPECIFIC		= 0x100,
	NVME_SCT_MEDIA			= 0x200,
	NVME_SCT_PATH			= 0x300,
	NVME_SCT_VS			= 0x700,
	NVME_SCT_MASK			= 0x700,

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
	NVME_SC_AWU_EXCEEDED		= 0x14,
	NVME_SC_OP_DENIED		= 0x15,
	NVME_SC_SGL_INVALID_OFFSET	= 0x16,

	NVME_SC_HOSTID_FORMAT		= 0x18,
	NVME_SC_KAT_EXPIRED		= 0x19,
	NVME_SC_KAT_INVALID		= 0x1a,
	NVME_SC_CMD_ABORTED_PREMEPT	= 0x1b,
	NVME_SC_SANITIZE_FAILED		= 0x1c,
	NVME_SC_SANITIZE_IN_PROGRESS	= 0x1d,
	NVME_SC_SGL_INVALID_GRANULARITY	= 0x1e,
	NVME_SC_CMD_IN_CMBQ_NOT_SUPP	= 0x1f,
	NVME_SC_NS_WRITE_PROTECTED	= 0x20,
	NVME_SC_CMD_INTERRUPTED		= 0x21,
	NVME_SC_TRAN_TPORT_ERROR	= 0x22,

	NVME_SC_LBA_RANGE		= 0x80,
	NVME_SC_CAP_EXCEEDED		= 0x81,
	NVME_SC_NS_NOT_READY		= 0x82,
	NVME_SC_RESERVATION_CONFLICT	= 0x83,
	NVME_SC_FORMAT_IN_PROGRESS	= 0x84,

	/*
	 * Command Specific Status:
	 */
	NVME_SC_CQ_INVALID		= 0x00,
	NVME_SC_QID_INVALID		= 0x01,
	NVME_SC_QUEUE_SIZE		= 0x02,
	NVME_SC_ABORT_LIMIT		= 0x03,
	NVME_SC_ABORT_MISSING		= 0x04,
	NVME_SC_ASYNC_LIMIT		= 0x05,
	NVME_SC_FIRMWARE_SLOT		= 0x06,
	NVME_SC_FIRMWARE_IMAGE		= 0x07,
	NVME_SC_INVALID_VECTOR		= 0x08,
	NVME_SC_INVALID_LOG_PAGE	= 0x09,
	NVME_SC_INVALID_FORMAT		= 0x0a,
	NVME_SC_FW_NEEDS_CONV_RESET	= 0x0b,
	NVME_SC_INVALID_QUEUE		= 0x0c,
	NVME_SC_FEATURE_NOT_SAVEABLE	= 0x0d,
	NVME_SC_FEATURE_NOT_CHANGEABLE	= 0x0e,
	NVME_SC_FEATURE_NOT_PER_NS	= 0x0f,
	NVME_SC_FW_NEEDS_SUBSYS_RESET	= 0x10,
	NVME_SC_FW_NEEDS_RESET		= 0x11,
	NVME_SC_FW_NEEDS_MAX_TIME	= 0x12,
	NVME_SC_FW_ACTIVATE_PROHIBITED	= 0x13,
	NVME_SC_OVERLAPPING_RANGE	= 0x14,
	NVME_SC_NS_INSUFFICIENT_CAP	= 0x15,
	NVME_SC_NS_ID_UNAVAILABLE	= 0x16,
	NVME_SC_NS_ALREADY_ATTACHED	= 0x18,
	NVME_SC_NS_IS_PRIVATE		= 0x19,
	NVME_SC_NS_NOT_ATTACHED		= 0x1a,
	NVME_SC_THIN_PROV_NOT_SUPP	= 0x1b,
	NVME_SC_CTRL_LIST_INVALID	= 0x1c,
	NVME_SC_SELF_TEST_IN_PROGRESS	= 0x1d,
	NVME_SC_BP_WRITE_PROHIBITED	= 0x1e,
	NVME_SC_INVALID_CTRL_ID		= 0x1f,
	NVME_SC_INVALID_SEC_CTRL_STATE	= 0x20,
	NVME_SC_INVALID_CTRL_RESOURCES	= 0x21,
	NVME_SC_INVALID_RESOURCE_ID	= 0x22,
	NVME_SC_PMR_SAN_PROHIBITED	= 0x23,
	NVME_SC_ANA_GROUP_ID_INVALID	= 0x24,
	NVME_SC_ANA_ATTACH_FAILED	= 0x25,

	/*
	 * I/O Command Set Specific - NVM commands:
	 */
	NVME_SC_BAD_ATTRIBUTES		= 0x80,
	NVME_SC_INVALID_PI		= 0x81,
	NVME_SC_READ_ONLY		= 0x82,

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
	 * Status code mask
	 */
	NVME_SC_MASK			= 0xff,

	/*
	 * Additional status info
	 */
	NVME_SC_CRD			= 0x1800,
	NVME_SC_MORE			= 0x2000,
	NVME_SC_DNR			= 0x4000,
};

#define NVME_MAJOR(ver)		((ver) >> 16)
#define NVME_MINOR(ver)		(((ver) >> 8) & 0xff)
#define NVME_TERTIARY(ver)	((ver) & 0xff)

#endif /* _LIBNVME_TYPES_H */
