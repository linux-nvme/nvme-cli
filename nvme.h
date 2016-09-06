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

#ifndef _NVME_H
#define _NVME_H

#include <linux/types.h>
#include "plugin.h"

/* NQN names in commands fields specified one size */
#define NVMF_NQN_FIELD_LEN	256

/* However the max length of a qualified name is another size */
#define NVMF_NQN_SIZE		223
#define NVMF_TRSVCID_SIZE	32
#define NVMF_TRADDR_SIZE	256
#define NVMF_TSAS_SIZE		256

#define NVME_DISC_SUBSYS_NAME	"nqn.2014-08.org.nvmexpress.discovery"

enum nvme_subsys_type {
	NVME_NQN_DISC	= 1,		/* Discovery type target subsystem */
	NVME_NQN_NVME	= 2,		/* NVME type target subsystem */
};

/* Transport Type codes for Discovery Log Page entry TRTYPE field */
enum {
	NVMF_TRTYPE_RDMA	= 1,	/* RDMA */
	NVMF_TRTYPE_FC		= 2,	/* Fibre Channel */
	NVMF_TRTYPE_LOOP	= 254,  /* Reserved for host usage */
};

/* Transport Requirements codes for Discovery Log Page entry TREQ field */
enum {
	NVMF_TREQ_NOT_SPECIFIED	= 0,	/* Not specified */
	NVMF_TREQ_REQUIRED	= 1,	/* Required */
	NVMF_TREQ_NOT_REQUIRED	= 2,	/* Not Required */
};

/* RDMA QP Service Type codes for Discovery Log Page entry TSAS
 * RDMA_QPTYPE field
 */
enum {
	NVMF_RDMA_QPTYPE_CONNECTED	= 0, /* Reliable Connected */
	NVMF_RDMA_QPTYPE_DATAGRAM	= 1, /* Reliable Datagram */
};

/* RDMA QP Service Type codes for Discovery Log Page entry TSAS
 * RDMA_QPTYPE field
 */
enum {
	NVMF_RDMA_PRTYPE_NOT_SPECIFIED	= 0, /* No Provider Specified */
	NVMF_RDMA_PRTYPE_IB		= 1, /* InfiniBand */
	NVMF_RDMA_PRTYPE_ROCE		= 2, /* InfiniBand RoCE */
	NVMF_RDMA_PRTYPE_ROCEV2		= 3, /* InfiniBand RoCEV2 */
	NVMF_RDMA_PRTYPE_IWARP		= 4, /* IWARP */
};

/* RDMA Connection Management Service Type codes for Discovery Log Page
 * entry TSAS RDMA_CMS field
 */
enum {
	NVMF_RDMA_CMS_RDMA_CM	= 0, /* Sockets based enpoint addressing */
};

/* Address Family codes for Discovery Log Page entry ADRFAM field */
enum {
	NVMF_ADDR_FAMILY_PCI	= 0,	/* PCIe */
	NVMF_ADDR_FAMILY_IP4	= 1,	/* IP4 */
	NVMF_ADDR_FAMILY_IP6	= 2,	/* IP6 */
	NVMF_ADDR_FAMILY_IB	= 3,	/* InfiniBand */
	NVMF_ADDR_FAMILY_FC	= 4,	/* Fibre Channel */
};

struct nvme_error_log_page {
	__u64	error_count;
	__u16	sqid;
	__u16	cmdid;
	__u16	status_field;
	__u16	parm_error_location;
	__u64	lba;
	__u32	nsid;
	__u8	vs;
	__u8	resv[35];
};

struct nvme_firmware_log_page {
	__u8	afi;
	__u8	resv[7];
	__u64	frs[7];
	__u8	resv2[448];
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
	__u8			rsvd96[160];
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
	__u8			rsvd316[196];
	__u8			sqes;
	__u8			cqes;
	__u8			rsvd514[2];
	__le32			nn;
	__le16			oncs;
	__le16			fuses;
	__u8			fna;
	__u8			vwc;
	__le16			awun;
	__le16			awupf;
	__u8			nvscc;
	__u8			rsvd531;
	__le16			acwu;
	__u8			rsvd534[2];
	__le32			sgls;
	__u8			rsvd540[1508];
	struct nvme_id_power_state	psd[32];
	__u8			vs[1024];
};

enum {
	NVME_CTRL_ONCS_COMPARE			= 1 << 0,
	NVME_CTRL_ONCS_WRITE_UNCORRECTABLE	= 1 << 1,
	NVME_CTRL_ONCS_DSM			= 1 << 2,
	NVME_CTRL_VWC_PRESENT			= 1 << 0,
};

enum {
	NVME_ID_CNS_NS			= 0x00,
	NVME_ID_CNS_CTRL		= 0x01,
	NVME_ID_CNS_NS_ACTIVE_LIST	= 0x02,
	NVME_ID_CNS_NS_PRESENT_LIST	= 0x10,
	NVME_ID_CNS_NS_PRESENT		= 0x11,
	NVME_ID_CNS_CTRL_NS_LIST	= 0x12,
	NVME_ID_CNS_CTRL_LIST		= 0x13,
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
	__u8			rsvd33;
	__le16			nawun;
	__le16			nawupf;
	__le16			nacwu;
	__le16			nabsn;
	__le16			nabo;
	__le16			nabspf;
	__u16			rsvd46;
	__u8			nvmcap[16];
	__u8			rsvd64[40];
	__u8			nguid[16];
	__u8			eui64[8];
	struct nvme_lbaf	lbaf[16];
	__u8			rsvd192[192];
	__u8			vs[3712];
};

enum {
	NVME_NS_FEAT_THIN	= 1 << 0,
	NVME_LBAF_RP_BEST	= 0,
	NVME_LBAF_RP_BETTER	= 1,
	NVME_LBAF_RP_GOOD	= 2,
	NVME_LBAF_RP_DEGRADED	= 3,
};

struct nvme_smart_log {
	__u8			critical_warning;
	__u8			temperature[2];
	__u8			avail_spare;
	__u8			spare_thresh;
	__u8			percent_used;
	__u8			rsvd6[26];
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
	__u8			rsvd216[296];
};

enum {
	NVME_SMART_CRIT_SPARE		= 1 << 0,
	NVME_SMART_CRIT_TEMPERATURE	= 1 << 1,
	NVME_SMART_CRIT_RELIABILITY	= 1 << 2,
	NVME_SMART_CRIT_MEDIA		= 1 << 3,
	NVME_SMART_CRIT_VOLATILE_MEMORY	= 1 << 4,
};

#pragma pack(push,1)
struct nvme_additional_smart_log_item {
	__u8			key;
	__u8			_kp[2];
	__u8			norm;
	__u8			_np;
	union {
		__u8		raw[6];
		struct wear_level {
			__le16	min;
			__le16	max;
			__le16	avg;
		} wear_level ;
		struct thermal_throttle {
			__u8	pct;
			__u32	count;
		} thermal_throttle;
	};
	__u8			_rp;
};
#pragma pack(pop)

struct nvme_additional_smart_log {
	struct nvme_additional_smart_log_item	program_fail_cnt;
	struct nvme_additional_smart_log_item	erase_fail_cnt;
	struct nvme_additional_smart_log_item	wear_leveling_cnt;
	struct nvme_additional_smart_log_item	e2e_err_cnt;
	struct nvme_additional_smart_log_item	crc_err_cnt;
	struct nvme_additional_smart_log_item	timed_workload_media_wear;
	struct nvme_additional_smart_log_item	timed_workload_host_reads;
	struct nvme_additional_smart_log_item	timed_workload_timer;
	struct nvme_additional_smart_log_item	thermal_throttle_status;
	struct nvme_additional_smart_log_item	retry_buffer_overflow_cnt;
	struct nvme_additional_smart_log_item	pll_lock_loss_cnt;
	struct nvme_additional_smart_log_item	nand_bytes_written;
	struct nvme_additional_smart_log_item	host_bytes_written;
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

enum {
	NVME_LBART_TYPE_FS	= 0x01,
	NVME_LBART_TYPE_RAID	= 0x02,
	NVME_LBART_TYPE_CACHE	= 0x03,
	NVME_LBART_TYPE_SWAP	= 0x04,

	NVME_LBART_ATTRIB_TEMP	= 1 << 0,
	NVME_LBART_ATTRIB_HIDE	= 1 << 1,
};

struct nvme_reservation_status {
	__le32	gen;
	__u8	rtype;
	__u8	regctl[2];
	__u8	resv5[2];
	__u8	ptpls;
	__u8	resv10[14];
	struct {
		__le16	cntlid;
		__u8	rcsts;
		__u8	resv3[5];
		__le64	hostid;
		__le64	rkey;
	} regctl_ds[];
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
	nvme_cmd_resv_register	= 0x0d,
	nvme_cmd_resv_report	= 0x0e,
	nvme_cmd_resv_acquire	= 0x11,
	nvme_cmd_resv_release	= 0x15,
};

enum {
	NVME_RW_LR			= 1 << 15,
	NVME_RW_FUA			= 1 << 14,
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
};

enum {
	NVME_DSMGMT_IDR		= 1 << 0,
	NVME_DSMGMT_IDW		= 1 << 1,
	NVME_DSMGMT_AD		= 1 << 2,
};

struct nvme_dsm_range {
	__le32			cattr;
	__le32			nlb;
	__le64			slba;
};

struct nvme_controller_list {
	__le16 num;
	__le16 identifier[];
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
	nvme_admin_ns_attach		= 0x15,
	nvme_admin_format_nvm		= 0x80,
	nvme_admin_security_send	= 0x81,
	nvme_admin_security_recv	= 0x82,
};

enum {
	NVME_QUEUE_PHYS_CONTIG	= (1 << 0),
	NVME_CQ_IRQ_ENABLED	= (1 << 1),
	NVME_SQ_PRIO_URGENT	= (0 << 1),
	NVME_SQ_PRIO_HIGH	= (1 << 1),
	NVME_SQ_PRIO_MEDIUM	= (2 << 1),
	NVME_SQ_PRIO_LOW	= (3 << 1),
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
	NVME_FEAT_SW_PROGRESS	= 0x80,
	NVME_FEAT_HOST_ID	= 0x81,
	NVME_FEAT_RESV_MASK	= 0x82,
	NVME_FEAT_RESV_PERSIST	= 0x83,
	NVME_LOG_ERROR		= 0x01,
	NVME_LOG_SMART		= 0x02,
	NVME_LOG_FW_SLOT	= 0x03,
	NVME_LOG_DISC		= 0x70,
	NVME_LOG_RESERVATION	= 0x80,
	NVME_FWACT_REPL		= (0 << 3),
	NVME_FWACT_REPL_ACTV	= (1 << 3),
	NVME_FWACT_ACTV		= (2 << 3),
};

enum {
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
	NVME_SC_LBA_RANGE		= 0x80,
	NVME_SC_CAP_EXCEEDED		= 0x81,
	NVME_SC_NS_NOT_READY		= 0x82,
	NVME_SC_RESERVATION_CONFLICT	= 0x83,
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
	NVME_SC_FW_ACIVATE_PROHIBITED	= 0x113,
	NVME_SC_OVERLAPPING_RANGE	= 0x114,
	NVME_SC_NS_INSUFFICENT_CAP	= 0x115,
	NVME_SC_NS_ID_UNAVAILABLE	= 0x116,
	NVME_SC_NS_ALREADY_ATTACHED	= 0x118,
	NVME_SC_NS_IS_PRIVATE		= 0x119,
	NVME_SC_NS_NOT_ATTACHED		= 0x11a,
	NVME_SC_THIN_PROV_NOT_SUPP	= 0x11b,
	NVME_SC_CTRL_LIST_INVALID	= 0x11c,
	NVME_SC_BAD_ATTRIBUTES		= 0x180,
	NVME_SC_INVALID_PI		= 0x181,
	NVME_SC_READ_ONLY		= 0x182,
	NVME_SC_WRITE_FAULT		= 0x280,
	NVME_SC_READ_ERROR		= 0x281,
	NVME_SC_GUARD_CHECK		= 0x282,
	NVME_SC_APPTAG_CHECK		= 0x283,
	NVME_SC_REFTAG_CHECK		= 0x284,
	NVME_SC_COMPARE_FAILED		= 0x285,
	NVME_SC_ACCESS_DENIED		= 0x286,
	NVME_SC_UNWRITTEN_BLOCK		= 0x287,
	NVME_SC_DNR			= 0x4000,
};

struct nvme_bar {
	__u64			cap;	/* Controller Capabilities */
	__u32			vs;	/* Version */
	__u32			intms;	/* Interrupt Mask Set */
	__u32			intmc;	/* Interrupt Mask Clear */
	__u32			cc;	/* Controller Configuration */
	__u32			rsvd1;	/* Reserved */
	__u32			csts;	/* Controller Status */
	__u32			nssr;	/* NVM Subsystem Reset */
	__u32			aqa;	/* Admin Queue Attributes */
	__u64			asq;	/* Admin SQ Base Address */
	__u64			acq;	/* Admin CQ Base Address */
	__u32			cmbloc;	/* Controller Memory Buffer Location */
	__u32			cmbsz;	/* Controller Memory Buffer Size */
};

struct nvme_bar_cap {
	__u16	mqes;
	__u8	ams_cqr;
	__u8	to;
	__u16	css_nssrs_dstrd;
	__u8	mpsmax_mpsmin;
	__u8	reserved;
};

#define NVME_CNTLID_DYNAMIC	0xFFFF

/* Discovery log page entry */
struct nvmf_disc_rsp_page_entry {
	__u8	trtype;
	__u8	adrfam;
	__u8	nqntype;
	__u8	treq;
	__le16	portid;
	__le16	cntlid;
	__u8	resv8[24];
	char	trsvcid[NVMF_TRSVCID_SIZE];
	__u8	resv64[192];
	char	subnqn[NVMF_NQN_FIELD_LEN];
	char	traddr[NVMF_TRADDR_SIZE];
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
	} tsas;
};

/* Discovery log page header */
struct nvmf_disc_rsp_page_hdr {
	__le64	genctr;
	__le64	numrec;
	__le16	recfmt;
	__u8	resv14[1006];
	struct nvmf_disc_rsp_page_entry entries[0];
};

#define NVME_VS(major, minor) (((major) << 16) | ((minor) << 8))

void register_extension(struct plugin *plugin);

#include "argconfig.h"
int parse_and_open(int argc, char **argv, const char *desc,
	const struct argconfig_commandline_options *clo, void *cfg, size_t size);

extern const char *devicename;

int __id_ctrl(int argc, char **argv, struct command *cmd, struct plugin *plugin, void (*vs)(__u8 *vs));

#endif /* _NVME_H */
