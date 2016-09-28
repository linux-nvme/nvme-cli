/*
 * Copyright (C) 2016 CNEX Labs.  All rights reserved.
 *
 * Author: Matias Bjoerling <matias@cnexlabs.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.  If not, write to
 * the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139,
 * USA.
 */

#ifndef NVME_LIGHTNVM_H_
#define NVME_LIGHTNVM_H_

#include "linux/lightnvm.h"

enum nvme_nvm_admin_opcode {
	nvme_nvm_admin_identity		= 0xe2,
	nvme_nvm_admin_get_bb_tbl	= 0xf2,
	nvme_nvm_admin_set_bb_tbl	= 0xf1,
};

struct nvme_nvm_identity {
	__u8	opcode;
	__u8	flags;
	__le16	command_id;
	__le32	nsid;
	__le64	rsvd[2];
	__le64	prp1;
	__le64	prp2;
	__le32	chnl_off;
	__le32	rsvd11[5];
};

struct nvme_nvm_setbbtbl {
	__u8	opcode;
	__u8	flags;
	__le16	rsvd1;
	__le32	nsid;
	__le32	cdw2;
	__le32	cdw3;
	__le64	metadata;
	__u64	addr;
	__le32	metadata_len;
	__le32	data_len;
	__le64	ppa;
	__le16	nlb;
	__u8	value;
	__u8	rsvd2;
	__le32	cdw14;
	__le32	cdw15;
	__le32	timeout_ms;
	__le32	result;
};

struct nvme_nvm_getbbtbl {
	__u8	opcode;
	__u8	flags;
	__le16	rsvd1;
	__le32	nsid;
	__le32	cdw2;
	__le32	cdw3;
	__le64	metadata;
	__u64	addr;
	__le32	metadata_len;
	__le32	data_len;
	__le64	ppa;
	__le32	cdw11;
	__le32	cdw12;
	__le32	cdw13;
	__le32	cdw14;
	__le32	cdw15;
	__le32	timeout_ms;
	__le32	result;
};

struct nvme_nvm_command {
	union {
		struct nvme_nvm_identity identity;
		struct nvme_nvm_getbbtbl get_bb;
	};
};

struct nvme_nvm_completion {
	__le64	result;		/* Used by LightNVM to return ppa completions */
	__le16	sq_head;	/* how much of this queue may be reclaimed */
	__le16	sq_id;		/* submission queue that generated this entry */
	__le16	command_id;	/* of the command which completed */
	__le16	status;		/* did the command fail, and if so, why? */
};

#define NVME_NVM_LP_MLC_PAIRS 886
struct nvme_nvm_lp_mlc {
	__le16			num_pairs;
	__u8			pairs[NVME_NVM_LP_MLC_PAIRS];
};

struct nvme_nvm_lp_tbl {
	__u8			id[8];
	struct nvme_nvm_lp_mlc	mlc;
};

struct nvme_nvm_id_group {
	__u8			mtype;
	__u8			fmtype;
	__le16			res16;
	__u8			num_ch;
	__u8			num_lun;
	__u8			num_pln;
	__u8			rsvd1;
	__le16			num_blk;
	__le16			num_pg;
	__le16			fpg_sz;
	__le16			csecs;
	__le16			sos;
	__le16			rsvd2;
	__le32			trdt;
	__le32			trdm;
	__le32			tprt;
	__le32			tprm;
	__le32			tbet;
	__le32			tbem;
	__le32			mpos;
	__le32			mccap;
	__le16			cpar;
	__u8			reserved[10];
	struct nvme_nvm_lp_tbl lptbl;
} __attribute__((packed));

struct nvme_nvm_addr_format {
	__u8			ch_offset;
	__u8			ch_len;
	__u8			lun_offset;
	__u8			lun_len;
	__u8			pln_offset;
	__u8			pln_len;
	__u8			blk_offset;
	__u8			blk_len;
	__u8			pg_offset;
	__u8			pg_len;
	__u8			sect_offset;
	__u8			sect_len;
	__u8			res[4];
} __attribute__((packed));

struct nvme_nvm_id {
	__u8			ver_id;
	__u8			vmnt;
	__u8			cgrps;
	__u8			res;
	__le32			cap;
	__le32			dom;
	struct nvme_nvm_addr_format ppaf;
	__u8			resv[228];
	struct nvme_nvm_id_group groups[4];
} __attribute__((packed));

struct nvme_nvm_bb_tbl {
	__u8	tblid[4];
	__le16	verid;
	__le16	revid;
	__le32	rvsd1;
	__le32	tblks;
	__le32	tfact;
	__le32	tgrown;
	__le32	tdresv;
	__le32	thresv;
	__le32	rsvd2[8];
	__u8	blk[0];
};

#define NVM_BLK_BITS (16)
#define NVM_PG_BITS  (16)
#define NVM_SEC_BITS (8)
#define NVM_PL_BITS  (8)
#define NVM_LUN_BITS (8)
#define NVM_CH_BITS  (7)

struct ppa_addr {
	/* Generic structure for all addresses */
	union {
		struct {
			__u64 blk	: NVM_BLK_BITS;
			__u64 pg	: NVM_PG_BITS;
			__u64 sec	: NVM_SEC_BITS;
			__u64 pl	: NVM_PL_BITS;
			__u64 lun	: NVM_LUN_BITS;
			__u64 ch	: NVM_CH_BITS;
			__u64 reserved	: 1;
		} g;

		__u64 ppa;
	};
};

static inline struct ppa_addr generic_to_dev_addr(
			struct nvme_nvm_addr_format *ppaf, struct ppa_addr r)
{
	struct ppa_addr l;

	l.ppa = ((__u64)r.g.blk) << ppaf->blk_offset;
	l.ppa |= ((__u64)r.g.pg) << ppaf->pg_offset;
	l.ppa |= ((__u64)r.g.sec) << ppaf->sect_offset;
	l.ppa |= ((__u64)r.g.pl) << ppaf->pln_offset;
	l.ppa |= ((__u64)r.g.lun) << ppaf->lun_offset;
	l.ppa |= ((__u64)r.g.ch) << ppaf->ch_offset;

	return l;
}

int lnvm_do_init(char *, char *);
int lnvm_do_list_devices(void);
int lnvm_do_info(void);
int lnvm_do_create_tgt(char *, char *, char *, int, int);
int lnvm_do_remove_tgt(char *);
int lnvm_do_factory_init(char *, int, int, int);
int lnvm_do_id_ns(int, int, unsigned int);
int lnvm_do_get_bbtbl(int, int, int, int, unsigned int);
int lnvm_do_set_bbtbl(int, int, int, int, int, int, __u8);

#endif
