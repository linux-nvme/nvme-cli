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
	__u16	command_id;
	__u32	nsid;
	__u64	rsvd[2];
	__u64	prp1;
	__u64	prp2;
	__u32	chnl_off;
	__u32	rsvd11[5];
};

struct nvme_nvm_setbbtbl {
	__u8	opcode;
	__u8	flags;
	__u16	rsvd1;
	__u32	nsid;
	__u32	cdw2;
	__u32	cdw3;
	__u64	metadata;
	__u64	addr;
	__u32	metadata_len;
	__u32	data_len;
	__u64	ppa;
	__u16	nlb;
	__u8	value;
	__u8	rsvd2;
	__u32	cdw14;
	__u32	cdw15;
	__u32	timeout_ms;
	__u32	result;
};

struct nvme_nvm_getbbtbl {
	__u8	opcode;
	__u8	flags;
	__u16	rsvd1;
	__u32	nsid;
	__u32	cdw2;
	__u32	cdw3;
	__u64	metadata;
	__u64	addr;
	__u32	metadata_len;
	__u32	data_len;
	__u64	ppa;
	__u32	cdw11;
	__u32	cdw12;
	__u32	cdw13;
	__u32	cdw14;
	__u32	cdw15;
	__u32	timeout_ms;
	__u32	result;
};

struct nvme_nvm_command {
	union {
		struct nvme_nvm_identity identity;
		struct nvme_nvm_getbbtbl get_bb;
	};
};

struct nvme_nvm_completion {
	__u64	result;		/* Used by LightNVM to return ppa completions */
	__u16	sq_head;	/* how much of this queue may be reclaimed */
	__u16	sq_id;		/* submission queue that generated this entry */
	__u16	command_id;	/* of the command which completed */
	__u16	status;		/* did the command fail, and if so, why? */
};

#define NVME_NVM_LP_MLC_PAIRS 886
struct nvme_nvm_lp_mlc {
	__u16			num_pairs;
	__u8			pairs[NVME_NVM_LP_MLC_PAIRS];
};

struct nvme_nvm_lp_tbl {
	__u8			id[8];
	struct nvme_nvm_lp_mlc	mlc;
};

struct nvme_nvm_id_group {
	__u8			mtype;
	__u8			fmtype;
	__u16			res16;
	__u8			num_ch;
	__u8			num_lun;
	__u8			num_pln;
	__u8			rsvd1;
	__u16			num_blk;
	__u16			num_pg;
	__u16			fpg_sz;
	__u16			csecs;
	__u16			sos;
	__u16			rsvd2;
	__u32			trdt;
	__u32			trdm;
	__u32			tprt;
	__u32			tprm;
	__u32			tbet;
	__u32			tbem;
	__u32			mpos;
	__u32			mccap;
	__u16			cpar;
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
	__u32			cap;
	__u32			dom;
	struct nvme_nvm_addr_format ppaf;
	__u8			resv[228];
	struct nvme_nvm_id_group groups[4];
} __attribute__((packed));

struct nvme_nvm_bb_tbl {
	__u8	tblid[4];
	__u16	verid;
	__u16	revid;
	__u32	rvsd1;
	__u32	tblks;
	__u32	tfact;
	__u32	tgrown;
	__u32	tdresv;
	__u32	thresv;
	__u32	rsvd2[8];
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
