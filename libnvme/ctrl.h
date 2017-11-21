/*
 * Copyright (C) 2017 Red Hat, Inc.
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; If not, see <http://www.gnu.org/licenses/>.
 *
 * Author: Gris Ge <fge@redhat.com>
 */

#ifndef _NVME_CTRL_H_
#define _NVME_CTRL_H_

#include <stdint.h>

#include <libnvme/libnvme.h>

#pragma pack(push, 1)
struct _nvme_spec_psd {
	uint8_t mp[2];
	uint8_t reserved_0;
	uint8_t _bit_field_0;		/* mxps:1, nops:1, reserve:6 */
	uint8_t enlat[4];
	uint8_t exlat[4];
	uint8_t _bit_field_1;		/* rrt:5, reserve:3 */
	uint8_t _bit_field_2;		/* rrl:5, reserved:3 */
	uint8_t _bit_field_3;		/* rwt:5, reserved:3 */
	uint8_t _bit_field_4;		/* rwl:5, reserved:3 */
	uint8_t idlp[2];
	uint8_t _bit_field_5;		/* reserved:6, ips:2 */
	uint8_t reserved_7;
	uint8_t actp[2];
	uint8_t _bit_field_6;		/* apw:3, reserved:3, aps:2 */
	uint8_t reserved_9[9];
};

struct _nvme_spec_fabric_id_ctrl_data {
	uint8_t ioccsz[4];
	uint8_t iorcsz[4];
};

struct _nvme_spec_id_ctrl_data {
	uint8_t vid[2];
	uint8_t ssvid[2];
	uint8_t sn[20];
	uint8_t mn[40];
	uint8_t fr[8];
	uint8_t rab;
	uint8_t ieee[3];
	uint8_t cmic;
	uint8_t mdts;
	uint8_t cntlid[2];
	uint8_t ver[4];
	uint8_t rtd3r[4];
	uint8_t rtd3e[4];
	uint8_t oaes[4];
	uint8_t ctratt[4];
	uint8_t reserved_0[12];
	uint8_t fguid[16];
	uint8_t reserved_1[112];
	uint8_t ressered_mi[16];
	uint8_t oacs[2];
	uint8_t acl;
	uint8_t aerl;
	uint8_t frmw;
	uint8_t lpa;
	uint8_t elpe;
	uint8_t npss;
	uint8_t avscc;
	uint8_t apsta;
	uint8_t wctemp[2];
	uint8_t cctemp[2];
	uint8_t mtfa[2];
	uint8_t hmpre[4];
	uint8_t hmmin[4];
	uint8_t tnvmcap[16];
	uint8_t unvmcap[16];
	uint8_t rpmbs[4];
	uint8_t edstt[2];
	uint8_t esto;
	uint8_t fwug;
	uint8_t kas[2];
	uint8_t hctma[2];
	uint8_t mntmt[2];
	uint8_t mxtmt[2];
	uint8_t sanicap[4];
	uint8_t reserved_2[180];
	uint8_t sqes;
	uint8_t cqes;
	uint8_t maxcmd[2];
	uint8_t nn[4];
	uint8_t oncs[2];
	uint8_t fuses[2];
	uint8_t fna;
	uint8_t vwc;
	uint8_t awun[2];
	uint8_t awupf[2];
	uint8_t nvscc;
	uint8_t reserved_3;
	uint8_t acwu[2];
	uint8_t reserved_4[2];
	uint8_t sgls[4];
	uint8_t reserved_5[228];
	uint8_t subnqn[256];
	uint8_t reserved_6[768];
	/* Below are for NVMe Fabric */
	uint8_t ioccsz[4];
	uint8_t iorcsz[4];
	uint8_t icdoff[2];
	uint8_t ctrattr;
	uint8_t msdbd;
	uint8_t reserved_nvme_fabric[244];
	/* Above are for NVMe Fabric */
	struct _nvme_spec_psd psds[32];
	uint8_t vendor_specific[1024];
};

struct _nvme_spec_ver {
	uint8_t ter;
	uint8_t mnr;
	uint16_t mjr;
};
#pragma pack(pop)

int _nvme_ctrl_get_by_fd(int fd, struct nvme_ctrl **cnt,
			 const char *dev_path, char *err_msg);

#endif	/* End of _NVME_CTRL_H_ */
