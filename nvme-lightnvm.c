/*
 * lightnvm.c -- LightNVM NVMe integration.
 *
 * Copyright (c) 2016, CNEX Labs.
 *
 * Written by Matias Bjoerling <matias@cnexlabs.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>

#include "nvme-lightnvm.h"
#include "nvme-print.h"
#include "nvme-ioctl.h"

static int lnvm_open(void)
{
	char dev[FILENAME_MAX] = NVM_CTRL_FILE;
	int fd;

	fd = open(dev, O_WRONLY);
	if (fd < 0) {
		printf("Failed to open LightNVM mgmt interface\n");
		perror(dev);
		return fd;
	}

	return fd;
}

static void lnvm_close(int fd)
{
	close(fd);
}

int lnvm_do_init(char *dev, char *mmtype)
{
	struct nvm_ioctl_dev_init init;
	int fd, ret;

	fd = lnvm_open();
	if (fd < 0)
		return fd;

	memset(&init, 0, sizeof(struct nvm_ioctl_dev_init));
	strncpy(init.dev, dev, DISK_NAME_LEN);
	strncpy(init.mmtype, mmtype, NVM_MMTYPE_LEN);

	ret = ioctl(fd, NVM_DEV_INIT, &init);
	switch (errno) {
	case EINVAL:
		printf("Initialization failed.\n");
		break;
	case EEXIST:
		printf("Device has already been initialized.\n");
		break;
	case 0:
		break;
	default:
		printf("Unknown error occurred (%d)\n", errno);
		break;
	}

	lnvm_close(fd);

	return ret;
}

int lnvm_do_list_devices(void)
{
	struct nvm_ioctl_get_devices devs;
	int fd, ret, i;

	fd = lnvm_open();
	if (fd < 0)
		return fd;

	ret = ioctl(fd, NVM_GET_DEVICES, &devs);
	if (ret)
		return ret;

	printf("Number of devices: %u\n", devs.nr_devices);
	printf("%-12s\t%-12s\tVersion\n", "Device", "Block manager");

	for (i = 0; i < devs.nr_devices && i < 31; i++) {
		struct nvm_ioctl_device_info *info = &devs.info[i];

		printf("%-12s\t%-12s\t(%u,%u,%u)\n", info->devname, info->bmname,
				info->bmversion[0], info->bmversion[1],
				info->bmversion[2]);
	}

	lnvm_close(fd);

	return 0;
}

int lnvm_do_info(void)
{
	struct nvm_ioctl_info c;
	int fd, ret, i;

	fd = lnvm_open();
	if (fd < 0)
		return fd;

	memset(&c, 0, sizeof(struct nvm_ioctl_info));
	ret = ioctl(fd, NVM_INFO, &c);
	if (ret)
		return ret;

	printf("LightNVM (%u,%u,%u). %u target type(s) registered.\n",
			c.version[0], c.version[1], c.version[2], c.tgtsize);
	printf("Type\tVersion\n");

	for (i = 0; i < c.tgtsize; i++) {
		struct nvm_ioctl_info_tgt *tgt = &c.tgts[i];

		printf("%s\t(%u,%u,%u)\n",
				tgt->tgtname, tgt->version[0], tgt->version[1],
				tgt->version[2]);
	}

	lnvm_close(fd);
	return 0;
}

int lnvm_do_create_tgt(char *devname, char *tgtname, char *tgttype,
						int lun_begin, int lun_end)
{
	struct nvm_ioctl_create c;
	int fd, ret;

	fd = lnvm_open();
	if (fd < 0)
		return fd;

	strncpy(c.dev, devname, DISK_NAME_LEN);
	strncpy(c.tgtname, tgtname, DISK_NAME_LEN);
	strncpy(c.tgttype, tgttype, NVM_TTYPE_NAME_MAX);
	c.flags = 0;
	c.conf.type = 0;
	c.conf.s.lun_begin = lun_begin;
	c.conf.s.lun_end = lun_end;

	ret = ioctl(fd, NVM_DEV_CREATE, &c);
	if (ret)
		fprintf(stderr, "Creation of target failed. Please see dmesg.\n");

	lnvm_close(fd);
	return ret;
}

int lnvm_do_remove_tgt(char *tgtname)
{
	struct nvm_ioctl_remove c;
	int fd, ret;

	fd = lnvm_open();
	if (fd < 0)
		return fd;

	strncpy(c.tgtname, tgtname, DISK_NAME_LEN);
	c.flags = 0;

	ret = ioctl(fd, NVM_DEV_REMOVE, &c);
	if (ret)
		fprintf(stderr, "Remove of target failed. Please see dmesg.\n");

	lnvm_close(fd);
	return ret;
}

int lnvm_do_factory_init(char *devname, int erase_only_marked,
						int clear_host_marks,
						int clear_bb_marks)
{
	struct nvm_ioctl_dev_factory fact;
	int fd, ret;

	fd = lnvm_open();
	if (fd < 0)
		return fd;

	memset(&fact, 0, sizeof(struct nvm_ioctl_dev_factory));

	strncpy(fact.dev, devname, DISK_NAME_LEN);
	if (erase_only_marked)
		fact.flags |= NVM_FACTORY_ERASE_ONLY_USER;
	if (clear_host_marks)
		fact.flags |= NVM_FACTORY_RESET_HOST_BLKS;
	if (clear_bb_marks)
		fact.flags |= NVM_FACTORY_RESET_GRWN_BBLKS;

	ret = ioctl(fd, NVM_DEV_FACTORY, &fact);
	switch (errno) {
	case EINVAL:
		fprintf(stderr, "Factory reset failed.\n");
		break;
	case 0:
		break;
	default:
		fprintf(stderr, "Unknown error occurred (%d)\n", errno);
		break;
	}

	lnvm_close(fd);
	return ret;
}

static void show_lnvm_id_grp(struct nvme_nvm_id_group *grp)
{
	printf(" mtype   : %d\n", grp->mtype);
	printf(" fmtype  : %d\n", grp->fmtype);
	printf(" chnls   : %d\n", grp->num_ch);
	printf(" luns    : %d\n", grp->num_lun);
	printf(" plns    : %d\n", grp->num_pln);
	printf(" blks    : %d\n", (uint16_t)le16_to_cpu(grp->num_blk));
	printf(" pgs     : %d\n", (uint16_t)le16_to_cpu(grp->num_pg));
	printf(" fpg_sz  : %d\n", (uint16_t)le16_to_cpu(grp->fpg_sz));
	printf(" csecs   : %d\n", (uint16_t)le16_to_cpu(grp->csecs));
	printf(" sos     : %d\n", (uint16_t)le16_to_cpu(grp->sos));
	printf(" trdt    : %d\n", (uint32_t)le32_to_cpu(grp->trdt));
	printf(" trdm    : %d\n", (uint32_t)le32_to_cpu(grp->trdm));
	printf(" tprt    : %d\n", (uint32_t)le32_to_cpu(grp->tprt));
	printf(" tprm    : %d\n", (uint32_t)le32_to_cpu(grp->tprm));
	printf(" tbet    : %d\n", (uint32_t)le32_to_cpu(grp->tbet));
	printf(" tbem    : %d\n", (uint32_t)le32_to_cpu(grp->tbem));
	printf(" mpos    : %#x\n", (uint32_t)le32_to_cpu(grp->mpos));
	printf(" mccap   : %#x\n", (uint32_t)le32_to_cpu(grp->mccap));
	printf(" cpar    : %#x\n", (uint16_t)le16_to_cpu(grp->cpar));
}

static void show_lnvm_ppaf(struct nvme_nvm_addr_format *ppaf)
{
	printf("ppaf     :\n");
	printf(" ch offs : %d ch bits  : %d\n",
					ppaf->ch_offset, ppaf->ch_len);
	printf(" lun offs: %d lun bits : %d\n",
					ppaf->lun_offset, ppaf->lun_len);
	printf(" pl offs : %d pl bits  : %d\n",
					ppaf->pln_offset, ppaf->pln_len);
	printf(" blk offs: %d blk bits : %d\n",
					ppaf->blk_offset, ppaf->blk_len);
	printf(" pg offs : %d pg bits  : %d\n",
					ppaf->pg_offset, ppaf->pg_len);
	printf(" sec offs: %d sec bits : %d\n",
					ppaf->sect_offset, ppaf->sect_len);
}

static void show_lnvm_id_ns(struct nvme_nvm_id *id)
{
	int i;

	if (id->cgrps > 4) {
		fprintf(stderr, "invalid identify geometry returned\n");
		return;
	}

	printf("verid    : %#x\n", id->ver_id);
	printf("vmnt     : %#x\n", id->vmnt);
	printf("cgrps    : %d\n", id->cgrps);
	printf("cap      : %#x\n", (uint32_t)le32_to_cpu(id->cap));
	printf("dom      : %#x\n", (uint32_t)le32_to_cpu(id->dom));
	show_lnvm_ppaf(&id->ppaf);

	for (i = 0; i < id->cgrps; i++) {
		printf("grp      : %d\n", i);
		show_lnvm_id_grp(&id->groups[i]);
	}
}

static int lnvm_get_identity(int fd, int nsid, struct nvme_nvm_id *nvm_id)
{
	struct nvme_admin_cmd cmd = {
		.opcode		= nvme_nvm_admin_identity,
		.nsid		= nsid,
		.addr		= (__u64)(uintptr_t)nvm_id,
		.data_len	= 0x1000,
	};

	return nvme_submit_passthru(fd, NVME_IOCTL_ADMIN_CMD, &cmd);
}

int lnvm_do_id_ns(int fd, int nsid, unsigned int flags)
{
	struct nvme_nvm_id nvm_id;
	int err;

	err = lnvm_get_identity(fd, nsid, &nvm_id);
	if (!err) {
		if (flags & RAW)
			d_raw((unsigned char *)&nvm_id, sizeof(nvm_id));
		else {
			printf("LightNVM Identify Geometry (%d):\n", nsid);
			show_lnvm_id_ns(&nvm_id);
		}
	}
	else if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x) NSID:%d\n",
			nvme_status_to_string(err), err, nsid);
	return err;
}

static void show_lnvm_bbtbl(struct nvme_nvm_bb_tbl *tbl)
{
	printf("verid    : %#x\n", (uint16_t)le16_to_cpu(tbl->verid));
	printf("tblks    : %d\n", (uint32_t)le32_to_cpu(tbl->tblks));
	printf("tfact    : %d\n", (uint32_t)le32_to_cpu(tbl->tfact));
	printf("tgrown   : %d\n", (uint32_t)le32_to_cpu(tbl->tgrown));
	printf("tdresv   : %d\n", (uint32_t)le32_to_cpu(tbl->tdresv));
	printf("thresv   : %d\n", (uint32_t)le32_to_cpu(tbl->thresv));
	printf("Use raw output to retrieve table.\n");
}

static int __lnvm_do_get_bbtbl(int fd, struct nvme_nvm_id *id,
						struct ppa_addr ppa,
						unsigned int flags)
{
	struct nvme_nvm_id_group *grp = &id->groups[0];
	int bbtblsz = ((uint16_t)le16_to_cpu(grp->num_blk) * grp->num_pln);
	int bufsz = bbtblsz + sizeof(struct nvme_nvm_bb_tbl);
	struct nvme_nvm_bb_tbl *bbtbl;
	int err;

	bbtbl = calloc(1, bufsz);
	if (!bbtbl)
		return -ENOMEM;

	struct nvme_nvm_getbbtbl cmd = {
		.opcode		= nvme_nvm_admin_get_bb_tbl,
		.nsid		= cpu_to_le32(1),
		.addr		= (__u64)(uintptr_t)bbtbl,
		.data_len	= cpu_to_le32(bufsz),
		.ppa		= cpu_to_le64(ppa.ppa),
	};

	err = nvme_submit_passthru(fd, NVME_IOCTL_ADMIN_CMD,
					(struct nvme_passthru_cmd *)&cmd);
	if (err > 0) {
		fprintf(stderr, "NVMe Status:%s(%x)\n",
			nvme_status_to_string(err), err);
		free(bbtbl);
		return err;
	}

	if (flags & RAW)
		d_raw((unsigned char *)&bbtbl->blk, bbtblsz);
	else {
		printf("LightNVM Bad Block Stats:\n");
		show_lnvm_bbtbl(bbtbl);
	}

	free(bbtbl);
	return 0;
}

int lnvm_do_get_bbtbl(int fd, int nsid, int lunid, int chid, unsigned int flags)
{
	struct nvme_nvm_id nvm_id;
	struct ppa_addr ppa;
	int err;

	err = lnvm_get_identity(fd, nsid, &nvm_id);
	if (err) {
		fprintf(stderr, "NVMe Status:%s(%x)\n",
			nvme_status_to_string(err), err);
		return err;
	}

	if (chid >= nvm_id.groups[0].num_ch ||
					lunid >= nvm_id.groups[0].num_lun) {
		fprintf(stderr, "Out of bound channel id or LUN id\n");
		return -EINVAL;
	}

	ppa.ppa = 0;
	ppa.g.lun = lunid;
	ppa.g.ch = chid;

	ppa = generic_to_dev_addr(&nvm_id.ppaf, ppa);

	return __lnvm_do_get_bbtbl(fd, &nvm_id, ppa, flags);
}

static int __lnvm_do_set_bbtbl(int fd, struct ppa_addr ppa, __u8 value)
{
	int err;

	struct nvme_nvm_setbbtbl cmd = {
		.opcode		= nvme_nvm_admin_set_bb_tbl,
		.nsid		= cpu_to_le32(1),
		.ppa		= cpu_to_le64(ppa.ppa),
		.nlb		= cpu_to_le16(0),
		.value		= value,
	};

	err = nvme_submit_passthru(fd, NVME_IOCTL_ADMIN_CMD,
					(struct nvme_passthru_cmd *)&cmd);
	if (err > 0) {
		fprintf(stderr, "NVMe Status:%s(%x)\n",
			nvme_status_to_string(err), err);
		return err;
	}
	return 0;
}

int lnvm_do_set_bbtbl(int fd, int nsid,
				int chid, int lunid, int plnid, int blkid,
				__u8 value)
{
	struct nvme_nvm_id nvm_id;
	struct ppa_addr ppa;
	int err;

	err = lnvm_get_identity(fd, nsid, &nvm_id);
	if (err) {
		fprintf(stderr, "NVMe Status:%s(%x)\n",
			nvme_status_to_string(err), err);
		return err;
	}

	if (chid >= nvm_id.groups[0].num_ch ||
					lunid >= nvm_id.groups[0].num_lun ||
					plnid >= nvm_id.groups[0].num_pln ||
					blkid >= le16_to_cpu(nvm_id.groups[0].num_blk)) {
		fprintf(stderr, "Out of bound channel id, LUN id, plane id, or"\
				"block id\n");
		return -EINVAL;
	}

	ppa.ppa = 0;
	ppa.g.lun = lunid;
	ppa.g.ch = chid;
	ppa.g.pl = plnid;
	ppa.g.blk = blkid;

	ppa = generic_to_dev_addr(&nvm_id.ppaf, ppa);

	return __lnvm_do_set_bbtbl(fd, ppa, value);
}
