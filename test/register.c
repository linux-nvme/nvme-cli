// SPDX-License-Identifier: LGPL-2.1-or-later
/**
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 */

/**
 * Prints the values of the nvme register map. Use the nvme controller resource
 * for your pci device found in /sys/class/nvme/nvmeX/device/resource0
 */

#define __SANE_USERSPACE_TYPES__

#include <fcntl.h>
#include <inttypes.h>
#include <libnvme.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#include <sys/mman.h>

#include <ccan/endian/endian.h>

static inline uint32_t nvme_mmio_read32(volatile void *addr)
{
        uint32_t *p = (__le32 *)addr;

        return le32_to_cpu(*p);
}

static inline uint64_t nvme_mmio_read64(volatile void *addr)
{
        volatile __u32 *p = (__u32 *)addr;
        uint32_t low, high;

        low = nvme_mmio_read32(p);
        high = nvme_mmio_read32(p + 1);

        return low + ((uint64_t)high << 32);
}

void nvme_print_registers(void *regs)
{
	__u64 cap	= nvme_mmio_read64(regs + NVME_REG_CAP);
	__u32 vs	= nvme_mmio_read32(regs + NVME_REG_VS);
	__u32 intms	= nvme_mmio_read32(regs + NVME_REG_INTMS);
	__u32 intmc	= nvme_mmio_read32(regs + NVME_REG_INTMC);
	__u32 cc	= nvme_mmio_read32(regs + NVME_REG_CC);
	__u32 csts	= nvme_mmio_read32(regs + NVME_REG_CSTS);
	__u32 nssr	= nvme_mmio_read32(regs + NVME_REG_NSSR);
	__u32 aqa	= nvme_mmio_read32(regs + NVME_REG_AQA);
	__u64 asq	= nvme_mmio_read64(regs + NVME_REG_ASQ);
	__u64 acq	= nvme_mmio_read64(regs + NVME_REG_ACQ);
	__u32 cmbloc	= nvme_mmio_read32(regs + NVME_REG_CMBLOC);
	__u32 cmbsz	= nvme_mmio_read32(regs + NVME_REG_CMBSZ);
	__u32 bpinfo	= nvme_mmio_read32(regs + NVME_REG_BPINFO);
	__u32 bprsel	= nvme_mmio_read32(regs + NVME_REG_BPRSEL);
	__u64 bpmbl	= nvme_mmio_read64(regs + NVME_REG_BPMBL);
	__u64 cmbmsc	= nvme_mmio_read64(regs + NVME_REG_CMBMSC);
	__u32 cmbsts	= nvme_mmio_read32(regs + NVME_REG_CMBSTS);
	__u32 pmrcap	= nvme_mmio_read32(regs + NVME_REG_PMRCAP);
	__u32 pmrctl	= nvme_mmio_read32(regs + NVME_REG_PMRCTL);
	__u32 pmrsts	= nvme_mmio_read32(regs + NVME_REG_PMRSTS);
	__u32 pmrebs	= nvme_mmio_read32(regs + NVME_REG_PMREBS);
	__u32 pmrswtp	= nvme_mmio_read32(regs + NVME_REG_PMRSWTP);
	__u64 pmrmsc	= nvme_mmio_read32(regs + NVME_REG_PMRMSCL) |
		   (__u64)nvme_mmio_read64(regs + NVME_REG_PMRMSCU) << 32;

	printf("%-10s : %llx\n", "CAP", cap);
	printf("  %-8s : %llx\n", "MQES", NVME_CAP_MQES(cap));
	printf("  %-8s : %llx\n", "CQRS", NVME_CAP_CQR(cap));
	printf("  %-8s : %llx\n", "AMS", NVME_CAP_AMS(cap));
	printf("  %-8s : %llx\n", "TO", NVME_CAP_TO(cap));
	printf("  %-8s : %llx\n", "DSTRD", NVME_CAP_DSTRD(cap));
	printf("  %-8s : %llx\n", "NSSRC", NVME_CAP_NSSRC(cap));
	printf("  %-8s : %llx\n", "CSS", NVME_CAP_CSS(cap));
	printf("  %-8s : %llx\n", "BPS", NVME_CAP_BPS(cap));
	printf("  %-8s : %llx\n", "MPSMIN", NVME_CAP_MPSMIN(cap));
	printf("  %-8s : %llx\n", "MPSMAX", NVME_CAP_MPSMAX(cap));
	printf("  %-8s : %llx\n", "CMBS", NVME_CAP_CMBS(cap));
	printf("  %-8s : %llx\n", "PMRS", NVME_CAP_PMRS(cap));

	printf("%-10s : %x\n", "VS", vs);
	printf("  %-8s : %x\n", "MJR", NVME_VS_TER(vs));
	printf("  %-8s : %x\n", "MNR", NVME_VS_MNR(vs));
	printf("  %-8s : %x\n", "TER", NVME_VS_MJR(vs));

	printf("%-10s : %x\n", "INTMS", intms);
	printf("%-10s : %x\n", "INTMC", intmc);

	printf("%-10s : %x\n", "CC", cc);
	printf("  %-8s : %x\n", "EN", NVME_CC_EN(cc));
	printf("  %-8s : %x\n", "CSS", NVME_CC_CSS(cc));
	printf("  %-8s : %x\n", "MPS", NVME_CC_MPS(cc));
	printf("  %-8s : %x\n", "AMS", NVME_CC_AMS(cc));
	printf("  %-8s : %x\n", "SHN", NVME_CC_SHN(cc));
	printf("  %-8s : %x\n", "IOSQES", NVME_CC_IOSQES(cc));
	printf("  %-8s : %x\n", "IOCQES", NVME_CC_IOCQES(cc));

	printf("%-10s : %x\n", "CSTS", csts);
	printf("  %-8s : %x\n", "RDY", NVME_CSTS_RDY(csts));
	printf("  %-8s : %x\n", "CFS", NVME_CSTS_CFS(csts));
	printf("  %-8s : %x\n", "SHST", NVME_CSTS_SHST(csts));
	printf("  %-8s : %x\n", "NSSRO", NVME_CSTS_NSSRO(csts));
	printf("  %-8s : %x\n", "PP", NVME_CSTS_PP(csts));

	printf("%-10s : %x\n", "NSSR", nssr);

	printf("%-10s : %x\n", "AQA", aqa);
	printf("  %-8s : %x\n", "ASQS", NVME_AQA_ASQS(aqa));
	printf("  %-8s : %x\n", "ACQS", NVME_AQA_ACQS(aqa));

	printf("%-10s : %llx\n", "ASQ", asq);
	printf("%-10s : %llx\n", "ACQ", acq);

	printf("%-10s : %x\n",   "CMBLOC",  cmbloc);
	printf("  %-8s : %x\n", "BIR", NVME_CMBLOC_BIR(cmbloc));
	printf("  %-8s : %x\n", "CQMMS", NVME_CMBLOC_CQMMS(cmbloc));
	printf("  %-8s : %x\n", "CQPDS", NVME_CMBLOC_CQPDS(cmbloc));
	printf("  %-8s : %x\n", "CDPLMS", NVME_CMBLOC_CDPLMS(cmbloc));
	printf("  %-8s : %x\n", "CDPCILS", NVME_CMBLOC_CDPCILS(cmbloc));
	printf("  %-8s : %x\n", "CDMMMS", NVME_CMBLOC_CDMMMS(cmbloc));
	printf("  %-8s : %x\n", "CQDA", NVME_CMBLOC_CQDA(cmbloc));
	printf("  %-8s : %x\n", "OFST", NVME_CMBLOC_OFST(cmbloc));

	printf("%-10s : %x\n", "CMBSZ", cmbsz);
	printf("  %-8s : %x\n", "SQS", NVME_CMBSZ_SQS(cmbsz));
	printf("  %-8s : %x\n", "CQS", NVME_CMBSZ_CQS(cmbsz));
	printf("  %-8s : %x\n", "LISTS", NVME_CMBSZ_LISTS(cmbsz));
	printf("  %-8s : %x\n", "RDS", NVME_CMBSZ_RDS(cmbsz));
	printf("  %-8s : %x\n", "WDS", NVME_CMBSZ_WDS(cmbsz));
	printf("  %-8s : %x\n", "SZU", NVME_CMBSZ_SZU(cmbsz));
	printf("  %-8s : %x\n", "SZ", NVME_CMBSZ_SZ(cmbsz));
	printf("  %-8s : %llx\n", "bytes", nvme_cmb_size(cmbsz));

	printf("%-10s : %x\n", "BPINFO", bpinfo);
	printf("  %-8s : %x\n", "BPSZ", NVME_BPINFO_BPSZ(bpinfo));
	printf("  %-8s : %x\n", "BRS", NVME_BPINFO_BRS(bpinfo));
	printf("  %-8s : %x\n", "ABPID", NVME_BPINFO_ABPID(bpinfo));

	printf("%-10s : %x\n", "BPRSEL", bprsel);
	printf("  %-8s : %x\n", "BPRSZ", NVME_BPRSEL_BPRSZ(bprsel));
	printf("  %-8s : %x\n", "BPROF", NVME_BPRSEL_BPROF(bprsel));
	printf("  %-8s : %x\n", "BPID", NVME_BPRSEL_BPID(bprsel));

	printf("%-10s : %llx\n", "BPMBL", bpmbl);

	printf("%-10s : %llx\n", "CMBMSC", cmbmsc);
	printf("  %-8s : %llx\n", "CRE", NVME_CMBMSC_CRE(cmbmsc));
	printf("  %-8s : %llx\n", "CMSE", NVME_CMBMSC_CMSE(cmbmsc));
	printf("  %-8s : %llx\n", "CBA", NVME_CMBMSC_CBA(cmbmsc));

	printf("%-10s : %x\n", "CMBSTS", cmbsts);
	printf("  %-8s : %x\n", "CBAI", NVME_CMBSTS_CBAI(cmbsts));

	printf("%-10s : %x\n", "PMRCAP", pmrcap);
	printf("  %-8s : %x\n", "RDS", NVME_PMRCAP_RDS(pmrcap));
	printf("  %-8s : %x\n", "WDS", NVME_PMRCAP_WDS(pmrcap));
	printf("  %-8s : %x\n", "BIR", NVME_PMRCAP_BIR(pmrcap));
	printf("  %-8s : %x\n", "PMRTU", NVME_PMRCAP_PMRTU(pmrcap));
	printf("  %-8s : %x\n", "PMRWMB", NVME_PMRCAP_PMRWMB(pmrcap));
	printf("  %-8s : %x\n", "PMRTO", NVME_PMRCAP_PMRTO(pmrcap));
	printf("  %-8s : %x\n", "CMSS", NVME_PMRCAP_CMSS(pmrcap));

	printf("%-10s : %x\n", "PMRCTL", pmrctl);
	printf("  %-8s : %x\n", "EN", NVME_PMRCTL_EN(pmrctl));

	printf("%-10s : %x\n", "PMRSTS", pmrsts);
	printf("  %-8s : %x\n", "ERR", NVME_PMRSTS_ERR(pmrsts));
	printf("  %-8s : %x\n", "NRDY", NVME_PMRSTS_NRDY(pmrsts));
	printf("  %-8s : %x\n", "HSTS", NVME_PMRSTS_HSTS(pmrsts));
	printf("  %-8s : %x\n", "CBAI", NVME_PMRSTS_CBAI(pmrsts));

	printf("%-10s : %x\n", "PMREBS", pmrebs);
	printf("  %-8s : %x\n", "PMRSZU", NVME_PMREBS_PMRSZU(pmrebs));
	printf("  %-8s : %x\n", "RBB", NVME_PMREBS_RBB(pmrebs));
	printf("  %-8s : %x\n", "PMRWBZ", NVME_PMREBS_PMRWBZ(pmrebs));
	printf("  %-8s : %llx\n", "bytes", nvme_pmr_size(pmrebs));

	printf("%-10s : %x\n", "PMRSWTP", pmrswtp);
	printf("  %-8s : %x\n", "PMRSWTU", NVME_PMRSWTP_PMRSWTU(pmrswtp));
	printf("  %-8s : %x\n", "PMRSWTV", NVME_PMRSWTP_PMRSWTV(pmrswtp));
	printf("  %-8s : %llx\n", "tput", nvme_pmr_throughput(pmrswtp));

	printf("%-10s : %llx\n", "PMRMSC", pmrmsc);
	printf("  %-8s : %llx\n", "CMSE", NVME_PMRMSC_CMSE(pmrmsc));
	printf("  %-8s : %llx\n", "CBA", NVME_PMRMSC_CBA(pmrmsc));
}

int main(int argc, char **argv)
{
	int ret, fd;
	char *path;
	void *regs;

	if (argc != 2) {
		fprintf(stderr, "%s nvme<X>\n", argv[0]);
		return 1;
	}

	ret = asprintf(&path, "/sys/class/nvme/%s/device/resource0", argv[1]);
	if (ret < 0)
		return 0;

	printf("open %s\n", path);
	fd = open(path, O_RDONLY | O_SYNC);
	if (fd < 0) {
		fprintf(stderr, "failed to open %s\n", path);
		free(path);
		return 1;
	}

	regs = mmap(NULL, getpagesize(), PROT_READ, MAP_SHARED, fd, 0);
	if (regs == MAP_FAILED) {
		fprintf(stderr, "failed to map device BAR\n");
		fprintf(stderr, "did your kernel enable CONFIG_IO_STRICT_DEVMEM?\n");
		free(path);
		close(fd);
		return 1;
	}

	nvme_print_registers(regs);
	munmap(regs, getpagesize());
	free(path);
	close(fd);

	return 0;
}

