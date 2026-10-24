// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE LLC
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */
#include <stddef.h>
#include <stdlib.h>

#include <libnvme.h>

#include <ccan/array_size/array_size.h>
#include <shared/fs-util.h>

#include "nvme-regs.h"

/* A field FLD of the register REG, see the NVME_<REG>_<FLD>_* of libnvme */
#define F(name, reg, fld, fmt)						\
	BITFIELD(name, NVME_##reg##_##fld##_SHIFT,			\
		 NVME_##reg##_##fld##_MASK, fmt)
#define F_POW2(name, reg, fld, exp)					\
	BITFIELD_POW2(name, NVME_##reg##_##fld##_SHIFT,			\
		      NVME_##reg##_##fld##_MASK, exp)
#define F_STR(name, reg, fld, strs)					\
	BITFIELD_STR(name, NVME_##reg##_##fld##_SHIFT,			\
		     NVME_##reg##_##fld##_MASK, strs)
/* Bit BIT of the field FLD */
#define F_BIT(name, reg, fld, bit, fmt)					\
	BITFIELD(name, NVME_##reg##_##fld##_SHIFT + (bit), 1, fmt)

/*
 * The base addresses, bits 63:12 of their register. libnvme has their
 * masks as variables, which can't initialize a table.
 */
#define ADDR_MASK	UINT64_C(0xfffffffffffff)

static const char * const cps[] = {
	"Not Reported", "Controller scope", "Domain scope",
	"NVM subsystem scope",
};

static const struct bitfield cap[] = {
	F("NVM Subsystem Shutdown Enhancements Supported (NSSES)",
	  CAP, NSSES, BF_SUPPORTED),
	F_BIT("Controller Ready With Media Support (CRWMS)",
	      CAP, CRMS, 0, BF_SUPPORTED),
	F_BIT("Controller Ready Independent of Media Support (CRIMS)",
	      CAP, CRMS, 1, BF_SUPPORTED),
	F("NVM Subsystem Shutdown Supported (NSSS)", CAP, NSSS, BF_SUPPORTED),
	F("Controller Memory Buffer Supported (CMBS)", CAP, CMBS,
	  BF_SUPPORTED),
	F("Persistent Memory Region Supported (PMRS)", CAP, PMRS,
	  BF_SUPPORTED),
	F_POW2("Memory Page Size Maximum (MPSMAX)", CAP, MPSMAX, 12),
	F_POW2("Memory Page Size Minimum (MPSMIN)", CAP, MPSMIN, 12),
	F_STR("Controller Power Scope (CPS)", CAP, CPS, cps),
	F("Boot Partition Support (BPS)", CAP, BPS, BF_YESNO),
	F_BIT("NVM Command Set Supported (CSS.NCSS)", CAP, CSS, 0,
	      BF_YESNO),
	F_BIT("I/O Command Sets Supported (CSS.IOCSS)", CAP, CSS, 6,
	      BF_YESNO),
	F_BIT("No I/O Command Set Supported (CSS.NOIOCSS)", CAP, CSS, 7,
	      BF_YESNO),
	F("NVM Subsystem Reset Supported (NSSRS)", CAP, NSSRS, BF_YESNO),
	F_POW2("Doorbell Stride (DSTRD)", CAP, DSTRD, 2),
	F("Timeout (TO)", CAP, TO, BF_MS500),
	F_BIT("Weighted Round Robin with Urgent Priority Class (AMS.WRRUPC)",
	      CAP, AMS, 0, BF_SUPPORTED),
	F_BIT("Vendor Specific Arbitration (AMS.VS)", CAP, AMS, 1,
	      BF_SUPPORTED),
	F("Contiguous Queues Required (CQR)", CAP, CQR, BF_YESNO),
	F("Maximum Queue Entries Supported (MQES)", CAP, MQES, BF_DEC1),
};

static const struct bitfield vs[] = {
	F("Major Version Number (MJR)", VS, MJR, BF_DEC),
	F("Minor Version Number (MNR)", VS, MNR, BF_DEC),
	F("Tertiary Version Number (TER)", VS, TER, BF_DEC),
};

static const struct bitfield intms[] = {
	BITFIELD("Interrupt Vector Mask Set (IVMS)", 0, 0xffffffff, BF_HEX),
};

static const struct bitfield intmc[] = {
	BITFIELD("Interrupt Vector Mask Clear (IVMC)", 0, 0xffffffff,
		 BF_HEX),
};

static const char * const cc_shn[] = {
	"No notification; no effect", "Normal shutdown notification",
	"Abrupt shutdown notification",
};

static const char * const cc_ams[] = {
	[NVME_CC_AMS_RR] = "Round Robin",
	[NVME_CC_AMS_WRRU] = "Weighted Round Robin with Urgent Priority Class",
	[NVME_CC_AMS_VS] = "Vendor Specific",
};

static const char * const cc_css[] = {
	[NVME_CC_CSS_NVM] = "NVM Command Set",
	[NVME_CC_CSS_CSI] = "All supported I/O Command Sets",
	[NVME_CC_CSS_ADMIN] = "Admin Command Set only",
};

static const struct bitfield cc[] = {
	F("Controller Ready Independent of Media Enable (CRIME)", CC, CRIME,
	  BF_ENABLED),
	F_POW2("I/O Completion Queue Entry Size (IOCQES)", CC, IOCQES, 0),
	F_POW2("I/O Submission Queue Entry Size (IOSQES)", CC, IOSQES, 0),
	F_STR("Shutdown Notification (SHN)", CC, SHN, cc_shn),
	F_STR("Arbitration Mechanism Selected (AMS)", CC, AMS, cc_ams),
	F_POW2("Memory Page Size (MPS)", CC, MPS, 12),
	F_STR("I/O Command Set Selected (CSS)", CC, CSS, cc_css),
	F("Enable (EN)", CC, EN, BF_YESNO),
};

static const char * const csts_st[] = { "Controller", "NVM Subsystem" };

static const char * const csts_shst[] = {
	"Normal operation (no shutdown has been requested)",
	"Shutdown processing occurring", "Shutdown processing complete",
};

static const struct bitfield csts[] = {
	F_STR("Shutdown Type (ST)", CSTS, ST, csts_st),
	F("Processing Paused (PP)", CSTS, PP, BF_YESNO),
	F("NVM Subsystem Reset Occurred (NSSRO)", CSTS, NSSRO, BF_YESNO),
	F_STR("Shutdown Status (SHST)", CSTS, SHST, csts_shst),
	F("Controller Fatal Status (CFS)", CSTS, CFS, BF_YESNO),
	F("Ready (RDY)", CSTS, RDY, BF_YESNO),
};

static const struct bitfield nssr[] = {
	BITFIELD("NVM Subsystem Reset Control (NSSRC)", 0, 0xffffffff,
		 BF_HEX),
};

static const struct bitfield aqa[] = {
	F("Admin Completion Queue Size (ACQS)", AQA, ACQS, BF_DEC1),
	F("Admin Submission Queue Size (ASQS)", AQA, ASQS, BF_DEC1),
};

static const struct bitfield asq[] = {
	BITFIELD("Admin Submission Queue Base (ASQB)", NVME_ASQ_ASQB_SHIFT,
		 ADDR_MASK, BF_ADDR),
};

static const struct bitfield acq[] = {
	BITFIELD("Admin Completion Queue Base (ACQB)", NVME_ACQ_ACQB_SHIFT,
		 ADDR_MASK, BF_ADDR),
};

static const char * const enforced[] = { "Enforced", "Not Enforced" };

static const struct bitfield cmbloc[] = {
	F("Offset (OFST)", CMBLOC, OFST, BF_HEX),
	F("CMB Queue Dword Alignment (CQDA)", CMBLOC, CQDA, BF_YESNO),
	F_STR("CMB Data Metadata Mixed Memory Support (CDMMMS)",
	      CMBLOC, CDMMMS, enforced),
	F_STR(
	      "CMB Data Pointer and Command Independent Locations Support (CDPCILS)",
	      CMBLOC, CDPCILS, enforced),
	F_STR("CMB Data Pointer Mixed Locations Support (CDPMLS)",
	      CMBLOC, CDPLMS, enforced),
	F_STR("CMB Queue Physically Discontiguous Support (CQPDS)",
	      CMBLOC, CQPDS, enforced),
	F_STR("CMB Queue Mixed Memory Support (CQMMS)", CMBLOC, CQMMS,
	      enforced),
	F("Base Indicator Register (BIR)", CMBLOC, BIR, BF_HEX),
};

static const char * const cmbsz_szu[] = {
	"4 KiB", "64 KiB", "1 MiB", "16 MiB", "256 MiB", "4 GiB", "64 GiB",
};

static const struct bitfield cmbsz[] = {
	F("Size (SZ)", CMBSZ, SZ, BF_DEC),
	F_STR("Size Units (SZU)", CMBSZ, SZU, cmbsz_szu),
	F("Write Data Support (WDS)", CMBSZ, WDS, BF_SUPPORTED),
	F("Read Data Support (RDS)", CMBSZ, RDS, BF_SUPPORTED),
	F("PRP SGL List Support (LISTS)", CMBSZ, LISTS, BF_SUPPORTED),
	F("Completion Queue Support (CQS)", CMBSZ, CQS, BF_SUPPORTED),
	F("Submission Queue Support (SQS)", CMBSZ, SQS, BF_SUPPORTED),
};

static const char * const bpinfo_brs[] = {
	"No Boot Partition read operation requested",
	"Boot Partition read in progress",
	"Boot Partition read completed successfully",
	"Error completing Boot Partition read",
};

static const struct bitfield bpinfo[] = {
	F("Active Boot Partition ID (ABPID)", BPINFO, ABPID, BF_DEC),
	F_STR("Boot Read Status (BRS)", BPINFO, BRS, bpinfo_brs),
	F("Boot Partition Size (BPSZ)", BPINFO, BPSZ, BF_DEC),
};

static const struct bitfield bprsel[] = {
	F("Boot Partition Identifier (BPID)", BPRSEL, BPID, BF_DEC),
	F("Boot Partition Read Offset (BPROF)", BPRSEL, BPROF, BF_HEX),
	F("Boot Partition Read Size (BPRSZ)", BPRSEL, BPRSZ, BF_HEX),
};

static const struct bitfield bpmbl[] = {
	BITFIELD("Boot Partition Memory Buffer Base Address (BMBBA)",
		 NVME_BPMBL_BMBBA_SHIFT, ADDR_MASK, BF_ADDR),
};

static const struct bitfield cmbmsc[] = {
	BITFIELD("Controller Base Address (CBA)", NVME_CMBMSC_CBA_SHIFT,
		 ADDR_MASK, BF_ADDR),
	F("Controller Memory Space Enable (CMSE)", CMBMSC, CMSE, BF_ENABLED),
	F("Capabilities Registers Enabled (CRE)", CMBMSC, CRE, BF_ENABLED),
};

static const struct bitfield cmbsts[] = {
	F("Controller Base Address Invalid (CBAI)", CMBSTS, CBAI, BF_YESNO),
};

static const char * const rbb[] = { "May bypass", "Shall bypass" };

static const char * const units[] = { "Bytes", "1 KiB", "1 MiB", "1 GiB" };

static const char * const units_per_sec[] = {
	"Bytes/second", "1 KiB/second", "1 MiB/second", "1 GiB/second",
};

static const struct bitfield cmbebs[] = {
	F("CMB Elasticity Buffer Size Base (CMBWBZ)", CMBEBS, CMBWBZ, BF_DEC),
	F_STR("CMB Read Bypass Behavior (CMBRBB)", CMBEBS, RBB, rbb),
	F_STR("CMB Elasticity Buffer Size Units (CMBSZU)", CMBEBS, CMBSZU,
	      units),
};

static const struct bitfield cmbswtp[] = {
	F("CMB Sustained Write Throughput (CMBSWTV)", CMBSWTP, CMBSWTV,
	  BF_DEC),
	F_STR("CMB Sustained Write Throughput Units (CMBSWTU)", CMBSWTP,
	      CMBSWTU, units_per_sec),
};

static const struct bitfield nssd[] = {
	BITFIELD("NVM Subsystem Shutdown Control (NSSC)", 0, 0xffffffff,
		 BF_HEX),
};

static const struct bitfield crto[] = {
	F("Controller Ready Independent of Media Timeout (CRIMT)", CRTO,
	  CRIMT, BF_MS500),
	F("Controller Ready With Media Timeout (CRWMT)", CRTO, CRWMT,
	  BF_MS500),
};

static const char * const pmrtu[] = { "500 milliseconds", "minutes" };

static const struct bitfield pmrcap[] = {
	F("Controller Memory Space Supported (CMSS)", PMRCAP, CMSS,
	  BF_SUPPORTED),
	F("Persistent Memory Region Timeout (PMRTO)", PMRCAP, PMRTO, BF_DEC),
	F("Persistent Memory Region Write Barrier Mechanisms (PMRWBM)",
	  PMRCAP, PMRWBM, BF_HEX),
	F_STR("Persistent Memory Region Time Units (PMRTU)", PMRCAP, PMRTU,
	      pmrtu),
	F("Base Indicator Register (BIR)", PMRCAP, BIR, BF_HEX),
	F("Write Data Support (WDS)", PMRCAP, WDS, BF_SUPPORTED),
	F("Read Data Support (RDS)", PMRCAP, RDS, BF_SUPPORTED),
};

static const struct bitfield pmrctl[] = {
	F("Enable (EN)", PMRCTL, EN, BF_ENABLED),
};

static const char * const pmrsts_hsts[] = {
	"Normal Operation", "Restore Error", "Read Only", "Unreliable",
};

static const struct bitfield pmrsts[] = {
	F("Controller Base Address Invalid (CBAI)", PMRSTS, CBAI, BF_YESNO),
	F_STR("Health Status (HSTS)", PMRSTS, HSTS, pmrsts_hsts),
	F("Not Ready (NRDY)", PMRSTS, NRDY, BF_YESNO),
	F("Error (ERR)", PMRSTS, ERR, BF_HEX),
};

static const struct bitfield pmrebs[] = {
	F("PMR Elasticity Buffer Size Base (PMRWBZ)", PMREBS, PMRWBZ,
	  BF_DEC),
	F_STR("PMR Read Bypass Behavior (PMRRBB)", PMREBS, RBB, rbb),
	F_STR("PMR Elasticity Buffer Size Units (PMRSZU)", PMREBS, PMRSZU,
	      units),
};

static const struct bitfield pmrswtp[] = {
	F("PMR Sustained Write Throughput (PMRSWTV)", PMRSWTP, PMRSWTV,
	  BF_DEC),
	F_STR("PMR Sustained Write Throughput Units (PMRSWTU)", PMRSWTP,
	      PMRSWTU, units_per_sec),
};

static const struct bitfield pmrmscl[] = {
	/* bits 31:12 of the address, the upper ones are in PMRMSCU */
	BITFIELD("Controller Base Address (CBA)", NVME_PMRMSC_CBA_SHIFT,
		 0xfffff, BF_ADDR),
	F("Controller Memory Space Enable (CMSE)", PMRMSC, CMSE, BF_ENABLED),
};

static const struct bitfield pmrmscu[] = {
	BITFIELD("Controller Base Address, upper 32 bits (CBA)", 0,
		 0xffffffff, BF_HEX),
};

#define REG(idx, _size, _flags, _sym, _name, _fields)			\
	[NVME_REGI_##idx] = {						\
		.offset = NVME_REG_##idx, .size = (_size),		\
		.flags = (_flags), .sym = (_sym), .name = (_name),	\
		.fields = (_fields), .nr_fields = ARRAY_SIZE(_fields),	\
	}

#define FAB	NVME_REGF_FABRICS
#define OPT	NVME_REGF_OPTIONAL
#define WR	NVME_REGF_WRITE

const struct nvme_reg nvme_regs[NVME_NR_REGS] = {
	REG(CAP, 8, FAB, "cap", "Controller Capabilities", cap),
	REG(VS, 4, FAB, "vs", "Version", vs),
	REG(INTMS, 4, WR, "intms", "Interrupt Vector Mask Set", intms),
	REG(INTMC, 4, WR, "intmc", "Interrupt Vector Mask Clear", intmc),
	REG(CC, 4, FAB | WR, "cc", "Controller Configuration", cc),
	REG(CSTS, 4, FAB | WR, "csts", "Controller Status", csts),
	REG(NSSR, 4, FAB | OPT | WR, "nssr", "NVM Subsystem Reset", nssr),
	REG(AQA, 4, WR, "aqa", "Admin Queue Attributes", aqa),
	REG(ASQ, 8, WR, "asq", "Admin Submission Queue Base Address", asq),
	REG(ACQ, 8, WR, "acq", "Admin Completion Queue Base Address", acq),
	REG(CMBLOC, 4, 0, "cmbloc", "Controller Memory Buffer Location",
	    cmbloc),
	REG(CMBSZ, 4, 0, "cmbsz", "Controller Memory Buffer Size", cmbsz),
	REG(BPINFO, 4, 0, "bpinfo", "Boot Partition Information", bpinfo),
	REG(BPRSEL, 4, WR, "bprsel", "Boot Partition Read Select", bprsel),
	REG(BPMBL, 8, WR, "bpmbl", "Boot Partition Memory Buffer Location",
	    bpmbl),
	REG(CMBMSC, 8, WR, "cmbmsc",
	    "Controller Memory Buffer Memory Space Control", cmbmsc),
	REG(CMBSTS, 4, 0, "cmbsts", "Controller Memory Buffer Status",
	    cmbsts),
	REG(CMBEBS, 4, 0, "cmbebs",
	    "Controller Memory Buffer Elasticity Buffer Size", cmbebs),
	REG(CMBSWTP, 4, 0, "cmbswtp",
	    "Controller Memory Buffer Sustained Write Throughput", cmbswtp),
	REG(NSSD, 4, FAB | OPT | WR, "nssd", "NVM Subsystem Shutdown", nssd),
	/* a Discovery Controller has none, nor one before NVMe 2.0 */
	REG(CRTO, 4, FAB | OPT, "crto", "Controller Ready Timeouts", crto),
	REG(PMRCAP, 4, 0, "pmrcap", "Persistent Memory Region Capabilities",
	    pmrcap),
	REG(PMRCTL, 4, WR, "pmrctl", "Persistent Memory Region Control",
	    pmrctl),
	REG(PMRSTS, 4, 0, "pmrsts", "Persistent Memory Region Status",
	    pmrsts),
	REG(PMREBS, 4, 0, "pmrebs",
	    "Persistent Memory Region Elasticity Buffer Size", pmrebs),
	REG(PMRSWTP, 4, 0, "pmrswtp",
	    "Persistent Memory Region Sustained Write Throughput", pmrswtp),
	REG(PMRMSCL, 4, WR, "pmrmscl",
	    "Persistent Memory Region Controller Memory Space Control Lower",
	    pmrmscl),
	REG(PMRMSCU, 4, WR, "pmrmscu",
	    "Persistent Memory Region Controller Memory Space Control Upper",
	    pmrmscu),
};

const struct nvme_reg *nvme_reg_by_offset(uint32_t offset)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(nvme_regs); i++)
		if (nvme_regs[i].offset == offset)
			return &nvme_regs[i];

	return NULL;
}

void *read_registers(struct libnvme_transport_handle *hdl)
{
	int size = shr_getpagesize();
	void *bar;

	bar = calloc(1, size);
	if (!bar)
		return NULL;

	if (libnvme_read_regs(hdl, NVME_REG_CAP, bar + NVME_REG_CAP,
			      NVME_REG_CRTO + sizeof(uint32_t)) ||
	    libnvme_read_regs(hdl, NVME_REG_PMRCAP, bar + NVME_REG_PMRCAP,
			      NVME_REG_PMRMSCU + sizeof(uint32_t) -
			      NVME_REG_PMRCAP)) {
		free(bar);
		return NULL;
	}

	return bar;
}
