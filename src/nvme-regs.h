/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE LLC
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "bitfields.h"

/*
 * The controller registers (NVM Express Base Specification 2.4, 3.1.4),
 * which a fabrics controller has as properties, as far as its transport
 * allows: one table with their fields for the commands and every output
 * format.
 */

enum nvme_reg_idx {
	NVME_REGI_CAP,
	NVME_REGI_VS,
	NVME_REGI_INTMS,
	NVME_REGI_INTMC,
	NVME_REGI_CC,
	NVME_REGI_CSTS,
	NVME_REGI_NSSR,
	NVME_REGI_AQA,
	NVME_REGI_ASQ,
	NVME_REGI_ACQ,
	NVME_REGI_CMBLOC,
	NVME_REGI_CMBSZ,
	NVME_REGI_BPINFO,
	NVME_REGI_BPRSEL,
	NVME_REGI_BPMBL,
	NVME_REGI_CMBMSC,
	NVME_REGI_CMBSTS,
	NVME_REGI_CMBEBS,
	NVME_REGI_CMBSWTP,
	NVME_REGI_NSSD,
	NVME_REGI_CRTO,
	NVME_REGI_PMRCAP,
	NVME_REGI_PMRCTL,
	NVME_REGI_PMRSTS,
	NVME_REGI_PMREBS,
	NVME_REGI_PMRSWTP,
	NVME_REGI_PMRMSCL,
	NVME_REGI_PMRMSCU,
	NVME_NR_REGS,
};

enum nvme_reg_flags {
	NVME_REGF_FABRICS	= 1 << 0,	/* a fabrics property */
	NVME_REGF_OPTIONAL	= 1 << 1,	/* which it may not implement */
	NVME_REGF_WRITE		= 1 << 2,	/* the host may write it */
};

struct nvme_reg {
	uint32_t offset;
	uint8_t size;			/* in bytes, 4 or 8 */
	uint8_t flags;			/* enum nvme_reg_flags */
	const char *sym;		/* "cc" */
	const char *name;		/* "Controller Configuration" */
	const struct bitfield *fields;
	unsigned int nr_fields;
};

extern const struct nvme_reg nvme_regs[NVME_NR_REGS];

/* The register at @offset, NULL if there is none */
const struct nvme_reg *nvme_reg_by_offset(uint32_t offset);

/* A register and its value */
struct nvme_reg_val {
	const struct nvme_reg *reg;
	uint64_t value;
};
