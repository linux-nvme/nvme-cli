// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE LLC
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

/*
 * Unit tests for nvme-regs.c: the consistency of the register table, and
 * which registers are properties of a fabrics controller and which the
 * host may write (NVM Express Base Specification 2.4, Figure 33).
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ccan/array_size/array_size.h>
#include <libnvme.h>

#include "../src/nvme-regs.h"

static bool report(const char *what, bool pass)
{
	printf(" - %s [%s]\n", what, pass ? "PASS" : "FAIL");
	return pass;
}

static int mask_bits(uint64_t mask)
{
	int n = 0;

	while (mask & 1) {
		mask >>= 1;
		n++;
	}
	return mask ? -1 : n;	/* -1: not contiguous from bit 0 */
}

static bool test_layout(void)
{
	bool order = true, size = true, unique = true, pass;
	size_t i, j;

	printf("register table layout\n");
	for (i = 0; i < ARRAY_SIZE(nvme_regs); i++) {
		const struct nvme_reg *r = &nvme_regs[i];

		if (i && r->offset <= nvme_regs[i - 1].offset) {
			printf("   %s out of order\n", r->sym);
			order = false;
		}
		if (r->size != (nvme_is_64bit_reg(r->offset) ? 8 : 4)) {
			printf("   %s: size %u\n", r->sym, r->size);
			size = false;
		}
		for (j = 0; j < i; j++)
			if (!strcmp(r->sym, nvme_regs[j].sym) ||
			    !strcmp(r->name, nvme_regs[j].name)) {
				printf("   %s twice\n", r->sym);
				unique = false;
			}
	}

	pass = report("ascending offsets", order);
	pass &= report("size of the 64 bit registers", size);
	pass &= report("unique names", unique);

	return pass;
}

static bool test_fields(void)
{
	bool inside = true, overlap = true, strs = true, names = true, pass;
	size_t i;

	printf("register fields\n");
	for (i = 0; i < ARRAY_SIZE(nvme_regs); i++) {
		const struct nvme_reg *r = &nvme_regs[i];
		uint64_t used = 0;
		unsigned int f, g;

		if (!r->nr_fields) {
			printf("   %s: no fields\n", r->sym);
			inside = false;
		}
		for (f = 0; f < r->nr_fields; f++) {
			const struct bitfield *b = &r->fields[f];
			int bits = mask_bits(b->mask);
			uint64_t m;

			if (bits <= 0 || b->shift + bits > r->size * 8) {
				printf("   %s: %s outside\n", r->sym, b->name);
				inside = false;
				continue;
			}
			m = (bits == 64 ? UINT64_MAX :
			     (UINT64_C(1) << bits) - 1) << b->shift;
			if (used & m) {
				printf("   %s: %s overlaps\n", r->sym, b->name);
				overlap = false;
			}
			used |= m;
			if (b->fmt == BF_STR &&
			    (!b->nr_strs || b->nr_strs - 1 > b->mask)) {
				printf("   %s: %s strings\n", r->sym, b->name);
				strs = false;
			}
			if (!b->name || !b->name[0])
				names = false;
			for (g = 0; g < f; g++)
				if (!strcmp(b->name, r->fields[g].name)) {
					printf("   %s: %s twice\n", r->sym,
					       b->name);
					names = false;
				}
		}
	}

	pass = report("fields inside their register", inside);
	pass &= report("no overlapping fields", overlap);
	pass &= report("string tables fit their field", strs);
	pass &= report("unique field names", names);

	return pass;
}

static bool flags_are(const char *what, unsigned int flag,
		      const enum nvme_reg_idx *expected, size_t n)
{
	bool pass = true;
	size_t i, j;

	for (i = 0; i < ARRAY_SIZE(nvme_regs); i++) {
		bool want = false;

		for (j = 0; j < n; j++)
			want |= expected[j] == i;
		if (!!(nvme_regs[i].flags & flag) != want) {
			printf("   %s: %s\n", what, nvme_regs[i].sym);
			pass = false;
		}
	}
	return report(what, pass);
}

static bool test_flags(void)
{
	static const enum nvme_reg_idx fabrics[] = {
		NVME_REGI_CAP, NVME_REGI_VS, NVME_REGI_CC, NVME_REGI_CSTS,
		NVME_REGI_NSSR, NVME_REGI_NSSD, NVME_REGI_CRTO,
	};
	static const enum nvme_reg_idx optional[] = {
		NVME_REGI_NSSR, NVME_REGI_NSSD, NVME_REGI_CRTO,
	};
	static const enum nvme_reg_idx write[] = {
		NVME_REGI_INTMS, NVME_REGI_INTMC, NVME_REGI_CC, NVME_REGI_CSTS,
		NVME_REGI_NSSR, NVME_REGI_AQA, NVME_REGI_ASQ, NVME_REGI_ACQ,
		NVME_REGI_BPRSEL, NVME_REGI_BPMBL, NVME_REGI_CMBMSC,
		NVME_REGI_NSSD, NVME_REGI_PMRCTL, NVME_REGI_PMRMSCL,
		NVME_REGI_PMRMSCU,
	};

	bool pass;

	printf("register flags\n");
	pass = flags_are("fabrics properties", NVME_REGF_FABRICS, fabrics,
			 ARRAY_SIZE(fabrics));
	pass &= flags_are("optional fabrics properties", NVME_REGF_OPTIONAL,
			  optional, ARRAY_SIZE(optional));
	pass &= flags_are("host writable registers", NVME_REGF_WRITE, write,
			  ARRAY_SIZE(write));

	return pass;
}

static bool test_by_offset(void)
{
	bool found = true, pass;
	size_t i;

	printf("nvme_reg_by_offset\n");
	for (i = 0; i < ARRAY_SIZE(nvme_regs); i++)
		found &= nvme_reg_by_offset(nvme_regs[i].offset) ==
			&nvme_regs[i];

	pass = report("each register", found);
	pass &= report("reserved and unaligned offsets",
		       !nvme_reg_by_offset(0x18) &&
		       !nvme_reg_by_offset(0x2) &&
		       !nvme_reg_by_offset(0x6c) &&
		       !nvme_reg_by_offset(0x1000));

	return pass;
}

int main(void)
{
	bool pass = true;

	pass &= test_layout();
	pass &= test_fields();
	pass &= test_flags();
	pass &= test_by_offset();

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
