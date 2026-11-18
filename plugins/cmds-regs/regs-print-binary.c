// SPDX-License-Identifier: GPL-2.0-or-later

#include <libnvme.h>

#include <shared/compiler-attributes-util.h>
#include <shared/mmio-util.h>

#include "nvme-print.h"
#include "regs-print.h"

/*
 * The registers as they are in BAR0, 0h to E1Bh, the ones not read zero:
 * all of them for a PCIe controller, the properties of a fabrics one.
 */
static void binary_ctrl_registers(const struct nvme_reg_val *vals,
				  unsigned int nr,
				  enum nvme_regs_style style __shr_unused)
{
	const unsigned int size = NVME_REG_PMRMSCU + sizeof(uint32_t);
	unsigned char page[NVME_REG_PMRMSCU + sizeof(uint32_t)] = { 0 };
	unsigned int i;

	for (i = 0; i < nr; i++) {
		const struct nvme_reg *reg = vals[i].reg;

		if (reg->offset + reg->size > size)
			continue;
		if (reg->size == 8)
			shr_mmio_write64(page + reg->offset, vals[i].value,
					 true);
		else
			shr_mmio_write32(page + reg->offset, vals[i].value);
	}

	d_raw(page, size);
}

static struct regs_print_ops binary_regs_print_ops = {
	.ctrl_registers	= binary_ctrl_registers,
};

struct regs_print_ops *regs_get_binary_print_ops(nvme_print_flags_t flags)
{
	binary_regs_print_ops.flags = flags;
	return &binary_regs_print_ops;
}
