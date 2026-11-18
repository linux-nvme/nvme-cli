/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include <libnvme.h>

#include "args.h"
#include "nvme-regs.h"

/* How nvme_show_ctrl_registers() shows the registers */
enum nvme_regs_style {
	NVME_REGS_TABLE,	/* show-regs: a row for each */
	NVME_REGS_REGISTER,	/* get-reg: "register : offset (name), value" */
	NVME_REGS_PROPERTY,	/* get-property: "property : ..." */
};

struct regs_print_ops {
	void (*ctrl_registers)(const struct nvme_reg_val *vals, unsigned int nr,
			       enum nvme_regs_style style);
	nvme_print_flags_t flags;
};

struct regs_print_ops *regs_get_stdout_print_ops(nvme_print_flags_t flags);
struct regs_print_ops *regs_get_binary_print_ops(nvme_print_flags_t flags);

#ifdef CONFIG_JSONC
struct regs_print_ops *regs_get_json_print_ops(nvme_print_flags_t flags);
#else
static inline struct regs_print_ops *
regs_get_json_print_ops(nvme_print_flags_t flags)
{
	return NULL;
}
#endif

void nvme_show_ctrl_registers(const struct nvme_reg_val *vals, unsigned int nr,
			      enum nvme_regs_style style,
			      nvme_print_flags_t flags);
