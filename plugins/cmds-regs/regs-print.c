// SPDX-License-Identifier: GPL-2.0-or-later

#include <libnvme.h>

#include "nvme-print.h"
#include "regs-print.h"

/*
 * Run the printers in the sandbox. Like nvme_print(), silently skip
 * printers that an output format does not implement.
 */
#define regs_print(name, flags, ...)					\
	do {								\
		struct regs_print_ops *ops = regs_print_ops(flags);	\
									\
		if (ops && ops->name)					\
			nvme_print_decoder(ops, name, true, flags,	\
					   ##__VA_ARGS__);		\
	} while (false)

static struct regs_print_ops *regs_print_ops(nvme_print_flags_t flags)
{
	struct regs_print_ops *ops = NULL;

	if (flags & JSON || nvme_is_output_format_json())
		ops = regs_get_json_print_ops(flags);
	else if (flags & BINARY)
		ops = regs_get_binary_print_ops(flags);
	else
		ops = regs_get_stdout_print_ops(flags);

	return ops;
}

void nvme_show_ctrl_registers(const struct nvme_reg_val *vals, unsigned int nr,
			      enum nvme_regs_style style,
			      nvme_print_flags_t flags)
{
	regs_print(ctrl_registers, flags, vals, nr, style);
}
