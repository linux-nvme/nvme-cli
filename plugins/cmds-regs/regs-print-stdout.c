// SPDX-License-Identifier: GPL-2.0-or-later

#include <inttypes.h>
#include <stdio.h>

#include <libnvme.h>

#include <shared/table-util.h>

#include "nvme-print.h"
#include "nvme-print-stdout.h"
#include "regs-print.h"

static struct regs_print_ops regs_stdout_print_ops;

/*
 * The "field : value" table of the fields @fields of @value, decoded: the
 * subtable of a row with the value itself.
 */
static struct shr_table *stdout_bitfields_table(const struct bitfield *fields,
						unsigned int nr,
						uint64_t value)
{
	struct shr_table *t;
	char buf[128];
	unsigned int i;

	t = stdout_kv_table_create();
	if (!t)
		return NULL;

	for (i = 0; i < nr; i++) {
		bitfield_str(&fields[i], value, buf, sizeof(buf));
		stdout_kv_add(t, fields[i].name, "%s", buf);
	}

	return t;
}

static void stdout_ctrl_registers(const struct nvme_reg_val *vals,
				  unsigned int nr, enum nvme_regs_style style)
{
	bool verbose = !!(regs_stdout_print_ops.flags & VERBOSE);
	struct shr_table *t;
	unsigned int i;
	int row;

	t = stdout_kv_table_create();
	if (!t)
		return;

	for (i = 0; i < nr; i++) {
		const struct nvme_reg *reg = vals[i].reg;
		uint64_t value = vals[i].value;

		if (style == NVME_REGS_TABLE)
			row = stdout_kv_add(t, reg->sym, "%#"PRIx64, value);
		else if (verbose)
			row = stdout_kv_add(t, reg->name, "%#"PRIx64, value);
		else
			row = stdout_kv_add(t,
				style == NVME_REGS_PROPERTY ? "property" :
							      "register",
				"%#04x (%s), value: %#"PRIx64, reg->offset,
				reg->name, value);
		if (verbose && reg->nr_fields)
			shr_table_set_row_subtable(t, row,
				stdout_bitfields_table(reg->fields,
						       reg->nr_fields, value));
	}

	stdout_kv_table_finish(t, "registers");
}

static struct regs_print_ops regs_stdout_print_ops = {
	.ctrl_registers	= stdout_ctrl_registers,
};

struct regs_print_ops *regs_get_stdout_print_ops(nvme_print_flags_t flags)
{
	regs_stdout_print_ops.flags = flags;
	return &regs_stdout_print_ops;
}
