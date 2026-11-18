// SPDX-License-Identifier: GPL-2.0-or-later

#include <libnvme.h>

#include <shared/compiler-attributes-util.h>

#include "nvme-print.h"
#include "nvme-print-json.h"
#include "regs-print.h"

/* Adds the fields @fields of @value to @o, decoded, under their names */
static void json_bitfields(struct json_object *o,
			   const struct bitfield *fields, unsigned int nr,
			   uint64_t value)
{
	char buf[128];
	unsigned int i;

	for (i = 0; i < nr; i++) {
		bitfield_str(&fields[i], value, buf, sizeof(buf));
		obj_add_str(o, fields[i].name, buf);
	}
}

/*
 * The same for each style: the value of each register under its symbol,
 * with -v an object of the value and its fields.
 */
static void json_ctrl_registers(const struct nvme_reg_val *vals,
				unsigned int nr,
				enum nvme_regs_style style __shr_unused)
{
	struct json_object *r = json_root();
	struct json_object *o;
	unsigned int i;

	for (i = 0; i < nr; i++) {
		const struct nvme_reg *reg = vals[i].reg;

		if (!json_verbose_mode()) {
			obj_add_uint64(r, reg->sym, vals[i].value);
			continue;
		}

		o = json_create_object();
		obj_add_uint64(o, "value", vals[i].value);
		json_bitfields(o, reg->fields, reg->nr_fields, vals[i].value);
		obj_add_obj(r, reg->sym, o);
	}
}

static struct regs_print_ops regs_json_print_ops = {
	.ctrl_registers	= json_ctrl_registers,
};

struct regs_print_ops *regs_get_json_print_ops(nvme_print_flags_t flags)
{
	regs_json_print_ops.flags = flags;
	return &regs_json_print_ops;
}
