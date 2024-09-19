// SPDX-License-Identifier: GPL-2.0-or-later
#include "util/types.h"
#include "common.h"
#include "nvme-print.h"
#include "ocp-print.h"
#include "ocp-hardware-component-log.h"

static void print_hwcomp_desc(struct hwcomp_desc_entry *e, bool list, int num)
{
	printf("  Component %d: %s\n", num, hwcomp_id_to_string(le32_to_cpu(e->desc->id)));

	if (list)
		return;

	printf("    Date/Lot Size: 0x%"PRIx64"\n", (uint64_t)e->date_lot_size);
	printf("    Additional Information Size: 0x%"PRIx64"\n", (uint64_t)e->add_info_size);
	printf("    Identifier: 0x%08x\n", le32_to_cpu(e->desc->id));
	printf("    Manufacture: 0x%016"PRIx64"\n", le64_to_cpu(e->desc->mfg));
	printf("    Revision: 0x%016"PRIx64"\n", le64_to_cpu(e->desc->rev));
	printf("    Manufacture Code: 0x%016"PRIx64"\n", le64_to_cpu(e->desc->mfg_code));
	print_array("    Date/Lot Code", e->date_lot_code, e->date_lot_size);
	print_array("    Additional Information", e->add_info, e->add_info_size);
}

static void stdout_hwcomp_log(struct hwcomp_log *log, __u32 id, bool list)
{
	size_t date_lot_code_offset = sizeof(struct hwcomp_desc);
	int num = 1;
	struct hwcomp_desc_entry e = { log->desc };

	long double log_size = uint128_t_to_double(le128_to_cpu(log->size)) * sizeof(__le32);

	printf("Log Identifier: 0x%02xh\n", LID_HWCOMP);
	printf("Log Page Version: 0x%x\n", le16_to_cpu(log->ver));
	print_array("Reserved2", log->rsvd2, ARRAY_SIZE(log->rsvd2));
	print_array("Log page GUID", log->guid, ARRAY_SIZE(log->guid));
	printf("Hardware Component Log Size: 0x%"PRIx64"\n", (uint64_t)log_size);
	print_array("Reserved48", log->rsvd48, ARRAY_SIZE(log->rsvd48));
	printf("Component Descriptions\n");
	while (log_size > 0) {
		e.date_lot_size = le64_to_cpu(e.desc->date_lot_size) * sizeof(__le32);
		e.date_lot_code = e.date_lot_size ? (__u8 *)e.desc + date_lot_code_offset : NULL;
		e.add_info_size = le64_to_cpu(e.desc->add_info_size) * sizeof(__le32);
		e.add_info = e.add_info_size ? e.date_lot_code ? e.date_lot_code + e.date_lot_size :
		    (__u8 *)e.desc + date_lot_code_offset : NULL;
		if (!id || id == le32_to_cpu(e.desc->id))
			print_hwcomp_desc(&e, list, num++);
		e.desc_size = date_lot_code_offset + e.date_lot_size + e.add_info_size;
		e.desc = (struct hwcomp_desc *)((__u8 *)e.desc + e.desc_size);
		log_size -= e.desc_size;
	}
}

static struct ocp_print_ops stdout_print_ops = {
	.hwcomp_log = stdout_hwcomp_log,
};

struct ocp_print_ops *ocp_get_stdout_print_ops(nvme_print_flags_t flags)
{
	stdout_print_ops.flags = flags;
	return &stdout_print_ops;
}
