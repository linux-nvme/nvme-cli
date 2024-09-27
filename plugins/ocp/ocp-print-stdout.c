// SPDX-License-Identifier: GPL-2.0-or-later
#include "util/types.h"
#include "common.h"
#include "nvme-print.h"
#include "ocp-print.h"
#include "ocp-hardware-component-log.h"
#include "ocp-fw-activation-history.h"

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

static void stdout_fw_activation_history(const struct fw_activation_history *fw_history)
{
	printf("Firmware History Log:\n");

	printf("  %-26s%d\n", "log identifier:", fw_history->log_id);
	printf("  %-26s%d\n", "valid entries:", le32_to_cpu(fw_history->valid_entries));

	printf("  entries:\n");

	for (int index = 0; index < fw_history->valid_entries; index++) {
		const struct fw_activation_history_entry *entry = &fw_history->entries[index];

		printf("    entry[%d]:\n", le32_to_cpu(index));
		printf("      %-22s%d\n", "version number:", entry->ver_num);
		printf("      %-22s%d\n", "entry length:", entry->entry_length);
		printf("      %-22s%d\n", "activation count:",
		       le16_to_cpu(entry->activation_count));
		printf("      %-22s%"PRIu64"\n", "timestamp:",
				(0x0000FFFFFFFFFFFF & le64_to_cpu(entry->timestamp)));
		printf("      %-22s%"PRIu64"\n", "power cycle count:",
		       le64_to_cpu(entry->power_cycle_count));
		printf("      %-22s%.*s\n", "previous firmware:", (int)sizeof(entry->previous_fw),
		       entry->previous_fw);
		printf("      %-22s%.*s\n", "new firmware:", (int)sizeof(entry->new_fw),
		       entry->new_fw);
		printf("      %-22s%d\n", "slot number:", entry->slot_number);
		printf("      %-22s%d\n", "commit action type:", entry->commit_action);
		printf("      %-22s%d\n", "result:",  le16_to_cpu(entry->result));
	}

	printf("  %-26s%d\n", "log page version:",
	       le16_to_cpu(fw_history->log_page_version));

	printf("  %-26s0x%"PRIx64"%"PRIx64"\n", "log page guid:",
	       le64_to_cpu(fw_history->log_page_guid[1]),
	       le64_to_cpu(fw_history->log_page_guid[0]));

	printf("\n");
}

static struct ocp_print_ops stdout_print_ops = {
	.hwcomp_log = stdout_hwcomp_log,
	.fw_act_history = stdout_fw_activation_history,
};

struct ocp_print_ops *ocp_get_stdout_print_ops(nvme_print_flags_t flags)
{
	stdout_print_ops.flags = flags;
	return &stdout_print_ops;
}
