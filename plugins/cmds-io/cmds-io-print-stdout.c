// SPDX-License-Identifier: GPL-2.0-or-later

#include <inttypes.h>
#include <stdio.h>

#include <libnvme.h>

#include <ccan/array_size/array_size.h>
#include <ccan/endian/endian.h>
#include <shared/table-util.h>

#include "cmds-io-print.h"
#include "nvme-print.h"
#include "nvme-print-stdout.h"

static void stdout_lba_status(struct nvme_lba_status *list,
			      unsigned long len)
{
	struct shr_table_column columns[] = {
		{ "DSLBA",  LEFT, AUTO_WIDTH },
		{ "NLB",    LEFT, AUTO_WIDTH },
		{ "Status", LEFT, AUTO_WIDTH },
	};
	struct shr_table *t;
	__u32 nlsd = le32_to_cpu(list->nlsd);
	size_t nr = nvme_log_nr_entries(nlsd, len, sizeof(*list),
					sizeof(list->descs[0]));
	size_t idx;
	int row;

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "Number of LBA Status Descriptors(NLSD)", "%"PRIu32,
		      nlsd);
	stdout_kv_add(t, "Completion Condition(CMPC)", "%u", list->cmpc);

	stdout_kv_table_finish(t, "lba-status");

	switch (list->cmpc) {
	case NVME_LBA_STATUS_CMPC_NO_CMPC:
		printf("\tNo indication of the completion condition\n");
		break;
	case NVME_LBA_STATUS_CMPC_INCOMPLETE:
		printf("%s%s%s",
		       "\tCompleted transferring the amount of data specified in the\n",
		       "\tMNDW field. But, additional LBA Status Descriptor Entries are\n",
		       "\tavailable to transfer or scan did not complete (if ATYPE = 10h)\n");
		break;
	case NVME_LBA_STATUS_CMPC_COMPLETE:
		printf("%s%s%s",
		       "\tCompleted the specified action over the number of LBAs specified\n",
		       "\tin the Range Length field and transferred all available LBA Status\n",
		       "\tDescriptor Entries\n");
		break;
	default:
		break;
	}

	if (!nr)
		return;

	t = shr_table_init_with_columns(columns, ARRAY_SIZE(columns));
	if (!t)
		return;

	for (idx = 0; idx < nr; idx++) {
		struct nvme_lba_status_desc *e = &list->descs[idx];
		char dslba[24], nlb[16], status[8];

		snprintf(dslba, sizeof(dslba), "%#016"PRIx64,
			 le64_to_cpu(e->dslba));
		snprintf(nlb, sizeof(nlb), "%#08x", le32_to_cpu(e->nlb));
		snprintf(status, sizeof(status), "%#02x", e->status);

		row = shr_table_get_row_id(t);
		shr_table_set_value_str(t, 0, row, dslba, LEFT);
		shr_table_set_value_str(t, 1, row, nlb, LEFT);
		shr_table_set_value_str(t, 2, row, status, LEFT);
		shr_table_add_row(t, row);
	}

	shr_table_print(t);
	shr_table_free(t);
}

static struct cmds_io_print_ops cmds_io_stdout_print_ops = {
	.lba_status	= stdout_lba_status,
};

struct cmds_io_print_ops *cmds_io_get_stdout_print_ops(nvme_print_flags_t flags)
{
	cmds_io_stdout_print_ops.flags = flags;
	return &cmds_io_stdout_print_ops;
}
