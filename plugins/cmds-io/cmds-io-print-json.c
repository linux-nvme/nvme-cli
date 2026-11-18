// SPDX-License-Identifier: GPL-2.0-or-later

#include <inttypes.h>
#include <stdio.h>

#include <libnvme.h>

#include <ccan/endian/endian.h>

#include "cmds-io-print.h"
#include "nvme-print.h"
#include "nvme-print-json.h"

static void json_lba_status(struct nvme_lba_status *list,
			      unsigned long len)
{
	struct json_object *r = json_root();
	__u32 nlsd = le32_to_cpu(list->nlsd);
	size_t nr = nvme_log_nr_entries(nlsd, len, sizeof(*list),
					sizeof(list->descs[0]));
	size_t idx;
	struct nvme_lba_status_desc *e;
	struct json_object *lsde;
	char json_str[STR_LEN];

	obj_add_uint(r, "Number of LBA Status Descriptors (NLSD)", nlsd);
	obj_add_uint(r, "Completion Condition (CMPC)", list->cmpc);

	switch (list->cmpc) {
	case NVME_LBA_STATUS_CMPC_NO_CMPC:
		obj_add_str(r, "cmpc-definition",
			"No indication of the completion condition");
		break;
	case NVME_LBA_STATUS_CMPC_INCOMPLETE:
		obj_add_str(r, "cmpc-definition",
			"Completed transferring the amount of data specified in theMNDW field. But, additional LBA Status Descriptor Entries areavailable to transfer or scan did not complete (if ATYPE = 10h)");
		break;
	case NVME_LBA_STATUS_CMPC_COMPLETE:
		obj_add_str(r, "cmpc-definition",
			"Completed the specified action over the number of LBAs specifiedin the Range Length field and transferred all available LBA StatusDescriptor Entries");
		break;
	default:
		break;
	}

	for (idx = 0; idx < nr; idx++) {
		lsde = json_create_object();
		sprintf(json_str, "LSD entry %zu", idx);
		obj_add_obj(r, json_str, lsde);
		e = &list->descs[idx];
		sprintf(json_str, "0x%016"PRIx64"", le64_to_cpu(e->dslba));
		obj_add_str(lsde, "DSLBA", json_str);
		sprintf(json_str, "0x%08x", le32_to_cpu(e->nlb));
		obj_add_str(lsde, "NLB", json_str);
		sprintf(json_str, "0x%02x", e->status);
		obj_add_str(lsde, "status", json_str);
	}
}

static struct cmds_io_print_ops cmds_io_json_print_ops = {
	.lba_status	= json_lba_status,
};

struct cmds_io_print_ops *cmds_io_get_json_print_ops(nvme_print_flags_t flags)
{
	cmds_io_json_print_ops.flags = flags;
	return &cmds_io_json_print_ops;
}
