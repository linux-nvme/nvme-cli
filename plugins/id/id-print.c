// SPDX-License-Identifier: GPL-2.0-or-later

#include <libnvme.h>

#include <ccan/minmax/minmax.h>

#include "cleanup.h"
#include "id-print.h"
#include "nvme-models.h"
#include "nvme-print.h"

/*
 * Run the printers in the sandbox. Like nvme_print(), silently skip
 * printers that an output format does not implement.
 */
#define id_print(name, flags, ...)					\
	do {								\
		struct id_print_ops *ops = id_print_ops(flags);		\
									\
		if (ops && ops->name)					\
			nvme_print_decoder(ops, name, true, flags,	\
					   ##__VA_ARGS__);		\
	} while (false)

static struct id_print_ops *id_print_ops(nvme_print_flags_t flags)
{
	struct id_print_ops *ops = NULL;

	if (flags & JSON || nvme_is_output_format_json())
		ops = id_get_json_print_ops(flags);
	else if (flags & BINARY)
		ops = id_get_binary_print_ops(flags);
	else
		ops = id_get_stdout_print_ops(flags);

	return ops;
}

void nvme_show_id_ns(struct nvme_id_ns *ns, unsigned int nsid,
	unsigned int lba_index, bool cap_only, nvme_print_flags_t flags)
{
	id_print(id_ns, flags, ns, nsid, lba_index, cap_only);
}

void nvme_show_cmd_set_independent_id_ns(
	struct nvme_id_independent_id_ns *ns, unsigned int nsid,
	nvme_print_flags_t flags)
{
	id_print(id_independent_id_ns, flags, ns, nsid);
}

void nvme_show_id_ns_descs(void *data, unsigned int nsid,
	nvme_print_flags_t flags)
{
	id_print(id_ns_descs, flags, data, nsid);
}

void nvme_show_id_ctrl(struct libnvme_global_ctx *ctx,
		struct libnvme_transport_handle *hdl, struct nvme_id_ctrl *ctrl,
		nvme_print_flags_t flags,
		void (*vendor_show)(__u8 *vs, struct json_object *root))
{
	__cleanup_free char *product_name = nvme_product_name(ctx, hdl);

	id_print(id_ctrl, flags, ctrl, product_name, vendor_show);
}

void nvme_show_id_ctrl_nvm(struct nvme_id_ctrl_nvm *ctrl_nvm,
	nvme_print_flags_t flags)
{
	id_print(id_ctrl_nvm, flags, ctrl_nvm);
}

void nvme_show_nvm_id_ns(struct nvme_nvm_id_ns *nvm_ns, unsigned int nsid,
	struct nvme_id_ns *ns, unsigned int lba_index, bool cap_only,
	nvme_print_flags_t flags)
{
	id_print(nvm_id_ns, flags, nvm_ns, nsid, ns, lba_index, cap_only);
}

void nvme_show_list_ns(struct nvme_ns_list *ns_list, nvme_print_flags_t flags)
{
	id_print(ns_list, flags, ns_list);
}

void nvme_show_list_ctrl(struct nvme_ctrl_list *ctrl_list,
	nvme_print_flags_t flags)
{
	id_print(ctrl_list, flags, ctrl_list);
}

void nvme_show_id_nvmset(struct nvme_id_nvmset_list *nvmset,
	unsigned int nvmset_id, nvme_print_flags_t flags)
{
	id_print(id_nvmset_list, flags, nvmset, nvmset_id);
}

void nvme_show_primary_ctrl_cap(const struct nvme_primary_ctrl_cap *caps,
				nvme_print_flags_t flags)
{
	id_print(primary_ctrl_cap, flags, caps);
}

void nvme_show_list_secondary_ctrl(
	const struct nvme_secondary_ctrl_list *sc_list,
	__u32 count, nvme_print_flags_t flags)
{
	__u16 num = sc_list->num;
	__u32 entries = min(num, count);

	id_print(secondary_ctrl_list, flags, sc_list, entries);
}

void nvme_show_id_ns_granularity_list(
	const struct nvme_id_ns_granularity_list *glist,
	nvme_print_flags_t flags)
{
	id_print(id_ns_granularity_list, flags, glist);
}

void nvme_show_id_uuid_list(const struct nvme_id_uuid_list *uuid_list,
				nvme_print_flags_t flags)
{
	id_print(id_uuid_list, flags, uuid_list);
}

void nvme_show_id_domain_list(struct nvme_id_domain_list *id_dom,
	nvme_print_flags_t flags)
{
	id_print(id_domain_list, flags, id_dom);
}

void nvme_show_endurance_group_list(
	struct nvme_id_endurance_group_list *endgrp_list,
	nvme_print_flags_t flags)
{
	id_print(endurance_group_list, flags, endgrp_list);
}

void nvme_show_id_iocs(struct nvme_id_iocs *iocs, nvme_print_flags_t flags)
{
	id_print(id_iocs, flags, iocs);
}
