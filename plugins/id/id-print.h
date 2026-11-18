/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include <libnvme.h>

#include "args.h"
#include "id.h"
#include "nvme-json.h"

struct id_print_ops {
	void (*ctrl_list)(struct nvme_ctrl_list *ctrl_list);
	void (*endurance_group_list)(
		struct nvme_id_endurance_group_list *endgrp_list);
	void (*id_ctrl)(struct nvme_id_ctrl *ctrl, const char *product_name,
			void (*vs)(__u8 *vs, struct json_object *root));
	void (*id_ctrl_nvm)(struct nvme_id_ctrl_nvm *ctrl_nvm);
	void (*id_domain_list)(struct nvme_id_domain_list *id_dom);
	void (*id_independent_id_ns)(struct nvme_id_independent_id_ns *ns,
				     unsigned int nsid);
	void (*id_iocs)(struct nvme_id_iocs *ioscs);
	void (*id_ns)(struct nvme_id_ns *ns, unsigned int nsid,
		      unsigned int lba_index, bool cap_only);
	void (*id_ns_descs)(void *data, unsigned int nsid);
	void (*id_ns_granularity_list)(
		const struct nvme_id_ns_granularity_list *list);
	void (*id_nvmset_list)(struct nvme_id_nvmset_list *nvmset,
			       unsigned int nvmeset_id);
	void (*id_uuid_list)(const struct nvme_id_uuid_list *uuid_list);
	void (*ns_list)(struct nvme_ns_list *ns_list);
	void (*nvm_id_ns)(struct nvme_nvm_id_ns *nvm_ns, unsigned int nsid,
			  struct nvme_id_ns *ns, unsigned int lba_index,
			  bool cap_only);
	void (*primary_ctrl_cap)(const struct nvme_primary_ctrl_cap *caps);
	void (*secondary_ctrl_list)(
		const struct nvme_secondary_ctrl_list *sc_list, __u32 count);
	nvme_print_flags_t flags;
};

struct id_print_ops *id_get_stdout_print_ops(nvme_print_flags_t flags);
struct id_print_ops *id_get_binary_print_ops(nvme_print_flags_t flags);

#ifdef CONFIG_JSONC
struct id_print_ops *id_get_json_print_ops(nvme_print_flags_t flags);
#else
static inline struct id_print_ops *
id_get_json_print_ops(nvme_print_flags_t flags)
{
	return NULL;
}
#endif

void nvme_show_id_iocs(struct nvme_id_iocs *iocs, nvme_print_flags_t flags);
void nvme_show_id_ns(struct nvme_id_ns *ns, unsigned int nsid,
	unsigned int lba_index, bool cap_only, nvme_print_flags_t flags);
void nvme_show_cmd_set_independent_id_ns(
	struct nvme_id_independent_id_ns *ns, unsigned int nsid,
	nvme_print_flags_t flags);
void nvme_show_id_ns_descs(void *data, unsigned int nsid,
	nvme_print_flags_t flags);
void nvme_show_id_nvmset(struct nvme_id_nvmset_list *nvmset,
	unsigned int nvmset_id, nvme_print_flags_t flags);
void nvme_show_primary_ctrl_cap(const struct nvme_primary_ctrl_cap *cap,
	nvme_print_flags_t flags);
void nvme_show_list_secondary_ctrl(
	const struct nvme_secondary_ctrl_list *sc_list, __u32 count,
	nvme_print_flags_t flags);
void nvme_show_id_ns_granularity_list(
	const struct nvme_id_ns_granularity_list *glist,
	nvme_print_flags_t flags);
void nvme_show_id_uuid_list(const struct nvme_id_uuid_list *uuid_list,
	nvme_print_flags_t flags);
void nvme_show_list_ctrl(struct nvme_ctrl_list *ctrl_list,
	nvme_print_flags_t flags);
void nvme_show_id_domain_list(struct nvme_id_domain_list *id_dom,
	nvme_print_flags_t flags);
void nvme_show_endurance_group_list(
	struct nvme_id_endurance_group_list *endgrp_list,
	nvme_print_flags_t flags);
void nvme_show_list_ns(struct nvme_ns_list *ns_list,
	nvme_print_flags_t flags);
void nvme_show_id_ctrl_nvm(struct nvme_id_ctrl_nvm *ctrl_nvm,
	nvme_print_flags_t flags);
void nvme_show_nvm_id_ns(struct nvme_nvm_id_ns *nvm_ns, unsigned int nsid,
	struct nvme_id_ns *ns, unsigned int lba_index, bool cap_only,
	nvme_print_flags_t flags);
