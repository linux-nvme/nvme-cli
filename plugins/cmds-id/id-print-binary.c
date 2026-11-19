// SPDX-License-Identifier: GPL-2.0-or-later

#include <libnvme.h>

#include "id-print.h"
#include "nvme-print.h"

static void binary_id_ns(struct nvme_id_ns *ns, unsigned int nsid,
	unsigned int lba_index, bool cap_only)
{
	d_raw((unsigned char *)ns, sizeof(*ns));
}

static void binary_cmd_set_independent_id_ns(
	struct nvme_id_independent_id_ns *ns, unsigned int nsid)
{
	d_raw((unsigned char *)ns, sizeof(*ns));
}

static void binary_id_ns_descs(void *data, unsigned int nsid)
{
	d_raw((unsigned char *)data, 0x1000);
}

static void binary_id_ctrl(struct nvme_id_ctrl *ctrl, const char *product_name,
	void (*vendor_show)(__u8 *vs, struct json_object *root))
{
	d_raw((unsigned char *)ctrl, sizeof(*ctrl));
}

static void binary_id_ctrl_nvm(struct nvme_id_ctrl_nvm *ctrl_nvm)
{
	d_raw((unsigned char *)ctrl_nvm, sizeof(*ctrl_nvm));
}

static void binary_nvm_id_ns(struct nvme_nvm_id_ns *nvm_ns, unsigned int nsid,
	struct nvme_id_ns *ns, unsigned int lba_index,
	bool cap_only)
{
	d_raw((unsigned char *)nvm_ns, sizeof(*nvm_ns));
}

static void binary_list_ctrl(struct nvme_ctrl_list *ctrl_list)
{
	d_raw((unsigned char *)ctrl_list, sizeof(*ctrl_list));
}

static void binary_id_nvmset(struct nvme_id_nvmset_list *nvmset,
			     unsigned int nvmset_id)
{
	d_raw((unsigned char *)nvmset, sizeof(*nvmset));
}

static void binary_primary_ctrl_cap(const struct nvme_primary_ctrl_cap *caps)
{
	d_raw((unsigned char *)caps, sizeof(*caps));
}

static void binary_list_secondary_ctrl(
	const struct nvme_secondary_ctrl_list *sc_list,
	__u32 count)
{
	d_raw((unsigned char *)sc_list, sizeof(*sc_list));
}

static void binary_id_ns_granularity_list(
	const struct nvme_id_ns_granularity_list *glist)
{
	d_raw((unsigned char *)glist, sizeof(*glist));
}

static void binary_id_uuid_list(const struct nvme_id_uuid_list *uuid_list)
{
	d_raw((unsigned char *)uuid_list, sizeof(*uuid_list));
}

static void binary_id_domain_list(struct nvme_id_domain_list *id_dom)
{
	d_raw((unsigned char *)id_dom, sizeof(*id_dom));
}

static struct id_print_ops id_binary_print_ops = {
	.ctrl_list			= binary_list_ctrl,
	.endurance_group_list		= NULL,
	.id_ctrl			= binary_id_ctrl,
	.id_ctrl_nvm			= binary_id_ctrl_nvm,
	.id_domain_list			= binary_id_domain_list,
	.id_independent_id_ns		= binary_cmd_set_independent_id_ns,
	.id_iocs			= NULL,
	.id_ns				= binary_id_ns,
	.id_ns_descs			= binary_id_ns_descs,
	.id_ns_granularity_list		= binary_id_ns_granularity_list,
	.id_nvmset_list			= binary_id_nvmset,
	.id_uuid_list			= binary_id_uuid_list,
	.ns_list			= NULL,
	.nvm_id_ns			= binary_nvm_id_ns,
	.primary_ctrl_cap		= binary_primary_ctrl_cap,
	.secondary_ctrl_list		= binary_list_secondary_ctrl,
};

struct id_print_ops *id_get_binary_print_ops(nvme_print_flags_t flags)
{
	id_binary_print_ops.flags = flags;
	return &id_binary_print_ops;
}
