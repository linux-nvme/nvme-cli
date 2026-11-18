/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <libnvme.h>

#include <ccan/endian/endian.h>
#include <shared/compiler-attributes-util.h>
#include <shared/mmio-util.h>

#include "nvme-print.h"

static struct print_ops binary_print_ops;

/*
 * The registers as they are in BAR0, 0h to E1Bh, the ones not read zero:
 * all of them for a PCIe controller, the properties of a fabrics one.
 */
static void binary_ctrl_registers(const struct nvme_reg_val *vals,
				  unsigned int nr,
				  enum nvme_regs_style style __shr_unused)
{
	const unsigned int size = NVME_REG_PMRMSCU + sizeof(uint32_t);
	unsigned char page[NVME_REG_PMRMSCU + sizeof(uint32_t)] = { 0 };
	unsigned int i;

	for (i = 0; i < nr; i++) {
		const struct nvme_reg *reg = vals[i].reg;

		if (reg->offset + reg->size > size)
			continue;
		if (reg->size == 8)
			shr_mmio_write64(page + reg->offset, vals[i].value,
					 true);
		else
			shr_mmio_write32(page + reg->offset, vals[i].value);
	}

	d_raw(page, size);
}

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

static void binary_id_ns_descs(void *data, unsigned nsid)
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

static void binary_id_nvmset(struct nvme_id_nvmset_list *nvmset, unsigned nvmset_id)
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

static void binary_resv_report(struct nvme_resv_status *status, int bytes,
	bool eds)
{
	d_raw((unsigned char *)status, bytes);
}


static void binary_directive(__u8 type, __u8 oper, __u16 spec, __u32 nsid, __u64 result,
	void *buf, __u32 len)
{
	if (!buf)
		return;

	d_raw(buf, len);
}

static void binary_lba_status(struct nvme_lba_status *list, unsigned long len)
{
	d_raw((unsigned char *)list, len);
}

static void binary_discovery_log(const struct nvmf_discovery_log *log,
				  int numrec)
{
	d_raw((unsigned char *)log,
	      sizeof(struct nvmf_discovery_log) +
	      numrec * sizeof(struct nvmf_disc_log_entry));
}

static void binary_feature_show(enum nvme_features_id fid, int sel,
				unsigned int result, void *buf, __u32 data_len)
{
	if (buf) {
		d_raw(buf, data_len);
	}
}

static struct print_ops binary_print_ops = {
	/* libnvme types.h print functions */
	.ctrl_list			= binary_list_ctrl,
	.ctrl_registers			= binary_ctrl_registers,
	.directive			= binary_directive,
	.discovery_log			= binary_discovery_log,
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
	.lba_status			= binary_lba_status,
	.ns_list			= NULL,
	.nvm_id_ns			= binary_nvm_id_ns,
	.primary_ctrl_cap		= binary_primary_ctrl_cap,
	.resv_report			= binary_resv_report,
	.secondary_ctrl_list		= binary_list_secondary_ctrl,
	.select_result			= NULL,
	.show_feature			= binary_feature_show,
	.show_feature_fields		= NULL,
	.id_ctrl_rpmbs			= NULL,
	.lba_range			= NULL,
	.lba_status_info		= NULL,
	.d				= NULL,
	.show_init			= NULL,
	.show_finish			= NULL,

	/* libnvme tree print functions */
	.list_item			= NULL,
	.list_items			= NULL,
	.print_nvme_subsystem_list	= NULL,
	.topology_ctrl			= NULL,
	.topology_namespace		= NULL,
	.topology_multipath		= NULL,

	/* status and error messages */
	.connect_msg			= NULL,
	.show_message			= NULL,
	.show_perror			= NULL,
	.show_status			= NULL,
	.show_opcode_status		= NULL,
	.show_error_status		= NULL,
	.show_key_value			= NULL,
};

struct print_ops *nvme_get_binary_print_ops(nvme_print_flags_t flags)
{
	binary_print_ops.flags = flags;
	return &binary_print_ops;
}
