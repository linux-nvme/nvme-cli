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
	.ctrl_registers			= binary_ctrl_registers,
	.directive			= binary_directive,
	.discovery_log			= binary_discovery_log,
	.lba_status			= binary_lba_status,
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
