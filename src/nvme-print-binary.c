/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <libnvme.h>

#include <ccan/endian/endian.h>

#include "nvme-print.h"

static struct print_ops binary_print_ops;

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
	.discovery_log			= binary_discovery_log,
	.select_result			= NULL,
	.show_feature			= binary_feature_show,
	.show_feature_fields		= NULL,
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
