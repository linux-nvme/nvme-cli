// SPDX-License-Identifier: GPL-2.0-or-later

#include "lm-print.h"

static void binary_controller_state_data(struct nvme_lm_controller_state_data *data, size_t len,
					 __u32 offset)
{
	d_raw((unsigned char *)data, len);
}

static void binary_controller_data_queue(struct nvme_lm_ctrl_data_queue_fid_data *data)
{
	d_raw((unsigned char *)data, sizeof(*data));
}

static struct lm_print_ops binary_print_ops = {
	.controller_state_data = binary_controller_state_data,
	.controller_data_queue = binary_controller_data_queue,
};

struct lm_print_ops *lm_get_binary_print_ops(nvme_print_flags_t flags)
{
	binary_print_ops.flags = flags;
	return &binary_print_ops;
}
