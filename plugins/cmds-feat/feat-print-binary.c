// SPDX-License-Identifier: GPL-2.0-or-later

#include <libnvme.h>

#include "feat-print.h"
#include "nvme-print.h"

static void binary_feature_show(enum nvme_features_id fid, int sel,
				unsigned int result, void *buf, __u32 data_len)
{
	if (buf)
		d_raw(buf, data_len);
}

static struct feat_print_ops feat_binary_print_ops = {
	.show_feature			= binary_feature_show,
};

struct feat_print_ops *feat_get_binary_print_ops(nvme_print_flags_t flags)
{
	feat_binary_print_ops.flags = flags;
	return &feat_binary_print_ops;
}
