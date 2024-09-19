// SPDX-License-Identifier: GPL-2.0-or-later

#include "util/types.h"
#include "nvme-print.h"
#include "ocp-print.h"
#include "ocp-hardware-component-log.h"

static void binary_hwcomp_log(struct hwcomp_log *log, __u32 id, bool list)
{
	long double desc_len = uint128_t_to_double(le128_to_cpu(log->size)) * sizeof(__le32);

	d_raw((unsigned char *)log, offsetof(struct hwcomp_log, desc) + desc_len);
}

static struct ocp_print_ops binary_print_ops = {
	.hwcomp_log = binary_hwcomp_log,
};

struct ocp_print_ops *ocp_get_binary_print_ops(nvme_print_flags_t flags)
{
	binary_print_ops.flags = flags;
	return &binary_print_ops;
}
