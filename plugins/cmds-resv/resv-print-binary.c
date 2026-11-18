// SPDX-License-Identifier: GPL-2.0-or-later

#include <libnvme.h>

#include "nvme-print.h"
#include "resv-print.h"

static void binary_resv_report(struct nvme_resv_status *status, int bytes,
	bool eds)
{
	d_raw((unsigned char *)status, bytes);
}

static struct resv_print_ops binary_resv_print_ops = {
	.resv_report	= binary_resv_report,
};

struct resv_print_ops *resv_get_binary_print_ops(nvme_print_flags_t flags)
{
	binary_resv_print_ops.flags = flags;
	return &binary_resv_print_ops;
}
