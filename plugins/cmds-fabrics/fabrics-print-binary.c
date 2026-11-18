// SPDX-License-Identifier: GPL-2.0-or-later

#include <libnvme.h>

#include "fabrics-print.h"
#include "nvme-print.h"

static void binary_discovery_log(const struct nvmf_discovery_log *log,
				  int numrec)
{
	d_raw((unsigned char *)log,
	      sizeof(struct nvmf_discovery_log) +
	      numrec * sizeof(struct nvmf_disc_log_entry));
}

static struct fabrics_print_ops binary_fabrics_print_ops = {
	.discovery_log		= binary_discovery_log,
};

struct fabrics_print_ops *
fabrics_get_binary_print_ops(nvme_print_flags_t flags)
{
	binary_fabrics_print_ops.flags = flags;
	return &binary_fabrics_print_ops;
}
