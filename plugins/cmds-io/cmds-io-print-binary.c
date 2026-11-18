// SPDX-License-Identifier: GPL-2.0-or-later

#include <libnvme.h>

#include "cmds-io-print.h"
#include "nvme-print.h"

static void binary_lba_status(struct nvme_lba_status *list, unsigned long len)
{
	d_raw((unsigned char *)list, len);
}

static struct cmds_io_print_ops cmds_io_binary_print_ops = {
	.lba_status	= binary_lba_status,
};

struct cmds_io_print_ops *cmds_io_get_binary_print_ops(nvme_print_flags_t flags)
{
	cmds_io_binary_print_ops.flags = flags;
	return &cmds_io_binary_print_ops;
}
