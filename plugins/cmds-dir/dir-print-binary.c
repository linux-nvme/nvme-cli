// SPDX-License-Identifier: GPL-2.0-or-later

#include <libnvme.h>

#include "dir-print.h"
#include "nvme-print.h"

static void binary_directive(__u8 type, __u8 oper, __u16 spec, __u32 nsid,
	__u64 result, void *buf, __u32 len)
{
	if (!buf)
		return;

	d_raw(buf, len);
}

static struct dir_print_ops binary_dir_print_ops = {
	.directive	= binary_directive,
};

struct dir_print_ops *dir_get_binary_print_ops(nvme_print_flags_t flags)
{
	binary_dir_print_ops.flags = flags;
	return &binary_dir_print_ops;
}
