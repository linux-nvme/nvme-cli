/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include <libnvme.h>

#include "args.h"

struct cmds_io_print_ops {
	void (*lba_status)(struct nvme_lba_status *list, unsigned long len);
	nvme_print_flags_t flags;
};

struct cmds_io_print_ops *
cmds_io_get_stdout_print_ops(nvme_print_flags_t flags);
struct cmds_io_print_ops *
cmds_io_get_binary_print_ops(nvme_print_flags_t flags);

#ifdef CONFIG_JSONC
struct cmds_io_print_ops *cmds_io_get_json_print_ops(nvme_print_flags_t flags);
#else
static inline struct cmds_io_print_ops *
cmds_io_get_json_print_ops(nvme_print_flags_t flags)
{
	return NULL;
}
#endif

void nvme_show_lba_status(struct nvme_lba_status *list, unsigned long len,
			  nvme_print_flags_t flags);
