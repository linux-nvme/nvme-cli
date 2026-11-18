/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include <libnvme.h>

#include "args.h"

struct admin_print_ops {
	void (*relatives)(struct libnvme_global_ctx *ctx, const char *name);
	nvme_print_flags_t flags;
};

struct admin_print_ops *admin_get_stdout_print_ops(nvme_print_flags_t flags);

void nvme_show_relatives(struct libnvme_global_ctx *ctx, const char *name,
			 nvme_print_flags_t flags);
