/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include <libnvme.h>

#include "args.h"

struct resv_print_ops {
	void (*resv_report)(struct nvme_resv_status *status, int bytes,
			    bool eds);
	nvme_print_flags_t flags;
};

struct resv_print_ops *resv_get_stdout_print_ops(nvme_print_flags_t flags);
struct resv_print_ops *resv_get_binary_print_ops(nvme_print_flags_t flags);

#ifdef CONFIG_JSONC
struct resv_print_ops *resv_get_json_print_ops(nvme_print_flags_t flags);
#else
static inline struct resv_print_ops *
resv_get_json_print_ops(nvme_print_flags_t flags)
{
	return NULL;
}
#endif

void nvme_show_resv_report(struct nvme_resv_status *status, int bytes,
			   bool eds, nvme_print_flags_t flags);
