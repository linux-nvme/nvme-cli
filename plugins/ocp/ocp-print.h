/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef OCP_PRINT_H
#define OCP_PRINT_H

#include "ocp-hardware-component-log.h"

struct ocp_print_ops {
	void (*hwcomp_log)(struct hwcomp_log *log, __u32 id, bool list);
	nvme_print_flags_t flags;
};

struct ocp_print_ops *ocp_get_stdout_print_ops(nvme_print_flags_t flags);
struct ocp_print_ops *ocp_get_binary_print_ops(nvme_print_flags_t flags);

#ifdef CONFIG_JSONC
struct ocp_print_ops *ocp_get_json_print_ops(nvme_print_flags_t flags);
#else /* !CONFIG_JSONC */
static inline struct ocp_print_ops *ocp_get_json_print_ops(nvme_print_flags_t flags)
{
	return NULL;
}
#endif /* !CONFIG_JSONC */

void ocp_show_hwcomp_log(struct hwcomp_log *log, __u32 id, bool list, nvme_print_flags_t flags);
#endif /* OCP_PRINT_H */
