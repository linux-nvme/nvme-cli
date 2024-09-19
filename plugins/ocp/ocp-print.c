// SPDX-License-Identifier: GPL-2.0-or-later
#include "nvme-print.h"
#include "ocp-print.h"
#include "ocp-hardware-component-log.h"

#define ocp_print(name, flags, ...) \
	do { \
		struct ocp_print_ops *ops = ocp_print_ops(flags); \
		if (ops && ops->name) \
			ops->name(__VA_ARGS__); \
	} while (false)

static struct ocp_print_ops *ocp_print_ops(nvme_print_flags_t flags)
{
	struct ocp_print_ops *ops = NULL;

	if (flags & JSON || nvme_is_output_format_json())
		ops = ocp_get_json_print_ops(flags);
	else if (flags & BINARY)
		ops = ocp_get_binary_print_ops(flags);
	else
		ops = ocp_get_stdout_print_ops(flags);

	return ops;
}

void ocp_show_hwcomp_log(struct hwcomp_log *log, __u32 id, bool list, nvme_print_flags_t flags)
{
	ocp_print(hwcomp_log, flags, log, id, list);
}

