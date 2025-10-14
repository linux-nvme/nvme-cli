// SPDX-License-Identifier: GPL-2.0-or-later

#include "lm-print.h"

#define lm_print(name, flags, ...) \
	do { \
		struct lm_print_ops *ops = lm_print_ops(flags); \
		if (ops && ops->name) \
			ops->name(__VA_ARGS__); \
		else \
			fprintf(stderr, "unhandled output format\n"); \
	} while (false)

static struct lm_print_ops *lm_print_ops(nvme_print_flags_t flags)
{
	struct lm_print_ops *ops = NULL;

	if (flags & JSON || nvme_is_output_format_json())
		ops = lm_get_json_print_ops(flags);
	else if (flags & BINARY)
		ops = lm_get_binary_print_ops(flags);
	else
		ops = lm_get_stdout_print_ops(flags);

	return ops;
}

void lm_show_controller_state_data(struct nvme_lm_controller_state_data *data, size_t len,
				   __u32 offset, nvme_print_flags_t flags)
{
	lm_print(controller_state_data, flags, data, len, offset);
}

void lm_show_controller_data_queue(struct nvme_lm_ctrl_data_queue_fid_data *data,
				   nvme_print_flags_t flags)
{
	lm_print(controller_data_queue, flags, data);
}
