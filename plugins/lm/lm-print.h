/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef LM_PRINT_H
#define LM_PRINT_H

#include "nvme.h"
#include "libnvme.h"

struct lm_print_ops {
	void (*controller_state_data)(struct nvme_lm_controller_state_data *data, size_t len,
				      __u32 offset);
	void (*controller_data_queue)(struct nvme_lm_ctrl_data_queue_fid_data *data);
	nvme_print_flags_t flags;
};

struct lm_print_ops *lm_get_stdout_print_ops(nvme_print_flags_t flags);
struct lm_print_ops *lm_get_binary_print_ops(nvme_print_flags_t flags);

#ifdef CONFIG_JSONC
struct lm_print_ops *lm_get_json_print_ops(nvme_print_flags_t flags);
#else
static inline struct lm_print_ops *lm_get_json_print_ops(nvme_print_flags_t flags)
{
	return NULL;
}
#endif

void lm_show_controller_state_data(struct nvme_lm_controller_state_data *data, size_t len,
				   __u32 offset, nvme_print_flags_t flags);
void lm_show_controller_data_queue(struct nvme_lm_ctrl_data_queue_fid_data *data,
				   nvme_print_flags_t flags);
#endif /* LM_PRINT_H */
