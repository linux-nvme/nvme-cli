/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include <libnvme.h>

#include "args.h"

struct fabrics_print_ops {
	void (*discovery_log)(const struct nvmf_discovery_log *log, int numrec);
	void (*config_conn_list)(struct libnvmf_config *config);
	nvme_print_flags_t flags;
};

struct fabrics_print_ops *
fabrics_get_stdout_print_ops(nvme_print_flags_t flags);
struct fabrics_print_ops *
fabrics_get_binary_print_ops(nvme_print_flags_t flags);

#ifdef CONFIG_JSONC
struct fabrics_print_ops *fabrics_get_json_print_ops(nvme_print_flags_t flags);
#else
static inline struct fabrics_print_ops *
fabrics_get_json_print_ops(nvme_print_flags_t flags)
{
	return NULL;
}
#endif

void fabrics_show_discovery_log(const struct nvmf_discovery_log *log,
				uint64_t numrec, nvme_print_flags_t flags);
void fabrics_show_config_conn_list(struct libnvmf_config *config,
				   nvme_print_flags_t flags);

/* Register the Discovery log page decoder for get-log -v */
void fabrics_register_log_decoder(void);
