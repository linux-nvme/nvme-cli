/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include <libnvme.h>

#include "args.h"

struct fdp_print_ops {
	void (*config_log)(struct nvme_fdp_config_log *log, size_t len);
	void (*event_log)(struct nvme_fdp_events_log *log);
	void (*ruh_status)(struct nvme_fdp_ruh_status *status, size_t len);
	void (*stats_log)(struct nvme_fdp_stats_log *log);
	void (*usage_log)(struct nvme_fdp_ruhu_log *log, size_t len);
	nvme_print_flags_t flags;
};

struct fdp_print_ops *fdp_get_stdout_print_ops(nvme_print_flags_t flags);
struct fdp_print_ops *fdp_get_binary_print_ops(nvme_print_flags_t flags);

#ifdef CONFIG_JSONC
struct fdp_print_ops *fdp_get_json_print_ops(nvme_print_flags_t flags);
#else
static inline struct fdp_print_ops *
fdp_get_json_print_ops(nvme_print_flags_t flags)
{
	return NULL;
}
#endif

void fdp_show_configs(struct nvme_fdp_config_log *log, size_t len,
		      nvme_print_flags_t flags);
void fdp_show_usage(struct nvme_fdp_ruhu_log *log, size_t len,
		    nvme_print_flags_t flags);
void fdp_show_stats(struct nvme_fdp_stats_log *log, nvme_print_flags_t flags);
void fdp_show_events(struct nvme_fdp_events_log *log,
		     nvme_print_flags_t flags);
void fdp_show_ruh_status(struct nvme_fdp_ruh_status *status, size_t len,
			 nvme_print_flags_t flags);

/* Register the FDP log page decoder for get-log -v */
void fdp_register_log_decoder(void);
