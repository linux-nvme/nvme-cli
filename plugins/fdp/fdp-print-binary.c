// SPDX-License-Identifier: GPL-2.0-or-later

#include <libnvme.h>

#include "fdp-print.h"
#include "nvme-print.h"

static void binary_fdp_configs(struct nvme_fdp_config_log *log, size_t len)
{
	d_raw((unsigned char *)log, len);
}

static void binary_fdp_usage(struct nvme_fdp_ruhu_log *log, size_t len)
{
	d_raw((unsigned char *)log, len);
}

static void binary_fdp_stats(struct nvme_fdp_stats_log *log)
{
	d_raw((unsigned char *)log, sizeof(*log));
}

static void binary_fdp_events(struct nvme_fdp_events_log *log)
{
	d_raw((unsigned char *)log, sizeof(*log));
}

static void binary_fdp_ruh_status(struct nvme_fdp_ruh_status *status,
				  size_t len)
{
	d_raw((unsigned char *)status, len);
}

static struct fdp_print_ops binary_fdp_print_ops = {
	.config_log	= binary_fdp_configs,
	.event_log	= binary_fdp_events,
	.ruh_status	= binary_fdp_ruh_status,
	.stats_log	= binary_fdp_stats,
	.usage_log	= binary_fdp_usage,
};

struct fdp_print_ops *fdp_get_binary_print_ops(nvme_print_flags_t flags)
{
	binary_fdp_print_ops.flags = flags;
	return &binary_fdp_print_ops;
}
