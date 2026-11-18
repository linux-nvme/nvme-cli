// SPDX-License-Identifier: GPL-2.0-or-later

#include <libnvme.h>

#include "fdp-print.h"
#include "nvme-print.h"

/*
 * Run the printers in the sandbox. Like nvme_print(), silently skip
 * printers that an output format does not implement.
 */
#define fdp_print(name, flags, ...)					\
	do {								\
		struct fdp_print_ops *__fops = fdp_print_ops(flags);	\
									\
		if (__fops && __fops->name)				\
			nvme_print_decoder(__fops, name, true, flags,	\
					   ##__VA_ARGS__);		\
	} while (false)

static struct fdp_print_ops *fdp_print_ops(nvme_print_flags_t flags)
{
	struct fdp_print_ops *ops = NULL;

	if (flags & JSON || nvme_is_output_format_json())
		ops = fdp_get_json_print_ops(flags);
	else if (flags & BINARY)
		ops = fdp_get_binary_print_ops(flags);
	else
		ops = fdp_get_stdout_print_ops(flags);

	return ops;
}

void fdp_show_configs(struct nvme_fdp_config_log *log, size_t len,
		      nvme_print_flags_t flags)
{
	fdp_print(config_log, flags, log, len);
}

void fdp_show_usage(struct nvme_fdp_ruhu_log *log, size_t len,
		    nvme_print_flags_t flags)
{
	fdp_print(usage_log, flags, log, len);
}

void fdp_show_stats(struct nvme_fdp_stats_log *log, nvme_print_flags_t flags)
{
	fdp_print(stats_log, flags, log);
}

void fdp_show_events(struct nvme_fdp_events_log *log,
		     nvme_print_flags_t flags)
{
	fdp_print(event_log, flags, log);
}

void fdp_show_ruh_status(struct nvme_fdp_ruh_status *status, size_t len,
			 nvme_print_flags_t flags)
{
	fdp_print(ruh_status, flags, status, len);
}

static bool fdp_show_log(const char *devname, enum nvme_cmd_get_log_lid lid,
			 __u32 nsid, __u16 lsi, __u8 lsp, void *log,
			 __u32 len, nvme_print_flags_t flags)
{
	switch (lid) {
	case NVME_LOG_LID_FDP_CONFIGS:
		fdp_show_configs(log, len, flags);
		break;
	case NVME_LOG_LID_FDP_RUH_USAGE:
		fdp_show_usage(log, len, flags);
		break;
	case NVME_LOG_LID_FDP_STATS:
		fdp_show_stats(log, flags);
		break;
	case NVME_LOG_LID_FDP_EVENTS:
		fdp_show_events(log, flags);
		break;
	default:
		return false;
	}

	return true;
}

static struct nvme_log_decoder fdp_log_decoder = {
	.show = fdp_show_log,
};

void fdp_register_log_decoder(void)
{
	nvme_register_log_decoder(&fdp_log_decoder);
}
