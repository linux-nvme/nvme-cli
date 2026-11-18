// SPDX-License-Identifier: GPL-2.0-or-later

#include <libnvme.h>

#include <ccan/endian/endian.h>
#include <ccan/minmax/minmax.h>

#include "fabrics-print.h"
#include "nvme-print.h"

/*
 * Like nvme_print(), silently skip printers that an output format does
 * not implement.
 */
#define fabrics_print(name, sandbox, flags, ...)			\
	do {								\
		struct fabrics_print_ops *__fops =			\
			fabrics_print_ops(flags);			\
									\
		if (__fops && __fops->name)				\
			nvme_print_decoder(__fops, name, sandbox,	\
					   flags, ##__VA_ARGS__);	\
	} while (false)

static struct fabrics_print_ops *fabrics_print_ops(nvme_print_flags_t flags)
{
	struct fabrics_print_ops *ops = NULL;

	if (flags & JSON || nvme_is_output_format_json())
		ops = fabrics_get_json_print_ops(flags);
	else if (flags & BINARY)
		ops = fabrics_get_binary_print_ops(flags);
	else
		ops = fabrics_get_stdout_print_ops(flags);

	return ops;
}

/* The log page comes from the device: decode it in the sandbox */
void fabrics_show_discovery_log(const struct nvmf_discovery_log *log,
				uint64_t numrec, nvme_print_flags_t flags)
{
	fabrics_print(discovery_log, true, flags, log, numrec);
}

/* The configuration is no device data: print it in process */
void fabrics_show_config_conn_list(struct libnvmf_config *config,
				   nvme_print_flags_t flags)
{
	fabrics_print(config_conn_list, false, flags, config);
}

static bool fabrics_show_log(const char *devname,
			     enum nvme_cmd_get_log_lid lid, __u32 nsid,
			     __u16 lsi, __u8 lsp, void *log, __u32 len,
			     nvme_print_flags_t flags)
{
	struct nvmf_discovery_log *discovery_log = log;
	__u64 nr;

	if (lid != NVME_LOG_LID_DISCOVERY)
		return false;

	/* no more records than the log holds, before size_t cuts it */
	nr = min_t(__u64, le64_to_cpu(discovery_log->numrec), len);
	fabrics_show_discovery_log(discovery_log,
		nvme_log_nr_entries(nr, len, sizeof(*discovery_log),
				    sizeof(discovery_log->entries[0])),
		flags);

	return true;
}

static struct nvme_log_decoder fabrics_log_decoder = {
	.show = fabrics_show_log,
};

void fabrics_register_log_decoder(void)
{
	nvme_register_log_decoder(&fabrics_log_decoder);
}
