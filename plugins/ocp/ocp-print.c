// SPDX-License-Identifier: GPL-2.0-or-later
#include "nvme-print.h"
#include "ocp-print.h"
#include "ocp-hardware-component-log.h"

#define ocp_print(name, flags, ...) \
	do { \
		struct ocp_print_ops *ops = ocp_print_ops(flags); \
		if (ops && ops->name) \
			ops->name(__VA_ARGS__); \
		else \
			fprintf(stderr, "unhandled output format\n"); \
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

void ocp_fw_act_history(const struct fw_activation_history *fw_history, nvme_print_flags_t flags)
{
	ocp_print(fw_act_history, flags, fw_history);
}

void ocp_smart_extended_log(struct ocp_smart_extended_log *log, unsigned int version,
		nvme_print_flags_t flags)
{
	ocp_print(smart_extended_log, flags, log, version);
}

void ocp_show_telemetry_log(struct ocp_telemetry_parse_options *options, nvme_print_flags_t flags)
{
	ocp_print(telemetry_log, flags, options);
}

void ocp_c3_log(struct nvme_transport_handle *hdl,
		struct ssd_latency_monitor_log *log_data,
		nvme_print_flags_t flags)
{
	ocp_print(c3_log, flags, hdl, log_data);
}

void ocp_c5_log(struct nvme_transport_handle *hdl,
		struct unsupported_requirement_log *log_data,
		nvme_print_flags_t flags)
{
	ocp_print(c5_log, flags, hdl, log_data);
}

void ocp_c1_log(struct ocp_error_recovery_log_page *log_data, nvme_print_flags_t flags)
{
	ocp_print(c1_log, flags, log_data);
}

void ocp_c4_log(struct ocp_device_capabilities_log_page *log_data, nvme_print_flags_t flags)
{
	ocp_print(c4_log, flags, log_data);
}

void ocp_c9_log(struct telemetry_str_log_format *log_data, __u8 *log_data_buf,
		int total_log_page_size, nvme_print_flags_t flags)
{
	ocp_print(c9_log, flags, log_data, log_data_buf, total_log_page_size);
}

void ocp_c7_log(struct nvme_transport_handle *hdl,
		struct tcg_configuration_log *log_data,
		nvme_print_flags_t flags)
{
	ocp_print(c7_log, flags, hdl, log_data);
}
