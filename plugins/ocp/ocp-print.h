/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef OCP_PRINT_H
#define OCP_PRINT_H

#include "ocp-hardware-component-log.h"
#include "ocp-fw-activation-history.h"
#include "ocp-smart-extended-log.h"
#include "ocp-telemetry-decode.h"
#include "ocp-nvme.h"

struct ocp_print_ops {
	void (*hwcomp_log)(struct hwcomp_log *log, __u32 id, bool list);
	void (*fw_act_history)(const struct fw_activation_history *fw_history);
	void (*smart_extended_log)(struct ocp_smart_extended_log *log, unsigned int version);
	void (*telemetry_log)(struct ocp_telemetry_parse_options *options);
	void (*c3_log)(struct nvme_transport_handle *hdl, struct ssd_latency_monitor_log *log_data);
	void (*c5_log)(struct nvme_transport_handle *hdl, struct unsupported_requirement_log *log_data);
	void (*c1_log)(struct ocp_error_recovery_log_page *log_data);
	void (*c4_log)(struct ocp_device_capabilities_log_page *log_data);
	void (*c9_log)(struct telemetry_str_log_format *log_data, __u8 *log_data_buf,
		       int total_log_page_size);
	void (*c7_log)(struct nvme_transport_handle *hdl, struct tcg_configuration_log *log_data);
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
void ocp_fw_act_history(const struct fw_activation_history *fw_history, nvme_print_flags_t flags);
void ocp_smart_extended_log(struct ocp_smart_extended_log *log, unsigned int version,
		nvme_print_flags_t flags);
void ocp_show_telemetry_log(struct ocp_telemetry_parse_options *options, nvme_print_flags_t flags);
void ocp_c3_log(struct nvme_transport_handle *hdl, struct ssd_latency_monitor_log *log_data,
		nvme_print_flags_t flags);
void ocp_c5_log(struct nvme_transport_handle *hdl, struct unsupported_requirement_log *log_data,
		nvme_print_flags_t flags);
void ocp_c1_log(struct ocp_error_recovery_log_page *log_data, nvme_print_flags_t flags);
void ocp_c4_log(struct ocp_device_capabilities_log_page *log_data, nvme_print_flags_t flags);
void ocp_c9_log(struct telemetry_str_log_format *log_data, __u8 *log_data_buf,
		int total_log_page_size, nvme_print_flags_t flags);
void ocp_c7_log(struct nvme_transport_handle *hdl, struct tcg_configuration_log *log_data,
		nvme_print_flags_t flags);
#endif /* OCP_PRINT_H */
