// SPDX-License-Identifier: GPL-2.0-or-later

#include "util/types.h"
#include "nvme-print.h"
#include "ocp-print.h"
#include "ocp-hardware-component-log.h"

static void binary_hwcomp_log(struct hwcomp_log *log, __u32 id, bool list)
{
	long double log_bytes = uint128_t_to_double(le128_to_cpu(log->size));

	if (log->ver == 1)
		log_bytes *= sizeof(__le32);

	d_raw((unsigned char *)log, log_bytes);
}

static void binary_c5_log(struct nvme_transport_handle *hdl, struct unsupported_requirement_log *log_data)
{
	d_raw((unsigned char *)log_data, sizeof(*log_data));
}

static void binary_c1_log(struct ocp_error_recovery_log_page *log_data)
{
	d_raw((unsigned char *)log_data, sizeof(*log_data));
}

static void binary_c4_log(struct ocp_device_capabilities_log_page *log_data)
{
	d_raw((unsigned char *)log_data, sizeof(*log_data));
}

static void binary_c9_log(struct telemetry_str_log_format *log_data, __u8 *log_data_buf,
			  int total_log_page_size)
{
	d_raw((unsigned char *)log_data_buf, total_log_page_size);
}

static void binary_c7_log(struct nvme_transport_handle *hdl, struct tcg_configuration_log *log_data)
{
	d_raw((unsigned char *)log_data, sizeof(*log_data));
}

static struct ocp_print_ops binary_print_ops = {
	.hwcomp_log = binary_hwcomp_log,
	.c5_log = binary_c5_log,
	.c1_log = binary_c1_log,
	.c4_log = binary_c4_log,
	.c9_log = binary_c9_log,
	.c7_log = binary_c7_log,
};

struct ocp_print_ops *ocp_get_binary_print_ops(nvme_print_flags_t flags)
{
	binary_print_ops.flags = flags;
	return &binary_print_ops;
}
