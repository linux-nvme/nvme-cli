// SPDX-License-Identifier: GPL-2.0-or-later

#include <libnvme.h>

#include "nvme-print.h"
#include "zns-print.h"

static void binary_id_ctrl(struct nvme_zns_id_ctrl *ctrl)
{
	d_raw((unsigned char *)ctrl, sizeof(*ctrl));
}

static void binary_id_ns(struct nvme_zns_id_ns *ns, struct nvme_id_ns *id_ns)
{
	d_raw((unsigned char *)ns, sizeof(*ns));
}

static void binary_changed_zone_log(struct nvme_zns_changed_zone_log *log)
{
	d_raw((unsigned char *)log, sizeof(*log));
}

static void binary_report_zones(void *report, __u32 descs, __u8 ext_size,
				__u32 report_size,
				struct json_object *zone_list)
{
	d_raw((unsigned char *)report, report_size);
}

static struct zns_print_ops binary_print_ops = {
	.id_ctrl		= binary_id_ctrl,
	.id_ns			= binary_id_ns,
	.changed_zone_log	= binary_changed_zone_log,
	.start_zone_list	= NULL,
	.report_zones		= binary_report_zones,
	.finish_zone_list	= NULL,
};

struct zns_print_ops *zns_get_binary_print_ops(nvme_print_flags_t flags)
{
	binary_print_ops.flags = flags;
	return &binary_print_ops;
}
