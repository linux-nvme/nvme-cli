/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include <libnvme.h>

#include "args.h"

struct json_object;

struct zns_print_ops {
	void (*id_ctrl)(struct nvme_zns_id_ctrl *ctrl);
	void (*id_ns)(struct nvme_zns_id_ns *ns, struct nvme_id_ns *id_ns);
	void (*changed_zone_log)(struct nvme_zns_changed_zone_log *log);
	void (*start_zone_list)(__u64 nr_zones,
				struct json_object **zone_list);
	void (*report_zones)(void *report, __u32 descs, __u8 ext_size,
			     __u32 report_size, struct json_object *zone_list);
	void (*finish_zone_list)(__u64 nr_zones,
				 struct json_object *zone_list);
	nvme_print_flags_t flags;
};

struct zns_print_ops *zns_get_stdout_print_ops(nvme_print_flags_t flags);
struct zns_print_ops *zns_get_binary_print_ops(nvme_print_flags_t flags);

#ifdef CONFIG_JSONC
struct zns_print_ops *zns_get_json_print_ops(nvme_print_flags_t flags);
#else
static inline struct zns_print_ops *
zns_get_json_print_ops(nvme_print_flags_t flags)
{
	return NULL;
}
#endif

const char *zns_zone_type_to_string(__u8 cond);
const char *zns_zone_state_to_string(__u8 state);

void zns_show_id_ctrl(struct nvme_zns_id_ctrl *ctrl,
		      nvme_print_flags_t flags);
void zns_show_id_ns(struct nvme_zns_id_ns *ns, struct nvme_id_ns *id_ns,
		    nvme_print_flags_t flags);
void zns_show_changed(struct nvme_zns_changed_zone_log *log,
		      nvme_print_flags_t flags);
bool zns_show_log(const char *devname, enum nvme_cmd_get_log_lid lid,
		  __u32 nsid, __u16 lsi, __u8 lsp, void *log, __u32 len,
		  nvme_print_flags_t flags);
void zns_start_zone_list(__u64 nr_zones, struct json_object **zone_list,
			 nvme_print_flags_t flags);
void zns_show_report_zones(void *report, __u32 descs, __u8 ext_size,
			   __u32 report_size, struct json_object *zone_list,
			   nvme_print_flags_t flags);
void zns_finish_zone_list(__u64 nr_zones, struct json_object *zone_list,
			  nvme_print_flags_t flags);
