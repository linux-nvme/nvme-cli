// SPDX-License-Identifier: GPL-2.0-or-later

#include <libnvme.h>

#include "nvme-print.h"
#include "zns-print.h"

/*
 * Run the printers in the sandbox, except for the zone list printers, which
 * pass a JSON object from one call to the next. Like nvme_print(), silently
 * skip printers that an output format does not implement.
 */
#define zns_print(name, sandbox, flags, ...)				\
	do {								\
		struct zns_print_ops *__zops = zns_print_ops(flags);	\
									\
		if (__zops && __zops->name)				\
			nvme_print_decoder(__zops, name, sandbox, flags, \
					   ##__VA_ARGS__);		\
	} while (false)

static struct zns_print_ops *zns_print_ops(nvme_print_flags_t flags)
{
	struct zns_print_ops *ops = NULL;

	if (flags & JSON || nvme_is_output_format_json())
		ops = zns_get_json_print_ops(flags);
	else if (flags & BINARY)
		ops = zns_get_binary_print_ops(flags);
	else
		ops = zns_get_stdout_print_ops(flags);

	return ops;
}

const char *zns_zone_type_to_string(__u8 cond)
{
	switch (cond) {
	case NVME_ZONE_TYPE_SEQWRITE_REQ:
		return "SEQWRITE_REQ";
	default:
		return "Unknown";
	}
}

const char *zns_zone_state_to_string(__u8 state)
{
	switch (state) {
	case NVME_ZNS_ZS_EMPTY:
		return "EMPTY";
	case NVME_ZNS_ZS_IMPL_OPEN:
		return "IMP_OPENED";
	case NVME_ZNS_ZS_EXPL_OPEN:
		return "EXP_OPENED";
	case NVME_ZNS_ZS_CLOSED:
		return "CLOSED";
	case NVME_ZNS_ZS_READ_ONLY:
		return "READONLY";
	case NVME_ZNS_ZS_FULL:
		return "FULL";
	case NVME_ZNS_ZS_OFFLINE:
		return "OFFLINE";
	default:
		return "Unknown State";
	}
}

void zns_show_id_ctrl(struct nvme_zns_id_ctrl *ctrl,
		      nvme_print_flags_t flags)
{
	zns_print(id_ctrl, true, flags, ctrl);
}

void zns_show_id_ns(struct nvme_zns_id_ns *ns, struct nvme_id_ns *id_ns,
		    nvme_print_flags_t flags)
{
	zns_print(id_ns, true, flags, ns, id_ns);
}

void zns_show_changed(struct nvme_zns_changed_zone_log *log,
		      nvme_print_flags_t flags)
{
	zns_print(changed_zone_log, true, flags, log);
}

/* Log page decoder for get-log -v, see nvme_show_log() */
bool zns_show_log(const char *devname, enum nvme_cmd_get_log_lid lid,
		  __u32 nsid, __u16 lsi, __u8 lsp, void *log, __u32 len,
		  nvme_print_flags_t flags)
{
	if (lid != NVME_LOG_LID_ZNS_CHANGED_ZONES)
		return false;

	zns_show_changed(log, flags);
	return true;
}

void zns_start_zone_list(__u64 nr_zones, struct json_object **zone_list,
			 nvme_print_flags_t flags)
{
	zns_print(start_zone_list, false, flags, nr_zones, zone_list);
}

void zns_show_report_zones(void *report, __u32 descs, __u8 ext_size,
			   __u32 report_size, struct json_object *zone_list,
			   nvme_print_flags_t flags)
{
	zns_print(report_zones, false, flags, report, descs, ext_size,
		  report_size, zone_list);
}

void zns_finish_zone_list(__u64 nr_zones, struct json_object *zone_list,
			  nvme_print_flags_t flags)
{
	zns_print(finish_zone_list, false, flags, nr_zones, zone_list);
}
