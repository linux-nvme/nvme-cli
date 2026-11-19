// SPDX-License-Identifier: GPL-2.0-or-later

#include <libnvme.h>

#include <ccan/array_size/array_size.h>
#include <ccan/endian/endian.h>

#include "nvme-print-json.h"
#include "nvme-print.h"
#include "zns-print.h"

static void json_id_ctrl(struct nvme_zns_id_ctrl *ctrl)
{
	struct json_object *r = json_root();

	obj_add_int(r, "zasl", ctrl->zasl);
}

static void json_id_ns(struct nvme_zns_id_ns *ns, struct nvme_id_ns *id_ns)
{
	struct json_object *r = json_root();
	struct json_object *lbafs = json_create_array();
	int i;

	obj_add_int(r, "zoc", le16_to_cpu(ns->zoc));
	obj_add_int(r, "ozcs", le16_to_cpu(ns->ozcs));
	obj_add_uint(r, "mar", le32_to_cpu(ns->mar));
	obj_add_uint(r, "mor", le32_to_cpu(ns->mor));
	obj_add_uint(r, "rrl", le32_to_cpu(ns->rrl));
	obj_add_uint(r, "frl", le32_to_cpu(ns->frl));
	obj_add_uint(r, "rrl1", le32_to_cpu(ns->rrl1));
	obj_add_uint(r, "rrl2", le32_to_cpu(ns->rrl2));
	obj_add_uint(r, "rrl3", le32_to_cpu(ns->rrl3));
	obj_add_uint(r, "frl1", le32_to_cpu(ns->frl1));
	obj_add_uint(r, "frl2", le32_to_cpu(ns->frl2));
	obj_add_uint(r, "frl3", le32_to_cpu(ns->frl3));
	obj_add_uint(r, "numzrwa", le32_to_cpu(ns->numzrwa));
	obj_add_int(r, "zrwafg", le16_to_cpu(ns->zrwafg));
	obj_add_int(r, "zrwasz", le16_to_cpu(ns->zrwasz));
	obj_add_int(r, "zrwacap", ns->zrwacap);

	obj_add_array(r, "lbafe", lbafs);

	for (i = 0; i <= id_ns->nlbaf && i < ARRAY_SIZE(ns->lbafe); i++) {
		struct json_object *lbaf = json_create_object();

		obj_add_uint64(lbaf, "zsze", le64_to_cpu(ns->lbafe[i].zsze));
		obj_add_int(lbaf, "zdes", ns->lbafe[i].zdes);

		array_add_obj(lbafs, lbaf);
	}
}

static void json_changed_zone_log(struct nvme_zns_changed_zone_log *log)
{
	struct json_object *r = json_root();
	char json_str[STR_LEN];
	uint16_t nrzid = le16_to_cpu(log->nrzid);
	int i;

	if (nrzid == 0xFFFF) {
		obj_add_result(r,
			"Too many zones have changed to fit into the log. Use report zones for changes.");
	} else {
		obj_add_uint(r, "nrzid", nrzid);
		for (i = 0; i < nrzid && i < ARRAY_SIZE(log->zid); i++) {
			sprintf(json_str, "zid %03d", i);
			obj_add_uint64(r, json_str,
				       (uint64_t)le64_to_cpu(log->zid[i]));
		}
	}
}

static void json_start_zone_list(__u64 nr_zones,
				 struct json_object **zone_list)
{
	*zone_list = json_create_array();
}

static void json_report_zones(void *report, __u32 descs, __u8 ext_size,
			      __u32 report_size,
			      struct json_object *zone_list)
{
	struct json_object *zone;
	struct nvme_zone_report *r = report;
	struct nvme_zns_desc *desc;
	int i;

	for (i = 0; i < descs; i++) {
		desc = (struct nvme_zns_desc *)
			(report + sizeof(*r) + i * (sizeof(*desc) + ext_size));
		zone = json_create_object();

		obj_add_uint64(zone, "slba", le64_to_cpu(desc->zslba));
		obj_add_uint64(zone, "wp", le64_to_cpu(desc->wp));
		obj_add_uint64(zone, "cap", le64_to_cpu(desc->zcap));
		obj_add_str(zone, "state",
			    zns_zone_state_to_string(desc->zs >> 4));
		obj_add_str(zone, "type", zns_zone_type_to_string(desc->zt));
		obj_add_uint(zone, "attrs", desc->za);
		obj_add_uint(zone, "attrs_info", desc->zai);

		if (ext_size) {
			if (desc->za & NVME_ZNS_ZA_ZDEV)
				obj_d(zone, "ext_data",
				      (unsigned char *)desc + sizeof(*desc),
				      ext_size, 16, 1);
			else
				obj_add_str(zone, "ext_data", "Not valid");
		}

		array_add_obj(zone_list, zone);
	}
}

static void json_finish_zone_list(__u64 nr_zones,
				  struct json_object *zone_list)
{
	struct json_object *r = json_root();

	obj_add_uint(r, "nr_zones", nr_zones);
	obj_add_array(r, "zone_list", zone_list);
}

static struct zns_print_ops json_print_ops = {
	.id_ctrl		= json_id_ctrl,
	.id_ns			= json_id_ns,
	.changed_zone_log	= json_changed_zone_log,
	.start_zone_list	= json_start_zone_list,
	.report_zones		= json_report_zones,
	.finish_zone_list	= json_finish_zone_list,
};

struct zns_print_ops *zns_get_json_print_ops(nvme_print_flags_t flags)
{
	json_print_ops.flags = flags;
	return &json_print_ops;
}
