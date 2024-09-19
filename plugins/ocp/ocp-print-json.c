// SPDX-License-Identifier: GPL-2.0-or-later
#include "util/types.h"
#include "common.h"
#include "nvme-print.h"
#include "ocp-print.h"
#include "ocp-hardware-component-log.h"

static void print_hwcomp_desc_json(struct hwcomp_desc_entry *e, struct json_object *r)
{
	obj_add_str(r, "Description", hwcomp_id_to_string(le32_to_cpu(e->desc->id)));
	obj_add_nprix64(r, "Date/Lot Size", e->date_lot_size);
	obj_add_nprix64(r, "Additional Information Size", e->add_info_size);
	obj_add_uint_0nx(r, "Identifier", le32_to_cpu(e->desc->id), 8);
	obj_add_0nprix64(r, "Manufacture", le64_to_cpu(e->desc->mfg), 16);
	obj_add_0nprix64(r, "Revision", le64_to_cpu(e->desc->rev), 16);
	obj_add_0nprix64(r, "Manufacture Code", le64_to_cpu(e->desc->mfg_code), 16);
	obj_add_byte_array(r, "Date/Lot Code", e->date_lot_code, e->date_lot_size);
	obj_add_byte_array(r, "Additional Information", e->add_info, e->add_info_size);
}

static void print_hwcomp_desc_list_json(struct json_object *r, struct hwcomp_desc_entry *e,
					bool list, int num)
{
	_cleanup_free_ char *k = NULL;

	if (asprintf(&k, "Component %d", num) < 0)
		return;

	if (list) {
		obj_add_str(r, k, hwcomp_id_to_string(le32_to_cpu(e->desc->id)));
		return;
	}

	print_hwcomp_desc_json(e, obj_create_array_obj(r, k));
}

static void print_hwcomp_descs_json(struct hwcomp_desc *desc, long double log_size, __u32 id,
				    bool list, struct json_object *r)
{
	size_t date_lot_code_offset = sizeof(struct hwcomp_desc);
	struct hwcomp_desc_entry e = { desc };
	int num = 1;

	while (log_size > 0) {
		e.date_lot_size = le64_to_cpu(e.desc->date_lot_size) * sizeof(__le32);
		e.date_lot_code = e.date_lot_size ?
		    (__u8 *)e.desc + date_lot_code_offset : NULL;
		e.add_info_size = le64_to_cpu(e.desc->add_info_size) * sizeof(__le32);
		e.add_info = e.add_info_size ? e.date_lot_code ?
		    e.date_lot_code + e.date_lot_size :
		    (__u8 *)e.desc + date_lot_code_offset : NULL;
		if (!id || id == le32_to_cpu(e.desc->id))
			print_hwcomp_desc_list_json(r, &e, list, num++);
		e.desc_size = date_lot_code_offset + e.date_lot_size + e.add_info_size;
		e.desc = (struct hwcomp_desc *)((__u8 *)e.desc + e.desc_size);
		log_size -= e.desc_size;
	}
}

static void json_hwcomp_log(struct hwcomp_log *log, __u32 id, bool list)
{
	struct json_object *r = json_create_object();

	long double log_size = uint128_t_to_double(le128_to_cpu(log->size)) * sizeof(__le32);

	obj_add_uint_02x(r, "Log Identifier", LID_HWCOMP);
	obj_add_uint_0x(r, "Log Page Version", le16_to_cpu(log->ver));
	obj_add_byte_array(r, "Reserved2", log->rsvd2, ARRAY_SIZE(log->rsvd2));
	obj_add_byte_array(r, "Log page GUID", log->guid, ARRAY_SIZE(log->guid));
	obj_add_nprix64(r, "Hardware Component Log Size", (unsigned long long)log_size);
	obj_add_byte_array(r, "Reserved48", log->rsvd48, ARRAY_SIZE(log->rsvd48));
	print_hwcomp_descs_json(log->desc, log_size, id, list,
				obj_create_array_obj(r, "Component Descriptions"));

	json_print(r);
}

static struct ocp_print_ops json_print_ops = {
	.hwcomp_log = json_hwcomp_log,
};

struct ocp_print_ops *ocp_get_json_print_ops(nvme_print_flags_t flags)
{
	json_print_ops.flags = flags;
	return &json_print_ops;
}
