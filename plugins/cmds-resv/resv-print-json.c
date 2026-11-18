// SPDX-License-Identifier: GPL-2.0-or-later

#include <libnvme.h>

#include <ccan/endian/endian.h>
#include <shared/hex-util.h>

#include "nvme-print.h"
#include "nvme-print-json.h"
#include "resv-print.h"

static void json_nvme_resv_report(struct nvme_resv_status *status,
				  int bytes, bool eds)
{
	struct json_object *r = json_root();
	struct json_object *rcs = json_create_array();
	int i, entries;
	int regstrnt = status->regstrnt[0] | (status->regstrnt[1] << 8);

	obj_add_uint(r, "gen", le32_to_cpu(status->gen));
	obj_add_int(r, "rtype", status->rtype);
	obj_add_int(r, "regstrnt", regstrnt);
	obj_add_int(r, "ptpls", status->ptpls);

	/* check Extended Data Structure bit */
	if (!eds) {
		/*
		 * if status buffer was too small, don't loop past the end of
		 * the buffer
		 */
		entries = (bytes - 24) / 24;
		if (entries < regstrnt)
			regstrnt = entries;

		obj_add_array(r, "registrants", rcs);
		for (i = 0; i < regstrnt; i++) {
			struct json_object *rc = json_create_object();

			obj_add_int(rc, "cntlid",
				le16_to_cpu(status->registrant_ds[i].cntlid));
			obj_add_int(rc, "rcsts",
				    status->registrant_ds[i].rcsts);
			obj_add_uint64(rc, "hostid",
				le64_to_cpu(status->registrant_ds[i].hostid));
			obj_add_uint64(rc, "rkey",
				le64_to_cpu(status->registrant_ds[i].rkey));

			array_add_obj(rcs, rc);
		}
	} else {
		char hostid[33];

		/*
		 * if status buffer was too small, don't loop past the end of
		 * the buffer
		 */
		entries = (bytes - 64) / 64;

		if (entries < regstrnt)
			regstrnt = entries;

		obj_add_array(r, "registrantext", rcs);

		for (i = 0; i < regstrnt; i++) {
			struct json_object *rc = json_create_object();

			obj_add_int(rc, "cntlid",
				le16_to_cpu(status->registrant_eds[i].cntlid));
			obj_add_int(rc, "rcsts",
				    status->registrant_eds[i].rcsts);
			obj_add_uint64(rc, "rkey",
				le64_to_cpu(status->registrant_eds[i].rkey));

			shr_bin_to_hex(hostid, sizeof(hostid),
				       status->registrant_eds[i].hostid,
				       sizeof(status->registrant_eds[i].hostid),
				       0);

			obj_add_str(rc, "hostid", hostid);
			array_add_obj(rcs, rc);
		}
	}
}

static struct resv_print_ops resv_json_print_ops = {
	.resv_report	= json_nvme_resv_report,
};

struct resv_print_ops *resv_get_json_print_ops(nvme_print_flags_t flags)
{
	resv_json_print_ops.flags = flags;
	return &resv_json_print_ops;
}
