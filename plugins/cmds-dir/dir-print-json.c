// SPDX-License-Identifier: GPL-2.0-or-later

#include <inttypes.h>
#include <stdio.h>

#include <libnvme.h>

#include <ccan/endian/endian.h>

#include "dir-print.h"
#include "nvme-print.h"
#include "nvme-print-json.h"

static void json_directive_show_fields_identify(__u8 doper, __u8 *field,
						__u32 len,
						struct json_object *r)
{
	struct json_object *support;
	struct json_object *enabled;
	struct json_object *persistent;

	switch (doper) {
	case NVME_DIRECTIVE_RECEIVE_IDENTIFY_DOPER_PARAM:
		if (len < NVME_DIRECTIVE_IDENTIFY_PARAM_LEN) {
			obj_add_str(r, "Error", "directive data too short");
			break;
		}
		support = json_create_object();
		obj_add_obj(r, "Directive support", support);
		obj_add_str(support, "Identify Directive",
			    *field & 0x1 ? "Supported" : "Not supported");
		obj_add_str(support, "Stream Directive",
			    *field & 0x2 ? "Supported" : "Not supported");
		obj_add_str(support, "Data Placement Directive",
			    *field & 0x4 ? "Supported" : "Not supported");
		enabled = json_create_object();
		obj_add_obj(r, "Directive enabled", enabled);
		obj_add_str(enabled, "Identify Directive",
			    *(field + 32) & 0x1 ? "Enabled" : "Disabled");
		obj_add_str(enabled, "Stream Directive",
			    *(field + 32) & 0x2 ? "Enabled" : "Disabled");
		obj_add_str(enabled, "Data Placement Directive",
			    *(field + 32) & 0x4 ? "Enabled" : "Disabled");
		persistent = json_create_object();
		obj_add_obj(r,
			    "Directive Persistent Across Controller Level Resets",
			    persistent);
		obj_add_str(persistent, "Identify Directive",
			    *(field + 64) & 0x1 ? "Enabled" : "Disabled");
		obj_add_str(persistent, "Stream Directive",
			    *(field + 64) & 0x2 ? "Enabled" : "Disabled");
		obj_add_str(persistent, "Data Placement Directive",
			    *(field + 64) & 0x4 ? "Enabled" : "Disabled");
		break;
	default:
		obj_add_str(r, "Error",
			    "invalid directive operations for Identify Directives");
		break;
	}
}

static void json_directive_show_fields_streams(__u8 doper,
					       unsigned int result, __u8 *field,
					       __u32 len, struct json_object *r)
{
	struct nvme_streams_directive_params *params = (void *)field;
	struct nvme_streams_directive_status *status = (void *)field;
	int count;
	int i;
	char json_str[STR_LEN];

	switch (doper) {
	case NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_PARAM:
		if (len < sizeof(*params)) {
			obj_add_str(r, "Error", "directive data too short");
			break;
		}
		obj_add_uint(r, "Max Streams Limit (MSL)",
			     le16_to_cpu(params->msl));
		obj_add_uint(r, "NVM Subsystem Streams Available (NSSA)",
			     le16_to_cpu(params->nssa));
		obj_add_uint(r, "NVM Subsystem Streams Open (NSSO)",
			     le16_to_cpu(params->nsso));
		obj_add_uint(r, "NVM Subsystem Stream Capability (NSSC)",
			     params->nssc);
		obj_add_uint(r, "Stream Write Size (in unit of LB size) (SWS)",
			     le32_to_cpu(params->sws));
		obj_add_uint(r,
			     "Stream Granularity Size (in unit of SWS) (SGS)",
			     le16_to_cpu(params->sgs));
		obj_add_uint(r, "Namespace Streams Allocated (NSA)",
			     le16_to_cpu(params->nsa));
		obj_add_uint(r, "Namespace Streams Open (NSO)",
			     le16_to_cpu(params->nso));
		break;
	case NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_STATUS:
		if (len < sizeof(*status)) {
			obj_add_str(r, "Error", "directive data too short");
			break;
		}
		count = nvme_streams_status_nr_sid(status, len);
		obj_add_uint(r, "Open Stream Count", le16_to_cpu(status->osc));
		for (i = 0; i < count; i++) {
			sprintf(json_str, "Stream Identifier %.6u", i + 1);
			obj_add_uint(r, json_str, le16_to_cpu(status->sid[i]));
		}
		break;
	case NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_RESOURCE:
		obj_add_uint(r, "Namespace Streams Allocated (NSA)",
			     result & 0xffff);
		break;
	default:
		obj_add_str(r, "Error",
			    "invalid directive operations for Streams Directives");
		break;
	}
}

static void json_directive_show_fields(__u8 dtype, __u8 doper,
				       unsigned int result, __u8 *field,
				       __u32 len, struct json_object *r)
{
	switch (dtype) {
	case NVME_DIRECTIVE_DTYPE_IDENTIFY:
		json_directive_show_fields_identify(doper, field, len, r);
		break;
	case NVME_DIRECTIVE_DTYPE_STREAMS:
		json_directive_show_fields_streams(doper, result, field, len,
						   r);
		break;
	default:
		obj_add_str(r, "Error", "invalid directive type");
		break;
	}
}

static void json_directive_show(__u8 type, __u8 oper, __u16 spec,
				__u32 nsid, __u64 result, void *buf, __u32 len)
{
	struct json_object *r = json_root();
	char json_str[STR_LEN];

	sprintf(json_str, "%#x", type);
	obj_add_str(r, "Type", json_str);
	sprintf(json_str, "%#x", oper);
	obj_add_str(r, "Operation", json_str);
	sprintf(json_str, "%#x", spec);
	obj_add_str(r, "spec", json_str);
	sprintf(json_str, "%#x", nsid);
	obj_add_str(r, "NSID", json_str);
	sprintf(json_str, "%#"PRIx64, (uint64_t)result);
	obj_add_result(r, "%s", json_str);

	if (json_verbose_mode())
		json_directive_show_fields(type, oper, result, buf, len, r);
	else if (buf)
		obj_d(r, "data", buf, len, 16, 1);
}

static struct dir_print_ops dir_json_print_ops = {
	.directive	= json_directive_show,
};

struct dir_print_ops *dir_get_json_print_ops(nvme_print_flags_t flags)
{
	dir_json_print_ops.flags = flags;
	return &dir_json_print_ops;
}
