// SPDX-License-Identifier: GPL-2.0-or-later

#include <inttypes.h>
#include <stdio.h>

#include <libnvme.h>

#include <ccan/endian/endian.h>
#include <shared/table-util.h>

#include "dir-print.h"
#include "nvme-print.h"
#include "nvme-print-stdout.h"

static struct dir_print_ops dir_stdout_print_ops;

static void stdout_directive_show_fields(__u8 dtype, __u8 doper,
					 unsigned int result,
					 unsigned char *buf, __u32 len)
{
	struct nvme_streams_directive_params *params = (void *)buf;
	struct nvme_streams_directive_status *status = (void *)buf;
	__u8 *field = buf;
	int count, i;
	struct shr_table *t;

	switch (dtype) {
	case NVME_DIRECTIVE_DTYPE_IDENTIFY:
		switch (doper) {
		case NVME_DIRECTIVE_RECEIVE_IDENTIFY_DOPER_PARAM:
			if (len < NVME_DIRECTIVE_IDENTIFY_PARAM_LEN) {
				fprintf(stderr, "directive data too short\n");
				break;
			}
			printf("\tDirective support\n");

			t = stdout_kv_table_create();
			if (!t)
				return;

			shr_table_set_indent(t, 2);
			stdout_kv_add(t, "Identify Directive", "%s",
				      (*field & 0x1) ?
				      "supported" : "not supported");
			stdout_kv_add(t, "Stream Directive", "%s",
				      (*field & 0x2) ?
				      "supported" : "not supported");
			stdout_kv_add(t, "Data Placement Directive", "%s",
				      (*field & 0x4) ?
				      "supported" : "not supported");

			stdout_kv_table_finish(t, "directive-show");

			printf("\tDirective enabled\n");

			t = stdout_kv_table_create();
			if (!t)
				return;

			shr_table_set_indent(t, 2);
			stdout_kv_add(t, "Identify Directive", "%s",
				      (*(field + 32) & 0x1) ?
				      "enabled" : "disabled");
			stdout_kv_add(t, "Stream Directive", "%s",
				      (*(field + 32) & 0x2) ?
				      "enabled" : "disabled");
			stdout_kv_add(t, "Data Placement Directive", "%s",
				      (*(field + 32) & 0x4) ?
				      "enabled" : "disabled");

			stdout_kv_table_finish(t, "directive-show");

			printf(
			    "\tDirective Persistent Across Controller Level Resets\n");

			t = stdout_kv_table_create();
			if (!t)
				return;

			shr_table_set_indent(t, 2);
			stdout_kv_add(t, "Identify Directive", "%s",
				      (*(field + 64) & 0x1) ?
				      "enabled" : "disabled");
			stdout_kv_add(t, "Stream Directive", "%s",
				      (*(field + 64) & 0x2) ?
				      "enabled" : "disabled");
			stdout_kv_add(t, "Data Placement Directive", "%s",
				      (*(field + 64) & 0x4) ?
				      "enabled" : "disabled");

			stdout_kv_table_finish(t, "directive-show");
			break;
		default:
			fprintf(stderr,
				"invalid directive operations for Identify Directives\n");
			break;
		}
		break;
	case NVME_DIRECTIVE_DTYPE_STREAMS:
		switch (doper) {
		case NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_PARAM:
			if (len < sizeof(*params)) {
				fprintf(stderr, "directive data too short\n");
				break;
			}
			t = stdout_kv_table_create();
			if (!t)
				return;

			stdout_kv_add(t, "Max Streams Limit (MSL)", "%u",
				      le16_to_cpu(params->msl));
			stdout_kv_add(t,
				      "NVM Subsystem Streams Available (NSSA)",
				      "%u", le16_to_cpu(params->nssa));
			stdout_kv_add(t,
				      "NVM Subsystem Streams Open (NSSO)",
				      "%u", le16_to_cpu(params->nsso));
			stdout_kv_add(t,
				      "NVM Subsystem Stream Capability (NSSC)",
				      "%u", params->nssc);
			stdout_kv_add(t,
				      "Stream Write Size (in unit of LB size) (SWS)",
				      "%u", le32_to_cpu(params->sws));
			stdout_kv_add(t,
				      "Stream Granularity Size (in unit of SWS) (SGS)",
				      "%u", le16_to_cpu(params->sgs));
			stdout_kv_add(t,
				      "Namespace Streams Allocated (NSA)",
				      "%u", le16_to_cpu(params->nsa));
			stdout_kv_add(t, "Namespace Streams Open (NSO)", "%u",
				      le16_to_cpu(params->nso));

			stdout_kv_table_finish(t, "directive-show");
			break;
		case NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_STATUS:
			if (len < sizeof(*status)) {
				fprintf(stderr, "directive data too short\n");
				break;
			}
			count = nvme_streams_status_nr_sid(status, len);

			t = stdout_kv_table_create();
			if (!t)
				return;

			stdout_kv_add(t, "Open Stream Count", "%u",
				      le16_to_cpu(status->osc));
			for (i = 0; i < count; i++) {
				char name[32];

				snprintf(name, sizeof(name),
					 "Stream Identifier %.6u", i + 1);
				stdout_kv_add(t, name, "%u",
					      le16_to_cpu(status->sid[i]));
			}

			stdout_kv_table_finish(t, "directive-show");
			break;
		case NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_RESOURCE:
			t = stdout_kv_table_create();
			if (!t)
				return;

			stdout_kv_add(t, "Namespace Streams Allocated (NSA)",
				      "%u", result & 0xffff);

			stdout_kv_table_finish(t, "directive-show");
			break;
		default:
			fprintf(stderr,
				"invalid directive operations for Streams Directives\n");
			break;
		}
		break;
	default:
		fprintf(stderr, "invalid directive type\n");
		break;
	}
}

static void stdout_directive_show(__u8 type, __u8 oper, __u16 spec,
				  __u32 nsid, __u64 result, void *buf,
				  __u32 len)
{
	printf("dir-receive: type:%#x operation:%#x spec:%#x nsid:%#x result:%#"
	       PRIx64 "\n", type, oper, spec, nsid, (uint64_t)result);
	if (dir_stdout_print_ops.flags & VERBOSE)
		stdout_directive_show_fields(type, oper, result, buf, len);
	else if (buf)
		d(buf, len, 16, 1);
}

static struct dir_print_ops dir_stdout_print_ops = {
	.directive	= stdout_directive_show,
};

struct dir_print_ops *dir_get_stdout_print_ops(nvme_print_flags_t flags)
{
	dir_stdout_print_ops.flags = flags;
	return &dir_stdout_print_ops;
}
