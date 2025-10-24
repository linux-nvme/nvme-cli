// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2022-2024 Solidigm.
 *
 * Author: leonardo.da.cunha@solidigm.com
 */

#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>

#include "common.h"
#include "nvme.h"
#include "libnvme.h"
#include "plugin.h"
#include "linux/types.h"
#include "nvme-print.h"
#include "solidigm-garbage-collection.h"
#include "solidigm-util.h"

struct __packed gc_item {
	__le32 timer_type;
	__le64 timestamp;
};

#define VU_GC_MAX_ITEMS 100
struct garbage_control_collection_log {
	__le16 version_major;
	__le16 version_minor;
	struct __packed gc_item item[VU_GC_MAX_ITEMS];
	__u8 reserved[2892];
};

static void vu_gc_log_show_json(struct garbage_control_collection_log *payload, const char *devname)
{
	struct json_object *gc_entries = json_create_array();

	for (int i = 0; i < VU_GC_MAX_ITEMS; i++) {
		struct __packed gc_item item = payload->item[i];
		struct json_object *entry = json_create_object();

		json_object_add_value_int(entry, "timestamp", le64_to_cpu(item.timestamp));
		json_object_add_value_int(entry, "timer_type", le32_to_cpu(item.timer_type));
		json_array_add_value_object(gc_entries, entry);
	}

	json_print_object(gc_entries, NULL);
	json_free_object(gc_entries);
}

static void vu_gc_log_show(struct garbage_control_collection_log *payload, const char *devname,
			   __u8 uuid_index)
{
	printf("Solidigm Garbage Collection Log for NVME device:%s UUID-idx:%d\n", devname,
	       uuid_index);
	printf("Timestamp     Timer Type\n");

	for (int i = 0; i < VU_GC_MAX_ITEMS; i++) {
		struct __packed gc_item item = payload->item[i];

		printf("%-13" PRIu64 " %d\n", le64_to_cpu(item.timestamp), le32_to_cpu(item.timer_type));
	}
}

int solidigm_get_garbage_collection_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Get and parse Solidigm vendor specific garbage collection event log.";
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	nvme_print_flags_t flags;
	int err;
	__u8 uuid_index;

	struct config {
		char	*output_format;
	};

	struct config cfg = {
		.output_format	= "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format",   'o', &cfg.output_format,  output_format),
		OPT_END()
	};

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(cfg.output_format, &flags);
	if (err) {
		fprintf(stderr, "Invalid output format '%s'\n", cfg.output_format);
		return -EINVAL;
	}

	sldgm_get_uuid_index(hdl, &uuid_index);

	struct garbage_control_collection_log gc_log;
	const int solidigm_vu_gc_log_id = 0xfd;
	struct nvme_get_log_args args = {
		.lpo = 0,
		.result = NULL,
		.log = &gc_log,
		.args_size = sizeof(args),
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.lid = solidigm_vu_gc_log_id,
		.len = sizeof(gc_log),
		.nsid = NVME_NSID_ALL,
		.csi = NVME_CSI_NVM,
		.lsi = NVME_LOG_LSI_NONE,
		.lsp = NVME_LOG_LSP_NONE,
		.uuidx = uuid_index,
		.rae = false,
		.ot = false,
	};

	err =  nvme_get_log(hdl, &args);
	if (!err) {
		if (flags & BINARY)
			d_raw((unsigned char *)&gc_log, sizeof(gc_log));
		else if (flags & JSON)
			vu_gc_log_show_json(&gc_log, nvme_transport_handle_get_name(hdl));
		else
			vu_gc_log_show(&gc_log, nvme_transport_handle_get_name(hdl), uuid_index);
	} else if (err > 0) {
		nvme_show_status(err);
	}

	return err;
}
