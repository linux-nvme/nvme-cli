// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2022 Solidigm.
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

typedef struct __attribute__((packed)) gc_item {
	__le32 timer_type;
	__le64 timestamp;
} gc_item_t;

#define VU_GC_MAX_ITEMS 100
typedef struct garbage_control_collection_log {
	__le16 version_major;
	__le16 version_minor;
	gc_item_t item[VU_GC_MAX_ITEMS];
	__u8 reserved[2892];
} garbage_control_collection_log_t;

static void vu_gc_log_show_json(garbage_control_collection_log_t *payload, const char *devname)
{
	struct json_object *gc_entries = json_create_array();

	for (int i = 0; i < VU_GC_MAX_ITEMS; i++) {
		gc_item_t item = payload->item[i];
		struct json_object *entry = json_create_object();
		json_object_add_value_int(entry, "timestamp", le64_to_cpu(item.timestamp));
		json_object_add_value_int(entry, "timer_type", le32_to_cpu(item.timer_type));
		json_array_add_value_object(gc_entries, entry);
	}

	json_print_object(gc_entries, NULL);
	json_free_object(gc_entries);
}

static void vu_gc_log_show(garbage_control_collection_log_t *payload, const char *devname)
{
	printf("Solidigm Garbage Collection Log for NVME device: %s\n", devname);
	printf("Timestamp     Timer Type\n");

	for (int i = 0; i < VU_GC_MAX_ITEMS; i++) {
		gc_item_t item = payload->item[i];
		printf("%-13lu %d\n",le64_to_cpu(item.timestamp), le32_to_cpu(item.timer_type));
	}
}

int solidigm_get_garbage_collection_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Get and parse Solidigm vendor specific garbage collection event log.";
	struct nvme_dev *dev;
	int err;

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

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err < 0)
		return err;

	enum nvme_print_flags flags = validate_output_format(cfg.output_format);
	if (flags == -EINVAL) {
		fprintf(stderr, "Invalid output format '%s'\n", cfg.output_format);
		dev_close(dev);
		return flags;
	}

	garbage_control_collection_log_t gc_log;
	const int solidigm_vu_gc_log_id = 0xfd;

	err = nvme_get_log_simple(dev_fd(dev), solidigm_vu_gc_log_id,
				  sizeof(gc_log), &gc_log);
	if (!err) {
		if (flags & BINARY)	{
			d_raw((unsigned char *)&gc_log, sizeof(gc_log));
		} else if (flags & JSON) {
			vu_gc_log_show_json(&gc_log, dev->name);
		} else {
			vu_gc_log_show(&gc_log, dev->name);
		}
	}
	else if (err > 0) {
		nvme_show_status(err);
	}

	dev_close(dev);
	return err;
}
