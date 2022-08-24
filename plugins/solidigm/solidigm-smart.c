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
#include <endian.h>

#include "common.h"
#include "nvme.h"
#include "libnvme.h"
#include "plugin.h"
#include "linux/types.h"
#include "nvme-print.h"

#include "solidigm-smart.h"

struct  __attribute__((packed)) nvme_additional_smart_log_item {
	__u8			id;
	__u8			_kp[2];
	__u8			normalized;
	__u8			_np;
	union __attribute__((packed)) {
		__u8		raw[6];
		struct __attribute__((packed))  wear_level {
			__le16	min;
			__le16	max;
			__le16	avg;
		} wear_level;
		struct __attribute__((packed)) thermal_throttle {
			__u8	pct;
			__u32	count;
		} thermal_throttle;
	} ;
	__u8			_rp;
} ;
typedef struct nvme_additional_smart_log_item smart_log_item_t;

#define VU_SMART_PAGE_SIZE 512
#define VU_SMART_MAX_ITEMS VU_SMART_PAGE_SIZE / sizeof(smart_log_item_t)
typedef struct vu_smart_log {
	smart_log_item_t item[VU_SMART_MAX_ITEMS];
} vu_smart_log_t;

static char *id_to_name(__u8 id)
{
	switch (id) {
	case 0x0D:
		return "soft_ecc_error_rate";
	case 0x05:
		return "relocatable_sector_count";
	case 0xAB:
		return "program_fail_count";
	case 0xAC:
		return "erase_fail_count";
	case 0xAD:
		return "wear_leveling_count";
	case 0xAE:
		return "unexpected_power_loss";
	case 0xB8:
		return "e2e_error_detect_count";
	case 0xC7:
		return "crc_error_count";
	case 0xE2:
		return "media_wear_percentage";
	case 0xE3:
		return "host_reads";
	case 0xE4:
		return "timed_work_load";
	case 0xE5:
		return "read_commands_in_flight_counter";
	case 0xE6:
		return "write_commands_in_flight_counter";
	case 0xEA:
		return "thermal_throttle_status";
	case 0xF0:
		return "retry_buffer_overflow_counter";
	case 0xF3:
		return "pll_lock_loss_counter";
	case 0xF4:
		return "nand_bytes_written";
	case 0xF5:
		return "host_bytes_written";
	case 0xF6:
		return "host_context_wear_used";
	case 0xF7:
		return "performance_status_indicator";
	case 0xF8:
		return "media_bytes_read";
	case 0xF9:
		return "available_fw_downgrades";
	case 0xFA:
		return "host_read_collision_count";
	case 0xFB:
		return "host_write_collision_count";
	case 0xFC:
		return "xor_pass_count";
	case 0xFD:
		return "xor_fail_count";
	case 0xFE:
		return "xor_invoked_count";
	default:
		return "unknown";
	}
}

static void smart_log_item_print(smart_log_item_t *item)
{
	if (!item->id) {
		return;
	}

	printf("%#x    %-45s  %3d         ",
		item->id, id_to_name(item->id), item->normalized);

	switch (item->id) {
	case 0xAD:
		printf("min: %u, max: %u, avg: %u\n",
			le16_to_cpu(item->wear_level.min),
			le16_to_cpu(item->wear_level.max),
			le16_to_cpu(item->wear_level.avg));
		return;
	case 0xEA:
		printf("%u%%, cnt: %u\n",
			item->thermal_throttle.pct,
			le32_to_cpu(item->thermal_throttle.count));
		return;
	default:
		printf("%"PRIu64"\n", int48_to_long(item->raw));
	}
}

static void smart_log_item_add_json(smart_log_item_t *item, struct json_object *dev_stats)
{
	struct json_object *entry_stats = json_create_object();

	if (!item->id) {
		return;
	}

	json_object_add_value_int(entry_stats, "normalized", item->normalized);

	switch (item->id) {
	case 0xAD:
		json_object_add_value_int(entry_stats, "min", le16_to_cpu(item->wear_level.min));
		json_object_add_value_int(entry_stats, "max", le16_to_cpu(item->wear_level.max));
		json_object_add_value_int(entry_stats, "avg", le16_to_cpu(item->wear_level.avg));
		break;
	case 0xEA:
		json_object_add_value_int(entry_stats, "percentage", item->thermal_throttle.pct);
		json_object_add_value_int(entry_stats, "count", le32_to_cpu(item->thermal_throttle.count));
		break;
	default:
		json_object_add_value_int(entry_stats, "raw", int48_to_long(item->raw));
	}
	json_object_add_value_object(dev_stats, id_to_name(item->id), entry_stats);
}

static void vu_smart_log_show_json(vu_smart_log_t *payload, unsigned int nsid, const char *devname)
{
	struct json_object *dev_stats = json_create_object();
	smart_log_item_t *item = payload->item;
	struct json_object *root;

	for (int i = 0; i < VU_SMART_MAX_ITEMS; i++) {
		smart_log_item_add_json(&item[i], dev_stats);
	}

	root = json_create_object();
	json_object_add_value_string(root, "Solidigm SMART log", devname);
	json_object_add_value_object(root, "Device stats", dev_stats);

	json_print_object(root, NULL);
	json_free_object(root);
}

static void vu_smart_log_show(vu_smart_log_t *payload, unsigned int nsid, const char *devname)
{
	smart_log_item_t *item = payload->item;

	printf("Additional Smart Log for NVME device:%s namespace-id:%x\n",
		devname, nsid);
	printf("ID             KEY                                 Normalized     Raw\n");

	for (int i = 0; i < VU_SMART_MAX_ITEMS; i++) {
		smart_log_item_print(&item[i]);
	}
}

int solidigm_get_additional_smart_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Get Solidigm vendor specific smart log (optionally, "\
		      "for the specified namespace), and show it.";
	const int solidigm_vu_smart_log_id = 0xCA;
	vu_smart_log_t smart_log_payload;
	enum nvme_print_flags flags;
	struct nvme_dev *dev;
	int err;

	struct config {
		__u32	namespace_id;
		char	*output_format;
	};

	struct config cfg = {
		.namespace_id	= NVME_NSID_ALL,
		.output_format	= "normal",
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id",   'n', &cfg.namespace_id,   "(optional) desired namespace"),
		OPT_FMT("output-format",   'o', &cfg.output_format,  output_format),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	flags = validate_output_format(cfg.output_format);
	if (flags == -EINVAL) {
		fprintf(stderr, "Invalid output format '%s'\n", cfg.output_format);
		dev_close(dev);
		return flags;
	}

	err = nvme_get_log_simple(dev_fd(dev), solidigm_vu_smart_log_id,
				  sizeof(smart_log_payload), &smart_log_payload);
	if (!err) {
		if (flags & JSON) {
			vu_smart_log_show_json(&smart_log_payload,
					       cfg.namespace_id, dev->name);
		} else if (flags & BINARY) {
			d_raw((unsigned char *)&smart_log_payload, sizeof(smart_log_payload));
		} else {
			vu_smart_log_show(&smart_log_payload, cfg.namespace_id,
					  dev->name);
		}
	} else if (err > 0) {
		nvme_show_status(err);
	}

	dev_close(dev);
	return err;
}

