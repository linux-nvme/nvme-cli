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

#include "common.h"
#include "nvme.h"
#include "libnvme.h"
#include "plugin.h"
#include "linux/types.h"
#include "nvme-print.h"

#include "solidigm-smart.h"
#include "solidigm-util.h"

struct __packed nvme_additional_smart_log_item {
	__u8			id;
	__u8			_kp[2];
	__u8			normalized;
	__u8			_np;
	union __packed {
		__u8		raw[6];
		struct __packed  wear_level {
			__le16	min;
			__le16	max;
			__le16	avg;
		} wear_level;
		struct __packed thermal_throttle {
			__u8	pct;
			__u32	count;
		} thermal_throttle;
	};
	__u8			_rp;
};

struct __packed smart_ref_clk {
	__u8 id;
	__u8 _kp[2];
	__u8 normalized;
	__le16 gainCount0;
	__le16 lossCount0;
	__le16 gainCount1;
	__le16 lossCount1;
};

_Static_assert(sizeof(struct nvme_additional_smart_log_item) == sizeof(struct smart_ref_clk),
	"Size mismatch for smart_ref_clk");

#define VU_SMART_PAGE_SIZE 512
#define VU_SMART_MAX_ITEMS (VU_SMART_PAGE_SIZE / sizeof(struct nvme_additional_smart_log_item))
struct vu_smart_log {
	struct nvme_additional_smart_log_item item[VU_SMART_MAX_ITEMS];
};

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
		return "timed_work_load_host_reads";
	case 0xE4:
		return "timed_work_load_timer";
	case 0xE5:
		return "read_commands_in_flight_counter";
	case 0xE6:
		return "write_commands_in_flight_counter";
	case 0xEA:
		return "thermal_throttle_status";
	case 0xEE:
		return "re_sku_count";
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

static void smart_log_item_print(struct nvme_additional_smart_log_item *item)
{
	struct smart_ref_clk *pll_item = (struct smart_ref_clk *)item;

	if (!item->id)
		return;

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
	case 0xF3:
		printf("gain0: %u, loss0: %u, gain1: %u, loss1: %u, legacy:%lu\n",
			le16_to_cpu(pll_item->gainCount0),
			le16_to_cpu(pll_item->lossCount0),
			le16_to_cpu(pll_item->gainCount1),
			le16_to_cpu(pll_item->lossCount1),
			int48_to_long(item->raw));
		return;
	default:
		printf("%"PRIu64"\n", int48_to_long(item->raw));
	}
}

static void smart_log_item_add_json(struct nvme_additional_smart_log_item *item, struct json_object *dev_stats)
{
	struct smart_ref_clk *pll_item = (struct smart_ref_clk *)item;
	struct json_object *entry_stats = json_create_object();

	if (!item->id)
		return;

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
	case 0xF3:
		json_object_add_value_int(entry_stats, "gain0", le16_to_cpu(pll_item->gainCount0));
		json_object_add_value_int(entry_stats, "loss0", le16_to_cpu(pll_item->lossCount0));
		json_object_add_value_int(entry_stats, "gain1", le16_to_cpu(pll_item->gainCount1));
		json_object_add_value_int(entry_stats, "loss1", le16_to_cpu(pll_item->lossCount1));
		json_object_add_value_int(entry_stats, "legacy", int48_to_long(item->raw));
		break;
	default:
		json_object_add_value_int(entry_stats, "raw", int48_to_long(item->raw));
	}
	json_object_add_value_object(dev_stats, id_to_name(item->id), entry_stats);
}

static void vu_smart_log_show_json(struct vu_smart_log *payload, unsigned int nsid, const char *devname)
{
	struct json_object *dev_stats = json_create_object();
	struct nvme_additional_smart_log_item *item = payload->item;
	struct json_object *root;

	for (int i = 0; i < VU_SMART_MAX_ITEMS; i++)
		smart_log_item_add_json(&item[i], dev_stats);

	root = json_create_object();
	json_object_add_value_string(root, "Solidigm SMART log", devname);
	json_object_add_value_object(root, "Device stats", dev_stats);

	json_print_object(root, NULL);
	json_free_object(root);
}

static void vu_smart_log_show(struct vu_smart_log *payload, unsigned int nsid, const char *devname,
			      __u8 uuid_index)
{
	struct nvme_additional_smart_log_item *item = payload->item;

	printf("Additional Smart Log for NVMe device:%s namespace-id:%x UUID-idx:%d\n",
		devname, nsid, uuid_index);
	printf("ID             KEY                                 Normalized     Raw\n");

	for (int i = 0; i < VU_SMART_MAX_ITEMS; i++)
		smart_log_item_print(&item[i]);
}

int solidigm_get_additional_smart_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc =
	    "Get Solidigm vendor specific smart log (optionally, for the specified namespace), and show it.";
	const int solidigm_vu_smart_log_id = 0xCA;
	struct vu_smart_log smart_log_payload;
	nvme_print_flags_t flags;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	struct nvme_passthru_cmd cmd;
	int err;
	__u8 uuid_index;

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
		OPT_INCR("verbose",        'v', &nvme_cfg.verbose, verbose),
		OPT_END()
	};

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(cfg.output_format, &flags);
	if (err < 0) {
		fprintf(stderr, "Invalid output format '%s'\n", cfg.output_format);
		return err;
	}

	sldgm_get_uuid_index(hdl, &uuid_index);

	nvme_init_get_log(&cmd, NVME_NSID_ALL,
			  solidigm_vu_smart_log_id, NVME_CSI_NVM,
			  &smart_log_payload, sizeof(smart_log_payload));
	cmd.cdw14 |= NVME_FIELD_ENCODE(uuid_index,
				       NVME_LOG_CDW14_UUID_SHIFT,
				       NVME_LOG_CDW14_UUID_MASK);
	err = nvme_get_log(hdl, &cmd, false,
				   NVME_LOG_PAGE_PDU_SIZE, NULL);
	if (!err) {
		if (flags & JSON)
			vu_smart_log_show_json(&smart_log_payload,
					       cfg.namespace_id, nvme_transport_handle_get_name(hdl));
		else if (flags & BINARY)
			d_raw((unsigned char *)&smart_log_payload, sizeof(smart_log_payload));
		else
			vu_smart_log_show(&smart_log_payload, cfg.namespace_id,
					  nvme_transport_handle_get_name(hdl), uuid_index);
	} else if (err > 0) {
		nvme_show_status(err);
	}

	return err;
}

