// SPDX-License-Identifier: GPL-2.0-or-later

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <libnvme.h>

#include "ccan/endian/endian.h"
#include "memblaze-smart-log-add-x.h"
#include "nvme-cmds.h"
#include "nvme-print.h"
#include "nvme.h"
#include "plugin.h"
#include "util/argconfig.h"

enum {
	LID_SMART_LOG_ADD = 0xca,
};

struct smart_log_add_desc {
	uint32_t index;
	const char *attr;
};

struct smart_log_add_print_ctx {
	const struct smart_log_add_desc *items;
	uint8_t version;
};

static size_t mb_smart_log_add_max_slots(uint8_t version)
{
	switch (version) {
	case 0:
	case 2:
		/*
		 * Byte 511 stores the version, the preceding
		 * bytes are item slots.
		 */
		return (MB_SMART_LOG_ADD_SIZE - 1) /
		       sizeof(struct smart_log_add_item_12);
	case 3:
		return (MB_SMART_LOG_ADD_SIZE - 1) /
		       sizeof(struct smart_log_add_item_10);
	default:
		return 0;
	}
}

static inline int k2c(int kelvin)
{
	return kelvin - 273;
}

static uint64_t int48_to_long_local(const uint8_t *data)
{
	uint64_t value = 0;

	memcpy(&value, data, 6);
	return le64_to_cpu(value);
}

static const struct smart_log_add_desc smart_log_add_v0_items[0xff] = {
	[0xab] = {0,  "program_fail_count"},
	[0xac] = {1,  "erase_fail_count"},
	[0xad] = {2,  "wear_leveling_count"},
	[0xb8] = {3,  "end_to_end_error_count"},
	[0xc7] = {4,  "crc_error_count"},
	[0xe2] = {5,  "timed_workload_media_wear"},
	[0xe3] = {6,  "timed_workload_host_reads"},
	[0xe4] = {7,  "timed_workload_timer"},
	[0xea] = {8,  "thermal_throttle_status"},
	[0xf0] = {9,  "retry_buffer_overflow_counter"},
	[0xf3] = {10, "pll_lock_loss_count"},
	[0xf4] = {11, "nand_bytes_written"},
	[0xf5] = {12, "host_bytes_written"},
	[0xf6] = {13, "system_area_life_remaining"},
	[0xfa] = {14, "nand_bytes_read"},
	[0xe7] = {15, "temperature"},
	[0xe8] = {16, "power_consumption"},
	[0xaf] = {17, "power_on_temperature"},
	[0xec] = {18, "power_loss_protection"},
	[0xf2] = {19, "read_fail_count"},
	[0xeb] = {20, "thermal_throttle_time"},
	[0xed] = {21, "flash_error_media_count"},
};

static const struct smart_log_add_desc smart_log_add_v2_items[0xff] = {
	[0xab] = {0,  "program_fail_count"},
	[0xac] = {1,  "erase_fail_count"},
	[0xad] = {2,  "wear_leveling_count"},
	[0xb8] = {3,  "end_to_end_error_count"},
	[0xc7] = {4,  "crc_error_count"},
	[0xe2] = {5,  "timed_workload_media_wear"},
	[0xe3] = {6,  "timed_workload_host_reads"},
	[0xe4] = {7,  "timed_workload_timer"},
	[0xea] = {8,  "thermal_throttle_status"},
	[0xf0] = {9,  "lifetime_write_amplification"},
	[0xf3] = {10, "pll_lock_loss_count"},
	[0xf4] = {11, "nand_bytes_written"},
	[0xf5] = {12, "host_bytes_written"},
	[0xf6] = {13, "system_area_life_remaining"},
	[0xf9] = {14, "firmware_update_count"},
	[0xfa] = {15, "dram_cecc_count"},
	[0xfb] = {16, "dram_uecc_count"},
	[0xfc] = {17, "xor_pass_count"},
	[0xfd] = {18, "xor_fail_count"},
	[0xfe] = {19, "xor_invoked_count"},
	[0xe5] = {20, "inflight_read_io_cmd"},
	[0xe6] = {21, "inflight_write_io_cmd"},
	[0xf8] = {22, "nand_bytes_read"},
	[0xe7] = {23, "temp_since_born"},
	[0xe8] = {24, "power_consumption"},
	[0xaf] = {25, "temp_since_bootup"},
	[0xeb] = {26, "thermal_throttle_time"},
	[0xec] = {27, "capacitor_capacitance"},
	[0xed] = {28, "free_xblock_status"},
};

static const struct smart_log_add_desc smart_log_add_v3_items[0xff] = {
	[0xab] = {0,  "program_fail_count"},
	[0xac] = {1,  "erase_fail_count"},
	[0xad] = {2,  "wear_leveling_count"},
	[0xdf] = {3,  "ext_e2e_err_count"},
	[0xc7] = {4,  "crc_err_count"},
	[0xf4] = {5,  "nand_bytes_written"},
	[0xf5] = {6,  "host_bytes_written"},
	[0xd0] = {7,  "reallocated_sector_count"},
	[0xd1] = {8,  "uncorrectable_sector_count"},
	[0xd2] = {9,  "nand_uecc_detection"},
	[0xd3] = {10, "nand_xor_correction"},
	[0xd4] = {12, "gc_count"},
	[0xd5] = {13, "dram_uecc_detection_count"},
	[0xd6] = {14, "sram_uecc_detection_count"},
	[0xd7] = {15, "internal_raid_recovery_fail_count"},
	[0xd8] = {16, "inflight_cmds"},
	[0xd9] = {17, "internal_e2e_err_count"},
	[0xda] = {19, "die_fail_count"},
	[0xdb] = {20, "wear_leveling_execution_count"},
	[0xdc] = {21, "read_disturb_count"},
	[0xdd] = {22, "data_retention_count"},
	[0xde] = {23, "capacitor_health"},
	[0xf6] = {24, "dram_cecc_count"},
	[0xf7] = {25, "dram_cecc_address"},
	[0xf8] = {26, "sram_cecc_count"},
	[0xf9] = {27, "sram_cecc_address"},
	[0xfa] = {28, "write_throttle_status"},
	[0xea] = {29, "thermal_throttle_status"},
	[0xe1] = {30, "block_padding_count"},
	[0xe5] = {31, "host_trimmed_sector_count"},
	[0xe7] = {32, "host_write_zeroes_sector_count"},
	[0xe9] = {33, "firmware_update_count"},
};

static const struct smart_log_add_desc *mb_smart_log_add_items(uint8_t version)
{
	switch (version) {
	case 0:
		return smart_log_add_v0_items;
	case 2:
		return smart_log_add_v2_items;
	case 3:
		return smart_log_add_v3_items;
	default:
		return NULL;
	}
}

size_t mb_smart_log_add_item_count(uint8_t version)
{
	switch (version) {
	case 0:
		return 22;
	case 2:
		return 29;
	case 3:
		return 34;
	default:
		return 0;
	}
}

const char *mb_smart_log_add_attr_name(uint8_t version, uint8_t id)
{
	const struct smart_log_add_desc *items =
		mb_smart_log_add_items(version);

	if (!items || !items[id].attr)
		return NULL;

	return items[id].attr;
}

static void smart_log_add_item_12_print(
		const struct smart_log_add_print_ctx *ctx,
		const struct smart_log_add_item_12 *item)
{
	const char *attr = ctx->items[item->id].attr;

	if (item->id == 0 || !attr)
		return;

	printf("%#-12" PRIx8 "%-36s%-12d", item->id, attr, item->norm);
	switch (item->id) {
	case 0xad:
		printf("min: %d, max: %d, avg: %d\n",
		       le16_to_cpu(item->ra.r0),
		       le16_to_cpu(item->ra.r2),
		       le16_to_cpu(item->ra.r4));
		break;
	case 0xe7:
	case 0xaf:
		printf(
			   "max: %d °C (%d K), min: %d °C (%d K), curr: %d °C (%d K)\n",
		       k2c(le16_to_cpu(item->ra.r0)),
		       le16_to_cpu(item->ra.r0),
		       k2c(le16_to_cpu(item->ra.r2)),
		       le16_to_cpu(item->ra.r2),
		       k2c(le16_to_cpu(item->ra.r4)),
		       le16_to_cpu(item->ra.r4));
		break;
	case 0xe8:
		printf("max: %d, min: %d, curr: %d\n",
		       le16_to_cpu(item->ra.r0),
		       le16_to_cpu(item->ra.r2),
		       le16_to_cpu(item->ra.r4));
		break;
	case 0xea:
		if (ctx->version == 2)
			printf("throttle status: %d, count: %d\n",
			       item->raw[0],
			       le32_to_cpu(*(uint32_t *)&item->raw[1]));
		else
			printf("%" PRIu64 "\n",
			       int48_to_long_local(item->raw));
		break;
	case 0xeb:
		printf("throttle status: %d, total throttling time: %d\n",
		       item->raw[0],
		       le32_to_cpu(*(uint32_t *)&item->raw[1]));
		break;
	case 0xec:
		if (ctx->version == 2) {
			printf("current: %d, norminal: %d, threshold: %d\n",
			       le16_to_cpu(item->ra.r0),
			       le16_to_cpu(item->ra.r2),
			       le16_to_cpu(item->ra.r4));
			break;
		}
		printf("%" PRIu64 "\n", int48_to_long_local(item->raw));
		break;
	default:
		printf("%" PRIu64 "\n", int48_to_long_local(item->raw));
		break;
	}
}

static void smart_log_add_item_10_print(
		const struct smart_log_add_print_ctx *ctx,
		const struct smart_log_add_item_10 *item)
{
	const char *attr = ctx->items[item->id].attr;

	if (item->id == 0 || !attr)
		return;

	printf("%#-12" PRIx8 "%-36s%-12d", item->id, attr, item->norm);
	switch (item->id) {
	case 0xad:
		printf("min: %d, max: %d, avg: %d\n",
		       le16_to_cpu(item->ra.r0),
		       le16_to_cpu(item->ra.r2),
		       le16_to_cpu(item->ra.r4));
		break;
	case 0xd8:
		printf("io: %d, admin: %d\n",
		       le16_to_cpu(item->ra.r0),
		       le16_to_cpu(item->ra.r4));
		break;
	case 0xdf:
	case 0xd9:
		printf("v0: %d, v1: %d, v2: %d\n",
		       le16_to_cpu(item->ra.r0),
		       le16_to_cpu(item->ra.r2),
		       le16_to_cpu(item->ra.r4));
		break;
	case 0xf6:
	case 0xf7:
	case 0xf8:
	case 0xf9:
		printf("%d\n", le32_to_cpu(item->ra1.r0));
		break;
	case 0xfa:
		printf("curr: %d, total: %d\n",
		       le16_to_cpu(item->ra.r0),
		       le16_to_cpu(item->ra.r2));
		break;
	case 0xea:
		printf("throttle status: %d, count: %d\n",
		       item->raw[0],
		       le32_to_cpu(*(uint32_t *)&item->raw[1]));
		break;
	case 0xe9:
		printf("without reset: %d, with reset: %d, fail: %d\n",
		       le16_to_cpu(item->ra.r0),
		       le16_to_cpu(item->ra.r2),
		       le16_to_cpu(item->ra.r4));
		break;
	default:
		printf("%" PRIu64 "\n", int48_to_long_local(item->raw));
		break;
	}
}

void mb_smart_log_add_print(const struct smart_log_add *log,
			    const char *devname)
{
	uint8_t version = log->raw[511];
	const struct smart_log_add_desc *items =
		mb_smart_log_add_items(version);
	struct smart_log_add_print_ctx ctx = {
		.items = items,
		.version = version,
	};
	size_t slots = mb_smart_log_add_max_slots(version);

	printf("Version: %u\n\n", version);
	printf("Additional Smart Log for NVMe device: %s\n\n", devname);
	printf("%-12s%-36s%-12s%s\n", "Id", "Key", "Normalized", "Raw");

	if (!items || !slots) {
		if (version == 1)
			nvme_show_error("Version %d: N/A", version);
		else
			nvme_show_error("Version %d: Not supported yet",
					version);
		return;
	}

	if (version == 0 || version == 2) {
		const struct smart_log_add_item_12 *item =
			(const struct smart_log_add_item_12 *)log->raw;

		for (size_t i = 0; i < slots; i++)
			smart_log_add_item_12_print(&ctx, &item[i]);
		return;
	}

	if (version == 3) {
		const struct smart_log_add_item_10 *item =
			(const struct smart_log_add_item_10 *)log->raw;

		for (size_t i = 0; i < slots; i++)
			smart_log_add_item_10_print(&ctx, &item[i]);
	}
}

int mb_smart_log_add_x(int argc, char **argv, struct command *acmd,
		       struct plugin *plugin)
{
	int err = 0;
	struct libnvme_global_ctx *ctx = NULL;
	struct libnvme_transport_handle *hdl = NULL;
	struct smart_log_add log = {0};
	(void)plugin;

	struct config {
		bool raw_binary;
	};

	struct config cfg = {0};

	OPT_ARGS(opts) = {
		OPT_FLAG("raw-binary", 'b', &cfg.raw_binary,
			 "dump the whole log buffer in binary format"),
		OPT_END()
	};

	err = parse_and_open(&ctx, &hdl, argc, argv, acmd->help, opts);
	if (err)
		goto out;

	err = nvme_get_log_simple(hdl, LID_SMART_LOG_ADD, &log, sizeof(log));
	if (!err) {
		if (!cfg.raw_binary)
			mb_smart_log_add_print(&log,
				libnvme_transport_handle_get_name(hdl));
		else
			d_raw((unsigned char *)&log, sizeof(log));
	} else if (err > 0) {
		nvme_show_status(err);
	} else {
		nvme_show_error("%s: %s", acmd->name, libnvme_strerror(errno));
	}

out:
	if (hdl)
		put_transport_handle(hdl);
	if (ctx)
		libnvme_free_global_ctx(ctx);

	return err;
}
