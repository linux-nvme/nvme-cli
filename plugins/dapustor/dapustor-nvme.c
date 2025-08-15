// SPDX-License-Identifier: GPL-2.0-or-later
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>

#include <sys/stat.h>

#include "common.h"
#include "nvme.h"
#include "libnvme.h"
#include "plugin.h"
#include "nvme-print.h"

#include "util/suffix.h"

#define CREATE_CMD
#include "dapustor-nvme.h"

struct __packed nvme_additional_smart_log_item {
	__u8			key;
	__u8			_kp[2];
	__u8			norm;
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
		struct __packed  temperature {
			__le16	max;
			__le16	min;
			__le16	cur;
		} temperature;
		struct __packed  power_consumption {
			__le16	max;
			__le16	min;
			__le16	avg;
		} power_consumption;
		struct __packed  thermal_throttle_time {
			__u8	sts;
			__u32	time;
			__u8	rsv;
		} thermal_throttle_time;
	};
	__u8			_rp;
};

struct nvme_additional_smart_log {
	struct nvme_additional_smart_log_item	program_fail_cnt;
	struct nvme_additional_smart_log_item	erase_fail_cnt;
	struct nvme_additional_smart_log_item	wear_leveling_cnt;
	struct nvme_additional_smart_log_item	e2e_err_cnt;
	struct nvme_additional_smart_log_item	crc_err_cnt;
	struct nvme_additional_smart_log_item	timed_workload_media_wear;
	struct nvme_additional_smart_log_item	timed_workload_host_reads;
	struct nvme_additional_smart_log_item	timed_workload_timer;
	struct nvme_additional_smart_log_item	thermal_throttle_status;
	struct nvme_additional_smart_log_item	retry_buffer_overflow_cnt;
	struct nvme_additional_smart_log_item	pll_lock_loss_cnt;
	struct nvme_additional_smart_log_item	nand_bytes_written;
	struct nvme_additional_smart_log_item	host_bytes_written;
};

struct nvme_extended_additional_smart_log {
	struct nvme_additional_smart_log_item	sys_area_life_remain;
	struct nvme_additional_smart_log_item	nand_bytes_read;
	struct nvme_additional_smart_log_item	temperature;
	struct nvme_additional_smart_log_item	power_consumption;
	struct nvme_additional_smart_log_item	power_on_temperature;
	struct nvme_additional_smart_log_item	power_loss_protection;
	struct nvme_additional_smart_log_item	read_fail_count;
	struct nvme_additional_smart_log_item	thermal_throttle_time;
	struct nvme_additional_smart_log_item	flash_error_media_count;
	struct nvme_additional_smart_log_item	lifetime_write_amplification;
	struct nvme_additional_smart_log_item	firmware_update_count;
	struct nvme_additional_smart_log_item	dram_cecc_count;
	struct nvme_additional_smart_log_item	dram_uecc_count;
	struct nvme_additional_smart_log_item	xor_pass_count;
	struct nvme_additional_smart_log_item	xor_fail_count;
	struct nvme_additional_smart_log_item	xor_invoked_count;
	struct nvme_additional_smart_log_item	inflight_read_io_cmd;
	struct nvme_additional_smart_log_item	temp_since_born;
	struct nvme_additional_smart_log_item	temp_since_bootup;
	struct nvme_additional_smart_log_item	inflight_write_io_cmd;
};

static void show_dapustor_add_smart_log_jsn(struct nvme_additional_smart_log *smart,
					    struct json_object *dev_stats)
{
	struct json_object *entry_stats, *multi;

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->program_fail_cnt.norm);
	json_object_add_value_int(entry_stats, "raw", int48_to_long(smart->program_fail_cnt.raw));
	json_object_add_value_object(dev_stats, "program_fail_count", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->erase_fail_cnt.norm);
	json_object_add_value_int(entry_stats, "raw", int48_to_long(smart->erase_fail_cnt.raw));
	json_object_add_value_object(dev_stats, "erase_fail_count", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->wear_leveling_cnt.norm);
	multi = json_create_object();
	json_object_add_value_int(multi, "min",
				  le16_to_cpu(smart->wear_leveling_cnt.wear_level.min));
	json_object_add_value_int(multi, "max",
				  le16_to_cpu(smart->wear_leveling_cnt.wear_level.max));
	json_object_add_value_int(multi, "avg",
				  le16_to_cpu(smart->wear_leveling_cnt.wear_level.avg));
	json_object_add_value_object(entry_stats, "raw", multi);
	json_object_add_value_object(dev_stats, "wear_leveling", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->e2e_err_cnt.norm);
	json_object_add_value_int(entry_stats, "raw", int48_to_long(smart->e2e_err_cnt.raw));
	json_object_add_value_object(dev_stats, "end_to_end_error_detection_count", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->crc_err_cnt.norm);
	json_object_add_value_int(entry_stats, "raw", int48_to_long(smart->crc_err_cnt.raw));
	json_object_add_value_object(dev_stats, "crc_error_count", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->timed_workload_media_wear.norm);
	json_object_add_value_float(entry_stats, "raw",
		((long double)int48_to_long(smart->timed_workload_media_wear.raw)) / 1024);
	json_object_add_value_object(dev_stats, "timed_workload_media_wear", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->timed_workload_host_reads.norm);
	json_object_add_value_int(entry_stats, "raw",
				  int48_to_long(smart->timed_workload_host_reads.raw));
	json_object_add_value_object(dev_stats, "timed_workload_host_reads", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->timed_workload_timer.norm);
	json_object_add_value_int(entry_stats, "raw",
				  int48_to_long(smart->timed_workload_timer.raw));
	json_object_add_value_object(dev_stats, "timed_workload_timer", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->thermal_throttle_status.norm);
	multi = json_create_object();
	json_object_add_value_int(multi, "pct",
				  smart->thermal_throttle_status.thermal_throttle.pct);
	json_object_add_value_int(multi, "cnt",
				  smart->thermal_throttle_status.thermal_throttle.count);
	json_object_add_value_object(entry_stats, "raw", multi);
	json_object_add_value_object(dev_stats, "thermal_throttle_status", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->retry_buffer_overflow_cnt.norm);
	json_object_add_value_int(entry_stats, "raw",
				  int48_to_long(smart->retry_buffer_overflow_cnt.raw));
	json_object_add_value_object(dev_stats, "retry_buffer_overflow_count", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->pll_lock_loss_cnt.norm);
	json_object_add_value_int(entry_stats, "raw", int48_to_long(smart->pll_lock_loss_cnt.raw));
	json_object_add_value_object(dev_stats, "pll_lock_loss_count", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->nand_bytes_written.norm);
	json_object_add_value_int(entry_stats, "raw", int48_to_long(smart->nand_bytes_written.raw));
	json_object_add_value_object(dev_stats, "nand_bytes_written", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->host_bytes_written.norm);
	json_object_add_value_int(entry_stats, "raw", int48_to_long(smart->host_bytes_written.raw));
	json_object_add_value_object(dev_stats, "host_bytes_written", entry_stats);
}

static void show_dapustor_ext_add_smart_log_jsn(struct nvme_extended_additional_smart_log *smart,
						struct json_object *dev_stats)
{
	struct json_object *entry_stats, *multi;

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->sys_area_life_remain.norm);
	json_object_add_value_int(entry_stats, "raw",
				  int48_to_long(smart->sys_area_life_remain.raw));
	json_object_add_value_object(dev_stats, "system_area_life_remaining", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->nand_bytes_read.norm);
	json_object_add_value_int(entry_stats, "raw", int48_to_long(smart->nand_bytes_read.raw));
	json_object_add_value_object(dev_stats, "nand_bytes_read", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->temperature.norm);
	multi = json_create_object();
	json_object_add_value_int(multi, "min", le16_to_cpu(smart->temperature.temperature.min));
	json_object_add_value_int(multi, "max", le16_to_cpu(smart->temperature.temperature.max));
	json_object_add_value_int(multi, "cur", le16_to_cpu(smart->temperature.temperature.cur));
	json_object_add_value_object(entry_stats, "raw", multi);
	json_object_add_value_object(dev_stats, "temperature", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->power_consumption.norm);
	multi = json_create_object();
	json_object_add_value_int(multi, "min",
				  le16_to_cpu(smart->power_consumption.power_consumption.min));
	json_object_add_value_int(multi, "max",
				  le16_to_cpu(smart->power_consumption.power_consumption.max));
	json_object_add_value_int(multi, "avg",
				  le16_to_cpu(smart->power_consumption.power_consumption.avg));
	json_object_add_value_object(entry_stats, "raw", multi);
	json_object_add_value_object(dev_stats, "power_consumption", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->power_on_temperature.norm);
	multi = json_create_object();
	json_object_add_value_int(multi, "min",
				  le16_to_cpu(smart->power_on_temperature.temperature.min));
	json_object_add_value_int(multi, "max",
				  le16_to_cpu(smart->power_on_temperature.temperature.max));
	json_object_add_value_int(multi, "cur",
				  le16_to_cpu(smart->power_on_temperature.temperature.cur));
	json_object_add_value_object(entry_stats, "raw", multi);
	json_object_add_value_object(dev_stats, "power_on_temperature", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->power_loss_protection.norm);
	json_object_add_value_int(entry_stats, "raw",
				  int48_to_long(smart->power_loss_protection.raw));
	json_object_add_value_object(dev_stats, "power_loss_protection", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->read_fail_count.norm);
	json_object_add_value_int(entry_stats, "raw", int48_to_long(smart->read_fail_count.raw));
	json_object_add_value_object(dev_stats, "read_fail_count", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->thermal_throttle_time.norm);
	json_object_add_value_int(entry_stats, "raw",
				  int48_to_long(smart->thermal_throttle_time.raw));
	json_object_add_value_object(dev_stats, "thermal_throttle_time", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->flash_error_media_count.norm);
	json_object_add_value_int(entry_stats, "raw",
				  int48_to_long(smart->flash_error_media_count.raw));
	json_object_add_value_object(dev_stats, "flash_error_media_count", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized",
				  smart->lifetime_write_amplification.norm);
	json_object_add_value_int(entry_stats, "raw",
				  int48_to_long(smart->lifetime_write_amplification.raw));
	json_object_add_value_object(dev_stats, "lifetime_write_amplification", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->firmware_update_count.norm);
	json_object_add_value_int(entry_stats, "raw",
				  int48_to_long(smart->firmware_update_count.raw));
	json_object_add_value_object(dev_stats, "firmware_update_count", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->dram_cecc_count.norm);
	json_object_add_value_int(entry_stats, "raw", int48_to_long(smart->dram_cecc_count.raw));
	json_object_add_value_object(dev_stats, "dram_cecc_count", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->dram_uecc_count.norm);
	json_object_add_value_int(entry_stats, "raw", int48_to_long(smart->dram_uecc_count.raw));
	json_object_add_value_object(dev_stats, "dram_uecc_count", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->xor_pass_count.norm);
	json_object_add_value_int(entry_stats, "raw", int48_to_long(smart->xor_pass_count.raw));
	json_object_add_value_object(dev_stats, "xor_pass_count", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->xor_fail_count.norm);
	json_object_add_value_int(entry_stats, "raw", int48_to_long(smart->xor_fail_count.raw));
	json_object_add_value_object(dev_stats, "xor_fail_count", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->xor_invoked_count.norm);
	json_object_add_value_int(entry_stats, "raw", int48_to_long(smart->xor_invoked_count.raw));
	json_object_add_value_object(dev_stats, "xor_invoked_count", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->inflight_read_io_cmd.norm);
	json_object_add_value_int(entry_stats, "raw",
				  int48_to_long(smart->inflight_read_io_cmd.raw));
	json_object_add_value_object(dev_stats, "inflight_read_io_cmd", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->temp_since_born.norm);
	multi = json_create_object();
	json_object_add_value_int(multi, "min",
				  le16_to_cpu(smart->temp_since_born.temperature.min));
	json_object_add_value_int(multi, "max",
				  le16_to_cpu(smart->temp_since_born.temperature.max));
	json_object_add_value_int(multi, "cur",
				  le16_to_cpu(smart->temp_since_born.temperature.cur));
	json_object_add_value_object(entry_stats, "raw", multi);
	json_object_add_value_object(dev_stats, "temp_since_born", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->temp_since_bootup.norm);
	multi = json_create_object();
	json_object_add_value_int(multi, "min",
				  le16_to_cpu(smart->temp_since_bootup.temperature.min));
	json_object_add_value_int(multi, "max",
				  le16_to_cpu(smart->temp_since_bootup.temperature.max));
	json_object_add_value_int(multi, "cur",
				  le16_to_cpu(smart->temp_since_bootup.temperature.cur));
	json_object_add_value_object(entry_stats, "raw", multi);
	json_object_add_value_object(dev_stats, "temp_since_bootup", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->inflight_write_io_cmd.norm);
	json_object_add_value_int(entry_stats, "raw",
				  int48_to_long(smart->inflight_write_io_cmd.raw));
	json_object_add_value_object(dev_stats, "inflight_write_io_cmd", entry_stats);
}

static void show_dapustor_smart_log_jsn(struct nvme_additional_smart_log *smart,
					struct nvme_extended_additional_smart_log *ext_smart,
					unsigned int nsid, const char *devname, bool has_ext)
{
	struct json_object *root, *dev_stats;

	root = json_create_object();
	json_object_add_value_string(root, "Intel Smart log", devname);

	dev_stats = json_create_object();
	show_dapustor_add_smart_log_jsn(smart, dev_stats);
	if (has_ext)
		show_dapustor_ext_add_smart_log_jsn(ext_smart, dev_stats);
	json_object_add_value_object(root, "Device stats", dev_stats);

	json_print_object(root, NULL);
	json_free_object(root);
}

static void show_dapustor_add_smart_log(struct nvme_additional_smart_log *smart)
{
	printf("program_fail_count              : %3d%%       %"PRIu64"\n",
		smart->program_fail_cnt.norm,
		int48_to_long(smart->program_fail_cnt.raw));
	printf("erase_fail_count                : %3d%%       %"PRIu64"\n",
		smart->erase_fail_cnt.norm,
		int48_to_long(smart->erase_fail_cnt.raw));
	printf("wear_leveling                   : %3d%%       min: %u, max: %u, avg: %u\n",
		smart->wear_leveling_cnt.norm,
		le16_to_cpu(smart->wear_leveling_cnt.wear_level.min),
		le16_to_cpu(smart->wear_leveling_cnt.wear_level.max),
		le16_to_cpu(smart->wear_leveling_cnt.wear_level.avg));
	printf("end_to_end_error_detection_count: %3d%%       %"PRIu64"\n",
		smart->e2e_err_cnt.norm,
		int48_to_long(smart->e2e_err_cnt.raw));
	printf("crc_error_count                 : %3d%%       %"PRIu64"\n",
		smart->crc_err_cnt.norm,
		int48_to_long(smart->crc_err_cnt.raw));
	printf("timed_workload_media_wear       : %3d%%       %.3f%%\n",
		smart->timed_workload_media_wear.norm,
		((float)int48_to_long(smart->timed_workload_media_wear.raw)) / 1024);
	printf("timed_workload_host_reads       : %3d%%       %"PRIu64"%%\n",
		smart->timed_workload_host_reads.norm,
		int48_to_long(smart->timed_workload_host_reads.raw));
	printf("timed_workload_timer            : %3d%%       %"PRIu64" min\n",
		smart->timed_workload_timer.norm,
		int48_to_long(smart->timed_workload_timer.raw));
	printf("thermal_throttle_status         : %3d%%       %u%%, cnt: %u\n",
		smart->thermal_throttle_status.norm,
		smart->thermal_throttle_status.thermal_throttle.pct,
		smart->thermal_throttle_status.thermal_throttle.count);
	printf("retry_buffer_overflow_count     : %3d%%       %"PRIu64"\n",
		smart->retry_buffer_overflow_cnt.norm,
		int48_to_long(smart->retry_buffer_overflow_cnt.raw));
	printf("pll_lock_loss_count             : %3d%%       %"PRIu64"\n",
		smart->pll_lock_loss_cnt.norm,
		int48_to_long(smart->pll_lock_loss_cnt.raw));
	printf("nand_bytes_written              : %3d%%       sectors: %"PRIu64"\n",
		smart->nand_bytes_written.norm,
		int48_to_long(smart->nand_bytes_written.raw));
	printf("host_bytes_written              : %3d%%       sectors: %"PRIu64"\n",
		smart->host_bytes_written.norm,
		int48_to_long(smart->host_bytes_written.raw));
}

static void show_dapustor_ext_add_smart_log(struct nvme_extended_additional_smart_log *smart)
{
	printf("system_area_life_remaining      : %3d%%       %"PRIu64"\n",
		smart->sys_area_life_remain.norm,
		int48_to_long(smart->sys_area_life_remain.raw));
	printf("nand_bytes_read                 : %3d%%       %"PRIu64"\n",
		smart->nand_bytes_read.norm,
		int48_to_long(smart->nand_bytes_read.raw));
	printf("temperature                     : %3d%%       min: %u, max: %u, cur: %u\n",
		smart->temperature.norm,
		le16_to_cpu(smart->temperature.temperature.min),
		le16_to_cpu(smart->temperature.temperature.max),
		le16_to_cpu(smart->temperature.temperature.cur));
	printf("power_consumption               : %3d%%       min: %u, max: %u, avg: %u\n",
		smart->power_consumption.norm,
		le16_to_cpu(smart->power_consumption.power_consumption.min),
		le16_to_cpu(smart->power_consumption.power_consumption.max),
		le16_to_cpu(smart->power_consumption.power_consumption.avg));
	printf("power_on_temperature            : %3d%%       min: %u, max: %u, cur: %u\n",
		smart->power_on_temperature.norm,
		le16_to_cpu(smart->power_on_temperature.temperature.min),
		le16_to_cpu(smart->power_on_temperature.temperature.max),
		le16_to_cpu(smart->power_on_temperature.temperature.cur));
	printf("power_loss_protection           : %3d%%       %"PRIu64"\n",
		smart->power_loss_protection.norm,
		int48_to_long(smart->power_loss_protection.raw));
	printf("read_fail_count                 : %3d%%       %"PRIu64"\n",
		smart->read_fail_count.norm,
		int48_to_long(smart->read_fail_count.raw));
	printf("thermal_throttle_time           : %3d%%       %"PRIu64"\n",
		smart->thermal_throttle_time.norm,
		int48_to_long(smart->thermal_throttle_time.raw));
	printf("flash_error_media_count         : %3d%%       %"PRIu64"\n",
		smart->flash_error_media_count.norm,
		int48_to_long(smart->flash_error_media_count.raw));
	printf("lifetime_write_amplification    : %3d%%       %"PRIu64"\n",
		smart->lifetime_write_amplification.norm,
		int48_to_long(smart->lifetime_write_amplification.raw));
	printf("firmware_update_count           : %3d%%       %"PRIu64"\n",
		smart->firmware_update_count.norm,
		int48_to_long(smart->firmware_update_count.raw));
	printf("dram_cecc_count                 : %3d%%       %"PRIu64"\n",
		smart->dram_cecc_count.norm,
		int48_to_long(smart->dram_cecc_count.raw));
	printf("dram_uecc_count                 : %3d%%       %"PRIu64"\n",
		smart->dram_uecc_count.norm,
		int48_to_long(smart->dram_uecc_count.raw));
	printf("xor_pass_count                  : %3d%%       %"PRIu64"\n",
		smart->xor_pass_count.norm,
		int48_to_long(smart->xor_pass_count.raw));
	printf("xor_fail_count                  : %3d%%       %"PRIu64"\n",
		smart->xor_fail_count.norm,
		int48_to_long(smart->xor_fail_count.raw));
	printf("xor_invoked_count               : %3d%%       %"PRIu64"\n",
		smart->xor_invoked_count.norm,
		int48_to_long(smart->xor_invoked_count.raw));
	printf("inflight_read_io_cmd            : %3d%%       %"PRIu64"\n",
		smart->inflight_read_io_cmd.norm,
		int48_to_long(smart->inflight_read_io_cmd.raw));
	printf("temp_since_born                 : %3d%%       min: %u, max: %u, cur: %u\n",
		smart->temp_since_born.norm,
		le16_to_cpu(smart->temp_since_born.temperature.min),
		le16_to_cpu(smart->temp_since_born.temperature.max),
		le16_to_cpu(smart->temp_since_born.temperature.cur));
	printf("temp_since_bootup               : %3d%%       min: %u, max: %u, cur: %u\n",
		smart->temp_since_bootup.norm,
		le16_to_cpu(smart->temp_since_bootup.temperature.min),
		le16_to_cpu(smart->temp_since_bootup.temperature.max),
		le16_to_cpu(smart->temp_since_bootup.temperature.cur));
	printf("inflight_write_io_cmd           : %3d%%       %"PRIu64"\n",
		smart->inflight_write_io_cmd.norm,
		int48_to_long(smart->inflight_write_io_cmd.raw));
}

static void show_dapustor_smart_log(struct nvme_additional_smart_log *smart,
				    struct nvme_extended_additional_smart_log *ext_smart,
				    unsigned int nsid, const char *devname, bool has_ext)
{
	printf("Additional Smart Log for NVME device:%s namespace-id:%x\n",
		devname, nsid);
	printf("key                               normalized raw\n");
	show_dapustor_add_smart_log(smart);
	if (has_ext)
		show_dapustor_ext_add_smart_log(ext_smart);
}

static int dapustor_additional_smart_log_data(
		struct nvme_transport_handle *hdl,
		struct nvme_additional_smart_log *smart_log,
		struct nvme_extended_additional_smart_log *ext_smart_log,
		bool *has_ext)
{
	int err;

	err = nvme_get_log_simple(hdl, 0xca, smart_log, sizeof(*smart_log));
	if (err) {
		nvme_show_status(err);
		return err;
	}
	err = nvme_get_log_simple(hdl, 0xcb, ext_smart_log, sizeof(*ext_smart_log));
	*has_ext = !err;
	return 0;
}

static int dapustor_additional_smart_log(int argc, char **argv, struct command *acmd,
					 struct plugin *plugin)
{
	const char *desc = "Get DapuStor vendor specific additional smart log, and show it.";
	const char *namespace = "(optional) desired namespace";
	const char *raw = "Dump output in binary format";
#ifdef CONFIG_JSONC
	const char *json = "Dump output in json format";
#endif /* CONFIG_JSONC */

	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	struct nvme_extended_additional_smart_log ext_smart_log;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	struct nvme_additional_smart_log smart_log;
	bool has_ext = false;
	int err;

	struct config {
		uint32_t namespace_id;
		bool  raw_binary;
		bool  json;
	};

	struct config cfg = {
		.namespace_id = NVME_NSID_ALL,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace),
		OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,   raw),
		OPT_FLAG_JSON("json",    'j', &cfg.json,         json),
		OPT_END()
	};

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = dapustor_additional_smart_log_data(hdl, &smart_log,
						 &ext_smart_log, &has_ext);
	if (!err) {
		if (cfg.json)
			show_dapustor_smart_log_jsn(&smart_log, &ext_smart_log,
						    cfg.namespace_id,
						    nvme_transport_handle_get_name(hdl),
						    has_ext);
		else if (!cfg.raw_binary)
			show_dapustor_smart_log(&smart_log, &ext_smart_log,
						cfg.namespace_id,
						nvme_transport_handle_get_name(hdl), has_ext);
		else {
			d_raw((unsigned char *)&smart_log, sizeof(smart_log));
			if (has_ext)
				d_raw((unsigned char *)&ext_smart_log,
				      sizeof(ext_smart_log));
		}
	}
	return err;
}
