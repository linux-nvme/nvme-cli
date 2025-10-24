// SPDX-License-Identifier: GPL-2.0-or-later
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

#define CREATE_CMD
#include "ssstc-nvme.h"

struct  __packed nvme_additional_smart_log_item
{
	__u8 key;
	__u8 norm;
	union __packed {
		__u8 raw[6];
		struct __packed wear_level
		{
			__le16	min;
			__le16	max;
			__le16	avg;
		} wear_level;
	};
	__u8 _rp[2];
};

struct nvme_additional_smart_log {
	struct nvme_additional_smart_log_item	program_fail_cnt;
	struct nvme_additional_smart_log_item	erase_fail_cnt;
	struct nvme_additional_smart_log_item	wear_leveling_cnt;
	struct nvme_additional_smart_log_item	e2e_err_cnt;
	struct nvme_additional_smart_log_item	crc_err_cnt;
	struct nvme_additional_smart_log_item	nand_bytes_written;
	struct nvme_additional_smart_log_item	host_bytes_written;
	struct nvme_additional_smart_log_item	reallocated_sector_count;
	struct nvme_additional_smart_log_item	uncorrectable_sector_count;
	struct nvme_additional_smart_log_item	NAND_ECC_Detection_Count;
	struct nvme_additional_smart_log_item	NAND_ECC_Correction_Count;
	struct nvme_additional_smart_log_item	Bad_Block_Failure_Rate;
	struct nvme_additional_smart_log_item	GC_Count;
	struct nvme_additional_smart_log_item	DRAM_UECC_Detection_Count;
	struct nvme_additional_smart_log_item	SRAM_UECC_Detection_Count;
	struct nvme_additional_smart_log_item	Raid_Recovery_Fail_Count;
	struct nvme_additional_smart_log_item	Inflight_Command;
	struct nvme_additional_smart_log_item	Internal_End_to_End_Dect_Count;
	struct nvme_additional_smart_log_item	PCIe_Correctable_Error_Count;
	struct nvme_additional_smart_log_item	die_fail_count;
	struct nvme_additional_smart_log_item	wear_leveling_exec_count;
	struct nvme_additional_smart_log_item	read_disturb_count;
	struct nvme_additional_smart_log_item	data_retention_count;
};


static
void show_ssstc_add_smart_log_jsn(struct nvme_additional_smart_log *smart,
		unsigned int nsid, const char *devname)
{
	struct json_object *root, *entry_stats, *dev_stats, *multi;
	uint16_t wear_level_min = 0;
	uint16_t wear_level_max = 0;
	uint16_t wear_level_avg = 0;
	uint64_t raw_val = 0;

	root = json_create_object();
	json_object_add_value_string(root, "SSSTC Smart log", devname);

	dev_stats = json_create_object();

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "#id", smart->program_fail_cnt.key);
	json_object_add_value_int(entry_stats, "normalized", smart->program_fail_cnt.norm);
	raw_val = int48_to_long(smart->program_fail_cnt.raw);
	json_object_add_value_int(entry_stats, "raw", raw_val);
	json_object_add_value_object(dev_stats, "program_fail_count", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "#id", smart->erase_fail_cnt.key);
	json_object_add_value_int(entry_stats, "normalized", smart->erase_fail_cnt.norm);
	raw_val = int48_to_long(smart->erase_fail_cnt.raw);
	json_object_add_value_int(entry_stats, "raw", raw_val);
	json_object_add_value_object(dev_stats, "erase_fail_count", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "#id", smart->wear_leveling_cnt.key);
	json_object_add_value_int(entry_stats, "normalized", smart->wear_leveling_cnt.norm);
	multi = json_create_object();
	wear_level_min = le16_to_cpu(smart->wear_leveling_cnt.wear_level.min);
	wear_level_max = le16_to_cpu(smart->wear_leveling_cnt.wear_level.max);
	wear_level_avg = le16_to_cpu(smart->wear_leveling_cnt.wear_level.avg);
	json_object_add_value_int(multi, "min", wear_level_min);
	json_object_add_value_int(multi, "max", wear_level_max);
	json_object_add_value_int(multi, "avg", wear_level_avg);
	json_object_add_value_object(entry_stats, "raw", multi);
	json_object_add_value_object(dev_stats, "wear_leveling", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "#id", smart->e2e_err_cnt.key);
	json_object_add_value_int(entry_stats, "normalized", smart->e2e_err_cnt.norm);
	multi = json_create_object();
	wear_level_min = le16_to_cpu(smart->e2e_err_cnt.wear_level.min);
	wear_level_max = le16_to_cpu(smart->e2e_err_cnt.wear_level.max);
	wear_level_avg = le16_to_cpu(smart->e2e_err_cnt.wear_level.avg);
	json_object_add_value_int(multi, "guard check error", wear_level_min);
	json_object_add_value_int(multi, "application tag check error", wear_level_max);
	json_object_add_value_int(multi, "reference tag check error", wear_level_avg);
	json_object_add_value_object(entry_stats, "raw", multi);
	json_object_add_value_object(dev_stats, "end_to_end_error_dect_count", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "#id", smart->crc_err_cnt.key);
	json_object_add_value_int(entry_stats, "normalized", smart->crc_err_cnt.norm);
	raw_val = int48_to_long(smart->crc_err_cnt.raw);
	json_object_add_value_int(entry_stats, "raw", raw_val);
	json_object_add_value_object(dev_stats, "crc_error_count", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "#id", smart->nand_bytes_written.key);
	json_object_add_value_int(entry_stats, "normalized", smart->nand_bytes_written.norm);
	raw_val = int48_to_long(smart->nand_bytes_written.raw);
	json_object_add_value_int(entry_stats, "raw", raw_val);
	json_object_add_value_object(dev_stats, "nand_bytes_written", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "#id", smart->host_bytes_written.key);
	json_object_add_value_int(entry_stats, "normalized", smart->host_bytes_written.norm);
	raw_val = int48_to_long(smart->host_bytes_written.raw);
	json_object_add_value_int(entry_stats, "raw", raw_val);
	json_object_add_value_object(dev_stats, "host_bytes_written", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "#id", smart->reallocated_sector_count.key);
	json_object_add_value_int(entry_stats, "normalized", smart->reallocated_sector_count.norm);
	raw_val = int48_to_long(smart->reallocated_sector_count.raw);
	json_object_add_value_int(entry_stats, "raw", raw_val);
	json_object_add_value_object(dev_stats, "reallocated_sector_count", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "#id", smart->uncorrectable_sector_count.key);
	json_object_add_value_int(entry_stats, "normalized",
		smart->uncorrectable_sector_count.norm);
	raw_val = int48_to_long(smart->uncorrectable_sector_count.raw);
	json_object_add_value_int(entry_stats, "raw", raw_val);
	json_object_add_value_object(dev_stats, "uncorrectable_sector_count", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "#id", smart->NAND_ECC_Detection_Count.key);
	json_object_add_value_int(entry_stats, "normalized", smart->NAND_ECC_Detection_Count.norm);
	raw_val = int48_to_long(smart->NAND_ECC_Detection_Count.raw);
	json_object_add_value_int(entry_stats, "raw", raw_val);
	json_object_add_value_object(dev_stats, "NAND_ECC_detection_count", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "#id", smart->NAND_ECC_Correction_Count.key);
	json_object_add_value_int(entry_stats, "normalized", smart->NAND_ECC_Correction_Count.norm);
	raw_val = int48_to_long(smart->NAND_ECC_Correction_Count.raw);
	json_object_add_value_int(entry_stats, "raw", raw_val);
	json_object_add_value_object(dev_stats, "NAND_ECC_correction_count", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "#id", smart->GC_Count.key);
	json_object_add_value_int(entry_stats, "normalized", smart->GC_Count.norm);
	raw_val = int48_to_long(smart->GC_Count.raw);
	json_object_add_value_int(entry_stats, "raw", raw_val);
	json_object_add_value_object(dev_stats, "GC_count", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "#id", smart->DRAM_UECC_Detection_Count.key);
	json_object_add_value_int(entry_stats, "normalized", smart->DRAM_UECC_Detection_Count.norm);
	multi = json_create_object();
	wear_level_max = le16_to_cpu(smart->DRAM_UECC_Detection_Count.wear_level.max);
	wear_level_avg = le16_to_cpu(smart->DRAM_UECC_Detection_Count.wear_level.avg);
	json_object_add_value_int(multi, "1-Bit Err", wear_level_max);
	json_object_add_value_int(multi, "2-Bit Err", wear_level_avg);
	json_object_add_value_object(entry_stats, "raw", multi);
	json_object_add_value_object(dev_stats, "DRAM_UECC_detection_count", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "#id", smart->SRAM_UECC_Detection_Count.key);
	json_object_add_value_int(entry_stats, "normalized", smart->SRAM_UECC_Detection_Count.norm);
	multi = json_create_object();
	wear_level_min = le16_to_cpu(smart->SRAM_UECC_Detection_Count.wear_level.min);
	wear_level_max = le16_to_cpu(smart->SRAM_UECC_Detection_Count.wear_level.max);
	wear_level_avg = le16_to_cpu(smart->SRAM_UECC_Detection_Count.wear_level.avg);
	json_object_add_value_int(multi, "parity error detected", wear_level_min);
	json_object_add_value_int(multi, "ecc error detection", wear_level_max);
	json_object_add_value_int(multi, "axi data parity errors", wear_level_avg);
	json_object_add_value_object(entry_stats, "raw", multi);
	json_object_add_value_object(dev_stats, "SRAM_UECC_Detection_Count", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "#id", smart->Raid_Recovery_Fail_Count.key);
	json_object_add_value_int(entry_stats, "normalized", smart->Raid_Recovery_Fail_Count.norm);
	raw_val = int48_to_long(smart->Raid_Recovery_Fail_Count.raw);
	json_object_add_value_int(entry_stats, "raw", raw_val);
	json_object_add_value_object(dev_stats, "raid_Recovery_fail_count", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "#id", smart->Inflight_Command.key);
	json_object_add_value_int(entry_stats, "normalized", smart->Inflight_Command.norm);
	multi = json_create_object();
	wear_level_min = le16_to_cpu(smart->Inflight_Command.wear_level.min);
	wear_level_max = le16_to_cpu(smart->Inflight_Command.wear_level.max);
	wear_level_avg = le16_to_cpu(smart->Inflight_Command.wear_level.avg);
	json_object_add_value_int(multi, "Read Cmd", wear_level_min);
	json_object_add_value_int(multi, "Write Cmd", wear_level_max);
	json_object_add_value_int(multi, "Admin Cmd", wear_level_avg);
	json_object_add_value_object(entry_stats, "raw", multi);
	json_object_add_value_object(dev_stats, "Inflight_Command", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "#id", smart->Internal_End_to_End_Dect_Count.key);
	json_object_add_value_int(entry_stats, "normalized", 100);
	multi = json_create_object();
	wear_level_min = le16_to_cpu(smart->Internal_End_to_End_Dect_Count.wear_level.min);
	wear_level_max = le16_to_cpu(smart->Internal_End_to_End_Dect_Count.wear_level.max);
	wear_level_avg = le16_to_cpu(smart->Internal_End_to_End_Dect_Count.wear_level.avg);
	json_object_add_value_int(multi, "read hcrc", wear_level_min);
	json_object_add_value_int(multi, "write hcrc", wear_level_max);
	json_object_add_value_int(multi, "reserved", wear_level_avg);
	json_object_add_value_object(entry_stats, "raw", multi);
	json_object_add_value_object(dev_stats, "internal_end_to_end_dect_count", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "#id", smart->die_fail_count.key);
	json_object_add_value_int(entry_stats, "normalized", smart->die_fail_count.norm);
	raw_val = int48_to_long(smart->die_fail_count.raw);
	json_object_add_value_int(entry_stats, "raw", raw_val);
	json_object_add_value_object(dev_stats, "die_fail_count", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "#id", smart->wear_leveling_exec_count.key);
	json_object_add_value_int(entry_stats, "normalized", smart->wear_leveling_exec_count.norm);
	raw_val = int48_to_long(smart->wear_leveling_exec_count.raw);
	json_object_add_value_int(entry_stats, "raw", raw_val);
	json_object_add_value_object(dev_stats, "wear_leveling_exec_count", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "#id", smart->read_disturb_count.key);
	json_object_add_value_int(entry_stats, "normalized", smart->read_disturb_count.norm);
	raw_val = int48_to_long(smart->read_disturb_count.raw);
	json_object_add_value_int(entry_stats, "raw", raw_val);
	json_object_add_value_object(dev_stats, "read_disturb_count", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "#id", smart->data_retention_count.key);
	json_object_add_value_int(entry_stats, "normalized", smart->data_retention_count.norm);
	raw_val = int48_to_long(smart->data_retention_count.raw);
	json_object_add_value_int(entry_stats, "raw", raw_val);
	json_object_add_value_object(dev_stats, "data_retention_count", entry_stats);

	json_object_add_value_object(root, "Device stats", dev_stats);

	json_print_object(root, NULL);
	json_free_object(root);
}

static
void show_ssstc_add_smart_log(struct nvme_additional_smart_log *smart,
		unsigned int nsid, const char *devname)
{
	printf("Additional Smart Log for NVME device:%s namespace-id:%x\n",
		devname, nsid);
	printf("key                               #id  normalized raw\n");
	printf("program_fail_count              : %03d  %3d%%       %"PRIu64"\n",
		smart->program_fail_cnt.key,
		smart->program_fail_cnt.norm,
		int48_to_long(smart->program_fail_cnt.raw));
	printf("erase_fail_count                : %03d  %3d%%       %"PRIu64"\n",
		smart->erase_fail_cnt.key,
		smart->erase_fail_cnt.norm,
		int48_to_long(smart->erase_fail_cnt.raw));
	printf("wear_leveling                   : %03d  %3d%%       min: %u, max: %u, avg: %u\n",
		smart->wear_leveling_cnt.key,
		smart->wear_leveling_cnt.norm,
		le16_to_cpu(smart->wear_leveling_cnt.wear_level.min),
		le16_to_cpu(smart->wear_leveling_cnt.wear_level.max),
		le16_to_cpu(smart->wear_leveling_cnt.wear_level.avg));
	printf("end_to_end_error_dect_count     : %03d  %3d%%       "
		"guard check error: %u, "
		"application tag check error: %u, "
		"reference tag check error: %u\n",
		smart->e2e_err_cnt.key,
		smart->e2e_err_cnt.norm,
		le16_to_cpu(smart->e2e_err_cnt.wear_level.min),
		le16_to_cpu(smart->e2e_err_cnt.wear_level.max),
		le16_to_cpu(smart->e2e_err_cnt.wear_level.avg));
	printf("crc_error_count                 : %03d  %3d%%       %"PRIu64"\n",
		smart->crc_err_cnt.key,
		smart->crc_err_cnt.norm,
		int48_to_long(smart->crc_err_cnt.raw));
	printf("nand_bytes_written              : %03d  %3d%%       sectors: %"PRIu64"\n",
		smart->nand_bytes_written.key,
		smart->nand_bytes_written.norm,
		int48_to_long(smart->nand_bytes_written.raw));
	printf("host_bytes_written              : %3d  %3d%%       sectors: %"PRIu64"\n",
		smart->host_bytes_written.key,
		smart->host_bytes_written.norm,
		int48_to_long(smart->host_bytes_written.raw));
	printf("reallocated_sector_count        : %03d  %3d%%       %"PRIu64"\n",
		smart->reallocated_sector_count.key,
		smart->reallocated_sector_count.norm,
		int48_to_long(smart->reallocated_sector_count.raw));
	printf("uncorrectable_sector_count      : %03d  %3d%%       %"PRIu64"\n",
		smart->uncorrectable_sector_count.key,
		smart->uncorrectable_sector_count.norm,
		int48_to_long(smart->uncorrectable_sector_count.raw));
	printf("NAND_ECC_detection_count        : %03d  %3d%%       %"PRIu64"\n",
		smart->NAND_ECC_Detection_Count.key,
		smart->NAND_ECC_Detection_Count.norm,
		int48_to_long(smart->NAND_ECC_Detection_Count.raw));
	printf("NAND_ECC_correction_count       : %03d  %3d%%       %"PRIu64"\n",
		smart->NAND_ECC_Correction_Count.key,
		smart->NAND_ECC_Correction_Count.norm,
		int48_to_long(smart->NAND_ECC_Correction_Count.raw));
	printf("GC_count                        : %03d  %3d%%       %"PRIu64"\n",
		smart->GC_Count.key,
		smart->GC_Count.norm,
		int48_to_long(smart->GC_Count.raw));
	printf("DRAM_UECC_detection_count       : %03d  %3d%%       1-Bit Err: %u, 2-Bit Err: %u\n",
		smart->DRAM_UECC_Detection_Count.key,
		smart->DRAM_UECC_Detection_Count.norm,
		le16_to_cpu(smart->DRAM_UECC_Detection_Count.wear_level.max),
		le16_to_cpu(smart->DRAM_UECC_Detection_Count.wear_level.avg));
	printf("SRAM_UECC_Detection_Count       : %03d  %3d%%       "
		"parity error detected: %u, "
		"ecc error detection: %u, "
		"axi data parity errors: %u\n",
		smart->SRAM_UECC_Detection_Count.key,
		smart->SRAM_UECC_Detection_Count.norm,
		le16_to_cpu(smart->SRAM_UECC_Detection_Count.wear_level.min),
		le16_to_cpu(smart->SRAM_UECC_Detection_Count.wear_level.max),
		le16_to_cpu(smart->SRAM_UECC_Detection_Count.wear_level.avg));
	printf("raid_recovery_fail_count        : %03d  %3d%%       %"PRIu64"\n",
		smart->Raid_Recovery_Fail_Count.key,
		smart->Raid_Recovery_Fail_Count.norm,
		int48_to_long(smart->Raid_Recovery_Fail_Count.raw));
	printf("Inflight_Command                : %03d  %3d%%       "
		"Read Cmd: %u, Write Cmd: %u, Admin Cmd: %u\n",
		smart->Inflight_Command.key,
		smart->Inflight_Command.norm,
		le16_to_cpu(smart->Inflight_Command.wear_level.min),
		le16_to_cpu(smart->Inflight_Command.wear_level.max),
		le16_to_cpu(smart->Inflight_Command.wear_level.avg));
	printf("internal_end_to_end_dect_count  : %03d  %3d%%       "
		"read hcrc: %u, write hcrc: %u, reserved: %u\n",
		smart->Internal_End_to_End_Dect_Count.key,
		100,
		le16_to_cpu(smart->Internal_End_to_End_Dect_Count.wear_level.min),
		le16_to_cpu(smart->Internal_End_to_End_Dect_Count.wear_level.max),
		le16_to_cpu(smart->Internal_End_to_End_Dect_Count.wear_level.avg));
	printf("die_fail_count                  : %03d  %3d%%       %"PRIu64"\n",
		smart->die_fail_count.key,
		smart->die_fail_count.norm,
		int48_to_long(smart->die_fail_count.raw));
	printf("wear_leveling_exec_count        : %03d  %3d%%       %"PRIu64"\n",
		smart->wear_leveling_exec_count.key,
		smart->wear_leveling_exec_count.norm,
		int48_to_long(smart->wear_leveling_exec_count.raw));
	printf("read_disturb_count              : %03d  %3d%%       %"PRIu64"\n",
		smart->read_disturb_count.key,
		smart->read_disturb_count.norm,
		int48_to_long(smart->read_disturb_count.raw));
	printf("data_retention_count            : %03d  %3d%%       %"PRIu64"\n",
		smart->data_retention_count.key,
		smart->data_retention_count.norm,
		int48_to_long(smart->data_retention_count.raw));
}

static
int ssstc_get_add_smart_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{

	const char *desc =
		"Get SSSTC vendor specific additional smart log\n"
		"(optionally, for the specified namespace), and show it.";
	const char *namespace = "(optional) desired namespace";
	const char *raw = "Dump output in binary format";
#ifdef CONFIG_JSONC
	const char *json = "Dump output in json format";
#endif /* CONFIG_JSONC */

	struct nvme_additional_smart_log smart_log_add;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	int err;

	struct config {
		__u32 namespace_id;
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

	err = nvme_get_log_simple(hdl, 0xca, sizeof(smart_log_add),
				  &smart_log_add);
	if (!err) {
		if (cfg.json)
			show_ssstc_add_smart_log_jsn(
				&smart_log_add, cfg.namespace_id,
				nvme_transport_handle_get_name(hdl));
		else if (!cfg.raw_binary)
			show_ssstc_add_smart_log(
				&smart_log_add, cfg.namespace_id,
				nvme_transport_handle_get_name(hdl));
		else
			d_raw((unsigned char *)&smart_log_add, sizeof(smart_log_add));
	} else if (err > 0) {
		nvme_show_status(err);
	}
	return err;

}
