// SPDX-License-Identifier: GPL-2.0-or-later
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "nvme.h"
#include "libnvme.h"
#include "plugin.h"
#include "linux/types.h"
#include "nvme-print.h"

#define CREATE_CMD
#include "ymtc-nvme.h"
#include "ymtc-utils.h"

static void get_ymtc_smart_info(struct nvme_ymtc_smart_log *smart, int index, u8 *nm_val, u8 *raw_val)
{
	memcpy(nm_val, smart->itemArr[index].nmVal, NM_SIZE);
	memcpy(raw_val, smart->itemArr[index].rawVal, RAW_SIZE);
}

static int show_ymtc_smart_log(struct nvme_transport_handle *hdl, __u32 nsid,
			       struct nvme_ymtc_smart_log *smart)
{
	struct nvme_id_ctrl ctrl;
	char fw_ver[10];
	int err = 0;

	u8 *nm = malloc(NM_SIZE * sizeof(u8));
	u8 *raw = malloc(RAW_SIZE * sizeof(u8));

	if (!nm) {
		free(raw);
		return -1;
	}
	if (!raw) {
		free(nm);
		return -1;
	}
	err = nvme_identify_ctrl(hdl, &ctrl);
	if (err) {
		free(nm);
		free(raw);
		return err;
	}

	snprintf(fw_ver, sizeof(fw_ver), "%c.%c%c.%c%c%c%c",
		 ctrl.fr[0], ctrl.fr[1], ctrl.fr[2], ctrl.fr[3],
		 ctrl.fr[4], ctrl.fr[5], ctrl.fr[6]);

	/* Table Title */
	printf("Additional Smart Log for NVME device:%s namespace-id:%x\n",
	       nvme_transport_handle_get_name(hdl), nsid);
	/* Column Name*/
	printf("key                               normalized raw\n");
	/* 00 SI_VD_PROGRAM_FAIL */
	get_ymtc_smart_info(smart, SI_VD_PROGRAM_FAIL, nm, raw);
	printf("program_fail_count              : %3d%%       %"PRIu64"\n", *nm, int48_to_long(raw));
	/* 01 SI_VD_ERASE_FAIL */
	get_ymtc_smart_info(smart, SI_VD_ERASE_FAIL, nm, raw);
	printf("erase_fail_count                : %3d%%       %"PRIu64"\n", *nm, int48_to_long(raw));
	/* 02 SI_VD_WEARLEVELING_COUNT */
	get_ymtc_smart_info(smart, SI_VD_WEARLEVELING_COUNT, nm, raw);
	printf("wear_leveling                   : %3d%%       min: %u, max: %u, avg: %u\n", *nm,
	       *(uint16_t *)raw, *(uint16_t *)(raw+2), *(uint16_t *)(raw+4));
	/* 03 SI_VD_E2E_DECTECTION_COUNT */
	get_ymtc_smart_info(smart, SI_VD_E2E_DECTECTION_COUNT, nm, raw);
	printf("end_to_end_error_detection_count: %3d%%       %"PRIu64"\n", *nm, int48_to_long(raw));
	/* 04 SI_VD_PCIE_CRC_ERR_COUNT */
	get_ymtc_smart_info(smart, SI_VD_PCIE_CRC_ERR_COUNT, nm, raw);
	printf("crc_error_count                 : %3d%%       %"PRIu32"\n", *nm, *(uint32_t *)raw);
	/* 08 SI_VD_THERMAL_THROTTLE_STATUS */
	get_ymtc_smart_info(smart, SI_VD_THERMAL_THROTTLE_STATUS, nm, raw);
	printf("thermal_throttle_status         : %3d%%       %d%%, cnt: %"PRIu32"\n", *nm,
	       *raw, *(uint32_t *)(raw+1));
	/* 11 SI_VD_TOTAL_WRITE */
	get_ymtc_smart_info(smart, SI_VD_TOTAL_WRITE, nm, raw);
	printf("nand_bytes_written              : %3d%%       sectors: %"PRIu64"\n", *nm, int48_to_long(raw));
	/* 12 SI_VD_HOST_WRITE */
	get_ymtc_smart_info(smart, SI_VD_HOST_WRITE, nm, raw);
	printf("host_bytes_written              : %3d%%       sectors: %"PRIu64"\n", *nm, int48_to_long(raw));
	/* 14 SI_VD_TOTAL_READ */
	get_ymtc_smart_info(smart, SI_VD_TOTAL_READ, nm, raw);
	printf("nand_bytes_read                 : %3d%%       %"PRIu64"\n", *nm, int48_to_long(raw));
	/* 15 SI_VD_TEMPT_SINCE_BORN */
	get_ymtc_smart_info(smart, SI_VD_TEMPT_SINCE_BORN, nm, raw);
	printf("tempt_since_born                : %3d%%       max: %u, min: %u, curr: %u\n",  *nm,
	       *(uint16_t *)raw-273, *(uint16_t *)(raw+2)-273, *(int16_t *)(raw+4)-273);
	/* 16 SI_VD_POWER_CONSUMPTION */
	get_ymtc_smart_info(smart, SI_VD_POWER_CONSUMPTION, nm, raw);
	printf("power_consumption               : %3d%%       max: %u, min: %u, curr: %u\n",  *nm,
	       *(uint16_t *)raw, *(uint16_t *)(raw+2), *(uint16_t *)(raw+4));
	/* 17 SI_VD_TEMPT_SINCE_BOOTUP */
	get_ymtc_smart_info(smart, SI_VD_TEMPT_SINCE_BOOTUP, nm, raw);
	printf("tempt_since_bootup              : %3d%%       max: %u, min: %u, curr: %u\n",  *nm,
	       *(uint16_t *)raw-273, *(uint16_t *)(raw+2)-273, *(uint16_t *)(raw+4)-273);
	/* 18 SI_VD_POWER_LOSS_PROTECTION */
	get_ymtc_smart_info(smart, SI_VD_POWER_LOSS_PROTECTION, nm, raw);
	printf("power_loss_protection           : %3d%%       %"PRIu64"\n", *nm, int48_to_long(raw));
	/* 19 SI_VD_READ_FAIL */
	get_ymtc_smart_info(smart, SI_VD_READ_FAIL, nm, raw);
	printf("read_fail                       : %3d%%       %"PRIu64"\n", *nm, int48_to_long(raw));
	/* 20 SI_VD_THERMAL_THROTTLE_TIME */
	get_ymtc_smart_info(smart, SI_VD_THERMAL_THROTTLE_TIME, nm, raw);
	printf("thermal_throttle_time           : %3d%%       %u, time: %"PRIu32"\n", *nm,
	       *raw, *(uint32_t *)(raw+1));
	/* 21 SI_VD_FLASH_MEDIA_ERROR */
	get_ymtc_smart_info(smart, SI_VD_FLASH_MEDIA_ERROR, nm, raw);
	printf("flash_error_media_count         : %3d%%       %"PRIu64"\n", *nm, int48_to_long(raw));

	free(nm);
	free(raw);

	return err;
}

static int get_additional_smart_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	struct nvme_ymtc_smart_log smart_log;
	char *desc =
	    "Get Ymtc vendor specific additional smart log (optionally, for the specified namespace), and show it.";
	const char *namespace = "(optional) desired namespace";
	const char *raw = "dump output in binary format";
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	struct config {
		__u32 namespace_id;
		bool  raw_binary;
	};
	int err;

	struct config cfg = {
		.namespace_id = NVME_NSID_ALL,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id,  namespace),
		OPT_FLAG("raw-binary",	 'b', &cfg.raw_binary,	  raw),
		OPT_END()
	};

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = nvme_get_nsid_log(hdl, false, 0xca, cfg.namespace_id,
				sizeof(smart_log), &smart_log);
	if (!err) {
		if (!cfg.raw_binary)
			err = show_ymtc_smart_log(hdl, cfg.namespace_id, &smart_log);
		else
			d_raw((unsigned char *)&smart_log, sizeof(smart_log));
	}
	if (err > 0)
		nvme_show_status(err);

	return err;
}
