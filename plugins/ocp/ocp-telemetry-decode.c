// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (c) 2024 Western Digital Corporation or its affiliates.
 *
 * Authors: Jeff Lien <jeff.lien@wdc.com>,
 */

#include "common.h"
#include "nvme.h"
#include "libnvme.h"
#include "plugin.h"
#include "linux/types.h"
#include "util/types.h"
#include "nvme-print.h"

#include "ocp-telemetry-decode.h"


void print_vu_event_data(__u32 size, __u8 *data)
{
	int j;
	__u16 vu_event_id = *(__u16 *)data;

	printf("  VU Event ID   : 0x%02x\n", le16_to_cpu(vu_event_id));
	printf("  VU Data       : 0x");
	for (j = 2; j < size; j++)
		printf("%x", data[j]);
	printf("\n\n");
}

void print_stats_desc(struct telemetry_stats_desc *stat_desc)
{
	int j;
	/* Get the statistics Identifier string name and data size  */
	__u16 stat_id = stat_desc->id;
	__u32 stat_data_sz = ((stat_desc->size) * 4);

	printf("Statistics Identifier         : 0x%x, %s\n",
			stat_id, telemetry_stat_id_to_string(stat_id));
	printf("Statistics info               : 0x%x\n", stat_desc->info);
	printf("NS info                       : 0x%x\n", stat_desc->ns_info);
	printf("Statistic Data Size           : 0x%x\n", le16_to_cpu(stat_data_sz));

	if (stat_data_sz > 0) {
		printf("%s  : 0x",
				telemetry_stat_id_to_string(stat_id));
		for (j = 0; j < stat_data_sz; j++)
			printf("%02x", stat_desc->data[j]);
		printf("\n");
	}
	printf("\n");
}

void print_telemetry_fifo_event(__u8 class_type,
		__u16 id, __u8 size_dw, __u8 *data)
{
	int j;
	const char *class_str = NULL;
	__u32 size = size_dw * 4;
	char time_str[40];
	uint64_t timestamp = 0;
	memset((void *)time_str, '\0', 40);

	if (class_type) {
		class_str = telemetry_event_class_to_string(class_type);
		printf("Event Class : %s\n", class_str);
	}

	switch (class_type)	{
	case TELEMETRY_TIMESTAMP_CLASS:
		timestamp = (0x0000FFFFFFFFFFFF & le64_to_cpu(*(uint64_t *)data));

		memset((void *)time_str, 0, 9);
		sprintf((char *)time_str, "%04d:%02d:%02d", (int)(le64_to_cpu(timestamp)/3600),
				(int)((le64_to_cpu(timestamp%3600)/60)),
				(int)(le64_to_cpu(timestamp%60)));

		printf("  Event ID  : 0x%02x %s\n", id, telemetry_ts_event_to_string(id));
		printf("  Timestamp : %s\n", time_str);
		printf("  Size      : %d\n", size);
		if (size > 8) {
			printf("  VU Data : 0x");
			for (j = 8; j < size; j++)
				printf("%02x", data[j]);
			printf("\n\n");
		}
		break;

	case TELEMETRY_PCIE_CLASS:
		printf("  Event ID : 0x%02x %s\n",
			id, telemetry_pcie_event_id_to_string(id));
		printf("  State    : 0x%02x %s\n",
			data[0], telemetry_pcie_state_data_to_string(data[0]));
		printf("  Speed    : 0x%02x %s\n",
			data[1], telemetry_pcie_speed_data_to_string(data[1]));
		printf("  Width    : 0x%02x %s\n",
			data[2], telemetry_pcie_width_data_to_string(data[2]));
		if (size > 4) {
			printf("  VU Data : ");
			for (j = 4; j < size; j++)
				printf("%x", data[j]);
			printf("\n\n");
		}
		break;

	case TELEMETRY_NVME_CLASS:
		printf("  Event ID          : 0x%02x %s\n",
			id, telemetry_nvme_event_id_to_string(id));
		if ((id == ADMIN_QUEUE_NONZERO_STATUS) ||
			(id == IO_QUEUE_NONZERO_STATUS)) {
			printf("  Cmd Op Code   : 0x%02x\n", data[0]);
			__u16 status = *(__u16 *)&data[1];
			__u16 cmd_id = *(__u16 *)&data[3];
			__u16 sq_id = *(__u16 *)&data[5];

			printf("  Status Code   : 0x%04x\n", le16_to_cpu(status));
			printf("  Cmd ID        : 0x%04x\n", le16_to_cpu(cmd_id));
			printf("  SQ ID         : 0x%04x\n", le16_to_cpu(sq_id));
		} else if (id == CC_REGISTER_CHANGED) {
			__u32 cc_reg_data = *(__u32 *)data;

			printf("  CC Reg Data   : 0x%08x\n",
					le32_to_cpu(cc_reg_data));
		} else if (id == CSTS_REGISTER_CHANGED) {
			__u32 csts_reg_data = *(__u32 *)data;

			printf("  CSTS Reg Data : 0x%08x\n",
					le32_to_cpu(csts_reg_data));
		}
		if (size > 8)
			print_vu_event_data(size, (__u8 *)&data[8]);
		break;

	case TELEMETRY_RESET_CLASS:
		printf("  Event ID          : 0x%02x %s\n",
			id, telemetry_reset_event_id_to_string(id));
		if (size)
			print_vu_event_data(size, data);
		break;

	case TELEMETRY_BOOT_SEQ_CLASS:
		printf("  Event ID          : 0x%02x %s\n",
			id, telemetry_boot_seq_event_id_to_string(id));
		if (size)
			print_vu_event_data(size, data);
		break;

	case TELEMETRY_FW_ASSERT_CLASS:
		printf("  Event ID          : 0x%02x %s\n",
			id, telemetry_fw_assert_event_id_to_string(id));
		if (size)
			print_vu_event_data(size, data);
		break;

	case TELEMETRY_TEMPERATURE_CLASS:
		printf("  Event ID          : 0x%02x %s\n",
			id, telemetry_temperature_event_id_to_string(id));
		if (size)
			print_vu_event_data(size, data);
		break;

	case TELEMETRY_MEDIA_DBG_CLASS:
		printf("  Event ID          : 0x%02x %s\n",
			id, telemetry_media_debug_event_id_to_string(id));
		if (size)
			print_vu_event_data(size, data);
		break;

	case TELEMETRY_MEDIA_WEAR_CLASS:
		printf("  Event ID          : 0x%02x %s\n",
			id, telemetry_media_debug_event_id_to_string(id));
		__u32 host_tb_written = *(__u32 *)&data[0];
		__u32 media_tb_written = *(__u32 *)&data[4];
		__u32 media_tb_erased = *(__u32 *)&data[8];

		printf("  Host TB Written   : 0x%04x\n",
			le16_to_cpu(host_tb_written));
		printf("  Media TB Written  : 0x%04x\n",
			le16_to_cpu(media_tb_written));
		printf("  Media TB Erased   : 0x%04x\n",
			le16_to_cpu(media_tb_erased));

		if (size > 12)
			print_vu_event_data(size, (__u8 *)&data[12]);
		break;

	case TELEMETRY_STAT_SNAPSHOT_CLASS:
		printf("  Statistic ID      : 0x%02x %s\n",
			id, telemetry_stat_id_to_string(id));
		print_stats_desc((struct telemetry_stats_desc *)data);
		break;

	default:
		/*
		 * printf("Unknown Event Class Type\n");
		 * printf("Data : 0x");
		 * for (j = 0; j < size; j++)
		 *   printf("%x", data[j]);
		 * printf("\n\n");
		 */
		break;
	}
}
