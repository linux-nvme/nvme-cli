/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2022 Solidigm.
 *
 * Authors: karl.dedow@solidigm.com
 */
#include <libnvme.h>
#include "common.h"
#include "linux/types.h"

#ifndef OCP_FIRMWARE_ACTIVATION_HISTORY_H
#define OCP_FIRMWARE_ACTIVATION_HISTORY_H

struct command;
struct plugin;

struct __packed fw_activation_history_entry {
	__u8 ver_num;
	__u8 entry_length;
	__le16 reserved1;
	__le16 activation_count;
	struct nvme_timestamp ts;
	__le64 reserved2;
	__le64 power_cycle_count;
	char previous_fw[8];
	char new_fw[8];
	__u8 slot_number;
	__u8 commit_action;
	__le16 result;
	__u8 reserved3[14];
};

struct __packed fw_activation_history {
	__u8 log_id;
	__u8 reserved1[3];
	__le32 valid_entries;
	struct fw_activation_history_entry entries[20];
	__u8 reserved2[2790];
	__le16 log_page_version;
	__le64 log_page_guid[2];
};

int ocp_fw_activation_history_log(int argc, char **argv, struct command *acmd,
				  struct plugin *plugin);

#endif
