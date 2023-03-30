// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2022 Solidigm.
 *
 * Author: karl.dedow@solidigm.com
 */

#include "ocp-fw-activation-history.h"

#include <errno.h>
#include <stdio.h>

#include "common.h"
#include "nvme-print.h"

#include "ocp-utils.h"

static const unsigned char ocp_fw_activation_history_guid[16] = {
	0x6D, 0x79, 0x9a, 0x76,
	0xb4, 0xda, 0xf6, 0xa3,
	0xe2, 0x4d, 0xb2, 0x8a,
	0xac, 0xf3, 0x1c, 0xd1
};

struct __attribute__ ((packed)) fw_activation_history_entry {
	__u8 ver_num;
	__u8 entry_length;
	__u16 reserved1;
	__u16 activation_count;
	__u64 timestamp;
	__u64 reserved2;
	__u64 power_cycle_count;
	char previous_fw[8];
	char new_fw[8];
	__u8 slot_number;
	__u8 commit_action;
	__u16 result;
	__u8 reserved3[14];
};

struct __attribute__ ((packed)) fw_activation_history {
	__u8 log_id;
	__u8 reserved1[3];
	__u32 valid_entries;
	struct fw_activation_history_entry entries[20];
	__u8 reserved2[2790];
	__u16 log_page_version;
	__u64 log_page_guid[2];
};

static void ocp_fw_activation_history_normal(const struct fw_activation_history *fw_history)
{
	printf("Firmware History Log:\n");

	printf("  %-26s%d\n", "log identifier:", fw_history->log_id);
	printf("  %-26s%d\n", "valid entries:", le32_to_cpu(fw_history->valid_entries));

	printf("  entries:\n");

	for (int index = 0; index < fw_history->valid_entries; index++) {
		const struct fw_activation_history_entry *entry = &fw_history->entries[index];

		printf("    entry[%d]:\n", le32_to_cpu(index));
		printf("      %-22s%d\n", "version number:", entry->ver_num);
		printf("      %-22s%d\n", "entry length:", entry->entry_length);
		printf("      %-22s%d\n", "activation count:",
		       le16_to_cpu(entry->activation_count));
		printf("      %-22s%"PRIu64"\n", "timestamp:",
		       le64_to_cpu(entry->timestamp));
		printf("      %-22s%"PRIu64"\n", "power cycle count:",
		       le64_to_cpu(entry->power_cycle_count));
		printf("      %-22s%.*s\n", "previous firmware:", (int)sizeof(entry->previous_fw),
		       entry->previous_fw);
		printf("      %-22s%.*s\n", "new firmware:", (int)sizeof(entry->new_fw),
		       entry->new_fw);
		printf("      %-22s%d\n", "slot number:", entry->slot_number);
		printf("      %-22s%d\n", "commit action type:", entry->commit_action);
		printf("      %-22s%d\n", "result:",  le16_to_cpu(entry->result));
	}

	printf("  %-26s%d\n", "log page version:",
	       le16_to_cpu(fw_history->log_page_version));

	printf("  %-26s0x%"PRIx64"%"PRIx64"\n", "log page guid:",
	       le64_to_cpu(fw_history->log_page_guid[1]),
	       le64_to_cpu(fw_history->log_page_guid[0]));

	printf("\n");
}

static void ocp_fw_activation_history_json(const struct fw_activation_history *fw_history)
{
	struct json_object *root = json_create_object();

	json_object_add_value_uint(root, "log identifier", fw_history->log_id);
	json_object_add_value_uint(root, "valid entries", le32_to_cpu(fw_history->valid_entries));

	struct json_object *entries = json_create_array();

	for (int index = 0; index < fw_history->valid_entries; index++) {
		const struct fw_activation_history_entry *entry = &fw_history->entries[index];
		struct json_object *entry_obj = json_create_object();

		json_object_add_value_uint(entry_obj, "version number", entry->ver_num);
		json_object_add_value_uint(entry_obj, "entry length", entry->entry_length);
		json_object_add_value_uint(entry_obj, "activation count",
					   le16_to_cpu(entry->activation_count));
		json_object_add_value_uint64(entry_obj, "timestamp",
					     le64_to_cpu(entry->timestamp));
		json_object_add_value_uint(entry_obj, "power cycle count",
					   le64_to_cpu(entry->power_cycle_count));

		struct json_object *fw = json_object_new_string_len(entry->previous_fw,
								    sizeof(entry->previous_fw));

		json_object_add_value_object(entry_obj, "previous firmware", fw);

		fw = json_object_new_string_len(entry->new_fw, sizeof(entry->new_fw));

		json_object_add_value_object(entry_obj, "new firmware", fw);
		json_object_add_value_uint(entry_obj, "slot number", entry->slot_number);
		json_object_add_value_uint(entry_obj, "commit action type", entry->commit_action);
		json_object_add_value_uint(entry_obj, "result", le16_to_cpu(entry->result));

		json_array_add_value_object(entries, entry_obj);
	}

	json_object_add_value_array(root, "entries", entries);

	json_object_add_value_uint(root, "log page version",
				   le16_to_cpu(fw_history->log_page_version));

	char guid[2 * sizeof(fw_history->log_page_guid) + 3] = { 0 };

	sprintf(guid, "0x%"PRIx64"%"PRIx64"",
		le64_to_cpu(fw_history->log_page_guid[1]),
		le64_to_cpu(fw_history->log_page_guid[0]));
	json_object_add_value_string(root, "log page guid", guid);

	json_print_object(root, NULL);
	json_free_object(root);

	printf("\n");
}

int ocp_fw_activation_history_log(int argc, char **argv, struct command *cmd,
				  struct plugin *plugin)
{
	const __u8 log_id = 0xC2;
	const char *description = "Retrieves the OCP firmware activation history log.";

	char *format = "normal";

	OPT_ARGS(options) = {
		OPT_FMT("output-format", 'o', &format, "output format : normal | json"),
		OPT_END()
	};

	struct nvme_dev *dev = NULL;
	int err = parse_and_open(&dev, argc, argv, description, options);

	if (err)
		return err;

	int uuid_index = 0;

	/*
	 * Best effort attempt at uuid. Otherwise, assume no index (i.e. 0)
	 * Log GUID check will ensure correctness of returned data
	 */
	ocp_get_uuid_index(dev, &uuid_index);

	struct fw_activation_history fw_history = { 0 };

	struct nvme_get_log_args args = {
		.lpo = 0,
		.result = NULL,
		.log = &fw_history,
		.args_size = sizeof(args),
		.fd = dev_fd(dev),
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.lid = log_id,
		.len = sizeof(fw_history),
		.nsid = NVME_NSID_ALL,
		.csi = NVME_CSI_NVM,
		.lsi = NVME_LOG_LSI_NONE,
		.lsp = 0,
		.uuidx = uuid_index,
		.rae = false,
		.ot = false,
	};

	err = nvme_get_log(&args);

	if (err)
		nvme_show_status(err);

	dev_close(dev);

	int guid_cmp_res = memcmp(fw_history.log_page_guid, ocp_fw_activation_history_guid,
				  sizeof(ocp_fw_activation_history_guid));

	if (!err && guid_cmp_res) {
		fprintf(stderr,
			"Error: Unexpected data. Log page guid does not match with expected.\n");
		err = -EINVAL;
	}

	if (!err) {
		const enum nvme_print_flags print_flag = validate_output_format(format);

		if (print_flag == JSON)
			ocp_fw_activation_history_json(&fw_history);
		else if (print_flag == NORMAL)
			ocp_fw_activation_history_normal(&fw_history);
		else {
			fprintf(stderr, "Error: Invalid output format.\n");
			err = -EINVAL;
		}
	}

	return err;
}
