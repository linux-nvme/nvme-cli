// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Solidigm.
 *
 * Author: karl.dedow@solidigm.com
 */

#include "solidigm-log-page-dir.h"

#include <errno.h>
#include <stdio.h>

#include "common.h"
#include "nvme-print.h"

#include "plugins/ocp/ocp-utils.h"

struct __attribute__((packed)) supported_log_pages {
	__u32 supported[256];
};

struct log_description {
	int lid;
	const char *description;
};

static const unsigned char ocp_uuid[NVME_UUID_LEN] = {
	0xc1, 0x94, 0xd5, 0x5b, 0xe0, 0x94, 0x47, 0x94, 0xa2, 0x1d,
	0x29, 0x99, 0x8f, 0x56, 0xbe, 0x6f };

static const unsigned char solidigm_uuid[NVME_UUID_LEN] = { 
	0x96, 0x19, 0x58, 0x6e, 0xc1, 0x1b, 0x43, 0xad, 0xaa, 0xaa,
	0x65, 0x41, 0x87, 0xf6, 0xbb, 0xb2 
};

enum solidigm_uuid {
	NO_UUID,
	INVALID_UUID,
	SOLIDIGM_UUID,
	OCP_UUID,
};

static int get_uuid_index(struct nvme_id_uuid_list *uuid_list, const unsigned char *uuid)
{
	// Some Solidigm drives have swapped UUIDs, so check for that too..
	unsigned char swapped_uuid[NVME_UUID_LEN] = { 0 };
	for (int index = NVME_UUID_LEN - 1; index >= 0; index--)
		swapped_uuid[NVME_UUID_LEN - index - 1] = uuid[index];

	const unsigned char *uuids[2] = { uuid, swapped_uuid };

	for (int index = 0; index < NVME_ID_UUID_LIST_MAX; index++) {
		for (int count = 0; count < sizeof(uuids) / sizeof(unsigned char *); count++) {
			if (!memcmp(uuids[count], &uuid_list->entry[index].uuid, NVME_UUID_LEN))
				return index + 1;
		}
	}

	return -1;
}

static enum solidigm_uuid get_uuid_enum(struct nvme_dev *dev, const int uuid_index)
{
	if (uuid_index == 0)
		return NO_UUID;
	
	if (uuid_index < 0 || uuid_index > 127)
		return INVALID_UUID;

	struct nvme_id_uuid_list uuid_list;
	int err = nvme_identify_uuid(dev_fd(dev), &uuid_list);

	// If UUID list not supported, then the logs are assumed to be Solidigm (legacy)
	if (err)
		return INVALID_UUID;

	int ocp_uuid_index = get_uuid_index(&uuid_list, ocp_uuid);

	if (ocp_uuid_index == uuid_index)
		return OCP_UUID;
	
	int solidigm_uuid_index = get_uuid_index(&uuid_list, solidigm_uuid);

	if (solidigm_uuid_index == uuid_index)
		return SOLIDIGM_UUID;
	
	return INVALID_UUID;
}

static const char *lid_desc_from_struct(const int lid, const int log_desc_size,
					struct log_description *log_desc)
{
	for (int index = 0; index < log_desc_size; index++) {
		if (lid == log_desc[index].lid)
			return log_desc[index].description;
	}

	return "Unknown";
}

static const char *lid_to_desc(const int lid, const enum solidigm_uuid uuid)
{
	static struct log_description standard_log_descs[] = {
		{ 0x00, "Supported Log Pages"},
		{ 0x01, "Error Information"},
		{ 0x02, "SMART / Health Information"},
		{ 0x03, "Firmware Slot Information"},
		{ 0x04, "Changed Namespace List"},
		{ 0x05, "Commands Supported and Effects"},
		{ 0x06, "Device Self Test"},
		{ 0x07, "Telemetry Host-Initiated"},
		{ 0x08, "Telemetry Controller-Initiated"},
		{ 0x09, "Endurance Group Information"},
		{ 0x0A, "Predictable Latency Per NVM Set"},
		{ 0x0B, "Predictable Latency Event Aggregate"},
		{ 0x0C, "Asymmetric Namespace Access"},
		{ 0x0D, "Persistent Event Log"},
		{ 0x0E, "Predictable Latency Event Aggregate"},
		{ 0x0F, "Endurance Group Event Aggregate"},
		{ 0x10, "Media Unit Status"},
		{ 0x11, "Supported Capacity Configuration List"},
		{ 0x12, "Feature Identifiers Supported and Effects"},
		{ 0x13, "NVMe-MI Commands Supported and Effects"},
		{ 0x14, "Command and Feature lockdown"},
		{ 0x15, "Boot Partition"},
		{ 0x16, "Rotational Media Information"},
		{ 0x70, "Discovery"},
		{ 0x80, "Reservation Notification"},
		{ 0x81, "Sanitize Status"},
	};
	const int standard_log_size = sizeof(standard_log_descs) / sizeof(struct log_description);

	static struct log_description ocp_log_descs[] = {
		{ 0xC0, "OCP SMART / Health Information Extended" },
		{ 0xC1, "OCP Error Recovery" },
		{ 0xC2, "OCP Firmware Activation History" },
		{ 0xC3, "OCP Latency Monitor" },
		{ 0xC4, "OCP Device Capabilities" },
		{ 0xC5, "OCP Unsupported Requirements" },
	};
	const int ocp_log_size = sizeof(ocp_log_descs) / sizeof(struct log_description);

	static struct log_description solidigm_log_descs[] = {
		{ 0xC1, "Read Commands Latency Statistics" },
		{ 0xC2, "Write Commands Latency Statistics" },
		{ 0xC4, "Endurance Manager Statistics" },
		{ 0xC5, "Temperature Statistics" },
		{ 0xCA, "SMART Attributes" },
	};
	const int solidigm_log_size = sizeof(solidigm_log_descs) / sizeof(struct log_description);

	static struct log_description all_vu_log_descs[] = {
		{ 0xC0, "OCP SMART / Health Information Extended" },
		{ 0xC1, "OCP Error Recovery or Read Commands Latency Statistics" },
		{ 0xC2, "OCP Firmware Activation History or Write Commands Latency Statistics" },
		{ 0xC3, "OCP Latency Monitor" },
		{ 0xC4, "OCP Device Capabilities or Endurance Manager Statistics" },
		{ 0xC5, "OCP Unsupported Requirements or Temperature Statistics" },
		{ 0xCA, "SMART Attributes" },
	};
	const int all_vu_log_size = sizeof(all_vu_log_descs) / sizeof(struct log_description);

	// Standard logs are less than 0xC0
	if (lid < 0xC0)
		return lid_desc_from_struct(lid, standard_log_size, standard_log_descs);
	else if (uuid == OCP_UUID)
		return lid_desc_from_struct(lid, ocp_log_size, ocp_log_descs);
	// Otherwise these are Solidigm logs.
	else if (uuid == SOLIDIGM_UUID)
		return lid_desc_from_struct(lid, solidigm_log_size, solidigm_log_descs);
	else if (uuid == NO_UUID)
		return lid_desc_from_struct(lid, all_vu_log_size, all_vu_log_descs);

	return "Unknown";
}

static void solidigm_supported_log_pages_print(const struct supported_log_pages *supported,
					       const enum solidigm_uuid uuid)
{
	printf("Log Page Directory Log:\n");
	printf("  Supported:\n");

	for (int lid = 0; lid < sizeof(supported->supported) / sizeof(__u32); lid++) {
		if (supported->supported[lid] == 0)
			continue;

		printf("    Log Page:\n");
		printf("      %-16s0x%02x\n", "LID:", le32_to_cpu(lid));
		printf("      %-16s%s\n", "Description:", lid_to_desc(lid, uuid));
	}

	printf("\n");
}

static void solidigm_supported_log_pages_json(const struct supported_log_pages *supported,
					      const enum solidigm_uuid uuid)
{
	struct json_object *root = json_create_object();
	struct json_object *supported_arry = json_create_array();

	for (int lid = 0; lid < sizeof(supported->supported) / sizeof(__u32); lid++) {
		if (supported->supported[lid] == 0)
			continue;

		struct json_object *supported_obj = json_create_object();

		json_object_add_value_uint(supported_obj, "lid", le32_to_cpu(lid));
		json_object_add_value_string(supported_obj, "description",
					     lid_to_desc(lid, uuid));

		json_array_add_value_object(supported_arry, supported_obj);
	}

	json_object_add_value_array(root, "supported", supported_arry);

	json_print_object(root, NULL);
	json_free_object(root);

	printf("\n");
}

int solidigm_get_log_page_directory_log(int argc, char **argv, struct command *cmd,
					struct plugin *plugin)
{
	const __u8 log_id = 0x00;
	int uuid_index = 0;
	enum solidigm_uuid uuid = INVALID_UUID;

	const char *description = "Retrieves and parses supported log pages log.";
	char *format = "normal";

	OPT_ARGS(options) = {
		OPT_INT("uuid-index", 'u', &uuid_index, "UUID index value : (integer)"),
		OPT_FMT("output-format", 'o', &format, "output format : normal | json"),
		OPT_END()
	};

	struct nvme_dev *dev = NULL;
	int err = parse_and_open(&dev, argc, argv, description, options);

	if (err)
		return err;

	struct supported_log_pages supported_data = { 0 };

	struct nvme_get_log_args args = {
		.lpo = 0,
		.result = NULL,
		.log = &supported_data,
		.args_size = sizeof(args),
		.fd = dev_fd(dev),
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.lid = log_id,
		.len = sizeof(supported_data),
		.nsid = NVME_NSID_ALL,
		.csi = NVME_CSI_NVM,
		.lsi = NVME_LOG_LSI_NONE,
		.lsp = 0,
		.uuidx = uuid_index,
		.rae = false,
		.ot = false,
	};

	err = nvme_get_log(&args);

	if (!err) {
		uuid = get_uuid_enum(dev, uuid_index);

		if (uuid == INVALID_UUID) {
			fprintf(stderr, "Error: Invalid UUID value: %d.\n", uuid_index);
			err = -EINVAL;
		}
	} else
		nvme_show_status(err);
	
	
	if (!err) {
		const enum nvme_print_flags print_flag = validate_output_format(format);

		if (print_flag == JSON)
			solidigm_supported_log_pages_json(&supported_data, uuid);
		else if (print_flag == NORMAL)
			solidigm_supported_log_pages_print(&supported_data, uuid);
		else {
			fprintf(stderr, "Error: Invalid output format specified.\n");
			err = -EINVAL;
		}
	}

	dev_close(dev);
	return err;
}
