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

static const int MIN_VENDOR_LID = 0xC0;

struct lid_dir {
	struct __attribute__((packed)) {
		bool supported;
		const char *str;
	} lid[NVME_LOG_SUPPORTED_LOG_PAGES_MAX];
};

static void init_lid_dir(struct lid_dir *lid_dir)
{
	static const char *unknown_str = "Unknown";

	for (int lid = 0; lid < NVME_LOG_SUPPORTED_LOG_PAGES_MAX; lid++) {
		lid_dir->lid[lid].supported = false;
		lid_dir->lid[lid].str = unknown_str;
	}
}

static bool is_invalid_uuid(const struct nvme_id_uuid_list_entry entry)
{
	static const unsigned char ALL_ZERO_UUID[NVME_UUID_LEN] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 
	};

	return memcmp(ALL_ZERO_UUID, entry.uuid, NVME_UUID_LEN) == 0;
}

static bool is_solidigm_uuid(const struct nvme_id_uuid_list_entry entry)
{
	static const unsigned char SOLIDIGM_UUID[NVME_UUID_LEN] = {
		0x96, 0x19, 0x58, 0x6e, 0xc1, 0x1b, 0x43, 0xad,
		0xaa, 0xaa, 0x65, 0x41, 0x87, 0xf6, 0xbb, 0xb2
	};

	return memcmp(SOLIDIGM_UUID, entry.uuid, NVME_UUID_LEN) == 0;
}

static bool is_ocp_uuid(const struct nvme_id_uuid_list_entry entry)
{
	static const unsigned char OCP_UUID[NVME_UUID_LEN] = {
		0xc1, 0x94, 0xd5, 0x5b, 0xe0, 0x94, 0x47, 0x94,
		0xa2, 0x1d, 0x29, 0x99, 0x8f, 0x56, 0xbe, 0x6f
	};

	return memcmp(OCP_UUID, entry.uuid, NVME_UUID_LEN) == 0;
}

static int get_supported_log_pages_log(struct nvme_dev *dev, int uuid_index,
				       struct nvme_supported_log_pages *supported)
{
	static const __u8 LID = 0x00;

	memset(supported, 0, sizeof(*supported));
	struct nvme_get_log_args args = {
		.lpo = 0,
		.result = NULL,
		.log = supported,
		.args_size = sizeof(args),
		.fd = dev_fd(dev),
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.lid = LID,
		.len = sizeof(*supported),
		.nsid = NVME_NSID_ALL,
		.csi = NVME_CSI_NVM,
		.lsi = NVME_LOG_LSI_NONE,
		.lsp = 0,
		.uuidx = uuid_index,
		.rae = false,
		.ot = false,
	};

	return nvme_get_log(&args);
}

static struct lid_dir* get_standard_lids(struct nvme_supported_log_pages *supported)
{
	static struct lid_dir standard_dir = { 0 };

	init_lid_dir(&standard_dir);
	standard_dir.lid[0x00].str = "Supported Log Pages";
	standard_dir.lid[0x01].str = "Error Information";
	standard_dir.lid[0x02].str = "SMART / Health Information";
	standard_dir.lid[0x03].str = "Firmware Slot Information";
	standard_dir.lid[0x04].str = "Changed Namespace List";
	standard_dir.lid[0x05].str = "Commands Supported and Effects";
	standard_dir.lid[0x06].str = "Device Self Test";
	standard_dir.lid[0x07].str = "Telemetry Host-Initiated";
	standard_dir.lid[0x08].str = "Telemetry Controller-Initiated";
	standard_dir.lid[0x09].str = "Endurance Group Information";
	standard_dir.lid[0x0A].str = "Predictable Latency Per NVM Set";
	standard_dir.lid[0x0B].str = "Predictable Latency Event Aggregate";
	standard_dir.lid[0x0C].str = "Asymmetric Namespace Access";
	standard_dir.lid[0x0D].str = "Persistent Event Log";
	standard_dir.lid[0x0E].str = "Predictable Latency Event Aggregate";
	standard_dir.lid[0x0F].str = "Endurance Group Event Aggregate";
	standard_dir.lid[0x10].str = "Media Unit Status";
	standard_dir.lid[0x11].str = "Supported Capacity Configuration List";
	standard_dir.lid[0x12].str = "Feature Identifiers Supported and Effects";
	standard_dir.lid[0x13].str = "NVMe-MI Commands Supported and Effects";
	standard_dir.lid[0x14].str = "Command and Feature lockdown";
	standard_dir.lid[0x15].str = "Boot Partition";
	standard_dir.lid[0x16].str = "Rotational Media Information";
	standard_dir.lid[0x70].str = "Discovery";
	standard_dir.lid[0x80].str = "Reservation Notification";
	standard_dir.lid[0x81].str = "Sanitize Status";

	for (int lid = 0; lid < NVME_LOG_SUPPORTED_LOG_PAGES_MAX; lid++) {
		if (!supported->lid_support[lid] || lid >= MIN_VENDOR_LID)
			continue;

		standard_dir.lid[lid].supported = true;
	}

	return &standard_dir;
}

static void update_vendor_lid_supported(struct nvme_supported_log_pages *supported,
					struct lid_dir* lid_dir)
{
	for (int lid = 0; lid < NVME_LOG_SUPPORTED_LOG_PAGES_MAX; lid++) {
		if (!supported->lid_support[lid]|| lid < MIN_VENDOR_LID)
			continue;

		lid_dir->lid[lid].supported = true;
	}
}

static struct lid_dir* get_solidigm_lids(struct nvme_supported_log_pages *supported)
{
	static struct lid_dir solidigm_dir = { 0 };

	init_lid_dir(&solidigm_dir);
	solidigm_dir.lid[0xC1].str = "Read Commands Latency Statistics";
	solidigm_dir.lid[0xC2].str = "Write Commands Latency Statistics";
	solidigm_dir.lid[0xC4].str = "Endurance Manager Statistics";
	solidigm_dir.lid[0xC5].str = "Temperature Statistics";
	solidigm_dir.lid[0xCA].str = "SMART Attributes";

	update_vendor_lid_supported(supported, &solidigm_dir);

	return &solidigm_dir;
}

static struct lid_dir* get_ocp_lids(struct nvme_supported_log_pages *supported)
{
	static struct lid_dir ocp_dir = { 0 };

	init_lid_dir(&ocp_dir);
	ocp_dir.lid[0xC0].str = "OCP SMART / Health Information Extended";
	ocp_dir.lid[0xC1].str = "OCP Error Recovery";
	ocp_dir.lid[0xC2].str = "OCP Firmware Activation History";
	ocp_dir.lid[0xC3].str = "OCP Latency Monitor";
	ocp_dir.lid[0xC4].str = "OCP Device Capabilities";
	ocp_dir.lid[0xC5].str = "OCP Unsupported Requirements";

	update_vendor_lid_supported(supported, &ocp_dir);

	return &ocp_dir;
}

static void supported_log_pages_normal(struct lid_dir *lid_dir[NVME_ID_UUID_LIST_MAX + 1])
{
	printf("Log Page Directory:\n");
	printf("-----------------------------------------------------------------\n");
	printf("| %-5s| %-42s| %-11s|\n", "LID", "Description", "UUID Index");
	printf("-----------------------------------------------------------------\n");

	for (int uuid_index = 0; uuid_index <= NVME_ID_UUID_LIST_MAX; uuid_index++) {
		if (!lid_dir[uuid_index])
			continue;

		for (int lid = 0; lid < NVME_LOG_SUPPORTED_LOG_PAGES_MAX; lid++) {
			if (!lid_dir[uuid_index]->lid[lid].supported)
				continue;

			printf("| 0x%-3.02x", le32_to_cpu(lid));
			printf("| %-42s", lid_dir[uuid_index]->lid[lid].str);
			printf("| %-11d|\n", le32_to_cpu(uuid_index));
		}
	}

	printf("-----------------------------------------------------------------\n");
}

static void supported_log_pages_json(struct lid_dir *lid_dir[NVME_ID_UUID_LIST_MAX + 1])
{
	struct json_object *root = json_create_object();
	struct json_object *supported_arry = json_create_array();

	for (int uuid_index = 0; uuid_index <= NVME_ID_UUID_LIST_MAX; uuid_index++) {
		if (!lid_dir[uuid_index])
			continue;

		for (int lid = 0; lid < NVME_LOG_SUPPORTED_LOG_PAGES_MAX; lid++) {
			if (!lid_dir[uuid_index]->lid[lid].supported)
				continue;

			struct json_object *lid_obj = json_create_object();

			json_object_add_value_uint(lid_obj, "lid", le32_to_cpu(lid));
			json_object_add_value_string(lid_obj, "description",
						     lid_dir[uuid_index]->lid[lid].str);
			json_object_add_value_uint(lid_obj, "uuid index", le32_to_cpu(uuid_index));
			json_array_add_value_object(supported_arry, lid_obj);
		}
	}

	json_object_add_value_array(root, "supported", supported_arry);

	json_print_object(root, NULL);
	json_free_object(root);
	printf("\n");
}

int solidigm_get_log_page_directory_log(int argc, char **argv, struct command *cmd,
					struct plugin *plugin)
{
	const int NO_UUID_INDEX = 0;
	const char *description = "Retrieves the list of supported log pages.";
	char *format = "normal";

	OPT_ARGS(options) = {
		OPT_FMT("output-format", 'o', &format, "output format : normal | json"),
		OPT_END()
	};

	struct nvme_dev *dev = NULL;
	int err = parse_and_open(&dev, argc, argv, description, options);

	if (err)
		return err;

	struct lid_dir *lid_dirs[NVME_ID_UUID_LIST_MAX + 1] = { 0 };
	struct nvme_id_uuid_list uuid_list = { 0 };
	struct nvme_supported_log_pages supported = { 0 };
	
	err = get_supported_log_pages_log(dev, NO_UUID_INDEX, &supported);

	if (!err) {
		lid_dirs[NO_UUID_INDEX] = get_standard_lids(&supported);

		// Assume VU logs are the Solidigm log pages if UUID not supported.
		if (nvme_identify_uuid(dev_fd(dev), &uuid_list)) {
			struct lid_dir *solidigm_lid_dir = get_solidigm_lids(&supported);

			// Transfer supported Solidigm lids to lid directory at UUID index 0
			for (int lid = 0; lid < NVME_LOG_SUPPORTED_LOG_PAGES_MAX; lid++) {
				if (solidigm_lid_dir->lid[lid].supported)
					lid_dirs[NO_UUID_INDEX]->lid[lid] = solidigm_lid_dir->lid[lid];
			}
		}
		else {
			for (int uuid_index = 1; uuid_index <= NVME_ID_UUID_LIST_MAX; uuid_index++) {
				if (is_invalid_uuid(uuid_list.entry[uuid_index - 1]))
					break;
				else if (get_supported_log_pages_log(dev, uuid_index, &supported))
					continue;
				
				if (is_solidigm_uuid(uuid_list.entry[uuid_index - 1]))
					lid_dirs[uuid_index] = get_solidigm_lids(&supported);
				else if (is_ocp_uuid(uuid_list.entry[uuid_index - 1]))
					lid_dirs[uuid_index] = get_ocp_lids(&supported);
			}
		}
	}
	else
		nvme_show_status(err);

	if (!err) {
		const enum nvme_print_flags print_flag = validate_output_format(format);

		if (print_flag == NORMAL)
			supported_log_pages_normal(lid_dirs);
		else if (print_flag == JSON) {
			supported_log_pages_json(lid_dirs);
		} else {
			fprintf(stderr, "Error: Invalid output format specified: %s.\n", format);
			return -EINVAL;
		}
	}

	dev_close(dev);
	return err;
}
