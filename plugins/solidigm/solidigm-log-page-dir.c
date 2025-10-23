// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023-2024 Solidigm.
 *
 * Author: karl.dedow@solidigm.com
 */

#include "solidigm-log-page-dir.h"

#include <errno.h>
#include <stdio.h>
#include <unistd.h>

#include "common.h"
#include "nvme-print.h"

#include "plugins/ocp/ocp-nvme.h"
#include "plugins/ocp/ocp-utils.h"
#include "solidigm-util.h"

#define MIN_VENDOR_LID 0xC0
#define SOLIDIGM_MAX_UUID 2

static const char dash[100] = {[0 ... 99] = '-'};

struct lid_dir {
	struct __packed {
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

static int get_supported_log_pages_log(struct nvme_transport_handle *hdl, int uuid_index,
				       struct nvme_supported_log_pages *supported)
{
	memset(supported, 0, sizeof(*supported));
	struct nvme_get_log_args args = {
		.lpo = 0,
		.result = NULL,
		.log = supported,
		.args_size = sizeof(args),
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.lid = NVME_LOG_LID_SUPPORTED_LOG_PAGES,
		.len = sizeof(*supported),
		.nsid = NVME_NSID_ALL,
		.csi = NVME_CSI_NVM,
		.lsi = NVME_LOG_LSI_NONE,
		.lsp = 0,
		.uuidx = uuid_index,
		.rae = false,
		.ot = false,
	};

	return nvme_get_log(hdl, &args);
}

static struct lid_dir *get_standard_lids(struct nvme_supported_log_pages *supported)
{
	static struct lid_dir standard_dir = { 0 };

	init_lid_dir(&standard_dir);

	for (int lid = 0; lid < MIN_VENDOR_LID; lid++) {
		if (!supported->lid_support[lid])
			continue;

		standard_dir.lid[lid].supported = true;
		standard_dir.lid[lid].str = nvme_log_to_string(lid);
	}

	return &standard_dir;
}

static void update_vendor_lid_supported(struct nvme_supported_log_pages *supported,
					struct lid_dir *lid_dir)
{
	for (int lid = 0; lid < NVME_LOG_SUPPORTED_LOG_PAGES_MAX; lid++) {
		if (!supported->lid_support[lid] || lid < MIN_VENDOR_LID)
			continue;

		lid_dir->lid[lid].supported = true;
	}
}

static struct lid_dir *get_solidigm_lids(struct nvme_supported_log_pages *supported)
{
	static struct lid_dir solidigm_dir = { 0 };

	init_lid_dir(&solidigm_dir);
	solidigm_dir.lid[0xC0].str = "OCP SMART / Health Information Extended";
	solidigm_dir.lid[0xC1].str = "Read Commands Latency Statistics";
	solidigm_dir.lid[0xC2].str = "Write Commands Latency Statistics";
	solidigm_dir.lid[0xC3].str = "OCP Latency Monitor";
	solidigm_dir.lid[0xC4].str = "Endurance Manager Statistics";
	solidigm_dir.lid[0xC5].str = "Temperature Statistics";
	solidigm_dir.lid[0xCA].str = "SMART Attributes";
	solidigm_dir.lid[0xCB].str = "VU NVMe IO Queue Metrics Log Page";
	solidigm_dir.lid[0xD5].str = solidigm_dir.lid[0xC5].str;
	solidigm_dir.lid[0xDD].str = "VU Marketing Description Log Page";
	solidigm_dir.lid[0xEF].str = "Performance Rating and LBA Access Histogram";
	solidigm_dir.lid[0xF2].str = "Get Power Usage Log Page";
	solidigm_dir.lid[0xF4].str = "Nand Statistics Log Page";
	solidigm_dir.lid[0xF5].str = "Nand Defects Count Log Page";
	solidigm_dir.lid[0xF6].str = "Vt Histo Get Log Page";
	solidigm_dir.lid[0xF9].str = "Workload Tracker Get Log Page";
	solidigm_dir.lid[0xFD].str = "Garbage Control Collection  Log Page";
	solidigm_dir.lid[0xFE].str = "Latency Outlier / SK SMART Log Page";

	update_vendor_lid_supported(supported, &solidigm_dir);

	return &solidigm_dir;
}

static struct lid_dir *get_ocp_lids(struct nvme_supported_log_pages *supported)
{
	static struct lid_dir ocp_dir = { 0 };

	init_lid_dir(&ocp_dir);
	ocp_dir.lid[0xC0].str = "OCP SMART / Health Information Extended";
	ocp_dir.lid[0xC1].str = "OCP Error Recovery";
	ocp_dir.lid[0xC2].str = "OCP Firmware Activation History";
	ocp_dir.lid[0xC3].str = "OCP Latency Monitor";
	ocp_dir.lid[0xC4].str = "OCP Device Capabilities";
	ocp_dir.lid[0xC5].str = "OCP Unsupported Requirements";
	ocp_dir.lid[0xC6].str = "OCP Hardware Component";
	ocp_dir.lid[0xC7].str = "OCP TCG Configuration";
	ocp_dir.lid[0xC9].str = "OCP Telemetry String Log";

	update_vendor_lid_supported(supported, &ocp_dir);

	return &ocp_dir;
}

static void supported_log_pages_normal(struct lid_dir *lid_dir[SOLIDIGM_MAX_UUID + 1])
{
	printf("%-5s %-4s %-42s\n", "uuidx", "LID", "Description");
	printf("%-.5s %-.4s %-.42s\n", dash, dash, dash);

	for (int uuid_index = 0; uuid_index <= SOLIDIGM_MAX_UUID; uuid_index++) {
		if (!lid_dir[uuid_index])
			continue;

		for (int lid = 0; lid < NVME_LOG_SUPPORTED_LOG_PAGES_MAX; lid++) {
			if (!lid_dir[uuid_index]->lid[lid].supported)
				continue;

			printf("%-5d 0x%02x %s\n", le32_to_cpu(uuid_index), le32_to_cpu(lid),
				   lid_dir[uuid_index]->lid[lid].str);
		}
	}
}

static void supported_log_pages_json(struct lid_dir *lid_dir[SOLIDIGM_MAX_UUID + 1])
{
	struct json_object *root = json_create_array();

	for (int uuid_index = 0; uuid_index <= SOLIDIGM_MAX_UUID; uuid_index++) {
		if (!lid_dir[uuid_index])
			continue;

		for (int lid = 0; lid < NVME_LOG_SUPPORTED_LOG_PAGES_MAX; lid++) {
			if (!lid_dir[uuid_index]->lid[lid].supported)
				continue;

			struct json_object *lid_obj = json_create_object();

			json_object_add_value_uint(lid_obj, "uuidx", le32_to_cpu(uuid_index));
			json_object_add_value_uint(lid_obj, "lid", le32_to_cpu(lid));
			json_object_add_value_string(lid_obj, "description",
						     lid_dir[uuid_index]->lid[lid].str);
			json_array_add_value_object(root, lid_obj);
		}
	}

	json_print_object(root, NULL);
	json_free_object(root);
	printf("\n");
}

int solidigm_get_log_page_directory_log(int argc, char **argv, struct command *acmd,
					struct plugin *plugin)
{
	const int NO_UUID_INDEX = 0;
	const char *description = "Retrieves list of supported log pages for each UUID index.";

	OPT_ARGS(options) = {
		OPT_FMT("output-format", 'o', &nvme_cfg.output_format,
			"output format : normal | json"),
		OPT_INCR("verbose", 'v', &nvme_cfg.verbose, verbose),
		OPT_END()
	};

	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;

	int err = parse_and_open(&ctx, &hdl, argc, argv, description, options);
	if (err)
		return err;

	struct lid_dir *lid_dirs[SOLIDIGM_MAX_UUID + 1] = { 0 };
	struct nvme_id_uuid_list uuid_list = { 0 };
	struct nvme_supported_log_pages supported = { 0 };

	err = get_supported_log_pages_log(hdl, NO_UUID_INDEX, &supported);

	if (!err) {
		lid_dirs[NO_UUID_INDEX] = get_standard_lids(&supported);

		// Assume VU logs are the Solidigm log pages if UUID not supported.
		if (!nvme_identify_uuid_list(hdl, &uuid_list)) {
			struct lid_dir *solidigm_lid_dir = get_solidigm_lids(&supported);

			// Transfer supported Solidigm lids to lid directory at UUID index 0
			for (int lid = 0; lid < NVME_LOG_SUPPORTED_LOG_PAGES_MAX; lid++) {
				if (solidigm_lid_dir->lid[lid].supported)
					lid_dirs[NO_UUID_INDEX]->lid[lid] = solidigm_lid_dir->lid[lid];
			}
		} else {
			__u8 sldgm_idx;
			__u8 ocp_idx;

			sldgm_find_uuid_index(&uuid_list, &sldgm_idx);
			ocp_find_uuid_index(&uuid_list, &ocp_idx);

			if (sldgm_idx && (sldgm_idx <= SOLIDIGM_MAX_UUID)) {
				err = get_supported_log_pages_log(hdl, sldgm_idx, &supported);
				if (!err)
					lid_dirs[sldgm_idx] = get_solidigm_lids(&supported);
			}
			if (ocp_idx && (ocp_idx <= SOLIDIGM_MAX_UUID)) {
				err = get_supported_log_pages_log(hdl, ocp_idx, &supported);
				if (!err)
					lid_dirs[ocp_idx] = get_ocp_lids(&supported);
			}
		}
	} else {
		nvme_show_status(err);
	}

	if (!err) {
		nvme_print_flags_t print_flag;

		err = validate_output_format(nvme_cfg.output_format, &print_flag);
		if (err) {
			nvme_show_error("Error: Invalid output format specified: %s.\n",
					nvme_cfg.output_format);
			return err;
		}

		if (print_flag == NORMAL) {
			supported_log_pages_normal(lid_dirs);
		} else if (print_flag == JSON) {
			supported_log_pages_json(lid_dirs);
		}
	}

	return err;
}
