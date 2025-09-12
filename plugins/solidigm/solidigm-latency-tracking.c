// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2022-2024 Solidigm.
 *
 * Author: leonardo.da.cunha@solidigm.com
 */

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
#include "solidigm-util.h"

#define BUCKET_LIST_SIZE_4_0 152
#define BUCKET_LIST_SIZE_4_1 1216

#define BASE_RANGE_BITS_4_0 3
#define BASE_RANGE_BITS_4_1 6

struct latency_statistics {
	__u16 version_major;
	__u16 version_minor;
	__u32 data[BUCKET_LIST_SIZE_4_1];
	__u64 average_latency;
};

struct config {
	bool enable;
	bool disable;
	bool read;
	bool write;
	unsigned char type;
	char *output_format;
};

struct latency_tracker {
	struct nvme_transport_handle *hdl;
	__u8 uuid_index;
	struct config cfg;
	nvme_print_flags_t print_flags;
	struct latency_statistics stats;
	struct json_object *bucket_list;
	__u32 bucket_list_size;
	__u8 base_range_bits;
	bool has_average_latency_field;
};

/* COL_WIDTH controls width of columns in NORMAL output. */
#define COL_WIDTH 12
#define BUCKET_LABEL_MAX_SIZE 10

#define US_IN_S 1000000
#define US_IN_MS 1000

/*
 * Edge buckets may have range [#s, inf) in some
 * latency statistics formats.
 */
static void get_time_unit_label(char *label, __u32 microseconds,
			    bool bonded)
{
	char *string = "us";
	int divisor = 1;

	if (!bonded) {
		snprintf(label, BUCKET_LABEL_MAX_SIZE, "%s", "+INF");
		return;
	}

	if (microseconds > US_IN_S) {
		string = "s";
		divisor = US_IN_S;
	} else if (microseconds > US_IN_MS) {
		string = "ms";
		divisor = US_IN_MS;
	}

	snprintf(label, BUCKET_LABEL_MAX_SIZE, "%4.2f%s",  (float) microseconds / divisor,
		 string);
}

static void latency_tracker_bucket_parse(const struct latency_tracker *lt, int id,
					 __u32 lower_us, __u32 upper_us, bool upper_bounded)
{
	char buffer[BUCKET_LABEL_MAX_SIZE] = "";
	__u32 bucket_data = le32_to_cpu(lt->stats.data[id]);

	if (lt->print_flags == NORMAL) {
		printf("%-*d", COL_WIDTH, id);

		get_time_unit_label(buffer, lower_us, true);
		printf("%-*s", COL_WIDTH, buffer);

		get_time_unit_label(buffer, upper_us, upper_bounded);
		printf("%-*s", COL_WIDTH, buffer);

		printf("%-*d\n", COL_WIDTH, bucket_data);
	}

	if (lt->print_flags == JSON) {
		/*
		 * Creates a bucket under the "values" json_object. Format is:
		 * "values" : {
		 *   "bucket" : {
		 *     "id" : #,
		 *     "start" : string,
		 *     "end" : string,
		 *     "value" : 0,
		 *   },
		 */
		struct json_object *bucket = json_create_object();

		json_object_array_add(lt->bucket_list, bucket);
		json_object_add_value_int(bucket, "id", id);

		get_time_unit_label(buffer, lower_us, true);
		json_object_add_value_string(bucket, "start", buffer);

		get_time_unit_label(buffer, upper_us, upper_bounded);
		json_object_add_value_string(bucket, "end", buffer);

		json_object_add_value_int(bucket, "value", bucket_data);
	}
}

static void latency_tracker_parse_linear(const struct latency_tracker *lt,
					 __u32 start_offset, __u32 end_offset,
					 __u32 bytes_per, __u32 us_step,
					 bool nonzero_print)
{
	for (int i = (start_offset / bytes_per) - 1; i < end_offset / bytes_per; i++) {
		if (nonzero_print && !lt->stats.data[i])
			continue;
		latency_tracker_bucket_parse(lt, i, us_step * i, us_step * (i + 1), true);
	}
}

/*
 * Calculates bucket time slot. Valid  starting on 4.0 revision.
 */

static int latency_tracker_bucket_pos2us(const struct latency_tracker *lt, int i)
{
	__u32 base_val = 1 <<  lt->base_range_bits;

	if (i < (base_val << 1))
		return i;

	int error_bits = (i >> lt->base_range_bits) - 1;
	int base = 1 << (error_bits + lt->base_range_bits);
	int k = i % base_val;

	return base + ((k + 0.5) * (1 << error_bits));
}

/*
 * Creates a subroot in the following manner:
 * {
 *   "latstats" : {
 *     "type" : "write" or "read",
 *     "values" : {
 */
static void latency_tracker_populate_json_root(const struct latency_tracker *lt,
					       struct json_object *root)
{
	struct json_object *subroot = json_create_object();

	json_object_add_value_object(root, "latstats", subroot);
	json_object_add_value_string(subroot, "type", lt->cfg.write ? "write" : "read");
	if (lt->has_average_latency_field)
		json_object_add_value_uint64(subroot, "average_latency",
					     le64_to_cpu(lt->stats.average_latency));
	json_object_add_value_object(subroot, "values", lt->bucket_list);
}

static void latency_tracker_parse_3_0(const struct latency_tracker *lt)
{
	latency_tracker_parse_linear(lt, 4, 131, 4, 32, false);
	latency_tracker_parse_linear(lt, 132, 255, 4, 1024, false);
	latency_tracker_parse_linear(lt, 256, 379, 4, 32768, false);
	latency_tracker_parse_linear(lt, 380, 383, 4, 32, true);
	latency_tracker_parse_linear(lt, 384, 387, 4, 32, true);
	latency_tracker_parse_linear(lt, 388, 391, 4, 32, true);
}

static void latency_tracker_parse_4_0(const struct latency_tracker *lt)
{
	for (unsigned int i = 0; i < lt->bucket_list_size; i++) {
		int lower_us = latency_tracker_bucket_pos2us(lt, i);
		int upper_us = latency_tracker_bucket_pos2us(lt, i + 1);

		latency_tracker_bucket_parse(lt, i, lower_us, upper_us,
					     i < (lt->bucket_list_size - 1));
	}
}

static void print_dash_separator(void)
{
	printf("--------------------------------------------------\n");
}

static void latency_tracker_pre_parse(struct latency_tracker *lt)
{
	if (lt->print_flags == NORMAL) {
		printf("Solidigm IO %s Command Latency Tracking Statistics type %d\n",
			lt->cfg.write ? "Write" : "Read", lt->cfg.type);
		printf("UUID-idx: %d\n", lt->uuid_index);
		printf("Major Revision: %u\nMinor Revision: %u\n",
			le16_to_cpu(lt->stats.version_major), le16_to_cpu(lt->stats.version_minor));
		if (lt->has_average_latency_field)
			printf("Average Latency: %" PRIu64 "\n", le64_to_cpu(lt->stats.average_latency));
		print_dash_separator();
		printf("%-12s%-12s%-12s%-20s\n", "Bucket", "Start", "End", "Value");
		print_dash_separator();
	}
	if (lt->print_flags == JSON)
		lt->bucket_list = json_object_new_array();
}

static void latency_tracker_post_parse(struct latency_tracker *lt)
{
	if (lt->print_flags == JSON) {
		struct json_object *root = json_create_object();

		latency_tracker_populate_json_root(lt, root);
		json_print_object(root, NULL);
		json_free_object(root);
		printf("\n");
	}
}

static void latency_tracker_parse(struct latency_tracker *lt)
{
	__u16 version_major = le16_to_cpu(lt->stats.version_major);
	__u16 version_minor = le16_to_cpu(lt->stats.version_minor);

	switch (version_major) {
	case 3:
		latency_tracker_pre_parse(lt);
		latency_tracker_parse_3_0(lt);
		break;
	case 4:
		if (version_minor >= 8)
			lt->has_average_latency_field = true;
		latency_tracker_pre_parse(lt);
		if (!version_minor) {
			lt->base_range_bits = BASE_RANGE_BITS_4_0;
			lt->bucket_list_size = BUCKET_LIST_SIZE_4_0;
		}
		latency_tracker_parse_4_0(lt);
		break;
	default:
		printf("Unsupported revision (%u.%u)\n",
		       version_major, version_minor);
		break;
	}

	latency_tracker_post_parse(lt);
}

#define LATENCY_TRACKING_FID 0xe2
#define LATENCY_TRACKING_FID_DATA_LEN 32

static int latency_tracking_is_enable(struct latency_tracker *lt, __u32 *enabled)
{
	struct nvme_get_features_args args_get = {
		.args_size	= sizeof(args_get),
		.uuidx		= lt->uuid_index,
		.fid		= LATENCY_TRACKING_FID,
		.nsid		= 0,
		.sel		= 0,
		.cdw11		= 0,
		.data_len	= LATENCY_TRACKING_FID_DATA_LEN,
		.data		= NULL,
		.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
		.result		= enabled,
	};
	return nvme_get_features(lt->hdl, &args_get);
}

static int latency_tracking_enable(struct latency_tracker *lt)
{
	__u32 result;
	int err;

	if (!(lt->cfg.enable || lt->cfg.disable))
		return 0;

	if (lt->cfg.enable && lt->cfg.disable) {
		fprintf(stderr, "Cannot enable and disable simultaneously.\n");
		return -EINVAL;
	}

	err = nvme_set_features(lt->hdl, 0, LATENCY_TRACKING_FID, 0,
			lt->cfg.enable, 0, 0, lt->uuid_index, 0, NULL,
			LATENCY_TRACKING_FID_DATA_LEN, &result);
	if (err > 0) {
		nvme_show_status(err);
	} else if (err < 0) {
		perror("Enable latency tracking");
		fprintf(stderr, "Command failed while parsing.\n");
	} else {
		if (lt->print_flags == NORMAL) {
			printf("Successfully set enable bit for UUID-idx:%d FID:0x%X, to %i.\n",
				lt->uuid_index, LATENCY_TRACKING_FID, lt->cfg.enable);
		}
	}
	return err;
}

#define READ_LOG_ID 0xc1
#define WRITE_LOG_ID 0xc2

static int latency_tracker_get_log(struct latency_tracker *lt)
{
	struct nvme_passthru_cmd cmd;
	int err;

	if (lt->cfg.read && lt->cfg.write) {
		fprintf(stderr, "Cannot capture read and write logs simultaneously.\n");
		return -EINVAL;
	}

	if (!(lt->cfg.read || lt->cfg.write))
		return 0;

	nvme_init_get_log(&cmd, NVME_NSID_ALL,
			  lt->cfg.write ? WRITE_LOG_ID : READ_LOG_ID,
			  NVME_CSI_NVM, &lt->stats, sizeof(lt->stats));
	cmd.cdw10 |= NVME_FIELD_ENCODE(lt->cfg.type,
				       NVME_LOG_CDW10_LSP_SHIFT,
				       NVME_LOG_CDW10_LSP_MASK);
	cmd.cdw14 |= NVME_FIELD_ENCODE(lt->uuid_index,
				       NVME_LOG_CDW14_UUID_SHIFT,
				       NVME_LOG_CDW14_UUID_MASK);
	err = nvme_get_log(lt->hdl, &cmd, false,
			   NVME_LOG_PAGE_PDU_SIZE, NULL);
	if (err)
		return err;

	if (lt->print_flags & BINARY)
		d_raw((unsigned char *)&lt->stats,
			      sizeof(lt->stats));
	else {
		latency_tracker_parse(lt);
	}
	return err;
}

int solidigm_get_latency_tracking_log(int argc, char **argv, struct command *acmd,
				      struct plugin *plugin)
{
	const char *desc = "Get and Parse Solidigm Latency Tracking Statistics log.";
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	__u32 enabled;
	int err;

	struct latency_tracker lt = {
		.uuid_index = 0,
		.cfg = {
			.output_format	= "normal",
		},
		.base_range_bits = BASE_RANGE_BITS_4_1,
		.bucket_list_size = BUCKET_LIST_SIZE_4_1,
		.has_average_latency_field = false,
	};

	OPT_ARGS(opts) = {
		OPT_FLAG("enable", 'e', &lt.cfg.enable, "Enable Latency Tracking"),
		OPT_FLAG("disable", 'd', &lt.cfg.disable, "Disable Latency Tracking"),
		OPT_FLAG("read", 'r', &lt.cfg.read, "Get read statistics"),
		OPT_FLAG("write", 'w', &lt.cfg.write, "Get write statistics"),
		OPT_BYTE("type", 't', &lt.cfg.type, "Log type to get"),
		OPT_FMT("output-format", 'o', &lt.cfg.output_format, output_format),
		OPT_END()
	};

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	lt.hdl = hdl;

	err = validate_output_format(lt.cfg.output_format, &lt.print_flags);
	if (err < 0) {
		fprintf(stderr, "Invalid output format '%s'\n", lt.cfg.output_format);
		return -EINVAL;
	}

	if (lt.cfg.type > 0xf) {
		fprintf(stderr, "Invalid Log type value '%d'\n", lt.cfg.type);
		return -EINVAL;
	}

	if (lt.cfg.type && !(lt.cfg.read || lt.cfg.write)) {
		fprintf(stderr, "Log type option valid only when retrieving statistics\n");
		return -EINVAL;
	}

	sldgm_get_uuid_index(hdl, &lt.uuid_index);

	err = latency_tracking_enable(&lt);
	if (err)
		return err;

	err = latency_tracker_get_log(&lt);
	if (err)
		return err;

	if ((lt.cfg.read || lt.cfg.write || lt.cfg.enable || lt.cfg.disable))
		return 0;

	err = latency_tracking_is_enable(&lt, &enabled);
	if (!err) {
		if (lt.print_flags == JSON) {
			struct json_object *root = json_create_object();

			json_object_add_value_int(root, "enabled", enabled);
			json_print_object(root, NULL);
			json_free_object(root);
			printf("\n");
		} else if (lt.print_flags == BINARY) {
			putchar(enabled);
		} else {
			printf("Latency Statistics Tracking (UUID-idx:%d, FID:0x%X) is currently %i.\n",
			       lt.uuid_index, LATENCY_TRACKING_FID, enabled);
		}
	} else {
		fprintf(stderr, "Could not read feature id 0xE2.\n");
	}
	return err;
}
