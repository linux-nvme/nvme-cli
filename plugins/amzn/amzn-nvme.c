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
#include "nvme-print.h"

#define CREATE_CMD
#include "amzn-nvme.h"

#define AMZN_NVME_STATS_LOGPAGE_ID 0xD0
#define AMZN_NVME_STATS_MAGIC 0x3C23B510

#define array_add_obj json_array_add_value_object
#define obj_add_array json_object_add_value_array
#define obj_add_obj json_object_add_value_object
#define obj_add_uint json_object_add_value_uint
#define obj_add_uint64 json_object_add_value_uint64

struct nvme_vu_id_ctrl_field {
	__u8			bdev[32];
	__u8			reserved0[992];
};

struct amzn_latency_histogram_bin {
	__u64 lower;
	__u64 upper;
	__u32 count;
	__u32 reserved;
} __packed;

struct amzn_latency_histogram {
	__u64 num_bins;
	struct amzn_latency_histogram_bin bins[64];
} __packed;

struct amzn_latency_log_page {
	__u32 magic;
	__u32 reserved0;
	__u64 total_read_ops;
	__u64 total_write_ops;
	__u64 total_read_bytes;
	__u64 total_write_bytes;
	__u64 total_read_time;
	__u64 total_write_time;
	__u64 ebs_volume_performance_exceeded_iops;
	__u64 ebs_volume_performance_exceeded_tp;
	__u64 ec2_instance_ebs_performance_exceeded_iops;
	__u64 ec2_instance_ebs_performance_exceeded_tp;
	__u64 volume_queue_length;
	__u8 reserved1[416];

	struct amzn_latency_histogram read_io_latency_histogram;
	struct amzn_latency_histogram write_io_latency_histogram;

	__u8 reserved2[496];
} __packed;

static void json_amzn_id_ctrl(struct nvme_vu_id_ctrl_field *id,
	char *bdev,
	struct json_object *root)
{
	json_object_add_value_string(root, "bdev", bdev);
}

static void amzn_id_ctrl(__u8 *vs, struct json_object *root)
{
	struct nvme_vu_id_ctrl_field *id = (struct nvme_vu_id_ctrl_field *)vs;

	char bdev[32] = { 0 };

	int len = 0;

	while (len < 31) {
		if (id->bdev[++len] == ' ')
			break;
	}
	snprintf(bdev, len+1, "%s", id->bdev);

	if (root) {
		json_amzn_id_ctrl(id, bdev, root);
		return;
	}

	printf("bdev      : %s\n", bdev);
}

static int id_ctrl(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	return __id_ctrl(argc, argv, cmd, plugin, amzn_id_ctrl);
}

static void amzn_print_latency_histogram(struct amzn_latency_histogram *hist)
{
	printf("=================================\n");
	printf("Lower       Upper        IO Count\n");
	printf("=================================\n");

	for (int b = 0; b < hist->num_bins && b < 64; b++) {
		struct amzn_latency_histogram_bin *bin = &hist->bins[b];

		printf("[%-8"PRIu64" - %-8"PRIu64"] => %-8u\n",
		       (uint64_t)bin->lower, (uint64_t)bin->upper, bin->count);
	}

	printf("=================================\n\n");
}

#ifdef CONFIG_JSONC
static void amzn_json_add_histogram(struct json_object *root,
				    struct amzn_latency_histogram *hist)
{
	struct json_object *bins = json_create_array();

	obj_add_uint64(root, "num_bins", hist->num_bins);
	obj_add_array(root, "bins", bins);

	for (int b = 0; b < hist->num_bins && b < 64; b++) {
		struct amzn_latency_histogram_bin *bin = &hist->bins[b];
		struct json_object *json_bin = json_create_object();

		obj_add_uint64(json_bin, "lower", bin->lower);
		obj_add_uint64(json_bin, "upper", bin->upper);
		obj_add_uint(json_bin, "count", bin->count);

		array_add_obj(bins, json_bin);
	}
}

static void amzn_print_json_stats(struct amzn_latency_log_page *log)
{
	struct json_object *root = json_create_object();
	struct json_object *r_hist = json_create_object();
	struct json_object *w_hist = json_create_object();

	obj_add_uint64(root, "total_read_ops", log->total_read_ops);
	obj_add_uint64(root, "total_write_ops", log->total_write_ops);
	obj_add_uint64(root, "total_read_bytes", log->total_read_bytes);
	obj_add_uint64(root, "total_write_bytes", log->total_write_bytes);
	obj_add_uint64(root, "total_read_time", log->total_read_time);
	obj_add_uint64(root, "total_write_time", log->total_write_time);
	obj_add_uint64(root, "ebs_volume_performance_exceeded_iops",
		       log->ebs_volume_performance_exceeded_iops);
	obj_add_uint64(root, "ebs_volume_performance_exceeded_tp",
		       log->ebs_volume_performance_exceeded_tp);
	obj_add_uint64(root,
		       "ec2_instance_ebs_performance_exceeded_iops",
		       log->ec2_instance_ebs_performance_exceeded_iops);
	obj_add_uint64(root, "ec2_instance_ebs_performance_exceeded_tp",
		       log->ec2_instance_ebs_performance_exceeded_tp);
	obj_add_uint64(root, "volume_queue_length", log->volume_queue_length);

	amzn_json_add_histogram(r_hist, &log->read_io_latency_histogram);
	obj_add_obj(root, "read_io_latency_histogram", r_hist);
	amzn_json_add_histogram(w_hist, &log->write_io_latency_histogram);
	obj_add_obj(root, "write_io_latency_histogram", w_hist);

	json_print_object(root, NULL);
	printf("\n");

	json_free_object(root);
}
#else /* CONFIG_JSONC */
#define amzn_print_json_stats(log)
#endif /* CONFIG_JSONC */

static void amzn_print_normal_stats(struct amzn_latency_log_page *log)
{
	printf("Total Ops:\n");
	printf("  Read: %"PRIu64"\n", (uint64_t)log->total_read_ops);
	printf("  Write: %"PRIu64"\n", (uint64_t)log->total_write_ops);
	printf("Total Bytes:\n");
	printf("  Read: %"PRIu64"\n", (uint64_t)log->total_read_bytes);
	printf("  Write: %"PRIu64"\n", (uint64_t)log->total_write_bytes);
	printf("Total Time (us):\n");
	printf("  Read: %"PRIu64"\n", (uint64_t)log->total_read_time);
	printf("  Write: %"PRIu64"\n\n", (uint64_t)log->total_write_time);

	printf("EBS Volume Performance Exceeded (us):\n");
	printf("  IOPS: %"PRIu64"\n", (uint64_t)log->ebs_volume_performance_exceeded_iops);
	printf("  Throughput: %"PRIu64"\n\n",
	       (uint64_t)log->ebs_volume_performance_exceeded_tp);
	printf("EC2 Instance EBS Performance Exceeded (us):\n");
	printf("  IOPS: %"PRIu64"\n",
	       (uint64_t)log->ec2_instance_ebs_performance_exceeded_iops);
	printf("  Throughput: %"PRIu64"\n\n",
	       (uint64_t)log->ec2_instance_ebs_performance_exceeded_tp);

	printf("Queue Length (point in time): %"PRIu64"\n\n",
	       (uint64_t)log->volume_queue_length);

	printf("Read IO Latency Histogram\n");
	amzn_print_latency_histogram(&log->read_io_latency_histogram);

	printf("Write IO Latency Histogram\n");
	amzn_print_latency_histogram(&log->write_io_latency_histogram);
}

static int get_stats(int argc, char **argv, struct command *cmd,
		     struct plugin *plugin)
{
	const char *desc = "display command latency statistics";
	struct nvme_dev *dev;
	struct amzn_latency_log_page log = { 0 };
	int rc;
	nvme_print_flags_t flags;
	int err;

	struct config {
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format,
			"Output Format: normal|json"),
		OPT_END()};

	rc = parse_and_open(&dev, argc, argv, desc, opts);
	if (rc)
		return rc;

	struct nvme_get_log_args args = {
		.args_size = sizeof(args),
		.fd = dev_fd(dev),
		.lid = AMZN_NVME_STATS_LOGPAGE_ID,
		.nsid = 1,
		.lpo = 0,
		.lsp = NVME_LOG_LSP_NONE,
		.lsi = 0,
		.rae = false,
		.uuidx = 0,
		.csi = NVME_CSI_NVM,
		.ot = false,
		.len = sizeof(log),
		.log = &log,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result = NULL,
	};

	rc = nvme_get_log(&args);
	if (rc != 0) {
		fprintf(stderr, "[ERROR] %s: Failed to get log page, rc = %d",
			__func__, rc);
		return rc;
	}

	if (log.magic != AMZN_NVME_STATS_MAGIC) {
		fprintf(stderr, "[ERROR] %s: Not an EBS device", __func__);
		return -ENOTSUP;
	}

	err = validate_output_format(cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (flags & JSON)
		amzn_print_json_stats(&log);
	else
		amzn_print_normal_stats(&log);

	return 0;
}
