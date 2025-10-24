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
#define AMZN_NVME_STATS_DETAIL_IO_VERSION 1
#define AMZN_NVME_EBS_STATS_MAGIC 0x3C23B510
#define AMZN_NVME_LOCAL_STORAGE_STATS_MAGIC 0xEC2C0D7E
#define AMZN_NVME_STATS_NUM_HISTOGRAM 8
#define AMZN_NVME_STATS_NUM_IO_SIZES 8
#define AMZN_NVME_STATS_NUM_HISTOGRAM_BINS 32
#define AMZN_NVME_STATS_IO_SIZE_BUF_LEN 16
#define AMZN_NVME_LOCAL_STORAGE_PREFIX "Amazon EC2 NVMe Instance Storage"

#define array_add_obj json_array_add_value_object
#define obj_add_array json_object_add_value_array
#define obj_add_obj json_object_add_value_object
#define obj_add_uint json_object_add_value_uint
#define obj_add_uint64 json_object_add_value_uint64

enum amzn_nvme_operation {
	AMZN_NVME_OP_READ = 0,
	AMZN_NVME_OP_WRITE = 1,
	AMZN_NVME_OP_MAX = 2,
};

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
struct amzn_latency_histogram_counts {
	__u64 counts[AMZN_NVME_STATS_NUM_HISTOGRAM_BINS];
};
struct amzn_latency_io_histogram {
	struct amzn_latency_histogram_counts read_io_histogram_counts;
	struct amzn_latency_histogram_counts write_io_histogram_counts;
};

struct amzn_latency_log_page_base {
	__u32 magic;
	__u32 version;
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

	__u32 num_of_hists;
	__u32 hist_io_sizes[AMZN_NVME_STATS_NUM_IO_SIZES];
	__u8 reserved0[460];
} __packed;

struct amzn_latency_detail_io_histogram {
	struct amzn_latency_io_histogram io_hist_array[AMZN_NVME_STATS_NUM_HISTOGRAM];
} __packed;

struct amzn_latency_log_page {
	struct amzn_latency_log_page_base base;
	struct amzn_latency_detail_io_histogram detail_io;
} __packed;

static bool is_local_storage(struct amzn_latency_log_page *log_page)
{
	return log_page->base.magic == AMZN_NVME_LOCAL_STORAGE_STATS_MAGIC;
}

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

static int id_ctrl(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return __id_ctrl(argc, argv, acmd, plugin, amzn_id_ctrl);
}

/* this function converts the size (in uint32_t) into human readable string
 * @param size: the size to be converted
 * @param buf: the buffer to store the converted string
 * @param buf_size: the size of the buffer
 * @return: the converted string
 */

const char *format_size(uint32_t size, char *buf, size_t buf_size)
{
	if (size == UINT32_MAX)
		return "max";

	if (size == 0)
		return "0";

	if (size % (1024 * 1024) == 0)
		snprintf(buf, buf_size, "%uM", (unsigned int)(size / (1024 * 1024)));
	else if (size % 1024 == 0)
		snprintf(buf, buf_size, "%uK", (unsigned int)(size / 1024));
	else
		snprintf(buf, buf_size, "%u", size);

	return buf;
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

static void amzn_print_io_stats(struct amzn_latency_log_page *log_page)
{
	struct amzn_latency_log_page_base *base = &log_page->base;

	printf("Total Ops:\n");
	printf("  Read: %"PRIu64"\n", (uint64_t)base->total_read_ops);
	printf("  Write: %"PRIu64"\n", (uint64_t)base->total_write_ops);
	printf("Total Bytes:\n");
	printf("  Read: %"PRIu64"\n", (uint64_t)base->total_read_bytes);
	printf("  Write: %"PRIu64"\n", (uint64_t)base->total_write_bytes);
	printf("Total Time (us):\n");
	printf("  Read: %"PRIu64"\n", (uint64_t)base->total_read_time);
	printf("  Write: %"PRIu64"\n\n", (uint64_t)base->total_write_time);

	if (is_local_storage(log_page)) {
		printf("EC2 Instance Local Storage Performance Exceeded (us):\n");
		printf("  IOPS: %"PRIu64"\n",
				(uint64_t)base->ec2_instance_ebs_performance_exceeded_iops);
		printf("  Throughput: %"PRIu64"\n\n",
				(uint64_t)base->ec2_instance_ebs_performance_exceeded_tp);
	} else {
		printf("EBS Volume Performance Exceeded (us):\n");
		printf("  IOPS: %"PRIu64"\n", (uint64_t)base->ebs_volume_performance_exceeded_iops);
		printf("  Throughput: %"PRIu64"\n\n",
				(uint64_t)base->ebs_volume_performance_exceeded_tp);
		printf("EC2 Instance EBS Performance Exceeded (us):\n");
		printf("  IOPS: %"PRIu64"\n",
				(uint64_t)base->ec2_instance_ebs_performance_exceeded_iops);
		printf("  Throughput: %"PRIu64"\n\n",
				(uint64_t)base->ec2_instance_ebs_performance_exceeded_tp);

	}

	printf("Queue Length (point in time): %"PRIu64"\n\n",
	       (uint64_t)base->volume_queue_length);
}

static void amzn_print_detail_io(struct amzn_latency_log_page *log)
{
	char from_buf[AMZN_NVME_STATS_IO_SIZE_BUF_LEN] = { 0 };
	char to_buf[AMZN_NVME_STATS_IO_SIZE_BUF_LEN] = { 0 };
	int io_size_low = 0;
	int io_size_high = 0;
	uint64_t upper_bound;
	uint64_t lower_bound;
	uint64_t hist_count;
	int num_of_bin = log->base.write_io_latency_histogram.num_bins;
	int num_of_hists = log->base.num_of_hists;
	struct amzn_latency_histogram *latency_histogram = &log->base.write_io_latency_histogram;
	enum amzn_nvme_operation op;

	for (int i = 0; i < num_of_hists; i++) {
		if (i == 0) {
			io_size_low = 0;
			io_size_high = log->base.hist_io_sizes[i];
		} else {
			io_size_low = log->base.hist_io_sizes[i - 1];
			io_size_high = log->base.hist_io_sizes[i];
		}

		/* print the io size range of the histogram */
		printf("=================================\n");
		printf("IO Size Range:\n");
		printf("(io_size_low: %s -> io_size_high: %s]\n",
				format_size(io_size_low, from_buf, sizeof(from_buf)),
				format_size(io_size_high, to_buf, sizeof(to_buf)));

		/*
		 * print io histogram for this size range. The bound is the same for
		 * all the ranges
		 */
		for (op = AMZN_NVME_OP_READ; op < AMZN_NVME_OP_MAX; op++) {

			if (op == AMZN_NVME_OP_READ)
				printf("Read IO Latency Histogram\n");
			else
				printf("Write IO Latency Histogram\n");

			for (int b = 0; b < num_of_bin; b++) {
				upper_bound = latency_histogram->bins[b].upper;
				lower_bound = latency_histogram->bins[b].lower;
				hist_count = (op == AMZN_NVME_OP_READ) ?
					log->detail_io.io_hist_array[i].read_io_histogram_counts.counts[b] :
					log->detail_io.io_hist_array[i].write_io_histogram_counts.counts[b];


				printf("[%-8"PRIu64" - %-8"PRIu64"] => %-8"PRIu64"\n",
				       (uint64_t)lower_bound, (uint64_t)upper_bound,
				       hist_count);
			}

		}
	}
}

static void amzn_print_normal_stats(struct amzn_latency_log_page *log, bool detail)
{
	amzn_print_io_stats(log);

	printf("Read IO Latency Histogram\n");
	amzn_print_latency_histogram(&log->base.read_io_latency_histogram);

	printf("Write IO Latency Histogram\n");
	amzn_print_latency_histogram(&log->base.write_io_latency_histogram);

	if (log->base.version == AMZN_NVME_STATS_DETAIL_IO_VERSION && detail)
		amzn_print_detail_io(log);
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

static void amzn_json_add_io_stats(struct json_object *root,
				   struct amzn_latency_log_page *log)
{
	struct amzn_latency_log_page_base *base = &log->base;

	obj_add_uint64(root, "total_read_ops", base->total_read_ops);
	obj_add_uint64(root, "total_write_ops", base->total_write_ops);
	obj_add_uint64(root, "total_read_bytes", base->total_read_bytes);
	obj_add_uint64(root, "total_write_bytes", base->total_write_bytes);
	obj_add_uint64(root, "total_read_time", base->total_read_time);
	obj_add_uint64(root, "total_write_time", base->total_write_time);
	obj_add_uint64(root, "ebs_volume_performance_exceeded_iops",
		       base->ebs_volume_performance_exceeded_iops);
	obj_add_uint64(root, "ebs_volume_performance_exceeded_tp",
		       base->ebs_volume_performance_exceeded_tp);
	obj_add_uint64(root,
		       "ec2_instance_ebs_performance_exceeded_iops",
		       base->ec2_instance_ebs_performance_exceeded_iops);
	obj_add_uint64(root, "ec2_instance_ebs_performance_exceeded_tp",
			   base->ec2_instance_ebs_performance_exceeded_tp);
	obj_add_uint64(root, "volume_queue_length", base->volume_queue_length);

}

/* This function prints the detail io histogram of multiple IO sizes
 * For each IO size range, it prints both read and write histogram
 * The histogram is divided into bins, and each bin has a lower and upper bound
 * the bins are the same for all the histograms.
 * This is an example of the output:
 *  "histograms": [
 *      {
 *		"io_size_low": "512",
 *		"io_size_high": "4k",
 *		"read_histogram": {
 *			"bins": [
 *				....
 *			{ "lower": 8, "upper": 16, "count": 40 }
 *			]
 *		},
 *		"write_histogram": {
 *			"bins": [
 *			...
 *			{ "lower": 8, "upper": 16, "count": 45 }
 *				]
 *			}
 *	},
 *		{
 *		"io_size_low": "1024",
 *		"io_size_high": "8k",
 *		"read_histogram": {
 *			"bins": [
 *				....
 *			]
 *		},
 *		"write_histogram": {
 *			"bins": [
 *				....
 *			]
 *		}
 */
static struct json_object *amzn_json_create_detail_io(struct amzn_latency_log_page *log)
{
	int io_size_low = 0;
	int io_size_high = 0;
	char from_buf[AMZN_NVME_STATS_IO_SIZE_BUF_LEN] = { 0 };
	char to_buf[AMZN_NVME_STATS_IO_SIZE_BUF_LEN] = { 0 };
	int num_of_bins = log->base.write_io_latency_histogram.num_bins;
	int num_of_hists = log->base.num_of_hists;
	struct amzn_latency_histogram *latency_histogram = &log->base.write_io_latency_histogram;

	struct json_object *root = json_create_object();
	struct json_object *io_hist_array = json_create_array();

	obj_add_uint(root, "num_of_hists", num_of_hists);
	obj_add_obj(root, "io_histograms", io_hist_array);


	for (int i = 0; i < num_of_hists; i++) {
		struct json_object *hist_object = json_create_object();

		json_object_array_add(io_hist_array, hist_object);

		if (i == 0) {
			io_size_low = 0;
			io_size_high = log->base.hist_io_sizes[i];
		} else {
			io_size_low = log->base.hist_io_sizes[i - 1];
			io_size_high = log->base.hist_io_sizes[i];
		}

		json_object_add_value_string(hist_object, "io_size_low",
			format_size(io_size_low, from_buf, sizeof(from_buf)));
		json_object_add_value_string(hist_object, "io_size_high",
			format_size(io_size_high, to_buf, sizeof(to_buf)));

		for (int op = AMZN_NVME_OP_READ; op < AMZN_NVME_OP_MAX; op++) {
			struct json_object *bin_array = json_create_array();
			struct json_object *op_object = json_create_object();

			json_object_add_value_uint64(op_object, "num_bins", num_of_bins);
			json_object_object_add(op_object, "bins", bin_array);

			if (op == AMZN_NVME_OP_READ)
				obj_add_obj(hist_object, "read_io_latency_histogram", op_object);
			else
				obj_add_obj(hist_object, "write_io_latency_histogram", op_object);

			for (int bin = 0; bin < num_of_bins; bin++) {
				struct json_object *bin_object = json_create_object();

				json_object_add_value_uint64(bin_object, "lower",
							     latency_histogram->bins[bin].lower);
				json_object_add_value_uint64(bin_object, "upper",
							     latency_histogram->bins[bin].upper);
				if (op == AMZN_NVME_OP_READ)
					json_object_add_value_uint64(bin_object, "count",
						log->detail_io.io_hist_array[i].read_io_histogram_counts.counts[bin]);
				else
					json_object_add_value_uint64(bin_object, "count",
						log->detail_io.io_hist_array[i].write_io_histogram_counts.counts[bin]);

				json_object_array_add(bin_array, bin_object);
			}
		}
	}

	return root;
}

static void amzn_print_json_stats(struct amzn_latency_log_page *log, bool detail)
{
	struct json_object *root = json_create_object();
	struct json_object *r_hist = json_create_object();
	struct json_object *w_hist = json_create_object();
	struct json_object *detail_io;

	amzn_json_add_io_stats(root, log);

	amzn_json_add_histogram(r_hist, &log->base.read_io_latency_histogram);
	obj_add_obj(root, "read_io_latency_histogram", r_hist);
	amzn_json_add_histogram(w_hist, &log->base.write_io_latency_histogram);
	obj_add_obj(root, "write_io_latency_histogram", w_hist);

	if (log->base.version == AMZN_NVME_STATS_DETAIL_IO_VERSION && detail) {
		detail_io = amzn_json_create_detail_io(log);
		json_object_object_add(root, "latency_histograms", detail_io);
	}

	json_print_object(root, NULL);
	printf("\n");

	json_free_object(root);
}

#else /* CONFIG_JSONC */
#define amzn_print_json_stats(log, detail)
#endif /* CONFIG_JSONC */

static int get_stats(int argc, char **argv, struct command *acmd,
		     struct plugin *plugin)
{
	const char *desc = "display command latency statistics";
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	struct amzn_latency_log_page log = { 0 };
	nvme_print_flags_t flags = 0; // Initialize flags to 0
	struct nvme_id_ctrl ctrl;
	bool detail = false;
	int rc;

	struct config {
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format,
			"Output Format: normal|json"),
		OPT_FLAG("details", 'd', &detail, "Detail IO histogram of each block size ranges"),
		OPT_END()};

	rc = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (rc)
		return rc;

	if (nvme_identify_ctrl(hdl, &ctrl)) {
		fprintf(stderr, "Failed to get identify controller\n");
		rc = -errno;
		goto done;
	}

	struct nvme_get_log_args args = {
		.args_size = sizeof(args),
		.lid = AMZN_NVME_STATS_LOGPAGE_ID,
		.nsid = 1,
		.lpo = 0,
		.lsp = NVME_LOG_LSP_NONE,
		.lsi = 0,
		.rae = false,
		.uuidx = 0,
		.csi = NVME_CSI_NVM,
		.ot = false,
		.log = (void *) &log,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result = NULL,
	};

	if (!strncmp((char *)ctrl.mn, AMZN_NVME_LOCAL_STORAGE_PREFIX,
		     strlen(AMZN_NVME_LOCAL_STORAGE_PREFIX))) {
		if (nvme_get_nsid(hdl, &args.nsid) < 0) {
			struct nvme_id_ctrl test_ctrl;

			if (nvme_identify_ctrl(hdl, &test_ctrl) == 0) {
				args.nsid = NVME_NSID_ALL;
			} else {
				rc = -errno;
				goto done;
			}
		}
		args.len = sizeof(log);
	} else {
		args.len = sizeof(log.base);
	}

	rc = nvme_get_log(hdl, &args);
	if (rc != 0) {
		fprintf(stderr, "[ERROR] %s: Failed to get log page, rc = %d\n",
			__func__, rc);
		goto done;
	}

	if (log.base.magic != AMZN_NVME_EBS_STATS_MAGIC &&
		log.base.magic != AMZN_NVME_LOCAL_STORAGE_STATS_MAGIC) {
		fprintf(stderr, "[ERROR] %s: Not an EC2 device\n", __func__);
		rc = -ENOTSUP;
		goto done;
	}

	rc = validate_output_format(cfg.output_format, &flags);
	if (rc < 0) {
		nvme_show_error("Invalid output format");
		goto done;
	}

	if (flags & JSON)
		amzn_print_json_stats(&log, detail);
	else
		amzn_print_normal_stats(&log, detail);

done:
	return rc;
}
