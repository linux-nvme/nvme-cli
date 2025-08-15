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
#include "linux/types.h"
#include "nvme-print.h"

#define CREATE_CMD
#include "shannon-nvme.h"

enum {
	PROGRAM_FAIL_CNT,
	ERASE_FAIL_CNT,
	WEARLEVELING_COUNT,
	E2E_ERR_CNT,
	CRC_ERR_CNT,
	TIME_WORKLOAD_MEDIA_WEAR,
	TIME_WORKLOAD_HOST_READS,
	TIME_WORKLOAD_TIMER,
	THERMAL_THROTTLE,
	RETRY_BUFFER_OVERFLOW,
	PLL_LOCK_LOSS,
	NAND_WRITE,
	HOST_WRITE,
	SRAM_ERROR_CNT,
	ADD_SMART_ITEMS,
};

#pragma pack(push, 1)
struct nvme_shannon_smart_log_item {
	__u8			rsv1[3];
	__u8			norm;
	__u8			rsv2;
	union {
		__u8		item_val[6];
		struct wear_level {
			__le16	min;
			__le16	max;
			__le16	avg;
		} wear_level;
		struct thermal_throttle {
			__u8	st;
			__u32	count;
		} thermal_throttle;
	};
	__u8			_resv;
};
#pragma pack(pop)

struct nvme_shannon_smart_log {
	struct nvme_shannon_smart_log_item items[ADD_SMART_ITEMS];
	__u8  vend_spec_resv;
};

static void show_shannon_smart_log(struct nvme_shannon_smart_log *smart,
				   unsigned int nsid, const char *devname)
{
	printf("Additional Smart Log for NVME device:%s namespace-id:%x\n",
	       devname, nsid);
	printf("key                               normalized value\n");
	printf("program_fail_count              : %3d%%       %"PRIu64"\n",
	       smart->items[PROGRAM_FAIL_CNT].norm,
	       int48_to_long(smart->items[PROGRAM_FAIL_CNT].item_val));
	printf("erase_fail_count                : %3d%%       %"PRIu64"\n",
	       smart->items[ERASE_FAIL_CNT].norm,
	       int48_to_long(smart->items[ERASE_FAIL_CNT].item_val));
	printf("wear_leveling                   : %3d%%       min: %u, max: %u, avg: %u\n",
	       smart->items[WEARLEVELING_COUNT].norm,
	       le16_to_cpu(smart->items[WEARLEVELING_COUNT].wear_level.min),
	       le16_to_cpu(smart->items[WEARLEVELING_COUNT].wear_level.max),
	       le16_to_cpu(smart->items[WEARLEVELING_COUNT].wear_level.avg));
	printf("end_to_end_error_detection_count: %3d%%       %"PRIu64"\n",
	       smart->items[E2E_ERR_CNT].norm,
	       int48_to_long(smart->items[E2E_ERR_CNT].item_val));
	printf("crc_error_count                 : %3d%%       %"PRIu64"\n",
	       smart->items[CRC_ERR_CNT].norm,
	       int48_to_long(smart->items[CRC_ERR_CNT].item_val));
	printf("timed_workload_media_wear       : %3d%%       %.3f%%\n",
	       smart->items[TIME_WORKLOAD_MEDIA_WEAR].norm,
	       ((float)int48_to_long(smart->items[TIME_WORKLOAD_MEDIA_WEAR].item_val)) / 1024);
	printf("timed_workload_host_reads       : %3d%%       %"PRIu64"%%\n",
	       smart->items[TIME_WORKLOAD_HOST_READS].norm,
	       int48_to_long(smart->items[TIME_WORKLOAD_HOST_READS].item_val));
	printf("timed_workload_timer            : %3d%%       %"PRIu64" min\n",
	       smart->items[TIME_WORKLOAD_TIMER].norm,
	       int48_to_long(smart->items[TIME_WORKLOAD_TIMER].item_val));
	printf("thermal_throttle_status         : %3d%%       CurTTSta: %u%%, TTCnt: %u\n",
	       smart->items[THERMAL_THROTTLE].norm,
	       smart->items[THERMAL_THROTTLE].thermal_throttle.st,
	       smart->items[THERMAL_THROTTLE].thermal_throttle.count);
	printf("retry_buffer_overflow_count     : %3d%%       %"PRIu64"\n",
	       smart->items[RETRY_BUFFER_OVERFLOW].norm,
	       int48_to_long(smart->items[RETRY_BUFFER_OVERFLOW].item_val));
	printf("pll_lock_loss_count             : %3d%%       %"PRIu64"\n",
	       smart->items[PLL_LOCK_LOSS].norm,
	       int48_to_long(smart->items[PLL_LOCK_LOSS].item_val));
	printf("nand_bytes_written              : %3d%%       sectors: %"PRIu64"\n",
	       smart->items[NAND_WRITE].norm,
	       int48_to_long(smart->items[NAND_WRITE].item_val));
	printf("host_bytes_written              : %3d%%       sectors: %"PRIu64"\n",
	       smart->items[HOST_WRITE].norm,
	       int48_to_long(smart->items[HOST_WRITE].item_val));
	printf("sram_error_count        : %3d%%       %"PRIu64"\n",
	       smart->items[RETRY_BUFFER_OVERFLOW].norm,
	       int48_to_long(smart->items[SRAM_ERROR_CNT].item_val));
}

static int get_additional_smart_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	struct nvme_shannon_smart_log smart_log;
	char *desc =
	    "Get Shannon vendor specific additional smart log (optionally, for the specified namespace), and show it.";
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
	err = nvme_get_nsid_log(hdl, cfg.namespace_id, false, 0xca,
				&smart_log, sizeof(smart_log));
	if (!err) {
		if (!cfg.raw_binary)
			show_shannon_smart_log(
				&smart_log, cfg.namespace_id,
				nvme_transport_handle_get_name(hdl));
		else
			d_raw((unsigned char *)&smart_log, sizeof(smart_log));
	} else if (err > 0) {
		nvme_show_status(err);
	}

	return err;
}

static int get_additional_feature(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Read operating parameters of the\n"
		"specified controller. Operating parameters are grouped\n"
		"and identified by Feature Identifiers; each Feature\n"
		"Identifier contains one or more attributes that may affect\n"
		"behavior of the feature. Each Feature has three possible\n"
		"settings: default, saveable, and current. If a Feature is\n"
		"saveable, it may be modified by set-feature. Default values\n"
		"are vendor-specific and not changeable. Use set-feature to\n"
		"change saveable Features.\n\n"
		"Available additional feature id:\n"
		"0x02:  Shannon power management\n";
	const char *raw = "show infos in binary format";
	const char *namespace_id = "identifier of desired namespace";
	const char *feature_id = "hexadecimal feature name";
	const char *sel = "[0-3]: curr./default/saved/supp.";
	const char *data_len = "buffer len (if) data is returned";
	const char *cdw11 = "dword 11 for interrupt vector config";
	const char *human_readable = "show infos in readable format";
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	void *buf = NULL;
	__u32 result;
	int err;

	struct config {
		__u32 namespace_id;
		enum nvme_features_id feature_id;
		__u8  sel;
		__u32 cdw11;
		__u32 data_len;
		bool  raw_binary;
		bool  human_readable;
	};

	struct config cfg = {
		.namespace_id = 1,
		.feature_id   = 0,
		.sel		  = 0,
		.cdw11		  = 0,
		.data_len	  = 0,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id",   'n', &cfg.namespace_id,	namespace_id),
		OPT_UINT("feature-id",	   'f', &cfg.feature_id,	feature_id),
		OPT_BYTE("sel",		   's', &cfg.sel,		sel),
		OPT_UINT("data-len",	   'l', &cfg.data_len,		data_len),
		OPT_FLAG("raw-binary",	   'b', &cfg.raw_binary,	raw),
		OPT_UINT("cdw11",	   'c', &cfg.cdw11,		cdw11),
		OPT_FLAG("human-readable", 'H', &cfg.human_readable,	human_readable),
		OPT_END()
	};

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	if (cfg.sel > 7) {
		fprintf(stderr, "invalid 'select' param:%d\n", cfg.sel);
		return -EINVAL;
	}
	if (!cfg.feature_id) {
		fprintf(stderr, "feature-id required param\n");
		return -EINVAL;
	}
	if (cfg.data_len) {
		if (posix_memalign(&buf, getpagesize(), cfg.data_len))
			return -ENOMEM;
		memset(buf, 0, cfg.data_len);
	}

	struct nvme_get_features_args args = {
		.args_size	= sizeof(args),
		.fid		= cfg.feature_id,
		.nsid		= cfg.namespace_id,
		.sel		= cfg.sel,
		.cdw11		= cfg.cdw11,
		.uuidx		= 0,
		.data_len	= cfg.data_len,
		.data		= buf,
		.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
		.result		= &result,
	};
	err = nvme_get_features(hdl, &args);
	if (err > 0)
		nvme_show_status(err);
	free(buf);
	return err;
}

static int set_additional_feature(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Modify the saveable or changeable\n"
		"current operating parameters of the controller. Operating\n"
		"parameters are grouped and identified by Feature\n"
		"Identifiers. Feature settings can be applied to the entire\n"
		"controller and all associated namespaces, or to only a few\n"
		"namespace(s) associated with the controller. Default values\n"
		"for each Feature are vendor-specific and may not be modified.\n"
		"Use get-feature to determine which Features are supported by\n"
		"the controller and are saveable/changeable.\n\n"
		"Available additional feature id:\n"
		"0x02:  Shannon power management\n";
	const char *namespace_id = "desired namespace";
	const char *feature_id = "hex feature name (required)";
	const char *data_len = "buffer length if data required";
	const char *data = "optional file for feature data (default stdin)";
	const char *value = "new value of feature (required)";
	const char *save = "specifies that the controller shall save the attribute";
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	_cleanup_free_ void *buf = NULL;
	int ffd = STDIN_FILENO;
	__u32 result;
	int err;

	struct config {
		char *file;
		__u32 namespace_id;
		__u32 feature_id;
		__u32 value;
		__u32 data_len;
		bool  save;
	};

	struct config cfg = {
		.file	      = "",
		.namespace_id = 0,
		.feature_id   = 0,
		.value	      = 0,
		.data_len     = 0,
		.save	      = 0,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id),
		OPT_UINT("feature-id",	 'f', &cfg.feature_id,	 feature_id),
		OPT_UINT("value",	 'v', &cfg.value,	 value),
		OPT_UINT("data-len",	 'l', &cfg.data_len,	 data_len),
		OPT_FILE("data",	 'd', &cfg.file,	 data),
		OPT_FLAG("save",	 's', &cfg.save,	 save),
		OPT_END()
	};

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	if (!cfg.feature_id) {
		fprintf(stderr, "feature-id required param\n");
		return -EINVAL;
	}

	if (cfg.data_len) {
		if (posix_memalign(&buf, getpagesize(), cfg.data_len)) {
			fprintf(stderr, "can not allocate feature payload\n");
			return -ENOMEM;
		}
		memset(buf, 0, cfg.data_len);
	}

	if (buf) {
		if (strlen(cfg.file)) {
			ffd = open(cfg.file, O_RDONLY);
			if (ffd <= 0) {
				fprintf(stderr, "no firmware file provided\n");
				return -EINVAL;
			}
		}
		err = read(ffd, (void *)buf, cfg.data_len);
		if (err < 0) {
			fprintf(stderr, "failed to read data buffer from input file\n");
			return -EINVAL;
		}
	}

	struct nvme_set_features_args args = {
		.args_size	= sizeof(args),
		.fid		= cfg.feature_id,
		.nsid		= cfg.namespace_id,
		.cdw11		= cfg.value,
		.cdw12		= 0,
		.save		= cfg.save,
		.uuidx		= 0,
		.cdw15		= 0,
		.data_len	= cfg.data_len,
		.data		= buf,
		.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
		.result		= &result,
	};
	err = nvme_set_features(hdl, &args);
	if (err < 0) {
		perror("set-feature");
		return -errno;
	}
	if (!err) {
		if (buf)
			d(buf, cfg.data_len, 16, 1);
	} else if (err > 0)
		nvme_show_status(err);

	return err;
}

static int shannon_id_ctrl(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return __id_ctrl(argc, argv, acmd, plugin, NULL);
}

