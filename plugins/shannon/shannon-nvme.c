#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>

#include "linux/nvme_ioctl.h"

#include "common.h"
#include "nvme.h"
#include "nvme-print.h"
#include "nvme-ioctl.h"
#include "plugin.h"

#include "argconfig.h"
#include "suffix.h"

#define CREATE_CMD
#include "shannon-nvme.h"

typedef enum {
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
}addtional_smart_items;

#pragma pack(push,1)
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
		} wear_level ;
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
	printf("sram_error_count		: %3d%%       %"PRIu64"\n",
		smart->items[RETRY_BUFFER_OVERFLOW].norm,
		int48_to_long(smart->items[SRAM_ERROR_CNT].item_val));
}


static int get_additional_smart_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	struct nvme_shannon_smart_log smart_log;
	int err, fd;
	char *desc = "Get Shannon vendor specific additional smart log (optionally, "\
		      "for the specified namespace), and show it.";
	const char *namespace = "(optional) desired namespace";
	const char *raw = "dump output in binary format";
	struct config {
		__u32 namespace_id;
		int   raw_binary;
	};

	struct config cfg = {
		.namespace_id = NVME_NSID_ALL,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id,  namespace),
		OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,    raw),
		OPT_END()
	};

	fd = parse_and_open(argc, argv, desc, opts);
	err = nvme_get_log(fd, cfg.namespace_id, 0xca, false,
		   NVME_NO_LOG_LSP, sizeof(smart_log), &smart_log);
	if (!err) {
		if (!cfg.raw_binary)
			show_shannon_smart_log(&smart_log, cfg.namespace_id, devicename);
		else
			d_raw((unsigned char *)&smart_log, sizeof(smart_log));
	}
	else if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x)\n",
					nvme_status_to_string(err), err);
	return err;
}

static int get_additional_feature(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Read operating parameters of the "\
		"specified controller. Operating parameters are grouped "\
		"and identified by Feature Identifiers; each Feature "\
		"Identifier contains one or more attributes that may affect "\
		"behaviour of the feature. Each Feature has three possible "\
		"settings: default, saveable, and current. If a Feature is "\
		"saveable, it may be modified by set-feature. Default values "\
		"are vendor-specific and not changeable. Use set-feature to "\
		"change saveable Features.\n\n"\
		"Available additional feature id:\n"\
		"0x02:	Shannon power management\n";
	const char *raw = "show infos in binary format";
	const char *namespace_id = "identifier of desired namespace";
	const char *feature_id = "hexadecimal feature name";
	const char *sel = "[0-3]: curr./default/saved/supp.";
	const char *data_len = "buffer len (if) data is returned";
	const char *cdw11 = "dword 11 for interrupt vector config";
	const char *human_readable = "show infos in readable format";
	int err, fd;
	__u32 result;
	void *buf = NULL;

	struct config {
		__u32 namespace_id;
		enum nvme_feat feature_id;
		__u8  sel;
		__u32 cdw11;
		__u32 data_len;
		int  raw_binary;
		int  human_readable;
	};

	struct config cfg = {
		.namespace_id = 1,
		.feature_id   = NVME_FEAT_NONE,
		.sel          = 0,
		.cdw11        = 0,
		.data_len     = 0,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id",  'n', &cfg.namespace_id,   namespace_id),
		OPT_UINT("feature-id",    'f', &cfg.feature_id,     feature_id),
		OPT_BYTE("sel",           's', &cfg.sel,            sel),
		OPT_UINT("data-len",      'l', &cfg.data_len,       data_len),
		OPT_FLAG("raw-binary",    'b', &cfg.raw_binary,     raw),
		OPT_UINT("cdw11",         'c', &cfg.cdw11,          cdw11),
		OPT_FLAG("human-readable",'H', &cfg.human_readable, human_readable),
		OPT_END()
	};

	fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		return fd;

	if (cfg.sel > 7) {
		fprintf(stderr, "invalid 'select' param:%d\n", cfg.sel);
		close(fd);
		return EINVAL;
	}
	if (!cfg.feature_id) {
		fprintf(stderr, "feature-id required param\n");
		close(fd);
		return EINVAL;
	}
	if (cfg.data_len) {
		if (posix_memalign(&buf, getpagesize(), cfg.data_len))
		{
			close(fd);
			exit(ENOMEM);
		}
		memset(buf, 0, cfg.data_len);
	}

	err = nvme_get_feature(fd, cfg.namespace_id, cfg.feature_id, cfg.sel, cfg.cdw11,
			cfg.data_len, buf, &result);
	if (!err) {
		printf("get-feature:0x%02x (%s), %s value: %#08x\n", cfg.feature_id,
				nvme_feature_to_string(cfg.feature_id),
				nvme_select_to_string(cfg.sel), result);
		if (cfg.human_readable)
			nvme_feature_show_fields(cfg.feature_id, result, buf);
		else {
			if (buf) {
				if (!cfg.raw_binary)
					d(buf, cfg.data_len, 16, 1);
				else
					d_raw(buf, cfg.data_len);
			}
		}
	} else if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x)\n",
				nvme_status_to_string(err), err);
	if (buf)
		free(buf);
	return err;
}

static int set_additional_feature(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Modify the saveable or changeable "\
		"current operating parameters of the controller. Operating "\
		"parameters are grouped and identified by Feature "\
		"Identifiers. Feature settings can be applied to the entire "\
		"controller and all associated namespaces, or to only a few "\
		"namespace(s) associated with the controller. Default values "\
		"for each Feature are vendor-specific and may not be modified."\
		"Use get-feature to determine which Features are supported by "\
		"the controller and are saveable/changeable.\n\n"\
		"Available additional feature id:\n"\
		"0x02:	Shannon power management\n";
	const char *namespace_id = "desired namespace";
	const char *feature_id = "hex feature name (required)";
	const char *data_len = "buffer length if data required";
	const char *data = "optional file for feature data (default stdin)";
	const char *value = "new value of feature (required)";
	const char *save = "specifies that the controller shall save the attribute";
	int err, fd;
	__u32 result;
	void *buf = NULL;
	int ffd = STDIN_FILENO;

	struct config {
		char *file;
		__u32 namespace_id;
		__u32 feature_id;
		__u32 value;
		__u32 data_len;
		int   save;
	};

	struct config cfg = {
		.file         = "",
		.namespace_id = 0,
		.feature_id   = 0,
		.value        = 0,
		.data_len     = 0,
		.save         = 0,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id),
		OPT_UINT("feature-id",   'f', &cfg.feature_id,   feature_id),
		OPT_UINT("value",        'v', &cfg.value,        value),
		OPT_UINT("data-len",     'l', &cfg.data_len,     data_len),
		OPT_FILE("data",         'd', &cfg.file,         data),
		OPT_FLAG("save",         's', &cfg.save,         save),
		OPT_END()
	};

	fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		return fd;

	if (!cfg.feature_id) {
		fprintf(stderr, "feature-id required param\n");
		close(fd);
		return EINVAL;
	}

	if (cfg.data_len) {
		if (posix_memalign(&buf, getpagesize(), cfg.data_len)){
			fprintf(stderr, "can not allocate feature payload\n");
			close(fd);
			return ENOMEM;
		}
		memset(buf, 0, cfg.data_len);
	}

	if (buf) {
		if (strlen(cfg.file)) {
			ffd = open(cfg.file, O_RDONLY);
			if (ffd <= 0) {
				fprintf(stderr, "no firmware file provided\n");
				err = EINVAL;
				goto free;
			}
		}
		err = read(ffd, (void *)buf, cfg.data_len);
		if (err < 0) {
			fprintf(stderr, "failed to read data buffer from input file\n");
			err = EINVAL;
			goto free;
		}
	}

	err = nvme_set_feature(fd, cfg.namespace_id, cfg.feature_id, cfg.value,
				0, cfg.save, cfg.data_len, buf, &result);
	if (err < 0) {
		perror("set-feature");
		goto free;
	}
	if (!err) {
		printf("set-feature:%02x (%s), value:%#08x\n", cfg.feature_id,
			nvme_feature_to_string(cfg.feature_id), cfg.value);
		if (buf)
			d(buf, cfg.data_len, 16, 1);
	} else if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x)\n",
				nvme_status_to_string(err), err);

free:
	if (buf)
		free(buf);
	return err;
}

static int shannon_id_ctrl(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	return __id_ctrl(argc, argv, cmd, plugin, NULL);
}



