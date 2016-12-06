#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/fs.h>

#include "linux/nvme_ioctl.h"

#include "nvme.h"
#include "nvme-print.h"
#include "nvme-ioctl.h"
#include "plugin.h"

#include "argconfig.h"
#include "suffix.h"

#define CREATE_CMD
#include "memblaze-nvme.h"

enum {
	TOTAL_WRITE,
	TOTAL_READ,
	THERMAL_THROTTLE,
	TEMPT_SINCE_RESET,
	POWER_CONSUMPTION,
	TEMPT_SINCE_BOOTUP,
	POWER_LOSS_PROTECTION,
	WEARLEVELING_COUNT,
	HOST_WRITE,
	THERMAL_THROTTLE_CNT,
	NR_SMART_ITEMS,
};

enum {
	MB_FEAT_POWER_MGMT = 0Xc6,
};

#pragma pack(push, 1)
struct nvme_memblaze_smart_log_item {
	__u8 id[3];
	union {
		__u8	__nmval[2];
		__le16  nmval;
	};
	union {
		__u8 rawval[6];
		struct temperature {
			__le16 max;
			__le16 min;
			__le16 curr;
		} temperature;
		struct power {
			__le16 max;
			__le16 min;
			__le16 curr;
		} power;
		struct thermal_throttle_mb {
			__u8 on;
			__u32 count;
		} thermal_throttle;
		struct temperature_p {
			__le16 max;
			__le16 min;
		} temperature_p;
		struct power_loss_protection {
			__u8 curr;
		} power_loss_protection;
		struct wearleveling_count {
			__le16 min;
			__le16 max;
			__le16 avg;
		} wearleveling_count;
		struct thermal_throttle_cnt {
			__u8 active;
			__le32 cnt;
		} thermal_throttle_cnt;
	};
	__u8 resv;
};
#pragma pack(pop)

struct nvme_memblaze_smart_log {
	struct nvme_memblaze_smart_log_item items[NR_SMART_ITEMS];
	__u8 resv[512 - sizeof(struct nvme_memblaze_smart_log_item) * NR_SMART_ITEMS];
};

/*
 * Return -1 if @fw1 < @fw2
 * Return 0 if @fw1 == @fw2
 * Return 1 if @fw1 > @fw2
 */
static int compare_fw_version(const char *fw1, const char *fw2)
{
	while (*fw1 != '\0') {
		if (*fw2 == '\0' || *fw1 > *fw2)
			return 1;
		if (*fw1 < *fw2)
			return -1;
		fw1++;
		fw2++;
	}

	if (*fw2 != '\0')
		return -1;

	return 0;
}

static __u32 item_id_2_u32(struct nvme_memblaze_smart_log_item *item)
{
	__le32	__id = 0;
	memcpy(&__id, item->id, 3);
	return le32_to_cpu(__id);
}

static __u64 raw_2_u64(const __u8 *buf, size_t len)
{
	__le64	val = 0;
	memcpy(&val, buf, len);
	return le64_to_cpu(val);
}

static int show_memblaze_smart_log(int fd, __u32 nsid, const char *devname,
		struct nvme_memblaze_smart_log *smart)
{
	struct nvme_id_ctrl ctrl;
	char fw_ver[10];
	int err = 0;
	struct nvme_memblaze_smart_log_item *item;

	err = nvme_identify_ctrl(fd, &ctrl);
	if (err)
		return err;
	snprintf(fw_ver, sizeof(fw_ver), "%c.%c%c.%c%c%c%c",
		ctrl.fr[0], ctrl.fr[1], ctrl.fr[2], ctrl.fr[3],
		ctrl.fr[4], ctrl.fr[5], ctrl.fr[6]);

	printf("Additional Smart Log for NVME device:%s namespace-id:%x\n", devname, nsid);

	printf("Total write in GB since last factory reset			: %"PRIu64"\n",
		int48_to_long(smart->items[TOTAL_WRITE].rawval));
	printf("Total read in GB since last factory reset			: %"PRIu64"\n",
		int48_to_long(smart->items[TOTAL_READ].rawval));

	printf("Thermal throttling status[1:HTP in progress]			: %u\n",
		smart->items[THERMAL_THROTTLE].thermal_throttle.on);
	printf("Total thermal throttling minutes since power on			: %u\n",
		smart->items[THERMAL_THROTTLE].thermal_throttle.count);

	printf("Maximum temperature in Kelvin since last factory reset		: %u\n",
		le16_to_cpu(smart->items[TEMPT_SINCE_RESET].temperature.max));
	printf("Minimum temperature in Kelvin since last factory reset		: %u\n",
		le16_to_cpu(smart->items[TEMPT_SINCE_RESET].temperature.min));
	if (compare_fw_version(fw_ver, "0.09.0300") != 0) {
		printf("Maximum temperature in Kelvin since power on			: %u\n",
			le16_to_cpu(smart->items[TEMPT_SINCE_BOOTUP].temperature_p.max));
		printf("Minimum temperature in Kelvin since power on			: %u\n",
			le16_to_cpu(smart->items[TEMPT_SINCE_BOOTUP].temperature_p.min));
	}
	printf("Current temperature in Kelvin					: %u\n",
		le16_to_cpu(smart->items[TEMPT_SINCE_RESET].temperature.curr));

	printf("Maximum power in watt since power on				: %u\n",
		le16_to_cpu(smart->items[POWER_CONSUMPTION].power.max));
	printf("Minimum power in watt since power on				: %u\n",
		le16_to_cpu(smart->items[POWER_CONSUMPTION].power.min));
	printf("Current power in watt						: %u\n",
		le16_to_cpu(smart->items[POWER_CONSUMPTION].power.curr));

	item = &smart->items[POWER_LOSS_PROTECTION];
	if (item_id_2_u32(item) == 0xEC)
		printf("Power loss protection normalized value				: %u\n",
			item->power_loss_protection.curr);

	item = &smart->items[WEARLEVELING_COUNT];
	if (item_id_2_u32(item) == 0xAD) {
		printf("Percentage of wearleveling count left				: %u\n",
				le16_to_cpu(item->nmval));
		printf("Wearleveling count min erase cycle				: %u\n",
				le16_to_cpu(item->wearleveling_count.min));
		printf("Wearleveling count max erase cycle				: %u\n",
				le16_to_cpu(item->wearleveling_count.max));
		printf("Wearleveling count avg erase cycle				: %u\n",
				le16_to_cpu(item->wearleveling_count.avg));
	}

	item = &smart->items[HOST_WRITE];
	if (item_id_2_u32(item) == 0xF5)
		printf("Total host write in GiB since device born 			: %llu\n",
				(unsigned long long)raw_2_u64(item->rawval, sizeof(item->rawval)));
		
	item = &smart->items[THERMAL_THROTTLE_CNT];
	if (item_id_2_u32(item) == 0xEB)
		printf("Thermal throttling count since device born 			: %u\n",
				item->thermal_throttle_cnt.cnt);

	return err;
}

static int get_additional_smart_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	struct nvme_memblaze_smart_log smart_log;
	int err, fd;
	char *desc = "Get Memblaze vendor specific additional smart log (optionally, "\
		      "for the specified namespace), and show it.";
	const char *namespace = "(optional) desired namespace";
	const char *raw = "dump output in binary format";
	struct config {
		__u32 namespace_id;
		int   raw_binary;
	};

	struct config cfg = {
		.namespace_id = 0xffffffff,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id", 'n', "NUM", CFG_POSITIVE, &cfg.namespace_id, required_argument, namespace},
		{"raw-binary",   'b', "",    CFG_NONE,     &cfg.raw_binary,   no_argument,       raw},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));

	err = nvme_get_log(fd, cfg.namespace_id, 0xca, sizeof(smart_log), &smart_log);
	if (!err) {
		if (!cfg.raw_binary)
			err = show_memblaze_smart_log(fd, cfg.namespace_id, devicename, &smart_log);
		else
			d_raw((unsigned char *)&smart_log, sizeof(smart_log));
	}
	if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x)\n", nvme_status_to_string(err), err);

	return err;
}

static char *mb_feature_to_string(int feature)
{
	switch (feature) {
	case MB_FEAT_POWER_MGMT: return "Memblaze power management";
	default:	return "Unknown";
	}
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
		"0xc6:	Memblaze power management\n"\
		"	(value 0 - 25w, 1 - 20w, 2 - 15w)";
	const char *raw_binary = "show infos in binary format";
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
		__u32 feature_id;
		__u8  sel;
		__u32 cdw11;
		__u32 data_len;
		int  raw_binary;
		int  human_readable;
	};

	struct config cfg = {
		.namespace_id = 1,
		.feature_id   = 0,
		.sel          = 0,
		.cdw11        = 0,
		.data_len     = 0,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id",   'n', "NUM", CFG_POSITIVE, &cfg.namespace_id,   required_argument, namespace_id},
		{"feature-id",     'f', "NUM", CFG_POSITIVE, &cfg.feature_id,     required_argument, feature_id},
		{"sel",            's', "NUM", CFG_BYTE,     &cfg.sel,            required_argument, sel},
		{"data-len",       'l', "NUM", CFG_POSITIVE, &cfg.data_len,       required_argument, data_len},
		{"raw-binary",     'b', "FLAG", CFG_NONE,     &cfg.raw_binary,     no_argument,       raw_binary},
		{"cdw11",          'c', "NUM", CFG_POSITIVE, &cfg.cdw11,          required_argument, cdw11},
		{"human-readable", 'H', "FLAG", CFG_NONE,     &cfg.human_readable, no_argument,       human_readable},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));

	if (cfg.sel > 7) {
		fprintf(stderr, "invalid 'select' param:%d\n", cfg.sel);
		return EINVAL;
	}
	if (!cfg.feature_id) {
		fprintf(stderr, "feature-id required param\n");
		return EINVAL;
	}
	if (cfg.data_len) {
		if (posix_memalign(&buf, getpagesize(), cfg.data_len))
			exit(ENOMEM);
		memset(buf, 0, cfg.data_len);
	}

	err = nvme_get_feature(fd, cfg.namespace_id, cfg.feature_id, cfg.sel, cfg.cdw11,
			cfg.data_len, buf, &result);
	if (!err) {
		printf("get-feature:0x%02x (%s), %s value: %#08x\n", cfg.feature_id,
				mb_feature_to_string(cfg.feature_id),
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
		"0xc6:	Memblaze power management\n"\
		"	(value 0 - 25w, 1 - 20w, 2 - 15w)";
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

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id", 'n', "NUM",  CFG_POSITIVE, &cfg.namespace_id, required_argument, namespace_id},
		{"feature-id",   'f', "NUM",  CFG_POSITIVE, &cfg.feature_id,   required_argument, feature_id},
		{"value",        'v', "NUM",  CFG_POSITIVE, &cfg.value,        required_argument, value},
		{"data-len",     'l', "NUM",  CFG_POSITIVE, &cfg.data_len,     required_argument, data_len},
		{"data",         'd', "FILE", CFG_STRING,   &cfg.file,         required_argument, data},
		{"save",         's', "FLAG", CFG_NONE,     &cfg.save,         no_argument, save},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));

	if (!cfg.feature_id) {
		fprintf(stderr, "feature-id required param\n");
		return EINVAL;
	}

	if (cfg.data_len) {
		if (posix_memalign(&buf, getpagesize(), cfg.data_len))
			exit(ENOMEM);
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
		if (read(ffd, (void *)buf, cfg.data_len) < 0) {
			fprintf(stderr, "failed to read data buffer from input file\n");
			return EINVAL;
		}
	}

	err = nvme_set_feature(fd, cfg.namespace_id, cfg.feature_id, cfg.value, cfg.save,
				cfg.data_len, buf, &result);
	if (err < 0) {
		perror("set-feature");
		return errno;
	}
	if (!err) {
		printf("set-feature:%02x (%s), value:%#08x\n", cfg.feature_id,
			mb_feature_to_string(cfg.feature_id), cfg.value);
		if (buf)
			d(buf, cfg.data_len, 16, 1);
	} else if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x)\n",
				nvme_status_to_string(err), err);
	if (buf)
		free(buf);
	return err;
}
