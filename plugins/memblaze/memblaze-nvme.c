// SPDX-License-Identifier: GPL-2.0-or-later
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>

#include "nvme.h"
#include "common.h"
#include "libnvme.h"
#include "plugin.h"
#include "linux/types.h"
#include "nvme-print.h"

#define CREATE_CMD
#include "memblaze-nvme.h"
#include "memblaze-utils.h"

enum {
	/* feature id */
	MB_FEAT_POWER_MGMT = 0x02,
	MB_FEAT_HIGH_LATENCY = 0xE1,
	/* log id */
	GLP_ID_VU_GET_READ_LATENCY_HISTOGRAM = 0xC1,
	GLP_ID_VU_GET_WRITE_LATENCY_HISTOGRAM = 0xC2,
	GLP_ID_VU_GET_HIGH_LATENCY_LOG = 0xC3,
	MB_FEAT_CLEAR_ERRORLOG = 0xF7,
};

#define LOG_PAGE_SIZE					(0x1000)
#define DO_PRINT_FLAG					(1)
#define NOT_PRINT_FLAG					(0)
#define FID_C1_LOG_FILENAME				"log_c1.csv"
#define FID_C2_LOG_FILENAME				"log_c2.csv"
#define FID_C3_LOG_FILENAME				"log_c3.csv"

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

/**********************************************************
 * input: firmware version string
 * output:
 *	   1: new intel format
 *	   0: old memblaze format
 * *******************************************************/
#define MEMBLAZE_FORMAT		(0)
#define INTEL_FORMAT		(1)

/* 2.13 = papaya */
#define IS_PAPAYA(str)			(!strcmp(str, "2.13"))
/* 2.83 = raisin */
#define IS_RAISIN(str)			(!strcmp(str, "2.83"))
/* 2.94 = kumquat */
#define IS_KUMQUAT(str)			(!strcmp(str, "2.94"))
/* 0.60 = loquat */
#define IS_LOQUAT(str)			(!strcmp(str, "0.60"))

#define STR_VER_SIZE			(5)

int getlogpage_format_type(char *model_name)
{
	int logpage_format_type = INTEL_FORMAT;
	const char *boundary_model_name1 = "P"; /* MEMBLAZE P7936DT0640M00 */
	const char *boundary_model_name2 = "P5920"; /* Use INTEL_FORMAT from Raisin P5920. */

	if (!strncmp(model_name, boundary_model_name1, strlen(boundary_model_name1))) {
		if (strncmp(model_name, boundary_model_name2, strlen(boundary_model_name2)) < 0)
			logpage_format_type = MEMBLAZE_FORMAT;
	}
	return logpage_format_type;
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

static void get_memblaze_new_smart_info(struct nvme_p4_smart_log *smart, int index, __u8 *nm_val,
		__u8 *raw_val)
{
	memcpy(nm_val, smart->itemArr[index].nmVal, NM_SIZE);
	memcpy(raw_val, smart->itemArr[index].rawVal, RAW_SIZE);
}

static void show_memblaze_smart_log_new(struct nvme_memblaze_smart_log *s, unsigned int nsid,
		const char *devname)
{
	struct nvme_p4_smart_log *smart = (struct nvme_p4_smart_log *)s;
	__u8 *nm = malloc(NM_SIZE * sizeof(__u8));
	__u8 *raw = malloc(RAW_SIZE * sizeof(__u8));

	if (!nm) {
		if (raw)
			free(raw);
		return;
	}
	if (!raw) {
		free(nm);
		return;
	}

	printf("%s:%s %s:%x\n", "Additional Smart Log for NVME device", devname, "namespace-id",
	       nsid);
	printf("%-34s%-11s%s\n", "key", "normalized", "raw");

	get_memblaze_new_smart_info(smart, RAISIN_SI_VD_PROGRAM_FAIL, nm, raw);
	printf("%-32s: %3d%%       %"PRIu64"\n", "program_fail_count", *nm, int48_to_long(raw));

	get_memblaze_new_smart_info(smart, RAISIN_SI_VD_ERASE_FAIL, nm, raw);
	printf("%-32s: %3d%%       %"PRIu64"\n", "erase_fail_count", *nm, int48_to_long(raw));

	get_memblaze_new_smart_info(smart, RAISIN_SI_VD_WEARLEVELING_COUNT, nm, raw);
	printf("%-31s : %3d%%       %s%u%s%u%s%u\n", "wear_leveling", *nm, "min: ", *(__u16 *)raw,
	       ", max: ", *(__u16 *)(raw+2), ", avg: ", *(__u16 *)(raw+4));

	get_memblaze_new_smart_info(smart, RAISIN_SI_VD_E2E_DECTECTION_COUNT, nm, raw);
	printf("%-31s: %3d%%       %"PRIu64"\n", "end_to_end_error_detection_count", *nm,
	       int48_to_long(raw));

	get_memblaze_new_smart_info(smart, RAISIN_SI_VD_PCIE_CRC_ERR_COUNT, nm, raw);
	printf("%-32s: %3d%%       %"PRIu64"\n", "crc_error_count", *nm, int48_to_long(raw));

	get_memblaze_new_smart_info(smart, RAISIN_SI_VD_TIMED_WORKLOAD_MEDIA_WEAR, nm, raw);
	printf("%-32s: %3d%%       %.3f%%\n", "timed_workload_media_wear", *nm,
	       ((float)int48_to_long(raw))/1000);

	get_memblaze_new_smart_info(smart, RAISIN_SI_VD_TIMED_WORKLOAD_HOST_READ, nm, raw);
	printf("%-32s: %3d%%       %"PRIu64"%%\n", "timed_workload_host_reads", *nm,
	       int48_to_long(raw));

	get_memblaze_new_smart_info(smart, RAISIN_SI_VD_TIMED_WORKLOAD_TIMER, nm, raw);
	printf("%-32s: %3d%%       %"PRIu64"%s\n", "timed_workload_timer", *nm,
	       int48_to_long(raw), " min");

	get_memblaze_new_smart_info(smart, RAISIN_SI_VD_THERMAL_THROTTLE_STATUS, nm, raw);
	printf("%-32s: %3d%%       %u%%%s%"PRIu64"\n", "thermal_throttle_status", *nm, *raw,
	       ", cnt: ", int48_to_long(raw+1));

	get_memblaze_new_smart_info(smart, RAISIN_SI_VD_RETRY_BUFF_OVERFLOW_COUNT, nm, raw);
	printf("%-32s: %3d%%       %"PRIu64"\n", "retry_buffer_overflow_count", *nm,
	       int48_to_long(raw));

	get_memblaze_new_smart_info(smart, RAISIN_SI_VD_PLL_LOCK_LOSS_COUNT, nm, raw);
	printf("%-32s: %3d%%       %"PRIu64"\n", "pll_lock_loss_count", *nm,
	       int48_to_long(raw));

	get_memblaze_new_smart_info(smart, RAISIN_SI_VD_TOTAL_WRITE, nm, raw);
	printf("%-32s: %3d%%       %s%"PRIu64"\n", "nand_bytes_written", *nm, "sectors: ",
	       int48_to_long(raw));

	get_memblaze_new_smart_info(smart, RAISIN_SI_VD_HOST_WRITE, nm, raw);
	printf("%-32s: %3d%%       %s%"PRIu64"\n", "host_bytes_written", *nm, "sectors: ",
	       int48_to_long(raw));

	get_memblaze_new_smart_info(smart, RAISIN_SI_VD_SYSTEM_AREA_LIFE_LEFT, nm, raw);
	printf("%-32s: %3d%%       %"PRIu64"\n", "system_area_life_left", *nm,
	       int48_to_long(raw));

	get_memblaze_new_smart_info(smart, RAISIN_SI_VD_TOTAL_READ, nm, raw);
	printf("%-32s: %3d%%       %"PRIu64"\n", "total_read", *nm, int48_to_long(raw));

	get_memblaze_new_smart_info(smart, RAISIN_SI_VD_TEMPT_SINCE_BORN, nm, raw);
	printf("%-32s: %3d%%       %s%u%s%u%s%u\n", "tempt_since_born",  *nm,
	       "max: ", *(__u16 *)raw, ", min: ", *(__u16 *)(raw+2), ", curr: ", *(__u16 *)(raw+4));

	get_memblaze_new_smart_info(smart, RAISIN_SI_VD_POWER_CONSUMPTION, nm, raw);
	printf("%-32s: %3d%%       %s%u%s%u%s%u\n", "power_consumption",  *nm,
	       "max: ", *(__u16 *)raw, ", min: ", *(__u16 *)(raw+2), ", curr: ", *(__u16 *)(raw+4));

	get_memblaze_new_smart_info(smart, RAISIN_SI_VD_TEMPT_SINCE_BOOTUP, nm, raw);
	printf("%-32s: %3d%%       %s%u%s%u%s%u\n", "tempt_since_bootup",  *nm, "max: ",
		*(__u16 *)raw, ", min: ", *(__u16 *)(raw+2), ", curr: ", *(__u16 *)(raw+4));

	get_memblaze_new_smart_info(smart, RAISIN_SI_VD_READ_FAIL, nm, raw);
	printf("%-32s: %3d%%       %"PRIu64"\n", "read_fail_count", *nm, int48_to_long(raw));

	get_memblaze_new_smart_info(smart, RAISIN_SI_VD_THERMAL_THROTTLE_TIME, nm, raw);
	printf("%-32s: %3d%%       %"PRIu64"\n", "thermal_throttle_time", *nm, int48_to_long(raw));

	get_memblaze_new_smart_info(smart, RAISIN_SI_VD_FLASH_MEDIA_ERROR, nm, raw);
	printf("%-32s: %3d%%       %"PRIu64"\n", "flash_media_error", *nm, int48_to_long(raw));

	free(nm);
	free(raw);
}

static void show_memblaze_smart_log_old(struct nvme_memblaze_smart_log *smart,
	unsigned int nsid, const char *devname, const char *fw_ver)
{
	char fw_ver_local[STR_VER_SIZE + 1];
	struct nvme_memblaze_smart_log_item *item;

	strncpy(fw_ver_local, fw_ver, STR_VER_SIZE);
	*(fw_ver_local + STR_VER_SIZE) = '\0';

	printf("Additional Smart Log for NVME device:%s namespace-id:%x\n", devname, nsid);

	printf("Total write in GB since last factory reset		: %"PRIu64"\n",
	       int48_to_long(smart->items[TOTAL_WRITE].rawval));
	printf("Total read in GB since last factory reset		: %"PRIu64"\n",
	       int48_to_long(smart->items[TOTAL_READ].rawval));

	printf("Thermal throttling status[1:HTP in progress]		: %u\n",
	       smart->items[THERMAL_THROTTLE].thermal_throttle.on);
	printf("Total thermal throttling minutes since power on		: %u\n",
	       smart->items[THERMAL_THROTTLE].thermal_throttle.count);

	printf("Maximum temperature in kelvins since last factory reset	: %u\n",
	       le16_to_cpu(smart->items[TEMPT_SINCE_RESET].temperature.max));
	printf("Minimum temperature in kelvins since last factory reset	: %u\n",
	       le16_to_cpu(smart->items[TEMPT_SINCE_RESET].temperature.min));
	if (compare_fw_version(fw_ver, "0.09.0300") != 0) {
		printf("Maximum temperature in kelvins since power on		: %u\n",
		       le16_to_cpu(smart->items[TEMPT_SINCE_BOOTUP].temperature_p.max));
		printf("Minimum temperature in kelvins since power on		: %u\n",
		       le16_to_cpu(smart->items[TEMPT_SINCE_BOOTUP].temperature_p.min));
	}
	printf("Current temperature in kelvins				: %u\n",
	       le16_to_cpu(smart->items[TEMPT_SINCE_RESET].temperature.curr));

	printf("Maximum power in watt since power on			: %u\n",
	       le16_to_cpu(smart->items[POWER_CONSUMPTION].power.max));
	printf("Minimum power in watt since power on			: %u\n",
	       le16_to_cpu(smart->items[POWER_CONSUMPTION].power.min));
	printf("Current power in watt					: %u\n",
	       le16_to_cpu(smart->items[POWER_CONSUMPTION].power.curr));

	item = &smart->items[POWER_LOSS_PROTECTION];
	if (item_id_2_u32(item) == 0xEC)
		printf("Power loss protection normalized value			: %u\n",
		       item->power_loss_protection.curr);

	item = &smart->items[WEARLEVELING_COUNT];
	if (item_id_2_u32(item) == 0xAD) {
		printf("Percentage of wearleveling count left			: %u\n",
		       le16_to_cpu(item->nmval));
		printf("Wearleveling count min erase cycle			: %u\n",
		       le16_to_cpu(item->wearleveling_count.min));
		printf("Wearleveling count max erase cycle			: %u\n",
		       le16_to_cpu(item->wearleveling_count.max));
		printf("Wearleveling count avg erase cycle			: %u\n",
		       le16_to_cpu(item->wearleveling_count.avg));
	}

	item = &smart->items[HOST_WRITE];
	if (item_id_2_u32(item) == 0xF5)
		printf("Total host write in GiB since device born		: %llu\n",
		       (unsigned long long)raw_2_u64(item->rawval, sizeof(item->rawval)));

	item = &smart->items[THERMAL_THROTTLE_CNT];
	if (item_id_2_u32(item) == 0xEB)
		printf("Thermal throttling count since device born		: %u\n",
		       item->thermal_throttle_cnt.cnt);

	item = &smart->items[CORRECT_PCIE_PORT0];
	if (item_id_2_u32(item) == 0xED)
		printf("PCIE Correctable Error Count of Port0			: %llu\n",
		       (unsigned long long)raw_2_u64(item->rawval, sizeof(item->rawval)));

	item = &smart->items[CORRECT_PCIE_PORT1];
	if (item_id_2_u32(item) == 0xEE)
		printf("PCIE Correctable Error Count of Port1			: %llu\n",
		       (unsigned long long)raw_2_u64(item->rawval, sizeof(item->rawval)));

	item = &smart->items[REBUILD_FAIL];
	if (item_id_2_u32(item) == 0xEF)
		printf("End-to-End Error Detection Count			: %llu\n",
		       (unsigned long long)raw_2_u64(item->rawval, sizeof(item->rawval)));

	item = &smart->items[ERASE_FAIL];
	if (item_id_2_u32(item) == 0xF0)
		printf("Erase Fail Count					: %llu\n",
		       (unsigned long long)raw_2_u64(item->rawval, sizeof(item->rawval)));

	item = &smart->items[PROGRAM_FAIL];
	if (item_id_2_u32(item) == 0xF1)
		printf("Program Fail Count					: %llu\n",
		       (unsigned long long)raw_2_u64(item->rawval, sizeof(item->rawval)));

	item = &smart->items[READ_FAIL];
	if (item_id_2_u32(item) == 0xF2)
		printf("Read Fail Count						: %llu\n",
		       (unsigned long long)raw_2_u64(item->rawval, sizeof(item->rawval)));

	if (IS_PAPAYA(fw_ver_local)) {
		struct nvme_p4_smart_log *s = (struct nvme_p4_smart_log *)smart;
		__u8 *nm = malloc(NM_SIZE * sizeof(__u8));
		__u8 *raw = malloc(RAW_SIZE * sizeof(__u8));

		if (!nm) {
			if (raw)
				free(raw);
			return;
		}
		if (!raw) {
			free(nm);
			return;
		}
		get_memblaze_new_smart_info(s, PROGRAM_FAIL, nm, raw);
		printf("%-32s                                : %3d%%       %"PRIu64"\n",
		       "program_fail_count", *nm, int48_to_long(raw));

		get_memblaze_new_smart_info(s, ERASE_FAIL, nm, raw);
		printf("%-32s                                : %3d%%       %"PRIu64"\n",
		       "erase_fail_count", *nm, int48_to_long(raw));

		get_memblaze_new_smart_info(s, WEARLEVELING_COUNT, nm, raw);
		printf("%-31s                                 : %3d%%       %s%u%s%u%s%u\n",
		       "wear_leveling", *nm, "min: ", *(__u16 *)raw, ", max: ", *(__u16 *)(raw+2),
		       ", avg: ", *(__u16 *)(raw+4));

		get_memblaze_new_smart_info(s, TOTAL_WRITE, nm, raw);
		printf("%-32s                                : %3d%%       %"PRIu64"\n",
		       "nand_bytes_written", *nm, 32*int48_to_long(raw));

		get_memblaze_new_smart_info(s, HOST_WRITE, nm, raw);
		printf("%-32s                                : %3d%%       %"PRIu64"\n",
		       "host_bytes_written", *nm, 32*int48_to_long(raw));

		free(nm);
		free(raw);
	}
}

static int show_memblaze_smart_log(int fd, __u32 nsid, const char *devname,
	struct nvme_memblaze_smart_log *smart)
{
	struct nvme_id_ctrl ctrl;
	char fw_ver[10];
	int err = 0;

	err = nvme_identify_ctrl(fd, &ctrl);
	if (err)
		return err;

	snprintf(fw_ver, sizeof(fw_ver), "%c.%c%c.%c%c%c%c",
		 ctrl.fr[0], ctrl.fr[1], ctrl.fr[2], ctrl.fr[3],
		 ctrl.fr[4], ctrl.fr[5], ctrl.fr[6]);

	if (getlogpage_format_type(ctrl.mn)) /* Intel Format & new format */
		show_memblaze_smart_log_new(smart, nsid, devname);
	else /* Memblaze Format & old format */
		show_memblaze_smart_log_old(smart, nsid, devname, fw_ver);
	return err;
}

int parse_params(char *str, int number, ...)
{
	va_list argp;
	int *param;
	char *c;
	int value;

	va_start(argp, number);

	while (number > 0) {
		c = strtok(str, ",");
		if (!c) {
			printf("No enough parameters. abort...\n");
			va_end(argp);
			return 1;
		}

		if (!isalnum((int)*c)) {
			printf("%s is not a valid number\n", c);
			va_end(argp);
			return 1;
		}
		value = atoi(c);
		param = va_arg(argp, int *);
		*param = value;

		if (str) {
			str = strchr(str, ',');
			if (str)
				str++;
		}
		number--;
	}
	va_end(argp);

	return 0;
}

static int mb_get_additional_smart_log(int argc, char **argv, struct command *cmd,
		struct plugin *plugin)
{
	struct nvme_memblaze_smart_log smart_log;
	char *desc =
	    "Get Memblaze vendor specific additional smart log, and show it.";
	const char *namespace = "(optional) desired namespace";
	const char *raw = "dump output in binary format";
	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
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

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	err = nvme_get_nsid_log(dev_fd(dev), false, 0xca, cfg.namespace_id,
				sizeof(smart_log), &smart_log);
	if (!err) {
		if (!cfg.raw_binary)
			err = show_memblaze_smart_log(dev_fd(dev), cfg.namespace_id, dev->name,
						      &smart_log);
		else
			d_raw((unsigned char *)&smart_log, sizeof(smart_log));
	}
	if (err > 0)
		nvme_show_status(err);

	return err;
}

static char *mb_feature_to_string(int feature)
{
	switch (feature) {
	case MB_FEAT_POWER_MGMT:
		return "Memblaze power management";
	case MB_FEAT_HIGH_LATENCY:
		return "Memblaze high latency log";
	case MB_FEAT_CLEAR_ERRORLOG:
		return "Memblaze clear error log";
	default:
		return "Unknown";
	}
}

static int mb_get_powermanager_status(int argc, char **argv, struct command *cmd,
		struct plugin *plugin)
{
	const char *desc = "Get Memblaze power management ststus\n	(value 0 - 25w, 1 - 20w, 2 - 15w)";
	__u32 result;
	__u32 feature_id = MB_FEAT_POWER_MGMT;
	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	int err;

	OPT_ARGS(opts) = {
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	struct nvme_get_features_args args = {
		.args_size	= sizeof(args),
		.fd		= dev_fd(dev),
		.fid		= feature_id,
		.nsid		= 0,
		.sel		= 0,
		.cdw11		= 0,
		.uuidx		= 0,
		.data_len	= 0,
		.data		= NULL,
		.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
		.result		= &result,
	};
	err = nvme_get_features(&args);
	if (err < 0)
		perror("get-feature");
	if (!err)
		printf("get-feature:0x%02x (%s), %s value: %#08x\n", feature_id,
		       mb_feature_to_string(feature_id), nvme_select_to_string(0), result);
	else if (err > 0)
		nvme_show_status(err);
	return err;
}

static int mb_set_powermanager_status(int argc, char **argv, struct command *cmd,
		struct plugin *plugin)
{
	const char *desc = "Set Memblaze power management status\n	(value 0 - 25w, 1 - 20w, 2 - 15w)";
	const char *value = "new value of feature (required)";
	const char *save = "specifies that the controller shall save the attribute";
	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	__u32 result;
	int err;

	struct config {
		__u32 feature_id;
		__u32 value;
		bool  save;
	};

	struct config cfg = {
		.feature_id   = MB_FEAT_POWER_MGMT,
		.value		  = 0,
		.save		  = 0,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("value",		 'v', &cfg.value,		 value),
		OPT_FLAG("save",		 's', &cfg.save,		 save),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	struct nvme_set_features_args args = {
		.args_size	= sizeof(args),
		.fd		= dev_fd(dev),
		.fid		= cfg.feature_id,
		.nsid		= 0,
		.cdw11		= cfg.value,
		.cdw12		= 0,
		.save		= cfg.save,
		.uuidx		= 0,
		.cdw15		= 0,
		.data_len	= 0,
		.data		= NULL,
		.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
		.result		= &result,
	};
	err = nvme_set_features(&args);
	if (err < 0)
		perror("set-feature");
	if (!err)
		printf("set-feature:%02x (%s), value:%#08x\n", cfg.feature_id,
		       mb_feature_to_string(cfg.feature_id), cfg.value);
	else if (err > 0)
		nvme_show_status(err);

	return err;
}

#define P2MIN					(1)
#define P2MAX					(5000)
#define MB_FEAT_HIGH_LATENCY_VALUE_SHIFT	(15)
static int mb_set_high_latency_log(int argc, char **argv, struct command *cmd,
		struct plugin *plugin)
{
	const char *desc = "Set Memblaze high latency log\n"
			   "	input parameter p1,p2\n"
			   "	p1 value: 0 is disable, 1 is enable\n"
			   "	p2 value: 1 .. 5000 ms";
	const char *param = "input parameters";
	int param1 = 0, param2 = 0;
	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	__u32 result;
	int err;

	struct config {
		__u32 feature_id;
		char *param;
		__u32 value;
	};

	struct config cfg = {
		.feature_id = MB_FEAT_HIGH_LATENCY,
		.param = "0,0",
		.value = 0,
	};

	OPT_ARGS(opts) = {
		OPT_LIST("param", 'p', &cfg.param, param),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	if (parse_params(cfg.param, 2, &param1, &param2)) {
		printf("setfeature: invalid formats %s\n", cfg.param);
		return -EINVAL;
	}
	if ((param1 == 1) && (param2 < P2MIN || param2 > P2MAX)) {
		printf("setfeature: invalid high io latency threshold %d\n", param2);
		return -EINVAL;
	}
	cfg.value = (param1 << MB_FEAT_HIGH_LATENCY_VALUE_SHIFT) | param2;

	struct nvme_set_features_args args = {
		.args_size	= sizeof(args),
		.fd		= dev_fd(dev),
		.fid		= cfg.feature_id,
		.nsid		= 0,
		.cdw11		= cfg.value,
		.cdw12		= 0,
		.save		= false,
		.uuidx		= 0,
		.cdw15		= 0,
		.data_len	= 0,
		.data		= NULL,
		.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
		.result		= &result,
	};
	err = nvme_set_features(&args);
	if (err < 0)
		perror("set-feature");
	if (!err)
		printf("set-feature:0x%02X (%s), value:%#08x\n", cfg.feature_id,
		       mb_feature_to_string(cfg.feature_id), cfg.value);
	else if (err > 0)
		nvme_show_status(err);

	return err;
}

static int glp_high_latency_show_bar(FILE *fdi, int print)
{
	fPRINT_PARAM1("Memblaze High Latency Log\n");
	fPRINT_PARAM1("---------------------------------------------------------------------------------------------\n");
	fPRINT_PARAM1("Timestamp                        Type    QID    CID    NSID     StartLBA      NumLBA   Latency\n");
	fPRINT_PARAM1("---------------------------------------------------------------------------------------------\n");
	return 0;
}

/*
 * High latency log page definition
 * Total 32 bytes
 */
struct log_page_high_latency {
	__u8 port;
	__u8 revision;
	__u16 rsvd;
	__u8 opcode;
	__u8 sqe;
	__u16 cid;
	__u32 nsid;
	__u32 latency;
	__u64 sLBA;
	__u16 numLBA;
	__u16 timestampH;
	__u32 timestampL;
}; /* total 32 bytes */

static int find_deadbeef(char *buf)
{
	if (((*(buf + 0) & 0xff) == 0xef) && ((*(buf + 1) & 0xff) == 0xbe) &&
	    ((*(buf + 2) & 0xff) == 0xad) && ((*(buf + 3) & 0xff) == 0xde))
		return 1;
	return 0;
}

#define TIME_STR_SIZE		(44)
static int glp_high_latency(FILE *fdi, char *buf, int buflen, int print)
{
	struct log_page_high_latency *logEntry;
	char string[TIME_STR_SIZE];
	int i, entrySize;
	__u64 timestamp;
	time_t tt = 0;
	struct tm *t = NULL;
	int millisec = 0;

	if (find_deadbeef(buf))
		return 0;

	entrySize = sizeof(struct log_page_high_latency);
	for (i = 0; i < buflen; i += entrySize) {
		logEntry = (struct log_page_high_latency *)(buf + i);

		if (logEntry->latency == 0 && logEntry->revision == 0)
			return 1;

		if (!logEntry->timestampH) { /* generate host time string */
			snprintf(string, sizeof(string), "%d", logEntry->timestampL);
		} else { /* sort */
			timestamp = logEntry->timestampH;
			timestamp = timestamp << 32;
			timestamp += logEntry->timestampL;
			tt = timestamp / 1000;
			millisec = timestamp % 1000;
			t = gmtime(&tt);
			snprintf(string, sizeof(string), "%4d%02d%02d--%02d:%02d:%02d.%03d UTC",
				 1900 + t->tm_year, 1 + t->tm_mon, t->tm_mday, t->tm_hour,
				 t->tm_min, t->tm_sec, millisec);
		}

		if (fdi)
			fprintf(fdi, "%-32s %-7x %-6x %-6x %-8x %4x%08x  %-8x %-d\n",
				string, logEntry->opcode, logEntry->sqe,
				logEntry->cid, logEntry->nsid,
				(__u32)(logEntry->sLBA >> 32),
				(__u32)logEntry->sLBA, logEntry->numLBA,
				logEntry->latency);
		if (print)
			printf("%-32s %-7x %-6x %-6x %-8x %4x%08x  %-8x %-d\n",
			       string, logEntry->opcode, logEntry->sqe, logEntry->cid,
			       logEntry->nsid, (__u32)(logEntry->sLBA >> 32), (__u32)logEntry->sLBA,
			       logEntry->numLBA, logEntry->latency);
	}
	return 1;
}

static int mb_high_latency_log_print(int argc, char **argv, struct command *cmd,
		struct plugin *plugin)
{
	const char *desc = "Get Memblaze high latency log";
	char buf[LOG_PAGE_SIZE];
	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	FILE *fdi = NULL;
	int err;

	OPT_ARGS(opts) = {
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	fdi = fopen(FID_C3_LOG_FILENAME, "w+");

	glp_high_latency_show_bar(fdi, DO_PRINT_FLAG);
	err = nvme_get_log_simple(dev_fd(dev), GLP_ID_VU_GET_HIGH_LATENCY_LOG, sizeof(buf), &buf);

	while (1) {
		if (!glp_high_latency(fdi, buf, LOG_PAGE_SIZE, DO_PRINT_FLAG))
			break;
		err = nvme_get_log_simple(dev_fd(dev), GLP_ID_VU_GET_HIGH_LATENCY_LOG, sizeof(buf),
					  &buf);
		if (err) {
			nvme_show_status(err);
			break;
		}
	}

	if (fdi)
		fclose(fdi);
	return err;
}

static int memblaze_fw_commit(int fd, int select)
{
	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_admin_fw_commit,
		.cdw10		= 8,
		.cdw12		= select,
	};

	return nvme_submit_admin_passthru(fd, &cmd, NULL);
}

static int mb_selective_download(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc =
		"This performs a selective firmware download, which allows the user to\n"
		"select which firmware binary to update for 9200 devices. This requires a power cycle once the\n"
		"update completes. The options available are:\n\n"
		"OOB - This updates the OOB and main firmware\n"
		"EEP - This updates the eeprom and main firmware\n"
		"ALL - This updates the eeprom, OOB, and main firmware";
	const char *fw = "firmware file (required)";
	const char *select = "FW Select (e.g., --select=OOB, EEP, ALL)";
	int xfer = 4096;
	void *fw_buf;
	int selectNo, fw_fd, fw_size, err, offset = 0;
	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	struct stat sb;
	int i;

	struct config {
		char *fw;
		char *select;
	};

	struct config cfg = {
		.fw  = "",
		.select = "\0",
	};

	OPT_ARGS(opts) = {
		OPT_STRING("fw", 'f', "FILE", &cfg.fw, fw),
		OPT_STRING("select", 's', "flag", &cfg.select, select),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	if (strlen(cfg.select) != 3) {
		fprintf(stderr, "Invalid select flag\n");
		err = EINVAL;
		goto out;
	}

	for (i = 0; i < 3; i++)
		cfg.select[i] = toupper(cfg.select[i]);

	if (!strncmp(cfg.select, "OOB", 3)) {
		selectNo = 18;
	} else if (!strncmp(cfg.select, "EEP", 3)) {
		selectNo = 10;
	} else if (!strncmp(cfg.select, "ALL", 3)) {
		selectNo = 26;
	} else {
		fprintf(stderr, "Invalid select flag\n");
		err = EINVAL;
		goto out;
	}

	fw_fd = open(cfg.fw, O_RDONLY);
	if (fw_fd < 0) {
		fprintf(stderr, "no firmware file provided\n");
		err = EINVAL;
		goto out;
	}

	err = fstat(fw_fd, &sb);
	if (err < 0) {
		perror("fstat");
		err = errno;
		goto out_close;
	}

	fw_size = sb.st_size;
	if (fw_size & 0x3) {
		fprintf(stderr, "Invalid size:%d for f/w image\n", fw_size);
		err = EINVAL;
		goto out_close;
	}

	if (posix_memalign(&fw_buf, getpagesize(), fw_size)) {
		fprintf(stderr, "No memory for f/w size:%d\n", fw_size);
		err = ENOMEM;
		goto out_close;
	}

	if (read(fw_fd, fw_buf, fw_size) != ((ssize_t)(fw_size))) {
		err = errno;
		goto out_free;
	}

	while (fw_size > 0) {
		xfer = min(xfer, fw_size);

		struct nvme_fw_download_args args = {
			.args_size	= sizeof(args),
			.fd		= dev_fd(dev),
			.offset		= offset,
			.data_len	= xfer,
			.data		= fw_buf,
			.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
			.result		= NULL,
		};
		err = nvme_fw_download(&args);
		if (err < 0) {
			perror("fw-download");
			goto out_free;
		} else if (err != 0) {
			nvme_show_status(err);
			goto out_free;
		}
		fw_buf	   += xfer;
		fw_size    -= xfer;
		offset += xfer;
	}

	err = memblaze_fw_commit(dev_fd(dev), selectNo);

	if (err == 0x10B || err == 0x20B) {
		err = 0;
		fprintf(stderr, "Update successful! Please power cycle for changes to take effect\n");
	}

out_free:
	free(fw_buf);
out_close:
	close(fw_fd);
out:
	return err;
}

static void ioLatencyHistogramOutput(FILE *fd, int index, int start, int end, char *unit0,
		char *unit1, unsigned int *pHistogram, int print)
{
	int len;
	char string[64], subString0[12], subString1[12];

	snprintf(subString0, sizeof(subString0), "%d%s", start, unit0);
	if (end != 0x7FFFFFFF)
		snprintf(subString1, sizeof(subString1), "%d%s", end, unit1);
	else
		snprintf(subString1, sizeof(subString1), "%s", "+INF");
	len = snprintf(string, sizeof(string), "%-11d %-11s %-11s %-11u\n",
		       index, subString0, subString1, pHistogram[index]);
	fwrite(string, 1, len, fd);
	if (print)
		printf("%s", string);
}

int io_latency_histogram(char *file, char *buf, int print, int logid)
{
	FILE *fdi = fopen(file, "w+");
	int i, index;
	char unit[2][3];
	unsigned int *revision = (unsigned int *)buf;

	if (logid == GLP_ID_VU_GET_READ_LATENCY_HISTOGRAM)
		fPRINT_PARAM1("Memblaze IO Read Command Latency Histogram\n");
	else if (logid == GLP_ID_VU_GET_WRITE_LATENCY_HISTOGRAM)
		fPRINT_PARAM1("Memblaze IO Write Command Latency Histogram\n");
	fPRINT_PARAM2("Major Revision : %d\n", revision[1]);
	fPRINT_PARAM2("Minor Revision : %d\n", revision[0]);
	buf += 8;

	if (revision[1] == 1 && revision[0] == 0) {
		fPRINT_PARAM1("--------------------------------------------------\n");
		fPRINT_PARAM1("Bucket      Start       End         Value\n");
		fPRINT_PARAM1("--------------------------------------------------\n");
		index = 0;
		strcpy(unit[0], "us");
		strcpy(unit[1], "us");
		for (i = 0; i < 32; i++, index++) {
			if (i == 31) {
				strcpy(unit[1], "ms");
				ioLatencyHistogramOutput(fdi, index, i * 32, 1, unit[0], unit[1],
							 (unsigned int *)buf, print);
			} else {
				ioLatencyHistogramOutput(fdi, index, i * 32, (i + 1) * 32, unit[0],
							 unit[1], (unsigned int *)buf, print);
			}
		}

		strcpy(unit[0], "ms");
		strcpy(unit[1], "ms");
		for (i = 1; i < 32; i++, index++)
			ioLatencyHistogramOutput(fdi, index, i, i + 1, unit[0], unit[1],
						 (unsigned int *)buf, print);

		for (i = 1; i < 32; i++, index++) {
			if (i == 31) {
				strcpy(unit[1], "s");
				ioLatencyHistogramOutput(fdi, index, i * 32, 1, unit[0], unit[1],
							 (unsigned int *)buf, print);
			} else {
				ioLatencyHistogramOutput(fdi, index, i * 32, (i + 1) * 32, unit[0],
							 unit[1], (unsigned int *)buf, print);
			}
		}

		strcpy(unit[0], "s");
		strcpy(unit[1], "s");
		for (i = 1; i < 4; i++, index++)
			ioLatencyHistogramOutput(fdi, index, i, i + 1, unit[0], unit[1],
						 (unsigned int *)buf, print);

		ioLatencyHistogramOutput(fdi, index, i, 0x7FFFFFFF, unit[0], unit[1],
					 (unsigned int *)buf, print);
	} else {
		fPRINT_PARAM1("Unsupported io latency histogram revision\n");
	}

	if (fdi)
		fclose(fdi);
	return 1;
}

static int mb_lat_stats_log_print(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	char stats[LOG_PAGE_SIZE];
	char f1[] = FID_C1_LOG_FILENAME;
	char f2[] = FID_C2_LOG_FILENAME;
	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	int err;

	const char *desc = "Get Latency Statistics log and show it.";
	const char *write = "Get write statistics (read default)";

	struct config {
		bool  write;
	};
	struct config cfg = {
		.write = 0,
	};

	OPT_ARGS(opts) = {
		OPT_FLAG("write", 'w', &cfg.write, write),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	err = nvme_get_log_simple(dev_fd(dev), cfg.write ? 0xc2 : 0xc1, sizeof(stats), &stats);
	if (!err)
		io_latency_histogram(cfg.write ? f2 : f1, stats, DO_PRINT_FLAG,
				     cfg.write ? GLP_ID_VU_GET_WRITE_LATENCY_HISTOGRAM :
				     GLP_ID_VU_GET_READ_LATENCY_HISTOGRAM);
	else
		nvme_show_status(err);

	return err;
}

static int memblaze_clear_error_log(int argc, char **argv, struct command *cmd,
		struct plugin *plugin)
{
	char *desc = "Clear Memblaze devices error log.";
	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	int err;

	__u32 result;

	struct config {
		__u32 feature_id;
		__u32 value;
		int   save;
	};

	struct config cfg = {
		.feature_id	= 0xf7,
		.value		= 0x534d0001,
		.save		= 0,
	};

	OPT_ARGS(opts) = {
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	struct nvme_set_features_args args = {
		.args_size		= sizeof(args),
		.fd			= dev_fd(dev),
		.fid			= cfg.feature_id,
		.nsid			= 0,
		.cdw11			= cfg.value,
		.cdw12			= 0,
		.save			= cfg.save,
		.uuidx			= 0,
		.cdw15			= 0,
		.data_len		= 0,
		.data			= NULL,
		.timeout		= NVME_DEFAULT_IOCTL_TIMEOUT,
		.result			= &result,
	};
	err = nvme_set_features(&args);
	if (err < 0)
		perror("set-feature");
	if (!err)
		printf("set-feature:%02x (%s), value:%#08x\n", cfg.feature_id,
		       mb_feature_to_string(cfg.feature_id), cfg.value);
	else if (err > 0)
		nvme_show_status(err);

	return err;
}

static int mb_set_lat_stats(int argc, char **argv, struct command *command, struct plugin *plugin)
{
	const char *desc = (
			"Enable/Disable Latency Statistics Tracking.\n"
			"No argument prints current status.");
	const char *enable_desc = "Enable LST";
	const char *disable_desc = "Disable LST";
	const __u32 nsid = 0;
	const __u8 fid = 0xe2;
	const __u8 sel = 0;
	const __u32 cdw11 = 0x0;
	const __u32 cdw12 = 0x0;
	const __u32 data_len = 32;
	const __u32 save = 0;
	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	void *buf = NULL;
	__u32 result;
	int err;

	struct config {
		bool enable, disable;
	};

	struct config cfg = {
		.enable = false,
		.disable = false,
	};

	struct argconfig_commandline_options command_line_options[] = {
		{"enable", 'e', "", CFG_FLAG, &cfg.enable, no_argument, enable_desc},
		{"disable", 'd', "", CFG_FLAG, &cfg.disable, no_argument, disable_desc},
		{NULL}
	};

	err = parse_and_open(&dev, argc, argv, desc, command_line_options);

	enum Option {
		None = -1,
		True = 1,
		False = 0,
	};
	enum Option option = None;

	if (cfg.enable && cfg.disable)
		printf("Cannot enable and disable simultaneously.");
	else if (cfg.enable || cfg.disable)
		option = cfg.enable;

	struct nvme_get_features_args args_get = {
		.args_size	= sizeof(args_get),
		.fd		= dev_fd(dev),
		.fid		= fid,
		.nsid		= nsid,
		.sel		= sel,
		.cdw11		= cdw11,
		.uuidx		= 0,
		.data_len	= data_len,
		.data		= buf,
		.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
		.result		= &result,
	};

	struct nvme_set_features_args args_set = {
		.args_size	= sizeof(args_set),
		.fd		= dev_fd(dev),
		.fid		= fid,
		.nsid		= nsid,
		.cdw11		= option,
		.cdw12		= cdw12,
		.save		= save,
		.uuidx		= 0,
		.cdw15		= 0,
		.data_len	= data_len,
		.data		= buf,
		.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
		.result		= &result,
	};

	if (err)
		return err;
	switch (option) {
	case None:
		err = nvme_get_features(&args_get);
		if (!err) {
			printf("Latency Statistics Tracking (FID 0x%X) is currently (%i).\n", fid,
			       result);
		} else {
			printf("Could not read feature id 0xE2.\n");
			return err;
		}
		break;
	case True:
	case False:
			err = nvme_set_features(&args_set);
		if (err > 0) {
			nvme_show_status(err);
		} else if (err < 0) {
			perror("Enable latency tracking");
			fprintf(stderr, "Command failed while parsing.\n");
		} else {
			printf("Successfully set enable bit for FID (0x%X) to %i.\n", 0xe2, option);
		}
		break;
	default:
		printf("%d not supported.\n", option);
		err = EINVAL;
	}
	return err;
}

// Global definitions

static inline int K2C(int k)  // KELVINS_2_CELSIUS
{
	return (k - 273);
};

// Global ID definitions

enum {
	// feature ids
	FID_LATENCY_FEATURE = 0xd0,

	// log ids
	LID_SMART_LOG_ADD          = 0xca,
	LID_LATENCY_STATISTICS     = 0xd0,
	LID_HIGH_LATENCY_LOG       = 0xd1,
	LID_PERFORMANCE_STATISTICS = 0xd2,
};

// smart-log-add

struct smart_log_add_item {
	uint32_t index;
	char    *attr;
};

struct __packed wear_level {
	__le16 min;
	__le16 max;
	__le16 avg;
};

struct __packed smart_log_add_item_12 {
	uint8_t id;
	uint8_t rsvd[2];
	uint8_t norm;
	uint8_t rsvd1;
	union {
		struct wear_level wear_level;  // 0xad
		struct __packed temp_since_born {       // 0xe7
			__le16 max;
			__le16 min;
			__le16 curr;
		} temp_since_born;
		struct __packed power_consumption {  // 0xe8
			__le16 max;
			__le16 min;
			__le16 curr;
		} power_consumption;
		struct __packed temp_since_power_on {  // 0xaf
			__le16 max;
			__le16 min;
			__le16 curr;
		} temp_since_power_on;
		uint8_t raw[6];
	};
	uint8_t rsvd2;
};

struct __packed smart_log_add_item_10 {
	uint8_t id;
	uint8_t norm;
	union {
		struct wear_level wear_level;  // 0xad
		uint8_t           raw[6];
	};
	uint8_t rsvd[2];
};

struct __packed smart_log_add {
	union {
		union {
			struct __packed smart_log_add_v0 {
				struct smart_log_add_item_12 program_fail_count;
				struct smart_log_add_item_12 erase_fail_count;
				struct smart_log_add_item_12 wear_leveling_count;
				struct smart_log_add_item_12 end_to_end_error_count;
				struct smart_log_add_item_12 crc_error_count;
				struct smart_log_add_item_12 timed_workload_media_wear;
				struct smart_log_add_item_12 timed_workload_host_reads;
				struct smart_log_add_item_12 timed_workload_timer;
				struct smart_log_add_item_12 thermal_throttle_status;
				struct smart_log_add_item_12 retry_buffer_overflow_counter;
				struct smart_log_add_item_12 pll_lock_loss_count;
				struct smart_log_add_item_12 nand_bytes_written;
				struct smart_log_add_item_12 host_bytes_written;
				struct smart_log_add_item_12 system_area_life_remaining;
				struct smart_log_add_item_12 nand_bytes_read;
				struct smart_log_add_item_12 temperature;
				struct smart_log_add_item_12 power_consumption;
				struct smart_log_add_item_12 power_on_temperature;
				struct smart_log_add_item_12 power_loss_protection;
				struct smart_log_add_item_12 read_fail_count;
				struct smart_log_add_item_12 thermal_throttle_time;
				struct smart_log_add_item_12 flash_error_media_count;
			} v0;

			struct smart_log_add_item_12 v0_raw[22];
		};

		union {
			struct __packed smart_log_add_v2 {
				struct smart_log_add_item_12 program_fail_count;
				struct smart_log_add_item_12 erase_fail_count;
				struct smart_log_add_item_12 wear_leveling_count;
				struct smart_log_add_item_12 end_to_end_error_count;
				struct smart_log_add_item_12 crc_error_count;
				struct smart_log_add_item_12 timed_workload_media_wear;
				struct smart_log_add_item_12 timed_workload_host_reads;
				struct smart_log_add_item_12 timed_workload_timer;
				struct smart_log_add_item_12 thermal_throttle_status;
				struct smart_log_add_item_12 lifetime_write_amplification;
				struct smart_log_add_item_12 pll_lock_loss_count;
				struct smart_log_add_item_12 nand_bytes_written;
				struct smart_log_add_item_12 host_bytes_written;
				struct smart_log_add_item_12 system_area_life_remaining;
				struct smart_log_add_item_12 firmware_update_count;
				struct smart_log_add_item_12 dram_cecc_count;
				struct smart_log_add_item_12 dram_uecc_count;
				struct smart_log_add_item_12 xor_pass_count;
				struct smart_log_add_item_12 xor_fail_count;
				struct smart_log_add_item_12 xor_invoked_count;
				struct smart_log_add_item_12 inflight_read_io_cmd;
				struct smart_log_add_item_12 inflight_write_io_cmd;
				struct smart_log_add_item_12 nand_bytes_read;
				struct smart_log_add_item_12 temp_since_born;
				struct smart_log_add_item_12 power_consumption;
				struct smart_log_add_item_12 temp_since_bootup;
				struct smart_log_add_item_12 thermal_throttle_time;
			} v2;

			struct smart_log_add_item_12 v2_raw[27];
		};

		union {
			struct __packed smart_log_add_v3 {
				struct smart_log_add_item_10 program_fail_count;
				struct smart_log_add_item_10 erase_fail_count;
				struct smart_log_add_item_10 wear_leveling_count;
				struct smart_log_add_item_10 ext_e2e_err_count;
				struct smart_log_add_item_10 crc_err_count;
				struct smart_log_add_item_10 nand_bytes_written;
				struct smart_log_add_item_10 host_bytes_written;
				struct smart_log_add_item_10 reallocated_sector_count;
				struct smart_log_add_item_10 uncorrectable_sector_count;
				struct smart_log_add_item_10 nand_uecc_detection;
				struct smart_log_add_item_10 nand_xor_correction;
				struct smart_log_add_item_10 gc_count;
				struct smart_log_add_item_10 dram_uecc_detection_count;
				struct smart_log_add_item_10 sram_uecc_detection_count;
				struct smart_log_add_item_10 internal_raid_recovery_fail_count;
				struct smart_log_add_item_10 inflight_cmds;
				struct smart_log_add_item_10 internal_e2e_err_count;
				struct smart_log_add_item_10 die_fail_count;
				struct smart_log_add_item_10 wear_leveling_execution_count;
				struct smart_log_add_item_10 read_disturb_count;
				struct smart_log_add_item_10 data_retention_count;
				struct smart_log_add_item_10 capacitor_health;
			} v3;

			struct smart_log_add_item_10 v3_raw[24];
		};

		uint8_t raw[512];
	};
};

static void smart_log_add_v0_print(struct smart_log_add_item_12 *item, int item_count)
{
	static const struct smart_log_add_item items[0xff] = {
		[0xab] = {0,  "program_fail_count"           },
		[0xac] = {1,  "erase_fail_count"             },
		[0xad] = {2,  "wear_leveling_count"          },
		[0xb8] = {3,  "end_to_end_error_count"       },
		[0xc7] = {4,  "crc_error_count"              },
		[0xe2] = {5,  "timed_workload_media_wear"    },
		[0xe3] = {6,  "timed_workload_host_reads"    },
		[0xe4] = {7,  "timed_workload_timer"         },
		[0xea] = {8,  "thermal_throttle_status"      },
		[0xf0] = {9,  "retry_buffer_overflow_counter"},
		[0xf3] = {10, "pll_lock_loss_count"          },
		[0xf4] = {11, "nand_bytes_written"           },
		[0xf5] = {12, "host_bytes_written"           },
		[0xf6] = {13, "system_area_life_remaining"   },
		[0xfa] = {14, "nand_bytes_read"              },
		[0xe7] = {15, "temperature"                  },
		[0xe8] = {16, "power_consumption"            },
		[0xaf] = {17, "power_on_temperature"         },
		[0xec] = {18, "power_loss_protection"        },
		[0xf2] = {19, "read_fail_count"              },
		[0xeb] = {20, "thermal_throttle_time"        },
		[0xed] = {21, "flash_error_media_count"      },
	};

	for (int i = 0; i < item_count; i++, item++) {
		if (item->id == 0)
			continue;

		printf("%#-12" PRIx8 "%-36s%-12d", item->id, items[item->id].attr, item->norm);
		switch (item->id) {
		case 0xad:
			printf("min: %d, max: %d, avg: %d\n",
			       le16_to_cpu(item->wear_level.min),
			       le16_to_cpu(item->wear_level.max),
			       le16_to_cpu(item->wear_level.avg));
			break;
		case 0xe7:
			printf("max: %d °C (%d K), min: %d °C (%d K), curr: %d °C (%d K)\n",
			       K2C(le16_to_cpu(item->temp_since_born.max)),
			       le16_to_cpu(item->temp_since_born.max),
			       K2C(le16_to_cpu(item->temp_since_born.min)),
			       le16_to_cpu(item->temp_since_born.min),
			       K2C(le16_to_cpu(item->temp_since_born.curr)),
			       le16_to_cpu(item->temp_since_born.curr));
			break;
		case 0xe8:
			printf("max: %d, min: %d, curr: %d\n",
			       le16_to_cpu(item->power_consumption.max),
			       le16_to_cpu(item->power_consumption.min),
			       le16_to_cpu(item->power_consumption.curr));
			break;
		case 0xaf:
			printf("max: %d °C (%d K), min: %d °C (%d K), curr: %d °C (%d K)\n",
			       K2C(le16_to_cpu(item->temp_since_power_on.max)),
			       le16_to_cpu(item->temp_since_power_on.max),
			       K2C(le16_to_cpu(item->temp_since_power_on.min)),
			       le16_to_cpu(item->temp_since_power_on.min),
			       K2C(le16_to_cpu(item->temp_since_power_on.curr)),
			       le16_to_cpu(item->temp_since_power_on.curr));
			break;
		default:
			printf("%" PRIu64 "\n", int48_to_long(item->raw));
			break;
		}
	}
}

static void smart_log_add_v2_print(struct smart_log_add_item_12 *item, int item_count)
{
	static const struct smart_log_add_item items[0xff] = {
		[0xab] = {0,  "program_fail_count"          },
		[0xac] = {1,  "erase_fail_count"            },
		[0xad] = {2,  "wear_leveling_count"         },
		[0xb8] = {3,  "end_to_end_error_count"      },
		[0xc7] = {4,  "crc_error_count"             },
		[0xe2] = {5,  "timed_workload_media_wear"   },
		[0xe3] = {6,  "timed_workload_host_reads"   },
		[0xe4] = {7,  "timed_workload_timer"        },
		[0xea] = {8,  "thermal_throttle_status"     },
		[0xf0] = {9,  "lifetime_write_amplification"},
		[0xf3] = {10, "pll_lock_loss_count"         },
		[0xf4] = {11, "nand_bytes_written"          },
		[0xf5] = {12, "host_bytes_written"          },
		[0xf6] = {13, "system_area_life_remaining"  },
		[0xf9] = {14, "firmware_update_count"       },
		[0xfa] = {15, "dram_cecc_count"             },
		[0xfb] = {16, "dram_uecc_count"             },
		[0xfc] = {17, "xor_pass_count"              },
		[0xfd] = {18, "xor_fail_count"              },
		[0xfe] = {19, "xor_invoked_count"           },
		[0xe5] = {20, "inflight_read_io_cmd"        },
		[0xe6] = {21, "inflight_write_io_cmd"       },
		[0xf8] = {22, "nand_bytes_read"             },
		[0xe7] = {23, "temp_since_born"             },
		[0xe8] = {24, "power_consumption"           },
		[0xaf] = {25, "temp_since_bootup"           },
		[0xeb] = {26, "thermal_throttle_time"       },
	};

	for (int i = 0; i < item_count; i++, item++) {
		if (item->id == 0)
			continue;

		printf("%#-12" PRIx8 "%-36s%-12d", item->id, items[item->id].attr, item->norm);
		switch (item->id) {
		case 0xad:
			printf("min: %d, max: %d, avg: %d\n",
			       le16_to_cpu(item->wear_level.min),
			       le16_to_cpu(item->wear_level.max),
			       le16_to_cpu(item->wear_level.avg));
			break;
		case 0xe7:
			printf("max: %d °C (%d K), min: %d °C (%d K), curr: %d °C (%d K)\n",
			       K2C(le16_to_cpu(item->temp_since_born.max)),
			       le16_to_cpu(item->temp_since_born.max),
			       K2C(le16_to_cpu(item->temp_since_born.min)),
			       le16_to_cpu(item->temp_since_born.min),
			       K2C(le16_to_cpu(item->temp_since_born.curr)),
			       le16_to_cpu(item->temp_since_born.curr));
			break;
		case 0xe8:
			printf("max: %d, min: %d, curr: %d\n",
			       le16_to_cpu(item->power_consumption.max),
			       le16_to_cpu(item->power_consumption.min),
			       le16_to_cpu(item->power_consumption.curr));
			break;
		case 0xaf:
			printf("max: %d °C (%d K), min: %d °C (%d K), curr: %d °C (%d K)\n",
			       K2C(le16_to_cpu(item->temp_since_power_on.max)),
			       le16_to_cpu(item->temp_since_power_on.max),
			       K2C(le16_to_cpu(item->temp_since_power_on.min)),
			       le16_to_cpu(item->temp_since_power_on.min),
			       K2C(le16_to_cpu(item->temp_since_power_on.curr)),
			       le16_to_cpu(item->temp_since_power_on.curr));
			break;
		default:
			printf("%" PRIu64 "\n", int48_to_long(item->raw));
			break;
		}
	}
}

static void smart_log_add_v3_print(struct smart_log_add_item_10 *item, int item_count)
{
	static const struct smart_log_add_item items[0xff] = {
		[0xab] = {0,  "program_fail_count"               },
		[0xac] = {1,  "erase_fail_count"                 },
		[0xad] = {2,  "wear_leveling_count"              },
		[0xdf] = {3,  "ext_e2e_err_count"                },
		[0xc7] = {4,  "crc_err_count"                    },
		[0xf4] = {5,  "nand_bytes_written"               },
		[0xf5] = {6,  "host_bytes_written"               },
		[0xd0] = {7,  "reallocated_sector_count"         },
		[0xd1] = {8,  "uncorrectable_sector_count"       },
		[0xd2] = {9,  "nand_uecc_detection"              },
		[0xd3] = {10, "nand_xor_correction"              },
		[0xd4] = {12, "gc_count"                         }, // 11 is reserved
		[0xd5] = {13, "dram_uecc_detection_count"        },
		[0xd6] = {14, "sram_uecc_detection_count"        },
		[0xd7] = {15, "internal_raid_recovery_fail_count"},
		[0xd8] = {16, "inflight_cmds"                    },
		[0xd9] = {17, "internal_e2e_err_count"           },
		[0xda] = {19, "die_fail_count"                   }, // 18 is reserved
		[0xdb] = {20, "wear_leveling_execution_count"    },
		[0xdc] = {21, "read_disturb_count"               },
		[0xdd] = {22, "data_retention_count"             },
		[0xde] = {23, "capacitor_health"                 },
	};

	for (int i = 0; i < item_count; i++, item++) {
		if (item->id == 0)
			continue;

		printf("%#-12" PRIx8 "%-36s%-12d", item->id, items[item->id].attr, item->norm);
		switch (item->id) {
		case 0xad:
			printf("min: %d, max: %d, avg: %d\n",
			       le16_to_cpu(item->wear_level.min),
			       le16_to_cpu(item->wear_level.max),
			       le16_to_cpu(item->wear_level.avg));
			break;
		default:
			printf("%" PRIu64 "\n", int48_to_long(item->raw));
			break;
		}
	}
}

static void smart_log_add_print(struct smart_log_add *log, const char *devname)
{
	uint8_t version = log->raw[511];

	printf("Version: %u\n", version);
	printf("\n");
	printf("Additional Smart Log for NVMe device: %s\n", devname);
	printf("\n");

	printf("%-12s%-36s%-12s%s\n", "Id", "Key", "Normalized", "Raw");

	switch (version) {
	case 0:
		return smart_log_add_v0_print(&log->v0_raw[0],
			sizeof(struct smart_log_add_v0) / sizeof(struct smart_log_add_item_12));
	case 2:
		return smart_log_add_v2_print(&log->v2_raw[0],
			sizeof(struct smart_log_add_v2) / sizeof(struct smart_log_add_item_12));
	case 3:
		return smart_log_add_v3_print(&log->v3_raw[0],
			sizeof(struct smart_log_add_v3) / sizeof(struct smart_log_add_item_10));

	case 1:
		fprintf(stderr, "Version %d: N/A\n", version);
		break;
	default:
		fprintf(stderr, "Version %d: Not supported yet\n", version);
		break;
	}
}

static int mb_get_smart_log_add(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	int err = 0;

	// Get the configuration

	struct config {
		bool raw_binary;
	};

	struct config cfg = {0};

	OPT_ARGS(opts) = {
		OPT_FLAG("raw-binary", 'b', &cfg.raw_binary, "dump the whole log buffer in binary format"),
		OPT_END()};

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;

	err = parse_and_open(&dev, argc, argv, cmd->help, opts);
	if (err)
		return err;

	// Get log

	struct smart_log_add log = {0};

	err = nvme_get_log_simple(dev_fd(dev), LID_SMART_LOG_ADD, sizeof(struct smart_log_add),
			&log);
	if (!err) {
		if (!cfg.raw_binary)
			smart_log_add_print(&log, dev->name);
		else
			d_raw((unsigned char *)&log, sizeof(struct smart_log_add));
	} else if (err > 0) {
		nvme_show_status(err);
	} else {
		nvme_show_error("%s: %s", cmd->name, nvme_strerror(errno));
	}

	return err;
}

// performance-monitor

struct latency_stats_bucket {
	char *start_threshold;
	char *end_threshold;
};

struct __packed latency_stats {
	union {
		struct __packed latency_stats_v2_0 {
			uint32_t minor_version;
			uint32_t major_version;
			uint32_t bucket_read_data[32];
			uint32_t rsvd[32];
			uint32_t bucket_write_data[32];
			uint32_t rsvd1[32];
			uint32_t bucket_trim_data[32];
			uint32_t rsvd2[32];
			uint8_t  rsvd3[248];
		} v2_0;
		uint8_t raw[1024];
	};
};

struct __packed high_latency_log {
	union {
		struct __packed high_latency_log_v1 {
			uint32_t version;
			struct __packed high_latency_log_entry {
				uint64_t timestamp;  // ms
				uint32_t latency;
				uint32_t qid;
				uint32_t opcode : 8;
				uint32_t fuse   : 2;
				uint32_t psdt   : 2;
				uint32_t cid    : 16;
				uint32_t rsvd   : 4;
				uint32_t nsid;
				uint64_t slba;
				uint32_t nlb   : 16;
				uint32_t dtype : 8;
				uint32_t pinfo : 4;
				uint32_t fua   : 1;
				uint32_t lr    : 1;
				uint32_t rsvd1 : 2;
				uint8_t  rsvd2[28];
			} entries[1024];
		} v1;
		uint8_t raw[4 + 1024 * 64];
	};
};

struct __packed performance_stats {
	union {
		struct __packed performance_stats_v1 {
			uint8_t version;
			uint8_t rsvd[3];
			struct __packed performance_stats_timestamp {
				uint8_t timestamp[6];
				struct __packed performance_stats_entry {
					uint16_t read_iops;          // K IOPS
					uint16_t read_bandwidth;     // MiB
					uint32_t read_latency;       // us
					uint32_t read_latency_max;   // us
					uint16_t write_iops;         // K IOPS
					uint16_t write_bandwidth;    // MiB
					uint32_t write_latency;      // us
					uint32_t write_latency_max;  // us
				} entries[3600];
			} timestamps[24];
		} v1;
		struct __packed performance_stats_v2 {
			uint8_t version;
			uint8_t rsvd[3];
			struct __packed performance_stats_timestamp_v2 {
				uint8_t timestamp[6];
				struct __packed performance_stats_entry_v2 {
					uint16_t read_iops;
					uint16_t read_bandwidth;
					uint16_t read_latency_avg;
					uint16_t read_latency_max;
					uint8_t  scale_of_read_iops;
					uint8_t  scale_of_read_bandwidth;
					uint8_t  scale_of_read_latency_avg;
					uint8_t  scale_of_read_latency_max;
					uint16_t write_iops;
					uint16_t write_bandwidth;
					uint16_t write_latency_avg;
					uint16_t write_latency_max;
					uint8_t  scale_of_write_iops;
					uint8_t  scale_of_write_bandwidth;
					uint8_t  scale_of_write_latency_avg;
					uint8_t  scale_of_write_latency_max;
				} entries[3600];
			} timestamps[24];
		} v2;
		uint8_t raw[4 + 24 * (6 + 3600 * 24)];
	};
};

static int mb_set_latency_feature(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	int err = 0;

	// Get the configuration

	struct config {
		uint32_t perf_monitor;
		uint32_t cmd_mask;
		uint32_t read_threshold;
		uint32_t write_threshold;
		uint32_t de_allocate_trim_threshold;
	};

	struct config cfg = {0};

	OPT_ARGS(opts) = {
		OPT_UINT("sel-perf-log", 's', &cfg.perf_monitor,
			 "Select features to turn on, default: Disable\n"
			 "    bit 0: latency statistics\n"
			 "    bit 1: high latency log\n"
			 "    bit 2: Performance stat"),
		OPT_UINT("set-commands-mask", 'm', &cfg.cmd_mask,
		  "Set Enable, default: Disable\n"
		  "    bit 0: Read commands\n"
		  "    bit 1: high Write commands\n"
		  "    bit 2: De-allocate/TRIM (this bit is not worked for Performance stat.)"),
		OPT_UINT("set-read-threshold", 'r', &cfg.read_threshold,
		  "set read high latency log threshold, it's a 0-based value and unit is 10ms"),
		OPT_UINT("set-write-threshold", 'w', &cfg.write_threshold,
		  "set write high latency log threshold, it's a 0-based value and unit is 10ms"),
		OPT_UINT("set-trim-threshold", 't', &cfg.de_allocate_trim_threshold,
		  "set trim high latency log threshold, it's a 0-based value and unit is 10ms"),
		OPT_END()};

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;

	err = parse_and_open(&dev, argc, argv, cmd->help, opts);
	if (err)
		return err;


	// Set feature

	uint32_t result = 0;

	struct nvme_set_features_args args = {
		.args_size = sizeof(args),
		.fd        = dev_fd(dev),
		.fid       = FID_LATENCY_FEATURE,
		.nsid      = 0,
		.cdw11     = 0 | cfg.perf_monitor,
		.cdw12     = 0 | cfg.cmd_mask,
		.cdw13     = 0 |
				(cfg.read_threshold & 0xff) |
				((cfg.write_threshold & 0xff) << 8) |
				((cfg.de_allocate_trim_threshold & 0xff) << 16),
		.cdw15     = 0,
		.save      = 0,
		.uuidx     = 0,
		.data      = NULL,
		.data_len  = 0,
		.timeout   = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result    = &result,
	};

	err = nvme_set_features(&args);
	if (!err)
		printf("%s have done successfully. result = %#" PRIx32 ".\n", cmd->name, result);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("%s: %s", cmd->name, nvme_strerror(errno));

	return err;
}

static int mb_get_latency_feature(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	int err = 0;

	// Get the configuration

	OPT_ARGS(opts) = {
		OPT_END()};

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;

	err = parse_and_open(&dev, argc, argv, cmd->help, opts);
	if (err)
		return err;

	// Get feature

	uint32_t result = 0;

	err = nvme_get_features_simple(dev_fd(dev), FID_LATENCY_FEATURE, 0, &result);
	if (!err) {
		printf("%s have done successfully. result = %#" PRIx32 ".\n", cmd->name, result);

		printf("latency statistics enable status = %d\n", (result & (0x01 << 0)) >> 0);
		printf("high latency enable status = %d\n", (result & (0x01 << 1)) >> 1);
		printf("performance stat enable status = %d\n", (result & (0x01 << 2)) >> 2);

		printf("Monitor Read command = %d\n", (result & (0x01 << 4)) >> 4);
		printf("Monitor Write command = %d\n", (result & (0x01 << 5)) >> 5);
		printf("Monitor Trim command = %d\n", (result & (0x01 << 6)) >> 6);

		printf("Threshold for Read = %dms\n", (((result & (0xff << 8)) >> 8) + 1) * 10);
		printf("Threshold for Write = %dms\n", (((result & (0xff << 16)) >> 16) + 1) * 10);
		printf("Threshold for Trim = %dms\n", (((result & (0xff << 24)) >> 24) + 1) * 10);
	} else if (err > 0) {
		nvme_show_status(err);
	} else {
		nvme_show_error("%s: %s", cmd->name, nvme_strerror(errno));
	}

	return err;
}

static void latency_stats_v2_0_print(struct latency_stats *log, int size)
{
	static const struct latency_stats_bucket buckets[0xff] = {
		[1] = {"0us",   "50us" },
		[2] = {"50us",  "100us"},
		[3] = {"100us", "150us"},
		[4] = {"150us", "200us"},
		[5] = {"200us", "300us"},
		[6] = {"300us", "400us"},
		[7] = {"400us", "500us"},
		[8] = {"500us", "600us"},
		[9] = {"600us", "700us"},
		[10] = {"700us", "800us"},
		[11] = {"800us", "900us"},
		[12] = {"900us", "1ms"  },
		[13] = {"1ms",   "5ms"  },
		[14] = {"5ms",   "10ms" },
		[15] = {"10ms",  "20ms" },
		[16] = {"20ms",  "50ms" },
		[17] = {"50ms",  "100ms"},
		[18] = {"100ms", "200ms"},
		[19] = {"200ms", "300ms"},
		[20] = {"300ms", "400ms"},
		[21] = {"400ms", "500ms"},
		[22] = {"500ms", "600ms"},
		[23] = {"600ms", "700ms"},
		[24] = {"700ms", "800ms"},
		[25] = {"800ms", "900ms"},
		[26] = {"900ms", "1s"   },
		[27] = {"1s",    "2s"   },
		[28] = {"2s",    "3s"   },
		[29] = {"3s",    "4s"   },
		[30] = {"4s",    "5s"   },
		[31] = {"5s",    "8s"   },
		[32] = {"8s",    "INF"  },
	};

	printf("Bucket 1-32 IO Read Command Data\n");
	printf("-------------------------------------------\n");
	printf("%-12s%-12s%-12s%-12s\n", "Bucket", "Start(>=)", "End(<)", "Value");
	int bucket_count = sizeof(log->v2_0.bucket_read_data) / sizeof(uint32_t);

	for (int i = 0; i < bucket_count; i++) {
		printf("%-12u%-12s%-12s%-12u\n", i + 1, buckets[i + 1].start_threshold,
		       buckets[i + 1].end_threshold, log->v2_0.bucket_read_data[i]);
	}
	printf("\n");

	printf("Bucket 1-32 IO Write Command Data\n");
	printf("-------------------------------------------\n");
	printf("%-12s%-12s%-12s%-12s\n", "Bucket", "Start(>=)", "End(<)", "Value");
	bucket_count = sizeof(log->v2_0.bucket_write_data) / sizeof(uint32_t);

	for (int i = 0; i < bucket_count; i++) {
		printf("%-12u%-12s%-12s%-12u\n", i + 1, buckets[i + 1].start_threshold,
		       buckets[i + 1].end_threshold, log->v2_0.bucket_write_data[i]);
	}
	printf("\n");

	printf("Bucket 1-32 IO Trim Command Data\n");
	printf("-------------------------------------------\n");
	printf("%-12s%-12s%-12s%-12s\n", "Bucket", "Start(>=)", "End(<)", "Value");
	bucket_count = sizeof(log->v2_0.bucket_trim_data) / sizeof(uint32_t);

	for (int i = 0; i < bucket_count; i++) {
		printf("%-12u%-12s%-12s%-12u\n", i + 1, buckets[i + 1].start_threshold,
		       buckets[i + 1].end_threshold, log->v2_0.bucket_trim_data[i]);
	}
	printf("\n");
}

static void latency_stats_print(struct latency_stats *log, const char *devname)
{
	uint32_t minor_version = *(uint32_t *)&log->raw[0];
	uint32_t major_version = *(uint32_t *)&log->raw[4];

	printf("Major Version: %u, Minor Version: %u\n", major_version, minor_version);
	printf("\n");
	printf("Latency Statistics Log for NVMe device: %s\n", devname);
	printf("\n");

	switch (major_version) {
	case 2:
		switch (minor_version) {
		case 0:
			latency_stats_v2_0_print(log, sizeof(struct latency_stats));
			break;
		default:
			fprintf(stderr, "Major Version %u, Minor Version %u: Not supported yet\n",
				major_version, minor_version);
			break;
		}
		break;

	default:
		fprintf(stderr, "Major Version %u: Not supported yet\n", major_version);
		break;
	}
}

static int mb_get_latency_stats(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	// Get the configuration

	struct config {
		bool raw_binary;
	};

	struct config cfg = {0};

	OPT_ARGS(opts) = {
		OPT_FLAG("raw-binary",
			'b',
			&cfg.raw_binary,
			"dump the whole log buffer in binary format"),
		OPT_END()};

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;

	int err = parse_and_open(&dev, argc, argv, cmd->help, opts);

	if (err)
		return err;

	// Get log

	struct latency_stats log = {0};

	err = nvme_get_log_simple(dev_fd(dev), LID_LATENCY_STATISTICS, sizeof(struct latency_stats),
				  &log);
	if (!err) {
		if (!cfg.raw_binary)
			latency_stats_print(&log, dev->name);
		else
			d_raw((unsigned char *)&log, sizeof(struct latency_stats));
	} else if (err > 0) {
		nvme_show_status(err);
	} else {
		nvme_show_error("%s: %s", cmd->name, nvme_strerror(errno));
	}

	return err;
}

static void high_latency_log_v1_print(struct high_latency_log *log, int size)
{
	printf("%-24s%-12s%-12s%-6s%-6s%-6s%-6s%-12s%-24s%-6s%-6s%-6s%-6s%-6s\n",
	       "Timestamp", "Latency(us)", "QID", "OpC", "Fuse", "PSDT", "CID", "NSID", "SLBA",
	       "NLB", "DType", "PInfo", "FUA", "LR");

	for (int i = 0; i < 1024; i++) {
		if (log->v1.entries[i].timestamp == 0)
			break;

		// Get the timestamp

		time_t timestamp_ms    = log->v1.entries[i].timestamp;
		time_t timestamp_s     = timestamp_ms / 1000;
		int    time_ms         = timestamp_ms % 1000;
		char   str_time_s[20]  = {0};
		char   str_time_ms[32] = {0};

		strftime(str_time_s, sizeof(str_time_s), "%Y-%m-%d %H:%M:%S",
			 localtime(&timestamp_s));
		snprintf(str_time_ms, sizeof(str_time_ms), "%s.%03d", str_time_s, time_ms);
		printf("%-24s", str_time_ms);

		//
		printf("%-12" PRIu32, log->v1.entries[i].latency);
		printf("%-12" PRIu32, log->v1.entries[i].qid);
		printf("%#-6" PRIx32, log->v1.entries[i].opcode);
		printf("%-6" PRIu32, log->v1.entries[i].fuse);
		printf("%-6" PRIu32, log->v1.entries[i].psdt);
		printf("%-6" PRIu32, log->v1.entries[i].cid);
		printf("%-12" PRIu32, log->v1.entries[i].nsid);
		printf("%-24" PRIu64, log->v1.entries[i].slba);
		printf("%-6" PRIu32, log->v1.entries[i].nlb);
		printf("%-6" PRIu32, log->v1.entries[i].dtype);
		printf("%-6" PRIu32, log->v1.entries[i].pinfo);
		printf("%-6" PRIu32, log->v1.entries[i].fua);
		printf("%-6" PRIu32, log->v1.entries[i].lr);
		printf("\n");
	}
}

static void high_latency_log_print(struct high_latency_log *log, const char *devname)
{
	uint32_t version = *(uint32_t *)&log->raw[0];

	printf("Version: %u\n", version);
	printf("\n");
	printf("High Latency Log for NVMe device: %s\n", devname);
	printf("\n");

	switch (version) {
	case 1:
		high_latency_log_v1_print(log, sizeof(struct high_latency_log));
		break;

	default:
		fprintf(stderr, "Version %u: Not supported yet\n", version);
		break;
	}
}

static int mb_get_high_latency_log(int argc, char **argv, struct command *cmd,
				   struct plugin *plugin)
{
	// Get the configuration

	struct config {
		bool raw_binary;
	};

	struct config cfg = {0};

	OPT_ARGS(opts) = {
		OPT_FLAG("raw-binary",
			'b',
			&cfg.raw_binary,
			"dump the whole log buffer in binary format"),
		OPT_END()};

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;

	int err = parse_and_open(&dev, argc, argv, cmd->help, opts);

	if (err)
		return err;

	// Get log

	struct high_latency_log log = {0};

	err = nvme_get_log_simple(dev_fd(dev), LID_HIGH_LATENCY_LOG,
				  sizeof(struct high_latency_log), &log);
	if (!err) {
		if (!cfg.raw_binary)
			high_latency_log_print(&log, dev->name);
		else
			d_raw((unsigned char *)&log, sizeof(struct high_latency_log));
	} else if (err > 0) {
		nvme_show_status(err);
	} else {
		nvme_show_error("%s: %s", cmd->name, nvme_strerror(errno));
	}

	return err;
}

static void performance_stats_v1_print(struct performance_stats *log, int duration)
{
	for (int i = 0; i < duration; i++) {
		// Print timestamp

		time_t timestamp_ms = int48_to_long(log->v1.timestamps[i].timestamp);
		time_t timestamp_s  = timestamp_ms / 1000;
		int    time_ms      = timestamp_ms % 1000;
		char   time_s[32]   = {0};

		strftime(time_s, sizeof(time_s), "%Y-%m-%d %H:%M:%S", localtime(&timestamp_s));
		printf("Timestamp %2d: %s.%03d\n", i + 1, time_s, time_ms);

		// Print entry title

		printf("%-8s%-14s%-21s%-22s%-22s%-15s%-22s%-23s%-23s\n", "Entry", "Read-IOs(K)",
		       "Read-Bandwidth(MiB)", "Avg-Read-Latency(us)", "Max-Read-Latency(us)",
		       "Write-IOs(K)", "Write-Bandwidth(MiB)", "Avg-Write-Latency(us)",
		       "Max-Write-Latency(us)");

		// Print all entries content

		struct performance_stats_entry entry = {0};

		for (int j = 0; j < 3600; j++) {
			entry.read_iops         =
				log->v1.timestamps[i].entries[j].read_iops;
			entry.read_bandwidth    =
				log->v1.timestamps[i].entries[j].read_bandwidth;
			entry.read_latency      =
				log->v1.timestamps[i].entries[j].read_latency;
			entry.read_latency_max  =
				log->v1.timestamps[i].entries[j].read_latency_max;
			entry.write_iops        =
				log->v1.timestamps[i].entries[j].write_iops;
			entry.write_bandwidth   =
				log->v1.timestamps[i].entries[j].write_bandwidth;
			entry.write_latency     =
				log->v1.timestamps[i].entries[j].write_latency;
			entry.write_latency_max =
				log->v1.timestamps[i].entries[j].write_latency_max;

			if (entry.read_iops == 0 && entry.write_iops == 0)
				continue;

			printf("%-8u%-14u%-21u%-22u%-22u%-15u%-22u%-23u%-23u\n",
			       j + 1,
			       entry.read_iops,
			       entry.read_bandwidth,
			       entry.read_iops == 0 ?
					0 : entry.read_latency / (1000 * entry.read_iops),
			       entry.read_latency_max,
			       entry.write_iops,
			       entry.write_bandwidth,
			       entry.write_iops == 0 ?
					0 : entry.write_latency / (1000 * entry.write_iops),
			       entry.write_latency_max);
			usleep(100);
		}
		printf("\n");
	}
}

static void performance_stats_v2_print(struct performance_stats *log, int duration)
{
	for (int i = 0; i < duration; i++) {
		// Print timestamp

		time_t timestamp_ms = int48_to_long(log->v2.timestamps[i].timestamp);
		time_t timestamp_s  = timestamp_ms / 1000;
		int    time_ms      = timestamp_ms % 1000;
		char   time_s[32]   = {0};

		strftime(time_s, sizeof(time_s), "%Y-%m-%d %H:%M:%S", localtime(&timestamp_s));
		printf("Timestamp %2d: %s.%03d\n", i + 1, time_s, time_ms);

		// Print entry title

		printf("%-8s%-23s%-23s%-23s%-23s%-23s%-23s%-23s%-23s\n",
		       "Entry",
		       "Read-IOs(IOPS)", "Read-Bandwidth(KiB)",
		       "Avg-Read-Latency(us)", "Max-Read-Latency(us)",
		       "Write-IOs(IOPS)", "Write-Bandwidth(KiB)",
		       "Avg-Write-Latency(us)", "Max-Write-Latency(us)");

		// Print all entries content
		for (int j = 0; j < 3600; j++) {
			uint32_t read_iops =
				log->v2.timestamps[i].entries[j].read_iops;
			uint32_t read_bandwidth            =
				log->v2.timestamps[i].entries[j].read_bandwidth;
			uint32_t read_latency_avg          =
				log->v2.timestamps[i].entries[j].read_latency_avg;
			uint32_t read_latency_max          =
				log->v2.timestamps[i].entries[j].read_latency_max;
			uint32_t scale_of_read_iops        =
				log->v2.timestamps[i].entries[j].scale_of_read_iops;
			uint32_t scale_of_read_bandwidth   =
				log->v2.timestamps[i].entries[j].scale_of_read_bandwidth;
			uint32_t scale_of_read_latency_avg =
				log->v2.timestamps[i].entries[j].scale_of_read_latency_avg;
			uint32_t scale_of_read_latency_max =
				log->v2.timestamps[i].entries[j].scale_of_read_latency_max;

			uint32_t write_iops                 =
				log->v2.timestamps[i].entries[j].write_iops;
			uint32_t write_bandwidth            =
				log->v2.timestamps[i].entries[j].write_bandwidth;
			uint32_t write_latency_avg          =
				log->v2.timestamps[i].entries[j].write_latency_avg;
			uint32_t write_latency_max          =
				log->v2.timestamps[i].entries[j].write_latency_max;
			uint32_t scale_of_write_iops        =
				log->v2.timestamps[i].entries[j].scale_of_write_iops;
			uint32_t scale_of_write_bandwidth   =
				log->v2.timestamps[i].entries[j].scale_of_write_bandwidth;
			uint32_t scale_of_write_latency_avg =
				log->v2.timestamps[i].entries[j].scale_of_write_latency_avg;
			uint32_t scale_of_write_latency_max =
				log->v2.timestamps[i].entries[j].scale_of_write_latency_max;

			if (read_iops == 0 && write_iops == 0)
				continue;

			while (scale_of_read_iops < 4 && scale_of_read_iops) {
				read_iops *= 10;
				scale_of_read_iops--;
			}
			while (scale_of_read_bandwidth < 3 && scale_of_read_bandwidth) {
				read_bandwidth *= 1024;
				scale_of_read_bandwidth--;
			}
			while (scale_of_read_latency_avg < 3 && scale_of_read_latency_avg) {
				read_latency_avg *= 1000;
				scale_of_read_latency_avg--;
			}
			while (scale_of_read_latency_max < 3 && scale_of_read_latency_max) {
				read_latency_max *= 1000;
				scale_of_read_latency_max--;
			}

			while (scale_of_write_iops < 4 && scale_of_write_iops) {
				write_iops *= 10;
				scale_of_write_iops--;
			}
			while (scale_of_write_bandwidth < 3 && scale_of_write_bandwidth) {
				write_bandwidth *= 1024;
				scale_of_write_bandwidth--;
			}
			while (scale_of_write_latency_avg < 3 && scale_of_write_latency_avg) {
				write_latency_avg *= 1000;
				scale_of_write_latency_avg--;
			}
			while (scale_of_write_latency_max < 3 && scale_of_write_latency_max) {
				write_latency_max *= 1000;
				scale_of_write_latency_max--;
			}

			printf("%-8u%-23u%-23u%-23u%-23u%-23u%-23u%-23u%-23u\n",
			       j + 1,
			       read_iops,
			       read_bandwidth,
			       read_latency_avg,
			       read_latency_max,
			       write_iops,
			       write_bandwidth,
			       write_latency_avg,
			       write_latency_max);
			usleep(100);
		}
		printf("\n");
	}
}

static void performance_stats_print(struct performance_stats *log, const char *devname,
				    int duration)
{
	uint8_t version = *(uint8_t *)&log->raw[0];

	printf("Version: %u\n", version);
	printf("\n");
	printf("Performance Stat log for NVMe device: %s\n", devname);
	printf("\n");

	switch (version) {
	case 1:
		performance_stats_v1_print(log, duration);
		break;
	case 2:
		performance_stats_v2_print(log, duration);
		break;
	default:
		fprintf(stderr, "Version %u: Not supported yet\n", version);
		break;
	}
}

static int mb_get_performance_stats(int argc, char **argv, struct command *cmd,
				    struct plugin *plugin)
{
	// Get the configuration

	struct config {
		int  duration;
		bool raw_binary;
	};

	struct config cfg = {.duration = 1, .raw_binary = false};

	OPT_ARGS(opts) = {
		OPT_UINT("duration",
			'd',
			&cfg.duration,
			"[1-24] hours: duration of the log to be printed, default is 1 hour"),
		OPT_FLAG("raw-binary",
			'b',
			&cfg.raw_binary,
			"dump the whole log buffer in binary format"),
		OPT_END()};

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;

	int err = parse_and_open(&dev, argc, argv, cmd->help, opts);

	if (err)
		return err;

	// Check parameters
	if (cfg.duration < 1 || cfg.duration > 24) {
		fprintf(stderr, "duration must be between 1 and 24.\n");
		exit(1);
	}

	// Get log

	struct performance_stats log = {0};

	int log_size = 4 + cfg.duration * sizeof(struct performance_stats_timestamp);
	// Get one more timestamp if duration is odd number to avoid non-dw alignment issues
	int xfer_size = (cfg.duration % 2) > 0 ?
		(4 + (cfg.duration + 1) * sizeof(struct performance_stats_timestamp)) : log_size;

	err = nvme_get_log_simple(dev_fd(dev), LID_PERFORMANCE_STATISTICS, xfer_size, &log);
	if (!err) {
		if (!cfg.raw_binary)
			performance_stats_print(&log, dev->name, cfg.duration);
		else
			d_raw((unsigned char *)&log, log_size);
	} else if (err > 0) {
		nvme_show_status(err);
	} else {
		nvme_show_error("%s: %s", cmd->name, nvme_strerror(errno));
	}

	return err;
}
