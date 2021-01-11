#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "linux/nvme_ioctl.h"

#include "nvme.h"
#include "nvme-print.h"
#include "nvme-ioctl.h"
#include "plugin.h"

#include "argconfig.h"
#include "suffix.h"

#define CREATE_CMD
#include "memblaze-nvme.h"
#include "memblaze-utils.h"

enum {
    MB_FEAT_POWER_MGMT = 0xc6,
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

/**********************************************************
 * input: firmware version string
 * output:
 *     1: new intel format
 *     0: old memblaze format
 * *******************************************************/
#define MEMBLAZE_FORMAT         (0)
#define INTEL_FORMAT            (1)

// 2.83 = raisin
#define IS_RAISIN(str)          (!strcmp(str, "2.83"))
// 2.13 = papaya
#define IS_PAPAYA(str)          (!strcmp(str, "2.13"))
#define STR_VER_SIZE            5

int getlogpage_format_type(char *fw_ver)
{
    char fw_ver_local[STR_VER_SIZE];
    strncpy(fw_ver_local, fw_ver, STR_VER_SIZE);
    *(fw_ver_local + STR_VER_SIZE - 1) = '\0';
    if ( IS_RAISIN(fw_ver_local) )
    {
        return INTEL_FORMAT;
    }
    else
    {
        return MEMBLAZE_FORMAT;
    }
}

static __u32 item_id_2_u32(struct nvme_memblaze_smart_log_item *item)
{
    __le32  __id = 0;
    memcpy(&__id, item->id, 3);
    return le32_to_cpu(__id);
}

static __u64 raw_2_u64(const __u8 *buf, size_t len)
{
    __le64  val = 0;
    memcpy(&val, buf, len);
    return le64_to_cpu(val);
}

#define STRN2_01    "Additional Smart Log for NVME device"
#define STRN2_02    "namespace-id"
#define STRN1_01    "key"
#define STRN1_02    "normalized"
#define STRN1_03    "raw"
#define STR00_01    "program_fail_count"
#define STR01_01    "erase_fail_count"
#define STR02_01    "wear_leveling"
#define STR02_03    "min: "
#define STR02_04    ", max: "
#define STR02_05    ", avg: "
#define STR03_01    "end_to_end_error_detection_count"
#define STR04_01    "crc_error_count"
#define STR05_01    "timed_workload_media_wear"
#define STR06_01    "timed_workload_host_reads"
#define STR07_01    "timed_workload_timer"
#define STR07_02    " min"
#define STR08_01    "thermal_throttle_status"
#define STR08_02    ", cnt: "
#define STR09_01    "retry_buffer_overflow_count"
#define STR10_01    "pll_lock_loss_count"
#define STR11_01    "nand_bytes_written"
#define STR11_03    "sectors: "
#define STR12_01    "host_bytes_written"
#define STR12_03    "sectors: "
#define STR13_01    "system_area_life_left"
#define STR14_01    "total_read"
#define STR15_01    "tempt_since_born"
#define STR15_03    "max: "
#define STR15_04    ", min: "
#define STR15_05    ", curr: "
#define STR16_01    "power_consumption"
#define STR16_03    "max: "
#define STR16_04    ", min: "
#define STR16_05    ", curr: "
#define STR17_01    "tempt_since_bootup"
#define STR17_03    "max: "
#define STR17_04    ", min: "
#define STR17_05    ", curr: "
#define STR18_01    "power_loss_protection"
#define STR19_01    "read_fail"
#define STR20_01    "thermal_throttle_time"
#define STR21_01    "flash_media_error"

static void get_memblaze_new_smart_info(struct nvme_p4_smart_log *smart, int index, u8 *nm_val, u8 *raw_val)
{
    memcpy(nm_val, smart->itemArr[index].nmVal, NM_SIZE);
    memcpy(raw_val, smart->itemArr[index].rawVal, RAW_SIZE);
}

static void show_memblaze_smart_log_new(struct nvme_memblaze_smart_log *s,
    unsigned int nsid, const char *devname)
{
    struct nvme_p4_smart_log *smart = (struct nvme_p4_smart_log *)s;
    u8 *nm = malloc(NM_SIZE * sizeof(u8));
    u8 *raw = malloc(RAW_SIZE * sizeof(u8));

    /* Table Title */
    printf("%s:%s %s:%x\n", STRN2_01, devname, STRN2_02, nsid);
    /* Clumn Name*/
    printf("%-34s%-11s%s\n", STRN1_01, STRN1_02, STRN1_03);
    /* 00 RAISIN_SI_VD_PROGRAM_FAIL */
    get_memblaze_new_smart_info(smart, RAISIN_SI_VD_PROGRAM_FAIL, nm, raw);
    printf("%-32s: %3d%%       %"PRIu64"\n", STR00_01, *nm, int48_to_long(raw));
    /* 01 RAISIN_SI_VD_ERASE_FAIL */
    get_memblaze_new_smart_info(smart, RAISIN_SI_VD_ERASE_FAIL, nm, raw);
    printf("%-32s: %3d%%       %"PRIu64"\n", STR01_01, *nm, int48_to_long(raw));
    /* 02 RAISIN_SI_VD_WEARLEVELING_COUNT */
    get_memblaze_new_smart_info(smart, RAISIN_SI_VD_WEARLEVELING_COUNT, nm, raw);
    printf("%-31s : %3d%%       %s%u%s%u%s%u\n", STR02_01, *nm,
        STR02_03, *raw, STR02_04, *(raw+2), STR02_05, *(raw+4));
    /* 03 RAISIN_SI_VD_E2E_DECTECTION_COUNT */
    get_memblaze_new_smart_info(smart, RAISIN_SI_VD_E2E_DECTECTION_COUNT, nm, raw);
    printf("%-31s: %3d%%       %"PRIu64"\n", STR03_01, *nm, int48_to_long(raw));
    /* 04 RAISIN_SI_VD_PCIE_CRC_ERR_COUNT */
    get_memblaze_new_smart_info(smart, RAISIN_SI_VD_PCIE_CRC_ERR_COUNT, nm, raw);
    printf("%-32s: %3d%%       %"PRIu64"\n", STR04_01, *nm, int48_to_long(raw));
    /* 05 RAISIN_SI_VD_TIMED_WORKLOAD_MEDIA_WEAR */
    get_memblaze_new_smart_info(smart, RAISIN_SI_VD_TIMED_WORKLOAD_MEDIA_WEAR, nm, raw);
    printf("%-32s: %3d%%       %.3f%%\n", STR05_01, *nm, ((float)int48_to_long(raw))/1000);
    /* 06 RAISIN_SI_VD_TIMED_WORKLOAD_HOST_READ */
    get_memblaze_new_smart_info(smart, RAISIN_SI_VD_TIMED_WORKLOAD_HOST_READ, nm, raw);
    printf("%-32s: %3d%%       %"PRIu64"%%\n", STR06_01, *nm, int48_to_long(raw));
    /* 07 RAISIN_SI_VD_TIMED_WORKLOAD_TIMER */
    get_memblaze_new_smart_info(smart, RAISIN_SI_VD_TIMED_WORKLOAD_TIMER, nm, raw);
    printf("%-32s: %3d%%       %"PRIu64"%s\n", STR07_01, *nm, int48_to_long(raw), STR07_02);
    /* 08 RAISIN_SI_VD_THERMAL_THROTTLE_STATUS */
    get_memblaze_new_smart_info(smart, RAISIN_SI_VD_THERMAL_THROTTLE_STATUS, nm, raw);
    printf("%-32s: %3d%%       %"PRIu64"%%%s%"PRIu64"\n", STR08_01, *nm,
        int48_to_long(raw), STR08_02, int48_to_long(raw+1));
    /* 09 RAISIN_SI_VD_RETRY_BUFF_OVERFLOW_COUNT */
    get_memblaze_new_smart_info(smart, RAISIN_SI_VD_RETRY_BUFF_OVERFLOW_COUNT, nm, raw);
    printf("%-32s: %3d%%       %"PRIu64"\n", STR09_01, *nm, int48_to_long(raw));
    /* 10 RAISIN_SI_VD_PLL_LOCK_LOSS_COUNT */
    get_memblaze_new_smart_info(smart, RAISIN_SI_VD_PLL_LOCK_LOSS_COUNT, nm, raw);
    printf("%-32s: %3d%%       %"PRIu64"\n", STR10_01, *nm, int48_to_long(raw));
    /* 11 RAISIN_SI_VD_TOTAL_WRITE */
    get_memblaze_new_smart_info(smart, RAISIN_SI_VD_TOTAL_WRITE, nm, raw);
    printf("%-32s: %3d%%       %s%"PRIu64"\n", STR11_01, *nm, STR11_03, int48_to_long(raw));
    /* 12 RAISIN_SI_VD_HOST_WRITE */
    get_memblaze_new_smart_info(smart, RAISIN_SI_VD_HOST_WRITE, nm, raw);
    printf("%-32s: %3d%%       %s%"PRIu64"\n", STR12_01, *nm, STR12_03, int48_to_long(raw));
    /* 13 RAISIN_SI_VD_SYSTEM_AREA_LIFE_LEFT */
    get_memblaze_new_smart_info(smart, RAISIN_SI_VD_SYSTEM_AREA_LIFE_LEFT, nm, raw);
    printf("%-32s: %3d%%       %"PRIu64"\n", STR13_01, *nm, int48_to_long(raw));
    /* 14 RAISIN_SI_VD_TOTAL_READ */
    get_memblaze_new_smart_info(smart, RAISIN_SI_VD_TOTAL_READ, nm, raw);
    printf("%-32s: %3d%%       %"PRIu64"\n", STR14_01, *nm, int48_to_long(raw));
    /* 15 RAISIN_SI_VD_TEMPT_SINCE_BORN */
    get_memblaze_new_smart_info(smart, RAISIN_SI_VD_TEMPT_SINCE_BORN, nm, raw);
    printf("%-32s: %3d%%       %s%u%s%u%s%u\n", STR15_01,  *nm,
        STR15_03, *raw, STR15_04, *(raw+2), STR15_05, *(raw+4));
    /* 16 RAISIN_SI_VD_POWER_CONSUMPTION */
    get_memblaze_new_smart_info(smart, RAISIN_SI_VD_POWER_CONSUMPTION, nm, raw);
    printf("%-32s: %3d%%       %s%u%s%u%s%u\n", STR16_01,  *nm,
        STR16_03, *raw, STR16_04, *(raw+2), STR16_05, *(raw+4));
    /* 17 RAISIN_SI_VD_TEMPT_SINCE_BOOTUP */
    get_memblaze_new_smart_info(smart, RAISIN_SI_VD_TEMPT_SINCE_BOOTUP, nm, raw);
    printf("%-32s: %3d%%       %s%u%s%u%s%u\n", STR17_01,  *nm, STR17_03, *raw,
        STR17_04, *(raw+2), STR17_05, *(raw+4));
    /* 18 RAISIN_SI_VD_POWER_LOSS_PROTECTION */
    get_memblaze_new_smart_info(smart, RAISIN_SI_VD_POWER_LOSS_PROTECTION, nm, raw);
    printf("%-32s: %3d%%       %"PRIu64"\n", STR18_01, *nm, int48_to_long(raw));
    /* 19 RAISIN_SI_VD_READ_FAIL */
    get_memblaze_new_smart_info(smart, RAISIN_SI_VD_READ_FAIL, nm, raw);
    printf("%-32s: %3d%%       %"PRIu64"\n", STR19_01, *nm, int48_to_long(raw));
    /* 20 RAISIN_SI_VD_THERMAL_THROTTLE_TIME */
    get_memblaze_new_smart_info(smart, RAISIN_SI_VD_THERMAL_THROTTLE_TIME, nm, raw);
    printf("%-32s: %3d%%       %"PRIu64"\n", STR20_01, *nm, int48_to_long(raw));
    /* 21 RAISIN_SI_VD_FLASH_MEDIA_ERROR */
    get_memblaze_new_smart_info(smart, RAISIN_SI_VD_FLASH_MEDIA_ERROR, nm, raw);
    printf("%-32s: %3d%%       %"PRIu64"\n", STR21_01, *nm, int48_to_long(raw));

    free(nm);
    free(raw);
}

static void show_memblaze_smart_log_old(struct nvme_memblaze_smart_log *smart,
    unsigned int nsid, const char *devname, const char *fw_ver)
{
    char fw_ver_local[STR_VER_SIZE];
    struct nvme_memblaze_smart_log_item *item;

    strncpy(fw_ver_local, fw_ver, STR_VER_SIZE);
    *(fw_ver_local + STR_VER_SIZE - 1) = '\0';

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

    item = &smart->items[CORRECT_PCIE_PORT0];
    if (item_id_2_u32(item) == 0xED)
        printf("PCIE Correctable Error Count of Port0    			: %llu\n",
            (unsigned long long)raw_2_u64(item->rawval, sizeof(item->rawval)));

    item = &smart->items[CORRECT_PCIE_PORT1];
    if (item_id_2_u32(item) == 0xEE)
        printf("PCIE Correctable Error Count of Port1 	        		: %llu\n",
            (unsigned long long)raw_2_u64(item->rawval, sizeof(item->rawval)));

    item = &smart->items[REBUILD_FAIL];
    if (item_id_2_u32(item) == 0xEF)
        printf("End-to-End Error Detection Count 	        		: %llu\n",
            (unsigned long long)raw_2_u64(item->rawval, sizeof(item->rawval)));

    item = &smart->items[ERASE_FAIL];
    if (item_id_2_u32(item) == 0xF0)
        printf("Erase Fail Count 		                        	: %llu\n",
            (unsigned long long)raw_2_u64(item->rawval, sizeof(item->rawval)));

    item = &smart->items[PROGRAM_FAIL];
    if (item_id_2_u32(item) == 0xF1)
        printf("Program Fail Count 		                        	: %llu\n",
            (unsigned long long)raw_2_u64(item->rawval, sizeof(item->rawval)));

    item = &smart->items[READ_FAIL];
    if (item_id_2_u32(item) == 0xF2)
        printf("Read Fail Count	                                 		: %llu\n",
            (unsigned long long)raw_2_u64(item->rawval, sizeof(item->rawval)));

     if ( IS_PAPAYA(fw_ver_local) ) {
        struct nvme_p4_smart_log *s = (struct nvme_p4_smart_log *)smart;
        u8 *nm = malloc(NM_SIZE * sizeof(u8));
        u8 *raw = malloc(RAW_SIZE * sizeof(u8));

        /* 00 RAISIN_SI_VD_PROGRAM_FAIL */
        get_memblaze_new_smart_info(s, PROGRAM_FAIL, nm, raw);
        printf("%-32s                                : %3d%%       %"PRIu64"\n",
			STR00_01, *nm, int48_to_long(raw));
        /* 01 RAISIN_SI_VD_ERASE_FAIL */
        get_memblaze_new_smart_info(s, ERASE_FAIL, nm, raw);
        printf("%-32s                                : %3d%%       %"PRIu64"\n",
			STR01_01, *nm, int48_to_long(raw));
        /* 02 RAISIN_SI_VD_WEARLEVELING_COUNT */
        get_memblaze_new_smart_info(s, WEARLEVELING_COUNT, nm, raw);
        printf("%-31s                                 : %3d%%       %s%u%s%u%s%u\n",
			STR02_01, *nm, STR02_03, *raw, STR02_04, *(raw+2), STR02_05, *(raw+4));
        /* 11 RAISIN_SI_VD_TOTAL_WRITE */
        get_memblaze_new_smart_info(s, TOTAL_WRITE, nm, raw);
        printf("%-32s                                : %3d%%       %"PRIu64"\n",
			STR11_01, *nm, 32*int48_to_long(raw));
        /* 12 RAISIN_SI_VD_HOST_WRITE */
        get_memblaze_new_smart_info(s, HOST_WRITE, nm, raw);
        printf("%-32s                                : %3d%%       %"PRIu64"\n",
			STR12_01, *nm, 32*int48_to_long(raw));

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

    if (getlogpage_format_type(fw_ver)) // Intel Format & new format
    {
        show_memblaze_smart_log_new(smart, nsid, devname);
    }
    else  // Memblaze Format & old format
    {
        show_memblaze_smart_log_old(smart, nsid, devname, fw_ver);
    }
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
		.namespace_id = NVME_NSID_ALL,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id,  namespace),
		OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,    raw),
		OPT_END()
	};

	fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		return fd;

	err = nvme_get_log(fd, cfg.namespace_id, 0xca, false,
			   NVME_NO_LOG_LSP, sizeof(smart_log), &smart_log);
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
	const char *raw = "show feature in binary format";
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

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id",   'n', &cfg.namespace_id,   namespace_id),
		OPT_UINT("feature-id",     'f', &cfg.feature_id,     feature_id),
		OPT_BYTE("sel",            's', &cfg.sel,            sel),
		OPT_UINT("data-len",       'l', &cfg.data_len,       data_len),
		OPT_UINT("cdw11",          'c', &cfg.cdw11,          cdw11),
		OPT_FLAG("human-readable", 'H', &cfg.human_readable, human_readable),
		OPT_FLAG("raw-binary",     'b', &cfg.raw_binary,     raw),
		OPT_END()
	};

	fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		return fd;

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
				err = EINVAL;
				goto free;
			}
		}
		if (read(ffd, (void *)buf, cfg.data_len) < 0) {
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
			mb_feature_to_string(cfg.feature_id), cfg.value);
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

static int memblaze_fw_commit(int fd, int select)
{
	struct nvme_admin_cmd cmd = {
		.opcode		= nvme_admin_activate_fw,
		.cdw10		= 8,
		.cdw12      = select,
	};

	return nvme_submit_admin_passthru(fd, &cmd);
}

static int memblaze_selective_download(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc =
		"This performs a selective firmware download, which allows the user to "
		"select which firmware binary to update for 9200 devices. This requires a power cycle once the "
		"update completes. The options available are: \n\n"
		"OOB - This updates the OOB and main firmware\n"
		"EEP - This updates the eeprom and main firmware\n"
		"ALL - This updates the eeprom, OOB, and main firmware";
	const char *fw = "firmware file (required)";
	const char *select = "FW Select (e.g., --select=OOB, EEP, ALL)";
	int xfer = 4096;
	void *fw_buf;
	int fd, selectNo,fw_fd,fw_size,err,offset = 0;
	struct stat sb;
	int i;

	struct config {
		char  *fw;
		char  *select;
	};

	struct config cfg = {
		.fw     = "",
		.select = "\0",
	};

	OPT_ARGS(opts) = {
		OPT_STRING("fw", 'f', "FILE", &cfg.fw, fw),
		OPT_STRING("select", 's', "flag", &cfg.select, select),
		OPT_END()
	};

	fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		return fd;

	if (strlen(cfg.select) != 3) {
		fprintf(stderr, "Invalid select flag\n");
		err = EINVAL;
		goto out;
	}

	for (i = 0; i < 3; i++) {
		cfg.select[i] = toupper(cfg.select[i]);
	}

	if (strncmp(cfg.select,"OOB", 3) == 0) {
		selectNo = 18;
	} else if (strncmp(cfg.select,"EEP", 3) == 0) {
		selectNo = 10;
	} else if (strncmp(cfg.select,"ALL", 3) == 0) {
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
	}

	fw_size = sb.st_size;
	if (fw_size & 0x3) {
		fprintf(stderr, "Invalid size:%d for f/w image\n", fw_size);
		err = EINVAL;
		goto out;
	}

	if (posix_memalign(&fw_buf, getpagesize(), fw_size)) {
		fprintf(stderr, "No memory for f/w size:%d\n", fw_size);
		err = ENOMEM;
		goto out;
	}

	if (read(fw_fd, fw_buf, fw_size) != ((ssize_t)(fw_size)))
		return EIO;

	while (fw_size > 0) {
		xfer = min(xfer, fw_size);

		err = nvme_fw_download(fd, offset, xfer, fw_buf);
		if (err < 0) {
			perror("fw-download");
			goto out;
		} else if (err != 0) {
			fprintf(stderr, "NVME Admin command error:%s(%x)\n",
					nvme_status_to_string(err), err);
			goto out;
		}
		fw_buf     += xfer;
		fw_size    -= xfer;
		offset += xfer;
	}

	err = memblaze_fw_commit(fd,selectNo);

	if(err == 0x10B || err == 0x20B) {
		err = 0;
		fprintf(stderr, "Update successful! Please power cycle for changes to take effect\n");
	}

out:
	return err;
}

