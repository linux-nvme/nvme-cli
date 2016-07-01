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
	NR_SMART_ITEMS,
};

#pragma pack(push, 1)
struct nvme_memblaze_smart_log_item {
	__u8 id[3];
	__u8 nmval[2];
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

	printf("Additional Smart Log for NVME device:%s namespace-id:%x\n", devname, nsid);

	printf("Total write in GB since last factory reset			: %lu\n",
		int48_to_long(smart->items[TOTAL_WRITE].rawval));
	printf("Total read in GB since last factory reset			: %lu\n",
		int48_to_long(smart->items[TOTAL_READ].rawval));

	printf("Thermal throttling status[1:HTP in progress]			: %u\n",
		smart->items[THERMAL_THROTTLE].thermal_throttle.on);
	printf("Total thermal throttling minutes since power on			: %u\n",
		smart->items[THERMAL_THROTTLE].thermal_throttle.count);

	printf("Maximum temperature in Kelvin since last factory reset		: %u\n",
		le16toh(smart->items[TEMPT_SINCE_RESET].temperature.max));
	printf("Minimum temperature in Kelvin since last factory reset		: %u\n",
		le16toh(smart->items[TEMPT_SINCE_RESET].temperature.min));
	if (compare_fw_version(fw_ver, "0.09.0300") != 0) {
		printf("Maximum temperature in Kelvin since power on			: %u\n",
			le16toh(smart->items[TEMPT_SINCE_BOOTUP].temperature_p.max));
		printf("Minimum temperature in Kelvin since power on			: %u\n",
			le16toh(smart->items[TEMPT_SINCE_BOOTUP].temperature_p.min));
	}
	printf("Current temperature in Kelvin					: %u\n",
		le16toh(smart->items[TEMPT_SINCE_RESET].temperature.curr));

	printf("Maximum power in watt since power on				: %u\n",
		le16toh(smart->items[POWER_CONSUMPTION].power.max));
	printf("Minimum power in watt since power on				: %u\n",
		le16toh(smart->items[POWER_CONSUMPTION].power.min));
	printf("Current power in watt						: %u\n",
		le16toh(smart->items[POWER_CONSUMPTION].power.curr));

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
		{0}
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
