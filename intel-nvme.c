#include <stdio.h>

#include "nvme.h"
#include "nvme-print.h"
#include "nvme-ioctl.h"
#include "plugin.h"

#include "argconfig.h"
#include "suffix.h"

#define CREATE_CMD
#include "intel-nvme.h"

static struct plugin intel_nvme = {
	.name = "intel",
	.desc = "Intel vendor specific extensions",
	.next = NULL,
	.commands = commands,
};

static void init() __attribute__((constructor));
static void init()
{
	register_extension(&intel_nvme);
}

static void intel_id_ctrl(__u8 *vs)
{
	char bl[9];
        char health[21];

	memcpy(bl, &vs[28], sizeof(bl));
	memcpy(health, &vs[4], sizeof(health));

        bl[sizeof(bl) - 1] = '\0';
        health[sizeof(health) - 1] = '\0';

	printf("ss      : %d\n", vs[3]);
	printf("health  : %s\n", health[0] ? health : "healthy");
	printf("bl      : %s\n", bl);
}

static int id_ctrl(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	return __id_ctrl(argc, argv, cmd, plugin, intel_id_ctrl);
}

static int get_additional_smart_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	struct nvme_additional_smart_log smart_log;
	int err, fd;
	char *desc = "Get Intel vendor specific additional smart log (optionally, "\
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

	err = nvme_intel_smart_log(fd, cfg.namespace_id, &smart_log);
	if (!err) {
		if (!cfg.raw_binary)
			show_intel_smart_log(&smart_log, cfg.namespace_id, devicename);
		else
			d_raw((unsigned char *)&smart_log, sizeof(smart_log));
	}
	else if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x)\n",
					nvme_status_to_string(err), err);
	return err;
}

static int get_market_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	char log[512];
	int err, fd;

	char *desc = "Get Intel Marketing Name log and show it.";
	const char *raw = "dump output in binary format";
	struct config {
		int  raw_binary;
	};

	struct config cfg = {
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"raw-binary", 'b', "", CFG_NONE, &cfg.raw_binary, no_argument, raw},
		{0}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));

	err = nvme_get_log(fd, 0xffffffff, 0xdd, sizeof(log), log);
	if (!err) {
		if (!cfg.raw_binary)
			printf("Intel Marketing Name Log:\n%s\n", log);
		else
			d_raw((unsigned char *)&log, sizeof(log));
	} else if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x)\n",
					nvme_status_to_string(err), err);
	return err;
}


struct intel_temp_stats {
	__u64	curr;
	__u64	last_overtemp;
	__u64	life_overtemp;
	__u64	highest_temp;
	__u64	lowest_temp;
	__u8	rsvd[40];
	__u64	max_operating_temp;
	__u64	min_operating_temp;
	__u64	est_offset;
};

static void show_temp_stats(struct intel_temp_stats *stats)
{
	printf("  Intel Temperature Statistics\n");
	printf("--------------------------------\n");
	printf("Current temperature         : %llu\n", stats->curr);
	printf("Last critical overtemp flag : %llu\n", stats->last_overtemp);
	printf("Life critical overtemp flag : %llu\n", stats->life_overtemp);
	printf("Highest temperature         : %llu\n", stats->highest_temp);
	printf("Lowest temperature          : %llu\n", stats->lowest_temp);
	printf("Max operating temperature   : %llu\n", stats->max_operating_temp);
	printf("Min operating temperature   : %llu\n", stats->min_operating_temp);
	printf("Estimated offset            : %llu\n", stats->est_offset);
}

static int get_temp_stats_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	struct intel_temp_stats stats;
	int err, fd;

	char *desc = "Get Intel Marketing Name log and show it.";
	const char *raw = "dump output in binary format";
	struct config {
		int  raw_binary;
	};

	struct config cfg = {
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"raw-binary", 'b', "", CFG_NONE, &cfg.raw_binary, no_argument, raw},
		{0}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));

	err = nvme_get_log(fd, 0xffffffff, 0xc5, sizeof(stats), &stats);
	if (!err) {
		if (!cfg.raw_binary)
			show_temp_stats(&stats);
		else
			d_raw((unsigned char *)&stats, sizeof(stats));
	} else if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x)\n",
					nvme_status_to_string(err), err);
	return err;
}

struct intel_lat_stats {
	__u16	maj;
	__u16	min;
	__u32	bucket_1[32];
	__u32	bucket_2[31];
	__u32	bucket_3[31];
};

static void show_lat_stats(struct intel_lat_stats *stats, int write)
{
	int i;

	printf(" Intel IO %s Command Latency Statistics\n", write ? "Write" : "Read");
	printf("-------------------------------------\n");
	printf("Major Revision : %u\n", stats->maj);
	printf("Minor Revision : %u\n", stats->min);

	printf("\nGroup 1: Range is 0-1ms, step is 32us\n");
	for (i = 0; i < 32; i++)
		printf("Bucket %2d: %u\n", i, stats->bucket_1[i]);

	printf("\nGroup 2: Range is 1-32ms, step is 1ms\n");
	for (i = 0; i < 31; i++)
		printf("Bucket %2d: %u\n", i, stats->bucket_1[i]);

	printf("\nGroup 3: Range is 32-1s, step is 32ms:\n");
	for (i = 0; i < 31; i++)
		printf("Bucket %2d: %u\n", i, stats->bucket_1[i]);
}

static int get_lat_stats_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	struct intel_lat_stats stats;
	int err, fd;

	char *desc = "Get Intel Latency Statistics log and show it.";
	const char *raw = "dump output in binary format";
	const char *write = "Get write statistics (read default)";
	struct config {
		int  raw_binary;
		int  write;
	};

	struct config cfg = {
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"write",      'w', "", CFG_NONE, &cfg.write,      no_argument, write},
		{"raw-binary", 'b', "", CFG_NONE, &cfg.raw_binary, no_argument, raw},
		{0}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));

	err = nvme_get_log(fd, 0xffffffff, write ? 0xc2 : 0xc1, sizeof(stats), &stats);
	if (!err) {
		if (!cfg.raw_binary)
			show_lat_stats(&stats, cfg.write);
		else
			d_raw((unsigned char *)&stats, sizeof(stats));
	} else if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x)\n",
					nvme_status_to_string(err), err);
	return err;
}
