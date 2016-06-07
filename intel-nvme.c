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
