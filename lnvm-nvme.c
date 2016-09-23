#include <stdio.h>
#include <errno.h>

#include "nvme.h"
#include "nvme-print.h"
#include "nvme-ioctl.h"
#include "plugin.h"

#include "nvme-lightnvm.h"

#include "argconfig.h"
#include "suffix.h"

#define CREATE_CMD
#include "lnvm-nvme.h"

static int lnvm_init(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Initialize LightNVM device. A LightNVM/Open-Channel SSD"\
			   " must have a media manager associated before it can "\
			   " be exposed to the user. The default is to initialize"
			   " the general media manager on top of the device.\n\n"
			   "Example:"
			   " lnvm-init -d nvme0n1";
	const char *devname = "identifier of desired device. e.g. nvme0n1.";
	const char *mmtype = "media manager to initialize on top of device. Default: gennvm.";

	struct config
	{
		char *devname;
		char *mmtype;
	};

	struct config cfg = {
		.devname = "",
		.mmtype = "gennvm",
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"device-name",   'd', "DEVICE", CFG_STRING, &cfg.devname, required_argument, devname},
		{"mediamgr-name", 'm', "MM",     CFG_STRING, &cfg.mmtype,  required_argument, mmtype},
		{NULL}
	};

	argconfig_parse(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));

	if (!strlen(cfg.devname)) {
		fprintf(stderr, "device name missing %d\n", (int)strlen(cfg.devname));
		return -EINVAL;
	}

	return lnvm_do_init(cfg.devname, cfg.mmtype);
}

static int lnvm_list(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "List all devices registered with LightNVM.";

	const struct argconfig_commandline_options command_line_options[] = {
		{NULL}
	};

	argconfig_parse(argc, argv, desc, command_line_options, NULL, 0);

	return lnvm_do_list_devices();
}

static int lnvm_info(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Show general information and registered target types with LightNVM";

	const struct argconfig_commandline_options command_line_options[] = {
		{NULL}
	};

	argconfig_parse(argc, argv, desc, command_line_options, NULL, 0);

	return lnvm_do_info();
}

static int lnvm_id_ns(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Send an Identify Geometry command to the "\
		"given LightNVM device, returns properties of the specified"\
		"namespace in either human-readable or binary format.";
	const char *force = "Return this namespace, even if not supported";
	const char *raw_binary = "show infos in binary format";
	const char *human_readable = "show infos in readable format";
	const char *namespace_id = "identifier of desired namespace. default: 1";
	unsigned int fd, flags = 0;

	struct config {
		__u32 namespace_id;
		int   raw_binary;
		int   human_readable;
		int   force;
	};

	struct config cfg = {
		.namespace_id    = 1,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id",    'n', "NUM",  CFG_POSITIVE, &cfg.namespace_id,    required_argument, namespace_id},
		{"force",           'f', "FLAG", CFG_NONE,     &cfg.force,           no_argument,       force},
		{"raw-binary",      'b', "FLAG", CFG_NONE,     &cfg.raw_binary,      no_argument,       raw_binary},
		{"human-readable",  'H', "FLAG", CFG_NONE,     &cfg.human_readable,  no_argument,       human_readable},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));

	if (cfg.human_readable)
		flags |= HUMAN;
	else if (cfg.raw_binary)
		flags |= RAW;

	return lnvm_do_id_ns(fd, cfg.namespace_id, flags);
}


static int lnvm_create_tgt(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Instantiate a target on top of a LightNVM enabled device.";
	const char *devname = "identifier of desired device. e.g. nvme0n1.";
	const char *tgtname = "target name of the device to initialize. e.g. target0.";
	const char *tgttype = "identifier of target type. e.g. pblk.";
	const char *lun_begin = "Define begin of luns to use for target.";
	const char *lun_end = "Define set of luns to use for target.";

	struct config
	{
		char *devname;
		char *tgtname;
		char *tgttype;
		__u32 lun_begin;
		__u32 lun_end;
	};

	struct config cfg = {
		.devname = "",
		.tgtname = "",
		.tgttype = "",
		.lun_begin = 0,
		.lun_end = 0,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"device-name",   'd', "DEVICE", CFG_STRING,    &cfg.devname,   required_argument, devname},
		{"target-name",   'n', "TARGET", CFG_STRING,    &cfg.tgtname,   required_argument, tgtname},
		{"target-type",   't', "TARGETTYPE",  CFG_STRING,    &cfg.tgttype,   required_argument, tgttype},
		{"lun-begin",     'b', "NUM",    CFG_POSITIVE,  &cfg.lun_begin,      required_argument,       lun_begin},
		{"lun-end",       'e', "NUM",    CFG_POSITIVE,  &cfg.lun_end,   required_argument,       lun_end},
		{NULL}
	};

	argconfig_parse(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));

	if (!strlen(cfg.devname)) {
		fprintf(stderr, "device name missing %d\n", (int)strlen(cfg.devname));
		return -EINVAL;
	}
	if (!strlen(cfg.tgtname)) {
		fprintf(stderr, "target name missing\n");
		return -EINVAL;
	}
	if (!strlen(cfg.tgttype)) {
		fprintf(stderr, "target type missing\n");
		return -EINVAL;
	}

	return lnvm_do_create_tgt(cfg.devname, cfg.tgtname, cfg.tgttype, cfg.lun_begin, cfg.lun_end);
}

static int lnvm_remove_tgt(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Remove an initialized LightNVM target.";
	const char *tgtname = "target name of the device to initialize. e.g. target0.";

	struct config
	{
		char *tgtname;
	};

	struct config cfg = {
		.tgtname = "",
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"target-name",   'n', "TARGET", CFG_STRING,    &cfg.tgtname,   required_argument, tgtname},
		{NULL}
	};

	argconfig_parse(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));

	if (!strlen(cfg.tgtname)) {
		fprintf(stderr, "target name missing\n");
		return -EINVAL;
	}

	return lnvm_do_remove_tgt(cfg.tgtname);
}

static int lnvm_factory_init(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Factory initialize a LightNVM enabled device.";
	const char *devname = "identifier of desired device. e.g. nvme0n1.";
	const char *erase_only_marked = "only erase marked blocks. default: all blocks.";
	const char *host_marks = "remove host side blocks list. default: keep.";
	const char *bb_marks = "remove grown bad blocks list. default: keep";

	struct config
	{
		char *devname;
		int  erase_only_marked;
		int  clear_host_marks;
		int  clear_bb_marks;
	};

	struct config cfg = {
		.devname = "",
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"device-name",          'd', "DEVICE", CFG_STRING, &cfg.devname,           required_argument, devname},
		{"erase-only-marked",    'e', "",       CFG_NONE,   &cfg.erase_only_marked, no_argument,       erase_only_marked},
		{"clear-host-side-blks", 's', "",       CFG_NONE,   &cfg.clear_host_marks,  no_argument,       host_marks},
		{"clear-bb-blks",        'b', "",       CFG_NONE,   &cfg.clear_bb_marks,    no_argument,       bb_marks},
		{NULL}
	};

	argconfig_parse(argc, argv, desc, command_line_options, &cfg,
								sizeof(cfg));

	if (!strlen(cfg.devname)) {
		fprintf(stderr, "device name missing %d\n", (int)strlen(cfg.devname));
		return -EINVAL;
	}

	return lnvm_do_factory_init(cfg.devname, cfg.erase_only_marked,
				cfg.clear_host_marks, cfg.clear_bb_marks);
}

static int lnvm_get_bbtbl(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Receive bad block table from a LightNVM compatible"\
			   " device.";
	const char *namespace = "(optional) desired namespace";
	const char *ch = "channel identifier";
	const char *lun = "lun identifier (within a channel)";
	const char *raw_binary = "show infos in binary format";
	unsigned int fd, flags = 0;

	struct config
	{
		__u32 namespace_id;
		__u16 lunid;
		__u16 chid;
		int   raw_binary;
	};

	struct config cfg = {
		.namespace_id = 1,
		.lunid = 0,
		.chid = 0,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id", 'n', "NUM",  CFG_POSITIVE, &cfg.namespace_id, required_argument, namespace},
		{"channel-id",   'c', "",     CFG_SHORT,    &cfg.chid,         required_argument, ch},
		{"lun-id",       'l', "",     CFG_SHORT,    &cfg.lunid,        required_argument, lun},
		{"raw-binary",   'b', "FLAG", CFG_NONE,     &cfg.raw_binary,   no_argument,       raw_binary},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));

	if (cfg.raw_binary)
		flags |= RAW;

	return lnvm_do_get_bbtbl(fd, cfg.namespace_id, cfg.lunid, cfg.chid,
									flags);
}

static int lnvm_set_bbtbl(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Update bad block table on a LightNVM compatible"\
			   " device.";
	const char *namespace = "(optional) desired namespace";
	const char *ch = "channel identifier";
	const char *lun = "lun identifier (within a channel)";
	const char *pln = "plane identifier (within a lun)";
	const char *blk = "block identifier (within a plane)";
	const char *value = "value to update the specific block to.";
	int fd;

	struct config
	{
		__u32 namespace_id;
		__u16 lunid;
		__u16 chid;
		__u16 plnid;
		__u16 blkid;
		__u16 value;
	};

	struct config cfg = {
		.namespace_id = 1,
		.lunid = 0,
		.chid = 0,
		.plnid = 0,
		.blkid = 0,
		.value = 0,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id", 'n', "NUM",  CFG_POSITIVE, &cfg.namespace_id, required_argument, namespace},
		{"channel-id",   'c', "NUM",     CFG_SHORT,    &cfg.chid,         required_argument, ch},
		{"lun-id",       'l', "NUM",     CFG_SHORT,    &cfg.lunid,        required_argument, lun},
		{"plane-id",     'p', "NUM",     CFG_SHORT,    &cfg.plnid,        required_argument, pln},
		{"block-id",     'b', "NUM",     CFG_SHORT,    &cfg.blkid,        required_argument, blk},
		{"value",        'v', "NUM",     CFG_SHORT,    &cfg.value,        required_argument, value},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));

	printf("Updating: Ch.: %u LUN: %u Plane: %u Block: %u -> %u\n",
			cfg.chid, cfg.lunid, cfg.plnid, cfg.blkid, cfg.value);

	return lnvm_do_set_bbtbl(fd, cfg.namespace_id,
				 cfg.chid, cfg.lunid, cfg.plnid, cfg.blkid,
				 cfg.value);
}
