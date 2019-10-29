#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

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
			   " must have a media manager associated before it can"\
			   " be exposed to the user. The default is to initialize"
			   " the general media manager on top of the device.\n\n"
			   "Example:"
			   " lnvm-init -d nvme0n1";
	const char *devname = "identifier of desired device. e.g. nvme0n1.";
	const char *mmtype = "media manager to initialize on top of device. Default: gennvm.";
	int ret;

	struct config {
		char *devname;
		char *mmtype;
	};

	struct config cfg = {
		.devname = "",
		.mmtype = "gennvm",
	};

	OPT_ARGS(opts) = {
		OPT_STRING("device-name",   'd', "DEVICE", &cfg.devname, devname),
		OPT_STRING("mediamgr-name", 'm', "MM",     &cfg.mmtype,  mmtype),
		OPT_END()
	};

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret < 0)
		return ret;

	if (!strlen(cfg.devname)) {
		fprintf(stderr, "device name missing\n");
		return -EINVAL;
	}

	return lnvm_do_init(cfg.devname, cfg.mmtype);
}

static int lnvm_list(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "List all devices registered with LightNVM.";
	int ret;

	OPT_ARGS(opts) = {
		OPT_END()
	};

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret < 0)
		return ret;

	return lnvm_do_list_devices();
}

static int lnvm_info(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Show general information and registered target types with LightNVM";
	int ret;

	OPT_ARGS(opts) = {
		OPT_END()
	};

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret < 0)
		return ret;

	return lnvm_do_info();
}

static int lnvm_id_ns(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Send an Identify Geometry command to the "\
		"given LightNVM device, returns properties of the specified "\
		"namespace in either human-readable or binary format.";
	const char *raw_binary = "show infos in binary format";
	const char *human_readable = "show infos in readable format";
	const char *namespace_id = "identifier of desired namespace. default: 1";
	unsigned int flags = 0;
	int fd;

	struct config {
		__u32 namespace_id;
		int   raw_binary;
		int   human_readable;
	};

	struct config cfg = {
		.namespace_id    = 1,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id",   'n', &cfg.namespace_id,   namespace_id),
		OPT_FLAG("raw-binary",     'b', &cfg.raw_binary,     raw_binary),
		OPT_FLAG("human-readable", 'H', &cfg.human_readable, human_readable),
		OPT_END()
	};

	fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		return fd;

	if (cfg.human_readable)
		flags |= VERBOSE;
	else if (cfg.raw_binary)
		flags |= BINARY;

	return lnvm_do_id_ns(fd, cfg.namespace_id, flags);
}

static int lnvm_chunk_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Retrieve the chunk information log for the "\
		"specified given LightNVM device, returns in either "\
		"human-readable or binary format.\n"\
		"This will request Geometry first to get the "\
		"num_grp,num_pu,num_chk first to figure out the total size "\
		"of the log pages."\
		;
	const char *output_format = "Output format: normal|binary";
	const char *human_readable = "Print normal in readable format";
	int err, fmt, fd;
	struct nvme_nvm_id20 geo;
	struct nvme_nvm_chunk_desc *chunk_log;
	__u32 nsid;
	__u32 data_len;
	unsigned int flags = 0;

	struct config {
		char *output_format;
		int human_readable;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format",  'o', &cfg.output_format,  output_format),
		OPT_FLAG("human-readable",'H', &cfg.human_readable, human_readable),
		OPT_END()
	};

	fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		return fd;

	fmt = validate_output_format(cfg.output_format);
	if (fmt < 0) {
		err = fmt;
		goto close;
	}

	if (fmt == BINARY)
		flags |= BINARY;
	else if (cfg.human_readable)
		flags |= VERBOSE;

	nsid = nvme_get_nsid(fd);

	/*
	 * It needs to figure out how many bytes will be requested by this
	 * subcommand by the (num_grp * num_pu * num_chk) from the Geometry.
	 */
	err = lnvm_get_identity(fd, nsid, (struct nvme_nvm_id *) &geo);
	if (err)
		goto close;

	data_len = (geo.num_grp * geo.num_pu * geo.num_chk) *
			sizeof(struct nvme_nvm_chunk_desc);
	chunk_log = malloc(data_len);
	if (!chunk_log) {
		fprintf(stderr, "cound not alloc for chunk log %dbytes\n",
				data_len);
		err = -ENOMEM;
		goto close;
	}

	err = lnvm_do_chunk_log(fd, nsid, data_len, chunk_log, flags);
	if (err)
		fprintf(stderr, "get log page for chunk information failed\n");

	free(chunk_log);
close:
	close(fd);
	return err;
}

static int lnvm_create_tgt(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Instantiate a target on top of a LightNVM enabled device.";
	const char *devname = "identifier of desired device. e.g. nvme0n1.";
	const char *tgtname = "target name of the device to initialize. e.g. target0.";
	const char *tgttype = "identifier of target type. e.g. pblk.";
	const char *lun_begin = "Define begin of luns to use for target.";
	const char *lun_end = "Define set of luns to use for target.";
	const char *over_prov = "Define over-provision percentage for target.";
	const char *flag_factory = "Create target in factory mode";
	int flags;
	int ret;

	struct config {
		char *devname;
		char *tgtname;
		char *tgttype;
		__u32 lun_begin;
		__u32 lun_end;
		__u32 over_prov;

		/* flags */
		__u32 factory;
	};

	struct config cfg = {
		.devname = "",
		.tgtname = "",
		.tgttype = "",
		.lun_begin = -1,
		.lun_end = -1,
		.over_prov = -1,
		.factory = 0,
	};

	OPT_ARGS(opts) = {
		OPT_STRING("device-name", 'd', "DEVICE",      &cfg.devname, devname),
		OPT_STRING("target-name", 'n', "TARGET",      &cfg.tgtname, tgtname),
		OPT_STRING("target-type", 't', "TARGETTYPE",  &cfg.tgttype, tgttype),
		OPT_UINT("lun-begin",     'b', &cfg.lun_begin, lun_begin),
		OPT_UINT("lun-end",       'e', &cfg.lun_end,   lun_end),
		OPT_UINT("over-prov",     'o', &cfg.over_prov, over_prov),
		OPT_FLAG("factory",       'f', &cfg.factory,   flag_factory),
		OPT_END()
	};

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret < 0)
		return ret;

	if (!strlen(cfg.devname)) {
		fprintf(stderr, "device name missing\n");
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

	flags = 0;
	if (cfg.factory)
		flags |= NVM_TARGET_FACTORY;

	return lnvm_do_create_tgt(cfg.devname, cfg.tgtname, cfg.tgttype, cfg.lun_begin, cfg.lun_end, cfg.over_prov, flags);
}

static int lnvm_remove_tgt(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Remove an initialized LightNVM target.";
	const char *tgtname = "target name of the device to remove. e.g. target0.";
	int ret;

	struct config {
		char *tgtname;
	};

	struct config cfg = {
		.tgtname = "",
	};

	OPT_ARGS(opts) = {
		OPT_STRING("target-name", 'n', "TARGET", &cfg.tgtname, tgtname),
		OPT_END()
	};

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret < 0)
		return ret;

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
	int ret;

	struct config {
		char *devname;
		int  erase_only_marked;
		int  clear_host_marks;
		int  clear_bb_marks;
	};

	struct config cfg = {
		.devname = "",
	};

	OPT_ARGS(opts) = {
		OPT_STRING("device-name",        'd', "DEVICE", &cfg.devname, devname),
		OPT_FLAG("erase-only-marked",    'e', &cfg.erase_only_marked, erase_only_marked),
		OPT_FLAG("clear-host-side-blks", 's', &cfg.clear_host_marks,  host_marks),
		OPT_FLAG("clear-bb-blks",        'b', &cfg.clear_bb_marks,    bb_marks),
		OPT_END()
	};

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret < 0)
		return ret;

	if (!strlen(cfg.devname)) {
		fprintf(stderr, "device name missing\n");
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

	struct config {
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

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace),
		OPT_SHRT("channel-id",   'c', &cfg.chid,         ch),
		OPT_SHRT("lun-id",       'l', &cfg.lunid,        lun),
		OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,   raw_binary),
		OPT_END()
	};

	fd = parse_and_open(argc, argv, desc, opts);

	if (cfg.raw_binary)
		flags |= BINARY;

	return lnvm_do_get_bbtbl(fd, cfg.namespace_id, cfg.lunid, cfg.chid, flags);
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

	struct config {
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

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace),
		OPT_SHRT("channel-id",   'c', &cfg.chid,         ch),
		OPT_SHRT("lun-id",       'l', &cfg.lunid,        lun),
		OPT_SHRT("plane-id",     'p', &cfg.plnid,        pln),
		OPT_SHRT("block-id",     'b', &cfg.blkid,        blk),
		OPT_SHRT("value",        'v', &cfg.value,        value),
		OPT_END()
	};

	fd = parse_and_open(argc, argv, desc, opts);

	printf("Updating: Ch.: %u LUN: %u Plane: %u Block: %u -> %u\n",
			cfg.chid, cfg.lunid, cfg.plnid, cfg.blkid, cfg.value);
	return lnvm_do_set_bbtbl(fd, cfg.namespace_id, cfg.chid, cfg.lunid,
				 cfg.plnid, cfg.blkid, cfg.value);
}
