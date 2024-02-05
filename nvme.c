// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * NVM-Express command line utility.
 *
 * Copyright (c) 2014-2015, Intel Corporation.
 *
 * Written by Keith Busch <kbusch@kernel.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

/**
 * This program uses NVMe IOCTLs to run native nvme commands to a device.
 */
#include "config.h"
#include "nvme/tree.h"
#include "nvme/types.h"
#include "util/cleanup.h"
#include <errno.h>
#include <getopt.h>
#include <fcntl.h>
#include <inttypes.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <math.h>
#include <dirent.h>
#include <libgen.h>
#include <signal.h>

#include <linux/fs.h>

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

#if HAVE_SYS_RANDOM
	#include <sys/random.h>
#endif

#include "common.h"
#include "nvme.h"
#include "libnvme.h"
#include "nvme-print.h"
#include "plugin.h"
#include "util/base64.h"
#include "util/crc32.h"
#include "nvme-wrap.h"
#include "util/argconfig.h"
#include "util/suffix.h"
#include "fabrics.h"
#define CREATE_CMD
#include "nvme-builtin.h"
#include "malloc.h"

struct feat_cfg {
	enum nvme_features_id feature_id;
	__u32 namespace_id;
	enum nvme_get_features_sel sel;
	__u32 cdw11;
	__u32 cdw12;
	__u8  uuid_index;
	__u32 data_len;
	bool  raw_binary;
	bool  human_readable;
};

struct passthru_config {
	__u8	opcode;
	__u8	flags;
	__u16	rsvd;
	__u32	namespace_id;
	__u32	data_len;
	__u32	metadata_len;
	__u32	timeout;
	__u32	cdw2;
	__u32	cdw3;
	__u32	cdw10;
	__u32	cdw11;
	__u32	cdw12;
	__u32	cdw13;
	__u32	cdw14;
	__u32	cdw15;
	char	*input_file;
	char	*metadata;
	bool	raw_binary;
	bool	show_command;
	bool	dry_run;
	bool	read;
	bool	write;
	__u8	prefill;
	bool	latency;
};

#define NVME_ARGS(n, ...)                                                         \
	struct argconfig_commandline_options n[] = {                              \
		OPT_FLAG("verbose",      'v', NULL,               verbose),       \
		OPT_FMT("output-format", 'o', &output_format_val, output_format), \
		##__VA_ARGS__,                                                    \
		OPT_END()                                                         \
	}

static const char nvme_version_string[] = NVME_VERSION;

static struct plugin builtin = {
	.commands = commands,
	.name = NULL,
	.desc = NULL,
	.next = NULL,
	.tail = &builtin,
};

static struct program nvme = {
	.name = "nvme",
	.version = nvme_version_string,
	.usage = "<command> [<device>] [<args>]",
	.desc = "The '<device>' may be either an NVMe character\n"
		"device (ex: /dev/nvme0), an nvme block device\n"
		"(ex: /dev/nvme0n1), or a mctp address in the form\n"
		"mctp:<net>,<eid>[:ctrl-id]",
	.extensions = &builtin,
};

const char *output_format = "Output format: normal|json|binary";
static const char *app_tag = "app tag for end-to-end PI";
static const char *app_tag_mask = "app tag mask for end-to-end PI";
static const char *block_count = "number of blocks (zeroes based) on device to access";
static const char *crkey = "current reservation key";
static const char *csi = "command set identifier";
static const char *buf_len = "buffer len (if) data is sent or received";
static const char *domainid = "Domain Identifier";
static const char *doper = "directive operation";
static const char *dry = "show command instead of sending";
static const char *dspec_w_dtype = "directive specification associated with directive type";
static const char *dtype = "directive type";
static const char *force_unit_access = "force device to commit data before command completes";
static const char *human_readable_directive = "show directive in readable format";
static const char *human_readable_identify = "show identify in readable format";
static const char *human_readable_info = "show info in readable format";
static const char *human_readable_log = "show log in readable format";
static const char *iekey = "ignore existing res. key";
static const char *latency = "output latency statistics";
static const char *lba_format_index = "The index into the LBA Format list\n"
	"identifying the LBA Format capabilities that are to be returned";
static const char *limited_retry = "limit media access attempts";
static const char *lsp = "log specific field";
static const char *mos = "management operation specific";
static const char *mo = "management operation";
static const char *namespace_desired = "desired namespace";
static const char *namespace_id_desired = "identifier of desired namespace";
static const char *namespace_id_optional = "optional namespace attached to controller";
static const char *nssf = "NVMe Security Specific Field";
static const char *prinfo = "PI and check field";
static const char *rae = "Retain an Asynchronous Event";
static const char *raw_directive = "show directive in binary format";
static const char *raw_dump = "dump output in binary format";
static const char *raw_identify = "show identify in binary format";
static const char *raw_log = "show log in binary format";
static const char *raw_output = "output in binary format";
static const char *ref_tag = "reference tag for end-to-end PI";
static const char *raw_use = "use binary output";
static const char *rtype = "reservation type";
static const char *secp = "security protocol (cf. SPC-4)";
static const char *spsp = "security-protocol-specific (cf. SPC-4)";
static const char *start_block = "64-bit LBA of first block to access";
static const char *storage_tag = "storage tag for end-to-end PI";
static const char *timeout = "timeout value, in milliseconds";
static const char *uuid_index = "UUID index";
static const char *uuid_index_specify = "specify uuid index";
static const char *verbose = "Increase output verbosity";
static const char dash[51] = {[0 ... 49] = '=', '\0'};
static const char space[51] = {[0 ... 49] = ' ', '\0'};

static char *output_format_val = "normal";

static void *mmap_registers(nvme_root_t r, struct nvme_dev *dev);

const char *nvme_strerror(int errnum)
{
	if (errnum >= ENVME_CONNECT_RESOLVE)
		return nvme_errno_to_string(errnum);
	return strerror(errnum);
}

int map_log_level(int verbose, bool quiet)
{
	int log_level;

	/*
	 * LOG_NOTICE is unused thus the user has to provide two 'v' for getting
	 * any feedback at all. Thus skip this level
	 */
	verbose++;

	switch (verbose) {
	case 0:
		log_level = LOG_WARNING;
		break;
	case 1:
		log_level = LOG_NOTICE;
		break;
	case 2:
		log_level = LOG_INFO;
		break;
	default:
		log_level = LOG_DEBUG;
		break;
	}
	if (quiet)
		log_level = LOG_ERR;

	return log_level;
}

static ssize_t getrandom_bytes(void *buf, size_t buflen)
{
#if HAVE_SYS_RANDOM
	return getrandom(buf, buflen, GRND_NONBLOCK);
#else
	ssize_t result;
	int fd, err = 0;

	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0)
		return fd;
	result = read(fd, buf, buflen);
	if (result < 0)
		err = errno;
	close(fd);
	errno = err;
	return result;
#endif
}

static bool is_chardev(struct nvme_dev *dev)
{
	return S_ISCHR(dev->direct.stat.st_mode);
}

static bool is_blkdev(struct nvme_dev *dev)
{
	return S_ISBLK(dev->direct.stat.st_mode);
}

static int open_dev_direct(struct nvme_dev **devp, char *devstr, int flags)
{
	struct nvme_dev *dev;
	int err;

	dev = calloc(1, sizeof(*dev));
	if (!dev)
		return -1;

	dev->type = NVME_DEV_DIRECT;
	dev->name = basename(devstr);
	err = open(devstr, flags);
	if (err < 0) {
		nvme_show_perror(devstr);
		goto err_free;
	}
	dev->direct.fd = err;

	err = fstat(dev_fd(dev), &dev->direct.stat);
	if (err < 0) {
		nvme_show_perror(devstr);
		goto err_close;
	}
	if (!is_chardev(dev) && !is_blkdev(dev)) {
		nvme_show_error("%s is not a block or character device", devstr);
		err = -ENODEV;
		goto err_close;
	}
	*devp = dev;
	return 0;

err_close:
	close(dev_fd(dev));
err_free:
	free(dev);
	return err;
}

static int parse_mi_dev(char *dev, unsigned int *net, uint8_t *eid,
			unsigned int *ctrl)
{
	int rc;

	/* <net>,<eid>:<ctrl-id> form */
	rc = sscanf(dev, "mctp:%u,%hhu:%u", net, eid, ctrl);
	if (rc == 3)
		return 0;

	/* <net>,<eid> form, implicit ctrl-id = 0 */
	*ctrl = 0;
	rc = sscanf(dev, "mctp:%u,%hhu", net, eid);
	if (rc == 2)
		return 0;

	return -1;
}

static int open_dev_mi_mctp(struct nvme_dev **devp, char *devstr)
{
	unsigned int net, ctrl_id;
	struct nvme_dev *dev;
	unsigned char eid;
	int rc;

	rc = parse_mi_dev(devstr, &net, &eid, &ctrl_id);
	if (rc) {
		nvme_show_error("invalid device specifier '%s'", devstr);
		return rc;
	}

	dev = calloc(1, sizeof(*dev));
	if (!dev)
		return -1;

	dev->type = NVME_DEV_MI;
	dev->name = devstr;

	/* todo: verbose argument */
	dev->mi.root = nvme_mi_create_root(stderr, LOG_WARNING);
	if (!dev->mi.root)
		goto err_free;

	dev->mi.ep = nvme_mi_open_mctp(dev->mi.root, net, eid);
	if (!dev->mi.ep)
		goto err_free_root;

	dev->mi.ctrl = nvme_mi_init_ctrl(dev->mi.ep, ctrl_id);
	if (!dev->mi.ctrl)
		goto err_close_ep;

	*devp = dev;
	return 0;

err_close_ep:
	nvme_mi_close(dev->mi.ep);
err_free_root:
	nvme_mi_free_root(dev->mi.root);
err_free:
	free(dev);
	return -1;
}

static int check_arg_dev(int argc, char **argv)
{
	if (optind >= argc) {
		errno = EINVAL;
		nvme_show_perror(argv[0]);
		return -EINVAL;
	}
	return 0;
}

static int get_dev(struct nvme_dev **dev, int argc, char **argv, int flags)
{
	char *devname;
	int ret;

	ret = check_arg_dev(argc, argv);
	if (ret)
		return ret;

	devname = argv[optind];

	if (!strncmp(devname, "mctp:", strlen("mctp:")))
		ret = open_dev_mi_mctp(dev, devname);
	else
		ret = open_dev_direct(dev, devname, flags);

	return ret != 0 ? -errno : 0;
}

int parse_and_open(struct nvme_dev **dev, int argc, char **argv,
		   const char *desc,
		   struct argconfig_commandline_options *opts)
{
	int ret;

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret)
		return ret;

	ret = get_dev(dev, argc, argv, O_RDONLY);
	if (ret < 0)
		argconfig_print_help(desc, opts);
	else if (argconfig_parse_seen(opts, "verbose"))
		nvme_cli_set_debug(*dev, true);

	return ret;
}

int open_exclusive(struct nvme_dev **dev, int argc, char **argv,
		   int ignore_exclusive)
{
	int flags = O_RDONLY;

	if (!ignore_exclusive)
		flags |= O_EXCL;

	return get_dev(dev, argc, argv, flags);
}

int validate_output_format(const char *format, enum nvme_print_flags *flags)
{
	enum nvme_print_flags f;

	if (!format)
		return -EINVAL;

	if (!strcmp(format, "normal"))
		f = NORMAL;
	else if (!strcmp(format, "json"))
		f = JSON;
	else if (!strcmp(format, "binary"))
		f = BINARY;
	else
		return -EINVAL;

	*flags = f;

	return 0;
}

bool nvme_is_output_format_json(void)
{
	enum nvme_print_flags flags;

	if (validate_output_format(output_format_val, &flags))
		return false;

	return flags == JSON;
}

void dev_close(struct nvme_dev *dev)
{
	switch (dev->type) {
	case NVME_DEV_DIRECT:
		close(dev_fd(dev));
		break;
	case NVME_DEV_MI:
		nvme_mi_close(dev->mi.ep);
		nvme_mi_free_root(dev->mi.root);
		break;
	}
	free(dev);
}

static int get_smart_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Retrieve SMART log for the given device\n"
		"(or optionally a namespace) in either decoded format\n"
		"(default) or binary.";

	_cleanup_free_ struct nvme_smart_log *smart_log = NULL;
	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	const char *namespace = "(optional) desired namespace";
	enum nvme_print_flags flags;
	int err = -1;

	struct config {
		__u32	namespace_id;
		bool	raw_binary;
		bool	human_readable;
	};

	struct config cfg = {
		.namespace_id	= NVME_NSID_ALL,
		.raw_binary	= false,
		.human_readable	= false,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id",   'n', &cfg.namespace_id,   namespace),
		  OPT_FLAG("raw-binary",     'b', &cfg.raw_binary,     raw_output),
		  OPT_FLAG("human-readable", 'H', &cfg.human_readable, human_readable_info));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(output_format_val, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.raw_binary)
		flags = BINARY;

	if (cfg.human_readable)
		flags |= VERBOSE;

	smart_log = nvme_alloc(sizeof(*smart_log));
	if (!smart_log)
		return -ENOMEM;

	err = nvme_cli_get_log_smart(dev, cfg.namespace_id, false,
				     smart_log);
	if (!err)
		nvme_show_smart_log(smart_log, cfg.namespace_id,
				    dev->name, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("smart log: %s", nvme_strerror(errno));

	return err;
}

static int get_ana_log(int argc, char **argv, struct command *cmd,
		struct plugin *plugin)
{
	const char *desc = "Retrieve ANA log for the given device in\n"
		"decoded format (default), json or binary.";
	const char *groups = "Return ANA groups only.";

	_cleanup_nvme_dev_ struct nvme_dev *dev= NULL;
	_cleanup_free_ struct nvme_id_ctrl *ctrl = NULL;
	_cleanup_free_ void *ana_log = NULL;
	size_t ana_log_len;
	enum nvme_print_flags flags;
	enum nvme_log_ana_lsp lsp;
	int err = -1;

	struct config {
		bool	groups;
	};

	struct config cfg = {
		.groups = false,
	};

	NVME_ARGS(opts,
		  OPT_FLAG("groups", 'g', &cfg.groups, groups));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(output_format_val, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	ctrl = nvme_alloc(sizeof(*ctrl));
	if (!ctrl)
		return -ENOMEM;

	err = nvme_cli_identify_ctrl(dev, ctrl);
	if (err) {
		nvme_show_error("ERROR : nvme_identify_ctrl() failed: %s",
			nvme_strerror(errno));
		return err;
	}

	ana_log_len = sizeof(struct nvme_ana_log) +
		le32_to_cpu(ctrl->nanagrpid) * sizeof(struct nvme_ana_group_desc);
	if (!(ctrl->anacap & (1 << 6)))
		ana_log_len += le32_to_cpu(ctrl->mnan) * sizeof(__le32);

	ana_log = nvme_alloc(ana_log_len);
	if (!ana_log)
		return -ENOMEM;

	lsp = cfg.groups ? NVME_LOG_ANA_LSP_RGO_GROUPS_ONLY :
		NVME_LOG_ANA_LSP_RGO_NAMESPACES;

	err = nvme_cli_get_log_ana(dev, lsp, true, 0, ana_log_len, ana_log);
	if (!err)
		nvme_show_ana_log(ana_log, dev->name, ana_log_len, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("ana-log: %s", nvme_strerror(errno));

	return err;
}

static int parse_telemetry_da(struct nvme_dev *dev,
			      enum nvme_telemetry_da da,
			      struct nvme_telemetry_log *telem,
			      size_t *size)

{
	_cleanup_free_ struct nvme_id_ctrl *id_ctrl = NULL;
	size_t dalb = 0;

	id_ctrl = nvme_alloc(sizeof(*id_ctrl));
	if (!id_ctrl)
		return -ENOMEM;

	switch (da) {
	case NVME_TELEMETRY_DA_1:
		dalb = le16_to_cpu(telem->dalb1);
		break;
	case NVME_TELEMETRY_DA_2:
		dalb = le16_to_cpu(telem->dalb2);
		break;
	case NVME_TELEMETRY_DA_3:
		/* dalb3 >= dalb2 >= dalb1 */
		dalb = le16_to_cpu(telem->dalb3);
		break;
	case NVME_TELEMETRY_DA_4:
		if (nvme_cli_identify_ctrl(dev, id_ctrl)) {
			perror("identify-ctrl");
			return -errno;
		}

		if (id_ctrl->lpa & 0x40) {
			dalb = le32_to_cpu(telem->dalb4);
		} else {
			nvme_show_error(
			    "Data area 4 unsupported, bit 6 of Log Page Attributes not set");
			return -EINVAL;
		}
		break;
	default:
		nvme_show_error("Invalid data area parameter - %d", da);
		return -EINVAL;
	}

	if (dalb == 0) {
		nvme_show_error("ERROR: No telemetry data block");
		return -ENOENT;
	}
	*size = (dalb + 1) * NVME_LOG_TELEM_BLOCK_SIZE;
	return 0;
}

static int get_log_telemetry_ctrl(struct nvme_dev *dev, bool rae, size_t size,
				  struct nvme_telemetry_log **buf)
{
	struct nvme_telemetry_log *log;
	int err;

	log = nvme_alloc(size);
	if (!log)
		return -errno;

	err = nvme_cli_get_log_telemetry_ctrl(dev, rae, 0, size, log);
	if (err) {
		free(log);
		return -errno;
	}

	*buf = log;
	return 0;
}

static int get_log_telemetry_host(struct nvme_dev *dev, size_t size,
				  struct nvme_telemetry_log **buf)
{
	struct nvme_telemetry_log *log;
	int err;

	log = nvme_alloc(size);
	if (!log)
		return -errno;

	err = nvme_cli_get_log_telemetry_host(dev, 0, size, log);
	if (err) {
		free(log);
		return -errno;
	}

	*buf = log;
	return 0;
}

static int __create_telemetry_log_host(struct nvme_dev *dev,
				       enum nvme_telemetry_da da,
				       size_t *size,
				       struct nvme_telemetry_log **buf)
{
	_cleanup_free_ struct nvme_telemetry_log *log = NULL;
	int err;

	log = nvme_alloc(sizeof(*log));
	if (!log)
		return -ENOMEM;

	err = nvme_cli_get_log_create_telemetry_host(dev, log);
	if (err)
		return -errno;

	err = parse_telemetry_da(dev, da, log, size);
	if (err)
		return err;

	return get_log_telemetry_host(dev, *size, buf);
}

static int __get_telemetry_log_ctrl(struct nvme_dev *dev,
				    bool rae,
				    enum nvme_telemetry_da da,
				    size_t *size,
				    struct nvme_telemetry_log **buf)
{
	struct nvme_telemetry_log *log;
	int err;

	log = nvme_alloc(NVME_LOG_TELEM_BLOCK_SIZE);
	if (!log)
		return -errno;

	/*
	 * set rae = true so it won't clear the current telemetry log in
	 * controller
	 */
	err = nvme_cli_get_log_telemetry_ctrl(dev, true, 0,
					      NVME_LOG_TELEM_BLOCK_SIZE,
					      log);
	if (err)
		goto free;

	if (!log->ctrlavail) {
		if (!rae) {
			err = nvme_cli_get_log_telemetry_ctrl(dev, rae, 0,
							      NVME_LOG_TELEM_BLOCK_SIZE,
							      log);
			goto free;
		}

		*size = NVME_LOG_TELEM_BLOCK_SIZE;
		*buf = log;

		printf("Warning: Telemetry Controller-Initiated Data Not Available.\n");
		return 0;
	}

	err = parse_telemetry_da(dev, da, log, size);
	if (err)
		goto free;

	return get_log_telemetry_ctrl(dev, rae, *size, buf);

free:
	free(log);
	return err;
}

static int __get_telemetry_log_host(struct nvme_dev *dev,
				    enum nvme_telemetry_da da,
				    size_t *size,
				    struct nvme_telemetry_log **buf)
{
	_cleanup_free_ struct nvme_telemetry_log *log = NULL;
	int err;

	log = nvme_alloc(sizeof(*log));
	if (!log)
		return -errno;

	err = nvme_cli_get_log_telemetry_host(dev, 0,
					      NVME_LOG_TELEM_BLOCK_SIZE,
					      log);
	if (err)
		return  err;

	err = parse_telemetry_da(dev, da, log, size);
	if (err)
		return err;

	return get_log_telemetry_host(dev, *size, buf);
}

static int get_telemetry_log(int argc, char **argv, struct command *cmd,
			     struct plugin *plugin)
{
	const char *desc = "Retrieve telemetry log and write to binary file";
	const char *fname = "File name to save raw binary, includes header";
	const char *hgen = "Have the host tell the controller to generate the report";
	const char *cgen = "Gather report generated by the controller.";
	const char *dgen = "Pick which telemetry data area to report. Default is 3 to fetch areas 1-3. Valid options are 1, 2, 3, 4.";

	_cleanup_free_ struct nvme_telemetry_log *log = NULL;
	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	_cleanup_file_ int output = -1;
	int err = 0;
	size_t total_size;
	__u8 *data_ptr = NULL;
	int data_written = 0, data_remaining = 0;

	struct config {
		char	*file_name;
		__u32	host_gen;
		bool	ctrl_init;
		int	data_area;
		bool	rae;
	};
	struct config cfg = {
		.file_name	= NULL,
		.host_gen	= 1,
		.ctrl_init	= false,
		.data_area	= 3,
		.rae		= true,
	};

	NVME_ARGS(opts,
		  OPT_FILE("output-file",     'O', &cfg.file_name, fname),
		  OPT_UINT("host-generate",   'g', &cfg.host_gen,  hgen),
		  OPT_FLAG("controller-init", 'c', &cfg.ctrl_init, cgen),
		  OPT_UINT("data-area",       'd', &cfg.data_area, dgen),
		  OPT_FLAG("rae",             'r', &cfg.rae,       rae));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	if (!cfg.file_name) {
		nvme_show_error("Please provide an output file!");
		return -EINVAL;
	}

	cfg.host_gen = !!cfg.host_gen;
	output = open(cfg.file_name, O_WRONLY | O_CREAT | O_TRUNC, 0666);
	if (output < 0) {
		nvme_show_error("Failed to open output file %s: %s!",
				cfg.file_name, strerror(errno));
		return output;
	}

	log = nvme_alloc(sizeof(*log));
	if (!log)
		return -ENOMEM;

	if (cfg.ctrl_init)
		err = __get_telemetry_log_ctrl(dev, cfg.rae, cfg.data_area,
					       &total_size, &log);
	else if (cfg.host_gen)
		err = __create_telemetry_log_host(dev, cfg.data_area,
						  &total_size, &log);
	else
		err = __get_telemetry_log_host(dev, cfg.data_area,
					       &total_size, &log);

	if (err < 0) {
		nvme_show_error("get-telemetry-log: %s", nvme_strerror(errno));
		return err;
	} else if (err > 0) {
		nvme_show_status(err);
		fprintf(stderr, "Failed to acquire telemetry log %d!\n", err);
		return err;
	}

	data_written = 0;
	data_remaining = total_size;
	data_ptr = (__u8 *)log;

	while (data_remaining) {
		data_written = write(output, data_ptr, data_remaining);
		if (data_written < 0) {
			data_remaining = data_written;
			break;
		} else if (data_written <= data_remaining) {
			data_remaining -= data_written;
			data_ptr += data_written;
		} else {
			/* Unexpected overwrite */
			fprintf(stderr, "Failure: Unexpected telemetry log overwrite - data_remaining = 0x%x, data_written = 0x%x\n",
					data_remaining, data_written);
			break;
		}
	}

	if (fsync(output) < 0) {
		nvme_show_error("ERROR : %s: : fsync : %s", __func__, strerror(errno));
		return -1;
	}

	return err;
}

static int get_endurance_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Retrieves endurance groups log page and prints the log.";
	const char *group_id = "The endurance group identifier";

	_cleanup_free_ struct nvme_endurance_group_log *endurance_log = NULL;
	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	enum nvme_print_flags flags;
	int err;

	struct config {
		__u16	group_id;
	};

	struct config cfg = {
		.group_id	= 0,
	};

	NVME_ARGS(opts,
		  OPT_SHRT("group-id",     'g', &cfg.group_id,      group_id));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(output_format_val, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	endurance_log = nvme_alloc(sizeof(*endurance_log));
	if (!endurance_log)
		return -ENOMEM;

	err = nvme_cli_get_log_endurance_group(dev, cfg.group_id,
					       endurance_log);
	if (!err)
		nvme_show_endurance_log(endurance_log, cfg.group_id,
					dev->name, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("endurance log: %s", nvme_strerror(errno));

	return err;
}

static int collect_effects_log(struct nvme_dev *dev, enum nvme_csi csi,
			       struct list_head *list, int flags)
{
	nvme_effects_log_node_t *node;
	int err;

	node = nvme_alloc(sizeof(*node));
	if (!node)
		return -ENOMEM;

	node->csi = csi;

	err = nvme_cli_get_log_cmd_effects(dev, csi, &node->effects);
	if (err) {
		free(node);
		return err;
	}
	list_add(list, &node->node);
	return 0;
}

static int get_effects_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Retrieve command effects log page and print the table.";

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	struct list_head log_pages;
	nvme_effects_log_node_t *node;

	void *bar = NULL;

	int err = -1;
	enum nvme_print_flags flags;

	struct config {
		bool	human_readable;
		bool	raw_binary;
		int	csi;
	};

	struct config cfg = {
		.human_readable	= false,
		.raw_binary	= false,
		.csi		= -1,
	};

	NVME_ARGS(opts,
		  OPT_FLAG("human-readable", 'H', &cfg.human_readable, human_readable_log),
		  OPT_FLAG("raw-binary",     'b', &cfg.raw_binary,     raw_log),
		  OPT_INT("csi",             'c', &cfg.csi,            csi));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(output_format_val, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.raw_binary)
		flags = BINARY;

	if (cfg.human_readable)
		flags |= VERBOSE;

	list_head_init(&log_pages);

	if (cfg.csi < 0) {
		nvme_root_t r;
		__u64 cap;

		r = nvme_scan(NULL);
		bar = mmap_registers(r, dev);
		nvme_free_tree(r);

		if (bar) {
			cap = mmio_read64(bar + NVME_REG_CAP);
			munmap(bar, getpagesize());
		} else {
			struct nvme_get_property_args args = {
				.args_size	= sizeof(args),
				.fd		= dev_fd(dev),
				.offset		= NVME_REG_CAP,
				.value		= &cap,
				.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
			};
			err = nvme_get_property(&args);
			if (err)
				goto cleanup_list;
		}

		if (NVME_CAP_CSS(cap) & NVME_CAP_CSS_NVM)
			err = collect_effects_log(dev, NVME_CSI_NVM,
						  &log_pages, flags);

		if (!err && (NVME_CAP_CSS(cap) & NVME_CAP_CSS_CSI))
			err = collect_effects_log(dev, NVME_CSI_ZNS,
						  &log_pages, flags);
	} else {
		err = collect_effects_log(dev, cfg.csi, &log_pages, flags);
	}

	if (!err)
		nvme_print_effects_log_pages(&log_pages, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_perror("effects log page");

cleanup_list:
	while ((node = list_pop(&log_pages, nvme_effects_log_node_t, node)))
		free(node);

	return err;
}

static int get_supported_log_pages(int argc, char **argv, struct command *cmd,
	struct plugin *plugin)
{
	const char *desc = "Retrieve supported logs and print the table.";

	_cleanup_free_ struct nvme_supported_log_pages *supports = NULL;
	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	enum nvme_print_flags flags;
	int err = -1;

	NVME_ARGS(opts);

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(output_format_val, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (argconfig_parse_seen(opts, "verbose"))
		flags |= VERBOSE;

	supports = nvme_alloc(sizeof(*supports));
	if (!supports)
		return -ENOMEM;

	err = nvme_cli_get_log_supported_log_pages(dev, false, supports);
	if (!err)
		nvme_show_supported_log(supports, dev->name, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("supported log pages: %s", nvme_strerror(errno));

	return err;
}

static int get_error_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Retrieve specified number of\n"
		"error log entries from a given device\n"
		"in either decoded format (default) or binary.";
	const char *log_entries = "number of entries to retrieve";
	const char *raw = "dump in binary format";

	_cleanup_free_ struct nvme_error_log_page *err_log = NULL;
	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	struct nvme_id_ctrl ctrl;
	enum nvme_print_flags flags;
	int err = -1;

	struct config {
		__u32	log_entries;
		bool	raw_binary;
	};

	struct config cfg = {
		.log_entries	= 64,
		.raw_binary	= false,
	};

	NVME_ARGS(opts,
		  OPT_UINT("log-entries",  'e', &cfg.log_entries,   log_entries),
		  OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,    raw));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(output_format_val, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.raw_binary)
		flags = BINARY;

	if (!cfg.log_entries) {
		nvme_show_error("non-zero log-entries is required param");
		return -1;
	}

	err = nvme_cli_identify_ctrl(dev, &ctrl);
	if (err < 0) {
		nvme_show_perror("identify controller");
		return err;
	} else if (err) {
		nvme_show_error("could not identify controller");
		return err;
	}

	cfg.log_entries = min(cfg.log_entries, ctrl.elpe + 1);
	err_log = nvme_alloc(cfg.log_entries * sizeof(struct nvme_error_log_page));
	if (!err_log)
		return -ENOMEM;

	err = nvme_cli_get_log_error(dev, cfg.log_entries, false, err_log);
	if (!err)
		nvme_show_error_log(err_log, cfg.log_entries,
				    dev->name, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_perror("error log");

	return err;
}

static int get_fw_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Retrieve the firmware log for the\n"
		"specified device in either decoded format (default) or binary.";

	_cleanup_free_ struct nvme_firmware_slot *fw_log = NULL;;
	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	enum nvme_print_flags flags;
	int err;

	struct config {
		bool	raw_binary;
	};

	struct config cfg = {
		.raw_binary	= false,
	};

	NVME_ARGS(opts,
		  OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,    raw_use));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(output_format_val, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.raw_binary)
		flags = BINARY;

	fw_log = nvme_alloc(sizeof(*fw_log));
	if (!fw_log)
		return -ENOMEM;

	err = nvme_cli_get_log_fw_slot(dev, false, fw_log);
	if (!err)
		nvme_show_fw_log(fw_log, dev->name, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("fw log: %s", nvme_strerror(errno));

	return err;
}

static int get_changed_ns_list_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Retrieve Changed Namespaces log for the given device\n"
		"in either decoded format (default) or binary.";

	_cleanup_free_ struct nvme_ns_list *changed_ns_list_log = NULL;
	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	enum nvme_print_flags flags;
	int err;

	struct config {
		bool	raw_binary;
	};

	struct config cfg = {
		.raw_binary	= false,
	};

	NVME_ARGS(opts,
		  OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,    raw_output));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(output_format_val, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.raw_binary)
		flags = BINARY;

	changed_ns_list_log = nvme_alloc(sizeof(*changed_ns_list_log));
	if (!changed_ns_list_log)
		return -ENOMEM;

	err = nvme_cli_get_log_changed_ns_list(dev, true,
					       changed_ns_list_log);
	if (!err)
		nvme_show_changed_ns_list_log(changed_ns_list_log,
					      dev->name, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("changed ns list log: %s", nvme_strerror(errno));

	return err;
}

static int get_pred_lat_per_nvmset_log(int argc, char **argv,
	struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Retrieve Predictable latency per nvm set log\n"
		"page and prints it for the given device in either decoded\n"
		"format(default),json or binary.";
	const char *nvmset_id = "NVM Set Identifier";

	_cleanup_free_ struct nvme_nvmset_predictable_lat_log *plpns_log = NULL;
	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	enum nvme_print_flags flags;
	int err;

	struct config {
		__u16	nvmset_id;
		bool	raw_binary;
	};

	struct config cfg = {
		.nvmset_id	= 1,
		.raw_binary	= false,
	};

	NVME_ARGS(opts,
		  OPT_SHRT("nvmset-id",	   'i', &cfg.nvmset_id,     nvmset_id),
		  OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,    raw_use));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(output_format_val, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.raw_binary)
		flags = BINARY;

	plpns_log = nvme_alloc(sizeof(*plpns_log));
	if (!plpns_log)
		return -ENOMEM;

	err = nvme_cli_get_log_predictable_lat_nvmset(dev, cfg.nvmset_id,
						      plpns_log);
	if (!err)
		nvme_show_predictable_latency_per_nvmset(plpns_log, cfg.nvmset_id, dev->name,
							 flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("predictable latency per nvm set: %s", nvme_strerror(errno));

	return err;
}

static int get_pred_lat_event_agg_log(int argc, char **argv,
		struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Retrieve Predictable Latency Event\n"
		"Aggregate Log page and prints it, for the given\n"
		"device in either decoded format(default), json or binary.";
	const char *log_entries = "Number of pending NVM Set log Entries list";

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	_cleanup_free_ struct nvme_id_ctrl *ctrl = NULL;
	_cleanup_free_ void *pea_log = NULL;
	enum nvme_print_flags flags;
	__u32 log_size;
	int err;

	struct config {
		__u64	log_entries;
		bool	rae;
		bool	raw_binary;
	};

	struct config cfg = {
		.log_entries	= 2044,
		.rae		= false,
		.raw_binary	= false,
	};

	NVME_ARGS(opts,
		  OPT_UINT("log-entries",  'e', &cfg.log_entries,   log_entries),
		  OPT_FLAG("rae",          'r', &cfg.rae,           rae),
		  OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,    raw_use));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(output_format_val, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.raw_binary)
		flags = BINARY;

	if (!cfg.log_entries) {
		nvme_show_error("non-zero log-entries is required param");
		return -EINVAL;
	}

	ctrl = nvme_alloc(sizeof(*ctrl));
	if (!ctrl)
		return -ENOMEM;

	err = nvme_cli_identify_ctrl(dev, ctrl);
	if (err < 0) {
		nvme_show_error("identify controller: %s", nvme_strerror(errno));
		return err;
	} else if (err) {
		nvme_show_status(err);
		return err;
	}

	cfg.log_entries = min(cfg.log_entries, le32_to_cpu(ctrl->nsetidmax));
	log_size = sizeof(__u64) + cfg.log_entries * sizeof(__u16);

	pea_log = nvme_alloc(log_size);
	if (!pea_log)
		return -ENOMEM;

	err = nvme_cli_get_log_predictable_lat_event(dev, cfg.rae, 0,
						     log_size, pea_log);
	if (!err)
		nvme_show_predictable_latency_event_agg_log(pea_log, cfg.log_entries, log_size,
							    dev->name, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("predictable latency event aggregate log page: %s",
				nvme_strerror(errno));

	return err;
}

static int get_persistent_event_log(int argc, char **argv,
		struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Retrieve Persistent Event log info for\n"
		"the given device in either decoded format(default), json or binary.";
	const char *action = "action the controller shall take during\n"
		"processing this persistent log page command.";
	const char *log_len = "number of bytes to retrieve";

	_cleanup_free_ struct nvme_persistent_event_log *pevent_collected = NULL;
	_cleanup_free_ struct nvme_persistent_event_log *pevent = NULL;
	_cleanup_huge_ struct nvme_mem_huge mh = { 0, };
	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	enum nvme_print_flags flags;
	void *pevent_log_info;
	int err;

	struct config {
		__u8	action;
		__u32	log_len;
		bool	raw_binary;
	};

	struct config cfg = {
		.action		= 0xff,
		.log_len	= 0,
		.raw_binary	= false,
	};

	NVME_ARGS(opts,
		  OPT_BYTE("action",       'a', &cfg.action,        action),
		  OPT_UINT("log_len",	 'l', &cfg.log_len,	  log_len),
		  OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,    raw_use));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(output_format_val, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.raw_binary)
		flags = BINARY;

	pevent = nvme_alloc(sizeof(*pevent));
	if (!pevent)
		return -ENOMEM;

	err = nvme_cli_get_log_persistent_event(dev, cfg.action,
						sizeof(*pevent), pevent);
	if (err < 0) {
		nvme_show_error("persistent event log: %s", nvme_strerror(errno));
		return err;
	} else if (err) {
		nvme_show_status(err);
		return err;
	}

	if (cfg.action == NVME_PEVENT_LOG_RELEASE_CTX) {
		printf("Releasing Persistent Event Log Context\n");
		return 0;
	}

	if (!cfg.log_len && cfg.action != NVME_PEVENT_LOG_EST_CTX_AND_READ) {
		cfg.log_len = le64_to_cpu(pevent->tll);
	} else if (!cfg.log_len && cfg.action == NVME_PEVENT_LOG_EST_CTX_AND_READ) {
		printf("Establishing Persistent Event Log Context\n");
		return 0;
	}

	/*
	 * if header already read with context establish action 0x1,
	 * action shall not be 0x1 again in the subsequent request,
	 * until the current context is released by issuing action
	 * with 0x2, otherwise throws command sequence error, make
	 * it as zero to read the log page
	 */
	if (cfg.action == NVME_PEVENT_LOG_EST_CTX_AND_READ)
		cfg.action = NVME_PEVENT_LOG_READ;

	pevent_log_info = nvme_alloc_huge(cfg.log_len, &mh);
	if (!pevent_log_info)
		return -ENOMEM;

	err = nvme_cli_get_log_persistent_event(dev, cfg.action,
						cfg.log_len, pevent_log_info);
	if (!err) {
		err = nvme_cli_get_log_persistent_event(dev, cfg.action,
							sizeof(*pevent),
							pevent);
		if (err < 0) {
			nvme_show_error("persistent event log: %s", nvme_strerror(errno));
			return err;
		} else if (err) {
			nvme_show_status(err);
			return err;
		}
		pevent_collected = pevent_log_info;
		if (pevent_collected->gen_number != pevent->gen_number) {
			printf("Collected Persistent Event Log may be invalid,\n"
			       "Re-read the log is required\n");
			return -EINVAL;
		}

		nvme_show_persistent_event_log(pevent_log_info, cfg.action,
			cfg.log_len, dev->name, flags);
	} else if (err > 0) {
		nvme_show_status(err);
	} else {
		nvme_show_error("persistent event log: %s", nvme_strerror(errno));
	}

	return err;
}

static int get_endurance_event_agg_log(int argc, char **argv,
		struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Retrieve Retrieve Predictable Latency\n"
		"Event Aggregate page and prints it, for the given\n"
		"device in either decoded format(default), json or binary.";
	const char *log_entries = "Number of pending Endurance Group Event log Entries list";

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	_cleanup_free_ struct nvme_id_ctrl *ctrl = NULL;
	_cleanup_free_ void *endurance_log = NULL;
	enum nvme_print_flags flags;
	__u32 log_size;
	int err;

	struct config {
		__u64	log_entries;
		bool	rae;
		bool	raw_binary;
	};

	struct config cfg = {
		.log_entries	= 2044,
		.rae		= false,
		.raw_binary	= false,
	};

	NVME_ARGS(opts,
		  OPT_UINT("log-entries",  'e', &cfg.log_entries,   log_entries),
		  OPT_FLAG("rae",          'r', &cfg.rae,           rae),
		  OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,    raw_use));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(output_format_val, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.raw_binary)
		flags = BINARY;

	if (!cfg.log_entries) {
		nvme_show_error("non-zero log-entries is required param");
		return -EINVAL;
	}

	ctrl = nvme_alloc(sizeof(*ctrl));
	if (!ctrl)
		return -ENOMEM;

	err = nvme_cli_identify_ctrl(dev, ctrl);
	if (err < 0) {
		nvme_show_error("identify controller: %s", nvme_strerror(errno));
		return err;
	} else if (err) {
		nvme_show_error("could not identify controller");
		return -ENODEV;
	}

	cfg.log_entries = min(cfg.log_entries, le16_to_cpu(ctrl->endgidmax));
	log_size = sizeof(__u64) + cfg.log_entries * sizeof(__u16);

	endurance_log = nvme_alloc(log_size);
	if (!endurance_log)
		return -ENOMEM;

	err = nvme_cli_get_log_endurance_grp_evt(dev, cfg.rae, 0, log_size,
						 endurance_log);
	if (!err)
		nvme_show_endurance_group_event_agg_log(endurance_log, cfg.log_entries, log_size,
							dev->name, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("endurance group event aggregate log page: %s",
				nvme_strerror(errno));

	return err;
}

static int get_lba_status_log(int argc, char **argv,
		struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Retrieve Get LBA Status Info Log and prints it,\n"
		"for the given device in either decoded format(default),json or binary.";

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	_cleanup_free_ void *lba_status = NULL;
	enum nvme_print_flags flags;
	__u32 lslplen;
	int err;

	struct config {
		bool	rae;
	};

	struct config cfg = {
		.rae		= false,
	};

	NVME_ARGS(opts,
		  OPT_FLAG("rae",          'r', &cfg.rae,           rae));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(output_format_val, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	err = nvme_cli_get_log_lba_status(dev, true, 0, sizeof(__u32),
					  &lslplen);
	if (err < 0) {
		nvme_show_error("lba status log page: %s", nvme_strerror(errno));
		return err;
	} else if (err) {
		nvme_show_status(err);
		return err;
	}

	lba_status = nvme_alloc(lslplen);
	if (!lba_status)
		return -ENOMEM;

	err = nvme_cli_get_log_lba_status(dev, cfg.rae, 0, lslplen, lba_status);
	if (!err)
		nvme_show_lba_status_log(lba_status, lslplen, dev->name, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("lba status log page: %s", nvme_strerror(errno));

	return err;
}

static int get_resv_notif_log(int argc, char **argv,
	struct command *cmd, struct plugin *plugin)
{

	const char *desc = "Retrieve Reservation Notification\n"
		"log page and prints it, for the given\n"
		"device in either decoded format(default), json or binary.";

	_cleanup_free_ struct nvme_resv_notification_log *resv = NULL;
	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	enum nvme_print_flags flags;
	int err;

	NVME_ARGS(opts);

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(output_format_val, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	resv = nvme_alloc(sizeof(*resv));
	if (!resv)
		return -ENOMEM;

	err = nvme_cli_get_log_reservation(dev, false, resv);
	if (!err)
		nvme_show_resv_notif_log(resv, dev->name, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("resv notifi log: %s", nvme_strerror(errno));

	return err;

}

static int get_boot_part_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Retrieve Boot Partition\n"
		"log page and prints it, for the given\n"
		"device in either decoded format(default), json or binary.";
	const char *fname = "boot partition data output file name";

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	_cleanup_free_ struct nvme_boot_partition *boot = NULL;
	_cleanup_free_ __u8 *bp_log = NULL;
	enum nvme_print_flags flags;
	int err = -1;
	_cleanup_file_ int output = -1;
	__u32 bpsz = 0;

	struct config {
		__u8	lsp;
		char	*file_name;
	};

	struct config cfg = {
		.lsp		= 0,
		.file_name	= NULL,
	};

	NVME_ARGS(opts,
		  OPT_BYTE("lsp",          's', &cfg.lsp,           lsp),
		  OPT_FILE("output-file",  'f', &cfg.file_name,     fname));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(output_format_val, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (!cfg.file_name) {
		nvme_show_error("Please provide an output file!");
		return -1;
	}

	if (cfg.lsp > 127) {
		nvme_show_error("invalid lsp param: %u", cfg.lsp);
		return -1;
	}

	output = open(cfg.file_name, O_WRONLY | O_CREAT | O_TRUNC, 0666);
	if (output < 0) {
		nvme_show_error("Failed to open output file %s: %s!",
				cfg.file_name, strerror(errno));
		return output;
	}

	boot = nvme_alloc(sizeof(*boot));
	if (!boot)
		return -ENOMEM;

	err = nvme_cli_get_log_boot_partition(dev, false, cfg.lsp,
					      sizeof(*boot), boot);
	if (err < 0) {
		nvme_show_error("boot partition log: %s", nvme_strerror(errno));
		return err;
	} else if (err) {
		nvme_show_status(err);
		return err;
	}

	bpsz = (boot->bpinfo & 0x7fff) * 128 * 1024;
	bp_log = nvme_alloc(sizeof(*boot) + bpsz);
	if (!bp_log)
		return -ENOMEM;

	err = nvme_cli_get_log_boot_partition(dev, false, cfg.lsp,
					      sizeof(*boot) + bpsz,
					      (struct nvme_boot_partition *)bp_log);
	if (!err)
		nvme_show_boot_part_log(&bp_log, dev->name, sizeof(*boot) + bpsz, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("boot partition log: %s", nvme_strerror(errno));

	err = write(output, (void *) bp_log + sizeof(*boot), bpsz);
	if (err != bpsz)
		fprintf(stderr, "Failed to flush all data to file!\n");
	else
		printf("Data flushed into file %s\n", cfg.file_name);
	err = 0;

	return err;
}

static int get_phy_rx_eom_log(int argc, char **argv, struct command *cmd,
		struct plugin *plugin)
{
	const char *desc = "Retrieve Physical Interface Receiver Eye Opening\n"
		"Measurement log for the given device in decoded format\n"
		"(default), json or binary.";
	const char *controller = "Target Controller ID.";
	_cleanup_free_ struct nvme_phy_rx_eom_log *phy_rx_eom_log = NULL;
	size_t phy_rx_eom_log_len;
	enum nvme_print_flags flags;
	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	int err = -1;
	__u8 lsp_tmp;

	struct config {
		__u8	lsp;
		__u16	controller;
	};

	struct config cfg = {
		.lsp		= 0,
		.controller	= NVME_LOG_LSI_NONE,
	};

	NVME_ARGS(opts,
		  OPT_BYTE("lsp",        's', &cfg.lsp,        lsp),
		  OPT_SHRT("controller", 'c', &cfg.controller, controller));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(output_format_val, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.lsp > 127) {
		nvme_show_error("invalid lsp param: %u", cfg.lsp);
		return -1;
	} else if ((cfg.lsp & 3) == 3) {
		nvme_show_error("invalid measurement quality: %u", cfg.lsp & 3);
		return -1;
	} else if ((cfg.lsp & 12) == 12) {
		nvme_show_error("invalid action: %u", cfg.lsp & 12);
		return -1;
	}

	/* Fetching header to calculate total log length */
	phy_rx_eom_log_len = sizeof(struct nvme_phy_rx_eom_log);
	phy_rx_eom_log = nvme_alloc(phy_rx_eom_log_len);
	if (!phy_rx_eom_log)
		return -ENOMEM;

	/* Just read measurement, take given action when fetching full log */
	lsp_tmp = cfg.lsp & 0xf3;

	err = nvme_cli_get_log_phy_rx_eom(dev, lsp_tmp, cfg.controller, phy_rx_eom_log_len,
					  phy_rx_eom_log);
	if (err) {
		if (err > 0)
			nvme_show_status(err);
		else
			nvme_show_error("phy-rx-eom-log: %s", nvme_strerror(errno));

		return err;
	}

	if (phy_rx_eom_log->eomip == NVME_PHY_RX_EOM_COMPLETED)
		phy_rx_eom_log_len = le16_to_cpu(phy_rx_eom_log->hsize) +
				     le32_to_cpu(phy_rx_eom_log->dsize) *
				     le16_to_cpu(phy_rx_eom_log->nd);
	else
		phy_rx_eom_log_len = le16_to_cpu(phy_rx_eom_log->hsize);

	phy_rx_eom_log = nvme_realloc(phy_rx_eom_log, phy_rx_eom_log_len);
	if (!phy_rx_eom_log)
		return -ENOMEM;

	err = nvme_cli_get_log_phy_rx_eom(dev, cfg.lsp, cfg.controller, phy_rx_eom_log_len,
					  phy_rx_eom_log);
	if (!err)
		nvme_show_phy_rx_eom_log(phy_rx_eom_log, cfg.controller, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("phy-rx-eom-log: %s", nvme_strerror(errno));

	return err;
}

static int get_media_unit_stat_log(int argc, char **argv, struct command *cmd,
				   struct plugin *plugin)
{
	const char *desc = "Retrieve the configuration and wear of media units and print it";

	_cleanup_free_ struct nvme_media_unit_stat_log *mus = NULL;
	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	enum nvme_print_flags flags;
	int err = -1;

	struct config {
		__u16	domainid;
		bool	raw_binary;
	};

	struct config cfg = {
		.domainid	= 0,
		.raw_binary	= false,
	};

	NVME_ARGS(opts,
		  OPT_UINT("domain-id",     'd', &cfg.domainid, domainid),
		  OPT_FLAG("raw-binary",    'b', &cfg.raw_binary, raw_use));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(output_format_val, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.raw_binary)
		flags = BINARY;

	mus = nvme_alloc(sizeof(*mus));
	if (!mus)
		return -ENOMEM;

	err = nvme_cli_get_log_media_unit_stat(dev, cfg.domainid, mus);
	if (!err)
		nvme_show_media_unit_stat_log(mus, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("media unit status log: %s", nvme_strerror(errno));

	return err;
}

static int get_supp_cap_config_log(int argc, char **argv, struct command *cmd,
				   struct plugin *plugin)
{
	const char *desc = "Retrieve the list of Supported Capacity Configuration Descriptors";

	_cleanup_free_ struct nvme_supported_cap_config_list_log *cap_log = NULL;
	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	enum nvme_print_flags flags;
	int err = -1;

	struct config {
		__u16	domainid;
		bool	raw_binary;
	};

	struct config cfg = {
		.domainid	= 0,
		.raw_binary	= false,
	};

	NVME_ARGS(opts,
		  OPT_UINT("domain-id",     'd', &cfg.domainid,       domainid),
		  OPT_FLAG("raw-binary",    'b', &cfg.raw_binary,     raw_use));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(output_format_val, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.raw_binary)
		flags = BINARY;

	cap_log = nvme_alloc(sizeof(*cap_log));
	if (!cap_log)
		return -ENOMEM;

	err = nvme_cli_get_log_support_cap_config_list(dev, cfg.domainid,
						       cap_log);
	if (!err)
		nvme_show_supported_cap_config_log(cap_log, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_perror("supported capacity configuration list log");

	return err;
}

static int io_mgmt_send(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "I/O Management Send";
	const char *data = "optional file for data (default stdin)";

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	_cleanup_free_ void *buf = NULL;
	int err = -1;
	int dfd = STDIN_FILENO;

	struct config {
		__u16 mos;
		__u8  mo;
		__u32 namespace_id;
		char  *file;
		__u32 data_len;
	};

	struct config cfg = {
		.mos = 0,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id",  'n', &cfg.namespace_id,   namespace_id_desired),
		  OPT_SHRT("mos",           's', &cfg.mos,            mos),
		  OPT_BYTE("mo",            'm', &cfg.mo,             mo),
		  OPT_FILE("data",          'd', &cfg.file,           data),
		  OPT_UINT("data-len",      'l', &cfg.data_len,       buf_len));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	if (!cfg.namespace_id) {
		err = nvme_get_nsid(dev_fd(dev), &cfg.namespace_id);
		if (err < 0) {
			nvme_show_perror("get-namespace-id");
			return err;
		}
	}

	if (cfg.data_len) {
		buf = nvme_alloc(cfg.data_len);
		if (!buf)
			return -ENOMEM;
	}

	if (cfg.file) {
		dfd = open(cfg.file, O_RDONLY);
		if (dfd < 0) {
			nvme_show_perror(cfg.file);
			return -errno;
		}
	}

	err = read(dfd, buf, cfg.data_len);
	if (err < 0) {
		nvme_show_perror("read");
		goto close_fd;
	}

	struct nvme_io_mgmt_send_args args = {
		.args_size	= sizeof(args),
		.fd		= dev_fd(dev),
		.nsid		= cfg.namespace_id,
		.mos		= cfg.mos,
		.mo		= cfg.mo,
		.data_len	= cfg.data_len,
		.data		= buf,
		.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
	};

	err = nvme_io_mgmt_send(&args);
	if (!err)
		printf("io-mgmt-send: Success, mos:%u mo:%u nsid:%d\n",
			cfg.mos, cfg.mo, cfg.namespace_id);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_perror("io-mgmt-send");

close_fd:
	if (cfg.file)
		close(dfd);
	return err;
}

static int io_mgmt_recv(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "I/O Management Receive";
	const char *data = "optional file for data (default stdout)";

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	_cleanup_free_ void *buf = NULL;
	int err = -1;
	_cleanup_file_ int dfd = -1;

	struct config {
		__u16 mos;
		__u8  mo;
		__u32 namespace_id;
		char  *file;
		__u32 data_len;
	};

	struct config cfg = {
		.mos = 0,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id",  'n', &cfg.namespace_id,   namespace_id_desired),
		  OPT_SHRT("mos",           's', &cfg.mos,            mos),
		  OPT_BYTE("mo",            'm', &cfg.mo,             mo),
		  OPT_FILE("data",          'd', &cfg.file,           data),
		  OPT_UINT("data-len",      'l', &cfg.data_len,       buf_len));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	if (!cfg.namespace_id) {
		err = nvme_get_nsid(dev_fd(dev), &cfg.namespace_id);
		if (err < 0) {
			nvme_show_perror("get-namespace-id");
			return err;
		}
	}

	if (cfg.data_len) {
		buf = nvme_alloc(cfg.data_len);
		if (!buf)
			return -ENOMEM;
	}

	struct nvme_io_mgmt_recv_args args = {
		.args_size	= sizeof(args),
		.fd		= dev_fd(dev),
		.nsid		= cfg.namespace_id,
		.mos		= cfg.mos,
		.mo		= cfg.mo,
		.data_len	= cfg.data_len,
		.data		= buf,
		.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
	};

	err = nvme_io_mgmt_recv(&args);
	if (!err) {
		printf("io-mgmt-recv: Success, mos:%u mo:%u nsid:%d\n",
			cfg.mos, cfg.mo, cfg.namespace_id);

		if (cfg.file) {
			dfd = open(cfg.file, O_WRONLY | O_CREAT, 0644);
			if (dfd < 0) {
				nvme_show_perror(cfg.file);
				return -errno;
			}

			err = write(dfd, buf, cfg.data_len);
			if (err < 0) {
				nvme_show_perror("write");
				return -errno;
			}
		} else {
			d((unsigned char *)buf, cfg.data_len, 16, 1);
		}
	} else if (err > 0) {
		nvme_show_status(err);
	} else {
		nvme_show_perror("io-mgmt-recv");
	}

	return err;
}

static int get_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Retrieve desired number of bytes\n"
		"from a given log on a specified device in either\n"
		"hex-dump (default) or binary format";
	const char *log_id = "identifier of log to retrieve";
	const char *log_len = "how many bytes to retrieve";
	const char *aen = "result of the aen, use to override log id";
	const char *lpo = "log page offset specifies the location within a log page from where to start returning data";
	const char *lsi = "log specific identifier specifies an identifier that is required for a particular log page";
	const char *raw = "output in raw format";
	const char *offset_type = "offset type";
	const char *xfer_len = "read chunk size (default 4k)";

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	_cleanup_free_ unsigned char *log = NULL;
	int err;

	struct config {
		__u32	namespace_id;
		__u8	log_id;
		__u32	log_len;
		__u32	aen;
		__u64	lpo;
		__u8	lsp;
		__u16	lsi;
		bool	rae;
		__u8	uuid_index;
		bool	raw_binary;
		__u8	csi;
		bool	ot;
		__u32	xfer_len;
	};

	struct config cfg = {
		.namespace_id	= NVME_NSID_ALL,
		.log_id		= 0xff,
		.log_len	= 0,
		.aen		= 0,
		.lpo		= NVME_LOG_LPO_NONE,
		.lsp		= NVME_LOG_LSP_NONE,
		.lsi		= NVME_LOG_LSI_NONE,
		.rae		= false,
		.uuid_index	= NVME_UUID_NONE,
		.raw_binary	= false,
		.csi		= NVME_CSI_NVM,
		.ot		= false,
		.xfer_len	= 4096,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_desired),
		  OPT_BYTE("log-id",       'i', &cfg.log_id,       log_id),
		  OPT_UINT("log-len",      'l', &cfg.log_len,      log_len),
		  OPT_UINT("aen",          'a', &cfg.aen,          aen),
		  OPT_SUFFIX("lpo",        'L', &cfg.lpo,          lpo),
		  OPT_BYTE("lsp",          's', &cfg.lsp,          lsp),
		  OPT_SHRT("lsi",          'S', &cfg.lsi,          lsi),
		  OPT_FLAG("rae",          'r', &cfg.rae,          rae),
		  OPT_BYTE("uuid-index",   'U', &cfg.uuid_index,   uuid_index),
		  OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,   raw),
		  OPT_BYTE("csi",          'y', &cfg.csi,          csi),
		  OPT_FLAG("ot",           'O', &cfg.ot,           offset_type),
		  OPT_UINT("xfer-len",     'x', &cfg.xfer_len,     xfer_len));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	if (cfg.aen) {
		cfg.log_len = 4096;
		cfg.log_id = (cfg.aen >> 16) & 0xff;
	}

	if (!cfg.log_len || cfg.log_len & 0x3) {
		nvme_show_error("non-zero or non-dw alignment log-len is required param");
		return -EINVAL;
	}

	if (cfg.lsp > 127) {
		nvme_show_error("invalid lsp param");
		return -EINVAL;
	}

	if (cfg.uuid_index > 127) {
		nvme_show_error("invalid uuid index param");
		return -EINVAL;
	}

	if (cfg.xfer_len == 0 || cfg.xfer_len % 4096) {
		nvme_show_error("xfer-len argument invalid. It needs to be multiple of 4k");
		return -EINVAL;
	}

	log = nvme_alloc(cfg.log_len);
	if (!log)
		return -ENOMEM;

	struct nvme_get_log_args args = {
		.args_size	= sizeof(args),
		.lid		= cfg.log_id,
		.nsid		= cfg.namespace_id,
		.lpo		= cfg.lpo,
		.lsp		= cfg.lsp,
		.lsi		= cfg.lsi,
		.rae		= cfg.rae,
		.uuidx		= cfg.uuid_index,
		.csi		= cfg.csi,
		.ot		= cfg.ot,
		.len		= cfg.log_len,
		.log		= log,
		.result		= NULL,
	};
	err = nvme_cli_get_log_page(dev, cfg.xfer_len, &args);
	if (!err) {
		if (!cfg.raw_binary) {
			printf("Device:%s log-id:%d namespace-id:%#x\n", dev->name, cfg.log_id,
			       cfg.namespace_id);
			d(log, cfg.log_len, 16, 1);
		} else {
			d_raw((unsigned char *)log, cfg.log_len);
		}
	} else if (err > 0) {
		nvme_show_status(err);
	} else {
		nvme_show_error("log page: %s", nvme_strerror(errno));
	}

	return err;
}

static int sanitize_log(int argc, char **argv, struct command *command, struct plugin *plugin)
{
	const char *desc = "Retrieve sanitize log and show it.";

	_cleanup_free_ struct nvme_sanitize_log_page *sanitize_log = NULL;
	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	enum nvme_print_flags flags;
	int err;

	struct config {
		bool	rae;
		bool	human_readable;
		bool	raw_binary;
	};

	struct config cfg = {
		.rae		= false,
		.human_readable	= false,
		.raw_binary	= false,
	};

	NVME_ARGS(opts,
		  OPT_FLAG("rae",            'r', &cfg.rae,            rae),
		  OPT_FLAG("human-readable", 'H', &cfg.human_readable, human_readable_log),
		  OPT_FLAG("raw-binary",     'b', &cfg.raw_binary,     raw_log));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(output_format_val, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.raw_binary)
		flags = BINARY;

	if (cfg.human_readable)
		flags |= VERBOSE;

	sanitize_log = nvme_alloc(sizeof(*sanitize_log));
	if (!sanitize_log)
		return -ENOMEM;

	err = nvme_cli_get_log_sanitize(dev, cfg.rae, sanitize_log);
	if (!err)
		nvme_show_sanitize_log(sanitize_log, dev->name, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("sanitize status log: %s", nvme_strerror(errno));

	return err;
}

static int get_fid_support_effects_log(int argc, char **argv, struct command *cmd,
	struct plugin *plugin)
{
	const char *desc = "Retrieve FID Support and Effects log and show it.";

	_cleanup_free_ struct nvme_fid_supported_effects_log *fid_support_log = NULL;
	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	enum nvme_print_flags flags;
	int err = -1;

	struct config {
		bool	human_readable;
	};

	struct config cfg = {
		.human_readable	= false,
	};

	NVME_ARGS(opts,
		  OPT_FLAG("human-readable", 'H', &cfg.human_readable, human_readable_log));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(output_format_val, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.human_readable)
		flags |= VERBOSE;

	fid_support_log = nvme_alloc(sizeof(*fid_support_log));
	if (!fid_support_log)
		return -ENOMEM;

	err = nvme_cli_get_log_fid_supported_effects(dev, false, fid_support_log);
	if (!err)
		nvme_show_fid_support_effects_log(fid_support_log, dev->name, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("fid support effects log: %s", nvme_strerror(errno));

	return err;
}

static int get_mi_cmd_support_effects_log(int argc, char **argv, struct command *cmd,
	struct plugin *plugin)
{
	const char *desc = "Retrieve NVMe-MI Command Support and Effects log and show it.";

	_cleanup_free_ struct nvme_mi_cmd_supported_effects_log *mi_cmd_support_log = NULL;
	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	enum nvme_print_flags flags;
	int err = -1;

	struct config {
		bool	human_readable;
	};

	struct config cfg = {
		.human_readable	= false,
	};

	NVME_ARGS(opts,
		  OPT_FLAG("human-readable", 'H', &cfg.human_readable, human_readable_log));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(output_format_val, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.human_readable)
		flags |= VERBOSE;

	mi_cmd_support_log = nvme_alloc(sizeof(*mi_cmd_support_log));
	if (!mi_cmd_support_log)
		return -ENOMEM;

	err = nvme_cli_get_log_mi_cmd_supported_effects(dev, false, mi_cmd_support_log);
	if (!err)
		nvme_show_mi_cmd_support_effects_log(mi_cmd_support_log, dev->name, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("mi command support effects log: %s", nvme_strerror(errno));

	return err;
}

static int list_ctrl(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Show controller list information for the subsystem the\n"
		"given device is part of, or optionally controllers attached to a specific namespace.";
	const char *controller = "controller to display";

	_cleanup_free_ struct nvme_ctrl_list *cntlist = NULL;
	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	enum nvme_print_flags flags;
	int err;

	struct config {
		__u16	cntid;
		__u32	namespace_id;
	};

	struct config cfg = {
		.cntid		= 0,
		.namespace_id	= NVME_NSID_NONE,
	};

	NVME_ARGS(opts,
		  OPT_SHRT("cntid",        'c', &cfg.cntid,         controller),
		  OPT_UINT("namespace-id", 'n', &cfg.namespace_id,  namespace_id_optional));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(output_format_val, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	cntlist = nvme_alloc(sizeof(*cntlist));
	if (!cntlist)
		return -ENOMEM;

	if (cfg.namespace_id == NVME_NSID_NONE)
		err = nvme_cli_identify_ctrl_list(dev, cfg.cntid, cntlist);
	else
		err = nvme_cli_identify_nsid_ctrl_list(dev, cfg.namespace_id,
							cfg.cntid, cntlist);
	if (!err)
		nvme_show_list_ctrl(cntlist, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("id controller list: %s", nvme_strerror(errno));

	return err;
}

static int list_ns(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "For the specified controller handle, show the\n"
		"namespace list in the associated NVMe subsystem, optionally starting with a given nsid.";
	const char *namespace_id = "first nsid returned list should start from";
	const char *csi = "I/O command set identifier";
	const char *all = "show all namespaces in the subsystem, whether attached or inactive";

	_cleanup_free_ struct nvme_ns_list *ns_list = NULL;
	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	enum nvme_print_flags flags;
	int err;

	struct config {
		__u32	namespace_id;
		int	csi;
		bool	all;
	};

	struct config cfg = {
		.namespace_id	= 1,
		.csi		= -1,
		.all		= false,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id", 'n', &cfg.namespace_id,  namespace_id),
		  OPT_INT("csi",           'y', &cfg.csi,           csi),
		  OPT_FLAG("all",          'a', &cfg.all,           all));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(output_format_val, &flags);
	if (err < 0 || (flags != JSON && flags != NORMAL)) {
		nvme_show_error("Invalid output format");
		return -EINVAL;
	}

	if (!cfg.namespace_id) {
		nvme_show_error("invalid nsid parameter");
		return -EINVAL;
	}

	ns_list = nvme_alloc(sizeof(*ns_list));
	if (!ns_list)
		return -ENOMEM;

	struct nvme_identify_args args = {
		.args_size	= sizeof(args),
		.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
		.data		= ns_list,
		.nsid		= cfg.namespace_id - 1.
	};
	if (cfg.csi < 0) {
		args.cns = cfg.all ? NVME_IDENTIFY_CNS_ALLOCATED_NS_LIST :
			NVME_IDENTIFY_CNS_NS_ACTIVE_LIST;
	} else {
		args.cns = cfg.all ? NVME_IDENTIFY_CNS_CSI_ALLOCATED_NS_LIST :
			NVME_IDENTIFY_CNS_CSI_NS_ACTIVE_LIST;
		args.csi = cfg.csi;
	}

	err = nvme_cli_identify(dev, &args);
	if (!err)
		nvme_show_list_ns(ns_list, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("id namespace list: %s", nvme_strerror(errno));

	return err;
}

static int id_ns_lba_format(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Send an Identify Namespace command to the given\n"
		"device, returns capability field properties of the specified\n"
		"LBA Format index in  various formats.";

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	_cleanup_free_ struct nvme_id_ns *ns = NULL;
	enum nvme_print_flags flags;
	int err = -1;

	struct config {
		__u16	lba_format_index;
		__u8	uuid_index;
	};

	struct config cfg = {
		.lba_format_index	= 0,
		.uuid_index		= NVME_UUID_NONE,
	};

	NVME_ARGS(opts,
		  OPT_UINT("lba-format-index", 'i', &cfg.lba_format_index, lba_format_index),
		  OPT_BYTE("uuid-index",       'U', &cfg.uuid_index,       uuid_index));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(output_format_val, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (argconfig_parse_seen(opts, "verbose"))
		flags |= VERBOSE;

	ns = nvme_alloc(sizeof(*ns));
	if (!ns)
		return -ENOMEM;

	err = nvme_identify_ns_csi_user_data_format(dev_fd(dev),
						    cfg.lba_format_index,
						    cfg.uuid_index, NVME_CSI_NVM, ns);
	if (!err)
		nvme_show_id_ns(ns, 0, cfg.lba_format_index, true, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_perror("identify namespace for specific LBA format");

	return err;
}

static int id_endurance_grp_list(int argc, char **argv, struct command *cmd,
	struct plugin *plugin)
{
	const char *desc = "Show endurance group list information for the given endurance group id";
	const char *endurance_grp_id = "Endurance Group ID";

	_cleanup_free_ struct nvme_id_endurance_group_list *endgrp_list = NULL;
	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	enum nvme_print_flags flags;
	int err = -1;

	struct config {
		__u16	endgrp_id;
	};

	struct config cfg = {
		.endgrp_id	= 0,
	};

	NVME_ARGS(opts,
		  OPT_SHRT("endgrp-id",    'i', &cfg.endgrp_id,     endurance_grp_id));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(output_format_val, &flags);
	if (err < 0 || (flags != JSON && flags != NORMAL)) {
		nvme_show_error("invalid output format");
		return -EINVAL;
	}

	endgrp_list = nvme_alloc(sizeof(*endgrp_list));
	if (!endgrp_list)
		return -ENOMEM;

	err = nvme_identify_endurance_group_list(dev_fd(dev), cfg.endgrp_id, endgrp_list);
	if (!err)
		nvme_show_endurance_group_list(endgrp_list, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("Id endurance group list: %s", nvme_strerror(errno));

	return err;
}

static int delete_ns(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Delete the given namespace by\n"
		"sending a namespace management command to\n"
		"the provided device. All controllers should be detached from\n"
		"the namespace prior to namespace deletion. A namespace ID\n"
		"becomes inactive when that namespace is detached or, if\n"
		"the namespace is not already inactive, once deleted.";
	const char *namespace_id = "namespace to delete";

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	int err;

	struct config {
		__u32	namespace_id;
		__u32	timeout;
	};

	struct config cfg = {
		.namespace_id	= 0,
		.timeout	= 120000,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id),
		  OPT_UINT("timeout",      't', &cfg.timeout,      timeout));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	if (!cfg.namespace_id) {
		err = nvme_get_nsid(dev_fd(dev), &cfg.namespace_id);
		if (err < 0) {
			nvme_show_error("get-namespace-id: %s", nvme_strerror(errno));
			return err;
		}
	}

	err = nvme_cli_ns_mgmt_delete(dev, cfg.namespace_id);
	if (!err)
		printf("%s: Success, deleted nsid:%d\n", cmd->name, cfg.namespace_id);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("delete namespace: %s", nvme_strerror(errno));

	return err;
}

static int nvme_attach_ns(int argc, char **argv, int attach, const char *desc, struct command *cmd)
{
	_cleanup_free_ struct nvme_ctrl_list *cntlist = NULL;
	_cleanup_free_ __u16 *ctrlist = NULL;
	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	int err, num, i, list[2048];

	const char *namespace_id = "namespace to attach";
	const char *cont = "optional comma-sep controller id list";

	struct config {
		__u32	namespace_id;
		char	*cntlist;
	};

	struct config cfg = {
		.namespace_id	= 0,
		.cntlist	= "",
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id),
		  OPT_LIST("controllers",  'c', &cfg.cntlist,      cont));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	if (!cfg.namespace_id) {
		nvme_show_error("%s: namespace-id parameter required", cmd->name);
		return -EINVAL;
	}

	num = argconfig_parse_comma_sep_array(cfg.cntlist, list, 2047);
	if (!num)
		fprintf(stderr, "warning: empty controller-id list will result in no actual change in namespace attachment\n");

	if (num == -1) {
		nvme_show_error("%s: controller id list is malformed", cmd->name);
		return -EINVAL;
	}

	cntlist = nvme_alloc(sizeof(*cntlist));
	if (!cntlist)
		return -ENOMEM;

	ctrlist = nvme_alloc(sizeof(*ctrlist) * 2048);
	if (!ctrlist)
		return -ENOMEM;

	for (i = 0; i < num; i++)
		ctrlist[i] = (__u16)list[i];

	nvme_init_ctrl_list(cntlist, num, ctrlist);

	if (attach)
		err = nvme_cli_ns_attach_ctrls(dev, cfg.namespace_id,
					       cntlist);
	else
		err = nvme_cli_ns_detach_ctrls(dev, cfg.namespace_id,
					       cntlist);

	if (!err)
		printf("%s: Success, nsid:%d\n", cmd->name, cfg.namespace_id);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_perror(attach ? "attach namespace" : "detach namespace");

	return err;
}

static int attach_ns(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Attach the given namespace to the\n"
		"given controller or comma-sep list of controllers. ID of the\n"
		"given namespace becomes active upon attachment to a\n"
		"controller. A namespace must be attached to a controller\n"
		"before IO commands may be directed to that namespace.";

	return nvme_attach_ns(argc, argv, 1, desc, cmd);
}

static int detach_ns(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Detach the given namespace from the\n"
		"given controller; de-activates the given namespace's ID. A\n"
		"namespace must be attached to a controller before IO\n"
		"commands may be directed to that namespace.";

	return nvme_attach_ns(argc, argv, 0, desc, cmd);
}

static int parse_lba_num_si(struct nvme_dev *dev, const char *opt,
			    const char *val, __u8 flbas, __u64 *num)
{
	_cleanup_free_ struct nvme_ns_list *ns_list = NULL;
	_cleanup_free_ struct nvme_id_ctrl *ctrl = NULL;
	_cleanup_free_ struct nvme_id_ns *ns = NULL;
	__u32 nsid = 1;
	char *endptr;
	int err = -EINVAL;
	int i;
	int lbas;

	struct nvme_identify_args args = {
		.args_size	= sizeof(args),
		.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
		.cns		= NVME_IDENTIFY_CNS_NS_ACTIVE_LIST,
		.nsid		= nsid - 1.
	};

	if (!val)
		return 0;

	if (*num) {
		nvme_show_error(
		    "Invalid specification of both %s and its SI argument, please specify only one",
		    opt);
		return err;
	}

	ctrl = nvme_alloc(sizeof(*ctrl));
	if (!ctrl)
		return -ENOMEM;

	err = nvme_cli_identify_ctrl(dev, ctrl);
	if (err) {
		if (err < 0)
			nvme_show_error("identify controller: %s", nvme_strerror(errno));
		else
			nvme_show_status(err);
		return err;
	}

	ns_list = nvme_alloc(sizeof(*ns_list));
	if (!ns_list)
		return -ENOMEM;
	args.data = ns_list;

	if ((ctrl->oacs & 0x8) >> 3)
		nsid = NVME_NSID_ALL;
	else {
		err = nvme_cli_identify(dev, &args);
		if (err) {
			if (err < 0)
				nvme_show_error("identify namespace list: %s",
						nvme_strerror(errno));
			else
				nvme_show_status(err);
			return err;
		}
		nsid = le32_to_cpu(ns_list->ns[0]);
	}

	ns = nvme_alloc(sizeof(*ns));
	if (!ns)
		return -ENOMEM;

	err = nvme_cli_identify_ns(dev, nsid, ns);
	if (err) {
		if (err < 0)
			nvme_show_error("identify namespace: %s", nvme_strerror(errno));
		else
			nvme_show_status(err);
		return err;
	}

	i = flbas & NVME_NS_FLBAS_LOWER_MASK;
	lbas = (1 << ns->lbaf[i].ds) + ns->lbaf[i].ms;

	if (suffix_si_parse(val, &endptr, (uint64_t *)num)) {
		nvme_show_error("Expected long suffixed integer argument for '%s-si' but got '%s'!",
				opt, val);
		return -errno;
	}

	if (endptr[0] != '\0')
		*num /= lbas;

	return 0;
}

static int create_ns(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Send a namespace management command\n"
		"to the specified device to create a namespace with the given\n"
		"parameters. The next available namespace ID is used for the\n"
		"create operation. Note that create-ns does not attach the\n"
		"namespace to a controller, the attach-ns command is needed.";
	const char *nsze = "size of ns (NSZE)";
	const char *ncap = "capacity of ns (NCAP)";
	const char *flbas =
	    "Formatted LBA size (FLBAS), if entering this value ignore \'block-size\' field";
	const char *dps = "data protection settings (DPS)";
	const char *nmic = "multipath and sharing capabilities (NMIC)";
	const char *anagrpid = "ANA Group Identifier (ANAGRPID)";
	const char *nvmsetid = "NVM Set Identifier (NVMSETID)";
	const char *endgid = "Endurance Group Identifier (ENDGID)";
	const char *csi = "command set identifier (CSI)";
	const char *lbstm = "logical block storage tag mask (LBSTM)";
	const char *nphndls = "Number of Placement Handles (NPHNDLS)";
	const char *bs = "target block size, specify only if \'FLBAS\' value not entered";
	const char *nsze_si = "size of ns (NSZE) in standard SI units";
	const char *ncap_si = "capacity of ns (NCAP) in standard SI units";
	const char *azr = "Allocate ZRWA Resources (AZR) for Zoned Namespace Command Set";
	const char *rar = "Requested Active Resources (RAR) for Zoned Namespace Command Set";
	const char *ror = "Requested Open Resources (ROR) for Zoned Namespace Command Set";
	const char *rnumzrwa =
	    "Requested Number of ZRWA Resources (RNUMZRWA) for Zoned Namespace Command Set";
	const char *phndls = "Comma separated list of Placement Handle Associated RUH";

	_cleanup_free_ struct nvme_ns_mgmt_host_sw_specified *data = NULL;
	_cleanup_free_ struct nvme_id_ns *ns = NULL;
	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	int err = 0, i;
	__u32 nsid;
	uint16_t num_phandle;
	uint16_t phndl[128] = { 0, };

	struct config {
		__u64	nsze;
		__u64	ncap;
		__u8	flbas;
		__u8	dps;
		__u8	nmic;
		__u32	anagrpid;
		__u16	nvmsetid;
		__u16	endgid;
		__u64	bs;
		__u32	timeout;
		__u8	csi;
		__u64	lbstm;
		__u16	nphndls;
		char	*nsze_si;
		char	*ncap_si;
		bool	azr;
		__u32	rar;
		__u32	ror;
		__u32	rnumzrwa;
		char	*phndls;
	};

	struct config cfg = {
		.nsze		= 0,
		.ncap		= 0,
		.flbas		= 0xff,
		.dps		= 0,
		.nmic		= 0,
		.anagrpid	= 0,
		.nvmsetid	= 0,
		.endgid		= 0,
		.bs		= 0x00,
		.timeout	= 120000,
		.csi		= 0,
		.lbstm		= 0,
		.nphndls	= 0,
		.nsze_si	= NULL,
		.ncap_si	= NULL,
		.azr		= false,
		.rar		= 0,
		.ror		= 0,
		.rnumzrwa	= 0,
		.phndls		= "",
	};

	NVME_ARGS(opts,
		  OPT_SUFFIX("nsze",       's', &cfg.nsze,     nsze),
		  OPT_SUFFIX("ncap",       'c', &cfg.ncap,     ncap),
		  OPT_BYTE("flbas",        'f', &cfg.flbas,    flbas),
		  OPT_BYTE("dps",          'd', &cfg.dps,      dps),
		  OPT_BYTE("nmic",         'm', &cfg.nmic,     nmic),
		  OPT_UINT("anagrp-id",    'a', &cfg.anagrpid, anagrpid),
		  OPT_UINT("nvmset-id",    'i', &cfg.nvmsetid, nvmsetid),
		  OPT_UINT("endg-id",      'e', &cfg.endgid,   endgid),
		  OPT_SUFFIX("block-size", 'b', &cfg.bs,       bs),
		  OPT_UINT("timeout",      't', &cfg.timeout,  timeout),
		  OPT_BYTE("csi",          'y', &cfg.csi,      csi),
		  OPT_SUFFIX("lbstm",      'l', &cfg.lbstm,    lbstm),
		  OPT_SHRT("nphndls",      'n', &cfg.nphndls,  nphndls),
		  OPT_STR("nsze-si",       'S', &cfg.nsze_si,  nsze_si),
		  OPT_STR("ncap-si",       'C', &cfg.ncap_si,  ncap_si),
		  OPT_FLAG("azr",          'z', &cfg.azr,      azr),
		  OPT_UINT("rar",          'r', &cfg.rar,      rar),
		  OPT_UINT("ror",          'O', &cfg.ror,      ror),
		  OPT_UINT("rnumzrwa",     'u', &cfg.rnumzrwa, rnumzrwa),
		  OPT_LIST("phndls",       'p', &cfg.phndls,   phndls));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	if (cfg.flbas != 0xff && cfg.bs != 0x00) {
		nvme_show_error(
		    "Invalid specification of both FLBAS and Block Size, please specify only one");
		return -EINVAL;
	}
	if (cfg.bs) {
		if ((cfg.bs & (~cfg.bs + 1)) != cfg.bs) {
			nvme_show_error(
			    "Invalid value for block size (%"PRIu64"). Block size must be a power of two",
			    (uint64_t)cfg.bs);
			return -EINVAL;
		}


		ns = nvme_alloc(sizeof(*ns));
		if (!ns)
			return -ENOMEM;

		err = nvme_cli_identify_ns(dev, NVME_NSID_ALL, ns);
		if (err) {
			if (err < 0) {
				nvme_show_error("identify-namespace: %s", nvme_strerror(errno));
			} else {
				fprintf(stderr, "identify failed\n");
				nvme_show_status(err);
			}
			return err;
		}
		for (i = 0; i <= ns->nlbaf; ++i) {
			if ((1 << ns->lbaf[i].ds) == cfg.bs && ns->lbaf[i].ms == 0) {
				cfg.flbas = i;
				break;
			}
		}

	}
	if (cfg.flbas == 0xff) {
		fprintf(stderr, "FLBAS corresponding to block size %"PRIu64" not found\n",
			(uint64_t)cfg.bs);
		fprintf(stderr, "Please correct block size, or specify FLBAS directly\n");

		return -EINVAL;
	}

	err = parse_lba_num_si(dev, "nsze", cfg.nsze_si, cfg.flbas, &cfg.nsze);
	if (err)
		return err;

	err = parse_lba_num_si(dev, "ncap", cfg.ncap_si, cfg.flbas, &cfg.ncap);
	if (err)
		return err;

	if (cfg.csi != NVME_CSI_ZNS && (cfg.azr || cfg.rar || cfg.ror || cfg.rnumzrwa)) {
		nvme_show_error("Invalid ZNS argument is given (CSI:%#x)", cfg.csi);
		return -EINVAL;
	}

	data = nvme_alloc(sizeof(*data));
	if (!data)
		return -ENOMEM;

	data->nsze = cpu_to_le64(cfg.nsze);
	data->ncap = cpu_to_le64(cfg.ncap);
	data->flbas = cfg.flbas;
	data->dps = cfg.dps;
	data->nmic = cfg.nmic;
	data->anagrpid = cpu_to_le32(cfg.anagrpid);
	data->nvmsetid = cpu_to_le16(cfg.nvmsetid);
	data->endgid = cpu_to_le16(cfg.endgid);
	data->lbstm = cpu_to_le64(cfg.lbstm);
	data->zns.znsco = cfg.azr;
	data->zns.rar = cpu_to_le32(cfg.rar);
	data->zns.ror = cpu_to_le32(cfg.ror);
	data->zns.rnumzrwa = cpu_to_le32(cfg.rnumzrwa);
	data->nphndls = cpu_to_le16(cfg.nphndls);

	num_phandle = argconfig_parse_comma_sep_array_short(cfg.phndls, phndl, ARRAY_SIZE(phndl));
	if (cfg.nphndls != num_phandle) {
		nvme_show_error("Invalid Placement handle list");
		return -EINVAL;
	}

	for (i = 0; i < num_phandle; i++)
		data->phndl[i] = cpu_to_le16(phndl[i]);

	err = nvme_cli_ns_mgmt_create(dev, data, &nsid, cfg.timeout, cfg.csi);
	if (!err)
		printf("%s: Success, created nsid:%d\n", cmd->name, nsid);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("create namespace: %s", nvme_strerror(errno));

	return err;
}

static bool nvme_match_device_filter(nvme_subsystem_t s,
		nvme_ctrl_t c, nvme_ns_t ns, void *f_args)
{
	int ret, instance, nsid, s_num;
	char *devname = f_args;

	if (!devname || !strlen(devname))
		return true;

	ret = sscanf(devname, "nvme%dn%d", &instance, &nsid);
	if (ret != 2)
		return true;

	if (s) {
		ret = sscanf(nvme_subsystem_get_name(s), "nvme-subsys%d",
			     &s_num);
		if (ret == 1 && s_num == instance)
			return true;
	}
	if (c) {
		s = nvme_ctrl_get_subsystem(c);

		ret = sscanf(nvme_subsystem_get_name(s), "nvme-subsys%d",
			     &s_num);
		if (ret == 1 && s_num == instance)
			return true;
	}
	if (ns) {
		if (!strcmp(devname, nvme_ns_get_name(ns)))
			return true;
	}

	return false;
}

static int list_subsys(int argc, char **argv, struct command *cmd,
		struct plugin *plugin)
{
	nvme_root_t r = NULL;
	enum nvme_print_flags flags;
	const char *desc = "Retrieve information for subsystems";
	nvme_scan_filter_t filter = NULL;
	char *devname;
	int err;
	int nsid = NVME_NSID_ALL;

	NVME_ARGS(opts);

	err = argconfig_parse(argc, argv, desc, opts);
	if (err < 0)
		goto ret;

	devname = NULL;
	if (optind < argc)
		devname = basename(argv[optind++]);

	err = validate_output_format(output_format_val, &flags);
	if (err < 0 || (flags != JSON && flags != NORMAL)) {
		nvme_show_error("Invalid output format");
		return -EINVAL;
	}

	if (argconfig_parse_seen(opts, "verbose"))
		flags |= VERBOSE;

	r = nvme_create_root(stderr, map_log_level(!!(flags & VERBOSE), false));
	if (!r) {
		if (devname)
			nvme_show_error("Failed to scan nvme subsystem for %s", devname);
		else
			nvme_show_error("Failed to scan nvme subsystem");
		err = -errno;
		goto ret;
	}

	if (devname) {
		int subsys_num;

		if (sscanf(devname, "nvme%dn%d", &subsys_num, &nsid) != 2) {
			nvme_show_error("Invalid device name %s", devname);
			err = -EINVAL;
			goto ret;
		}
		filter = nvme_match_device_filter;
	}

	err = nvme_scan_topology(r, filter, (void *)devname);
	if (err) {
		nvme_show_error("Failed to scan topology: %s", nvme_strerror(errno));
		goto ret;
	}

	nvme_show_subsystem_list(r, nsid != NVME_NSID_ALL, flags);

ret:
	if (r)
		nvme_free_tree(r);
	return err;
}

static int list(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Retrieve basic information for all NVMe namespaces";
	enum nvme_print_flags flags;
	nvme_root_t r;
	int err = 0;

	NVME_ARGS(opts);

	err = argconfig_parse(argc, argv, desc, opts);
	if (err < 0)
		return err;

	err = validate_output_format(output_format_val, &flags);
	if (err < 0 || (flags != JSON && flags != NORMAL)) {
		nvme_show_error("Invalid output format");
		return -EINVAL;
	}

	if (argconfig_parse_seen(opts, "verbose"))
		flags |= VERBOSE;

	r = nvme_create_root(stderr, map_log_level(!!(flags & VERBOSE), false));
	if (!r) {
		nvme_show_error("Failed to create topology root: %s", nvme_strerror(errno));
		return -errno;
	}
	err = nvme_scan_topology(r, NULL, NULL);
	if (err < 0) {
		nvme_show_error("Failed to scan topology: %s", nvme_strerror(errno));
		nvme_free_tree(r);
		return err;
	}

	nvme_show_list_items(r, flags);
	nvme_free_tree(r);

	return err;
}

int __id_ctrl(int argc, char **argv, struct command *cmd, struct plugin *plugin,
		void (*vs)(__u8 *vs, struct json_object *root))
{
	const char *desc = "Send an Identify Controller command to\n"
		"the given device and report information about the specified\n"
		"controller in human-readable or\n"
		"binary format. May also return vendor-specific\n"
		"controller attributes in hex-dump if requested.";
	const char *vendor_specific = "dump binary vendor field";

	_cleanup_free_ struct nvme_id_ctrl *ctrl = NULL;
	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	enum nvme_print_flags flags;
	int err;

	struct config {
		bool	vendor_specific;
		bool	raw_binary;
		bool	human_readable;
	};

	struct config cfg = {
		.vendor_specific	= false,
		.raw_binary		= false,
		.human_readable		= false,
	};

	NVME_ARGS(opts,
		  OPT_FLAG("vendor-specific", 'V', &cfg.vendor_specific, vendor_specific),
		  OPT_FLAG("raw-binary",      'b', &cfg.raw_binary,      raw_identify),
		  OPT_FLAG("human-readable",  'H', &cfg.human_readable,  human_readable_identify));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(output_format_val, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.raw_binary)
		flags = BINARY;

	if (cfg.vendor_specific)
		flags |= VS;

	if (cfg.human_readable)
		flags |= VERBOSE;

	ctrl = nvme_alloc(sizeof(*ctrl));
	if (!ctrl)
		return -ENOMEM;

	err = nvme_cli_identify_ctrl(dev, ctrl);
	if (!err)
		nvme_show_id_ctrl(ctrl, flags, vs);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("identify controller: %s", nvme_strerror(errno));

	return err;
}

static int id_ctrl(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	return __id_ctrl(argc, argv, cmd, plugin, NULL);
}

static int nvm_id_ctrl(int argc, char **argv, struct command *cmd,
	struct plugin *plugin)
{
	const char *desc = "Send an Identify Controller NVM Command Set\n"
		"command to the given device and report information about\n"
		"the specified controller in various formats.";

	_cleanup_free_ struct nvme_id_ctrl_nvm *ctrl_nvm = NULL;
	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	enum nvme_print_flags flags;
	int err = -1;

	NVME_ARGS(opts);

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(output_format_val, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	ctrl_nvm = nvme_alloc(sizeof(*ctrl_nvm));
	if (!ctrl_nvm)
		return -ENOMEM;

	err = nvme_nvm_identify_ctrl(dev_fd(dev), ctrl_nvm);
	if (!err)
		nvme_show_id_ctrl_nvm(ctrl_nvm, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("nvm identify controller: %s", nvme_strerror(errno));

	return err;
}

static int nvm_id_ns(int argc, char **argv, struct command *cmd,
	struct plugin *plugin)
{
	const char *desc = "Send an Identify Namespace NVM Command Set\n"
		"command to the given device and report information about\n"
		"the specified namespace in various formats.";

	_cleanup_free_ struct nvme_nvm_id_ns *id_ns = NULL;
	_cleanup_free_ struct nvme_id_ns *ns = NULL;
	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	enum nvme_print_flags flags;
	int err = -1;

	struct config {
		__u32	namespace_id;
		__u8	uuid_index;
	};

	struct config cfg = {
		.namespace_id	= 0,
		.uuid_index	= NVME_UUID_NONE,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id", 'n', &cfg.namespace_id,    namespace_id_desired),
		  OPT_BYTE("uuid-index",   'U', &cfg.uuid_index,      uuid_index));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(output_format_val, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (argconfig_parse_seen(opts, "verbose"))
		flags |= VERBOSE;

	if (!cfg.namespace_id) {
		err = nvme_get_nsid(dev_fd(dev), &cfg.namespace_id);
		if (err < 0) {
			nvme_show_perror("get-namespace-id");
			return err;
		}
	}

	ns = nvme_alloc(sizeof(*ns));
	if (!ns)
		return -ENOMEM;

	err = nvme_cli_identify_ns(dev, cfg.namespace_id, ns);
	if (err) {
		nvme_show_status(err);
		return err;
	}

	id_ns = nvme_alloc(sizeof(*id_ns));
	if (!id_ns)
		return -ENOMEM;

	err = nvme_identify_ns_csi(dev_fd(dev), cfg.namespace_id,
				   cfg.uuid_index,
				   NVME_CSI_NVM, id_ns);
	if (!err)
		nvme_show_nvm_id_ns(id_ns, cfg.namespace_id, ns, 0, false, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_perror("nvm identify namespace");

	return err;
}

static int nvm_id_ns_lba_format(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Send an NVM Command Set specific Identify Namespace\n"
		"command to the given device, returns capability field properties of\n"
		"the specified LBA Format index in the specified namespace in various formats.";

	_cleanup_free_ struct nvme_nvm_id_ns *nvm_ns = NULL;
	_cleanup_free_ struct nvme_id_ns *ns = NULL;
	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	enum nvme_print_flags flags;
	int err = -1;

	struct config {
		__u16	lba_format_index;
		__u8	uuid_index;
	};

	struct config cfg = {
		.lba_format_index	= 0,
		.uuid_index		= NVME_UUID_NONE,
	};

	NVME_ARGS(opts,
		  OPT_UINT("lba-format-index", 'i', &cfg.lba_format_index, lba_format_index),
		  OPT_BYTE("uuid-index",       'U', &cfg.uuid_index,       uuid_index));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(output_format_val, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (argconfig_parse_seen(opts, "verbose"))
		flags |= VERBOSE;

	ns = nvme_alloc(sizeof(*ns));
	if (!ns)
		return -ENOMEM;

	err = nvme_cli_identify_ns(dev, NVME_NSID_ALL, ns);
	if (err) {
		ns->nlbaf = NVME_FEAT_LBA_RANGE_MAX - 1;
		ns->nulbaf = 0;
	}

	nvm_ns = nvme_alloc(sizeof(*nvm_ns));
	if (!nvm_ns)
		return -ENOMEM;

	err = nvme_identify_iocs_ns_csi_user_data_format(dev_fd(dev), cfg.lba_format_index,
							 cfg.uuid_index, NVME_CSI_NVM, nvm_ns);
	if (!err)
		nvme_show_nvm_id_ns(nvm_ns, 0, ns, cfg.lba_format_index, true, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_perror("NVM identify namespace for specific LBA format");

	return err;
}

static int ns_descs(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Send Namespace Identification Descriptors command to the\n"
		"given device, returns the namespace identification descriptors\n"
		"of the specific namespace in either human-readable or binary format.";
	const char *raw = "show descriptors in binary format";

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	_cleanup_free_ void *nsdescs = NULL;;
	enum nvme_print_flags flags;
	int err;

	struct config {
		__u32	namespace_id;
		bool	raw_binary;
	};

	struct config cfg = {
		.namespace_id	= 0,
		.raw_binary	= false,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id",  'n', &cfg.namespace_id,  namespace_id_desired),
		  OPT_FLAG("raw-binary",    'b', &cfg.raw_binary,    raw));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(output_format_val, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.raw_binary)
		flags = BINARY;

	if (!cfg.namespace_id) {
		err = nvme_get_nsid(dev_fd(dev), &cfg.namespace_id);
		if (err < 0) {
			nvme_show_error("get-namespace-id: %s", nvme_strerror(errno));
			return err;
		}
	}

	nsdescs = nvme_alloc(sizeof(*nsdescs));
	if (!nsdescs)
		return -ENOMEM;

	err = nvme_cli_identify_ns_descs(dev, cfg.namespace_id, nsdescs);
	if (!err)
		nvme_show_id_ns_descs(nsdescs, cfg.namespace_id, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("identify namespace: %s", nvme_strerror(errno));

	return err;
}

static int id_ns(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Send an Identify Namespace command to the\n"
		"given device, returns properties of the specified namespace\n"
		"in either human-readable or binary format. Can also return\n"
		"binary vendor-specific namespace attributes.";
	const char *force = "Return this namespace, even if not attached (1.2 devices only)";
	const char *vendor_specific = "dump binary vendor fields";

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	_cleanup_free_ struct nvme_id_ns *ns = NULL;
	enum nvme_print_flags flags;
	int err;

	struct config {
		__u32	namespace_id;
		bool	force;
		bool	vendor_specific;
		bool	raw_binary;
		bool	human_readable;
	};

	struct config cfg = {
		.namespace_id		= 0,
		.force			= false,
		.vendor_specific	= false,
		.raw_binary		= false,
		.human_readable		= false,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id",    'n', &cfg.namespace_id,    namespace_id_desired),
		  OPT_FLAG("force",             0, &cfg.force,           force),
		  OPT_FLAG("vendor-specific", 'V', &cfg.vendor_specific, vendor_specific),
		  OPT_FLAG("raw-binary",      'b', &cfg.raw_binary,      raw_identify),
		  OPT_FLAG("human-readable",  'H', &cfg.human_readable,  human_readable_identify));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(output_format_val, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.raw_binary)
		flags = BINARY;

	if (cfg.vendor_specific)
		flags |= VS;

	if (cfg.human_readable)
		flags |= VERBOSE;

	if (!cfg.namespace_id) {
		err = nvme_get_nsid(dev_fd(dev), &cfg.namespace_id);
		if (err < 0) {
			nvme_show_error("get-namespace-id: %s", nvme_strerror(errno));
			return err;
		}
	}

	ns = nvme_alloc(sizeof(*ns));
	if (!ns)
		return -ENOMEM;

	if (cfg.force)
		err = nvme_cli_identify_allocated_ns(dev, cfg.namespace_id, ns);
	else
		err = nvme_cli_identify_ns(dev, cfg.namespace_id, ns);

	if (!err)
		nvme_show_id_ns(ns, cfg.namespace_id, 0, false, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("identify namespace: %s", nvme_strerror(errno));

	return err;
}

static int cmd_set_independent_id_ns(int argc, char **argv, struct command *cmd,
				     struct plugin *plugin)
{
	const char *desc = "Send an I/O Command Set Independent Identify\n"
		"Namespace command to the given device, returns properties of the\n"
		"specified namespace in human-readable or binary or json format.";

	_cleanup_free_ struct nvme_id_independent_id_ns *ns = NULL;
	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	enum nvme_print_flags flags;
	int err = -1;

	struct config {
		__u32	namespace_id;
		bool	raw_binary;
		bool	human_readable;
	};

	struct config cfg = {
		.namespace_id	= 0,
		.raw_binary	= false,
		.human_readable	= false,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id",    'n', &cfg.namespace_id,    namespace_id_desired),
		  OPT_FLAG("raw-binary",      'b', &cfg.raw_binary,      raw_identify),
		  OPT_FLAG("human-readable",  'H', &cfg.human_readable,  human_readable_identify));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(output_format_val, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.raw_binary)
		flags = BINARY;

	if (cfg.human_readable)
		flags |= VERBOSE;

	if (!cfg.namespace_id) {
		err = cfg.namespace_id = nvme_get_nsid(dev_fd(dev), &cfg.namespace_id);
		if (err < 0) {
			nvme_show_perror("get-namespace-id");
			return err;
		}
	}

	ns = nvme_alloc(sizeof(*ns));
	if (!ns)
		return -ENOMEM;

	err = nvme_identify_independent_identify_ns(dev_fd(dev), cfg.namespace_id, ns);
	if (!err)
		nvme_show_cmd_set_independent_id_ns(ns, cfg.namespace_id, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("I/O command set independent identify namespace: %s",
				nvme_strerror(errno));

	return err;
}

static int id_ns_granularity(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Send an Identify Namespace Granularity List command to the\n"
		"given device, returns namespace granularity list\n"
		"in either human-readable or binary format.";

	_cleanup_free_ struct nvme_id_ns_granularity_list *granularity_list = NULL;
	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	enum nvme_print_flags flags;
	int err;

	NVME_ARGS(opts);

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(output_format_val, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	granularity_list = nvme_alloc(NVME_IDENTIFY_DATA_SIZE);
	if (!granularity_list)
		return -ENOMEM;

	err = nvme_identify_ns_granularity(dev_fd(dev), granularity_list);
	if (!err)
		nvme_show_id_ns_granularity_list(granularity_list, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("identify namespace granularity: %s", nvme_strerror(errno));

	return err;
}

static int id_nvmset(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Send an Identify NVM Set List command to the\n"
		"given device, returns entries for NVM Set identifiers greater\n"
		"than or equal to the value specified CDW11.NVMSETID\n"
		"in either binary format or json format";
	const char *nvmset_id = "NVM Set Identify value";

	_cleanup_free_ struct nvme_id_nvmset_list *nvmset = NULL;
	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	enum nvme_print_flags flags;
	int err;

	struct config {
		__u16	nvmset_id;
	};

	struct config cfg = {
		.nvmset_id	= 0,
	};

	NVME_ARGS(opts,
		  OPT_SHRT("nvmset_id",    'i', &cfg.nvmset_id,     nvmset_id));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(output_format_val, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	nvmset = nvme_alloc(sizeof(*nvmset));
	if (!nvmset)
		return -ENOMEM;

	err = nvme_identify_nvmset_list(dev_fd(dev), cfg.nvmset_id, nvmset);
	if (!err)
		nvme_show_id_nvmset(nvmset, cfg.nvmset_id, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("identify nvm set list: %s", nvme_strerror(errno));

	return err;
}

static int id_uuid(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Send an Identify UUID List command to the\n"
		"given device, returns list of supported Vendor Specific UUIDs\n"
		"in either human-readable or binary format.";
	const char *raw = "show uuid in binary format";
	const char *human_readable = "show uuid in readable format";

	_cleanup_free_ struct nvme_id_uuid_list *uuid_list = NULL;
	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	enum nvme_print_flags flags;
	int err;

	struct config {
		bool	raw_binary;
		bool	human_readable;
	};

	struct config cfg = {
		.raw_binary	= false,
		.human_readable	= false,
	};

	NVME_ARGS(opts,
		  OPT_FLAG("raw-binary",     'b', &cfg.raw_binary,     raw),
		  OPT_FLAG("human-readable", 'H', &cfg.human_readable, human_readable));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(output_format_val, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.raw_binary)
		flags = BINARY;

	if (cfg.human_readable)
		flags |= VERBOSE;

	uuid_list = nvme_alloc(sizeof(*uuid_list));
	if (!uuid_list)
		return -ENOMEM;

	err = nvme_identify_uuid(dev_fd(dev), uuid_list);
	if (!err)
		nvme_show_id_uuid_list(uuid_list, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("identify UUID list: %s", nvme_strerror(errno));

	return err;
}

static int id_iocs(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Send an Identify Command Set Data command to\n"
		"the given device, returns properties of the specified controller\n"
		"in either human-readable or binary format.";
	const char *controller_id = "identifier of desired controller";

	_cleanup_free_ struct nvme_id_iocs *iocs = NULL;
	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	int err;

	struct config {
		__u16	cntid;
	};

	struct config cfg = {
		.cntid	= 0xffff,
	};

	NVME_ARGS(opts,
		  OPT_SHRT("controller-id", 'c', &cfg.cntid, controller_id));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	iocs = nvme_alloc(sizeof(*iocs));
	if (!iocs)
		return -ENOMEM;

	err = nvme_identify_iocs(dev_fd(dev), cfg.cntid, iocs);
	if (!err) {
		printf("NVMe Identify I/O Command Set:\n");
		nvme_show_id_iocs(iocs, 0);
	} else if (err > 0) {
		nvme_show_status(err);
	} else {
		nvme_show_error("NVMe Identify I/O Command Set: %s", nvme_strerror(errno));
	}

	return err;
}

static int id_domain(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Send an Identify Domain List command to the\n"
		"given device, returns properties of the specified domain\n"
		"in either normal|json|binary format.";
	const char *domain_id = "identifier of desired domain";

	_cleanup_free_ struct nvme_id_domain_list *id_domain = NULL;
	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	enum nvme_print_flags flags;
	int err;

	struct config {
		__u16	dom_id;
	};

	struct config cfg = {
		.dom_id		= 0xffff,
	};

	NVME_ARGS(opts,
		  OPT_SHRT("dom-id",         'd', &cfg.dom_id,         domain_id));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(output_format_val, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	id_domain = nvme_alloc(sizeof(*id_domain));
	if (!id_domain)
		return -ENOMEM;

	err = nvme_identify_domain_list(dev_fd(dev), cfg.dom_id, id_domain);
	if (!err) {
		printf("NVMe Identify command for Domain List is successful:\n");
		printf("NVMe Identify Domain List:\n");
		nvme_show_id_domain_list(id_domain, flags);
	} else if (err > 0) {
		nvme_show_status(err);
	} else {
		nvme_show_error("NVMe Identify Domain List: %s", nvme_strerror(errno));
	}

	return err;
}

static int get_ns_id(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Get namespace ID of a the block device.";

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	unsigned int nsid;
	int err;

	NVME_ARGS(opts);

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	err = nvme_get_nsid(dev_fd(dev), &nsid);
	if (err < 0) {
		nvme_show_error("get namespace ID: %s", nvme_strerror(errno));
		return -errno;
	}

	printf("%s: namespace-id:%d\n", dev->name, nsid);

	return 0;
}

static int virtual_mgmt(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "The Virtualization Management command is supported by primary controllers\n"
		"that support the Virtualization Enhancements capability. This command is used for:\n"
		"  1. Modifying Flexible Resource allocation for the primary controller\n"
		"  2. Assigning Flexible Resources for secondary controllers\n"
		"  3. Setting the Online and Offline state for secondary controllers";
	const char *cntlid = "Controller Identifier(CNTLID)";
	const char *rt = "Resource Type(RT): [0,1]\n"
		"0h: VQ Resources\n"
		"1h: VI Resources";
	const char *act = "Action(ACT): [1,7,8,9]\n"
		"1h: Primary Flexible\n"
		"7h: Secondary Offline\n"
		"8h: Secondary Assign\n"
		"9h: Secondary Online";
	const char *nr = "Number of Controller Resources(NR)";

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	__u32 result;
	int err;

	struct config {
		__u16	cntlid;
		__u8	rt;
		__u8	act;
		__u16	nr;
	};

	struct config cfg = {
		.cntlid	= 0,
		.rt	= 0,
		.act	= 0,
		.nr	= 0,
	};

	NVME_ARGS(opts,
		  OPT_UINT("cntlid", 'c', &cfg.cntlid, cntlid),
		  OPT_BYTE("rt",     'r', &cfg.rt,     rt),
		  OPT_BYTE("act",    'a', &cfg.act,    act),
		  OPT_SHRT("nr",     'n', &cfg.nr,     nr));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	struct nvme_virtual_mgmt_args args = {
		.args_size	= sizeof(args),
		.fd		= dev_fd(dev),
		.act		= cfg.act,
		.rt		= cfg.rt,
		.cntlid		= cfg.cntlid,
		.nr		= cfg.nr,
		.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
		.result		= &result,
	};
	err = nvme_virtual_mgmt(&args);
	if (!err)
		printf("success, Number of Controller Resources Modified (NRM):%#x\n", result);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("virt-mgmt: %s", nvme_strerror(errno));

	return err;
}

static int primary_ctrl_caps(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *cntlid = "Controller ID";
	const char *desc = "Send an Identify Primary Controller Capabilities\n"
		"command to the given device and report the information in a\n"
		"decoded format (default), json or binary.";

	_cleanup_free_ struct nvme_primary_ctrl_cap *caps = NULL;
	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	enum nvme_print_flags flags;
	int err;

	struct config {
		__u16	cntlid;
		bool	human_readable;
	};

	struct config cfg = {
		.cntlid		= 0,
		.human_readable	= false,
	};

	NVME_ARGS(opts,
		  OPT_UINT("cntlid",         'c', &cfg.cntlid, cntlid),
		  OPT_FLAG("human-readable", 'H', &cfg.human_readable, human_readable_info));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(output_format_val, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.human_readable)
		flags |= VERBOSE;

	caps = nvme_alloc(sizeof(*caps));
	if (!caps)
		return -ENOMEM;

	err = nvme_cli_identify_primary_ctrl(dev, cfg.cntlid, caps);
	if (!err)
		nvme_show_primary_ctrl_cap(caps, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("identify primary controller capabilities: %s",
				nvme_strerror(errno));

	return err;
}

static int list_secondary_ctrl(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc =
	    "Show secondary controller list associated with the primary controller of the given device.";
	const char *controller = "lowest controller identifier to display";
	const char *num_entries = "number of entries to retrieve";

	_cleanup_free_ struct nvme_secondary_ctrl_list *sc_list = NULL;
	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	enum nvme_print_flags flags;
	int err;

	struct config {
		__u16	cntid;
		__u32	num_entries;
	};

	struct config cfg = {
		.cntid		= 0,
		.num_entries	= ARRAY_SIZE(sc_list->sc_entry),
	};

	NVME_ARGS(opts,
		  OPT_SHRT("cntid",        'c', &cfg.cntid,         controller),
		  OPT_UINT("num-entries",  'e', &cfg.num_entries,   num_entries));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(output_format_val, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (!cfg.num_entries) {
		nvme_show_error("non-zero num-entries is required param");
		return -EINVAL;
	}

	sc_list = nvme_alloc(sizeof(*sc_list));
	if (!sc_list)
		return -ENOMEM;

	err = nvme_cli_identify_secondary_ctrl_list(dev, cfg.cntid, sc_list);
	if (!err)
		nvme_show_list_secondary_ctrl(sc_list, cfg.num_entries, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("id secondary controller list: %s", nvme_strerror(errno));

	return err;
}

static void intr_self_test(int signum)
{
	printf("\nInterrupted device self-test operation by %s\n", strsignal(signum));

	errno = EINTR;
}

static int sleep_self_test(unsigned int seconds)
{
	errno = 0;

	sleep(seconds);

	if (errno)
		return -errno;

	return 0;
}

static int wait_self_test(struct nvme_dev *dev)
{
	static const char spin[] = {'-', '\\', '|', '/' };
	_cleanup_free_ struct nvme_self_test_log *log = NULL;
	_cleanup_free_ struct nvme_id_ctrl *ctrl = NULL;
	int err, i = 0, p = 0, cnt = 0;
	int wthr;

	signal(SIGINT, intr_self_test);

	ctrl = nvme_alloc(sizeof(*ctrl));
	if (!ctrl)
		return -ENOMEM;

	log = nvme_alloc(sizeof(*log));
	if (!log)
		return -ENOMEM;

	err = nvme_cli_identify_ctrl(dev, ctrl);
	if (err) {
		nvme_show_error("identify-ctrl: %s", nvme_strerror(errno));
		return err;
	}

	wthr = le16_to_cpu(ctrl->edstt) * 60 / 100 + 60;

	printf("Waiting for self test completion...\n");
	while (true) {
		printf("\r[%.*s%c%.*s] %3d%%", p / 2, dash, spin[i % 4], 49 - p / 2, space, p);
		fflush(stdout);
		err = sleep_self_test(1);
		if (err)
			return err;

		err = nvme_cli_get_log_device_self_test(dev, log);
		if (err) {
			printf("\n");
			if (err < 0)
				perror("self test log\n");
			else
				nvme_show_status(err);
			return err;
		}

		if (++cnt > wthr) {
			nvme_show_error("no progress for %d seconds, stop waiting", wthr);
			return -EIO;
		}

		if (log->completion == 0 && p > 0) {
			printf("\r[%.*s] %3d%%\n", 50, dash, 100);
			break;
		}

		if (log->completion < p) {
			printf("\n");
				nvme_show_error("progress broken");
				return -EIO;
		} else if (log->completion != p) {
			p = log->completion;
			cnt = 0;
		}

		i++;
	}

	return 0;
}

static void abort_self_test(struct nvme_dev_self_test_args *args)
{
	int err;

	args->stc = NVME_DST_STC_ABORT;

	err = nvme_dev_self_test(args);
	if (!err)
		printf("Aborting device self-test operation\n");
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("Device self-test: %s", nvme_strerror(errno));
}

static int device_self_test(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Implementing the device self-test feature\n"
		"which provides the necessary log to determine the state of the device";
	const char *namespace_id =
	    "Indicate the namespace in which the device self-test has to be carried out";
	const char *self_test_code =
		"This field specifies the action taken by the device self-test command :\n"
		"0h Show current state of device self-test operation\n"
		"1h Start a short device self-test operation\n"
		"2h Start a extended device self-test operation\n"
		"eh Start a vendor specific device self-test operation\n"
		"fh Abort the device self-test operation";
	const char *wait = "Wait for the test to finish";

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	int err;

	struct config {
		__u32	namespace_id;
		__u8	stc;
		bool	wait;
	};

	struct config cfg = {
		.namespace_id	= NVME_NSID_ALL,
		.stc		= NVME_ST_CODE_RESERVED,
		.wait		= false,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id",   'n', &cfg.namespace_id, namespace_id),
		  OPT_BYTE("self-test-code", 's', &cfg.stc,          self_test_code),
		  OPT_FLAG("wait",           'w', &cfg.wait,         wait));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	if (cfg.stc == NVME_ST_CODE_RESERVED) {
		_cleanup_free_ struct nvme_self_test_log *log = NULL;

		log = nvme_alloc(sizeof(*log));
		if (!log)
			return -ENOMEM;

		err = nvme_cli_get_log_device_self_test(dev, log);
		if (err) {
			printf("\n");
			if (err < 0)
				perror("self test log\n");
			else
				nvme_show_status(err);
		}

		if (log->completion == 0) {
			printf("no self test running\n");
		} else {
			if (cfg.wait)
				err = wait_self_test(dev);
			else
				printf("progress %d%%\n", log->completion);
		}

		goto check_abort;
	}

	struct nvme_dev_self_test_args args = {
		.args_size	= sizeof(args),
		.fd		= dev_fd(dev),
		.nsid		= cfg.namespace_id,
		.stc		= cfg.stc,
		.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
		.result		= NULL,
	};
	err = nvme_dev_self_test(&args);
	if (!err) {
		if (cfg.stc == NVME_ST_CODE_ABORT)
			printf("Aborting device self-test operation\n");
		else if (cfg.stc == NVME_ST_CODE_EXTENDED)
			printf("Extended Device self-test started\n");
		else if (cfg.stc == NVME_ST_CODE_SHORT)
			printf("Short Device self-test started\n");

		if (cfg.wait && cfg.stc != NVME_ST_CODE_ABORT)
			err = wait_self_test(dev);
	} else if (err > 0) {
		nvme_show_status(err);
	} else {
		nvme_show_error("Device self-test: %s", nvme_strerror(errno));
	}

check_abort:
	if (err == -EINTR)
		abort_self_test(&args);

	return err;
}

static int self_test_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Retrieve the self-test log for the given device and given test\n"
		"(or optionally a namespace) in either decoded format (default) or binary.";
	const char *dst_entries = "Indicate how many DST log entries to be retrieved,\n"
		"by default all the 20 entries will be retrieved";

	_cleanup_free_ struct nvme_self_test_log *log = NULL;
	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	enum nvme_print_flags flags;
	int err;

	struct config {
		__u8	dst_entries;
	};

	struct config cfg = {
		.dst_entries	= NVME_LOG_ST_MAX_RESULTS,
	};

	NVME_ARGS(opts,
		  OPT_BYTE("dst-entries",  'e', &cfg.dst_entries,   dst_entries));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(output_format_val, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (argconfig_parse_seen(opts, "verbose"))
		flags |= VERBOSE;

	log = nvme_alloc(sizeof(*log));
	if (!log)
		return -ENOMEM;

	err = nvme_cli_get_log_device_self_test(dev, log);
	if (!err)
		nvme_show_self_test_log(log, cfg.dst_entries, 0, dev->name, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("self test log: %s", nvme_strerror(errno));

	return err;
}

static int get_feature_id(struct nvme_dev *dev, struct feat_cfg *cfg,
			  void **buf, __u32 *result)
{
	if (!cfg->data_len)
		nvme_get_feature_length(cfg->feature_id, cfg->cdw11,
					&cfg->data_len);

	/* check for Extended Host Identifier */
	if (cfg->feature_id == NVME_FEAT_FID_HOST_ID && (cfg->cdw11 & 0x1))
		cfg->data_len = 16;

	if (cfg->feature_id == NVME_FEAT_FID_FDP_EVENTS) {
		cfg->data_len = 0xff * sizeof(__u16);
		cfg->cdw11 |= 0xff << 16;
	}

	if (cfg->sel == 3)
		cfg->data_len = 0;

	if (cfg->data_len) {
		*buf = nvme_alloc(cfg->data_len - 1);
		if (!*buf)
			return -1;
	}

	struct nvme_get_features_args args = {
		.args_size	= sizeof(args),
		.fid		= cfg->feature_id,
		.nsid		= cfg->namespace_id,
		.sel		= cfg->sel,
		.cdw11		= cfg->cdw11,
		.uuidx		= cfg->uuid_index,
		.data_len	= cfg->data_len,
		.data		= *buf,
		.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
		.result		= result,
	};
	return nvme_cli_get_features(dev, &args);
}

static int filter_out_flags(int status)
{
	return status & (NVME_GET(NVME_SCT_MASK, SCT) |
			 NVME_GET(NVME_SC_MASK, SC));
}

static void get_feature_id_print(struct feat_cfg cfg, int err, __u32 result,
				 void *buf)
{
	int status = filter_out_flags(err);
	enum nvme_status_type type = NVME_STATUS_TYPE_NVME;

	if (!err) {
		if (!cfg.raw_binary || !buf) {
			nvme_feature_show(cfg.feature_id, cfg.sel, result);
			if (cfg.sel == 3)
				nvme_show_select_result(cfg.feature_id, result);
			else if (cfg.human_readable)
				nvme_feature_show_fields(cfg.feature_id, result,
							 buf);
			else if (buf)
				d(buf, cfg.data_len, 16, 1);
		} else if (buf) {
			d_raw(buf, cfg.data_len);
		}
	} else if (err > 0) {
		if (!nvme_status_equals(status, type, NVME_SC_INVALID_FIELD) &&
		    !nvme_status_equals(status,  type, NVME_SC_INVALID_NS))
			nvme_show_status(err);
	} else {
		nvme_show_error("get-feature: %s", nvme_strerror(errno));
	}
}

static int get_feature_id_changed(struct nvme_dev *dev, struct feat_cfg cfg,
				  bool changed)
{
	int err;
	int err_def = 0;
	__u32 result;
	__u32 result_def;
	void *buf = NULL;
	void *buf_def = NULL;

	if (changed)
		cfg.sel = 0;

	err = get_feature_id(dev, &cfg, &buf, &result);

	if (!err && changed) {
		cfg.sel = 1;
		err_def = get_feature_id(dev, &cfg, &buf_def, &result_def);
	}

	if (changed)
		cfg.sel = 8;

	if (err || !changed || err_def || result != result_def ||
	    (buf && buf_def && !strcmp(buf, buf_def)))
		get_feature_id_print(cfg, err, result, buf);

	free(buf);
	free(buf_def);

	return err;
}

static int get_feature_ids(struct nvme_dev *dev, struct feat_cfg cfg)
{
	int err = 0;
	int i;
	int feat_max = 0x100;
	int feat_num = 0;
	bool changed = false;
	int status = 0;
	enum nvme_status_type type = NVME_STATUS_TYPE_NVME;

	if (cfg.sel == 8)
		changed = true;

	if (cfg.feature_id)
		feat_max = cfg.feature_id + 1;

	for (i = cfg.feature_id; i < feat_max; i++, feat_num++) {
		cfg.feature_id = i;
		err = get_feature_id_changed(dev, cfg, changed);
		if (!err)
			continue;
		status = filter_out_flags(err);
		if (nvme_status_equals(status, type, NVME_SC_INVALID_FIELD))
			continue;
		if (!nvme_status_equals(status, type, NVME_SC_INVALID_NS))
			break;
		nvme_show_error_status(err, "get-feature:%#0*x (%s)", cfg.feature_id ? 4 : 2,
				       cfg.feature_id, nvme_feature_to_string(cfg.feature_id));
	}

	if (feat_num == 1 && nvme_status_equals(status, type, NVME_SC_INVALID_FIELD))
		nvme_show_status(err);

	return err;
}

static int get_feature(int argc, char **argv, struct command *cmd,
		       struct plugin *plugin)
{
	const char *desc = "Read operating parameters of the\n"
		"specified controller. Operating parameters are grouped\n"
		"and identified by Feature Identifiers; each Feature\n"
		"Identifier contains one or more attributes that may affect\n"
		"behavior of the feature. Each Feature has three possible\n"
		"settings: default, saveable, and current. If a Feature is\n"
		"saveable, it may be modified by set-feature. Default values\n"
		"are vendor-specific and not changeable. Use set-feature to\n"
		"change saveable Features.";
	const char *raw = "show feature in binary format";
	const char *feature_id = "feature identifier";
	const char *sel = "[0-3,8]: current/default/saved/supported/changed";
	const char *cdw11 = "feature specific dword 11";
	const char *human_readable = "show feature in readable format";

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	int err;

	struct feat_cfg cfg = {
		.feature_id	= 0,
		.namespace_id	= 0,
		.sel		= 0,
		.data_len	= 0,
		.raw_binary	= false,
		.cdw11		= 0,
		.uuid_index	= 0,
		.human_readable	= false,
	};

	NVME_ARGS(opts,
		  OPT_BYTE("feature-id",     'f', &cfg.feature_id,     feature_id),
		  OPT_UINT("namespace-id",   'n', &cfg.namespace_id,   namespace_id_desired),
		  OPT_BYTE("sel",            's', &cfg.sel,            sel),
		  OPT_UINT("data-len",       'l', &cfg.data_len,       buf_len),
		  OPT_FLAG("raw-binary",     'b', &cfg.raw_binary,     raw),
		  OPT_UINT("cdw11",          'c', &cfg.cdw11,          cdw11),
		  OPT_BYTE("uuid-index",     'U', &cfg.uuid_index,     uuid_index_specify),
		  OPT_FLAG("human-readable", 'H', &cfg.human_readable, human_readable));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	if (!argconfig_parse_seen(opts, "namespace-id")) {
		err = nvme_get_nsid(dev_fd(dev), &cfg.namespace_id);
		if (err < 0) {
			if (errno != ENOTTY) {
				nvme_show_error("get-namespace-id: %s", nvme_strerror(errno));
				return err;
			}
			cfg.namespace_id = NVME_NSID_ALL;
		}
	}

	if (cfg.sel > 8) {
		nvme_show_error("invalid 'select' param:%d", cfg.sel);
		return -EINVAL;
	}

	if (cfg.uuid_index > 127) {
		nvme_show_error("invalid uuid index param: %u", cfg.uuid_index);
		return -1;
	}

	nvme_show_init();

	err = get_feature_ids(dev, cfg);

	nvme_show_finish();

	return err;
}

/*
 * Transfers one chunk of firmware to the device, and decodes & reports any
 * errors. Returns -1 on (fatal) error; signifying that the transfer should
 * be aborted.
 */
static int fw_download_single(struct nvme_dev *dev, void *fw_buf,
			      unsigned int fw_len, uint32_t offset,
			      uint32_t len, bool progress, bool ignore_ovr)
{
	const unsigned int max_retries = 3;
	bool retryable, ovr;
	int err, try;

	if (progress) {
		printf("Firmware download: transferring 0x%08x/0x%08x bytes: %03d%%\r",
		       offset, fw_len, (int)(100 * offset / fw_len));
	}

	struct nvme_fw_download_args args = {
		.args_size	= sizeof(args),
		.offset		= offset,
		.data_len	= len,
		.data		= fw_buf,
		.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
		.result		= NULL,
	};

	for (try = 0; try < max_retries; try++) {
		if (try > 0) {
			fprintf(stderr, "retrying offset %x (%u/%u)\n",
				offset, try, max_retries);
		}

		err = nvme_cli_fw_download(dev, &args);
		if (!err)
			return 0;

		/*
		 * don't retry if the NVMe-type error indicates Do Not Resend.
		 */
		retryable = !((err > 0) &&
			(nvme_status_get_type(err) == NVME_STATUS_TYPE_NVME) &&
			(nvme_status_get_value(err) & NVME_SC_DNR));

		/*
		 * detect overwrite errors, which are handled differently
		 * depending on ignore_ovr
		 */
		ovr = (err > 0) &&
			(nvme_status_get_type(err) == NVME_STATUS_TYPE_NVME) &&
			(NVME_GET(err, SCT) == NVME_SCT_CMD_SPECIFIC) &&
			(NVME_GET(err, SC) == NVME_SC_OVERLAPPING_RANGE);

		if (ovr && ignore_ovr)
			return 0;

		/*
		 * if we're printing progress, we'll need a newline to separate
		 * error output from the progress data (which doesn't have a
		 * \n), and flush before we write to stderr.
		 */
		if (progress) {
			printf("\n");
			fflush(stdout);
		}

		fprintf(stderr, "fw-download: error on offset 0x%08x/0x%08x\n",
			offset, fw_len);

		if (err < 0) {
			fprintf(stderr, "fw-download: %s\n", nvme_strerror(errno));
		} else {
			nvme_show_status(err);
			if (ovr) {
				/*
				 * non-ignored ovr error: print a little extra info
				 * about recovering
				 */
				fprintf(stderr,
					"Use --ignore-ovr to ignore overwrite errors\n");

				/*
				 * We'll just be attempting more overwrites if
				 * we retry. DNR will likely be set, but force
				 * an exit anyway.
				 */
				retryable = false;
			}
		}

		if (!retryable)
			break;
	}

	return -1;
}

static int fw_download(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Copy all or part of a firmware image to\n"
		"a controller for future update. Optionally, specify how\n"
		"many KiB of the firmware to transfer at once. The offset will\n"
		"start at 0 and automatically adjust based on xfer size\n"
		"unless fw is split across multiple files. May be submitted\n"
		"while outstanding commands exist on the Admin and IO\n"
		"Submission Queues. Activate downloaded firmware with\n"
		"fw-activate, and then reset the device to apply the downloaded firmware.";
	const char *fw = "firmware file (required)";
	const char *xfer = "transfer chunksize limit";
	const char *offset = "starting dword offset, default 0";
	const char *progress = "display firmware transfer progress";
	const char *ignore_ovr = "ignore overwrite errors";

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	_cleanup_huge_ struct nvme_mem_huge mh = { 0, };
	_cleanup_file_ int fw_fd = -1;
	unsigned int fw_size, pos;
	int err;
	struct stat sb;
	void *fw_buf;
	struct nvme_id_ctrl ctrl;

	struct config {
		char	*fw;
		__u32	xfer;
		__u32	offset;
		bool	progress;
		bool	ignore_ovr;
	};

	struct config cfg = {
		.fw         = "",
		.xfer       = 4096,
		.offset     = 0,
		.progress   = false,
		.ignore_ovr = false,
	};

	NVME_ARGS(opts,
		  OPT_FILE("fw",         'f', &cfg.fw,         fw),
		  OPT_UINT("xfer",       'x', &cfg.xfer,       xfer),
		  OPT_UINT("offset",     'O', &cfg.offset,     offset),
		  OPT_FLAG("progress",   'p', &cfg.progress,   progress),
		  OPT_FLAG("ignore-ovr", 'i', &cfg.ignore_ovr, ignore_ovr));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	fw_fd = open(cfg.fw, O_RDONLY);
	cfg.offset <<= 2;
	if (fw_fd < 0) {
		nvme_show_error("Failed to open firmware file %s: %s", cfg.fw, strerror(errno));
		return -EINVAL;
	}

	err = fstat(fw_fd, &sb);
	if (err < 0) {
		nvme_show_perror("fstat");
		return err;
	}

	fw_size = sb.st_size;
	if ((fw_size & 0x3) || (fw_size == 0)) {
		nvme_show_error("Invalid size:%d for f/w image", fw_size);
		return -EINVAL;
	}

	if (cfg.xfer == 0) {
		err = nvme_cli_identify_ctrl(dev, &ctrl);
		if (err) {
			nvme_show_error("identify-ctrl: %s", nvme_strerror(errno));
			return err;
		}
		if (ctrl.fwug == 0 || ctrl.fwug == 0xff)
			cfg.xfer = 4096;
		else
			cfg.xfer = ctrl.fwug * 4096;
	} else if (cfg.xfer % 4096)
		cfg.xfer = 4096;

	fw_buf = nvme_alloc_huge(fw_size, &mh);
	if (!fw_buf)
		return -ENOMEM;

	if (read(fw_fd, fw_buf, fw_size) != ((ssize_t)(fw_size))) {
		err = -errno;
		nvme_show_error("read :%s :%s", cfg.fw, strerror(errno));
		return err;
	}

	for (pos = 0; pos < fw_size; pos += cfg.xfer) {
		cfg.xfer = min(cfg.xfer, fw_size - pos);

		err = fw_download_single(dev, fw_buf + pos, fw_size,
					 cfg.offset + pos, cfg.xfer,
					 cfg.progress, cfg.ignore_ovr);
		if (err)
			break;
	}

	if (!err) {
		/* end the progress output */
		if (cfg.progress)
			printf("\n");
		printf("Firmware download success\n");
	}

	return err;
}

static char *nvme_fw_status_reset_type(__u16 status)
{
	switch (status & 0x7ff) {
	case NVME_SC_FW_NEEDS_CONV_RESET:
		return "conventional";
	case NVME_SC_FW_NEEDS_SUBSYS_RESET:
		return "subsystem";
	case NVME_SC_FW_NEEDS_RESET:
		return "any controller";
	default:
		return "unknown";
	}
}

static bool fw_commit_support_mud(struct nvme_dev *dev)
{
	_cleanup_free_ struct nvme_id_ctrl *ctrl = NULL;
	int err;

	ctrl = nvme_alloc(sizeof(*ctrl));
	if (!ctrl)
		return false;

	err = nvme_cli_identify_ctrl(dev, ctrl);

	if (err)
		nvme_show_error("identify-ctrl: %s", nvme_strerror(errno));
	else if (ctrl->frmw >> 5 & 0x1)
		return true;

	return false;
}

static void fw_commit_print_mud(struct nvme_dev *dev, __u32 result)
{
	if (!fw_commit_support_mud(dev))
		return;

	printf("Multiple Update Detected (MUD) Value: %u\n", result);

	if (result & 0x1)
		printf("Detected an overlapping firmware/boot partition image update command\n"
		       "sequence due to processing a command from a Management Endpoint");

	if (result >> 1 & 0x1)
		printf("Detected an overlapping firmware/boot partition image update command\n"
		       "sequence due to processing a command from an Admin SQ on a controller");
}

static int fw_commit(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Verify downloaded firmware image and\n"
		"commit to specific firmware slot. Device is not automatically\n"
		"reset following firmware activation. A reset may be issued\n"
		"with an 'echo 1 > /sys/class/nvme/nvmeX/reset_controller'.\n"
		"Ensure nvmeX is the device you just activated before reset.";
	const char *slot = "[0-7]: firmware slot for commit action";
	const char *action = "[0-7]: commit action";
	const char *bpid = "[0,1]: boot partition identifier, if applicable (default: 0)";

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	__u32 result;
	int err;

	struct config {
		__u8	slot;
		__u8	action;
		__u8	bpid;
	};

	struct config cfg = {
		.slot	= 0,
		.action	= 0,
		.bpid	= 0,
	};

	NVME_ARGS(opts,
		  OPT_BYTE("slot",   's', &cfg.slot,   slot),
		  OPT_BYTE("action", 'a', &cfg.action, action),
		  OPT_BYTE("bpid",   'b', &cfg.bpid,   bpid));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	if (cfg.slot > 7) {
		nvme_show_error("invalid slot:%d", cfg.slot);
		return -EINVAL;
	}
	if (cfg.action > 7 || cfg.action == 4 || cfg.action == 5) {
		nvme_show_error("invalid action:%d", cfg.action);
		return -EINVAL;
	}
	if (cfg.bpid > 1) {
		nvme_show_error("invalid boot partition id:%d", cfg.bpid);
		return -EINVAL;
	}

	struct nvme_fw_commit_args args = {
		.args_size	= sizeof(args),
		.slot		= cfg.slot,
		.action		= cfg.action,
		.bpid		= cfg.bpid,
		.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
		.result		= &result,
	};
	err = nvme_cli_fw_commit(dev, &args);

	if (err < 0) {
		nvme_show_error("fw-commit: %s", nvme_strerror(errno));
	} else if (err != 0) {
		__u32 val = nvme_status_get_value(err);
		int type = nvme_status_get_type(err);

		if (type == NVME_STATUS_TYPE_NVME) {
			switch (val & 0x7ff) {
			case NVME_SC_FW_NEEDS_CONV_RESET:
			case NVME_SC_FW_NEEDS_SUBSYS_RESET:
			case NVME_SC_FW_NEEDS_RESET:
				printf("Success activating firmware action:%d slot:%d",
				       cfg.action, cfg.slot);
				if (cfg.action == 6 || cfg.action == 7)
					printf(" bpid:%d", cfg.bpid);
				printf(", but firmware requires %s reset\n",
				       nvme_fw_status_reset_type(val));
				break;
			default:
				nvme_show_status(err);
				break;
			}
		} else {
			nvme_show_status(err);
		}
	} else {
		printf("Success committing firmware action:%d slot:%d",
		       cfg.action, cfg.slot);
		if (cfg.action == 6 || cfg.action == 7)
			printf(" bpid:%d", cfg.bpid);
		printf("\n");
		fw_commit_print_mud(dev, result);
	}

	return err;
}

static int subsystem_reset(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Resets the NVMe subsystem\n";

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	int err;

	NVME_ARGS(opts);

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	err = nvme_subsystem_reset(dev_fd(dev));
	if (err < 0) {
		if (errno == ENOTTY)
			nvme_show_error("Subsystem-reset: NVM Subsystem Reset not supported.");
		else
			nvme_show_error("Subsystem-reset: %s", nvme_strerror(errno));
	}

	return err;
}

static int reset(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Resets the NVMe controller\n";

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	int err;

	NVME_ARGS(opts);

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	err = nvme_ctrl_reset(dev_fd(dev));
	if (err < 0)
		nvme_show_error("Reset: %s", nvme_strerror(errno));

	return err;
}

static int ns_rescan(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Rescans the NVMe namespaces\n";

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	int err;

	NVME_ARGS(opts);

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	err = nvme_ns_rescan(dev_fd(dev));
	if (err < 0)
		nvme_show_error("Namespace Rescan");

	return err;
}

static int sanitize_cmd(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Send a sanitize command.";
	const char *no_dealloc_desc = "No deallocate after sanitize.";
	const char *oipbp_desc = "Overwrite invert pattern between passes.";
	const char *owpass_desc = "Overwrite pass count.";
	const char *ause_desc = "Allow unrestricted sanitize exit.";
	const char *sanact_desc = "Sanitize action: 1 = Exit failure mode, 2 = Start block erase, 3 = Start overwrite, 4 = Start crypto erase";
	const char *ovrpat_desc = "Overwrite pattern.";

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	int err;

	struct config {
		bool	no_dealloc;
		bool	oipbp;
		__u8	owpass;
		bool	ause;
		__u8	sanact;
		__u32	ovrpat;
	};

	struct config cfg = {
		.no_dealloc	= false,
		.oipbp		= false,
		.owpass		= 0,
		.ause		= false,
		.sanact		= 0,
		.ovrpat		= 0,
	};

	OPT_VALS(sanact) = {
		VAL_BYTE("exit-failure", NVME_SANITIZE_SANACT_EXIT_FAILURE),
		VAL_BYTE("start-block-erase", NVME_SANITIZE_SANACT_START_BLOCK_ERASE),
		VAL_BYTE("start-overwrite", NVME_SANITIZE_SANACT_START_OVERWRITE),
		VAL_BYTE("start-crypto-erase", NVME_SANITIZE_SANACT_START_CRYPTO_ERASE),
		VAL_END()
	};

	NVME_ARGS(opts,
		  OPT_FLAG("no-dealloc", 'd', &cfg.no_dealloc, no_dealloc_desc),
		  OPT_FLAG("oipbp",      'i', &cfg.oipbp,      oipbp_desc),
		  OPT_BYTE("owpass",     'n', &cfg.owpass,     owpass_desc),
		  OPT_FLAG("ause",       'u', &cfg.ause,       ause_desc),
		  OPT_BYTE("sanact",     'a', &cfg.sanact,     sanact_desc, sanact),
		  OPT_UINT("ovrpat",     'p', &cfg.ovrpat,     ovrpat_desc));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	switch (cfg.sanact) {
	case NVME_SANITIZE_SANACT_EXIT_FAILURE:
	case NVME_SANITIZE_SANACT_START_BLOCK_ERASE:
	case NVME_SANITIZE_SANACT_START_OVERWRITE:
	case NVME_SANITIZE_SANACT_START_CRYPTO_ERASE:
		break;
	default:
		nvme_show_error("Invalid Sanitize Action");
		return -EINVAL;
	}

	if (cfg.sanact == NVME_SANITIZE_SANACT_EXIT_FAILURE) {
		if (cfg.ause || cfg.no_dealloc) {
			nvme_show_error("SANACT is Exit Failure Mode");
			return -EINVAL;
		}
	}

	if (cfg.sanact == NVME_SANITIZE_SANACT_START_OVERWRITE) {
		if (cfg.owpass > 15) {
			nvme_show_error("OWPASS out of range [0-15]");
			return -EINVAL;
		}
	} else {
		if (cfg.owpass || cfg.oipbp || cfg.ovrpat) {
			nvme_show_error("SANACT is not Overwrite");
			return -EINVAL;
		}
	}

	struct nvme_sanitize_nvm_args args = {
		.args_size	= sizeof(args),
		.sanact		= cfg.sanact,
		.ause		= cfg.ause,
		.owpass		= cfg.owpass,
		.oipbp		= cfg.oipbp,
		.nodas		= cfg.no_dealloc,
		.ovrpat		= cfg.ovrpat,
		.result		= NULL,
	};
	err = nvme_cli_sanitize_nvm(dev, &args);
	if (err < 0)
		nvme_show_error("sanitize: %s", nvme_strerror(errno));
	else if (err > 0)
		nvme_show_status(err);

	return err;
}

static int nvme_get_properties(int fd, void **pbar)
{
	int offset, err, size = getpagesize();
	__u64 value;
	void *bar = malloc(size);

	if (!bar) {
		nvme_show_error("malloc: %s", strerror(errno));
		return -1;
	}

	memset(bar, 0xff, size);
	for (offset = NVME_REG_CAP; offset <= NVME_REG_CMBSZ;) {
		struct nvme_get_property_args args = {
			.args_size	= sizeof(args),
			.fd		= fd,
			.offset		= offset,
			.value		= &value,
			.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
		};

		err = nvme_get_property(&args);
		if (nvme_status_equals(err, NVME_STATUS_TYPE_NVME, NVME_SC_INVALID_FIELD)) {
			err = 0;
			value = -1;
		} else if (err) {
			nvme_show_error("get-property: %s", nvme_strerror(errno));
			break;
		}
		if (nvme_is_64bit_reg(offset)) {
			*(uint64_t *)(bar + offset) = value;
			offset += 8;
		} else {
			*(uint32_t *)(bar + offset) = value;
			offset += 4;
		}
	}

	if (err)
		free(bar);
	else
		*pbar = bar;

	return err;
}

static void *mmap_registers(nvme_root_t r, struct nvme_dev *dev)
{
	nvme_ctrl_t c = NULL;
	nvme_ns_t n = NULL;

	char path[512];
	void *membase;
	int fd;

	c = nvme_scan_ctrl(r, dev->name);
	if (c) {
		snprintf(path, sizeof(path), "%s/device/resource0",
			nvme_ctrl_get_sysfs_dir(c));
		nvme_free_ctrl(c);
	} else {
		n = nvme_scan_namespace(dev->name);
		if (!n) {
			nvme_show_error("Unable to find %s", dev->name);
			return NULL;
		}
		snprintf(path, sizeof(path), "%s/device/device/resource0",
			 nvme_ns_get_sysfs_dir(n));
		nvme_free_ns(n);
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		if (map_log_level(0, false) >= LOG_DEBUG)
			nvme_show_error("%s did not find a pci resource, open failed %s",
					dev->name, strerror(errno));
		return NULL;
	}

	membase = mmap(NULL, getpagesize(), PROT_READ, MAP_SHARED, fd, 0);
	if (membase == MAP_FAILED) {
		if (map_log_level(0, false) >= LOG_DEBUG) {
			fprintf(stderr, "%s failed to map. ", dev->name);
			fprintf(stderr, "Did your kernel enable CONFIG_IO_STRICT_DEVMEM?\n");
		}
		membase = NULL;
	}

	close(fd);
	return membase;
}

static int show_registers(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Reads and shows the defined NVMe controller registers\n"
		"in binary or human-readable format";
	const char *human_readable =
	    "show info in readable format in case of output_format == normal";

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	enum nvme_print_flags flags;
	bool fabrics = false;
	nvme_root_t r;
	void *bar;
	int err;

	struct config {
		bool	human_readable;
	};

	struct config cfg = {
		.human_readable	= false,
	};

	NVME_ARGS(opts,
		  OPT_FLAG("human-readable", 'H', &cfg.human_readable, human_readable));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	r = nvme_scan(NULL);
	err = validate_output_format(output_format_val, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		goto free_tree;
	}

	if (cfg.human_readable)
		flags |= VERBOSE;

	bar = mmap_registers(r, dev);
	if (!bar) {
		err = nvme_get_properties(dev_fd(dev), &bar);
		if (err)
			goto free_tree;
		fabrics = true;
	}

	nvme_show_ctrl_registers(bar, fabrics, flags);
	if (fabrics)
		free(bar);
	else
		munmap(bar, getpagesize());
free_tree:
	nvme_free_tree(r);
	return err;
}

static int get_property(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Reads and shows the defined NVMe controller property\n"
		"for NVMe over Fabric. Property offset must be one of:\n"
		"CAP=0x0, VS=0x8, CC=0x14, CSTS=0x1c, NSSR=0x20";
	const char *offset = "offset of the requested property";
	const char *human_readable = "show property in readable format";

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	__u64 value;
	int err;

	struct config {
		int	offset;
		bool	human_readable;
	};

	struct config cfg = {
		.offset		= -1,
		.human_readable	= false,
	};

	NVME_ARGS(opts,
		  OPT_UINT("offset",         'O', &cfg.offset,         offset),
		  OPT_FLAG("human-readable", 'H', &cfg.human_readable, human_readable));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	if (cfg.offset == -1) {
		nvme_show_error("offset required param");
		return -EINVAL;
	}

	struct nvme_get_property_args args = {
		.args_size	= sizeof(args),
		.fd		= dev_fd(dev),
		.offset		= cfg.offset,
		.value		= &value,
		.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
	};
	err = nvme_get_property(&args);
	if (err < 0)
		nvme_show_error("get-property: %s", nvme_strerror(errno));
	else if (!err)
		nvme_show_single_property(cfg.offset, value, cfg.human_readable);
	else if (err > 0)
		nvme_show_status(err);

	return err;
}

static int set_property(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc =
	    "Writes and shows the defined NVMe controller property for NVMe over Fabric";
	const char *offset = "the offset of the property";
	const char *value = "the value of the property to be set";

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	int err;

	struct config {
		int	offset;
		int	value;
	};

	struct config cfg = {
		.offset	= -1,
		.value	= -1,
	};

	NVME_ARGS(opts,
		  OPT_UINT("offset", 'O', &cfg.offset, offset),
		  OPT_UINT("value",  'V', &cfg.value,  value));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	if (cfg.offset == -1) {
		nvme_show_error("offset required param");
		return -EINVAL;
	}
	if (cfg.value == -1) {
		nvme_show_error("value required param");
		return -EINVAL;
	}

	struct nvme_set_property_args args = {
		.args_size	= sizeof(args),
		.fd		= dev_fd(dev),
		.offset		= cfg.offset,
		.value		= cfg.value,
		.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
		.result		= NULL,
	};
	err = nvme_set_property(&args);
	if (err < 0)
		nvme_show_error("set-property: %s", nvme_strerror(errno));
	else if (!err)
		printf("set-property: %02x (%s), value: %#08x\n", cfg.offset,
		       nvme_register_to_string(cfg.offset), cfg.value);
	else if (err > 0)
		nvme_show_status(err);

	return err;
}

static int format_cmd(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Re-format a specified namespace on the\n"
		"given device. Can erase all data in namespace (user\n"
		"data erase) or delete data encryption key if specified.\n"
		"Can also be used to change LBAF to change the namespaces reported physical block format.";
	const char *lbaf = "LBA format to apply (required)";
	const char *ses = "[0-2]: secure erase";
	const char *pil = "[0-1]: protection info location last/first 8 bytes of metadata";
	const char *pi = "[0-3]: protection info off/Type 1/Type 2/Type 3";
	const char *ms = "[0-1]: extended format off/on";
	const char *reset = "Automatically reset the controller after successful format";
	const char *bs = "target block size";
	const char *force = "The \"I know what I'm doing\" flag, skip confirmation before sending command";

	_cleanup_free_ struct nvme_id_ctrl *ctrl = NULL;
	_cleanup_free_ struct nvme_id_ns *ns = NULL;
	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	__u8 prev_lbaf = 0;
	int block_size;
	int err, i;

	struct config {
		__u32	namespace_id;
		__u32	timeout;
		__u8	lbaf;
		__u8	ses;
		__u8	pi;
		__u8	pil;
		__u8	ms;
		bool	reset;
		bool	force;
		__u64	bs;
	};

	struct config cfg = {
		.namespace_id	= 0,
		.timeout	= 600000,
		.lbaf		= 0xff,
		.ses		= 0,
		.pi		= 0,
		.pil		= 0,
		.ms		= 0,
		.reset		= false,
		.force		= false,
		.bs		= 0,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id_desired),
		  OPT_UINT("timeout",      't', &cfg.timeout,      timeout),
		  OPT_BYTE("lbaf",         'l', &cfg.lbaf,         lbaf),
		  OPT_BYTE("ses",          's', &cfg.ses,          ses),
		  OPT_BYTE("pi",           'i', &cfg.pi,           pi),
		  OPT_BYTE("pil",          'p', &cfg.pil,          pil),
		  OPT_BYTE("ms",           'm', &cfg.ms,           ms),
		  OPT_FLAG("reset",        'r', &cfg.reset,        reset),
		  OPT_FLAG("force",          0, &cfg.force,        force),
		  OPT_SUFFIX("block-size", 'b', &cfg.bs,           bs));

	err = argconfig_parse(argc, argv, desc, opts);
	if (err)
		return err;

	err = open_exclusive(&dev, argc, argv, cfg.force);
	if (err) {
		if (errno == EBUSY) {
			fprintf(stderr, "Failed to open %s.\n", basename(argv[optind]));
			fprintf(stderr, "Namespace is currently busy.\n");
			if (!cfg.force)
				fprintf(stderr, "Use the force [--force] option to ignore that.\n");
		} else {
			argconfig_print_help(desc, opts);
		}
		return err;
	}

	if (cfg.lbaf != 0xff && cfg.bs != 0) {
		nvme_show_error(
		    "Invalid specification of both LBAF and Block Size, please specify only one");
		return -EINVAL;
	}
	if (cfg.bs) {
		if ((cfg.bs & (~cfg.bs + 1)) != cfg.bs) {
			nvme_show_error(
			    "Invalid value for block size (%"PRIu64"), must be a power of two",
			    (uint64_t) cfg.bs);
			return -EINVAL;
		}
	}

	ctrl = nvme_alloc(sizeof(*ctrl));
	if (!ctrl)
		return -ENOMEM;

	err = nvme_cli_identify_ctrl(dev, ctrl);
	if (err) {
		nvme_show_error("identify-ctrl: %s", nvme_strerror(errno));
		return -errno;
	}

	if ((ctrl->fna & 1) == 1) {
		/*
		 * FNA bit 0 set to 1: all namespaces ... shall be configured with the same
		 * attributes and a format (excluding secure erase) of any namespace results in a
		 * format of all namespaces.
		 */
		cfg.namespace_id = NVME_NSID_ALL;
	} else if (!cfg.namespace_id) {
		err = nvme_get_nsid(dev_fd(dev), &cfg.namespace_id);
		if (err < 0) {
			nvme_show_error("get-namespace-id: %s", nvme_strerror(errno));
			return -errno;
		}
	}

	if (cfg.namespace_id == 0) {
		nvme_show_error(
		    "Invalid namespace ID, specify a namespace to format or use\n"
		    "'-n 0xffffffff' to format all namespaces on this controller.");
		return -EINVAL;
	}

	if (cfg.namespace_id != NVME_NSID_ALL) {
		ns = nvme_alloc(sizeof(*ns));
		if (!ns)
			return -ENOMEM;

		err = nvme_cli_identify_ns(dev, cfg.namespace_id, ns);
		if (err) {
			if (err < 0) {
				nvme_show_error("identify-namespace: %s", nvme_strerror(errno));
			} else {
				fprintf(stderr, "identify failed\n");
				nvme_show_status(err);
			}
			return err;
		}
		nvme_id_ns_flbas_to_lbaf_inuse(ns->flbas, &prev_lbaf);

		if (cfg.bs) {
			for (i = 0; i <= ns->nlbaf; ++i) {
				if ((1ULL << ns->lbaf[i].ds) == cfg.bs && ns->lbaf[i].ms == 0) {
					cfg.lbaf = i;
					break;
				}
			}
			if (cfg.lbaf == 0xff) {
				fprintf(stderr,
				    "LBAF corresponding to given block size %"PRIu64" not found\n",
				    (uint64_t)cfg.bs);
				fprintf(stderr,
					"Please correct block size, or specify LBAF directly\n");
				return -EINVAL;
			}
		} else  if (cfg.lbaf == 0xff) {
			cfg.lbaf = prev_lbaf;
		}
	} else {
		if (cfg.lbaf == 0xff)
			cfg.lbaf = 0;
	}

	/* ses & pi checks set to 7 for forward-compatibility */
	if (cfg.ses > 7) {
		nvme_show_error("invalid secure erase settings:%d", cfg.ses);
		return -EINVAL;
	}
	if (cfg.lbaf > 63) {
		nvme_show_error("invalid lbaf:%d", cfg.lbaf);
		return -EINVAL;
	}
	if (cfg.pi > 7) {
		nvme_show_error("invalid pi:%d", cfg.pi);
		return -EINVAL;
	}
	if (cfg.pil > 1) {
		nvme_show_error("invalid pil:%d", cfg.pil);
		return -EINVAL;
	}
	if (cfg.ms > 1) {
		nvme_show_error("invalid ms:%d", cfg.ms);
		return -EINVAL;
	}

	if (!cfg.force) {
		fprintf(stderr, "You are about to format %s, namespace %#x%s.\n",
			dev->name, cfg.namespace_id,
			cfg.namespace_id == NVME_NSID_ALL ? "(ALL namespaces)" : "");
		nvme_show_relatives(dev->name);
		fprintf(stderr,
			"WARNING: Format may irrevocably delete this device's data.\n"
			"You have 10 seconds to press Ctrl-C to cancel this operation.\n\n"
			"Use the force [--force] option to suppress this warning.\n");
		sleep(10);
		fprintf(stderr, "Sending format operation ...\n");
	}

	struct nvme_format_nvm_args args = {
		.args_size	= sizeof(args),
		.nsid		= cfg.namespace_id,
		.lbafu		= (cfg.lbaf & NVME_NS_FLBAS_HIGHER_MASK) >> 4,
		.lbaf		= cfg.lbaf & NVME_NS_FLBAS_LOWER_MASK,
		.mset		= cfg.ms,
		.pi		= cfg.pi,
		.pil		= cfg.pil,
		.ses		= cfg.ses,
		.timeout	= cfg.timeout,
		.result		= NULL,
	};
	err = nvme_cli_format_nvm(dev, &args);
	if (err < 0) {
		nvme_show_error("format: %s", nvme_strerror(errno));
	} else if (err != 0) {
		nvme_show_status(err);
	} else {
		printf("Success formatting namespace:%x\n", cfg.namespace_id);
		if (dev->type == NVME_DEV_DIRECT && cfg.lbaf != prev_lbaf) {
			if (is_chardev(dev)) {
				if (ioctl(dev_fd(dev), NVME_IOCTL_RESCAN) < 0) {
					nvme_show_error("failed to rescan namespaces");
					return -errno;
				}
			} else if (cfg.namespace_id != NVME_NSID_ALL) {
				block_size = 1 << ns->lbaf[cfg.lbaf].ds;

				/*
				 * If block size has been changed by the format
				 * command up there, we should notify it to
				 * kernel blkdev to update its own block size
				 * to the given one because blkdev will not
				 * update by itself without re-opening fd.
				 */
				if (ioctl(dev_fd(dev), BLKBSZSET, &block_size) < 0) {
					nvme_show_error("failed to set block size to %d",
							block_size);
					return -errno;
				}

				if (ioctl(dev_fd(dev), BLKRRPART) < 0) {
					nvme_show_error("failed to re-read partition table");
					return -errno;
				}
			}
		}
		if (dev->type == NVME_DEV_DIRECT && cfg.reset && is_chardev(dev))
			nvme_ctrl_reset(dev_fd(dev));
	}

	return err;
}

#define STRTOUL_AUTO_BASE              (0)
#define NVME_FEAT_TIMESTAMP_DATA_SIZE  (6)

static int set_feature(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Modify the saveable or changeable\n"
		"current operating parameters of the controller.\n"
		"Operating parameters are grouped and identified by Feature\n"
		"Identifiers. Feature settings can be applied to the entire\n"
		"controller and all associated namespaces, or to only a few\n"
		"namespace(s) associated with the controller. Default values\n"
		"for each Feature are vendor-specific and may not be modified.\n"
		"Use get-feature to determine which Features are supported by\n"
		"the controller and are saveable/changeable.";
	const char *feature_id = "feature identifier (required)";
	const char *data = "optional file for feature data (default stdin)";
	const char *value = "new value of feature (required)";
	const char *cdw12 = "feature cdw12, if used";
	const char *save = "specifies that the controller shall save the attribute";

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	_cleanup_free_ void *buf = NULL;
	_cleanup_file_ int ffd = STDIN_FILENO;
	int err;
	__u32 result;

	struct config {
		__u32	namespace_id;
		__u8	feature_id;
		__u64	value;
		__u32	cdw12;
		__u8	uuid_index;
		__u32	data_len;
		char	*file;
		bool	save;
	};

	struct config cfg = {
		.namespace_id	= 0,
		.feature_id	= 0,
		.value		= 0,
		.uuid_index	= 0,
		.data_len	= 0,
		.file		= "",
		.save		= false,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_desired),
		  OPT_BYTE("feature-id",   'f', &cfg.feature_id,   feature_id),
		  OPT_SUFFIX("value",      'V', &cfg.value,        value),
		  OPT_UINT("cdw12",        'c', &cfg.cdw12,        cdw12),
		  OPT_BYTE("uuid-index",   'U', &cfg.uuid_index,   uuid_index_specify),
		  OPT_UINT("data-len",     'l', &cfg.data_len,     buf_len),
		  OPT_FILE("data",         'd', &cfg.file,         data),
		  OPT_FLAG("save",         's', &cfg.save,         save));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	if (!argconfig_parse_seen(opts, "namespace-id")) {
		err = nvme_get_nsid(dev_fd(dev), &cfg.namespace_id);
		if (err < 0) {
			if (errno != ENOTTY) {
				nvme_show_error("get-namespace-id: %s", nvme_strerror(errno));
				return -errno;
			}
			cfg.namespace_id = NVME_NSID_ALL;
		}
	}

	if (!cfg.feature_id) {
		nvme_show_error("feature-id required param");
		return -EINVAL;
	}

	if (cfg.uuid_index > 127) {
		nvme_show_error("invalid uuid index param: %u", cfg.uuid_index);
		return -1;
	}

	if (!cfg.data_len)
		nvme_cli_get_feature_length2(cfg.feature_id, cfg.value,
					     NVME_DATA_TFR_HOST_TO_CTRL,
					     &cfg.data_len);

	if (cfg.data_len) {
		buf = nvme_alloc(cfg.data_len);
		if (!buf)
			return -ENOMEM;
	}

	if (buf) {
		/*
		 * Use the '-v' value for the timestamp feature if provided as
		 * a convenience since it can often fit in 4-bytes. The user
		 * should use the buffer method if the value exceeds this
		 * length.
		 */
		if (cfg.feature_id == NVME_FEAT_FID_TIMESTAMP && cfg.value) {
			memcpy(buf, &cfg.value, NVME_FEAT_TIMESTAMP_DATA_SIZE);
		} else {
			if (strlen(cfg.file))
				ffd = open(cfg.file, O_RDONLY);

			if (ffd < 0) {
				nvme_show_error("Failed to open file %s: %s",
						cfg.file, strerror(errno));
				return -EINVAL;
			}

			err = read(ffd, buf, cfg.data_len);
			if (err < 0) {
				nvme_show_error("failed to read data buffer from input file: %s",
						strerror(errno));
				return -errno;
			}
		}
	}

	struct nvme_set_features_args args = {
		.args_size	= sizeof(args),
		.fd		= dev_fd(dev),
		.fid		= cfg.feature_id,
		.nsid		= cfg.namespace_id,
		.cdw11		= cfg.value,
		.cdw12		= cfg.cdw12,
		.save		= cfg.save,
		.uuidx		= cfg.uuid_index,
		.cdw15		= 0,
		.data_len	= cfg.data_len,
		.data		= buf,
		.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
		.result		= &result,
	};
	err = nvme_set_features(&args);
	if (err < 0) {
		nvme_show_error("set-feature: %s", nvme_strerror(errno));
	} else if (!err) {
		printf("set-feature:%#0*x (%s), value:%#0*"PRIx64", cdw12:%#0*x, save:%#x\n",
		       cfg.feature_id ? 4 : 2, cfg.feature_id,
		       nvme_feature_to_string(cfg.feature_id),
		       cfg.value ? 10 : 8, (uint64_t)cfg.value,
		       cfg.cdw12 ? 10 : 8, cfg.cdw12, cfg.save);
		if (cfg.feature_id == NVME_FEAT_FID_LBA_STS_INTERVAL)
			nvme_show_lba_status_info(result);
		if (buf) {
			if (cfg.feature_id == NVME_FEAT_FID_LBA_RANGE)
				nvme_show_lba_range((struct nvme_lba_range_type *)buf, result, 0);
			else
				d(buf, cfg.data_len, 16, 1);
		}
	} else if (err > 0) {
		nvme_show_status(err);
	}

	return err;
}

static int sec_send(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	struct stat sb;
	const char *desc = "Transfer security protocol data to\n"
		"a controller. Security Receives for the same protocol should be\n"
		"performed after Security Sends. The security protocol field\n"
		"associates Security Sends (security-send) and Security Receives (security-recv).";
	const char *file = "transfer payload";
	const char *tl = "transfer length (cf. SPC-4)";

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	_cleanup_free_ void *sec_buf = NULL;
	_cleanup_file_ int sec_fd = -1;
	unsigned int sec_size;
	int err;

	struct config {
		__u32	namespace_id;
		char	*file;
		__u8	nssf;
		__u8	secp;
		__u16	spsp;
		__u32	tl;
	};

	struct config cfg = {
		.namespace_id	= 0,
		.file		= "",
		.nssf		= 0,
		.secp		= 0,
		.spsp		= 0,
		.tl		= 0,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_desired),
		  OPT_FILE("file",         'f', &cfg.file,         file),
		  OPT_BYTE("nssf",         'N', &cfg.nssf,         nssf),
		  OPT_BYTE("secp",         'p', &cfg.secp,         secp),
		  OPT_SHRT("spsp",         's', &cfg.spsp,         spsp),
		  OPT_UINT("tl",           't', &cfg.tl,           tl));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	if (cfg.tl == 0) {
		nvme_show_error("--tl unspecified or zero");
		return -EINVAL;
	}
	if ((cfg.tl & 3) != 0)
		nvme_show_error(
		    "WARNING: --tl not dword aligned; unaligned bytes may be truncated");

	if (strlen(cfg.file) == 0) {
		sec_fd = STDIN_FILENO;
		sec_size = cfg.tl;
	} else {
		sec_fd = open(cfg.file, O_RDONLY);
		if (sec_fd < 0) {
			nvme_show_error("Failed to open %s: %s", cfg.file, strerror(errno));
			return -EINVAL;
		}

		err = fstat(sec_fd, &sb);
		if (err < 0) {
			nvme_show_perror("fstat");
			return err;
		}

		sec_size = cfg.tl > sb.st_size ? cfg.tl : sb.st_size;
	}

	sec_buf = nvme_alloc(cfg.tl);
	if (!sec_buf)
		return -ENOMEM;

	err = read(sec_fd, sec_buf, sec_size);
	if (err < 0) {
		nvme_show_error("Failed to read data from security file %s with %s", cfg.file,
				strerror(errno));
		return -errno;
	}

	struct nvme_security_send_args args = {
		.args_size	= sizeof(args),
		.nsid		= cfg.namespace_id,
		.nssf		= cfg.nssf,
		.spsp0		= cfg.spsp & 0xff,
		.spsp1		= cfg.spsp >> 8,
		.secp		= cfg.secp,
		.tl		= cfg.tl,
		.data_len	= cfg.tl,
		.data		= sec_buf,
		.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
		.result		= NULL,
	};

	err = nvme_cli_security_send(dev, &args);

	if (err < 0)
		nvme_show_error("security-send: %s", nvme_strerror(errno));
	else if (err != 0)
		nvme_show_status(err);
	else
		printf("NVME Security Send Command Success\n");

	return err;
}

static int dir_send(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Set directive parameters of the specified directive type.";
	const char *endir = "directive enable";
	const char *ttype = "target directive type to be enabled/disabled";
	const char *input = "write/send file (default stdin)";

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	_cleanup_free_ void *buf = NULL;
	__u32 result;
	__u32 dw12 = 0;
	_cleanup_file_ int ffd = STDIN_FILENO;
	int err;

	struct config {
		__u32	namespace_id;
		__u32	data_len;
		__u8	dtype;
		__u8	ttype;
		__u16	dspec;
		__u8	doper;
		__u16	endir;
		bool	human_readable;
		bool	raw_binary;
		char	*file;
	};

	struct config cfg = {
		.namespace_id	= 1,
		.data_len	= 0,
		.dtype		= 0,
		.ttype		= 0,
		.dspec		= 0,
		.doper		= 0,
		.endir		= 1,
		.human_readable	= false,
		.raw_binary	= false,
		.file		= "",
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id",   'n', &cfg.namespace_id,   namespace_id_desired),
		  OPT_UINT("data-len",       'l', &cfg.data_len,       buf_len),
		  OPT_BYTE("dir-type",       'D', &cfg.dtype,          dtype),
		  OPT_BYTE("target-dir",     'T', &cfg.ttype,          ttype),
		  OPT_SHRT("dir-spec",       'S', &cfg.dspec,          dspec_w_dtype),
		  OPT_BYTE("dir-oper",       'O', &cfg.doper,          doper),
		  OPT_SHRT("endir",          'e', &cfg.endir,          endir),
		  OPT_FLAG("human-readable", 'H', &cfg.human_readable, human_readable_directive),
		  OPT_FLAG("raw-binary",     'b', &cfg.raw_binary,     raw_directive),
		  OPT_FILE("input-file",     'i', &cfg.file,           input));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	switch (cfg.dtype) {
	case NVME_DIRECTIVE_DTYPE_IDENTIFY:
		switch (cfg.doper) {
		case NVME_DIRECTIVE_SEND_IDENTIFY_DOPER_ENDIR:
			if (!cfg.ttype) {
				nvme_show_error("target-dir required param\n");
				return -EINVAL;
			}
			dw12 = cfg.ttype << 8 | cfg.endir;
			break;
		default:
			nvme_show_error("invalid directive operations for Identify Directives");
			return -EINVAL;
		}
		break;
	case NVME_DIRECTIVE_DTYPE_STREAMS:
		switch (cfg.doper) {
		case NVME_DIRECTIVE_SEND_STREAMS_DOPER_RELEASE_IDENTIFIER:
		case NVME_DIRECTIVE_SEND_STREAMS_DOPER_RELEASE_RESOURCE:
			break;
		default:
			nvme_show_error("invalid directive operations for Streams Directives");
			return -EINVAL;
		}
		break;
	default:
		nvme_show_error("invalid directive type");
		return -EINVAL;
	}

	if (cfg.data_len) {
		buf = nvme_alloc(cfg.data_len);
		if (!buf)
			return -ENOMEM;
	}

	if (buf) {
		if (strlen(cfg.file)) {
			ffd = open(cfg.file, O_RDONLY);
			if (ffd <= 0) {
				nvme_show_error("Failed to open file %s: %s",
						cfg.file, strerror(errno));
				return -EINVAL;
			}
		}
		err = read(ffd, (void *)buf, cfg.data_len);
		if (err < 0) {
			nvme_show_error("failed to read data buffer from input file %s",
					strerror(errno));
			return -errno;
		}
	}

	struct nvme_directive_send_args args = {
		.args_size	= sizeof(args),
		.fd		= dev_fd(dev),
		.nsid		= cfg.namespace_id,
		.dspec		= cfg.dspec,
		.doper		= cfg.doper,
		.dtype		= cfg.dtype,
		.cdw12		= dw12,
		.data_len	= cfg.data_len,
		.data		= buf,
		.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
		.result		= &result,
	};
	err = nvme_directive_send(&args);
	if (err < 0) {
		nvme_show_error("dir-send: %s", nvme_strerror(errno));
		return err;
	}
	if (!err) {
		printf("dir-send: type %#x, operation %#x, spec_val %#x, nsid %#x, result %#x\n",
		       cfg.dtype, cfg.doper, cfg.dspec, cfg.namespace_id, result);
		if (buf) {
			if (!cfg.raw_binary)
				d(buf, cfg.data_len, 16, 1);
			else
				d_raw(buf, cfg.data_len);
		}
	} else if (err > 0) {
		nvme_show_status(err);
	}

	return err;
}

static int write_uncor(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc =
	    "The Write Uncorrectable command is used to set a range of logical blocks to invalid.";

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	int err;

	struct config {
		__u32	namespace_id;
		__u64	start_block;
		__u16	block_count;
		__u8	dtype;
		__u16	dspec;
	};

	struct config cfg = {
		.namespace_id	= 0,
		.start_block	= 0,
		.block_count	= 0,
		.dtype			= 0,
		.dspec			= 0,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id",  'n', &cfg.namespace_id, namespace_desired),
		  OPT_SUFFIX("start-block", 's', &cfg.start_block,  start_block),
		  OPT_SHRT("block-count",   'c', &cfg.block_count,  block_count),
		  OPT_BYTE("dir-type",      'T', &cfg.dtype,        dtype),
		  OPT_SHRT("dir-spec",      'S', &cfg.dspec,        dspec_w_dtype));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	if (!cfg.namespace_id) {
		err = nvme_get_nsid(dev_fd(dev), &cfg.namespace_id);
		if (err < 0) {
			nvme_show_error("get-namespace-id: %s", nvme_strerror(errno));
			return err;
		}
	}

	if (cfg.dtype > 0xf) {
		nvme_show_error("Invalid directive type, %x",	cfg.dtype);
		return -EINVAL;
	}

	struct nvme_io_args args = {
		.args_size	= sizeof(args),
		.fd		= dev_fd(dev),
		.nsid		= cfg.namespace_id,
		.slba		= cfg.start_block,
		.nlb		= cfg.block_count,
		.control	= cfg.dtype << 4,
		.dspec		= cfg.dspec,
		.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
		.result		= NULL,
	};
	err = nvme_write_uncorrectable(&args);
	if (err < 0)
		nvme_show_error("write uncorrectable: %s", nvme_strerror(errno));
	else if (err != 0)
		nvme_show_status(err);
	else
		printf("NVME Write Uncorrectable Success\n");

	return err;
}

static int invalid_tags(__u64 storage_tag, __u64 ref_tag, __u8 sts, __u8 pif)
{
	int result = 0;

	if (sts < 64 && storage_tag >= (1LL << sts)) {
		nvme_show_error("Storage tag larger than storage tag size");
		return 1;
	}

	switch (pif) {
	case 0:
		if (ref_tag >= (1LL << (32 - sts)))
			result = 1;
		break;
	case 1:
		if (sts > 16 && ref_tag >= (1LL << (80 - sts)))
			result = 1;
		break;
	case 2:
		if (sts > 0 && ref_tag >= (1LL << (48 - sts)))
			result = 1;
		break;
	default:
		nvme_show_error("Invalid PIF");
		result = 1;
		break;
	}

	if (result)
		nvme_show_error("Reference tag larger than allowed by PIF");

	return result;
}

static int write_zeroes(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	_cleanup_free_ struct nvme_nvm_id_ns *nvm_ns = NULL;
	_cleanup_free_ struct nvme_id_ns *ns = NULL;
	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	__u8 lba_index, sts = 0, pif = 0;
	__u16 control = 0;
	int err;

	const char *desc =
	    "The Write Zeroes command is used to set a range of logical blocks to zero.";
	const char *deac =
	    "Set DEAC bit, requesting controller to deallocate specified logical blocks";
	const char *storage_tag_check =
	    "This bit specifies the Storage Tag field shall be checked as\n"
	    "part of end-to-end data protection processing";

	struct config {
		__u32	namespace_id;
		__u64	start_block;
		__u16	block_count;
		__u8	dtype;
		bool	deac;
		bool	limited_retry;
		bool	force_unit_access;
		__u8	prinfo;
		__u64	ref_tag;
		__u16	app_tag_mask;
		__u16	app_tag;
		__u64	storage_tag;
		bool	storage_tag_check;
		__u16	dspec;
	};

	struct config cfg = {
		.namespace_id		= 0,
		.start_block		= 0,
		.block_count		= 0,
		.dtype				= 0,
		.deac				= false,
		.limited_retry		= false,
		.force_unit_access	= false,
		.prinfo				= 0,
		.ref_tag			= 0,
		.app_tag_mask		= 0,
		.app_tag			= 0,
		.storage_tag		= 0,
		.storage_tag_check	= false,
		.dspec				= 0,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id",      'n', &cfg.namespace_id,      namespace_desired),
		  OPT_SUFFIX("start-block",     's', &cfg.start_block,       start_block),
		  OPT_SHRT("block-count",       'c', &cfg.block_count,       block_count),
		  OPT_BYTE("dir-type",          'T', &cfg.dtype,             dtype),
		  OPT_FLAG("deac",              'd', &cfg.deac,              deac),
		  OPT_FLAG("limited-retry",     'l', &cfg.limited_retry,     limited_retry),
		  OPT_FLAG("force-unit-access", 'f', &cfg.force_unit_access, force_unit_access),
		  OPT_BYTE("prinfo",            'p', &cfg.prinfo,            prinfo),
		  OPT_SUFFIX("ref-tag",         'r', &cfg.ref_tag,           ref_tag),
		  OPT_SHRT("app-tag-mask",      'm', &cfg.app_tag_mask,      app_tag_mask),
		  OPT_SHRT("app-tag",           'a', &cfg.app_tag,           app_tag),
		  OPT_SUFFIX("storage-tag",     'S', &cfg.storage_tag,       storage_tag),
		  OPT_FLAG("storage-tag-check", 'C', &cfg.storage_tag_check, storage_tag_check),
		  OPT_SHRT("dir-spec",          'D', &cfg.dspec,             dspec_w_dtype));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	if (cfg.prinfo > 0xf)
		return -EINVAL;

	if (cfg.dtype > 0xf) {
		nvme_show_error("Invalid directive type, %x", cfg.dtype);
		return -EINVAL;
	}

	control |= (cfg.prinfo << 10);
	if (cfg.limited_retry)
		control |= NVME_IO_LR;
	if (cfg.force_unit_access)
		control |= NVME_IO_FUA;
	if (cfg.deac)
		control |= NVME_IO_DEAC;
	if (cfg.storage_tag_check)
		control |= NVME_IO_STC;
	control |= (cfg.dtype << 4);
	if (!cfg.namespace_id) {
		err = nvme_get_nsid(dev_fd(dev), &cfg.namespace_id);
		if (err < 0) {
			nvme_show_error("get-namespace-id: %s", nvme_strerror(errno));
			return err;
		}
	}

	ns = nvme_alloc(sizeof(*ns));
	if (!ns)
		return -ENOMEM;

	err = nvme_cli_identify_ns(dev, cfg.namespace_id, ns);
	if (err < 0) {
		nvme_show_error("identify namespace: %s", nvme_strerror(errno));
		return err;
	} else if (err) {
		nvme_show_status(err);
		return err;
	}

	nvm_ns = nvme_alloc(sizeof(*nvm_ns));
	if (!nvm_ns)
		return -ENOMEM;

	err = nvme_identify_ns_csi(dev_fd(dev), cfg.namespace_id, 0, NVME_CSI_NVM, nvm_ns);
	if (!err) {
		nvme_id_ns_flbas_to_lbaf_inuse(ns->flbas, &lba_index);
		sts = nvm_ns->elbaf[lba_index] & NVME_NVM_ELBAF_STS_MASK;
		pif = (nvm_ns->elbaf[lba_index] & NVME_NVM_ELBAF_PIF_MASK) >> 7;
	}

	if (invalid_tags(cfg.storage_tag, cfg.ref_tag, sts, pif))
		return -EINVAL;

	struct nvme_io_args args = {
		.args_size	= sizeof(args),
		.fd			= dev_fd(dev),
		.nsid		= cfg.namespace_id,
		.slba		= cfg.start_block,
		.nlb		= cfg.block_count,
		.control	= control,
		.reftag_u64	= cfg.ref_tag,
		.apptag		= cfg.app_tag,
		.appmask	= cfg.app_tag_mask,
		.sts		= sts,
		.pif		= pif,
		.storage_tag	= cfg.storage_tag,
		.dspec		= cfg.dspec,
		.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
		.result		= NULL,
	};
	err = nvme_write_zeros(&args);
	if (err < 0)
		nvme_show_error("write-zeroes: %s", nvme_strerror(errno));
	else if (err != 0)
		nvme_show_status(err);
	else
		printf("NVME Write Zeroes Success\n");

	return err;
}

static int dsm(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "The Dataset Management command is used by the host to\n"
		"indicate attributes for ranges of logical blocks. This includes attributes\n"
		"for discarding unused blocks, data read and write frequency, access size, and other\n"
		"information that may be used to optimize performance and reliability.";
	const char *blocks = "Comma separated list of the number of blocks in each range";
	const char *starting_blocks = "Comma separated list of the starting block in each range";
	const char *context_attrs = "Comma separated list of the context attributes in each range";
	const char *ad = "Attribute Deallocate";
	const char *idw = "Attribute Integral Dataset for Write";
	const char *idr = "Attribute Integral Dataset for Read";
	const char *cdw11 = "All the command DWORD 11 attributes. Use instead of specifying individual attributes";

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	_cleanup_free_ struct nvme_dsm_range *dsm = NULL;
	uint16_t nr, nc, nb, ns;
	__u32 ctx_attrs[256] = {0,};
	__u32 nlbs[256] = {0,};
	__u64 slbas[256] = {0,};
	int err;

	struct config {
		__u32	namespace_id;
		char	*ctx_attrs;
		char	*blocks;
		char	*slbas;
		bool	ad;
		bool	idw;
		bool	idr;
		__u32	cdw11;
	};

	struct config cfg = {
		.namespace_id	= 0,
		.ctx_attrs	= "",
		.blocks		= "",
		.slbas		= "",
		.ad		= false,
		.idw		= false,
		.idr		= false,
		.cdw11		= 0,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id_desired),
		  OPT_LIST("ctx-attrs",    'a', &cfg.ctx_attrs,    context_attrs),
		  OPT_LIST("blocks",       'b', &cfg.blocks,       blocks),
		  OPT_LIST("slbs",         's', &cfg.slbas,        starting_blocks),
		  OPT_FLAG("ad",           'd', &cfg.ad,           ad),
		  OPT_FLAG("idw",          'w', &cfg.idw,          idw),
		  OPT_FLAG("idr",          'r', &cfg.idr,          idr),
		  OPT_UINT("cdw11",        'c', &cfg.cdw11,        cdw11));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	nc = argconfig_parse_comma_sep_array_u32(cfg.ctx_attrs, ctx_attrs, ARRAY_SIZE(ctx_attrs));
	nb = argconfig_parse_comma_sep_array_u32(cfg.blocks, nlbs, ARRAY_SIZE(nlbs));
	ns = argconfig_parse_comma_sep_array_u64(cfg.slbas, slbas, ARRAY_SIZE(slbas));
	nr = max(nc, max(nb, ns));
	if (!nr || nr > 256) {
		nvme_show_error("No range definition provided");
		return -EINVAL;
	}

	if (!cfg.namespace_id) {
		err = nvme_get_nsid(dev_fd(dev), &cfg.namespace_id);
		if (err < 0) {
			nvme_show_error("get-namespace-id: %s", nvme_strerror(errno));
			return err;
		}
	}
	if (!cfg.cdw11)
		cfg.cdw11 = (cfg.ad << 2) | (cfg.idw << 1) | (cfg.idr << 0);

	dsm = nvme_alloc(sizeof(*dsm) * 256);
	if (!dsm)
		return -ENOMEM;

	nvme_init_dsm_range(dsm, ctx_attrs, nlbs, slbas, nr);
	struct nvme_dsm_args args = {
		.args_size	= sizeof(args),
		.fd		= dev_fd(dev),
		.nsid		= cfg.namespace_id,
		.attrs		= cfg.cdw11,
		.nr_ranges	= nr,
		.dsm		= dsm,
		.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
		.result		= NULL,
	};
	err = nvme_dsm(&args);
	if (err < 0)
		nvme_show_error("data-set management: %s", nvme_strerror(errno));
	else if (err != 0)
		nvme_show_status(err);
	else
		printf("NVMe DSM: success\n");

	return err;
}

static int copy_cmd(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "The Copy command is used by the host to copy data\n"
		"from one or more source logical block ranges to a\n"
		"single consecutive destination logical block range.";
	const char *d_sdlba = "64-bit addr of first destination logical block";
	const char *d_slbas = "64-bit addr of first block per range (comma-separated list)";
	const char *d_nlbs = "number of blocks per range (comma-separated list, zeroes-based values)";
	const char *d_snsids = "source namespace identifier per range (comma-separated list)";
	const char *d_sopts = "source options per range (comma-separated list)";
	const char *d_lr = "limited retry";
	const char *d_fua = "force unit access";
	const char *d_prinfor = "protection information and check field (read part)";
	const char *d_prinfow = "protection information and check field (write part)";
	const char *d_ilbrt = "initial lba reference tag (write part)";
	const char *d_eilbrts = "expected lba reference tags (read part, comma-separated list)";
	const char *d_lbat = "lba application tag (write part)";
	const char *d_elbats = "expected lba application tags (read part, comma-separated list)";
	const char *d_lbatm = "lba application tag mask (write part)";
	const char *d_elbatms = "expected lba application tag masks (read part, comma-separated list)";
	const char *d_dtype = "directive type (write part)";
	const char *d_dspec = "directive specific (write part)";
	const char *d_format = "source range entry format";

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	__u16 nr, nb, ns, nrts, natms, nats, nids;
	__u16 nlbs[256] = { 0 };
	__u64 slbas[256] = { 0 };
	__u32 snsids[256] = { 0 };
	__u16 sopts[256] = { 0 };
	int err;

	union {
		__u32 short_pi[256];
		__u64 long_pi[256];
	} eilbrts;

	__u32 elbatms[256] = { 0 };
	__u32 elbats[256] = { 0 };

	union {
		struct nvme_copy_range f0[256];
		struct nvme_copy_range_f1 f1[256];
		struct nvme_copy_range_f2 f2[256];
		struct nvme_copy_range_f3 f3[256];
	} *copy;

	struct config {
		__u32	namespace_id;
		__u64	sdlba;
		char	*slbas;
		char	*nlbs;
		char	*snsids;
		char	*sopts;
		bool	lr;
		bool	fua;
		__u8	prinfow;
		__u8	prinfor;
		__u64	ilbrt;
		char	*eilbrts;
		__u16	lbat;
		char	*elbats;
		__u16	lbatm;
		char	*elbatms;
		__u8	dtype;
		__u16	dspec;
		__u8	format;
	};

	struct config cfg = {
		.namespace_id	= 0,
		.sdlba		= 0,
		.slbas		= "",
		.nlbs		= "",
		.snsids		= "",
		.sopts		= "",
		.lr		= false,
		.fua		= false,
		.prinfow	= 0,
		.prinfor	= 0,
		.ilbrt		= 0,
		.eilbrts	= "",
		.lbat		= 0,
		.elbats		= "",
		.lbatm		= 0,
		.elbatms	= "",
		.dtype		= 0,
		.dspec		= 0,
		.format		= 0,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id",           'n', &cfg.namespace_id,	namespace_id_desired),
		  OPT_SUFFIX("sdlba",                'd', &cfg.sdlba,		d_sdlba),
		  OPT_LIST("slbs",                   's', &cfg.slbas,		d_slbas),
		  OPT_LIST("blocks",                 'b', &cfg.nlbs,		d_nlbs),
		  OPT_LIST("snsids",                 'N', &cfg.snsids,		d_snsids),
		  OPT_LIST("sopts",                  'O', &cfg.sopts,		d_sopts),
		  OPT_FLAG("limited-retry",          'l', &cfg.lr,		d_lr),
		  OPT_FLAG("force-unit-access",      'f', &cfg.fua,		d_fua),
		  OPT_BYTE("prinfow",                'p', &cfg.prinfow,		d_prinfow),
		  OPT_BYTE("prinfor",                'P', &cfg.prinfor,		d_prinfor),
		  OPT_SUFFIX("ref-tag",              'r', &cfg.ilbrt,		d_ilbrt),
		  OPT_LIST("expected-ref-tags",      'R', &cfg.eilbrts,		d_eilbrts),
		  OPT_SHRT("app-tag",                'a', &cfg.lbat,		d_lbat),
		  OPT_LIST("expected-app-tags",      'A', &cfg.elbats,		d_elbats),
		  OPT_SHRT("app-tag-mask",           'm', &cfg.lbatm,		d_lbatm),
		  OPT_LIST("expected-app-tag-masks", 'M', &cfg.elbatms,		d_elbatms),
		  OPT_BYTE("dir-type",               'T', &cfg.dtype,		d_dtype),
		  OPT_SHRT("dir-spec",               'S', &cfg.dspec,		d_dspec),
		  OPT_BYTE("format",                 'F', &cfg.format,		d_format));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	nb = argconfig_parse_comma_sep_array_u16(cfg.nlbs, nlbs, ARRAY_SIZE(nlbs));
	ns = argconfig_parse_comma_sep_array_u64(cfg.slbas, slbas, ARRAY_SIZE(slbas));
	nids = argconfig_parse_comma_sep_array_u32(cfg.snsids, snsids, ARRAY_SIZE(snsids));
	argconfig_parse_comma_sep_array_u16(cfg.sopts, sopts, ARRAY_SIZE(sopts));

	if (cfg.format == 0 || cfg.format == 2) {
		nrts = argconfig_parse_comma_sep_array_u32(cfg.eilbrts, eilbrts.short_pi,
							   ARRAY_SIZE(eilbrts.short_pi));
	} else if (cfg.format == 1 || cfg.format == 3) {
		nrts = argconfig_parse_comma_sep_array_u64(cfg.eilbrts, eilbrts.long_pi,
							   ARRAY_SIZE(eilbrts.long_pi));
	} else {
		nvme_show_error("invalid format");
		return -EINVAL;
	}

	natms = argconfig_parse_comma_sep_array_u32(cfg.elbatms, elbatms, ARRAY_SIZE(elbatms));
	nats = argconfig_parse_comma_sep_array_u32(cfg.elbats, elbats, ARRAY_SIZE(elbats));

	nr = max(nb, max(ns, max(nrts, max(natms, nats))));
	if (cfg.format == 2 || cfg.format == 3) {
		if (nr != nids) {
			nvme_show_error("formats 2 and 3 require source namespace ids for each source range");
			return -EINVAL;
		}
	} else if (nids) {
		nvme_show_error("formats 0 and 1 do not support cross-namespace copy");
		return -EINVAL;
	}
	if (!nr || nr > 256) {
		nvme_show_error("invalid range");
		return -EINVAL;
	}

	if (!cfg.namespace_id) {
		err = nvme_get_nsid(dev_fd(dev), &cfg.namespace_id);
		if (err < 0) {
			nvme_show_error("get-namespace-id: %s", nvme_strerror(errno));
			return err;
		}
	}

	copy = nvme_alloc(sizeof(*copy));
	if (!copy)
		return -ENOMEM;

	if (cfg.format == 0)
		nvme_init_copy_range(copy->f0, nlbs, slbas, eilbrts.short_pi, elbatms, elbats, nr);
	else if (cfg.format == 1)
		nvme_init_copy_range_f1(copy->f1, nlbs, slbas, eilbrts.long_pi, elbatms, elbats, nr);
	else if (cfg.format == 2)
		nvme_init_copy_range_f2(copy->f2, snsids, nlbs, slbas, sopts, eilbrts.short_pi, elbatms,
					elbats, nr);
	else if (cfg.format == 3)
		nvme_init_copy_range_f3(copy->f3, snsids, nlbs, slbas, sopts, eilbrts.long_pi, elbatms,
					elbats, nr);

	struct nvme_copy_args args = {
		.args_size	= sizeof(args),
		.fd		= dev_fd(dev),
		.nsid		= cfg.namespace_id,
		.copy		= copy->f0,
		.sdlba		= cfg.sdlba,
		.nr		= nr,
		.prinfor	= cfg.prinfor,
		.prinfow	= cfg.prinfow,
		.dtype		= cfg.dtype,
		.dspec		= cfg.dspec,
		.format		= cfg.format,
		.lr		= cfg.lr,
		.fua		= cfg.fua,
		.ilbrt_u64	= cfg.ilbrt,
		.lbatm		= cfg.lbatm,
		.lbat		= cfg.lbat,
		.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
		.result		= NULL,
	};
	err = nvme_copy(&args);
	if (err < 0)
		nvme_show_error("NVMe Copy: %s", nvme_strerror(errno));
	else if (err != 0)
		nvme_show_status(err);
	else
		printf("NVMe Copy: success\n");

	return err;
}

static int flush_cmd(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Commit data and metadata associated with\n"
		"given namespaces to nonvolatile media. Applies to all commands\n"
		"finished before the flush was submitted. Additional data may also be\n"
		"flushed by the controller, from any namespace, depending on controller and\n"
		"associated namespace status.";

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	int err;

	struct config {
		__u32	namespace_id;
	};

	struct config cfg = {
		.namespace_id	= 0,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id_desired));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	if (!cfg.namespace_id) {
		err = nvme_get_nsid(dev_fd(dev), &cfg.namespace_id);
		if (err < 0) {
			nvme_show_error("get-namespace-id: %s", nvme_strerror(errno));
			return err;
		}
	}

	err = nvme_flush(dev_fd(dev), cfg.namespace_id);
	if (err < 0)
		nvme_show_error("flush: %s", nvme_strerror(errno));
	else if (err != 0)
		nvme_show_status(err);
	else
		printf("NVMe Flush: success\n");

	return err;
}

static int resv_acquire(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Obtain a reservation on a given\n"
		"namespace. Only one reservation is allowed at a time on a\n"
		"given namespace, though multiple controllers may register\n"
		"with that namespace. Namespace reservation will abort with\n"
		"status Reservation Conflict if the given namespace is already reserved.";
	const char *prkey = "pre-empt reservation key";
	const char *racqa = "reservation acquire action";

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	int err;

	struct config {
		__u32	namespace_id;
		__u64	crkey;
		__u64	prkey;
		__u8	rtype;
		__u8	racqa;
		bool	iekey;
	};

	struct config cfg = {
		.namespace_id	= 0,
		.crkey		= 0,
		.prkey		= 0,
		.rtype		= 0,
		.racqa		= 0,
		.iekey		= false,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id_desired),
		  OPT_SUFFIX("crkey",      'c', &cfg.crkey,        crkey),
		  OPT_SUFFIX("prkey",      'p', &cfg.prkey,        prkey),
		  OPT_BYTE("rtype",        't', &cfg.rtype,        rtype),
		  OPT_BYTE("racqa",        'a', &cfg.racqa,        racqa),
		  OPT_FLAG("iekey",        'i', &cfg.iekey,        iekey));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	if (!cfg.namespace_id) {
		err = nvme_get_nsid(dev_fd(dev), &cfg.namespace_id);
		if (err < 0) {
			nvme_show_error("get-namespace-id: %s", nvme_strerror(errno));
			return err;
		}
	}
	if (cfg.racqa > 7) {
		nvme_show_error("invalid racqa:%d", cfg.racqa);
		return -EINVAL;
	}

	struct nvme_resv_acquire_args args = {
		.args_size	= sizeof(args),
		.fd		= dev_fd(dev),
		.nsid		= cfg.namespace_id,
		.rtype		= cfg.rtype,
		.racqa		= cfg.racqa,
		.iekey		= !!cfg.iekey,
		.crkey		= cfg.crkey,
		.nrkey		= cfg.prkey,
		.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
		.result		= NULL,
	};
	err = nvme_resv_acquire(&args);
	if (err < 0)
		nvme_show_error("reservation acquire: %s", nvme_strerror(errno));
	else if (err != 0)
		nvme_show_status(err);
	else
		printf("NVME Reservation Acquire success\n");

	return err;
}

static int resv_register(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Register, de-register, or\n"
		"replace a controller's reservation on a given namespace.\n"
		"Only one reservation at a time is allowed on any namespace.";
	const char *nrkey = "new reservation key";
	const char *rrega = "reservation registration action";
	const char *cptpl = "change persistence through power loss setting";

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	int err;

	struct config {
		__u32	namespace_id;
		__u64	crkey;
		__u64	nrkey;
		__u8	rrega;
		__u8	cptpl;
		bool	iekey;
	};

	struct config cfg = {
		.namespace_id	= 0,
		.crkey		= 0,
		.nrkey		= 0,
		.rrega		= 0,
		.cptpl		= false,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id_desired),
		  OPT_SUFFIX("crkey",      'c', &cfg.crkey,        crkey),
		  OPT_SUFFIX("nrkey",      'k', &cfg.nrkey,        nrkey),
		  OPT_BYTE("rrega",        'r', &cfg.rrega,        rrega),
		  OPT_BYTE("cptpl",        'p', &cfg.cptpl,        cptpl),
		  OPT_FLAG("iekey",        'i', &cfg.iekey,        iekey));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	if (!cfg.namespace_id) {
		err = nvme_get_nsid(dev_fd(dev), &cfg.namespace_id);
		if (err < 0) {
			nvme_show_error("get-namespace-id: %s", nvme_strerror(errno));
			return err;
		}
	}
	if (cfg.cptpl > 3) {
		nvme_show_error("invalid cptpl:%d", cfg.cptpl);
		return -EINVAL;
	}

	if (cfg.rrega > 7) {
		nvme_show_error("invalid rrega:%d", cfg.rrega);
		return -EINVAL;
	}

	struct nvme_resv_register_args args = {
		.args_size	= sizeof(args),
		.fd		= dev_fd(dev),
		.nsid		= cfg.namespace_id,
		.rrega		= cfg.rrega,
		.cptpl		= cfg.cptpl,
		.iekey		= !!cfg.iekey,
		.crkey		= cfg.crkey,
		.nrkey		= cfg.nrkey,
		.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
		.result		= NULL,
	};
	err = nvme_resv_register(&args);
	if (err < 0)
		nvme_show_error("reservation register: %s", nvme_strerror(errno));
	else if (err != 0)
		nvme_show_status(err);
	else
		printf("NVME Reservation  success\n");

	return err;
}

static int resv_release(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Releases reservation held on a\n"
		"namespace by the given controller. If rtype != current reservation\n"
		"type, release will fails. If the given controller holds no\n"
		"reservation on the namespace or is not the namespace's current\n"
		"reservation holder, the release command completes with no\n"
		"effect. If the reservation type is not Write Exclusive or\n"
		"Exclusive Access, all registrants on the namespace except\n"
		"the issuing controller are notified.";
	const char *rrela = "reservation release action";

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	int err;

	struct config {
		__u32	namespace_id;
		__u64	crkey;
		__u8	rtype;
		__u8	rrela;
		__u8	iekey;
	};

	struct config cfg = {
		.namespace_id	= 0,
		.crkey		= 0,
		.rtype		= 0,
		.rrela		= 0,
		.iekey		= 0,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_desired),
		  OPT_SUFFIX("crkey",      'c', &cfg.crkey,        crkey),
		  OPT_BYTE("rtype",        't', &cfg.rtype,        rtype),
		  OPT_BYTE("rrela",        'a', &cfg.rrela,        rrela),
		  OPT_FLAG("iekey",        'i', &cfg.iekey,        iekey));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	if (!cfg.namespace_id) {
		err = nvme_get_nsid(dev_fd(dev), &cfg.namespace_id);
		if (err < 0) {
			nvme_show_error("get-namespace-id: %s", nvme_strerror(errno));
			return err;
		}
	}
	if (cfg.rrela > 7) {
		nvme_show_error("invalid rrela:%d", cfg.rrela);
		return -EINVAL;
	}

	struct nvme_resv_release_args args = {
		.args_size	= sizeof(args),
		.fd		= dev_fd(dev),
		.nsid		= cfg.namespace_id,
		.rtype		= cfg.rtype,
		.rrela		= cfg.rrela,
		.iekey		= !!cfg.iekey,
		.crkey		= cfg.crkey,
		.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
		.result		= NULL,
	};
	err = nvme_resv_release(&args);
	if (err < 0)
		nvme_show_error("reservation release: %s", nvme_strerror(errno));
	else if (err != 0)
		nvme_show_status(err);
	else
		printf("NVME Reservation Release success\n");

	return err;
}

static int resv_report(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Returns Reservation Status data\n"
		"structure describing any existing reservations on and the\n"
		"status of a given namespace. Namespace Reservation Status\n"
		"depends on the number of controllers registered for that namespace.";
	const char *numd = "number of dwords to transfer";
	const char *eds = "request extended data structure";

	_cleanup_free_ struct nvme_resv_status *status = NULL;
	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	enum nvme_print_flags flags;
	int err, size;

	struct config {
		__u32	namespace_id;
		__u32	numd;
		__u8	eds;
		bool	raw_binary;
	};

	struct config cfg = {
		.namespace_id	= 0,
		.numd		= 0,
		.eds		= false,
		.raw_binary	= false,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id",  'n', &cfg.namespace_id,   namespace_id_desired),
		  OPT_UINT("numd",          'd', &cfg.numd,           numd),
		  OPT_FLAG("eds",           'e', &cfg.eds,            eds),
		  OPT_FLAG("raw-binary",    'b', &cfg.raw_binary,     raw_dump));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(output_format_val, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.raw_binary)
		flags = BINARY;

	if (!cfg.namespace_id) {
		err = nvme_get_nsid(dev_fd(dev), &cfg.namespace_id);
		if (err < 0) {
			nvme_show_error("get-namespace-id: %s", nvme_strerror(errno));
			return err;
		}
	}

	if (!cfg.numd || cfg.numd >= (0x1000 >> 2))
		cfg.numd = (0x1000 >> 2) - 1;
	if (cfg.numd < 3)
		cfg.numd = 3;

	size = (cfg.numd + 1) << 2;

	status = nvme_alloc(size);
	if (!status)
		return -ENOMEM;

	struct nvme_resv_report_args args = {
		.args_size	= sizeof(args),
		.fd		= dev_fd(dev),
		.nsid		= cfg.namespace_id,
		.eds		= cfg.eds,
		.len		= size,
		.report		= status,
		.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
		.result		= NULL,
	};
	err = nvme_resv_report(&args);
	if (!err)
		nvme_show_resv_report(status, size, cfg.eds, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("reservation report: %s", nvme_strerror(errno));

	return err;
}

unsigned long long elapsed_utime(struct timeval start_time,
					struct timeval end_time)
{
	unsigned long long err = (end_time.tv_sec - start_time.tv_sec) * 1000000 +
		(end_time.tv_usec - start_time.tv_usec);
	return err;
}

static int submit_io(int opcode, char *command, const char *desc, int argc, char **argv)
{
	struct timeval start_time, end_time;
	void *buffer;
	_cleanup_free_ void *mbuffer = NULL;
	int err = 0;
	_cleanup_file_ int dfd = -1, mfd = -1;
	int flags;
	int mode = 0644;
	__u16 control = 0, nblocks = 0;
	__u32 dsmgmt = 0;
	unsigned int logical_block_size = 0;
	unsigned long long buffer_size = 0, mbuffer_size = 0;
	_cleanup_huge_ struct nvme_mem_huge mh = { 0, };
	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	_cleanup_free_ struct nvme_nvm_id_ns *nvm_ns = NULL;
	_cleanup_free_ struct nvme_id_ns *ns = NULL;
	__u8 lba_index, ms = 0, sts = 0, pif = 0;

	const char *start_block_addr = "64-bit addr of first block to access";
	const char *data_size = "size of data in bytes";
	const char *metadata_size = "size of metadata in bytes";
	const char *data = "data file";
	const char *metadata = "metadata file";
	const char *limited_retry_num = "limit num. media access attempts";
	const char *show = "show command before sending";
	const char *dtype_for_write = "directive type (for write-only)";
	const char *dspec = "directive specific (for write-only)";
	const char *dsm = "dataset management attributes (lower 8 bits)";
	const char *storage_tag_check = "This bit specifies the Storage Tag field shall be\n"
		"checked as part of end-to-end data protection processing";
	const char *force = "The \"I know what I'm doing\" flag, do not enforce exclusive access for write";

	struct config {
		__u32	namespace_id;
		__u64	start_block;
		__u16	block_count;
		__u64	data_size;
		__u64	metadata_size;
		__u64	ref_tag;
		char	*data;
		char	*metadata;
		__u8	prinfo;
		__u16	app_tag_mask;
		__u16	app_tag;
		__u64	storage_tag;
		bool	limited_retry;
		bool	force_unit_access;
		bool	storage_tag_check;
		__u8	dtype;
		__u16	dspec;
		__u8	dsmgmt;
		bool	show;
		bool	dry_run;
		bool	latency;
		bool	force;
	};

	struct config cfg = {
		.namespace_id		= 0,
		.start_block		= 0,
		.block_count		= 0,
		.data_size		= 0,
		.metadata_size		= 0,
		.ref_tag		= 0,
		.data			= "",
		.metadata		= "",
		.prinfo			= 0,
		.app_tag_mask		= 0,
		.app_tag		= 0,
		.storage_tag		= 0,
		.limited_retry		= false,
		.force_unit_access	= false,
		.storage_tag_check	= false,
		.dtype			= 0,
		.dspec			= 0,
		.dsmgmt			= 0,
		.show			= false,
		.dry_run		= false,
		.latency		= false,
		.force			= false,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id",      'n', &cfg.namespace_id,      namespace_id_desired),
		  OPT_SUFFIX("start-block",     's', &cfg.start_block,       start_block_addr),
		  OPT_SHRT("block-count",       'c', &cfg.block_count,       block_count),
		  OPT_SUFFIX("data-size",       'z', &cfg.data_size,         data_size),
		  OPT_SUFFIX("metadata-size",   'y', &cfg.metadata_size,     metadata_size),
		  OPT_SUFFIX("ref-tag",         'r', &cfg.ref_tag,           ref_tag),
		  OPT_FILE("data",              'd', &cfg.data,              data),
		  OPT_FILE("metadata",          'M', &cfg.metadata,          metadata),
		  OPT_BYTE("prinfo",            'p', &cfg.prinfo,            prinfo),
		  OPT_SHRT("app-tag-mask",      'm', &cfg.app_tag_mask,      app_tag_mask),
		  OPT_SHRT("app-tag",           'a', &cfg.app_tag,           app_tag),
		  OPT_SUFFIX("storage-tag",     'g', &cfg.storage_tag,       storage_tag),
		  OPT_FLAG("limited-retry",     'l', &cfg.limited_retry,     limited_retry_num),
		  OPT_FLAG("force-unit-access", 'f', &cfg.force_unit_access, force_unit_access),
		  OPT_FLAG("storage-tag-check", 'C', &cfg.storage_tag_check, storage_tag_check),
		  OPT_BYTE("dir-type",          'T', &cfg.dtype,             dtype_for_write),
		  OPT_SHRT("dir-spec",          'S', &cfg.dspec,             dspec),
		  OPT_BYTE("dsm",               'D', &cfg.dsmgmt,            dsm),
		  OPT_FLAG("show-command",      'V', &cfg.show,              show),
		  OPT_FLAG("dry-run",           'w', &cfg.dry_run,           dry),
		  OPT_FLAG("latency",           't', &cfg.latency,           latency),
		  OPT_FLAG("force",               0, &cfg.force,             force));

	if (opcode != nvme_cmd_write) {
		err = parse_and_open(&dev, argc, argv, desc, opts);
		if (err)
			return err;
	} else {
		err = argconfig_parse(argc, argv, desc, opts);
		if (err)
			return err;
		err = open_exclusive(&dev, argc, argv, cfg.force);
		if (err) {
			if (errno == EBUSY) {
				fprintf(stderr, "Failed to open %s.\n", basename(argv[optind]));
				fprintf(stderr, "Namespace is currently busy.\n");
				if (!cfg.force)
					fprintf(stderr,
						"Use the force [--force] option to ignore that.\n");
			} else {
				argconfig_print_help(desc, opts);
			}
			return err;
		}
	}

	if (!cfg.namespace_id) {
		err = nvme_get_nsid(dev_fd(dev), &cfg.namespace_id);
		if (err < 0) {
			nvme_show_error("get-namespace-id: %s", nvme_strerror(errno));
			return err;
		}
	}

	if (cfg.prinfo > 0xf)
		return err;

	dsmgmt = cfg.dsmgmt;
	control |= (cfg.prinfo << 10);
	if (cfg.limited_retry)
		control |= NVME_IO_LR;
	if (cfg.force_unit_access)
		control |= NVME_IO_FUA;
	if (cfg.storage_tag_check)
		control |= NVME_IO_STC;
	if (cfg.dtype) {
		if (cfg.dtype > 0xf) {
			nvme_show_error("Invalid directive type, %x", cfg.dtype);
			return -EINVAL;
		}
		control |= cfg.dtype << 4;
		dsmgmt |= ((__u32)cfg.dspec) << 16;
	}

	if (opcode & 1) {
		dfd = mfd = STDIN_FILENO;
		flags = O_RDONLY;
	} else {
		dfd = mfd = STDOUT_FILENO;
		flags = O_WRONLY | O_CREAT;
	}

	if (strlen(cfg.data)) {
		dfd = open(cfg.data, flags, mode);
		if (dfd < 0) {
			nvme_show_perror(cfg.data);
			return -EINVAL;
		}
	}

	if (strlen(cfg.metadata)) {
		mfd = open(cfg.metadata, flags, mode);
		if (mfd < 0) {
			nvme_show_perror(cfg.metadata);
			return -EINVAL;
		}
	}

	if (!cfg.data_size) {
		nvme_show_error("data size not provided");
		return -EINVAL;
	}

	ns = nvme_alloc(sizeof(*ns));
	if (!ns)
		return -ENOMEM;

	err = nvme_cli_identify_ns(dev, cfg.namespace_id, ns);
	if (err > 0) {
		nvme_show_status(err);
		return err;
	} else if (err < 0) {
		nvme_show_error("identify namespace: %s", nvme_strerror(errno));
		return err;
	}

	nvme_id_ns_flbas_to_lbaf_inuse(ns->flbas, &lba_index);
	logical_block_size = 1 << ns->lbaf[lba_index].ds;
	ms = ns->lbaf[lba_index].ms;
	if (NVME_FLBAS_META_EXT(ns->flbas)) {
		/*
		 * No meta data is transferred for PRACT=1 and MD=8:
		 *   5.2.2.1 Protection Information and Write Commands
		 *   5.2.2.2 Protection Information and Read Commands
		 */
		if (!((cfg.prinfo & 0x8) != 0 && ms == 8))
			logical_block_size += ms;
	}

	buffer_size = ((long long)cfg.block_count + 1) * logical_block_size;
	if (cfg.data_size < buffer_size)
		nvme_show_error("Rounding data size to fit block count (%lld bytes)", buffer_size);
	else
		buffer_size = cfg.data_size;

	if (argconfig_parse_seen(opts, "block-count")) {
		/* Use the value provided */
		nblocks = cfg.block_count;
	} else {
		/* Get the required block count. Note this is a zeroes based value. */
		nblocks = ((buffer_size + (logical_block_size - 1)) / logical_block_size) - 1;

		/* Update the data size based on the required block count */
		buffer_size = ((unsigned long long)nblocks + 1) * logical_block_size;
	}

	buffer = nvme_alloc_huge(buffer_size, &mh);
	if (!buffer)
		return -ENOMEM;

	nvm_ns = nvme_alloc(sizeof(*nvm_ns));
	if (!nvm_ns)
		return -ENOMEM;

	if (cfg.metadata_size) {
		err = nvme_identify_ns_csi(dev_fd(dev), 1, 0, NVME_CSI_NVM, nvm_ns);
		if (!err) {
			sts = nvm_ns->elbaf[lba_index] & NVME_NVM_ELBAF_STS_MASK;
			pif = (nvm_ns->elbaf[lba_index] & NVME_NVM_ELBAF_PIF_MASK) >> 7;
		}

		mbuffer_size = ((unsigned long long)cfg.block_count + 1) * ms;
		if (ms && cfg.metadata_size < mbuffer_size)
			nvme_show_error("Rounding metadata size to fit block count (%lld bytes)",
					mbuffer_size);
		else
			mbuffer_size = cfg.metadata_size;

		mbuffer = malloc(mbuffer_size);
		if (!mbuffer)
			return -ENOMEM;
		memset(mbuffer, 0, mbuffer_size);
	}

	if (invalid_tags(cfg.storage_tag, cfg.ref_tag, sts, pif))
		return -EINVAL;

	if (opcode & 1) {
		err = read(dfd, (void *)buffer, cfg.data_size);
		if (err < 0) {
			err = -errno;
			nvme_show_error("failed to read data buffer from input file %s", strerror(errno));
			return err;
		}
	}

	if ((opcode & 1) && cfg.metadata_size) {
		err = read(mfd, (void *)mbuffer, mbuffer_size);
		if (err < 0) {
			err = -errno;
			nvme_show_error("failed to read meta-data buffer from input file %s", strerror(errno));
			return err;
		}
	}

	if (cfg.show || cfg.dry_run) {
		printf("opcode       : %02x\n", opcode);
		printf("nsid         : %02x\n", cfg.namespace_id);
		printf("flags        : %02x\n", 0);
		printf("control      : %04x\n", control);
		printf("nblocks      : %04x\n", nblocks);
		printf("metadata     : %"PRIx64"\n", (uint64_t)(uintptr_t)mbuffer);
		printf("addr         : %"PRIx64"\n", (uint64_t)(uintptr_t)buffer);
		printf("slba         : %"PRIx64"\n", (uint64_t)cfg.start_block);
		printf("dsmgmt       : %08x\n", dsmgmt);
		printf("reftag       : %"PRIx64"\n", (uint64_t)cfg.ref_tag);
		printf("apptag       : %04x\n", cfg.app_tag);
		printf("appmask      : %04x\n", cfg.app_tag_mask);
		printf("storagetagcheck : %04x\n", cfg.storage_tag_check);
		printf("storagetag      : %"PRIx64"\n", (uint64_t)cfg.storage_tag);
		printf("pif             : %02x\n", pif);
		printf("sts             : %02x\n", sts);
	}
	if (cfg.dry_run)
		return 0;

	struct nvme_io_args args = {
		.args_size	= sizeof(args),
		.fd		= dev_fd(dev),
		.nsid		= cfg.namespace_id,
		.slba		= cfg.start_block,
		.nlb		= nblocks,
		.control	= control,
		.dsm		= cfg.dsmgmt,
		.sts		= sts,
		.pif		= pif,
		.dspec		= cfg.dspec,
		.reftag_u64	= cfg.ref_tag,
		.apptag		= cfg.app_tag,
		.appmask	= cfg.app_tag_mask,
		.storage_tag	= cfg.storage_tag,
		.data_len	= buffer_size,
		.data		= buffer,
		.metadata_len	= mbuffer_size,
		.metadata	= mbuffer,
		.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
		.result		= NULL,
	};
	gettimeofday(&start_time, NULL);
	err = nvme_io(&args, opcode);
	gettimeofday(&end_time, NULL);
	if (cfg.latency)
		printf(" latency: %s: %llu us\n", command, elapsed_utime(start_time, end_time));
	if (err < 0) {
		nvme_show_error("submit-io: %s", nvme_strerror(errno));
	} else if (err) {
		nvme_show_status(err);
	} else {
		if (!(opcode & 1) && write(dfd, (void *)buffer, buffer_size) < 0) {
			nvme_show_error("write: %s: failed to write buffer to output file",
				strerror(errno));
			err = -EINVAL;
		} else if (!(opcode & 1) && cfg.metadata_size &&
			   write(mfd, (void *)mbuffer, mbuffer_size) < 0) {
			nvme_show_error(
			    "write: %s: failed to write meta-data buffer to output file",
			    strerror(errno));
			err = -EINVAL;
		} else {
			fprintf(stderr, "%s: Success\n", command);
		}
	}

	return err;
}

static int compare(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Compare specified logical blocks on\n"
		"device with specified data buffer; return failure if buffer\n"
		"and block(s) are dissimilar";

	return submit_io(nvme_cmd_compare, "compare", desc, argc, argv);
}

static int read_cmd(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Copy specified logical blocks on the given\n"
		"device to specified data buffer (default buffer is stdout).";

	return submit_io(nvme_cmd_read, "read", desc, argc, argv);
}

static int write_cmd(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Copy from provided data buffer (default\n"
		"buffer is stdin) to specified logical blocks on the given device.";

	return submit_io(nvme_cmd_write, "write", desc, argc, argv);
}

static int verify_cmd(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	__u16 control = 0;
	__u8 lba_index, sts = 0, pif = 0;
	_cleanup_free_ struct nvme_nvm_id_ns *nvm_ns = NULL;
	_cleanup_free_ struct nvme_id_ns *ns = NULL;
	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	int err;

	const char *desc = "Verify specified logical blocks on the given device.";
	const char *force_unit_access_verify =
	    "force device to commit cached data before performing the verify operation";
	const char *storage_tag_check =
	    "This bit specifies the Storage Tag field shall be checked as part of Verify operation";

	struct config {
		__u32	namespace_id;
		__u64	start_block;
		__u16	block_count;
		bool	limited_retry;
		bool	force_unit_access;
		__u8	prinfo;
		__u32	ref_tag;
		__u16	app_tag;
		__u16	app_tag_mask;
		__u64	storage_tag;
		bool	storage_tag_check;
	};

	struct config cfg = {
		.namespace_id		= 0,
		.start_block		= 0,
		.block_count		= 0,
		.limited_retry		= false,
		.force_unit_access	= false,
		.prinfo			= 0,
		.ref_tag		= 0,
		.app_tag		= 0,
		.app_tag_mask		= 0,
		.storage_tag		= 0,
		.storage_tag_check	= false,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id",      'n', &cfg.namespace_id,      namespace_desired),
		  OPT_SUFFIX("start-block",     's', &cfg.start_block,       start_block),
		  OPT_SHRT("block-count",       'c', &cfg.block_count,       block_count),
		  OPT_FLAG("limited-retry",     'l', &cfg.limited_retry,     limited_retry),
		  OPT_FLAG("force-unit-access", 'f', &cfg.force_unit_access, force_unit_access_verify),
		  OPT_BYTE("prinfo",            'p', &cfg.prinfo,            prinfo),
		  OPT_SUFFIX("ref-tag",         'r', &cfg.ref_tag,           ref_tag),
		  OPT_SHRT("app-tag",           'a', &cfg.app_tag,           app_tag),
		  OPT_SHRT("app-tag-mask",      'm', &cfg.app_tag_mask,      app_tag_mask),
		  OPT_SUFFIX("storage-tag",     'S', &cfg.storage_tag,       storage_tag),
		  OPT_FLAG("storage-tag-check", 'C', &cfg.storage_tag_check, storage_tag_check));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	if (cfg.prinfo > 0xf)
		return -EINVAL;

	control |= (cfg.prinfo << 10);
	if (cfg.limited_retry)
		control |= NVME_IO_LR;
	if (cfg.force_unit_access)
		control |= NVME_IO_FUA;
	if (cfg.storage_tag_check)
		control |= NVME_IO_STC;

	if (!cfg.namespace_id) {
		err = nvme_get_nsid(dev_fd(dev), &cfg.namespace_id);
		if (err < 0) {
			nvme_show_error("get-namespace-id: %s", nvme_strerror(errno));
			return err;
		}
	}

	ns = nvme_alloc(sizeof(*ns));
	if (!ns)
		return -ENOMEM;

	err = nvme_cli_identify_ns(dev, cfg.namespace_id, ns);
	if (err < 0) {
		nvme_show_error("identify namespace: %s", nvme_strerror(errno));
		return err;
	} else if (err) {
		nvme_show_status(err);
		return err;
	}

	nvm_ns = nvme_alloc(sizeof(*nvm_ns));
	if (!nvm_ns)
		return -ENOMEM;

	err = nvme_identify_ns_csi(dev_fd(dev), cfg.namespace_id, 0,
				   NVME_CSI_NVM, nvm_ns);
	if (!err) {
		nvme_id_ns_flbas_to_lbaf_inuse(ns->flbas, &lba_index);
		sts = nvm_ns->elbaf[lba_index] & NVME_NVM_ELBAF_STS_MASK;
		pif = (nvm_ns->elbaf[lba_index] & NVME_NVM_ELBAF_PIF_MASK) >> 7;
	}

	if (invalid_tags(cfg.storage_tag, cfg.ref_tag, sts, pif))
		return -EINVAL;

	struct nvme_io_args args = {
		.args_size	= sizeof(args),
		.fd		= dev_fd(dev),
		.nsid		= cfg.namespace_id,
		.slba		= cfg.start_block,
		.nlb		= cfg.block_count,
		.control	= control,
		.reftag_u64	= cfg.ref_tag,
		.apptag		= cfg.app_tag,
		.appmask	= cfg.app_tag_mask,
		.sts		= sts,
		.pif		= pif,
		.storage_tag	= cfg.storage_tag,
		.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
		.result		= NULL,
	};
	err = nvme_verify(&args);
	if (err < 0)
		nvme_show_error("verify: %s", nvme_strerror(errno));
	else if (err != 0)
		nvme_show_status(err);
	else
		printf("NVME Verify Success\n");

	return err;
}

static int sec_recv(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Obtain results of one or more\n"
		"previously submitted security-sends. Results, and association\n"
		"between Security Send and Receive, depend on the security\n"
		"protocol field as they are defined by the security protocol\n"
		"used. A Security Receive must follow a Security Send made with\n"
		"the same security protocol.";
	const char *size = "size of buffer (prints to stdout on success)";
	const char *al = "allocation length (cf. SPC-4)";

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	_cleanup_free_ void *sec_buf = NULL;
	int err;

	struct config {
		__u32	namespace_id;
		__u32	size;
		__u8	nssf;
		__u8	secp;
		__u16	spsp;
		__u32	al;
		bool	raw_binary;
	};

	struct config cfg = {
		.namespace_id	= 0,
		.size		= 0,
		.nssf		= 0,
		.secp		= 0,
		.spsp		= 0,
		.al		= 0,
		.raw_binary	= false,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_desired),
		  OPT_UINT("size",         'x', &cfg.size,         size),
		  OPT_BYTE("nssf",         'N', &cfg.nssf,         nssf),
		  OPT_BYTE("secp",         'p', &cfg.secp,         secp),
		  OPT_SHRT("spsp",         's', &cfg.spsp,         spsp),
		  OPT_UINT("al",           't', &cfg.al,           al),
		  OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,   raw_dump));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	if (cfg.size) {
		sec_buf = nvme_alloc(sizeof(*sec_buf));
		if (!sec_buf)
			return -ENOMEM;
	}

	struct nvme_security_receive_args args = {
		.args_size	= sizeof(args),
		.nsid		= cfg.namespace_id,
		.nssf		= cfg.nssf,
		.spsp0		= cfg.spsp & 0xff,
		.spsp1		= cfg.spsp >> 8,
		.secp		= cfg.secp,
		.al		= cfg.al,
		.data_len	= cfg.size,
		.data		= sec_buf,
		.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
		.result		= NULL,
	};

	err = nvme_cli_security_receive(dev, &args);
	if (err < 0) {
		nvme_show_error("security receive: %s", nvme_strerror(errno));
	} else if (err != 0) {
		nvme_show_status(err);
	} else {
		printf("NVME Security Receive Command Success\n");
		if (!cfg.raw_binary)
			d(sec_buf, cfg.size, 16, 1);
		else if (cfg.size)
			d_raw((unsigned char *)sec_buf, cfg.size);
	}

	return err;
}

static int get_lba_status(int argc, char **argv, struct command *cmd,
		struct plugin *plugin)
{
	const char *desc = "Information about potentially unrecoverable LBAs.";
	const char *slba =
	    "Starting LBA(SLBA) in 64-bit address of the first logical block addressed by this command";
	const char *mndw =
	    "Maximum Number of Dwords(MNDW) specifies maximum number of dwords to return";
	const char *atype = "Action Type(ATYPE) specifies the mechanism\n"
		"the controller uses in determining the LBA Status Descriptors to return.";
	const char *rl =
	    "Range Length(RL) specifies the length of the range of contiguous LBAs beginning at SLBA";

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	_cleanup_free_ void *buf = NULL;
	enum nvme_print_flags flags;
	unsigned long buf_len;
	int err;

	struct config {
		__u32	namespace_id;
		__u64	slba;
		__u32	mndw;
		__u8	atype;
		__u16	rl;
		__u32	timeout;
	};

	struct config cfg = {
		.namespace_id	= 0,
		.slba		= 0,
		.mndw		= 0,
		.atype		= 0,
		.rl		= 0,
		.timeout	= 0,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id", 'n', &cfg.namespace_id,  namespace_desired),
		  OPT_SUFFIX("start-lba",  's', &cfg.slba,          slba),
		  OPT_UINT("max-dw",       'm', &cfg.mndw,          mndw),
		  OPT_BYTE("action",       'a', &cfg.atype,         atype),
		  OPT_SHRT("range-len",    'l', &cfg.rl,            rl),
		  OPT_UINT("timeout",      't', &cfg.timeout,       timeout));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(output_format_val, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (!cfg.atype) {
		nvme_show_error("action type (--action) has to be given");
		return -EINVAL;
	}

	buf_len = (cfg.mndw + 1) * 4;
	buf = nvme_alloc(buf_len);
	if (!buf)
		return -ENOMEM;

	struct nvme_get_lba_status_args args = {
		.args_size	= sizeof(args),
		.fd		= dev_fd(dev),
		.nsid		= cfg.namespace_id,
		.slba		= cfg.slba,
		.mndw		= cfg.mndw,
		.rl		= cfg.rl,
		.atype		= cfg.atype,
		.lbas		= buf,
		.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
		.result		= NULL,
	};
	err = nvme_get_lba_status(&args);
	if (!err)
		nvme_show_lba_status(buf, buf_len, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("get lba status: %s", nvme_strerror(errno));

	return err;
}

static int capacity_mgmt(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Host software uses the Capacity Management command to\n"
		"configure Endurance Groups and NVM Sets in an NVM subsystem by either\n"
		"selecting one of a set of supported configurations or by specifying the\n"
		"capacity of the Endurance Group or NVM Set to be created";
	const char *operation = "Operation to be performed by the controller";
	const char *element_id = "Value specific to the value of the Operation field.";
	const char *cap_lower =
	    "Least significant 32 bits of the capacity in bytes of the Endurance Group or NVM Set to be created";
	const char *cap_upper =
	    "Most significant 32 bits of the capacity in bytes of the Endurance Group or NVM Set to be created";

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	int err = -1;
	__u32 result;

	struct config {
		__u8	operation;
		__u16	element_id;
		__u32	dw11;
		__u32	dw12;
	};

	struct config cfg = {
		.operation	= 0xff,
		.element_id	= 0xffff,
		.dw11		= 0,
		.dw12		= 0,
	};

	NVME_ARGS(opts,
		  OPT_BYTE("operation",   'O', &cfg.operation,    operation),
		  OPT_SHRT("element-id",  'i', &cfg.element_id,   element_id),
		  OPT_UINT("cap-lower",   'l', &cfg.dw11,         cap_lower),
		  OPT_UINT("cap-upper",   'u', &cfg.dw12,         cap_upper));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	if (cfg.operation > 0xf) {
		nvme_show_error("invalid operation field: %u", cfg.operation);
		return -1;
	}

	struct nvme_capacity_mgmt_args args = {
		.args_size	= sizeof(args),
		.fd		= dev_fd(dev),
		.op		= cfg.operation,
		.element_id	= cfg.element_id,
		.cdw11		= cfg.dw11,
		.cdw12		= cfg.dw12,
		.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
		.result		= &result,
	};
	err = nvme_capacity_mgmt(&args);
	if (!err) {
		printf("Capacity Management Command is Success\n");
		if (cfg.operation == 1)
			printf("Created Element Identifier for Endurance Group is: %u\n", result);
		else if (cfg.operation == 3)
			printf("Created Element Identifier for NVM Set is: %u\n", result);
	} else if (err > 0) {
		nvme_show_status(err);
	} else if (err < 0) {
		nvme_show_error("capacity management: %s", nvme_strerror(errno));
	}

	return err;
}

static int dir_receive(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Read directive parameters of the specified directive type.";
	const char *nsr = "namespace stream requested";

	enum nvme_print_flags flags = NORMAL;
	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	_cleanup_free_ void *buf = NULL;
	__u32 result;
	__u32 dw12 = 0;
	int err;

	struct config {
		__u32	namespace_id;
		__u32	data_len;
		bool	raw_binary;
		__u8	dtype;
		__u16	dspec;
		__u8	doper;
		__u16	nsr; /* dw12 for NVME_DIR_ST_RCVOP_STATUS */
		bool	human_readable;
	};

	struct config cfg = {
		.namespace_id	= 1,
		.data_len	= 0,
		.raw_binary	= false,
		.dtype		= 0,
		.dspec		= 0,
		.doper		= 0,
		.nsr		= 0,
		.human_readable	= false,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id",   'n', &cfg.namespace_id,   namespace_id_desired),
		  OPT_UINT("data-len",       'l', &cfg.data_len,       buf_len),
		  OPT_FLAG("raw-binary",     'b', &cfg.raw_binary,     raw_directive),
		  OPT_BYTE("dir-type",       'D', &cfg.dtype,          dtype),
		  OPT_SHRT("dir-spec",       'S', &cfg.dspec,          dspec_w_dtype),
		  OPT_BYTE("dir-oper",       'O', &cfg.doper,          doper),
		  OPT_SHRT("req-resource",   'r', &cfg.nsr,            nsr),
		  OPT_FLAG("human-readable", 'H', &cfg.human_readable, human_readable_directive));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	if (cfg.human_readable)
		flags |= VERBOSE;
	if (cfg.raw_binary)
		flags = BINARY;

	switch (cfg.dtype) {
	case NVME_DIRECTIVE_DTYPE_IDENTIFY:
		switch (cfg.doper) {
		case NVME_DIRECTIVE_RECEIVE_IDENTIFY_DOPER_PARAM:
			if (!cfg.data_len)
				cfg.data_len = 4096;
			break;
		default:
			nvme_show_error("invalid directive operations for Identify Directives");
			return -EINVAL;
		}
		break;
	case NVME_DIRECTIVE_DTYPE_STREAMS:
		switch (cfg.doper) {
		case NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_PARAM:
			if (!cfg.data_len)
				cfg.data_len = 32;
			break;
		case NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_STATUS:
			if (!cfg.data_len)
				cfg.data_len = 128 * 1024;
			break;
		case NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_RESOURCE:
			dw12 = cfg.nsr;
			break;
		default:
			nvme_show_error("invalid directive operations for Streams Directives");
			return -EINVAL;
		}
		break;
	default:
		nvme_show_error("invalid directive type");
		return -EINVAL;
	}

	if (cfg.data_len) {
		buf = nvme_alloc(cfg.data_len);
		if (!buf)
			return -ENOMEM;
	}

	struct nvme_directive_recv_args args = {
		.args_size	= sizeof(args),
		.fd		= dev_fd(dev),
		.nsid		= cfg.namespace_id,
		.dspec		= cfg.dspec,
		.doper		= cfg.doper,
		.dtype		= cfg.dtype,
		.cdw12		= dw12,
		.data_len	= cfg.data_len,
		.data		= buf,
		.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
		.result		= &result,
	};
	err = nvme_directive_recv(&args);
	if (!err)
		nvme_directive_show(cfg.dtype, cfg.doper, cfg.dspec, cfg.namespace_id,
				    result, buf, cfg.data_len, flags);
	else if (err > 0)
		nvme_show_status(err);
	else if (err < 0)
		nvme_show_error("dir-receive: %s", nvme_strerror(errno));

	return err;
}

/* rpmb_cmd_option is defined in nvme-rpmb.c */
extern int rpmb_cmd_option(int, char **, struct command *, struct plugin *);
static int rpmb_cmd(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	return rpmb_cmd_option(argc, argv, cmd, plugin);
}

static int lockdown_cmd(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "The Lockdown command is used to control the\n"
		"Command and Feature Lockdown capability which configures the\n"
		"prohibition or allowance of execution of the specified command\n"
		"or Set Features command targeting a specific Feature Identifier.";
	const char *ofi_desc = "Opcode or Feature Identifier (OFI)\n"
		"specifies the command opcode or Set Features Feature Identifier\n"
		"identified by the Scope field.";
	const char *ifc_desc =
	    "[0-3] Interface (INF) field identifies the interfaces affected by this command.";
	const char *prhbt_desc = "[0-1]Prohibit(PRHBT) bit specifies whether\n"
		"to prohibit or allow the command opcode or Set Features Feature\n"
		"Identifier specified by this command.";
	const char *scp_desc =
	    "[0-15]Scope(SCP) field specifies the contents of the Opcode or Feature Identifier field.";
	const char *uuid_desc = "UUID Index - If this field is set to a non-zero\n"
		"value, then the value of this field is the index of a UUID in the UUID\n"
		"List that is used by the command.If this field is cleared to 0h,\n"
		"then no UUID index is specified";

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	int err = -1;

	struct config {
		__u8	ofi;
		__u8	ifc;
		__u8	prhbt;
		__u8	scp;
		__u8	uuid;
	};

	struct config cfg = {
		.ofi	= 0,
		.ifc	= 0,
		.prhbt	= 0,
		.scp	= 0,
		.uuid	= 0,
	};

	NVME_ARGS(opts,
		  OPT_BYTE("ofi",	'O', &cfg.ofi,      ofi_desc),
		  OPT_BYTE("ifc",	'f', &cfg.ifc,      ifc_desc),
		  OPT_BYTE("prhbt",	'p', &cfg.prhbt,    prhbt_desc),
		  OPT_BYTE("scp",	's', &cfg.scp,      scp_desc),
		  OPT_BYTE("uuid",	'U', &cfg.uuid,     uuid_desc));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	/* check for input argument limit */
	if (cfg.ifc > 3) {
		nvme_show_error("invalid interface settings:%d", cfg.ifc);
		return -1;
	}
	if (cfg.prhbt > 1) {
		nvme_show_error("invalid prohibit settings:%d", cfg.prhbt);
		return -1;
	}
	if (cfg.scp > 15) {
		nvme_show_error("invalid scope settings:%d", cfg.scp);
		return -1;
	}
	if (cfg.uuid > 127) {
		nvme_show_error("invalid UUID index settings:%d", cfg.uuid);
		return -1;
	}

	struct nvme_lockdown_args args = {
		.args_size	= sizeof(args),
		.fd		= dev_fd(dev),
		.scp		= cfg.scp,
		.prhbt		= cfg.prhbt,
		.ifc		= cfg.ifc,
		.ofi		= cfg.ofi,
		.uuidx		= cfg.uuid,
		.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
		.result		= NULL,
	};
	err = nvme_lockdown(&args);
	if (err < 0)
		nvme_show_error("lockdown: %s", nvme_strerror(errno));
	else if (err > 0)
		nvme_show_status(err);
	else
		printf("Lockdown Command is Successful\n");

	return err;
}

static void passthru_print_read_output(struct passthru_config cfg, void *data, int dfd, void *mdata,
				       int mfd, int err)
{
	if (strlen(cfg.input_file)) {
		if (write(dfd, (void *)data, cfg.data_len) < 0)
			perror("failed to write data buffer");
	} else if (data) {
		if (cfg.raw_binary)
			d_raw((unsigned char *)data, cfg.data_len);
		else if (!err)
			d((unsigned char *)data, cfg.data_len, 16, 1);
	}
	if (cfg.metadata_len && cfg.metadata) {
		if (strlen(cfg.metadata)) {
			if (write(mfd, (void *)mdata, cfg.metadata_len) < 0)
				perror("failed to write metadata buffer");
		} else {
			if (cfg.raw_binary)
				d_raw((unsigned char *)mdata, cfg.metadata_len);
			else if (!err)
				d((unsigned char *)mdata, cfg.metadata_len, 16, 1);
		}
	}
}

static int passthru(int argc, char **argv, bool admin,
		const char *desc, struct command *cmd)
{
	const char *opcode = "opcode (required)";
	const char *cflags = "command flags";
	const char *rsvd = "value for reserved field";
	const char *data_len = "data I/O length (bytes)";
	const char *metadata_len = "metadata seg. length (bytes)";
	const char *metadata = "metadata input or output file";
	const char *cdw2 = "command dword 2 value";
	const char *cdw3 = "command dword 3 value";
	const char *cdw10 = "command dword 10 value";
	const char *cdw11 = "command dword 11 value";
	const char *cdw12 = "command dword 12 value";
	const char *cdw13 = "command dword 13 value";
	const char *cdw14 = "command dword 14 value";
	const char *cdw15 = "command dword 15 value";
	const char *input = "data input or output file";
	const char *show = "print command before sending";
	const char *re = "set dataflow direction to receive";
	const char *wr = "set dataflow direction to send";
	const char *prefill = "prefill buffers with known byte-value, default 0";

	_cleanup_huge_ struct nvme_mem_huge mh = { 0, };
	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	_cleanup_file_ int dfd = -1, mfd = -1;
	int flags;
	int mode = 0644;
	void *data = NULL;
	_cleanup_free_ void *mdata = NULL;
	int err = 0;
	__u32 result;
	const char *cmd_name = NULL;
	struct timeval start_time, end_time;

	struct passthru_config cfg = {
		.opcode		= 0,
		.flags		= 0,
		.prefill	= 0,
		.rsvd		= 0,
		.namespace_id	= 0,
		.data_len	= 0,
		.metadata_len	= 0,
		.timeout	= 0,
		.cdw2		= 0,
		.cdw3		= 0,
		.cdw10		= 0,
		.cdw11		= 0,
		.cdw12		= 0,
		.cdw13		= 0,
		.cdw14		= 0,
		.cdw15		= 0,
		.input_file	= "",
		.metadata	= "",
		.raw_binary	= false,
		.show_command	= false,
		.dry_run	= false,
		.read		= false,
		.write		= false,
		.latency	= false,
	};

	NVME_ARGS(opts,
		  OPT_BYTE("opcode",       'O', &cfg.opcode,       opcode),
		  OPT_BYTE("flags",        'f', &cfg.flags,        cflags),
		  OPT_BYTE("prefill",      'p', &cfg.prefill,      prefill),
		  OPT_SHRT("rsvd",         'R', &cfg.rsvd,         rsvd),
		  OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_desired),
		  OPT_UINT("data-len",     'l', &cfg.data_len,     data_len),
		  OPT_UINT("metadata-len", 'm', &cfg.metadata_len, metadata_len),
		  OPT_UINT("timeout",      't', &cfg.timeout,      timeout),
		  OPT_UINT("cdw2",         '2', &cfg.cdw2,         cdw2),
		  OPT_UINT("cdw3",         '3', &cfg.cdw3,         cdw3),
		  OPT_UINT("cdw10",        '4', &cfg.cdw10,        cdw10),
		  OPT_UINT("cdw11",        '5', &cfg.cdw11,        cdw11),
		  OPT_UINT("cdw12",        '6', &cfg.cdw12,        cdw12),
		  OPT_UINT("cdw13",        '7', &cfg.cdw13,        cdw13),
		  OPT_UINT("cdw14",        '8', &cfg.cdw14,        cdw14),
		  OPT_UINT("cdw15",        '9', &cfg.cdw15,        cdw15),
		  OPT_FILE("input-file",   'i', &cfg.input_file,   input),
		  OPT_FILE("metadata",     'M', &cfg.metadata,     metadata),
		  OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,   raw_dump),
		  OPT_FLAG("show-command", 's', &cfg.show_command, show),
		  OPT_FLAG("dry-run",      'd', &cfg.dry_run,      dry),
		  OPT_FLAG("read",         'r', &cfg.read,         re),
		  OPT_FLAG("write",        'w', &cfg.write,        wr),
		  OPT_FLAG("latency",      'T', &cfg.latency,      latency));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	if (cfg.opcode & 0x01) {
		cfg.write = true;
		flags = O_RDONLY;
		dfd = mfd = STDIN_FILENO;
	}

	if (cfg.opcode & 0x02) {
		cfg.read = true;
		flags = O_WRONLY | O_CREAT;
		dfd = mfd = STDOUT_FILENO;
	}

	if (strlen(cfg.input_file)) {
		dfd = open(cfg.input_file, flags, mode);
		if (dfd < 0) {
			nvme_show_perror(cfg.input_file);
			return -EINVAL;
		}
	}

	if (cfg.metadata && strlen(cfg.metadata)) {
		mfd = open(cfg.metadata, flags, mode);
		if (mfd < 0) {
			nvme_show_perror(cfg.metadata);
			return -EINVAL;
		}
	}

	if (cfg.metadata_len) {
		mdata = malloc(cfg.metadata_len);
		if (!mdata)
			return -ENOMEM;

		if (cfg.write) {
			if (read(mfd, mdata, cfg.metadata_len) < 0) {
				err = -errno;
				nvme_show_perror("failed to read metadata write buffer");
				return err;
			}
		} else {
			memset(mdata, cfg.prefill, cfg.metadata_len);
		}
	}

	if (cfg.data_len) {
		data = nvme_alloc_huge(cfg.data_len, &mh);
		if (!data)
			return -ENOMEM;

		memset(data, cfg.prefill, cfg.data_len);
		if (!cfg.read && !cfg.write) {
			nvme_show_error("data direction not given");
			return -EINVAL;
		} else if (cfg.write) {
			if (read(dfd, data, cfg.data_len) < 0) {
				err = -errno;
				nvme_show_error("failed to read write buffer %s", strerror(errno));
				return err;
			}
		}
	}

	if (cfg.show_command || cfg.dry_run) {
		printf("opcode       : %02x\n", cfg.opcode);
		printf("flags        : %02x\n", cfg.flags);
		printf("rsvd1        : %04x\n", cfg.rsvd);
		printf("nsid         : %08x\n", cfg.namespace_id);
		printf("cdw2         : %08x\n", cfg.cdw2);
		printf("cdw3         : %08x\n", cfg.cdw3);
		printf("data_len     : %08x\n", cfg.data_len);
		printf("metadata_len : %08x\n", cfg.metadata_len);
		printf("addr         : %"PRIx64"\n", (uint64_t)(uintptr_t)data);
		printf("metadata     : %"PRIx64"\n", (uint64_t)(uintptr_t)mdata);
		printf("cdw10        : %08x\n", cfg.cdw10);
		printf("cdw11        : %08x\n", cfg.cdw11);
		printf("cdw12        : %08x\n", cfg.cdw12);
		printf("cdw13        : %08x\n", cfg.cdw13);
		printf("cdw14        : %08x\n", cfg.cdw14);
		printf("cdw15        : %08x\n", cfg.cdw15);
		printf("timeout_ms   : %08x\n", cfg.timeout);
	}
	if (cfg.dry_run)
		return 0;

	gettimeofday(&start_time, NULL);

	if (admin)
		err = nvme_cli_admin_passthru(dev, cfg.opcode, cfg.flags,
					      cfg.rsvd,
					      cfg.namespace_id, cfg.cdw2,
					      cfg.cdw3, cfg.cdw10,
					      cfg.cdw11, cfg.cdw12, cfg.cdw13,
					      cfg.cdw14,
					      cfg.cdw15, cfg.data_len, data,
					      cfg.metadata_len,
					      mdata, cfg.timeout, &result);
	else
		err = nvme_io_passthru(dev_fd(dev), cfg.opcode, cfg.flags,
				       cfg.rsvd,
				       cfg.namespace_id, cfg.cdw2, cfg.cdw3,
				       cfg.cdw10,
				       cfg.cdw11, cfg.cdw12, cfg.cdw13,
				       cfg.cdw14,
				       cfg.cdw15, cfg.data_len, data,
				       cfg.metadata_len,
				       mdata, cfg.timeout, &result);

	gettimeofday(&end_time, NULL);
	cmd_name = nvme_cmd_to_string(admin, cfg.opcode);
	if (cfg.latency)
		printf("%s Command %s latency: %llu us\n", admin ? "Admin" : "IO",
		       strcmp(cmd_name, "Unknown") ? cmd_name : "Vendor Specific",
		       elapsed_utime(start_time, end_time));

	if (err < 0) {
		nvme_show_error("%s: %s", __func__, nvme_strerror(errno));
	} else if (err) {
		nvme_show_status(err);
	} else  {
		fprintf(stderr, "%s Command %s is Success and result: 0x%08x\n", admin ? "Admin" : "IO",
			strcmp(cmd_name, "Unknown") ? cmd_name : "Vendor Specific", result);
		if (cfg.read)
			passthru_print_read_output(cfg, data, dfd, mdata, mfd, err);
	}

	return err;
}

static int io_passthru(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc =
	    "Send a user-defined IO command to the specified device via IOCTL passthrough, return results.";

	return passthru(argc, argv, false, desc, cmd);
}

static int admin_passthru(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc =
	    "Send a user-defined Admin command to the specified device via IOCTL passthrough, return results.";

	return passthru(argc, argv, true, desc, cmd);
}

static int gen_hostnqn_cmd(int argc, char **argv, struct command *command, struct plugin *plugin)
{
	char *hostnqn;

	hostnqn = nvmf_hostnqn_generate();
	if (!hostnqn) {
		nvme_show_error("\"%s\" not supported. Install lib uuid and rebuild.",
				command->name);
		return -ENOTSUP;
	}
	printf("%s\n", hostnqn);
	free(hostnqn);
	return 0;
}

static int show_hostnqn_cmd(int argc, char **argv, struct command *command, struct plugin *plugin)
{
	char *hostnqn;

	hostnqn = nvmf_hostnqn_from_file();
	if (!hostnqn)
		hostnqn =  nvmf_hostnqn_generate();

	if (!hostnqn) {
		nvme_show_error("hostnqn is not available -- use nvme gen-hostnqn");
		return -ENOENT;
	}

	fprintf(stdout, "%s\n", hostnqn);
	free(hostnqn);

	return 0;
}


static int gen_dhchap_key(int argc, char **argv, struct command *command, struct plugin *plugin)
{
	const char *desc =
	    "Generate a DH-HMAC-CHAP host key usable for NVMe In-Band Authentication.";
	const char *secret =
	    "Optional secret (in hexadecimal characters) to be used to initialize the host key.";
	const char *key_len = "Length of the resulting key (32, 48, or 64 bytes).";
	const char *hmac =
	    "HMAC function to use for key transformation (0 = none, 1 = SHA-256, 2 = SHA-384, 3 = SHA-512).";
	const char *nqn = "Host NQN to use for key transformation.";

	unsigned char *raw_secret;
	unsigned char key[68];
	char encoded_key[128];
	unsigned long crc = crc32(0L, NULL, 0);
	int err = 0;

	struct config {
		char		*secret;
		unsigned int	key_len;
		char		*nqn;
		unsigned int	hmac;
	};

	struct config cfg = {
		.secret		= NULL,
		.key_len	= 0,
		.nqn		= NULL,
		.hmac		= 0,
	};

	NVME_ARGS(opts,
		  OPT_STR("secret",		's', &cfg.secret,	secret),
		  OPT_UINT("key-length",	'l', &cfg.key_len,	key_len),
		  OPT_STR("nqn",		'n', &cfg.nqn,		nqn),
		  OPT_UINT("hmac",		'm', &cfg.hmac,		hmac));

	err = argconfig_parse(argc, argv, desc, opts);
	if (err)
		return err;

	if (cfg.hmac > 3) {
		nvme_show_error("Invalid HMAC identifier %u", cfg.hmac);
		return -EINVAL;
	}
	if (cfg.hmac > 0) {
		switch (cfg.hmac) {
		case 1:
			if (!cfg.key_len) {
				cfg.key_len = 32;
			} else if (cfg.key_len != 32) {
				nvme_show_error("Invalid key length %d for SHA(256)", cfg.key_len);
				return -EINVAL;
			}
			break;
		case 2:
			if (!cfg.key_len) {
				cfg.key_len = 48;
			} else if (cfg.key_len != 48) {
				nvme_show_error("Invalid key length %d for SHA(384)", cfg.key_len);
				return -EINVAL;
			}
			break;
		case 3:
			if (!cfg.key_len) {
				cfg.key_len = 64;
			} else if (cfg.key_len != 64) {
				nvme_show_error("Invalid key length %d for SHA(512)", cfg.key_len);
				return -EINVAL;
			}
			break;
		default:
			break;
		}
	} else if (!cfg.key_len) {
		cfg.key_len = 32;
	}

	if (cfg.key_len != 32 && cfg.key_len != 48 && cfg.key_len != 64) {
		nvme_show_error("Invalid key length %u", cfg.key_len);
		return -EINVAL;
	}
	raw_secret = malloc(cfg.key_len);
	if (!raw_secret)
		return -ENOMEM;
	if (!cfg.secret) {
		if (getrandom_bytes(raw_secret, cfg.key_len) < 0)
			return -errno;
	} else {
		int secret_len = 0, i;
		unsigned int c;

		for (i = 0; i < strlen(cfg.secret); i += 2) {
			if (sscanf(&cfg.secret[i], "%02x", &c) != 1) {
				nvme_show_error("Invalid secret '%s'", cfg.secret);
				return -EINVAL;
			}
			raw_secret[secret_len++] = (unsigned char)c;
		}
		if (secret_len != cfg.key_len) {
			nvme_show_error("Invalid key length (%d bytes)", secret_len);
			return -EINVAL;
		}
	}

	if (!cfg.nqn) {
		cfg.nqn = nvmf_hostnqn_from_file();
		if (!cfg.nqn) {
			nvme_show_error("Could not read host NQN");
			return -ENOENT;
		}
	}

	if (nvme_gen_dhchap_key(cfg.nqn, cfg.hmac, cfg.key_len, raw_secret, key) < 0)
		return -errno;

	crc = crc32(crc, key, cfg.key_len);
	key[cfg.key_len++] = crc & 0xff;
	key[cfg.key_len++] = (crc >> 8) & 0xff;
	key[cfg.key_len++] = (crc >> 16) & 0xff;
	key[cfg.key_len++] = (crc >> 24) & 0xff;

	memset(encoded_key, 0, sizeof(encoded_key));
	base64_encode(key, cfg.key_len, encoded_key);

	printf("DHHC-1:%02x:%s:\n", cfg.hmac, encoded_key);
	return 0;
}

static int check_dhchap_key(int argc, char **argv, struct command *command, struct plugin *plugin)
{
	const char *desc =
	    "Check a DH-HMAC-CHAP host key for usability for NVMe In-Band Authentication.";
	const char *key = "DH-HMAC-CHAP key (in hexadecimal characters) to be validated.";

	unsigned char decoded_key[128];
	unsigned int decoded_len;
	u_int32_t crc = crc32(0L, NULL, 0);
	u_int32_t key_crc;
	int err = 0, hmac;
	struct config {
		char	*key;
	};

	struct config cfg = {
		.key	= NULL,
	};

	NVME_ARGS(opts,
		  OPT_STR("key", 'k', &cfg.key, key));

	err = argconfig_parse(argc, argv, desc, opts);
	if (err)
		return err;

	if (!cfg.key) {
		nvme_show_error("Key not specified");
		return -EINVAL;
	}

	if (sscanf(cfg.key, "DHHC-1:%02x:*s", &hmac) != 1) {
		nvme_show_error("Invalid key header '%s'", cfg.key);
		return -EINVAL;
	}
	switch (hmac) {
	case 0:
		break;
	case 1:
		if (strlen(cfg.key) != 59) {
			nvme_show_error("Invalid key length for SHA(256)");
			return -EINVAL;
		}
		break;
	case 2:
		if (strlen(cfg.key) != 83) {
			nvme_show_error("Invalid key length for SHA(384)");
			return -EINVAL;
		}
		break;
	case 3:
		if (strlen(cfg.key) != 103) {
			nvme_show_error("Invalid key length for SHA(512)");
			return -EINVAL;
		}
		break;
	default:
		nvme_show_error("Invalid HMAC identifier %d", hmac);
		return -EINVAL;
	}

	err = base64_decode(cfg.key + 10, strlen(cfg.key) - 11, decoded_key);
	if (err < 0) {
		nvme_show_error("Base64 decoding failed, error %d", err);
		return err;
	}
	decoded_len = err;
	if (decoded_len < 32) {
		nvme_show_error("Base64 decoding failed (%s, size %u)", cfg.key + 10, decoded_len);
		return -EINVAL;
	}
	decoded_len -= 4;
	if (decoded_len != 32 && decoded_len != 48 && decoded_len != 64) {
		nvme_show_error("Invalid key length %d", decoded_len);
		return -EINVAL;
	}
	crc = crc32(crc, decoded_key, decoded_len);
	key_crc = ((u_int32_t)decoded_key[decoded_len]) |
		   ((u_int32_t)decoded_key[decoded_len + 1] << 8) |
		   ((u_int32_t)decoded_key[decoded_len + 2] << 16) |
		   ((u_int32_t)decoded_key[decoded_len + 3] << 24);
	if (key_crc != crc) {
		nvme_show_error("CRC mismatch (key %08x, crc %08x)", key_crc, crc);
		return -EINVAL;
	}
	printf("Key is valid (HMAC %d, length %d, CRC %08x)\n", hmac, decoded_len, crc);
	return 0;
}

static int gen_tls_key(int argc, char **argv, struct command *command, struct plugin *plugin)
{
	const char *desc = "Generate a TLS key in NVMe PSK Interchange format.";
	const char *secret =
	    "Optional secret (in hexadecimal characters) to be used for the TLS key.";
	const char *hmac = "HMAC function to use for the retained key (1 = SHA-256, 2 = SHA-384).";
	const char *identity = "TLS identity version to use (0 = NVMe TCP 1.0c, 1 = NVMe TCP 2.0";
	const char *hostnqn = "Host NQN for the retained key.";
	const char *subsysnqn = "Subsystem NQN for the retained key.";
	const char *keyring = "Keyring for the retained key.";
	const char *keytype = "Key type of the retained key.";
	const char *insert = "Insert only, do not print the retained key.";

	unsigned char *raw_secret;
	char encoded_key[128];
	int key_len = 32;
	unsigned long crc = crc32(0L, NULL, 0);
	int err;
	long tls_key;

	struct config {
		char		*keyring;
		char		*keytype;
		char		*hostnqn;
		char		*subsysnqn;
		char		*secret;
		unsigned int	hmac;
		unsigned int	identity;
		bool		insert;
	};

	struct config cfg = {
		.keyring	= ".nvme",
		.keytype	= "psk",
		.hostnqn	= NULL,
		.subsysnqn	= NULL,
		.secret		= NULL,
		.hmac		= 1,
		.identity	= 0,
		.insert		= false,
	};

	NVME_ARGS(opts,
		  OPT_STR("keyring",	'k', &cfg.keyring,	keyring),
		  OPT_STR("keytype",	't', &cfg.keytype,	keytype),
		  OPT_STR("hostnqn",	'n', &cfg.hostnqn,	hostnqn),
		  OPT_STR("subsysnqn",	'c', &cfg.subsysnqn,	subsysnqn),
		  OPT_STR("secret",	's', &cfg.secret,	secret),
		  OPT_UINT("hmac",	'm', &cfg.hmac,		hmac),
		  OPT_UINT("identity",	'I', &cfg.identity,	identity),
		  OPT_FLAG("insert",	'i', &cfg.insert,	insert));

	err = argconfig_parse(argc, argv, desc, opts);
	if (err)
		return err;
	if (cfg.hmac < 1 || cfg.hmac > 2) {
		nvme_show_error("Invalid HMAC identifier %u", cfg.hmac);
		return -EINVAL;
	}
	if (cfg.identity > 1) {
		nvme_show_error("Invalid TLS identity version %u",
				cfg.identity);
		return -EINVAL;
	}
	if (cfg.insert) {
		if (!cfg.subsysnqn) {
			nvme_show_error("No subsystem NQN specified");
			return -EINVAL;
		}
		if (!cfg.hostnqn) {
			cfg.hostnqn = nvmf_hostnqn_from_file();
			if (!cfg.hostnqn) {
				nvme_show_error("Failed to read host NQN");
				return -EINVAL;
			}
		}
	}
	if (cfg.hmac == 2)
		key_len = 48;

	raw_secret = malloc(key_len + 4);
	if (!raw_secret)
		return -ENOMEM;
	if (!cfg.secret) {
		if (getrandom_bytes(raw_secret, key_len) < 0)
			return -errno;
	} else {
		int secret_len = 0, i;
		unsigned int c;

		for (i = 0; i < strlen(cfg.secret); i += 2) {
			if (sscanf(&cfg.secret[i], "%02x", &c) != 1) {
				nvme_show_error("Invalid secret '%s'", cfg.secret);
				return -EINVAL;
			}
			if (i >= key_len * 2) {
				fprintf(stderr, "Skipping excess secret bytes\n");
				break;
			}
			raw_secret[secret_len++] = (unsigned char)c;
		}
		if (secret_len != key_len) {
			nvme_show_error("Invalid key length (%d bytes)", secret_len);
			return -EINVAL;
		}
	}

	if (cfg.insert) {
		tls_key = nvme_insert_tls_key_versioned(cfg.keyring,
					cfg.keytype, cfg.hostnqn,
					cfg.subsysnqn, cfg.identity,
					cfg.hmac, raw_secret, key_len);
		if (tls_key < 0) {
			nvme_show_error("Failed to insert key, error %d", errno);
			return -errno;
		}

		printf("Inserted TLS key %08x\n", (unsigned int)tls_key);
		return 0;
	}
	crc = crc32(crc, raw_secret, key_len);
	raw_secret[key_len++] = crc & 0xff;
	raw_secret[key_len++] = (crc >> 8) & 0xff;
	raw_secret[key_len++] = (crc >> 16) & 0xff;
	raw_secret[key_len++] = (crc >> 24) & 0xff;

	memset(encoded_key, 0, sizeof(encoded_key));
	base64_encode(raw_secret, key_len, encoded_key);

	printf("NVMeTLSkey-1:%02x:%s:\n", cfg.hmac, encoded_key);
	return 0;
}

static int check_tls_key(int argc, char **argv, struct command *command, struct plugin *plugin)
{
	const char *desc = "Check a TLS key for NVMe PSK Interchange format.\n";
	const char *keydata = "TLS key (in PSK Interchange format) to be validated.";
	const char *identity = "TLS identity version to use (0 = NVMe TCP 1.0c, 1 = NVMe TCP 2.0)";
	const char *hostnqn = "Host NQN for the retained key.";
	const char *subsysnqn = "Subsystem NQN for the retained key.";
	const char *keyring = "Keyring for the retained key.";
	const char *keytype = "Key type of the retained key.";
	const char *insert = "Insert retained key into the keyring.";

	unsigned char decoded_key[128];
	unsigned int decoded_len;
	u_int32_t crc = crc32(0L, NULL, 0);
	u_int32_t key_crc;
	int err = 0, hmac;
	long tls_key;
	struct config {
		char		*keyring;
		char		*keytype;
		char		*hostnqn;
		char		*subsysnqn;
		char		*keydata;
		unsigned int	identity;
		bool		insert;
	};

	struct config cfg = {
		.keyring	= ".nvme",
		.keytype	= "psk",
		.hostnqn	= NULL,
		.subsysnqn	= NULL,
		.keydata	= NULL,
		.identity	= 0,
		.insert		= false,
	};

	NVME_ARGS(opts,
		  OPT_STR("keyring",	'k', &cfg.keyring,	keyring),
		  OPT_STR("keytype",	't', &cfg.keytype,	keytype),
		  OPT_STR("hostnqn",	'n', &cfg.hostnqn,	hostnqn),
		  OPT_STR("subsysnqn",	'c', &cfg.subsysnqn,	subsysnqn),
		  OPT_STR("keydata",	'd', &cfg.keydata,	keydata),
		  OPT_UINT("identity",	'I', &cfg.identity,	identity),
		  OPT_FLAG("insert",	'i', &cfg.insert,	insert));

	err = argconfig_parse(argc, argv, desc, opts);
	if (err)
		return err;

	if (!cfg.keydata) {
		nvme_show_error("No key data");
		return -EINVAL;
	}
	if (cfg.identity > 1) {
		nvme_show_error("Invalid TLS identity version %u",
				cfg.identity);
		return -EINVAL;
	}

	if (sscanf(cfg.keydata, "NVMeTLSkey-1:%02x:*s", &hmac) != 1) {
		nvme_show_error("Invalid key '%s'", cfg.keydata);
		return -EINVAL;
	}
	switch (hmac) {
	case 1:
		if (strlen(cfg.keydata) != 65) {
			nvme_show_error("Invalid key length %zu for SHA(256)", strlen(cfg.keydata));
			return -EINVAL;
		}
		break;
	case 2:
		if (strlen(cfg.keydata) != 89) {
			nvme_show_error("Invalid key length %zu for SHA(384)", strlen(cfg.keydata));
			return -EINVAL;
		}
		break;
	default:
		nvme_show_error("Invalid HMAC identifier %d", hmac);
		return -EINVAL;
	}

	if (cfg.subsysnqn) {
		if (cfg.insert && !cfg.hostnqn) {
			cfg.hostnqn = nvmf_hostnqn_from_file();
			if (!cfg.hostnqn) {
				nvme_show_error("Failed to read host NQN");
				return -EINVAL;
			}
		}
	} else if (cfg.insert || cfg.identity == 1) {
		nvme_show_error("Need to specify a subsystem NQN");
		return -EINVAL;
	}
	err = base64_decode(cfg.keydata + 16, strlen(cfg.keydata) - 17, decoded_key);
	if (err < 0) {
		nvme_show_error("Base64 decoding failed (%s, error %d)", cfg.keydata + 16, err);
		return err;
	}
	decoded_len = err;
	decoded_len -= 4;
	if (decoded_len != 32 && decoded_len != 48) {
		nvme_show_error("Invalid key length %d", decoded_len);
		return -EINVAL;
	}
	crc = crc32(crc, decoded_key, decoded_len);
	key_crc = ((u_int32_t)decoded_key[decoded_len]) |
		((u_int32_t)decoded_key[decoded_len + 1] << 8) |
		((u_int32_t)decoded_key[decoded_len + 2] << 16) |
		((u_int32_t)decoded_key[decoded_len + 3] << 24);
	if (key_crc != crc) {
		nvme_show_error("CRC mismatch (key %08x, crc %08x)", key_crc, crc);
		return -EINVAL;
	}
	if (cfg.insert) {
		tls_key = nvme_insert_tls_key_versioned(cfg.keyring,
					cfg.keytype, cfg.hostnqn,
					cfg.subsysnqn, cfg.identity,
					hmac, decoded_key, decoded_len);
		if (tls_key < 0) {
			nvme_show_error("Failed to insert key, error %d", errno);
			return -errno;
		}
		printf("Inserted TLS key %08x\n", (unsigned int)tls_key);
	} else {
		char *tls_id;

		tls_id = nvme_generate_tls_key_identity(cfg.hostnqn,
					cfg.subsysnqn, cfg.identity,
					hmac, decoded_key, decoded_len);
		if (!tls_id) {
			nvme_show_error("Failed to generate identity, error %d",
					errno);
			return -errno;
		}
		printf("%s\n", tls_id);
		free(tls_id);
	}
	return 0;
}

static int show_topology_cmd(int argc, char **argv, struct command *command, struct plugin *plugin)
{
	const char *desc = "Show the topology\n";
	const char *ranking = "Ranking order: namespace|ctrl";
	enum nvme_print_flags flags;
	nvme_root_t r;
	enum nvme_cli_topo_ranking rank;
	int err;

	struct config {
		char	*ranking;
	};

	struct config cfg = {
		.ranking	= "namespace",
	};

	NVME_ARGS(opts,
		  OPT_FMT("ranking",       'r', &cfg.ranking,       ranking));

	err = argconfig_parse(argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(output_format_val, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (argconfig_parse_seen(opts, "verbose"))
		flags |= VERBOSE;

	if (!strcmp(cfg.ranking, "namespace")) {
		rank = NVME_CLI_TOPO_NAMESPACE;
	} else if (!strcmp(cfg.ranking, "ctrl")) {
		rank = NVME_CLI_TOPO_CTRL;
	} else {
		nvme_show_error("Invalid ranking argument: %s", cfg.ranking);
		return -EINVAL;
	}

	r = nvme_create_root(stderr, map_log_level(!!(flags & VERBOSE), false));
	if (!r) {
		nvme_show_error("Failed to create topology root: %s", nvme_strerror(errno));
		return -errno;
	}

	err = nvme_scan_topology(r, NULL, NULL);
	if (err < 0) {
		nvme_show_error("Failed to scan topology: %s", nvme_strerror(errno));
		nvme_free_tree(r);
		return err;
	}

	nvme_show_topology(r, rank, flags);
	nvme_free_tree(r);

	return err;
}

static int discover_cmd(int argc, char **argv, struct command *command, struct plugin *plugin)
{
	const char *desc = "Send Get Log Page request to Discovery Controller.";

	return nvmf_discover(desc, argc, argv, false);
}

static int connect_all_cmd(int argc, char **argv, struct command *command, struct plugin *plugin)
{
	const char *desc = "Discover NVMeoF subsystems and connect to them";

	return nvmf_discover(desc, argc, argv, true);
}

static int connect_cmd(int argc, char **argv, struct command *command, struct plugin *plugin)
{
	const char *desc = "Connect to NVMeoF subsystem";

	return nvmf_connect(desc, argc, argv);
}

static int disconnect_cmd(int argc, char **argv, struct command *command, struct plugin *plugin)
{
	const char *desc = "Disconnect from NVMeoF subsystem";

	return nvmf_disconnect(desc, argc, argv);
}

int disconnect_all_cmd(int argc, char **argv, struct command *command,
	struct plugin *plugin)
{
	const char *desc = "Disconnect from all connected NVMeoF subsystems";

	return nvmf_disconnect_all(desc, argc, argv);
}

static int config_cmd(int argc, char **argv, struct command *command, struct plugin *plugin)
{
	const char *desc = "Configuration of NVMeoF subsystems";

	return nvmf_config(desc, argc, argv);
}

static int dim_cmd(int argc, char **argv, struct command *command, struct plugin *plugin)
{
	const char *desc =
	    "Send Discovery Information Management command to a Discovery Controller (DC)";

	return nvmf_dim(desc, argc, argv);
}

static int nvme_mi(int argc, char **argv, __u8 admin_opcode, const char *desc)
{
	const char *opcode = "opcode (required)";
	const char *data_len = "data I/O length (bytes)";
	const char *nmimt = "nvme-mi message type";
	const char *nmd0 = "nvme management dword 0 value";
	const char *nmd1 = "nvme management dword 1 value";
	const char *input = "data input or output file";

	int mode = 0644;
	void *data = NULL;
	int err = 0;
	bool send;
	_cleanup_file_ int fd = -1;
	int flags;
	_cleanup_huge_ struct nvme_mem_huge mh = { 0, };
	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	__u32 result;

	struct config {
		__u8 opcode;
		__u32 namespace_id;
		__u32 data_len;
		__u32 nmimt;
		__u32 nmd0;
		__u32 nmd1;
		char *input_file;
	};

	struct config cfg = {
		.opcode = 0,
		.namespace_id = 0,
		.data_len = 0,
		.nmimt = 0,
		.nmd0 = 0,
		.nmd1 = 0,
		.input_file = "",
	};

	NVME_ARGS(opts,
		  OPT_BYTE("opcode", 'O', &cfg.opcode, opcode),
		  OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_desired),
		  OPT_UINT("data-len", 'l', &cfg.data_len, data_len),
		  OPT_UINT("nmimt", 'm', &cfg.nmimt, nmimt),
		  OPT_UINT("nmd0", '0', &cfg.nmd0, nmd0),
		  OPT_UINT("nmd1", '1', &cfg.nmd1, nmd1),
		  OPT_FILE("input-file", 'i', &cfg.input_file, input));

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	if (admin_opcode == nvme_admin_nvme_mi_send) {
		flags = O_RDONLY;
		fd = STDIN_FILENO;
		send = true;
	} else {
		flags = O_WRONLY | O_CREAT;
		fd = STDOUT_FILENO;
		send = false;
	}

	if (strlen(cfg.input_file)) {
		fd = open(cfg.input_file, flags, mode);
		if (fd < 0) {
			nvme_show_perror(cfg.input_file);
			return -EINVAL;
		}
	}

	if (cfg.data_len) {
		data = nvme_alloc_huge(cfg.data_len, &mh);
		if (!data)
			return -ENOMEM;

		if (send) {
			if (read(fd, data, cfg.data_len) < 0) {
				err = -errno;
				nvme_show_error("failed to read write buffer %s", strerror(errno));
				return err;
			}
		}
	}

	err = nvme_cli_admin_passthru(dev, admin_opcode, 0, 0, cfg.namespace_id, 0, 0,
				      cfg.nmimt << 11 | 4, cfg.opcode, cfg.nmd0, cfg.nmd1, 0, 0,
				      cfg.data_len, data, 0, NULL, 0, &result);
	if (err < 0) {
		nvme_show_error("nmi_recv: %s", nvme_strerror(errno));
	} else if (err) {
		nvme_show_status(err);
	} else  {
		printf(
		    "%s Command is Success and result: 0x%08x (status: 0x%02x, response: 0x%06x)\n",
		    nvme_cmd_to_string(true, admin_opcode), result, result & 0xff, result >> 8);
		if (result & 0xff)
			printf("status: %s\n", nvme_mi_status_to_string(result & 0xff));
		if (!send && strlen(cfg.input_file)) {
			if (write(fd, (void *)data, cfg.data_len) < 0)
				perror("failed to write data buffer");
		} else if (data && !send && !err) {
			d((unsigned char *)data, cfg.data_len, 16, 1);
		}
	}

	return err;
}

static int nmi_recv(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc =
	    "Send a NVMe-MI Receive command to the specified device, return results.";

	return nvme_mi(argc, argv, nvme_admin_nvme_mi_recv, desc);
}

static int nmi_send(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Send a NVMe-MI Send command to the specified device, return results.";

	return nvme_mi(argc, argv, nvme_admin_nvme_mi_send, desc);
}

void register_extension(struct plugin *plugin)
{
	plugin->parent = &nvme;
	nvme.extensions->tail->next = plugin;
	nvme.extensions->tail = plugin;
}

int main(int argc, char **argv)
{
	int err;

	nvme.extensions->parent = &nvme;
	if (argc < 2) {
		general_help(&builtin);
		return 0;
	}
	setlocale(LC_ALL, "");

	err = handle_plugin(argc - 1, &argv[1], nvme.extensions);
	if (err == -ENOTTY)
		general_help(&builtin);

	return err ? 1 : 0;
}
