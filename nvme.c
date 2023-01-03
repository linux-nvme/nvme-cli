// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * nvme.c -- NVM-Express command line utility.
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
#include <zlib.h>

#ifdef CONFIG_LIBHUGETLBFS
#include <hugetlbfs.h>
#endif

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
#include "nvme-wrap.h"

#include "util/argconfig.h"
#include "fabrics.h"

#define CREATE_CMD
#include "nvme-builtin.h"

struct feat_cfg {
	enum nvme_features_id feature_id;
	__u32 namespace_id;
	enum nvme_get_features_sel sel;
	__u32 cdw11;
	__u8  uuid_index;
	__u32 data_len;
	bool  raw_binary;
	bool  human_readable;
};

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
	.desc = "The '<device>' may be either an NVMe character "\
		"device (ex: /dev/nvme0), an nvme block device "\
		"(ex: /dev/nvme0n1), or a mctp address in the form "\
		"mctp:<net>,<eid>[:ctrl-id]",
	.extensions = &builtin,
};

const char *output_format = "Output format: normal|json|binary";
static const char *output_format_no_binary = "Output format: normal|json";

static const char *app_tag = "app tag for end-to-end PI";
static const char *app_tag_mask = "app tag mask for end-to-end PI";
static const char *block_count = "number of blocks (zeroes based) on device to access";
static const char *crkey = "current reservation key";
static const char *buf_len = "buffer len (if) data is returned";
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
static const char *lba_format_index = "The index into the LBA Format list "\
	"identifying the LBA Format capabilities that are to be returned";
static const char *limited_retry = "limit media access attempts";
static const char *lsp = "log specific field";
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

static void *mmap_registers(nvme_root_t r, struct nvme_dev *dev);

static void *__nvme_alloc(size_t len, bool *huge) {
	void *p;

	if (!posix_memalign(&p, getpagesize(), len)) {
		*huge = false;
		memset(p, 0, len);
		return p;
	}
	return NULL;
}

#define HUGE_MIN 0x80000

#ifdef CONFIG_LIBHUGETLBFS
void nvme_free(void *p, bool huge)
{
	if (huge) {
		if (p)
			free_hugepage_region(p);
	}
	else
		free(p);
}

void *nvme_alloc(size_t len, bool *huge)
{
	void *p;

	if (len < HUGE_MIN)
		return __nvme_alloc(len, huge);

	p = get_hugepage_region(len, GHR_DEFAULT);
	if (!p)
		return __nvme_alloc(len, huge);

	*huge = true;
	return p;
}
#else
void nvme_free(void *p, bool huge)
{
	free(p);
}

void *nvme_alloc(size_t len, bool *huge)
{
	return __nvme_alloc(len, huge);
}
#endif

const char *nvme_strerror(int errnum)
{
	if (errnum >= ENVME_CONNECT_RESOLVE)
		return nvme_errno_to_string(errnum);
	return strerror(errnum);
}

int map_log_level(int verbose, bool quiet)
{
	int log_level;

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
		perror(devstr);
		goto err_free;
	}
	dev->direct.fd = err;

	err = fstat(dev_fd(dev), &dev->direct.stat);
	if (err < 0) {
		perror(devstr);
		goto err_close;
	}
	if (!is_chardev(dev) && !is_blkdev(dev)) {
		fprintf(stderr, "%s is not a block or character device\n",
			devstr);
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
		fprintf(stderr, "invalid device specifier '%s'\n", devstr);
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
		perror(argv[0]);
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

	return ret;
}

int parse_and_open(struct nvme_dev **dev, int argc, char **argv,
		   const char *desc,
		   const struct argconfig_commandline_options *opts)
{
	int ret;

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret)
		return ret;

	ret = get_dev(dev, argc, argv, O_RDONLY);
	if (ret < 0)
		argconfig_print_help(desc, opts);

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

enum nvme_print_flags validate_output_format(const char *format)
{
	if (!format)
		return -EINVAL;
	if (!strcmp(format, "normal"))
		return NORMAL;
	if (!strcmp(format, "json"))
		return JSON;
	if (!strcmp(format, "binary"))
		return BINARY;
	return -EINVAL;
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
	struct nvme_smart_log smart_log;
	const char *desc = "Retrieve SMART log for the given device "\
			"(or optionally a namespace) in either decoded format "\
			"(default) or binary.";
	const char *namespace = "(optional) desired namespace";
	enum nvme_print_flags flags;
	struct nvme_dev *dev;
	int err = -1;

	struct config {
		__u32	namespace_id;
		char	*output_format;
		bool	raw_binary;
		bool	human_readable;
	};

	struct config cfg = {
		.namespace_id	= NVME_NSID_ALL,
		.output_format	= "normal",
		.raw_binary	= false,
		.human_readable	= false,
	};


	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id",   'n', &cfg.namespace_id,   namespace),
		OPT_FMT("output-format",   'o', &cfg.output_format,  output_format),
		OPT_FLAG("raw-binary",     'b', &cfg.raw_binary,     raw_output),
		OPT_FLAG("human-readable", 'H', &cfg.human_readable, human_readable_info),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;
	if (cfg.raw_binary)
		flags = BINARY;
	if (cfg.human_readable)
		flags |= VERBOSE;

	err = nvme_cli_get_log_smart(dev, cfg.namespace_id, false,
				 &smart_log);
	if (!err)
		nvme_show_smart_log(&smart_log, cfg.namespace_id,
				    dev->name, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		fprintf(stderr, "smart log: %s\n", nvme_strerror(errno));
close_fd:
	dev_close(dev);
ret:
	return err;
}

static int get_ana_log(int argc, char **argv, struct command *cmd,
		struct plugin *plugin)
{
	const char *desc = "Retrieve ANA log for the given device in " \
			    "decoded format (default), json or binary.";
	const char *groups = "Return ANA groups only.";
	void *ana_log;
	size_t ana_log_len;
	struct nvme_id_ctrl ctrl;
	enum nvme_print_flags flags;
	enum nvme_log_ana_lsp lsp;
	struct nvme_dev *dev;
	int err = -1;

	struct config {
		bool	groups;
		char	*output_format;
	};

	struct config cfg = {
		.groups = false,
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FLAG("groups", 'g', &cfg.groups, groups),
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;

	err = nvme_cli_identify_ctrl(dev, &ctrl);
	if (err) {
		fprintf(stderr, "ERROR : nvme_identify_ctrl() failed: %s\n",
			nvme_strerror(errno));
		goto close_fd;
	}

	ana_log_len = sizeof(struct nvme_ana_log) +
		le32_to_cpu(ctrl.nanagrpid) * sizeof(struct nvme_ana_group_desc);
	if (!(ctrl.anacap & (1 << 6)))
		ana_log_len += le32_to_cpu(ctrl.mnan) * sizeof(__le32);

	ana_log = malloc(ana_log_len);
	if (!ana_log) {
		err = -ENOMEM;
		goto close_fd;
	}

	lsp = cfg.groups ? NVME_LOG_ANA_LSP_RGO_GROUPS_ONLY :
		NVME_LOG_ANA_LSP_RGO_NAMESPACES;

	err = nvme_cli_get_log_ana(dev, lsp, true, 0, ana_log_len, ana_log);
	if (!err) {
		nvme_show_ana_log(ana_log, dev->name, flags, ana_log_len);
	} else if (err > 0)
		nvme_show_status(err);
	else
		fprintf(stderr, "ana-log: %s", nvme_strerror(errno));
	free(ana_log);
close_fd:
	dev_close(dev);
ret:
	return err;
}

static int get_telemetry_log_helper(struct nvme_dev *dev, bool create,
				    bool ctrl, struct nvme_telemetry_log **buf,
				    enum nvme_telemetry_da da,
				    size_t *size)
{
	static const __u32 xfer = NVME_LOG_TELEM_BLOCK_SIZE;
	struct nvme_telemetry_log *telem;
	struct nvme_id_ctrl id_ctrl;
	void *log, *tmp;
	int err;
	*size = 0;

	log = calloc(1, xfer);
	if (!log)
		return -ENOMEM;

	if (ctrl) {
		/* set rae = true so it won't clear the current telemetry log in controller */
		err = nvme_cli_get_log_telemetry_ctrl(dev, true, 0, xfer, log);
	} else {
		if (create)
			err = nvme_cli_get_log_create_telemetry_host(dev, log);
		else
			err = nvme_cli_get_log_telemetry_host(dev, 0, xfer, log);
	}

	if (err)
		goto free;

	telem = log;
	if (ctrl && !telem->ctrlavail) {
		*buf = log;
		*size = xfer;
		printf("Warning: Telemetry Controller-Initiated Data Not Available.\n");
		return 0;
	}

	switch (da) {
	case NVME_TELEMETRY_DA_1:
	case NVME_TELEMETRY_DA_2:
	case NVME_TELEMETRY_DA_3:
		/* dalb3 >= dalb2 >= dalb1 */
		*size = (le16_to_cpu(telem->dalb3) + 1) * xfer;
		break;
	case NVME_TELEMETRY_DA_4:
		err = nvme_cli_identify_ctrl(dev, &id_ctrl);
		if (err) {
			perror("identify-ctrl");
			goto free;
		}

		if (id_ctrl.lpa & 0x40) {
			*size = (le32_to_cpu(telem->dalb4) + 1) * xfer;
		} else {
			fprintf(stderr, "Data area 4 unsupported, bit 6 of Log Page Attributes not set\n");
			err = -EINVAL;
			goto free;
		}
		break;
	default:
		fprintf(stderr, "Invalid data area parameter - %d\n", da);
		err = -EINVAL;
		goto free;
	}

	if (xfer == *size) {
		fprintf(stderr, "ERRO: No telemetry data block\n");
		err = -ENOENT;
		goto free;
	}

	tmp = realloc(log, *size);
	if (!tmp) {
		err = -ENOMEM;
		goto free;
	}
	log = tmp;

	if (ctrl) {
		err = nvme_cli_get_log_telemetry_ctrl(dev, true, 0, *size, log);
	} else {
		err = nvme_cli_get_log_telemetry_host(dev, 0, *size, log);
	}

	if (!err) {
		*buf = log;
		return 0;
	}
free:
	free(log);
	return err;
}


static int get_telemetry_log(int argc, char **argv, struct command *cmd,
			     struct plugin *plugin)
{
	const char *desc = "Retrieve telemetry log and write to binary file";
	const char *fname = "File name to save raw binary, includes header";
	const char *hgen = "Have the host tell the controller to generate the report";
	const char *cgen = "Gather report generated by the controller.";
	const char *dgen = "Pick which telemetry data area to report. Default is 3 to fetch areas 1-3. Valid options are 1, 2, 3, 4.";
	struct nvme_telemetry_log *log;
	int err = 0, output;
	size_t total_size;
	__u8 *data_ptr = NULL;
	int data_written = 0, data_remaining = 0;
	struct nvme_dev *dev;

	struct config {
		char	*file_name;
		__u32	host_gen;
		bool	ctrl_init;
		int	data_area;
	};
	struct config cfg = {
		.file_name	= NULL,
		.host_gen	= 1,
		.ctrl_init	= false,
		.data_area	= 3,
	};

	OPT_ARGS(opts) = {
		OPT_FILE("output-file",     'o', &cfg.file_name, fname),
		OPT_UINT("host-generate",   'g', &cfg.host_gen,  hgen),
		OPT_FLAG("controller-init", 'c', &cfg.ctrl_init, cgen),
		OPT_UINT("data-area",       'd', &cfg.data_area, dgen),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	if (!cfg.file_name) {
		fprintf(stderr, "Please provide an output file!\n");
		err = -EINVAL;
		goto close_dev;
	}

	cfg.host_gen = !!cfg.host_gen;
	output = open(cfg.file_name, O_WRONLY | O_CREAT | O_TRUNC, 0666);
	if (output < 0) {
		fprintf(stderr, "Failed to open output file %s: %s!\n",
				cfg.file_name, strerror(errno));
		err = output;
		goto close_dev;
	}

	if (cfg.ctrl_init)
		/* Create Telemetry Host-Initiated Data = false, Controller-Initiated = true */
		err = get_telemetry_log_helper(dev, false, true, &log,
					       cfg.data_area, &total_size);
	else if (cfg.host_gen)
		/* Create Telemetry Host-Initiated Data = true, Controller-Initiated = false */
		err = get_telemetry_log_helper(dev, true, false, &log,
					       cfg.data_area, &total_size);
	else
		/* Create Telemetry Host-Initiated Data = false, Controller-Initiated = false */
		err = get_telemetry_log_helper(dev, false, false, &log,
					       cfg.data_area, &total_size);

	if (err < 0) {
		fprintf(stderr, "get-telemetry-log: %s\n",
			nvme_strerror(errno));
		goto close_output;
	} else if (err > 0) {
		nvme_show_status(err);
		fprintf(stderr, "Failed to acquire telemetry log %d!\n", err);
		goto close_output;
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
		fprintf(stderr, "ERROR : %s: : fsync : %s\n", __func__, strerror(errno));
		return -1;
	}

	free(log);

close_output:
	close(output);
close_dev:
	dev_close(dev);
ret:
	return err;
}

static int get_endurance_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	struct nvme_endurance_group_log endurance_log;
	const char *desc = "Retrieves endurance groups log page and prints the log.";
	const char *group_id = "The endurance group identifier";
	enum nvme_print_flags flags;
	struct nvme_dev *dev;
	int err;

	struct config {
		char	*output_format;
		__u16	group_id;
	};

	struct config cfg = {
		.output_format	= "normal",
		.group_id	= 0,
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_SHRT("group-id",     'g', &cfg.group_id,      group_id),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_dev;

	err = nvme_cli_get_log_endurance_group(dev, cfg.group_id,
					       &endurance_log);
	if (!err)
		nvme_show_endurance_log(&endurance_log, cfg.group_id,
					dev->name, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		fprintf(stderr, "endurance log: %s\n", nvme_strerror(errno));
close_dev:
	dev_close(dev);
ret:
	return err;
}

static int collect_effects_log(struct nvme_dev *dev, enum nvme_csi csi,
			       struct list_head *list, int flags)
{
	nvme_effects_log_node_t *node;
	int err;

	node = malloc(sizeof(nvme_effects_log_node_t));
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
	const char *csi = "";
	struct list_head log_pages;
	nvme_effects_log_node_t *node;
	struct nvme_dev *dev;

	void *bar = NULL;

	int err = -1;
	enum nvme_print_flags flags;

	struct config {
		char	*output_format;
		bool	human_readable;
		bool	raw_binary;
		int	csi;
	};

	struct config cfg = {
		.output_format	= "normal",
		.human_readable	= false,
		.raw_binary	= false,
		.csi		= -1,
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format",  'o', &cfg.output_format,  output_format),
		OPT_FLAG("human-readable",'H', &cfg.human_readable, human_readable_log),
		OPT_FLAG("raw-binary",    'b', &cfg.raw_binary,     raw_log),
		OPT_INT("csi",            'c', &cfg.csi,            csi),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_dev;
	if (cfg.raw_binary)
		flags = BINARY;
	if (cfg.human_readable)
		flags |= VERBOSE;

	list_head_init(&log_pages);

	if (cfg.csi < 0) {
		nvme_root_t nvme_root;
		uint64_t cap;
		int nvme_command_set_supported;
		int other_command_sets_supported;
		nvme_root = nvme_scan(NULL);
		bar = mmap_registers(nvme_root, dev);
		nvme_free_tree(nvme_root);

		if (!bar) {
			goto close_dev;
		}
		cap = mmio_read64(bar + NVME_REG_CAP);
		munmap(bar, getpagesize());

		nvme_command_set_supported = NVME_CAP_CSS(cap) & NVME_CAP_CSS_NVM;
		other_command_sets_supported = NVME_CAP_CSS(cap) & NVME_CAP_CSS_CSI;

		if (nvme_command_set_supported)
			err = collect_effects_log(dev, NVME_CSI_NVM,
						  &log_pages, flags);

		if (!err && other_command_sets_supported)
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
		perror("effects log page");

close_dev:
	while ((node = list_pop(&log_pages, nvme_effects_log_node_t, node))) {
		free(node);
	}

	dev_close(dev);
ret:
	return err;
}

static int get_supported_log_pages(int argc, char **argv, struct command *cmd,
	struct plugin *plugin)
{
	const char *desc = "Retrieve supported logs and print the table.";
	struct nvme_supported_log_pages supports;
	enum nvme_print_flags flags;
	struct nvme_dev *dev;
	int err = -1;

	struct config {
		char	*output_format;
		bool	verbose;
	};

	struct config cfg = {
		.output_format	= "normal",
		.verbose	= false
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format",  'o', &cfg.output_format,  output_format),
		OPT_FLAG("verbose",       'v', &cfg.verbose,        verbose),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_dev;

	if (cfg.verbose)
		flags |= VERBOSE;

	err = nvme_cli_get_log_supported_log_pages(dev, false, &supports);
	if (!err)
		nvme_show_supported_log(&supports, dev->name, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		fprintf(stderr, "supported log pages: %s",
			nvme_strerror(errno));

close_dev:
	dev_close(dev);
ret:
	return err;
}

static int get_error_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Retrieve specified number of "\
		"error log entries from a given device "\
		"in either decoded format (default) or binary.";
	const char *log_entries = "number of entries to retrieve";
	const char *raw = "dump in binary format";
	struct nvme_error_log_page *err_log;
	struct nvme_id_ctrl ctrl;
	enum nvme_print_flags flags;
	struct nvme_dev *dev;
	int err = -1;

	struct config {
		__u32	log_entries;
		char	*output_format;
		bool	raw_binary;
	};

	struct config cfg = {
		.log_entries	= 64,
		.output_format	= "normal",
		.raw_binary	= false,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("log-entries",  'e', &cfg.log_entries,   log_entries),
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,    raw),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_dev;
	if (cfg.raw_binary)
		flags = BINARY;

	if (!cfg.log_entries) {
		fprintf(stderr, "non-zero log-entries is required param\n");
		err = -1;
		goto close_dev;
	}

	err = nvme_cli_identify_ctrl(dev, &ctrl);
	if (err < 0) {
		perror("identify controller");
		goto close_dev;
	} else if (err) {
		fprintf(stderr, "could not identify controller\n");
		err = -1;
		goto close_dev;
	}

	cfg.log_entries = min(cfg.log_entries, ctrl.elpe + 1);
	err_log = calloc(cfg.log_entries, sizeof(struct nvme_error_log_page));
	if (!err_log) {
		err = -1;
		goto close_dev;
	}

	err = nvme_cli_get_log_error(dev, cfg.log_entries, false, err_log);
	if (!err)
		nvme_show_error_log(err_log, cfg.log_entries,
				    dev->name, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		perror("error log");
	free(err_log);
close_dev:
	dev_close(dev);
ret:
	return err;
}

static int get_fw_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Retrieve the firmware log for the "\
		"specified device in either decoded format (default) or binary.";
	struct nvme_firmware_slot fw_log;
	enum nvme_print_flags flags;
	struct nvme_dev *dev;
	int err;

	struct config {
		char	*output_format;
		bool	raw_binary;
	};

	struct config cfg = {
		.output_format	= "normal",
		.raw_binary	= false,
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,    raw_use),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_dev;
	if (cfg.raw_binary)
		flags = BINARY;

	err = nvme_cli_get_log_fw_slot(dev, false, &fw_log);
	if (!err)
		nvme_show_fw_log(&fw_log, dev->name, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		fprintf(stderr, "fw log: %s\n", nvme_strerror(errno));
close_dev:
	dev_close(dev);
ret:
	return err;
}

static int get_changed_ns_list_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Retrieve Changed Namespaces log for the given device "\
			"in either decoded format "\
			"(default) or binary.";
	struct nvme_ns_list changed_ns_list_log;
	enum nvme_print_flags flags;
	struct nvme_dev *dev;
	int err;

	struct config {
		char	*output_format;
		bool	raw_binary;
	};

	struct config cfg = {
		.output_format	= "normal",
		.raw_binary	= false,
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,    raw_output),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_dev;
	if (cfg.raw_binary)
		flags = BINARY;

	err = nvme_cli_get_log_changed_ns_list(dev, true,
					       &changed_ns_list_log);
	if (!err)
		nvme_show_changed_ns_list_log(&changed_ns_list_log,
					      dev->name, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		fprintf(stderr, "changed ns list log: %s\n",
			nvme_strerror(errno));
close_dev:
	dev_close(dev);
ret:
	return err;
}

static int get_pred_lat_per_nvmset_log(int argc, char **argv,
	struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Retrieve Predictable latency per nvm set log "\
			"page and prints it for the given device in either decoded " \
			"format(default),json or binary.";
	const char *nvmset_id = "NVM Set Identifier";
	struct nvme_nvmset_predictable_lat_log plpns_log;
	enum nvme_print_flags flags;
	struct nvme_dev *dev;
	int err;

	struct config {
		__u16	nvmset_id;
		char	*output_format;
		bool	raw_binary;
	};

	struct config cfg = {
		.nvmset_id	= 1,
		.output_format	= "normal",
		.raw_binary	= false,
	};

	OPT_ARGS(opts) = {
		OPT_SHRT("nvmset-id",	 'i', &cfg.nvmset_id,     nvmset_id),
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,	  raw_use),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_dev;
	if (cfg.raw_binary)
		flags = BINARY;

	err = nvme_cli_get_log_predictable_lat_nvmset(dev, cfg.nvmset_id,
						      &plpns_log);
	if (!err)
		nvme_show_predictable_latency_per_nvmset(&plpns_log,
			cfg.nvmset_id, dev->name, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		fprintf(stderr, "predictable latency per nvm set: %s\n",
			nvme_strerror(errno));

close_dev:
	dev_close(dev);
ret:
	return err;
}

static int get_pred_lat_event_agg_log(int argc, char **argv,
		struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Retrieve Predictable Latency Event" \
			"Aggregate Log page and prints it, for the given" \
			"device in either decoded format(default)," \
			"json or binary.";
	const char *log_entries = "Number of pending NVM Set" \
			"log Entries list";
	enum nvme_print_flags flags;
	struct nvme_id_ctrl ctrl;
	struct nvme_dev *dev;
	__u32 log_size;
	void *pea_log;
	int err;

	struct config {
		__u64	log_entries;
		bool	rae;
		char	*output_format;
		bool	raw_binary;
	};

	struct config cfg = {
		.log_entries	= 2044,
		.rae		= false,
		.output_format	= "normal",
		.raw_binary	= false,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("log-entries",  'e', &cfg.log_entries,   log_entries),
		OPT_FLAG("rae",          'r', &cfg.rae,           rae),
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,    raw_use),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_dev;
	if (cfg.raw_binary)
		flags = BINARY;

	if (!cfg.log_entries) {
		fprintf(stderr, "non-zero log-entries is required param\n");
		err = -EINVAL;
		goto close_dev;
	}

	err = nvme_cli_identify_ctrl(dev, &ctrl);
	if (err < 0) {
		fprintf(stderr, "identify controller: %s\n",
			nvme_strerror(errno));
		goto close_dev;
	} else if (err) {
		nvme_show_status(err);
		goto close_dev;
	}

	cfg.log_entries = min(cfg.log_entries, le32_to_cpu(ctrl.nsetidmax));
	log_size = sizeof(__u64) + cfg.log_entries * sizeof(__u16);
	pea_log = calloc(log_size, 1);
	if (!pea_log) {
		err = -ENOMEM;
		goto close_dev;
	}

	err = nvme_cli_get_log_predictable_lat_event(dev, cfg.rae, 0,
						     log_size, pea_log);
	if (!err)
		nvme_show_predictable_latency_event_agg_log(pea_log, cfg.log_entries,
			log_size, dev->name, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		fprintf(stderr, "predictable latency event aggregate log page: %s",
			nvme_strerror(errno));
	free(pea_log);

close_dev:
	dev_close(dev);
ret:
	return err;
}

static int get_persistent_event_log(int argc, char **argv,
		struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Retrieve Persistent Event log info for"\
			" the given device in either decoded format(default),"\
			" json or binary.";
	const char *action = "action the controller shall take during"\
			" processing this persistent log page command.";
	const char *log_len = "number of bytes to retrieve";
	struct nvme_persistent_event_log *pevent, *pevent_collected;
	enum nvme_print_flags flags;
	void *pevent_log_info;
	struct nvme_dev *dev;
	bool huge;
	int err;

	struct config {
		__u8	action;
		__u32	log_len;
		char	*output_format;
		bool	raw_binary;
	};

	struct config cfg = {
		.action		= 0xff,
		.log_len	= 0,
		.output_format	= "normal",
		.raw_binary	= false,
	};

	OPT_ARGS(opts) = {
		OPT_BYTE("action",       'a', &cfg.action,        action),
		OPT_UINT("log_len",	 'l', &cfg.log_len,	  log_len),
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,    raw_use),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_dev;
	if (cfg.raw_binary)
		flags = BINARY;

	pevent = calloc(sizeof(*pevent), 1);
	if (!pevent) {
		err = -ENOMEM;
		goto close_dev;
	}

	err = nvme_cli_get_log_persistent_event(dev, cfg.action,
						sizeof(*pevent), pevent);
	if (err < 0) {
		fprintf(stderr, "persistent event log: %s\n",
			nvme_strerror(errno));
		goto free_pevent;
	} else if (err) {
		nvme_show_status(err);
		goto free_pevent;
	}

	if (cfg.action == NVME_PEVENT_LOG_RELEASE_CTX) {
		printf("Releasing Persistent Event Log Context\n");
		goto free_pevent;
	}

	if (!cfg.log_len && cfg.action != NVME_PEVENT_LOG_EST_CTX_AND_READ) {
		cfg.log_len = le64_to_cpu(pevent->tll);
	} else if (!cfg.log_len && cfg.action == NVME_PEVENT_LOG_EST_CTX_AND_READ) {
		printf("Establishing Persistent Event Log Context\n");
		goto free_pevent;
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

	pevent_log_info = nvme_alloc(cfg.log_len, &huge);
	if (!pevent_log_info) {
		err = -ENOMEM;
		goto free_pevent;
	}
	err = nvme_cli_get_log_persistent_event(dev, cfg.action,
						cfg.log_len, pevent_log_info);
	if (!err) {
		err = nvme_cli_get_log_persistent_event(dev, cfg.action,
							sizeof(*pevent),
							pevent);
		if (err < 0) {
			fprintf(stderr, "persistent event log: %s\n",
				nvme_strerror(errno));
			goto free;
		} else if (err) {
			nvme_show_status(err);
			goto free;
		}
		pevent_collected = pevent_log_info;
		if (pevent_collected->gen_number != pevent->gen_number) {
			printf("Collected Persistent Event Log may be invalid, "\
				"Re-read the log is required\n");
			goto free;
		}

		nvme_show_persistent_event_log(pevent_log_info, cfg.action,
			cfg.log_len, dev->name, flags);
	} else if (err > 0)
		nvme_show_status(err);
	else
		fprintf(stderr, "persistent event log: %s\n",
			nvme_strerror(errno));

free:
	nvme_free(pevent_log_info, huge);
free_pevent:
	free(pevent);
close_dev:
	dev_close(dev);
ret:
	return err;
}

static int get_endurance_event_agg_log(int argc, char **argv,
		struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Retrieve Retrieve Predictable Latency " \
			"Event Aggregate page and prints it, for the given " \
			"device in either decoded format(default), " \
			"json or binary.";
	const char *log_entries = "Number of pending Endurance Group " \
			"Event log Entries list";
	void *endurance_log;
	struct nvme_id_ctrl ctrl;
	enum nvme_print_flags flags;
	struct nvme_dev *dev;
	__u32 log_size;
	int err;

	struct config {
		__u64	log_entries;
		bool	rae;
		char	*output_format;
		bool	raw_binary;
	};

	struct config cfg = {
		.log_entries	= 2044,
		.rae		= false,
		.output_format	= "normal",
		.raw_binary	= false,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("log-entries",  'e', &cfg.log_entries,   log_entries),
		OPT_FLAG("rae",          'r', &cfg.rae,           rae),
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,    raw_use),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_dev;
	if (cfg.raw_binary)
		flags = BINARY;

	if (!cfg.log_entries) {
		fprintf(stderr, "non-zero log-entries is required param\n");
		err = -EINVAL;
		goto close_dev;
	}

	err = nvme_cli_identify_ctrl(dev, &ctrl);
	if (err < 0) {
		fprintf(stderr, "identify controller: %s\n",
			nvme_strerror(errno));
		goto close_dev;
	} else if (err) {
		fprintf(stderr, "could not identify controller\n");
		err = -ENODEV;
		goto close_dev;
	}

	cfg.log_entries = min(cfg.log_entries, le16_to_cpu(ctrl.endgidmax));
	log_size = sizeof(__u64) + cfg.log_entries * sizeof(__u16);
	endurance_log = calloc(log_size, 1);
	if (!endurance_log) {
		err = -ENOMEM;
		goto close_dev;
	}

	err = nvme_cli_get_log_endurance_grp_evt(dev, cfg.rae, 0, log_size,
						 endurance_log);
	if (!err)
		nvme_show_endurance_group_event_agg_log(endurance_log, cfg.log_entries,
			log_size, dev->name, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		fprintf(stderr, "endurance group event aggregate log page: %s\n",
			nvme_strerror(errno));
	free(endurance_log);

close_dev:
	dev_close(dev);
ret:
	return err;
}

static int get_lba_status_log(int argc, char **argv,
		struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Retrieve Get LBA Status Info Log " \
			"and prints it, for the given device in either " \
			"decoded format(default),json or binary.";
	void *lab_status;
	enum nvme_print_flags flags;
	struct nvme_dev *dev;
	__u32 lslplen;
	int err;

	struct config {
		bool	rae;
		char	*output_format;
	};

	struct config cfg = {
		.rae		= false,
		.output_format	= "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FLAG("rae",          'r', &cfg.rae,           rae),
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_dev;

	err = nvme_cli_get_log_lba_status(dev, true, 0, sizeof(__u32),
					  &lslplen);
	if (err < 0) {
		fprintf(stderr, "lba status log page: %s\n",
			nvme_strerror(errno));
		goto close_dev;
	} else if (err) {
		nvme_show_status(err);
		goto close_dev;
	}

	lab_status = calloc(lslplen, 1);
	if (!lab_status) {
		err = -ENOMEM;
		goto close_dev;
	}

	err = nvme_cli_get_log_lba_status(dev, cfg.rae, 0, lslplen,
					  lab_status);
	if (!err)
		nvme_show_lba_status_log(lab_status, lslplen, dev->name, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		fprintf(stderr, "lba status log page: %s\n",
			nvme_strerror(errno));
	free(lab_status);

close_dev:
	dev_close(dev);
ret:
	return err;
}

static int get_resv_notif_log(int argc, char **argv,
	struct command *cmd, struct plugin *plugin)
{

	const char *desc = "Retrieve Reservation Notification " \
		"log page and prints it, for the given " \
		"device in either decoded format(default), " \
		"json or binary.";
	struct nvme_resv_notification_log resv;
	enum nvme_print_flags flags;
	struct nvme_dev *dev;
	int err;

	struct config {
		char	*output_format;
	};

	struct config cfg = {
		.output_format	= "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_dev;

	err = nvme_cli_get_log_reservation(dev, false, &resv);
	if (!err)
		nvme_show_resv_notif_log(&resv, dev->name, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		fprintf(stderr, "resv notifi log: %s\n",
			nvme_strerror(errno));

close_dev:
	dev_close(dev);
ret:
	return err;

}

static int get_boot_part_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Retrieve Boot Partition " \
		"log page and prints it, for the given " \
		"device in either decoded format(default), " \
		"json or binary.";
	const char *fname = "boot partition data output file name";
	struct nvme_boot_partition boot;
	__u8 *bp_log;
	enum nvme_print_flags flags;
	int err = -1, output = 0;
	struct nvme_dev *dev;
	__u32 bpsz = 0;

	struct config {
		__u8	lsp;
		char	*file_name;
		char	*output_format;
	};

	struct config cfg = {
		.lsp		= 0,
		.output_format	= "normal",
		.file_name	= NULL,
	};

	OPT_ARGS(opts) = {
		OPT_BYTE("lsp",          's', &cfg.lsp,           lsp),
		OPT_FILE("output-file",  'f', &cfg.file_name,     fname),
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_dev;

	if (!cfg.file_name) {
		fprintf(stderr, "Please provide an output file!\n");
		err = -1;
		goto close_dev;
	}

	if (cfg.lsp > 128) {
		fprintf(stderr, "invalid lsp param: %u\n", cfg.lsp);
		err = -1;
		goto close_dev;
	}

	output = open(cfg.file_name, O_WRONLY | O_CREAT | O_TRUNC, 0666);
	if (output < 0) {
		fprintf(stderr, "Failed to open output file %s: %s!\n",
				cfg.file_name, strerror(errno));
		err = output;
		goto close_dev;
	}

	err = nvme_cli_get_log_boot_partition(dev, false, cfg.lsp,
					      sizeof(boot), &boot);
	if (err < 0) {
		fprintf(stderr, "boot partition log: %s\n",
			nvme_strerror(errno));
		goto close_output;
	} else if (err) {
		nvme_show_status(err);
		goto close_output;
	}

	bpsz = (boot.bpinfo & 0x7fff) * 128 * 1024;
	bp_log = calloc(sizeof(boot) + bpsz, 1);
	if (!bp_log) {
		err = -1;
		goto close_output;
	}

	err = nvme_cli_get_log_boot_partition(dev, false, cfg.lsp,
					      sizeof(boot) + bpsz,
					      (struct nvme_boot_partition *)bp_log);
	if (!err)
		nvme_show_boot_part_log(&bp_log, dev->name, flags,
					sizeof(boot) + bpsz);
	else if (err > 0)
		nvme_show_status(err);
	else
		fprintf(stderr, "boot partition log: %s\n",
			nvme_strerror(errno));

	err = write(output, (void *) bp_log + sizeof(boot), bpsz);
	if (err != bpsz) {
		fprintf(stderr, "Failed to flush all data to file!\n");
	} else {
		printf("Data flushed into file %s\n", cfg.file_name);
	}
	err = 0;

	free(bp_log);

close_output:
	close(output);
close_dev:
	dev_close(dev);
ret:
	return err;
}

static int get_media_unit_stat_log(int argc, char **argv, struct command *cmd,
				   struct plugin *plugin)
{
	const char *desc = "Retrieve the configuration and wear of media units and print it";
	struct nvme_media_unit_stat_log mus;
	enum nvme_print_flags flags;
	struct nvme_dev *dev;
	int err = -1;

	struct config {
		__u16	domainid;
		char	*output_format;
		bool	raw_binary;
	};

	struct config cfg = {
		.domainid	= 0,
		.output_format	= "normal",
		.raw_binary	= false,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("domain-id",     'd', &cfg.domainid, domainid),
		OPT_FMT("output-format",  'o', &cfg.output_format, output_format),
		OPT_FLAG("raw-binary",    'b', &cfg.raw_binary, raw_use),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_dev;

	if (cfg.raw_binary)
		flags = BINARY;

	err = nvme_cli_get_log_media_unit_stat(dev, cfg.domainid, &mus);
	if (!err)
		nvme_show_media_unit_stat_log(&mus, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		fprintf(stderr, "media unit status log: %s\n",
			nvme_strerror(errno));

close_dev:
	dev_close(dev);
ret:
	return err;
}

static int get_supp_cap_config_log(int argc, char **argv, struct command *cmd,
				   struct plugin *plugin)
{
	const char *desc = "Retrieve the list of Supported Capacity Configuration Descriptors";
	struct nvme_supported_cap_config_list_log cap_log;
	enum nvme_print_flags flags;
	struct nvme_dev *dev;
	int err = -1;

	struct config {
		__u16	domainid;
		char	*output_format;
		bool	raw_binary;
	};

	struct config cfg = {
		.domainid	= 0,
		.output_format	= "normal",
		.raw_binary	= false,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("domain-id",     'd', &cfg.domainid,       domainid),
		OPT_FMT("output-format",  'o', &cfg.output_format,  output_format),
		OPT_FLAG("raw-binary",    'b', &cfg.raw_binary,     raw_use),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_dev;

	if (cfg.raw_binary)
		flags = BINARY;

	err = nvme_cli_get_log_support_cap_config_list(dev, cfg.domainid,
						       &cap_log);
	if (!err)
		nvme_show_supported_cap_config_log(&cap_log, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		perror("supported capacity configuration list log");

close_dev:
	dev_close(dev);
ret:
	return err;
}

static int get_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Retrieve desired number of bytes "\
		"from a given log on a specified device in either "\
		"hex-dump (default) or binary format";
	const char *log_id = "identifier of log to retrieve";
	const char *log_len = "how many bytes to retrieve";
	const char *aen = "result of the aen, use to override log id";
	const char *lpo = "log page offset specifies the location within a log page from where to start returning data";
	const char *lsi = "log specific identifier specifies an identifier that is required for a particular log page";
	const char *raw = "output in raw format";
	const char *csi = "command set identifier";
	const char *offset_type = "offset type";
	struct nvme_dev *dev;
	unsigned char *log;
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
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_desired),
		OPT_BYTE("log-id",       'i', &cfg.log_id,       log_id),
		OPT_UINT("log-len",      'l', &cfg.log_len,      log_len),
		OPT_UINT("aen",          'a', &cfg.aen,          aen),
		OPT_SUFFIX("lpo",        'o', &cfg.lpo,          lpo),
		OPT_BYTE("lsp",          's', &cfg.lsp,          lsp),
		OPT_SHRT("lsi",          'S', &cfg.lsi,          lsi),
		OPT_FLAG("rae",          'r', &cfg.rae,          rae),
		OPT_BYTE("uuid-index",   'U', &cfg.uuid_index,   uuid_index),
		OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,   raw),
		OPT_BYTE("csi",          'y', &cfg.csi,          csi),
		OPT_FLAG("ot",           'O', &cfg.ot,           offset_type),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	if (cfg.aen) {
		cfg.log_len = 4096;
		cfg.log_id = (cfg.aen >> 16) & 0xff;
	}

	if (!cfg.log_len) {
		perror("non-zero log-len is required param\n");
		err = -EINVAL;
		goto close_dev;
	}

	if (cfg.lsp > 128) {
		perror("invalid lsp param\n");
		err = -EINVAL;
		goto close_dev;
	}

	if (cfg.uuid_index > 128) {
		perror("invalid uuid index param\n");
		err = -EINVAL;
		goto close_dev;
	}

	log = malloc(cfg.log_len);
	if (!log) {
		perror("could not alloc buffer for log\n");
		err = -ENOMEM;
		goto close_dev;
	}

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
	err = nvme_cli_get_log(dev, &args);
	if (!err) {
		if (!cfg.raw_binary) {
			printf("Device:%s log-id:%d namespace-id:%#x\n",
				dev->name, cfg.log_id,
				cfg.namespace_id);
			d(log, cfg.log_len, 16, 1);
		} else
			d_raw((unsigned char *)log, cfg.log_len);
	} else if (err > 0)
		nvme_show_status(err);
	else
		fprintf(stderr, "log page: %s\n", nvme_strerror(errno));
	free(log);

close_dev:
	dev_close(dev);
ret:
	return err;
}

static int sanitize_log(int argc, char **argv, struct command *command, struct plugin *plugin)
{
	const char *desc = "Retrieve sanitize log and show it.";
	struct nvme_sanitize_log_page sanitize_log;
	enum nvme_print_flags flags;
	struct nvme_dev *dev;
	int err;

	struct config {
		bool	rae;
		char	*output_format;
		bool	human_readable;
		bool	raw_binary;
	};

	struct config cfg = {
		.rae		= false,
		.output_format	= "normal",
		.human_readable	= false,
		.raw_binary	= false,
	};

	OPT_ARGS(opts) = {
		OPT_FLAG("rae",           'r', &cfg.rae,            rae),
		OPT_FMT("output-format",  'o', &cfg.output_format,  output_format),
		OPT_FLAG("human-readable",'H', &cfg.human_readable, human_readable_log),
		OPT_FLAG("raw-binary",    'b', &cfg.raw_binary,     raw_log),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_dev;
	if (cfg.raw_binary)
		flags = BINARY;
	if (cfg.human_readable)
		flags |= VERBOSE;

	err = nvme_cli_get_log_sanitize(dev, cfg.rae, &sanitize_log);
	if (!err)
		nvme_show_sanitize_log(&sanitize_log, dev->name, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		fprintf(stderr, "sanitize status log: %s\n",
			nvme_strerror(errno));
close_dev:
	dev_close(dev);
ret:
	return err;
}

static int get_fid_support_effects_log(int argc, char **argv, struct command *cmd,
	struct plugin *plugin)
{
	const char *desc = "Retrieve FID Support and Effects log and show it.";
	struct nvme_fid_supported_effects_log fid_support_log;
	enum nvme_print_flags flags;
	struct nvme_dev *dev;
	int err = -1;

	struct config {
		char	*output_format;
		bool	human_readable;
	};

	struct config cfg = {
		.output_format	= "normal",
		.human_readable	= false,
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format",  'o', &cfg.output_format,  output_format),
		OPT_FLAG("human-readable",'H', &cfg.human_readable, human_readable_log),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_dev;
	if (cfg.human_readable)
		flags |= VERBOSE;

	err = nvme_cli_get_log_fid_supported_effects(dev, false,
						     &fid_support_log);
	if (!err)
		nvme_show_fid_support_effects_log(&fid_support_log,
						  dev->name, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		fprintf(stderr, "fid support effects log: %s\n",
			nvme_strerror(errno));
close_dev:
	dev_close(dev);
ret:
	return err;
}

static int get_mi_cmd_support_effects_log(int argc, char **argv, struct command *cmd,
	struct plugin *plugin)
{
	const char *desc = "Retrieve NVMe-MI Command Support and Effects log and show it.";
	struct nvme_mi_cmd_supported_effects_log mi_cmd_support_log;
	enum nvme_print_flags flags;
	struct nvme_dev *dev;
	int err = -1;

	struct config {
		char	*output_format;
		bool	human_readable;
	};

	struct config cfg = {
		.output_format	= "normal",
		.human_readable	= false,
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format",  'o', &cfg.output_format,  output_format),
		OPT_FLAG("human-readable",'H', &cfg.human_readable, human_readable_log),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_dev;
	if (cfg.human_readable)
		flags |= VERBOSE;

	err = nvme_cli_get_log_mi_cmd_supported_effects(dev, false,
							&mi_cmd_support_log);
	if (!err)
		nvme_show_mi_cmd_support_effects_log(&mi_cmd_support_log,
						     dev->name, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		fprintf(stderr, "mi command support effects log: %s\n",
			nvme_strerror(errno));
close_dev:
	dev_close(dev);
ret:
	return err;
}

static int list_ctrl(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Show controller list information for the subsystem the "\
		"given device is part of, or optionally controllers attached to a specific namespace.";
	const char *controller = "controller to display";
	struct nvme_ctrl_list *cntlist;
	enum nvme_print_flags flags;
	struct nvme_dev *dev;
	int err;

	struct config {
		__u16	cntid;
		__u32	namespace_id;
		char	*output_format;
	};

	struct config cfg = {
		.cntid		= 0,
		.namespace_id	= NVME_NSID_NONE,
		.output_format	= "normal",
	};

	OPT_ARGS(opts) = {
		OPT_SHRT("cntid",        'c', &cfg.cntid,         controller),
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id,  namespace_id_optional),
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_dev;

	if (posix_memalign((void *)&cntlist, getpagesize(), 0x1000)) {
		fprintf(stderr, "can not allocate controller list payload\n");
		err = -ENOMEM;
		goto close_dev;
	}

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
		fprintf(stderr, "id controller list: %s\n",
			nvme_strerror(errno));

	free(cntlist);
close_dev:
	dev_close(dev);
ret:
	return err;
}

static int list_ns(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "For the specified controller handle, show the "\
		"namespace list in the associated NVMe subsystem, optionally starting with a given nsid.";
	const char *namespace_id = "first nsid returned list should start from";
	const char *csi = "I/O command set identifier";
	const char *all = "show all namespaces in the subsystem, whether attached or inactive";
	struct nvme_ns_list ns_list;
	enum nvme_print_flags flags;
	struct nvme_dev *dev;
	int err;

	struct config {
		__u32	namespace_id;
		int	csi;
		bool	all;
		char	*output_format;
	};

	struct config cfg = {
		.namespace_id	= 1,
		.csi		= -1,
		.all		= false,
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id,  namespace_id),
		OPT_INT("csi",           'y', &cfg.csi,           csi),
		OPT_FLAG("all",          'a', &cfg.all,           all),
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format_no_binary),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_dev;
	if (flags != JSON && flags != NORMAL) {
		err = -EINVAL;
		goto close_dev;
	}

	if (!cfg.namespace_id) {
		err = -EINVAL;
		fprintf(stderr, "invalid nsid parameter\n");
		goto close_dev;
	}

	struct nvme_identify_args args = {
		.args_size	= sizeof(args),
		.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
		.data		= &ns_list,
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
		nvme_show_list_ns(&ns_list, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		fprintf(stderr, "id namespace list: %s",
			nvme_strerror(errno));
close_dev:
	dev_close(dev);
ret:
	return err;
}

static int id_ns_lba_format(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Send an Identify Namespace command to the given "\
		"device, returns capability field properties of the specified "\
		"LBA Format index in  various formats.";
	enum nvme_print_flags flags;
	struct nvme_id_ns ns;
	struct nvme_dev *dev;
	int err = -1;

	struct config {
		__u16	lba_format_index;
		__u8	uuid_index;
		bool	verbose;
		char	*output_format;
	};

	struct config cfg = {
		.lba_format_index	= 0,
		.uuid_index		= NVME_UUID_NONE,
		.verbose		= false,
		.output_format		= "normal",
	};

	OPT_ARGS(opts) = {
		OPT_UINT("lba-format-index", 'i', &cfg.lba_format_index, lba_format_index),
		OPT_BYTE("uuid-index",       'U', &cfg.uuid_index,       uuid_index),
		OPT_FLAG("verbose",          'v', &cfg.verbose,          verbose),
		OPT_FMT("output-format",     'o', &cfg.output_format,    output_format),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_dev;

	if (cfg.verbose)
		flags |= VERBOSE;

	err = nvme_identify_ns_csi_user_data_format(dev_fd(dev),
										cfg.lba_format_index,
										cfg.uuid_index, NVME_CSI_NVM, &ns);
	if (!err)
		nvme_show_id_ns(&ns, 0, cfg.lba_format_index, true, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		perror("identify namespace for specific LBA format");
close_dev:
	dev_close(dev);
ret:
	return nvme_status_to_errno(err, false);
}

static int id_endurance_grp_list(int argc, char **argv, struct command *cmd,
	struct plugin *plugin)
{
	const char *desc = "Show endurance group list information for the given endurance "\
		"group id";
	const char *endurance_grp_id = "Endurance Group ID";
	struct nvme_id_endurance_group_list *endgrp_list;
	enum nvme_print_flags flags;
	struct nvme_dev *dev;
	int err = -1;

	struct config {
		__u16	endgrp_id;
		char	*output_format;
	};

	struct config cfg = {
		.endgrp_id	= 0,
		.output_format	= "normal",
	};

	OPT_ARGS(opts) = {
		OPT_SHRT("endgrp-id",    'i', &cfg.endgrp_id,     endurance_grp_id),
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_dev;
	if (flags != JSON && flags != NORMAL) {
		err = -EINVAL;
		fprintf(stderr, "invalid output format\n");
		goto close_dev;
	}

	if (posix_memalign((void *)&endgrp_list, getpagesize(), 0x1000)) {
		err = -1;
		goto close_dev;
	}

	err = nvme_identify_endurance_group_list(dev_fd(dev), cfg.endgrp_id,
						 endgrp_list);
	if (!err)
		nvme_show_endurance_group_list(endgrp_list, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		fprintf(stderr, "Id endurance group list: %s",
			nvme_strerror(errno));

	free(endgrp_list);
close_dev:
	dev_close(dev);
ret:
	return err;
}

static int delete_ns(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Delete the given namespace by "\
		"sending a namespace management command to "\
		"the provided device. All controllers should be detached from "\
		"the namespace prior to namespace deletion. A namespace ID "\
		"becomes inactive when that namespace is detached or, if "\
		"the namespace is not already inactive, once deleted.";
	const char *namespace_id = "namespace to delete";
	struct nvme_dev *dev;
	int err;

	struct config {
		__u32	namespace_id;
		__u32	timeout;
	};

	struct config cfg = {
		.namespace_id	= 0,
		.timeout	= 120000,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id),
		OPT_UINT("timeout",      't', &cfg.timeout,      timeout),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	if (!cfg.namespace_id) {
		err = nvme_get_nsid(dev_fd(dev), &cfg.namespace_id);
		if (err < 0) {
			fprintf(stderr, "get-namespace-id: %s\n",
				nvme_strerror(errno));
			goto close_dev;
		}
	}

	err = nvme_cli_ns_mgmt_delete(dev, cfg.namespace_id);
	if (!err)
		printf("%s: Success, deleted nsid:%d\n", cmd->name,
								cfg.namespace_id);
	else if (err > 0)
		nvme_show_status(err);
	else
		fprintf(stderr, "delete namespace: %s\n", nvme_strerror(errno));

close_dev:
	dev_close(dev);
ret:
	return err;
}

static int nvme_attach_ns(int argc, char **argv, int attach, const char *desc, struct command *cmd)
{
	struct nvme_ctrl_list cntlist;
	int err, num, i, list[2048];
	struct nvme_dev *dev;
	__u16 ctrlist[2048];

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

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id),
		OPT_LIST("controllers",  'c', &cfg.cntlist,      cont),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	if (!cfg.namespace_id) {
		fprintf(stderr, "%s: namespace-id parameter required\n",
						cmd->name);
		err = -EINVAL;
		goto close_dev;
	}

	num = argconfig_parse_comma_sep_array(cfg.cntlist, list, 2047);
	if (!num) {
		fprintf(stderr, "warning: empty controller-id list will result in no actual change in namespace attachment\n");
	}

	if (num == -1) {
		fprintf(stderr, "%s: controller id list is malformed\n",
						cmd->name);
		err = -EINVAL;
		goto close_dev;
	}

	for (i = 0; i < num; i++)
		ctrlist[i] = (__u16)list[i];

	nvme_init_ctrl_list(&cntlist, num, ctrlist);

	if (attach)
		err = nvme_cli_ns_attach_ctrls(dev, cfg.namespace_id,
					       &cntlist);
	else
		err = nvme_cli_ns_detach_ctrls(dev, cfg.namespace_id,
					       &cntlist);

	if (!err)
		printf("%s: Success, nsid:%d\n", cmd->name, cfg.namespace_id);
	else if (err > 0)
		nvme_show_status(err);
	else
		perror(attach ? "attach namespace" : "detach namespace");

close_dev:
	dev_close(dev);
ret:
	return err;
}

static int attach_ns(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Attach the given namespace to the "\
		"given controller or comma-sep list of controllers. ID of the "\
		"given namespace becomes active upon attachment to a "\
		"controller. A namespace must be attached to a controller "\
		"before IO commands may be directed to that namespace.";
	return nvme_attach_ns(argc, argv, 1, desc, cmd);
}

static int detach_ns(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Detach the given namespace from the "\
		"given controller; de-activates the given namespace's ID. A "\
		"namespace must be attached to a controller before IO "\
		"commands may be directed to that namespace.";
	return nvme_attach_ns(argc, argv, 0, desc, cmd);
}

static int create_ns(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Send a namespace management command "\
		"to the specified device to create a namespace with the given "\
		"parameters. The next available namespace ID is used for the "\
		"create operation. Note that create-ns does not attach the "\
		"namespace to a controller, the attach-ns command is needed.";
	const char *nsze = "size of ns (NSZE)";
	const char *ncap = "capacity of ns (NCAP)";
	const char *flbas = "Formatted LBA size (FLBAS), if entering this "\
		"value ignore \'block-size\' field";
	const char *dps = "data protection settings (DPS)";
	const char *nmic = "multipath and sharing capabilities (NMIC)";
	const char *anagrpid = "ANA Group Identifier (ANAGRPID)";
	const char *nvmsetid = "NVM Set Identifier (NVMSETID)";
	const char *csi = "command set identifier (CSI)";
	const char *lbstm = "logical block storage tag mask (LBSTM)";
	const char *bs = "target block size, specify only if \'FLBAS\' "\
		"value not entered";

	struct nvme_id_ns ns;
	struct nvme_dev *dev;
	int err = 0, i;
	__u32 nsid;

	struct config {
		__u64	nsze;
		__u64	ncap;
		__u8	flbas;
		__u8	dps;
		__u8	nmic;
		__u32	anagrpid;
		__u16	nvmsetid;
		__u64	bs;
		__u32	timeout;
		__u8	csi;
		__u64	lbstm;
	};

	struct config cfg = {
		.nsze		= 0,
		.ncap		= 0,
		.flbas		= 0xff,
		.dps		= 0,
		.nmic		= 0,
		.anagrpid	= 0,
		.nvmsetid	= 0,
		.bs		= 0x00,
		.timeout	= 120000,
		.csi		= 0,
		.lbstm		= 0,
	};

	OPT_ARGS(opts) = {
		OPT_SUFFIX("nsze",       's', &cfg.nsze,     nsze),
		OPT_SUFFIX("ncap",       'c', &cfg.ncap,     ncap),
		OPT_BYTE("flbas",        'f', &cfg.flbas,    flbas),
		OPT_BYTE("dps",          'd', &cfg.dps,      dps),
		OPT_BYTE("nmic",         'm', &cfg.nmic,     nmic),
		OPT_UINT("anagrp-id",	 'a', &cfg.anagrpid, anagrpid),
		OPT_UINT("nvmset-id",	 'i', &cfg.nvmsetid, nvmsetid),
		OPT_SUFFIX("block-size", 'b', &cfg.bs,       bs),
		OPT_UINT("timeout",      't', &cfg.timeout,  timeout),
		OPT_BYTE("csi",          'y', &cfg.csi,      csi),
		OPT_SUFFIX("lbstm",      'l', &cfg.lbstm,    lbstm),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	if (cfg.flbas != 0xff && cfg.bs != 0x00) {
		fprintf(stderr,
			"Invalid specification of both FLBAS and Block Size, please specify only one\n");
		err = -EINVAL;
		goto close_dev;
	}
	if (cfg.bs) {
		if ((cfg.bs & (~cfg.bs + 1)) != cfg.bs) {
			fprintf(stderr,
				"Invalid value for block size (%"PRIu64"). Block size must be a power of two\n",
				(uint64_t)cfg.bs);
			err = -EINVAL;
			goto close_dev;
		}
		err = nvme_cli_identify_ns(dev, NVME_NSID_ALL, &ns);
		if (err) {
			if (err < 0)
				fprintf(stderr, "identify-namespace: %s",
					nvme_strerror(errno));
			else {
				fprintf(stderr, "identify failed\n");
				nvme_show_status(err);
			}
			goto close_dev;
		}
		for (i = 0; i <= ns.nlbaf; ++i) {
			if ((1 << ns.lbaf[i].ds) == cfg.bs && ns.lbaf[i].ms == 0) {
				cfg.flbas = i;
				break;
			}
		}

	}
	if (cfg.flbas == 0xff) {
		fprintf(stderr,
			"FLBAS corresponding to block size %"PRIu64" not found\n",
			(uint64_t)cfg.bs);
		fprintf(stderr,
			"Please correct block size, or specify FLBAS directly\n");

		err = -EINVAL;
		goto close_dev;
	}

	struct nvme_id_ns ns2 = {
		.nsze = cpu_to_le64(cfg.nsze),
		.ncap = cpu_to_le64(cfg.ncap),
		.flbas = cfg.flbas,
		.dps = cfg.dps,
		.nmic = cfg.nmic,
		.anagrpid = cpu_to_le32(cfg.anagrpid),
		.nvmsetid = cpu_to_le16(cfg.nvmsetid),
		.lbstm = cpu_to_le64(cfg.lbstm),
	};

	err = nvme_cli_ns_mgmt_create(dev, &ns2, &nsid, cfg.timeout, cfg.csi);
	if (!err)
		printf("%s: Success, created nsid:%d\n", cmd->name, nsid);
	else if (err > 0)
		nvme_show_status(err);
	else
		fprintf(stderr, "create namespace: %s\n", nvme_strerror(errno));

close_dev:
	dev_close(dev);
ret:
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

	struct config {
		char	*output_format;
		int	verbose;
	};

	struct config cfg = {
		.output_format	= "normal",
		.verbose	= 0,
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format_no_binary),
		OPT_INCR("verbose",      'v', &cfg.verbose,       verbose),
		OPT_END()
	};

	err = argconfig_parse(argc, argv, desc, opts);
	if (err < 0)
		goto ret;

	devname = NULL;
	if (optind < argc)
		devname = basename(argv[optind++]);

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto ret;
	if (flags != JSON && flags != NORMAL) {
		err = -EINVAL;
		goto ret;
	}
	if (cfg.verbose)
		flags |= VERBOSE;

	r = nvme_create_root(stderr, map_log_level(cfg.verbose, false));
	if (!r) {
		if (devname)
			fprintf(stderr,
				"Failed to scan nvme subsystem for %s\n",
				devname);
		else
			fprintf(stderr, "Failed to scan nvme subsystem\n");
		err = -errno;
		goto ret;
	}

	if (devname) {
		int subsys_num;

		if (sscanf(devname, "nvme%dn%d", &subsys_num, &nsid) != 2) {
			fprintf(stderr, "Invalid device name %s\n", devname);
			err = -EINVAL;
			goto ret;
		}
		filter = nvme_match_device_filter;
	}

	err = nvme_scan_topology(r, filter, (void *)devname);
	if (err) {
		fprintf(stderr, "Failed to scan topology: %s\n",
			nvme_strerror(errno));
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

	struct config {
		char	*output_format;
		bool	verbose;
	};

	struct config cfg = {
		.output_format	= "normal",
		.verbose	= false,
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format_no_binary),
		OPT_FLAG("verbose",      'v', &cfg.verbose,       verbose),
		OPT_END()
	};

	err = argconfig_parse(argc, argv, desc, opts);
	if (err < 0)
		return err;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		return err;
	if (flags != JSON && flags != NORMAL) {
		fprintf(stderr, "Invalid output format\n");
		return -EINVAL;
	}
	if (cfg.verbose)
		flags |= VERBOSE;

	r = nvme_create_root(stderr, map_log_level(cfg.verbose, false));
	if (!r) {
		fprintf(stderr, "Failed to create topology root: %s\n",
			nvme_strerror(errno));
		return -errno;
	}
	err = nvme_scan_topology(r, NULL, NULL);
	if (err < 0) {
		fprintf(stderr, "Failed to scan topology: %s\n",
			 nvme_strerror(errno));
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
	const char *desc = "Send an Identify Controller command to "\
		"the given device and report information about the specified "\
		"controller in human-readable or "\
		"binary format. May also return vendor-specific "\
		"controller attributes in hex-dump if requested.";
	const char *vendor_specific = "dump binary vendor field";
	enum nvme_print_flags flags;
	struct nvme_id_ctrl ctrl;
	struct nvme_dev *dev;
	int err;

	struct config {
		bool	vendor_specific;
		char	*output_format;
		bool	raw_binary;
		bool	human_readable;
	};

	struct config cfg = {
		.vendor_specific	= false,
		.output_format		= "normal",
		.raw_binary		= false,
		.human_readable		= false,
	};

	OPT_ARGS(opts) = {
		OPT_FLAG("vendor-specific", 'v', &cfg.vendor_specific, vendor_specific),
		OPT_FMT("output-format",    'o', &cfg.output_format,   output_format),
		OPT_FLAG("raw-binary",      'b', &cfg.raw_binary,      raw_identify),
		OPT_FLAG("human-readable",  'H', &cfg.human_readable,  human_readable_identify),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_dev;
	if (cfg.raw_binary)
		flags = BINARY;
	if (cfg.vendor_specific)
		flags |= VS;
	if (cfg.human_readable)
		flags |= VERBOSE;

	err = nvme_cli_identify_ctrl(dev, &ctrl);
	if (!err)
		nvme_show_id_ctrl(&ctrl, flags, vs);
	else if (err > 0)
		nvme_show_status(err);
	else
		fprintf(stderr, "identify controller: %s\n", nvme_strerror(errno));
close_dev:
	dev_close(dev);
ret:
	return err;
}

static int id_ctrl(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	return __id_ctrl(argc, argv, cmd, plugin, NULL);
}

static int nvm_id_ctrl(int argc, char **argv, struct command *cmd,
	struct plugin *plugin)
{
	const char *desc = "Send an Identify Controller NVM Command Set "\
		"command to the given device and report information about "\
		"the specified controller in various formats.";
	enum nvme_print_flags flags;
	struct nvme_id_ctrl_nvm ctrl_nvm;
	struct nvme_dev *dev;
	int err = -1;

	struct config {
		char	*output_format;
	};

	struct config cfg = {
		.output_format	= "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format,   output_format),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_dev;

	err = nvme_nvm_identify_ctrl(dev_fd(dev), &ctrl_nvm);
	if (!err)
		nvme_show_id_ctrl_nvm(&ctrl_nvm, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		fprintf(stderr, "nvm identify controller: %s\n", nvme_strerror(errno));
close_dev:
	dev_close(dev);
ret:
	return err;
}

static int nvm_id_ns(int argc, char **argv, struct command *cmd,
	struct plugin *plugin)
{
	const char *desc = "Send an Identify Namespace NVM Command Set "\
		"command to the given device and report information about "\
		"the specified namespace in various formats.";
	enum nvme_print_flags flags;
	struct nvme_nvm_id_ns id_ns;
	struct nvme_id_ns ns;
	struct nvme_dev *dev;
	int err = -1;

	struct config {
		__u32	namespace_id;
		__u8	uuid_index;
		char	*output_format;
		bool	verbose;
	};

	struct config cfg = {
		.namespace_id	= 0,
		.uuid_index	= NVME_UUID_NONE,
		.output_format	= "normal",
		.verbose	= false,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id,    namespace_id_desired),
		OPT_BYTE("uuid-index",   'U', &cfg.uuid_index,      uuid_index),
		OPT_FMT("output-format", 'o', &cfg.output_format,   output_format),
		OPT_FLAG("verbose",      'v', &cfg.verbose,         verbose),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_dev;

	if (cfg.verbose)
		flags |= VERBOSE;

	if (!cfg.namespace_id) {
		err = nvme_get_nsid(dev_fd(dev), &cfg.namespace_id);
		if (err < 0) {
			perror("get-namespace-id");
			goto close_dev;
		}
	}

	err = nvme_cli_identify_ns(dev, cfg.namespace_id, &ns);
	if (err) {
		nvme_show_status(err);
		goto close_dev;
	}

	err = nvme_identify_ns_csi(dev_fd(dev), cfg.namespace_id,
							cfg.uuid_index,
							NVME_CSI_NVM, &id_ns);
	if (!err)
		nvme_show_nvm_id_ns(&id_ns, cfg.namespace_id, &ns, 0, false, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		perror("nvm identify namespace");
close_dev:
	dev_close(dev);
ret:
	return nvme_status_to_errno(err, false);
}

static int nvm_id_ns_lba_format(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Send an NVM Command Set specific Identify Namespace "
		"command to the given device, returns capability field properties of "
		"the specified LBA Format index in the specified namespace in various "
		"formats.";
	enum nvme_print_flags flags;
	struct nvme_id_ns ns;
	struct nvme_nvm_id_ns nvm_ns;
	struct nvme_dev *dev;
	int err = -1;

	struct config {
		__u16	lba_format_index;
		__u8	uuid_index;
		bool	verbose;
		char	*output_format;
	};

	struct config cfg = {
		.lba_format_index	= 0,
		.uuid_index		= NVME_UUID_NONE,
		.verbose		= false,
		.output_format		= "normal",
	};

	OPT_ARGS(opts) = {
		OPT_UINT("lba-format-index", 'i', &cfg.lba_format_index, lba_format_index),
		OPT_BYTE("uuid-index",       'U', &cfg.uuid_index,       uuid_index),
		OPT_FLAG("verbose",          'v', &cfg.verbose,          verbose),
		OPT_FMT("output-format",     'o', &cfg.output_format,    output_format),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_dev;

	if (cfg.verbose)
		flags |= VERBOSE;

	err = nvme_cli_identify_ns(dev, NVME_NSID_ALL, &ns);
	if (err) {
		ns.nlbaf = NVME_FEAT_LBA_RANGE_MAX - 1;
		ns.nulbaf = 0;
	}
	err = nvme_identify_iocs_ns_csi_user_data_format(dev_fd(dev),
										cfg.lba_format_index,
										cfg.uuid_index, NVME_CSI_NVM, &nvm_ns);
	if (!err)
		nvme_show_nvm_id_ns(&nvm_ns, 0, &ns, cfg.lba_format_index, true,
						flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		perror("NVM identify namespace for specific LBA format");
close_dev:
	dev_close(dev);
ret:
	return nvme_status_to_errno(err, false);
}

static int ns_descs(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Send Namespace Identification Descriptors command to the "\
			    "given device, returns the namespace identification descriptors "\
			    "of the specific namespace in either human-readable or binary format.";
	const char *raw = "show descriptors in binary format";
	enum nvme_print_flags flags;
	struct nvme_dev *dev;
	void *nsdescs;
	int err;

	struct config {
		__u32	namespace_id;
		char	*output_format;
		bool	raw_binary;
	};

	struct config cfg = {
		.namespace_id	= 0,
		.output_format	= "normal",
		.raw_binary	= false,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id",  'n', &cfg.namespace_id,  namespace_id_desired),
		OPT_FMT("output-format",  'o', &cfg.output_format, output_format),
		OPT_FLAG("raw-binary",    'b', &cfg.raw_binary,    raw),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_dev;
	if (cfg.raw_binary)
		flags = BINARY;

	if (!cfg.namespace_id) {
		err = nvme_get_nsid(dev_fd(dev), &cfg.namespace_id);
		if (err < 0) {
			fprintf(stderr, "get-namespace-id: %s\n", nvme_strerror(errno));
			goto close_dev;
		}
	}

	if (posix_memalign(&nsdescs, getpagesize(), 0x1000)) {
		err = -ENOMEM;
		goto close_dev;
	}

	err = nvme_cli_identify_ns_descs(dev, cfg.namespace_id, nsdescs);
	if (!err)
		nvme_show_id_ns_descs(nsdescs, cfg.namespace_id, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		fprintf(stderr, "identify namespace: %s\n", nvme_strerror(errno));
	free(nsdescs);
close_dev:
	dev_close(dev);
ret:
	return err;
}

static int id_ns(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Send an Identify Namespace command to the "\
		"given device, returns properties of the specified namespace "\
		"in either human-readable or binary format. Can also return "\
		"binary vendor-specific namespace attributes.";
	const char *force = "Return this namespace, even if not attached (1.2 devices only)";
	const char *vendor_specific = "dump binary vendor fields";

	enum nvme_print_flags flags;
	struct nvme_id_ns ns;
	struct nvme_dev *dev;
	int err;

	struct config {
		__u32	namespace_id;
		bool	force;
		bool	vendor_specific;
		bool	raw_binary;
		char	*output_format;
		bool	human_readable;
	};

	struct config cfg = {
		.namespace_id		= 0,
		.force			= false,
		.vendor_specific	= false,
		.raw_binary		= false,
		.output_format		= "normal",
		.human_readable		= false,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id",    'n', &cfg.namespace_id,    namespace_id_desired),
		OPT_FLAG("force",             0, &cfg.force,           force),
		OPT_FLAG("vendor-specific", 'v', &cfg.vendor_specific, vendor_specific),
		OPT_FLAG("raw-binary",      'b', &cfg.raw_binary,      raw_identify),
		OPT_FMT("output-format",    'o', &cfg.output_format,   output_format),
		OPT_FLAG("human-readable",  'H', &cfg.human_readable,  human_readable_identify),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_dev;
	if (cfg.raw_binary)
		flags = BINARY;
	if (cfg.vendor_specific)
		flags |= VS;
	if (cfg.human_readable)
		flags |= VERBOSE;

	if (!cfg.namespace_id) {
		err = nvme_get_nsid(dev_fd(dev), &cfg.namespace_id);
		if (err < 0) {
			fprintf(stderr, "get-namespace-id: %s\n", nvme_strerror(errno));
			goto close_dev;
		}
	}

	if (cfg.force)
		err = nvme_cli_identify_allocated_ns(dev,
						     cfg.namespace_id, &ns);
	else
		err = nvme_cli_identify_ns(dev, cfg.namespace_id, &ns);

	if (!err)
		nvme_show_id_ns(&ns, cfg.namespace_id, 0, false, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		fprintf(stderr, "identify namespace: %s\n", nvme_strerror(errno));
close_dev:
	dev_close(dev);
ret:
	return err;
}

static int cmd_set_independent_id_ns(int argc, char **argv,
    struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Send an I/O Command Set Independent Identify "\
		"Namespace command to the given device, returns properties of the "\
		"specified namespace in human-readable or binary or json format.";

	enum nvme_print_flags flags;
	struct nvme_id_independent_id_ns ns;
	struct nvme_dev *dev;
	int err = -1;

	struct config {
		__u32	namespace_id;
		bool	raw_binary;
		char	*output_format;
		bool	human_readable;
	};

	struct config cfg = {
		.namespace_id	= 0,
		.raw_binary	= false,
		.output_format	= "normal",
		.human_readable	= false,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id",    'n', &cfg.namespace_id,    namespace_id_desired),
		OPT_FLAG("raw-binary",      'b', &cfg.raw_binary,      raw_identify),
		OPT_FMT("output-format",    'o', &cfg.output_format,   output_format),
		OPT_FLAG("human-readable",  'H', &cfg.human_readable,  human_readable_identify),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_dev;
	if (cfg.raw_binary)
		flags = BINARY;
	if (cfg.human_readable)
		flags |= VERBOSE;

	if (!cfg.namespace_id) {
		err = cfg.namespace_id = nvme_get_nsid(dev_fd(dev),
						       &cfg.namespace_id);
		if (err < 0) {
			perror("get-namespace-id");
			goto close_dev;
		}
	}

	err = nvme_identify_independent_identify_ns(dev_fd(dev),
						    cfg.namespace_id, &ns);
	if (!err)
		nvme_show_cmd_set_independent_id_ns(&ns, cfg.namespace_id, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		fprintf(stderr, "I/O command set independent identify namespace: %s\n", nvme_strerror(errno));
close_dev:
	dev_close(dev);
ret:
	return err;
}

static int id_ns_granularity(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Send an Identify Namespace Granularity List command to the "\
		"given device, returns namespace granularity list "\
		"in either human-readable or binary format.";

	struct nvme_id_ns_granularity_list *granularity_list;
	enum nvme_print_flags flags;
	struct nvme_dev *dev;
	int err;

	struct config {
		char	*output_format;
	};

	struct config cfg = {
		.output_format	= "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_dev;

	if (posix_memalign((void *)&granularity_list, getpagesize(), NVME_IDENTIFY_DATA_SIZE)) {
		fprintf(stderr, "can not allocate granularity list payload\n");
		err = -ENOMEM;
		goto close_dev;
	}

	err = nvme_identify_ns_granularity(dev_fd(dev), granularity_list);
	if (!err)
		nvme_show_id_ns_granularity_list(granularity_list, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		fprintf(stderr, "identify namespace granularity: %s\n", nvme_strerror(errno));
	free(granularity_list);
close_dev:
	dev_close(dev);
ret:
	return err;
}

static int id_nvmset(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Send an Identify NVM Set List command to the "\
		"given device, returns entries for NVM Set identifiers greater "\
		"than or equal to the value specified CDW11.NVMSETID "\
		"in either binary format or json format";
	const char *nvmset_id = "NVM Set Identify value";

	struct nvme_id_nvmset_list nvmset;
	enum nvme_print_flags flags;
	struct nvme_dev *dev;
	int err;

	struct config {
		__u16	nvmset_id;
		char	*output_format;
	};

	struct config cfg = {
		.nvmset_id	= 0,
		.output_format	= "normal",
	};

	OPT_ARGS(opts) = {
		OPT_SHRT("nvmset_id",    'i', &cfg.nvmset_id,     nvmset_id),
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_dev;

	err = nvme_identify_nvmset_list(dev_fd(dev), cfg.nvmset_id, &nvmset);
	if (!err)
		nvme_show_id_nvmset(&nvmset, cfg.nvmset_id, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		fprintf(stderr, "identify nvm set list: %s\n", nvme_strerror(errno));

close_dev:
	dev_close(dev);
ret:
	return err;
}

static int id_uuid(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Send an Identify UUID List command to the "\
		"given device, returns list of supported Vendor Specific UUIDs "\
		"in either human-readable or binary format.";
	const char *raw = "show uuid in binary format";
	const char *human_readable = "show uuid in readable format";

	struct nvme_id_uuid_list uuid_list;
	enum nvme_print_flags flags;
	struct nvme_dev *dev;
	int err;

	struct config {
		char	*output_format;
		bool	raw_binary;
		bool	human_readable;
	};

	struct config cfg = {
		.output_format	= "normal",
		.raw_binary	= false,
		.human_readable	= false,
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format",   'o', &cfg.output_format,  output_format),
		OPT_FLAG("raw-binary",     'b', &cfg.raw_binary,     raw),
		OPT_FLAG("human-readable", 'H', &cfg.human_readable, human_readable),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_dev;
	if (cfg.raw_binary)
		flags = BINARY;
	if (cfg.human_readable)
		flags |= VERBOSE;

	err = nvme_identify_uuid(dev_fd(dev), &uuid_list);
	if (!err)
		nvme_show_id_uuid_list(&uuid_list, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		fprintf(stderr, "identify UUID list: %s\n", nvme_strerror(errno));
close_dev:
	dev_close(dev);
ret:
	return err;;
}

static int id_iocs(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Send an Identify Command Set Data command to the "\
		"given device, returns properties of the specified controller "\
		"in either human-readable or binary format.";
	const char *controller_id = "identifier of desired controller";
	struct nvme_id_iocs iocs;
	struct nvme_dev *dev;
	int err;

	struct config {
		__u16	cntid;
	};

	struct config cfg = {
		.cntid	= 0xffff,
	};

	OPT_ARGS(opts) = {
		OPT_SHRT("controller-id", 'c', &cfg.cntid, controller_id),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	err = nvme_identify_iocs(dev_fd(dev), cfg.cntid, &iocs);
	if (!err) {
		printf("NVMe Identify I/O Command Set:\n");
		nvme_show_id_iocs(&iocs);
	} else if (err > 0)
		nvme_show_status(err);
	else
		fprintf(stderr, "NVMe Identify I/O Command Set: %s\n", nvme_strerror(errno));

	dev_close(dev);
ret:
	return err;
}

static int id_domain(int argc, char **argv, struct command *cmd, struct plugin *plugin) {
	const char *desc = "Send an Identify Domain List command to the "\
		"given device, returns properties of the specified domain "\
		"in either normal|json|binary format.";
	const char *domain_id = "identifier of desired domain";
	struct nvme_id_domain_list id_domain;
	enum nvme_print_flags flags;
	struct nvme_dev *dev;
	int err;

	struct config {
		__u16	dom_id;
		char	*output_format;
	};

	struct config cfg = {
		.dom_id		= 0xffff,
		.output_format	= "normal",
	};

	OPT_ARGS(opts) = {
		OPT_SHRT("dom-id",         'd', &cfg.dom_id,         domain_id),
		OPT_FMT("output-format",   'o', &cfg.output_format,  output_format),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_dev;

	err = nvme_identify_domain_list(dev_fd(dev), cfg.dom_id, &id_domain);
	if (!err) {
		printf("NVMe Identify command for Domain List is successful:\n");
		printf("NVMe Identify Domain List:\n");
		nvme_show_id_domain_list(&id_domain, flags);
	} else if (err > 0)
		nvme_show_status(err);
	else
		fprintf(stderr, "NVMe Identify Domain List: %s\n", nvme_strerror(errno));

close_dev:
	dev_close(dev);
ret:
	return err;
}

static int get_ns_id(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Get namespace ID of a the block device.";
	struct nvme_dev *dev;
	unsigned int nsid;
	int err = 0;

	OPT_ARGS(opts) = {
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	err = nvme_get_nsid(dev_fd(dev), &nsid);
	if (err < 0) {
		fprintf(stderr, "get namespace ID: %s\n", nvme_strerror(errno));
		err = errno;
		goto close_fd;
	}
	err = 0;
	printf("%s: namespace-id:%d\n", dev->name, nsid);

close_fd:
	dev_close(dev);
ret:
	return err;
}

static int virtual_mgmt(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc  = "The Virtualization Management command is supported by primary controllers "\
		"that support the Virtualization Enhancements capability. This command is used for:\n"\
		"  1. Modifying Flexible Resource allocation for the primary controller\n"\
		"  2. Assigning Flexible Resources for secondary controllers\n"\
		"  3. Setting the Online and Offline state for secondary controllers";
	const char *cntlid = "Controller Identifier(CNTLID)";
	const char *rt = "Resource Type(RT): [0,1]\n"\
		"0h: VQ Resources\n"\
		"1h: VI Resources";
	const char *act = "Action(ACT): [1,7,8,9]\n"\
		"1h: Primary Flexible\n"\
		"7h: Secondary Offline\n"\
		"8h: Secondary Assign\n"\
		"9h: Secondary Online";
	const char *nr = "Number of Controller Resources(NR)";
	struct nvme_dev *dev;
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

	OPT_ARGS(opts) = {
		OPT_UINT("cntlid", 'c', &cfg.cntlid, cntlid),
		OPT_BYTE("rt",     'r', &cfg.rt,     rt),
		OPT_BYTE("act",    'a', &cfg.act,    act),
		OPT_SHRT("nr",     'n', &cfg.nr,     nr),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

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
	if (!err) {
		printf("success, Number of Controller Resources Modified "\
			"(NRM):%#x\n", result);
	} else if (err > 0) {
		nvme_show_status(err);
	} else
		fprintf(stderr, "virt-mgmt: %s\n", nvme_strerror(errno));

	dev_close(dev);
ret:
	return err;
}

static int primary_ctrl_caps(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *cntlid = "Controller ID";
	const char *desc = "Send an Identify Primary Controller Capabilities "\
		"command to the given device and report the information in a "\
		"decoded format (default), json or binary.";
	struct nvme_primary_ctrl_cap caps;
	enum nvme_print_flags flags;
	struct nvme_dev *dev;
	int err;

	struct config {
		__u16	cntlid;
		char	*output_format;
		bool	human_readable;
	};

	struct config cfg = {
		.cntlid		= 0,
		.output_format	= "normal",
		.human_readable	= false,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("cntlid",         'c', &cfg.cntlid, cntlid),
		OPT_FMT("output-format",   'o', &cfg.output_format,  output_format),
		OPT_FLAG("human-readable", 'H', &cfg.human_readable, human_readable_info),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_dev;
	if (cfg.human_readable)
		flags |= VERBOSE;

	err = nvme_cli_identify_primary_ctrl(dev, cfg.cntlid, &caps);
	if (!err)
		nvme_show_primary_ctrl_cap(&caps, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		fprintf(stderr, "identify primary controller capabilities: %s\n", nvme_strerror(errno));
close_dev:
	dev_close(dev);
ret:
	return err;
}

static int list_secondary_ctrl(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Show secondary controller list associated with the primary controller "\
		"of the given device.";
	const char *controller = "lowest controller identifier to display";
	const char *num_entries = "number of entries to retrieve";

	struct nvme_secondary_ctrl_list *sc_list;
	enum nvme_print_flags flags;
	struct nvme_dev *dev;
	int err;

	struct config {
		__u16	cntid;
		__u32	namespace_id;
		__u32	num_entries;
		char	*output_format;
	};

	struct config cfg = {
		.cntid		= 0,
		.namespace_id	= 0,
		.num_entries	= ARRAY_SIZE(sc_list->sc_entry),
		.output_format	= "normal",
	};

	OPT_ARGS(opts) = {
		OPT_SHRT("cntid",        'c', &cfg.cntid,         controller),
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id,  namespace_id_optional),
		OPT_UINT("num-entries",  'e', &cfg.num_entries,   num_entries),
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_err;

	if (!cfg.num_entries) {
		fprintf(stderr, "non-zero num-entries is required param\n");
		err = -EINVAL;
		goto close_err;
	}

	if (posix_memalign((void *)&sc_list, getpagesize(), sizeof(*sc_list))) {
		fprintf(stderr, "can not allocate controller list payload\n");
		err = -ENOMEM;
		goto close_err;
	}

	err = nvme_cli_identify_secondary_ctrl_list(dev, cfg.namespace_id,
						    cfg.cntid, sc_list);
	if (!err)
		nvme_show_list_secondary_ctrl(sc_list, cfg.num_entries, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		fprintf(stderr, "id secondary controller list: %s\n", nvme_strerror(errno));

	free(sc_list);

close_err:
	dev_close(dev);
ret:
	return err;
}

static int device_self_test(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc  = "Implementing the device self-test feature"\
		" which provides the necessary log to determine the state of the device";
	const char *namespace_id = "Indicate the namespace in which the device self-test"\
		" has to be carried out";
	const char * self_test_code = "This field specifies the action taken by the device self-test command : "\
		"\n1h Start a short device self-test operation\n"\
		"2h Start a extended device self-test operation\n"\
		"eh Start a vendor specific device self-test operation\n"\
		"fh abort the device self-test operation\n";
	struct nvme_dev *dev;
	int err;

	struct config {
		__u32	namespace_id;
		__u8	stc;
	};

	struct config cfg = {
		.namespace_id	= NVME_NSID_ALL,
		.stc		= 0,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id",   'n', &cfg.namespace_id, namespace_id),
		OPT_BYTE("self-test-code", 's', &cfg.stc,          self_test_code),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

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
		if (cfg.stc == 0xf)
			printf("Aborting device self-test operation\n");
		else if (cfg.stc == 0x2)
			printf("Extended Device self-test started\n");
		else if (cfg.stc == 0x1)
			printf("Short Device self-test started\n");
	} else if (err > 0) {
		nvme_show_status(err);
	} else
		fprintf(stderr, "Device self-test: %s\n", nvme_strerror(errno));

	dev_close(dev);
ret:
	return err;
}

static int self_test_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Retrieve the self-test log for the given device and given test "\
			"(or optionally a namespace) in either decoded format "\
			"(default) or binary.";
	const char *dst_entries = "Indicate how many DST log entries to be retrieved, "\
			"by default all the 20 entries will be retrieved";

	struct nvme_self_test_log log;
	enum nvme_print_flags flags;
	struct nvme_dev *dev;
	int err;

	struct config {
		__u8	dst_entries;
		char	*output_format;
		bool	verbose;
	};

	struct config cfg = {
		.dst_entries	= NVME_LOG_ST_MAX_RESULTS,
		.output_format	= "normal",
		.verbose	= false,
	};

	OPT_ARGS(opts) = {
		OPT_BYTE("dst-entries",  'e', &cfg.dst_entries,   dst_entries),
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_FLAG("verbose",      'v', &cfg.verbose,       verbose),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_dev;
	if (cfg.verbose)
		flags |= VERBOSE;

	err = nvme_cli_get_log_device_self_test(dev, &log);
	if (!err)
		nvme_show_self_test_log(&log, cfg.dst_entries, 0,
					dev->name, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		fprintf(stderr, "self test log: %s\n", nvme_strerror(errno));
close_dev:
	dev_close(dev);
ret:
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

	if (cfg->sel == 3)
		cfg->data_len = 0;

	if (cfg->data_len) {
		if (posix_memalign(buf, getpagesize(), cfg->data_len)) {
			return -1;
		}
		memset(*buf, 0, cfg->data_len);
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

static void get_feature_id_print(struct feat_cfg cfg, int err, __u32 result,
				 void *buf)
{
	if (!err) {
		if (!cfg.raw_binary || !buf) {
			printf("get-feature:%#0*x (%s), %s value:%#0*x\n",
			       cfg.feature_id ? 4 : 2, cfg.feature_id,
			       nvme_feature_to_string(cfg.feature_id),
			       nvme_select_to_string(cfg.sel), result ? 10 : 8,
			       result);
			if (cfg.sel == 3)
				nvme_show_select_result(result);
			else if (cfg.human_readable)
				nvme_feature_show_fields(cfg.feature_id, result,
							 buf);
			else if (buf)
				d(buf, cfg.data_len, 16, 1);
		} else if (buf) {
			d_raw(buf, cfg.data_len);
		}
	} else if (err > 0) {
		if (!nvme_status_equals(err, NVME_STATUS_TYPE_NVME,
					NVME_SC_INVALID_FIELD))
			nvme_show_status(err);
	} else {
		fprintf(stderr, "get-feature: %s\n", nvme_strerror(errno));
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

	if (cfg.sel == 8)
		changed = true;

	if (cfg.feature_id)
		feat_max = cfg.feature_id + 1;

	for (i = cfg.feature_id; i < feat_max; i++, feat_num++) {
		cfg.feature_id = i;
		err = get_feature_id_changed(dev, cfg, changed);
		if (err && !nvme_status_equals(err, NVME_STATUS_TYPE_NVME,
					       NVME_SC_INVALID_FIELD))
			break;
	}

	if (feat_num == 1 && nvme_status_equals(err, NVME_STATUS_TYPE_NVME,
						NVME_SC_INVALID_FIELD))
		nvme_show_status(err);

	return err;
}

static int get_feature(int argc, char **argv, struct command *cmd,
		       struct plugin *plugin)
{
	const char *desc = "Read operating parameters of the "\
		"specified controller. Operating parameters are grouped "\
		"and identified by Feature Identifiers; each Feature "\
		"Identifier contains one or more attributes that may affect "\
		"behavior of the feature. Each Feature has three possible "\
		"settings: default, saveable, and current. If a Feature is "\
		"saveable, it may be modified by set-feature. Default values "\
		"are vendor-specific and not changeable. Use set-feature to "\
		"change saveable Features.";
	const char *raw = "show feature in binary format";
	const char *feature_id = "feature identifier";
	const char *sel = "[0-3,8]: current/default/saved/supported/changed";
	const char *cdw11 = "dword 11 for interrupt vector config";
	const char *human_readable = "show feature in readable format";
	struct nvme_dev *dev;
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

	OPT_ARGS(opts) = {
		OPT_BYTE("feature-id",    'f', &cfg.feature_id,     feature_id),
		OPT_UINT("namespace-id",  'n', &cfg.namespace_id,   namespace_id_desired),
		OPT_BYTE("sel",           's', &cfg.sel,            sel),
		OPT_UINT("data-len",      'l', &cfg.data_len,       buf_len),
		OPT_FLAG("raw-binary",    'b', &cfg.raw_binary,     raw),
		OPT_UINT("cdw11",         'c', &cfg.cdw11,          cdw11),
		OPT_BYTE("uuid-index",    'U', &cfg.uuid_index,     uuid_index_specify),
		OPT_FLAG("human-readable",'H', &cfg.human_readable, human_readable),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	if (!cfg.namespace_id) {
		err = nvme_get_nsid(dev_fd(dev), &cfg.namespace_id);
		if (err < 0) {
			if (errno != ENOTTY) {
				fprintf(stderr, "get-namespace-id: %s\n", nvme_strerror(errno));
				goto close_dev;
			}
			cfg.namespace_id = NVME_NSID_ALL;
		}
	}

	if (cfg.sel > 8) {
		fprintf(stderr, "invalid 'select' param:%d\n", cfg.sel);
		err = -EINVAL;
		goto close_dev;
	}

	if (cfg.uuid_index > 128) {
		fprintf(stderr, "invalid uuid index param: %u\n", cfg.uuid_index);
		err = -1;
		goto close_dev;
	}

	err = get_feature_ids(dev, cfg);

close_dev:
	dev_close(dev);

ret:
	return err;
}

/* Transfers one chunk of firmware to the device, and decodes & reports any
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

		/* don't retry if the NVMe-type error indicates Do Not Resend.
		 */
		retryable = !((err > 0) &&
			(nvme_status_get_type(err) == NVME_STATUS_TYPE_NVME) &&
			(nvme_status_get_value(err) & NVME_SC_DNR));

		/* detect overwrite errors, which are handled differently
		 * depending on ignore_ovr */
		ovr = (err > 0) &&
			(nvme_status_get_type(err) == NVME_STATUS_TYPE_NVME) &&
			(NVME_GET(err, SCT) == NVME_SCT_CMD_SPECIFIC) &&
			(NVME_GET(err, SC) == NVME_SC_OVERLAPPING_RANGE);

		if (ovr && ignore_ovr)
			return 0;

		/* if we're printing progress, we'll need a newline to separate
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
				/* non-ignored ovr error: print a little extra info
				 * about recovering */
				fprintf(stderr,
					"Use --ignore-ovr to ignore overwrite errors\n");

				/* We'll just be attempting more overwrites if
				 * we retry. DNR will likely be set, but force
				 * an exit anyway. */
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
	const char *desc = "Copy all or part of a firmware image to "\
		"a controller for future update. Optionally, specify how "\
		"many KiB of the firmware to transfer at once. The offset will "\
		"start at 0 and automatically adjust based on xfer size "\
		"unless fw is split across multiple files. May be submitted "\
		"while outstanding commands exist on the Admin and IO "\
		"Submission Queues. Activate downloaded firmware with "\
		"fw-activate, and then reset the device to apply the downloaded firmware.";
	const char *fw = "firmware file (required)";
	const char *xfer = "transfer chunksize limit";
	const char *offset = "starting dword offset, default 0";
	const char *progress = "display firmware transfer progress";
	const char *ignore_ovr = "ignore overwrite errors";
	unsigned int fw_size;
	struct nvme_dev *dev;
	int err, fw_fd = -1;
	struct stat sb;
	void *fw_buf;
	bool huge;

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

	OPT_ARGS(opts) = {
		OPT_FILE("fw",         'f', &cfg.fw,         fw),
		OPT_UINT("xfer",       'x', &cfg.xfer,       xfer),
		OPT_UINT("offset",     'o', &cfg.offset,     offset),
		OPT_FLAG("progress",   'p', &cfg.progress,   progress),
		OPT_FLAG("ignore-ovr", 'i', &cfg.ignore_ovr, ignore_ovr),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	fw_fd = open(cfg.fw, O_RDONLY);
	cfg.offset <<= 2;
	if (fw_fd < 0) {
		fprintf(stderr, "Failed to open firmware file %s: %s\n",
				cfg.fw, strerror(errno));
		err = -EINVAL;
		goto close_dev;
	}

	err = fstat(fw_fd, &sb);
	if (err < 0) {
		perror("fstat");
		goto close_fw_fd;
	}

	fw_size = sb.st_size;
	if ((fw_size & 0x3) || (fw_size == 0)) {
		fprintf(stderr, "Invalid size:%d for f/w image\n", fw_size);
		err = -EINVAL;
		goto close_fw_fd;
	}

	if (cfg.xfer == 0 || cfg.xfer % 4096)
		cfg.xfer = 4096;

	if (cfg.xfer < HUGE_MIN)
		fw_buf = __nvme_alloc(fw_size, &huge);
	else
		fw_buf = nvme_alloc(fw_size, &huge);

	if (!fw_buf) {
		err = -ENOMEM;
		goto close_fw_fd;
	}

	if (read(fw_fd, fw_buf, fw_size) != ((ssize_t)(fw_size))) {
		err = -errno;
		fprintf(stderr, "read :%s :%s\n", cfg.fw, strerror(errno));
		goto free;
	}

	while (cfg.offset < fw_size) {
		cfg.xfer = min(cfg.xfer, fw_size);

		err = fw_download_single(dev, fw_buf + cfg.offset, fw_size,
					 cfg.offset, cfg.xfer, cfg.progress,
					 cfg.ignore_ovr);
		if (err)
			break;

		cfg.offset += cfg.xfer;
	}

	if (!err) {
		/* end the progress output */
		if (cfg.progress)
			printf("\n");
		printf("Firmware download success\n");
	}

free:
	nvme_free(fw_buf, huge);
close_fw_fd:
	close(fw_fd);
close_dev:
	dev_close(dev);
ret:
	return err;
}

static char *nvme_fw_status_reset_type(__u16 status)
{
	switch (status & 0x7ff) {
	case NVME_SC_FW_NEEDS_CONV_RESET:	return "conventional";
	case NVME_SC_FW_NEEDS_SUBSYS_RESET:	return "subsystem";
	case NVME_SC_FW_NEEDS_RESET:		return "any controller";
	default:				return "unknown";
	}
}

static int fw_commit(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Verify downloaded firmware image and "\
		"commit to specific firmware slot. Device is not automatically "\
		"reset following firmware activation. A reset may be issued "\
		"with an 'echo 1 > /sys/class/nvme/nvmeX/reset_controller'. "\
		"Ensure nvmeX is the device you just activated before reset.";
	const char *slot = "[0-7]: firmware slot for commit action";
	const char *action = "[0-7]: commit action";
	const char *bpid = "[0,1]: boot partition identifier, if applicable (default: 0)";
	struct nvme_dev *dev;
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

	OPT_ARGS(opts) = {
		OPT_BYTE("slot",   's', &cfg.slot,   slot),
		OPT_BYTE("action", 'a', &cfg.action, action),
		OPT_BYTE("bpid",   'b', &cfg.bpid,   bpid),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	if (cfg.slot > 7) {
		fprintf(stderr, "invalid slot:%d\n", cfg.slot);
		err = -EINVAL;
		goto close_dev;
	}
	if (cfg.action > 7 || cfg.action == 4 || cfg.action == 5) {
		fprintf(stderr, "invalid action:%d\n", cfg.action);
		err = -EINVAL;
		goto close_dev;
	}
	if (cfg.bpid > 1) {
		fprintf(stderr, "invalid boot partition id:%d\n", cfg.bpid);
		err = -EINVAL;
		goto close_dev;
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

	if (err < 0)
		fprintf(stderr, "fw-commit: %s\n", nvme_strerror(errno));
	else if (err != 0) {
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
	}

	if (err >= 0) {
		printf("Multiple Update Detected (MUD) Value: %u\n", result);
		if (result & 0x1)
			printf("Detected an overlapping firmware/boot partition image update command "\
				"sequence due to processing a command from a Management Endpoint");
		if ((result >> 1) & 0x1)
			printf("Detected an overlapping firmware/boot partition image update command "\
				"sequence due to processing a command from an Admin SQ on a controller");
	}

close_dev:
	dev_close(dev);
ret:
	return err;
}

static int subsystem_reset(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Resets the NVMe subsystem\n";
	struct nvme_dev *dev;
	int err;

	OPT_ARGS(opts) = {
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	err = nvme_subsystem_reset(dev_fd(dev));
	if (err < 0) {
		if (errno == ENOTTY)
			fprintf(stderr,
				"Subsystem-reset: NVM Subsystem Reset not supported.\n");
		else
			fprintf(stderr, "Subsystem-reset: %s\n", nvme_strerror(errno));
	}

	dev_close(dev);
ret:
	return err;
}

static int reset(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Resets the NVMe controller\n";
	struct nvme_dev *dev;
	int err;

	OPT_ARGS(opts) = {
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	err = nvme_ctrl_reset(dev_fd(dev));
	if (err < 0)
		fprintf(stderr, "Reset: %s\n", nvme_strerror(errno));

	dev_close(dev);
ret:
	return err;
}

static int ns_rescan(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Rescans the NVMe namespaces\n";
	struct nvme_dev *dev;
	int err;

	OPT_ARGS(opts) = {
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	err = nvme_ns_rescan(dev_fd(dev));
	if (err < 0)
		fprintf(stderr, "Namespace Rescan");

	dev_close(dev);
ret:
	return err;
}

static int parse_sanact(char *str, __u8 *val)
{
	int len = strlen(str);

	if (!strncasecmp(str, "exit-failure", len > 1 ? len : 1))
		*val = NVME_SANITIZE_SANACT_EXIT_FAILURE;

	if (!strncasecmp(str, "start-block-erase", len > 7 ? len : 7))
		*val = NVME_SANITIZE_SANACT_START_BLOCK_ERASE;

	if (!strncasecmp(str, "start-overwrite", len > 7 ? len : 7))
		*val = NVME_SANITIZE_SANACT_START_OVERWRITE;

	if (!strncasecmp(str, "start-crypto-erase", len > 7 ? len : 7))
		*val = NVME_SANITIZE_SANACT_START_CRYPTO_ERASE;

	if (*val)
		return 0;

	return argconfig_parse_byte("sanact", str, val);
}

static int sanitize(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Send a sanitize command.";
	const char *no_dealloc_desc = "No deallocate after sanitize.";
	const char *oipbp_desc = "Overwrite invert pattern between passes.";
	const char *owpass_desc = "Overwrite pass count.";
	const char *ause_desc = "Allow unrestricted sanitize exit.";
	const char *sanact_desc = "Sanitize action: 1 = Exit failure mode, 2 = Start block erase, 3 = Start overwrite, 4 = Start crypto erase";
	const char *ovrpat_desc = "Overwrite pattern.";
	struct nvme_dev *dev;
	int err;
	__u8 sanact = 0;

	struct config {
		bool	no_dealloc;
		bool	oipbp;
		__u8	owpass;
		bool	ause;
		char	*sanact;
		__u32	ovrpat;
	};

	struct config cfg = {
		.no_dealloc	= false,
		.oipbp		= false,
		.owpass		= 0,
		.ause		= false,
		.sanact		= NULL,
		.ovrpat		= 0,
	};

	OPT_ARGS(opts) = {
		OPT_FLAG("no-dealloc", 'd', &cfg.no_dealloc, no_dealloc_desc),
		OPT_FLAG("oipbp",      'i', &cfg.oipbp,      oipbp_desc),
		OPT_BYTE("owpass",     'n', &cfg.owpass,     owpass_desc),
		OPT_FLAG("ause",       'u', &cfg.ause,       ause_desc),
		OPT_STR("sanact",      'a', &cfg.sanact,     sanact_desc),
		OPT_UINT("ovrpat",     'p', &cfg.ovrpat,     ovrpat_desc),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	if (cfg.sanact) {
		err = parse_sanact(cfg.sanact, &sanact);
		if (err)
			goto close_dev;
	}

	switch (sanact) {
	case NVME_SANITIZE_SANACT_EXIT_FAILURE:
	case NVME_SANITIZE_SANACT_START_BLOCK_ERASE:
	case NVME_SANITIZE_SANACT_START_OVERWRITE:
	case NVME_SANITIZE_SANACT_START_CRYPTO_ERASE:
		break;
	default:
		fprintf(stderr, "Invalid Sanitize Action\n");
		err = -EINVAL;
		goto close_dev;
	}

	if (sanact == NVME_SANITIZE_SANACT_EXIT_FAILURE) {
		if (cfg.ause || cfg.no_dealloc) {
			fprintf(stderr, "SANACT is Exit Failure Mode\n");
			err = -EINVAL;
			goto close_dev;
		}
	}

	if (sanact == NVME_SANITIZE_SANACT_START_OVERWRITE) {
		if (cfg.owpass > 16) {
			fprintf(stderr, "OWPASS out of range [0-16]\n");
			err = -EINVAL;
			goto close_dev;
		}
	} else {
		if (cfg.owpass || cfg.oipbp || cfg.ovrpat) {
			fprintf(stderr, "SANACT is not Overwrite\n");
			err = -EINVAL;
			goto close_dev;
		}
	}

	struct nvme_sanitize_nvm_args args = {
		.args_size	= sizeof(args),
		.sanact		= sanact,
		.ause		= cfg.ause,
		.owpass		= cfg.owpass,
		.oipbp		= cfg.oipbp,
		.nodas		= cfg.no_dealloc,
		.ovrpat		= cfg.ovrpat,
		.result		= NULL,
	};
	err = nvme_cli_sanitize_nvm(dev, &args);
	if (err < 0)
		fprintf(stderr, "sanitize: %s\n", nvme_strerror(errno));
	else if (err > 0)
		nvme_show_status(err);

close_dev:
	dev_close(dev);
ret:
	return err;
}

static int nvme_get_properties(int fd, void **pbar)
{
	int offset, err, size = getpagesize();
	__u64 value;

	*pbar = malloc(size);
	if (!*pbar) {
		fprintf(stderr, "malloc: %s\n", strerror(errno));
		return -1;
	}

	memset(*pbar, 0xff, size);
	for (offset = NVME_REG_CAP; offset <= NVME_REG_CMBSZ;) {
		struct nvme_get_property_args args = {
			.args_size	= sizeof(args),
			.fd		= fd,
			.offset		= offset,
			.value		= &value,
			.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
		};

		err = nvme_get_property(&args);
		if (nvme_status_equals(err, NVME_STATUS_TYPE_NVME,
				       NVME_SC_INVALID_FIELD)) {
			err = 0;
			value = -1;
		} else if (err) {
			fprintf(stderr, "get-property: %s\n",
				nvme_strerror(errno));
			free(*pbar);
			break;
		}
		if (nvme_is_64bit_reg(offset)) {
			*(uint64_t *)(*pbar + offset) = value;
			offset += 8;
		} else {
			*(uint32_t *)(*pbar + offset) = value;
			offset += 4;
		}
	}

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
			fprintf(stderr, "Unable to find %s\n", dev->name);
			return NULL;
		}
		snprintf(path, sizeof(path), "%s/device/device/resource0",
			nvme_ns_get_sysfs_dir(n));
		nvme_free_ns(n);
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		if (map_log_level(0, false) >= LOG_DEBUG)
			fprintf(stderr,
				"%s did not find a pci resource, open failed %s\n",
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
	const char *desc = "Reads and shows the defined NVMe controller registers "\
					"in binary or human-readable format";
	const char *human_readable = "show info in readable format in case of "\
					"output_format == normal";

	enum nvme_print_flags flags;
	struct nvme_dev *dev;
	bool fabrics = false;
	nvme_root_t r;
	void *bar;
	int err;

	struct config {
		char	*output_format;
		bool	human_readable;
	};

	struct config cfg = {
		.output_format	= "normal",
		.human_readable	= false,
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format",  'o', &cfg.output_format,  output_format),
		OPT_FLAG("human-readable",'H', &cfg.human_readable, human_readable),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	r = nvme_scan(NULL);
	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_dev;
	if (cfg.human_readable)
		flags |= VERBOSE;
	bar = mmap_registers(r, dev);
	if (!bar) {
		err = nvme_get_properties(dev_fd(dev), &bar);
		if (!bar)
			goto close_dev;
		fabrics = true;
	}

	nvme_show_ctrl_registers(bar, fabrics, flags);
	if (fabrics)
		free(bar);
	else
		munmap(bar, getpagesize());
close_dev:
	dev_close(dev);
	nvme_free_tree(r);
ret:
	return err;
}

static int get_property(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Reads and shows the defined NVMe controller property "\
			   "for NVMe over Fabric. Property offset must be one of:\n"
			   "CAP=0x0, VS=0x8, CC=0x14, CSTS=0x1c, NSSR=0x20";
	const char *offset = "offset of the requested property";
	const char *human_readable = "show property in readable format";

	struct nvme_dev *dev;
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

	OPT_ARGS(opts) = {
		OPT_UINT("offset",        'o', &cfg.offset,         offset),
		OPT_FLAG("human-readable",'H', &cfg.human_readable, human_readable),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	if (cfg.offset == -1) {
		fprintf(stderr, "offset required param\n");
		err = -EINVAL;
		goto close_dev;
	}

	struct nvme_get_property_args args = {
		.args_size	= sizeof(args),
		.fd		= dev_fd(dev),
		.offset		= cfg.offset,
		.value		= &value,
		.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
	};
	err = nvme_get_property(&args);
	if (err < 0) {
		fprintf(stderr, "get-property: %s\n", nvme_strerror(errno));
	} else if (!err) {
		nvme_show_single_property(cfg.offset, value, cfg.human_readable);
	} else if (err > 0) {
		nvme_show_status(err);
	}

close_dev:
	dev_close(dev);
ret:
	return err;
}

static int set_property(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Writes and shows the defined NVMe controller property "\
			   "for NVMe over Fabric";
	const char *offset = "the offset of the property";
	const char *value = "the value of the property to be set";
	struct nvme_dev *dev;
	int err;

	struct config {
		int	offset;
		int	value;
	};

	struct config cfg = {
		.offset	= -1,
		.value	= -1,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("offset", 'o', &cfg.offset, offset),
		OPT_UINT("value",  'v', &cfg.value,  value),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	if (cfg.offset == -1) {
		fprintf(stderr, "offset required param\n");
		err = -EINVAL;
		goto close_dev;
	}
	if (cfg.value == -1) {
		fprintf(stderr, "value required param\n");
		err = -EINVAL;
		goto close_dev;
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
	if (err < 0) {
		fprintf(stderr, "set-property: %s\n", nvme_strerror(errno));
	} else if (!err) {
		printf("set-property: %02x (%s), value: %#08x\n", cfg.offset,
				nvme_register_to_string(cfg.offset), cfg.value);
	} else if (err > 0) {
		nvme_show_status(err);
	}

close_dev:
	dev_close(dev);
ret:
	return err;
}

static int format(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Re-format a specified namespace on the "\
		"given device. Can erase all data in namespace (user "\
		"data erase) or delete data encryption key if specified. "\
		"Can also be used to change LBAF to change the namespaces reported physical block format.";
	const char *lbaf = "LBA format to apply (required)";
	const char *ses = "[0-2]: secure erase";
	const char *pil = "[0-1]: protection info location last/first 8 bytes of metadata";
	const char *pi = "[0-3]: protection info off/Type 1/Type 2/Type 3";
	const char *ms = "[0-1]: extended format off/on";
	const char *reset = "Automatically reset the controller after successful format";
	const char *bs = "target block size";
	const char *force = "The \"I know what I'm doing\" flag, skip confirmation before sending command";
	struct nvme_id_ns ns;
	struct nvme_id_ctrl ctrl;
	struct nvme_dev *dev;
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

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id_desired),
		OPT_UINT("timeout",      't', &cfg.timeout,      timeout),
		OPT_BYTE("lbaf",         'l', &cfg.lbaf,         lbaf),
		OPT_BYTE("ses",          's', &cfg.ses,          ses),
		OPT_BYTE("pi",           'i', &cfg.pi,           pi),
		OPT_BYTE("pil",          'p', &cfg.pil,          pil),
		OPT_BYTE("ms",           'm', &cfg.ms,           ms),
		OPT_FLAG("reset",        'r', &cfg.reset,        reset),
		OPT_FLAG("force",          0, &cfg.force,        force),
		OPT_SUFFIX("block-size", 'b', &cfg.bs,           bs),
		OPT_END()
	};

	err = argconfig_parse(argc, argv, desc, opts);
	if (err)
		goto ret;

	err = open_exclusive(&dev, argc, argv, cfg.force);
	if (err) {
		if (errno == EBUSY) {
			fprintf(stderr, "Failed to open %s.\n",
		                basename(argv[optind]));
			fprintf(stderr,
				"Namespace is currently busy.\n");
			if (!cfg.force)
				fprintf(stderr,
				"Use the force [--force] option to ignore that.\n");
		} else {
			argconfig_print_help(desc, opts);
		}
		goto ret;
	}

	if (cfg.lbaf != 0xff && cfg.bs !=0) {
		fprintf(stderr,
			"Invalid specification of both LBAF and Block Size, please specify only one\n");
		err = -EINVAL;
		goto close_dev;
	}
	if (cfg.bs) {
		if ((cfg.bs & (~cfg.bs + 1)) != cfg.bs) {
			fprintf(stderr,
				"Invalid value for block size (%"PRIu64"), must be a power of two\n",
				       (uint64_t) cfg.bs);
			err = -EINVAL;
			goto close_dev;
		}
	}

	err = nvme_cli_identify_ctrl(dev, &ctrl);
	if (err) {
		fprintf(stderr, "identify-ctrl: %s\n", nvme_strerror(errno));
		goto close_dev;
	}

	if ((ctrl.fna & 1) == 1) {
		/*
		 * FNA bit 0 set to 1: all namespaces ... shall be configured with the same
		 * attributes and a format (excluding secure erase) of any namespace results in a
		 * format of all namespaces.
		 */
		cfg.namespace_id = NVME_NSID_ALL;
	} else if (!cfg.namespace_id) {
		err = nvme_get_nsid(dev_fd(dev), &cfg.namespace_id);
		if (err < 0) {
			fprintf(stderr, "get-namespace-id: %s\n", nvme_strerror(errno));
			goto close_dev;
		}
	}

	if (cfg.namespace_id == 0) {
		fprintf(stderr,
			"Invalid namespace ID, "
			"specify a namespace to format or use '-n 0xffffffff' "
			"to format all namespaces on this controller.\n");
		err = -EINVAL;
		goto close_dev;
	}

	if (cfg.namespace_id != NVME_NSID_ALL) {
		err = nvme_cli_identify_ns(dev, cfg.namespace_id, &ns);
		if (err) {
			if (err < 0)
				fprintf(stderr, "identify-namespace: %s\n", nvme_strerror(errno));
			else {
				fprintf(stderr, "identify failed\n");
				nvme_show_status(err);
			}
			goto close_dev;
		}
		nvme_id_ns_flbas_to_lbaf_inuse(ns.flbas, &prev_lbaf);

		if (cfg.bs) {
			for (i = 0; i < ns.nlbaf; ++i) {
				if ((1ULL << ns.lbaf[i].ds) == cfg.bs &&
				    ns.lbaf[i].ms == 0) {
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
				err = -EINVAL;
				goto close_dev;
			}
		} else  if (cfg.lbaf == 0xff)
			cfg.lbaf = prev_lbaf;
	} else {
		if (cfg.lbaf == 0xff) cfg.lbaf = 0;
	}

	/* ses & pi checks set to 7 for forward-compatibility */
	if (cfg.ses > 7) {
		fprintf(stderr, "invalid secure erase settings:%d\n", cfg.ses);
		err = -EINVAL;
		goto close_dev;
	}
	if (cfg.lbaf > 63) {
		fprintf(stderr, "invalid lbaf:%d\n", cfg.lbaf);
		err = -EINVAL;
		goto close_dev;
	}
	if (cfg.pi > 7) {
		fprintf(stderr, "invalid pi:%d\n", cfg.pi);
		err = -EINVAL;
		goto close_dev;
	}
	if (cfg.pil > 1) {
		fprintf(stderr, "invalid pil:%d\n", cfg.pil);
		err = -EINVAL;
		goto close_dev;
	}
	if (cfg.ms > 1) {
		fprintf(stderr, "invalid ms:%d\n", cfg.ms);
		err = -EINVAL;
		goto close_dev;
	}

	if (!cfg.force) {
		fprintf(stderr, "You are about to format %s, namespace %#x%s.\n",
			dev->name, cfg.namespace_id,
			cfg.namespace_id == NVME_NSID_ALL ? "(ALL namespaces)" : "");
		nvme_show_relatives(dev->name);
		fprintf(stderr, "WARNING: Format may irrevocably delete this device's data.\n"
			"You have 10 seconds to press Ctrl-C to cancel this operation.\n\n"
			"Use the force [--force] option to suppress this warning.\n");
		sleep(10);
		fprintf(stderr, "Sending format operation ... \n");
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
	if (err < 0)
		fprintf(stderr, "format: %s\n", nvme_strerror(errno));
	else if (err != 0)
		nvme_show_status(err);
	else {
		printf("Success formatting namespace:%x\n", cfg.namespace_id);
		if (dev->type == NVME_DEV_DIRECT && cfg.lbaf != prev_lbaf){
			if (is_chardev(dev)) {
				if (ioctl(dev_fd(dev), NVME_IOCTL_RESCAN) < 0) {
					fprintf(stderr, "failed to rescan namespaces\n");
					err = -errno;
					goto close_dev;
				}
			} else {
				block_size = 1 << ns.lbaf[cfg.lbaf].ds;

				/*
				 * If block size has been changed by the format
				 * command up there, we should notify it to
				 * kernel blkdev to update its own block size
				 * to the given one because blkdev will not
				 * update by itself without re-opening fd.
				 */
				if (ioctl(dev_fd(dev), BLKBSZSET, &block_size) < 0) {
					fprintf(stderr, "failed to set block size to %d\n",
							block_size);
					err = -errno;
					goto close_dev;
				}

				if (ioctl(dev_fd(dev), BLKRRPART) < 0) {
					fprintf(stderr, "failed to re-read partition table\n");
					err = -errno;
					goto close_dev;
				}
			}
		}
		if (dev->type == NVME_DEV_DIRECT && cfg.reset && is_chardev(dev))
			nvme_ctrl_reset(dev_fd(dev));
	}

close_dev:
	dev_close(dev);
ret:
	return err;
}

#define STRTOUL_AUTO_BASE              (0)
#define NVME_FEAT_TIMESTAMP_DATA_SIZE  (6)

static int set_feature(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Modify the saveable or changeable "\
		"current operating parameters of the controller. Operating "\
		"parameters are grouped and identified by Feature "\
		"Identifiers. Feature settings can be applied to the entire "\
		"controller and all associated namespaces, or to only a few "\
		"namespace(s) associated with the controller. Default values "\
		"for each Feature are vendor-specific and may not be modified."\
		"Use get-feature to determine which Features are supported by "\
		"the controller and are saveable/changeable.";
	const char *feature_id = "feature identifier (required)";
	const char *data = "optional file for feature data (default stdin)";
	const char *value = "new value of feature (required)";
	const char *cdw12 = "feature cdw12, if used";
	const char *save = "specifies that the controller shall save the attribute";
	struct nvme_dev *dev;
	int err;
	__u32 result;
	void *buf = NULL;
	int ffd = STDIN_FILENO;

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

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_desired),
		OPT_BYTE("feature-id",   'f', &cfg.feature_id,   feature_id),
		OPT_SUFFIX("value",      'v', &cfg.value,        value),
		OPT_UINT("cdw12",        'c', &cfg.cdw12,        cdw12),
		OPT_BYTE("uuid-index",   'U', &cfg.uuid_index,   uuid_index_specify),
		OPT_UINT("data-len",     'l', &cfg.data_len,     buf_len),
		OPT_FILE("data",         'd', &cfg.file,         data),
		OPT_FLAG("save",         's', &cfg.save,         save),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	if (!cfg.namespace_id) {
		err = nvme_get_nsid(dev_fd(dev), &cfg.namespace_id);
		if (err < 0) {
			if (errno != ENOTTY) {
				fprintf(stderr, "get-namespace-id: %s\n", nvme_strerror(errno));
				goto close_dev;
			}

			cfg.namespace_id = NVME_NSID_ALL;
		}
	}

	if (!cfg.feature_id) {
		fprintf(stderr, "feature-id required param\n");
		err = -EINVAL;
		goto close_dev;
	}

	if (cfg.uuid_index > 128) {
		fprintf(stderr, "invalid uuid index param: %u\n", cfg.uuid_index);
		err = -1;
		goto close_dev;
	}

	if (!cfg.data_len)
		nvme_cli_get_feature_length2(cfg.feature_id, cfg.value,
					     NVME_DATA_TFR_HOST_TO_CTRL,
					     &cfg.data_len);

	if (cfg.data_len) {
		if (posix_memalign(&buf, getpagesize(), cfg.data_len)) {
			fprintf(stderr, "can not allocate feature payload\n");
			err = -ENOMEM;
			goto close_dev;
		}
		memset(buf, 0, cfg.data_len);
	}

	if (buf) {
		/*
		 * Use the '-v' value for the timestamp feature if provided as
		 * a convenience since it can often fit in 4-bytes. The user
		 * should use the buffer method if the value exceeds this
		 * length.
		 */
		if (NVME_FEAT_FID_TIMESTAMP == cfg.feature_id && cfg.value) {
			memcpy(buf, &cfg.value, NVME_FEAT_TIMESTAMP_DATA_SIZE);
		} else {
			if (strlen(cfg.file)) {
				ffd = open(cfg.file, O_RDONLY);
				if (ffd <= 0) {
					fprintf(stderr, "Failed to open file %s: %s\n",
						cfg.file, strerror(errno));
					err = -EINVAL;
					goto free;
				}
			}

			err = read(ffd, (void *)buf, cfg.data_len);
			if (err < 0) {
				err = -errno;
				fprintf(stderr, "failed to read data buffer from input"
					" file: %s\n", strerror(errno));
				goto close_ffd;
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
		fprintf(stderr, "set-feature: %s\n", nvme_strerror(errno));
	} else if (!err) {
		printf("set-feature:%#0*x (%s), value:%#0*"PRIx64", cdw12:%#0*x, save:%#x\n",
		       cfg.feature_id ? 4 : 2, cfg.feature_id,
		       nvme_feature_to_string(cfg.feature_id),
		       cfg.value ? 10 : 8, (uint64_t)cfg.value,
		       cfg.cdw12 ? 10 : 8, cfg.cdw12, cfg.save);
		if (cfg.feature_id == NVME_FEAT_FID_LBA_STS_INTERVAL) {
			nvme_show_lba_status_info(result);
		}
		if (buf) {
			if (cfg.feature_id == NVME_FEAT_FID_LBA_RANGE)
				nvme_show_lba_range((struct nvme_lba_range_type *)buf,
								result);
			else
				d(buf, cfg.data_len, 16, 1);
		}
	} else if (err > 0)
		nvme_show_status(err);

close_ffd:
	if (ffd != STDIN_FILENO)
		close(ffd);
free:
	free(buf);
close_dev:
	dev_close(dev);
ret:
	return err;
}

static int sec_send(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	struct stat sb;
	const char *desc = "Transfer security protocol data to "\
		"a controller. Security Receives for the same protocol should be "\
		"performed after Security Sends. The security protocol field "\
		"associates Security Sends (security-send) and Security Receives "\
		"(security-recv).";
	const char *file = "transfer payload";
	const char *tl = "transfer length (cf. SPC-4)";
	int err, sec_fd = STDIN_FILENO;
	struct nvme_dev *dev;
	void *sec_buf;
	unsigned int sec_size;

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

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_desired),
		OPT_FILE("file",         'f', &cfg.file,         file),
		OPT_BYTE("nssf",         'N', &cfg.nssf,         nssf),
		OPT_BYTE("secp",         'p', &cfg.secp,         secp),
		OPT_SHRT("spsp",         's', &cfg.spsp,         spsp),
		OPT_UINT("tl",           't', &cfg.tl,           tl),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	if (cfg.tl == 0) {
		fprintf(stderr, "--tl unspecified or zero\n");
		err = -EINVAL;
		goto close_dev;
	}
	if ((cfg.tl & 3) != 0)
		fprintf(stderr, "WARNING: --tl not dword aligned; unaligned bytes may be truncated\n");

	if (strlen(cfg.file) == 0) {
		sec_fd = STDIN_FILENO;
		sec_size = cfg.tl;
	} else {
		sec_fd = open(cfg.file, O_RDONLY);
		if (sec_fd < 0) {
			fprintf(stderr, "Failed to open %s: %s\n",
					cfg.file, strerror(errno));
			err = -EINVAL;
			goto close_dev;
		}

		err = fstat(sec_fd, &sb);
		if (err < 0) {
			perror("fstat");
			goto close_sec_fd;
		}

		sec_size = cfg.tl > sb.st_size ? cfg.tl : sb.st_size;
	}

	if (posix_memalign(&sec_buf, getpagesize(), cfg.tl)) {
		fprintf(stderr, "No memory for security size:%d\n", cfg.tl);
		err = -ENOMEM;
		goto close_sec_fd;
	}

	memset(sec_buf, 0, cfg.tl); // ensure zero fill if buf_size > sec_size

	err = read(sec_fd, sec_buf, sec_size);
	if (err < 0) {
		err = -errno;
		fprintf(stderr, "Failed to read data from security file"
				" %s with %s\n", cfg.file, strerror(errno));
		goto free;
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
		fprintf(stderr, "security-send: %s\n", nvme_strerror(errno));
	else if (err != 0)
		nvme_show_status(err);
	else
		printf("NVME Security Send Command Success\n");

free:
	free(sec_buf);
close_sec_fd:
	close(sec_fd);
close_dev:
	dev_close(dev);
ret:
	return err;
}

static int dir_send(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Set directive parameters of the "\
			    "specified directive type.";
	const char *endir = "directive enable";
	const char *ttype = "target directive type to be enabled/disabled";
	const char *input = "write/send file (default stdin)";
	struct nvme_dev *dev;
	__u32 result;
	__u32 dw12 = 0;
	void *buf = NULL;
	int ffd = STDIN_FILENO;
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

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id",  'n', &cfg.namespace_id,   namespace_id_desired),
		OPT_UINT("data-len",      'l', &cfg.data_len,       buf_len),
		OPT_BYTE("dir-type",      'D', &cfg.dtype,          dtype),
		OPT_BYTE("target-dir",    'T', &cfg.ttype,          ttype),
		OPT_SHRT("dir-spec",      'S', &cfg.dspec,          dspec_w_dtype),
		OPT_BYTE("dir-oper",      'O', &cfg.doper,          doper),
		OPT_SHRT("endir",         'e', &cfg.endir,          endir),
		OPT_FLAG("human-readable",'H', &cfg.human_readable, human_readable_directive),
		OPT_FLAG("raw-binary",    'b', &cfg.raw_binary,     raw_directive),
		OPT_FILE("input-file",    'i', &cfg.file,	    input),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	switch (cfg.dtype) {
	case NVME_DIRECTIVE_DTYPE_IDENTIFY:
		switch (cfg.doper) {
		case NVME_DIRECTIVE_SEND_IDENTIFY_DOPER_ENDIR:
			if (!cfg.ttype) {
				fprintf(stderr, "target-dir required param\n");
				err = -EINVAL;
				goto close_dev;
			}
			dw12 = cfg.ttype << 8 | cfg.endir;
			break;
		default:
			fprintf(stderr, "invalid directive operations for Identify Directives\n");
			err = -EINVAL;
			goto close_dev;
		}
		break;
	case NVME_DIRECTIVE_DTYPE_STREAMS:
		switch (cfg.doper) {
		case NVME_DIRECTIVE_SEND_STREAMS_DOPER_RELEASE_IDENTIFIER:
		case NVME_DIRECTIVE_SEND_STREAMS_DOPER_RELEASE_RESOURCE:
			break;
		default:
			fprintf(stderr, "invalid directive operations for Streams Directives\n");
			err = -EINVAL;
			goto close_dev;
		}
		break;
	default:
		fprintf(stderr, "invalid directive type\n");
		err = -EINVAL;
		goto close_dev;
	}


	if (cfg.data_len) {
		if (posix_memalign(&buf, getpagesize(), cfg.data_len)) {
			err = -ENOMEM;
			goto close_dev;
		}
		memset(buf, 0, cfg.data_len);
	}

	if (buf) {
		if (strlen(cfg.file)) {
			ffd = open(cfg.file, O_RDONLY);
			if (ffd <= 0) {
				fprintf(stderr, "Failed to open file %s: %s\n",
						cfg.file, strerror(errno));
				err = -EINVAL;
				goto free;
			}
		}
		err = read(ffd, (void *)buf, cfg.data_len);
		if (err < 0) {
			err = -errno;
			fprintf(stderr, "failed to read data buffer from input"
					" file %s\n", strerror(errno));
			goto close_ffd;
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
		fprintf(stderr, "dir-send: %s\n", nvme_strerror(errno));
		goto close_ffd;
	}
	if (!err) {
		printf("dir-send: type %#x, operation %#x, spec_val %#x, nsid %#x, result %#x \n",
				cfg.dtype, cfg.doper, cfg.dspec, cfg.namespace_id, result);
		if (buf) {
			if (!cfg.raw_binary)
				d(buf, cfg.data_len, 16, 1);
			else
				d_raw(buf, cfg.data_len);
		}
	} else if (err > 0)
		nvme_show_status(err);

close_ffd:
	close(ffd);
free:
	free(buf);
close_dev:
	dev_close(dev);
ret:
	return err;
}

static int write_uncor(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "The Write Uncorrectable command is used to set a "\
			"range of logical blocks to invalid.";
	struct nvme_dev *dev;
	int err;

	struct config {
		__u32	namespace_id;
		__u64	start_block;
		__u16	block_count;
	};

	struct config cfg = {
		.namespace_id	= 0,
		.start_block	= 0,
		.block_count	= 0,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id",  'n', &cfg.namespace_id, namespace_desired),
		OPT_SUFFIX("start-block", 's', &cfg.start_block,  start_block),
		OPT_SHRT("block-count",   'c', &cfg.block_count,  block_count),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	if (!cfg.namespace_id) {
		err = nvme_get_nsid(dev_fd(dev), &cfg.namespace_id);
		if (err < 0) {
			fprintf(stderr, "get-namespace-id: %s\n", nvme_strerror(errno));
			goto close_dev;
		}
	}

	struct nvme_io_args args = {
		.args_size	= sizeof(args),
		.fd		= dev_fd(dev),
		.nsid		= cfg.namespace_id,
		.slba		= cfg.start_block,
		.nlb		= cfg.block_count,
		.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
		.result		= NULL,
	};
	err = nvme_write_uncorrectable(&args);
	if (err < 0)
		fprintf(stderr, "write uncorrectable: %s\n", nvme_strerror(errno));
	else if (err != 0)
		nvme_show_status(err);
	else
		printf("NVME Write Uncorrectable Success\n");

close_dev:
	dev_close(dev);
ret:
	return err;
}

static int invalid_tags(__u64 storage_tag, __u64 ref_tag, __u8 sts, __u8 pif)
{
	int result = 0;

	if (sts < 64 && storage_tag >= (1LL << sts)) {
		fprintf(stderr, "Storage tag larger than storage tag size\n");
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
		if (sts > 0 && ref_tag >= (1LL << (64 - sts)))
			result = 1;
		break;
	default:
		fprintf(stderr, "Invalid PIF\n");
		result = 1;
	}

	if (result)
		fprintf(stderr, "Reference tag larger than allowed by PIF\n");

	return result;
}

static int write_zeroes(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	__u16 control = 0;
	__u8 lba_index, sts = 0, pif = 0;
	struct nvme_id_ns ns;
	struct nvme_dev *dev;
	struct nvme_nvm_id_ns nvm_ns;
	int err;

	const char *desc = "The Write Zeroes command is used to set a "\
			"range of logical blocks to zero.";
	const char *deac = "Set DEAC bit, requesting controller to deallocate specified logical blocks";
	const char *storage_tag_check = "This bit specifies the Storage Tag field shall be checked as "\
		"part of end-to-end data protection processing";

	struct config {
		__u32	namespace_id;
		__u64	start_block;
		__u16	block_count;
		bool	deac;
		bool	limited_retry;
		bool	force_unit_access;
		__u8	prinfo;
		__u64	ref_tag;
		__u16	app_tag_mask;
		__u16	app_tag;
		__u64	storage_tag;
		bool	storage_tag_check;
	};

	struct config cfg = {
		.namespace_id		= 0,
		.start_block		= 0,
		.block_count		= 0,
		.deac			= false,
		.limited_retry		= false,
		.force_unit_access	= false,
		.prinfo			= 0,
		.ref_tag		= 0,
		.app_tag_mask		= 0,
		.app_tag		= 0,
		.storage_tag		= 0,
		.storage_tag_check	= false,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id",      'n', &cfg.namespace_id,      namespace_desired),
		OPT_SUFFIX("start-block",     's', &cfg.start_block,       start_block),
		OPT_SHRT("block-count",       'c', &cfg.block_count,       block_count),
		OPT_FLAG("deac",              'd', &cfg.deac,              deac),
		OPT_FLAG("limited-retry",     'l', &cfg.limited_retry,     limited_retry),
		OPT_FLAG("force-unit-access", 'f', &cfg.force_unit_access, force_unit_access),
		OPT_BYTE("prinfo",            'p', &cfg.prinfo,            prinfo),
		OPT_SUFFIX("ref-tag",         'r', &cfg.ref_tag,           ref_tag),
		OPT_SHRT("app-tag-mask",      'm', &cfg.app_tag_mask,      app_tag_mask),
		OPT_SHRT("app-tag",           'a', &cfg.app_tag,           app_tag),
		OPT_SUFFIX("storage-tag",     'S', &cfg.storage_tag,       storage_tag),
		OPT_FLAG("storage-tag-check", 'C', &cfg.storage_tag_check, storage_tag_check),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	if (cfg.prinfo > 0xf) {
		err = -EINVAL;
		goto close_dev;
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
	if (!cfg.namespace_id) {
		err = nvme_get_nsid(dev_fd(dev), &cfg.namespace_id);
		if (err < 0) {
			fprintf(stderr, "get-namespace-id: %s\n", nvme_strerror(errno));
			goto close_dev;
		}
	}

	err = nvme_cli_identify_ns(dev, cfg.namespace_id, &ns);
	if (err < 0) {
		fprintf(stderr, "identify namespace: %s\n", nvme_strerror(errno));
		goto close_dev;
	} else if (err) {
		nvme_show_status(err);
		goto close_dev;
	}

	err = nvme_identify_ns_csi(dev_fd(dev), cfg.namespace_id, 0,
				   NVME_CSI_NVM, &nvm_ns);
	if (!err) {
		nvme_id_ns_flbas_to_lbaf_inuse(ns.flbas, &lba_index);
		sts = nvm_ns.elbaf[lba_index] & NVME_NVM_ELBAF_STS_MASK;
		pif = (nvm_ns.elbaf[lba_index] & NVME_NVM_ELBAF_PIF_MASK) >> 7;
	}

	if (invalid_tags(cfg.storage_tag, cfg.ref_tag, sts, pif)) {
		err = -EINVAL;
		goto close_dev;
	}

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
	err = nvme_write_zeros(&args);
	if (err < 0)
		fprintf(stderr, "write-zeroes: %s\n", nvme_strerror(errno));
	else if (err != 0)
		nvme_show_status(err);
	else
		printf("NVME Write Zeroes Success\n");

close_dev:
	dev_close(dev);
ret:
	return err;
}

static int dsm(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "The Dataset Management command is used by the host to "\
		"indicate attributes for ranges of logical blocks. This includes attributes "\
		"for discarding unused blocks, data read and write frequency, access size, and other "\
		"information that may be used to optimize performance and reliability.";
	const char *blocks = "Comma separated list of the number of blocks in each range";
	const char *starting_blocks = "Comma separated list of the starting block in each range";
	const char *context_attrs = "Comma separated list of the context attributes in each range";
	const char *ad = "Attribute Deallocate";
	const char *idw = "Attribute Integral Dataset for Write";
	const char *idr = "Attribute Integral Dataset for Read";
	const char *cdw11 = "All the command DWORD 11 attributes. Use instead of specifying individual attributes";

	uint16_t nr, nc, nb, ns;
	__u32 ctx_attrs[256] = {0,};
	__u32 nlbs[256] = {0,};
	__u64 slbas[256] = {0,};
	struct nvme_dsm_range dsm[256];
	struct nvme_dev *dev;
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

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id_desired),
		OPT_LIST("ctx-attrs",    'a', &cfg.ctx_attrs,    context_attrs),
		OPT_LIST("blocks",	 'b', &cfg.blocks,       blocks),
		OPT_LIST("slbs",	 's', &cfg.slbas,        starting_blocks),
		OPT_FLAG("ad",	         'd', &cfg.ad,           ad),
		OPT_FLAG("idw",		 'w', &cfg.idw,          idw),
		OPT_FLAG("idr",		 'r', &cfg.idr,          idr),
		OPT_UINT("cdw11",        'c', &cfg.cdw11,        cdw11),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	nc = argconfig_parse_comma_sep_array(cfg.ctx_attrs, (int *)ctx_attrs, ARRAY_SIZE(ctx_attrs));
	nb = argconfig_parse_comma_sep_array(cfg.blocks, (int *)nlbs, ARRAY_SIZE(nlbs));
	ns = argconfig_parse_comma_sep_array_long(cfg.slbas, (unsigned long long *)slbas, ARRAY_SIZE(slbas));
	nr = max(nc, max(nb, ns));
	if (!nr || nr > 256) {
		fprintf(stderr, "No range definition provided\n");
		err = -EINVAL;
		goto close_dev;
	}

	if (!cfg.namespace_id) {
		err = nvme_get_nsid(dev_fd(dev), &cfg.namespace_id);
		if (err < 0) {
			fprintf(stderr, "get-namespace-id: %s\n", nvme_strerror(errno));
			goto close_dev;
		}
	}
	if (!cfg.cdw11)
		cfg.cdw11 = (cfg.ad << 2) | (cfg.idw << 1) | (cfg.idr << 0);

	nvme_init_dsm_range(dsm, ctx_attrs, nlbs, slbas, nr);
	struct nvme_dsm_args args = {
		.args_size	= sizeof(args),
		.fd		= dev_fd(dev),
		.nsid		= cfg.namespace_id,
		.attrs		= cfg.cdw11,
		.nr_ranges	= nr,
		.dsm		= dsm,
		.timeout        = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result		= NULL,
	};
	err = nvme_dsm(&args);
	if (err < 0)
		fprintf(stderr, "data-set management: %s\n", nvme_strerror(errno));
	else if (err != 0)
		nvme_show_status(err);
	else
		printf("NVMe DSM: success\n");

close_dev:
	dev_close(dev);
ret:
	return err;
}

static int copy(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "The Copy command is used by the host to copy data "
			   "from one or more source logical block ranges to a "
			   "single consecutive destination logical block "
			   "range.";

	const char *d_sdlba = "64-bit addr of first destination logical block";
	const char *d_slbas = "64-bit addr of first block per range (comma-separated list)";
	const char *d_nlbs = "number of blocks per range (comma-separated list, zeroes-based values)";
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

	uint16_t nr, nb, ns, nrts, natms, nats;
	__u16 nlbs[128] = { 0 };
	unsigned long long slbas[128] = {0,};
	struct nvme_dev *dev;
	int err;

	union {
		__u32 f0[128];
		__u64 f1[101];
	} eilbrts;

	__u32 elbatms[128] = { 0 };
	__u32 elbats[128] = { 0 };

	union {
		struct nvme_copy_range f0[128];
		struct nvme_copy_range_f1 f1[101];
	} copy;

	struct config {
		__u32	namespace_id;
		__u64	sdlba;
		char	*slbas;
		char	*nlbs;
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

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id",	   'n', &cfg.namespace_id,	namespace_id_desired),
		OPT_SUFFIX("sdlba",                'd', &cfg.sdlba,		d_sdlba),
		OPT_LIST("slbs",                   's', &cfg.slbas,		d_slbas),
		OPT_LIST("blocks",                 'b', &cfg.nlbs,		d_nlbs),
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
		OPT_BYTE("format",                 'F', &cfg.format,		d_format),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	nb = argconfig_parse_comma_sep_array_short(cfg.nlbs, nlbs, ARRAY_SIZE(nlbs));
	ns = argconfig_parse_comma_sep_array_long(cfg.slbas, slbas, ARRAY_SIZE(slbas));

	if (cfg.format == 0)
		nrts = argconfig_parse_comma_sep_array(cfg.eilbrts, (int *)eilbrts.f0, ARRAY_SIZE(eilbrts.f0));
	else if (cfg.format == 1)
		nrts = argconfig_parse_comma_sep_array_long(cfg.eilbrts, (unsigned long long *)eilbrts.f1, ARRAY_SIZE(eilbrts.f1));
	else {
		fprintf(stderr, "invalid format\n");
		err = -EINVAL;
		goto close_dev;
	}

	natms = argconfig_parse_comma_sep_array(cfg.elbatms, (int *)elbatms, ARRAY_SIZE(elbatms));
	nats = argconfig_parse_comma_sep_array(cfg.elbats, (int *)elbats, ARRAY_SIZE(elbats));

	nr = max(nb, max(ns, max(nrts, max(natms, nats))));
	if (!nr || nr > 128 || (cfg.format == 1 && nr > 101)) {
		fprintf(stderr, "invalid range\n");
		err = -EINVAL;
		goto close_dev;
	}

	if (!cfg.namespace_id) {
		err = nvme_get_nsid(dev_fd(dev), &cfg.namespace_id);
		if (err < 0) {
			fprintf(stderr, "get-namespace-id: %s\n", nvme_strerror(errno));
			goto close_dev;
		}
	}

	if (cfg.format == 0)
		nvme_init_copy_range(copy.f0, nlbs, (__u64 *)slbas,
		  eilbrts.f0, elbatms, elbats, nr);
	else if (cfg.format == 1)
		nvme_init_copy_range_f1(copy.f1, nlbs, (__u64 *)slbas,
		  eilbrts.f1, elbatms, elbats, nr);

	struct nvme_copy_args args = {
		.args_size	= sizeof(args),
		.fd		= dev_fd(dev),
		.nsid		= cfg.namespace_id,
		.copy		= copy.f0,
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
		fprintf(stderr, "NVMe Copy: %s\n", nvme_strerror(errno));
	else if (err != 0)
		nvme_show_status(err);
	else
		printf("NVMe Copy: success\n");

close_dev:
	dev_close(dev);
ret:
	return err;
}

static int flush(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Commit data and metadata associated with "\
		"given namespaces to nonvolatile media. Applies to all commands "\
		"finished before the flush was submitted. Additional data may also be "\
		"flushed by the controller, from any namespace, depending on controller and "\
		"associated namespace status.";
	struct nvme_dev *dev;
	int err;

	struct config {
		__u32	namespace_id;
	};

	struct config cfg = {
		.namespace_id	= 0,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id_desired),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	if (!cfg.namespace_id) {
		err = nvme_get_nsid(dev_fd(dev), &cfg.namespace_id);
		if (err < 0) {
			fprintf(stderr, "get-namespace-id: %s\n", nvme_strerror(errno));
			goto close_dev;
		}
	}

	err = nvme_flush(dev_fd(dev), cfg.namespace_id);
	if (err < 0)
		fprintf(stderr, "flush: %s\n", nvme_strerror(errno));
	else if (err != 0)
		nvme_show_status(err);
	else
		printf("NVMe Flush: success\n");
close_dev:
	dev_close(dev);
ret:
	return err;
}

static int resv_acquire(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Obtain a reservation on a given "\
		"namespace. Only one reservation is allowed at a time on a "\
		"given namespace, though multiple controllers may register "\
		"with that namespace. Namespace reservation will abort with "\
		"status Reservation Conflict if the given namespace is "\
		"already reserved.";
	const char *prkey = "pre-empt reservation key";
	const char *racqa = "reservation acquire action";
	struct nvme_dev *dev;
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

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id_desired),
		OPT_SUFFIX("crkey",      'c', &cfg.crkey,        crkey),
		OPT_SUFFIX("prkey",      'p', &cfg.prkey,        prkey),
		OPT_BYTE("rtype",        't', &cfg.rtype,        rtype),
		OPT_BYTE("racqa",        'a', &cfg.racqa,        racqa),
		OPT_FLAG("iekey",        'i', &cfg.iekey,        iekey),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	if (!cfg.namespace_id) {
		err = nvme_get_nsid(dev_fd(dev), &cfg.namespace_id);
		if (err < 0) {
			fprintf(stderr, "get-namespace-id: %s\n", nvme_strerror(errno));
			goto close_dev;
		}
	}
	if (cfg.racqa > 7) {
		fprintf(stderr, "invalid racqa:%d\n", cfg.racqa);
		err = -EINVAL;
		goto close_dev;
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
		fprintf(stderr, "reservation acquire: %s\n", nvme_strerror(errno));
	else if (err != 0)
		nvme_show_status(err);
	else
		printf("NVME Reservation Acquire success\n");

close_dev:
	dev_close(dev);
ret:
	return err;
}

static int resv_register(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Register, de-register, or "\
		"replace a controller's reservation on a given namespace. "\
		"Only one reservation at a time is allowed on any namespace.";
	const char *nrkey = "new reservation key";
	const char *rrega = "reservation registration action";
	const char *cptpl = "change persistence through power loss setting";
	struct nvme_dev *dev;
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

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id_desired),
		OPT_SUFFIX("crkey",      'c', &cfg.crkey,        crkey),
		OPT_SUFFIX("nrkey",      'k', &cfg.nrkey,        nrkey),
		OPT_BYTE("rrega",        'r', &cfg.rrega,        rrega),
		OPT_BYTE("cptpl",        'p', &cfg.cptpl,        cptpl),
		OPT_FLAG("iekey",        'i', &cfg.iekey,        iekey),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	if (!cfg.namespace_id) {
		err = nvme_get_nsid(dev_fd(dev), &cfg.namespace_id);
		if (err < 0) {
			fprintf(stderr, "get-namespace-id: %s\n", nvme_strerror(errno));
			goto close_dev;
		}
	}
	if (cfg.cptpl > 3) {
		fprintf(stderr, "invalid cptpl:%d\n", cfg.cptpl);
		err = -EINVAL;
		goto close_dev;
	}

	if (cfg.rrega > 7) {
		fprintf(stderr, "invalid rrega:%d\n", cfg.rrega);
		err = -EINVAL;
		goto close_dev;
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
		fprintf(stderr, "reservation register: %s\n", nvme_strerror(errno));
	else if (err != 0)
		nvme_show_status(err);
	else
		printf("NVME Reservation  success\n");

close_dev:
	dev_close(dev);
ret:
	return err;
}

static int resv_release(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Releases reservation held on a "\
		"namespace by the given controller. If rtype != current reservation"\
		"type, release will fails. If the given controller holds no "\
		"reservation on the namespace or is not the namespace's current "\
		"reservation holder, the release command completes with no "\
		"effect. If the reservation type is not Write Exclusive or "\
		"Exclusive Access, all registrants on the namespace except "\
		"the issuing controller are notified.";
	const char *rrela = "reservation release action";
	struct nvme_dev *dev;
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

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_desired),
		OPT_SUFFIX("crkey",      'c', &cfg.crkey,        crkey),
		OPT_BYTE("rtype",        't', &cfg.rtype,        rtype),
		OPT_BYTE("rrela",        'a', &cfg.rrela,        rrela),
		OPT_FLAG("iekey",        'i', &cfg.iekey,        iekey),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	if (!cfg.namespace_id) {
		err = nvme_get_nsid(dev_fd(dev), &cfg.namespace_id);
		if (err < 0) {
			fprintf(stderr, "get-namespace-id: %s\n", nvme_strerror(errno));
			goto close_dev;
		}
	}
	if (cfg.rrela > 7) {
		fprintf(stderr, "invalid rrela:%d\n", cfg.rrela);
		err = -EINVAL;
		goto close_dev;
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
		fprintf(stderr, "reservation release: %s\n", nvme_strerror(errno));
	else if (err != 0)
		nvme_show_status(err);
	else
		printf("NVME Reservation Release success\n");

close_dev:
	dev_close(dev);
ret:
	return err;
}

static int resv_report(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Returns Reservation Status data "\
		"structure describing any existing reservations on and the "\
		"status of a given namespace. Namespace Reservation Status "\
		"depends on the number of controllers registered for that "\
		"namespace.";
	const char *numd = "number of dwords to transfer";
	const char *eds = "request extended data structure";

	struct nvme_resv_status *status;
	enum nvme_print_flags flags;
	struct nvme_dev *dev;
	int err, size;

	struct config {
		__u32	namespace_id;
		__u32	numd;
		__u8	eds;
		char	*output_format;
		bool	raw_binary;
	};

	struct config cfg = {
		.namespace_id	= 0,
		.numd		= 0,
		.eds		= false,
		.output_format	= "normal",
		.raw_binary	= false,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id",  'n', &cfg.namespace_id,   namespace_id_desired),
		OPT_UINT("numd",          'd', &cfg.numd,           numd),
		OPT_FLAG("eds",           'e', &cfg.eds,            eds),
		OPT_FMT("output-format",  'o', &cfg.output_format,  output_format),
		OPT_FLAG("raw-binary",    'b', &cfg.raw_binary,     raw_dump),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_dev;
	if (cfg.raw_binary)
		flags = BINARY;

	if (!cfg.namespace_id) {
		err = nvme_get_nsid(dev_fd(dev), &cfg.namespace_id);
		if (err < 0) {
			fprintf(stderr, "get-namespace-id: %s\n", nvme_strerror(errno));
			goto close_dev;
		}
	}

	if (!cfg.numd || cfg.numd >= (0x1000 >> 2))
		cfg.numd = (0x1000 >> 2) - 1;
	if (cfg.numd < 3)
		cfg.numd = 3;

	size = (cfg.numd + 1) << 2;

	if (posix_memalign((void **)&status, getpagesize(), size)) {
		fprintf(stderr, "No memory for resv report:%d\n", size);
		err = -ENOMEM;
		goto close_dev;
	}
	memset(status, 0, size);

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
		fprintf(stderr, "reservation report: %s\n", nvme_strerror(errno));
	free(status);
close_dev:
	dev_close(dev);
ret:
	return err;
}

unsigned long long elapsed_utime(struct timeval start_time,
					struct timeval end_time)
{
	unsigned long long err = (end_time.tv_sec - start_time.tv_sec) * 1000000 +
		(end_time.tv_usec - start_time.tv_usec);
	return err;
}

static int submit_io(int opcode, char *command, const char *desc,
		     int argc, char **argv)
{
	struct timeval start_time, end_time;
	void *buffer, *mbuffer = NULL;
	int err = 0;
	int dfd, mfd;
	int flags = opcode & 1 ? O_RDONLY : O_WRONLY | O_CREAT;
	int mode = S_IRUSR | S_IWUSR |S_IRGRP | S_IWGRP| S_IROTH;
	__u16 control = 0;
	__u32 dsmgmt = 0;
	int logical_block_size = 0;
	unsigned long long buffer_size = 0, mbuffer_size = 0;
	bool huge;
	struct nvme_id_ns ns;
	struct nvme_nvm_id_ns nvm_ns;
	__u8 lba_index, ms = 0, sts = 0, pif = 0;
	struct nvme_dev *dev;

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
	const char *storage_tag_check = "This bit specifies the Storage Tag field shall be " \
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

	OPT_ARGS(opts) = {
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
		OPT_FLAG("show-command",      'v', &cfg.show,              show),
		OPT_FLAG("dry-run",           'w', &cfg.dry_run,           dry),
		OPT_FLAG("latency",           't', &cfg.latency,           latency),
		OPT_FLAG("force",	        0, &cfg.force,             force),
		OPT_END()
	};

	if (opcode != nvme_cmd_write) {
		err = parse_and_open(&dev, argc, argv, desc, opts);
		if (err)
			goto ret;
	} else {
		err = argconfig_parse(argc, argv, desc, opts);
		if (err)
			goto ret;
		err = open_exclusive(&dev, argc, argv, cfg.force);
		if (err) {
			if (errno == EBUSY) {
				fprintf(stderr, "Failed to open %s.\n",
					basename(argv[optind]));
				fprintf(stderr,
					"Namespace is currently busy.\n");
				if (!cfg.force)
					fprintf(stderr,
					"Use the force [--force] option to ignore that.\n");
			} else {
				argconfig_print_help(desc, opts);
			}
			goto ret;
		}
	}

	if (!cfg.namespace_id) {
		err = nvme_get_nsid(dev_fd(dev), &cfg.namespace_id);
		if (err < 0) {
			fprintf(stderr, "get-namespace-id: %s\n", nvme_strerror(errno));
			goto close_dev;
		}
	}

	dfd = mfd = opcode & 1 ? STDIN_FILENO : STDOUT_FILENO;
	if (cfg.prinfo > 0xf) {
		err = -EINVAL;
		goto close_dev;
	}

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
			fprintf(stderr, "Invalid directive type, %x\n",
				cfg.dtype);
			err = -EINVAL;
			goto close_dev;
		}
		control |= cfg.dtype << 4;
		dsmgmt |= ((__u32)cfg.dspec) << 16;
	}

	if (strlen(cfg.data)) {
		dfd = open(cfg.data, flags, mode);
		if (dfd < 0) {
			perror(cfg.data);
			err = -EINVAL;
			goto close_dev;
		}
	}

	if (strlen(cfg.metadata)) {
		mfd = open(cfg.metadata, flags, mode);
		if (mfd < 0) {
			perror(cfg.metadata);
			err = -EINVAL;
			goto close_dfd;
		}
	}

	if (!cfg.data_size)	{
		fprintf(stderr, "data size not provided\n");
		err = -EINVAL;
		goto close_mfd;
	}

	if (nvme_get_logical_block_size(dev_fd(dev), cfg.namespace_id,
					&logical_block_size) < 0)
		goto close_mfd;

	buffer_size = ((long long)cfg.block_count + 1) * logical_block_size;
	if (cfg.data_size < buffer_size) {
		fprintf(stderr, "Rounding data size to fit block count (%lld bytes)\n",
				buffer_size);
	} else {
		buffer_size = cfg.data_size;
	}

	buffer = nvme_alloc(buffer_size, &huge);
	if (!buffer) {
		err = -ENOMEM;
		goto close_mfd;
	}

	if (cfg.metadata_size) {
		err = nvme_cli_identify_ns(dev, cfg.namespace_id, &ns);
		if (err > 0) {
			nvme_show_status(err);
			goto free_buffer;
		} else if (err < 0) {
			fprintf(stderr, "identify namespace: %s\n", nvme_strerror(errno));
			goto free_buffer;
		}

		nvme_id_ns_flbas_to_lbaf_inuse(ns.flbas, &lba_index);
		ms = ns.lbaf[lba_index].ms;

		err = nvme_identify_ns_csi(dev_fd(dev), 1, 0, NVME_CSI_NVM,
					   &nvm_ns);
		if (!err) {
			sts = nvm_ns.elbaf[lba_index] & NVME_NVM_ELBAF_STS_MASK;
			pif = (nvm_ns.elbaf[lba_index] & NVME_NVM_ELBAF_PIF_MASK) >> 7;
		}

		mbuffer_size = ((unsigned long long)cfg.block_count + 1) * ms;
		if (ms && cfg.metadata_size < mbuffer_size) {
			fprintf(stderr, "Rounding metadata size to fit block count (%lld bytes)\n",
					mbuffer_size);
		} else {
			mbuffer_size = cfg.metadata_size;
		}
		mbuffer = malloc(mbuffer_size);
		if (!mbuffer) {
			err = -ENOMEM;
			goto free_buffer;
		}
		memset(mbuffer, 0, mbuffer_size);
	}

	if (invalid_tags(cfg.storage_tag, cfg.ref_tag, sts, pif)) {
		err = -EINVAL;
		goto free_buffer;
	}

	if ((opcode & 1)) {
		err = read(dfd, (void *)buffer, cfg.data_size);
		if (err < 0) {
			err = -errno;
			fprintf(stderr, "failed to read data buffer from input"
					" file %s\n", strerror(errno));
			goto free_mbuffer;
		}
	}

	if ((opcode & 1) && cfg.metadata_size) {
		err = read(mfd, (void *)mbuffer, mbuffer_size);
		if (err < 0) {
			err = -errno;
			fprintf(stderr, "failed to read meta-data buffer from"
					" input file %s\n", strerror(errno));
			goto free_mbuffer;
		}
	}

	if (cfg.show || cfg.dry_run) {
		printf("opcode       : %02x\n", opcode);
		printf("nsid         : %02x\n", cfg.namespace_id);
		printf("flags        : %02x\n", 0);
		printf("control      : %04x\n", control);
		printf("nblocks      : %04x\n", cfg.block_count);
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
		goto free_mbuffer;

	struct nvme_io_args args = {
		.args_size	= sizeof(args),
		.fd		= dev_fd(dev),
		.nsid		= cfg.namespace_id,
		.slba		= cfg.start_block,
		.nlb		= cfg.block_count,
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
		.metadata_len	= cfg.metadata_size,
		.metadata	= mbuffer,
		.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
		.result		= NULL,
	};
	gettimeofday(&start_time, NULL);
	err = nvme_io(&args, opcode);
	gettimeofday(&end_time, NULL);
	if (cfg.latency)
		printf(" latency: %s: %llu us\n",
			command, elapsed_utime(start_time, end_time));
	if (err < 0)
		fprintf(stderr, "submit-io: %s\n", nvme_strerror(errno));
	else if (err)
		nvme_show_status(err);
	else {
		if (!(opcode & 1) && write(dfd, (void *)buffer, cfg.data_size) < 0) {
			fprintf(stderr, "write: %s: failed to write buffer to output file\n",
					strerror(errno));
			err = -EINVAL;
		} else if (!(opcode & 1) && cfg.metadata_size &&
				write(mfd, (void *)mbuffer, mbuffer_size) < 0) {
			fprintf(stderr, "write: %s: failed to write meta-data buffer to output file\n",
					strerror(errno));
			err = -EINVAL;
		} else
			fprintf(stderr, "%s: Success\n", command);
	}

free_mbuffer:
	free(mbuffer);
free_buffer:
	nvme_free(buffer, huge);
close_mfd:
	if (strlen(cfg.metadata))
		close(mfd);
close_dfd:
	close(dfd);
close_dev:
	dev_close(dev);
ret:
	return err;
}

static int compare(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Compare specified logical blocks on "\
		"device with specified data buffer; return failure if buffer "\
		"and block(s) are dissimilar";
	return submit_io(nvme_cmd_compare, "compare", desc, argc, argv);
}

static int read_cmd(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Copy specified logical blocks on the given "\
		"device to specified data buffer (default buffer is stdout).";
	return submit_io(nvme_cmd_read, "read", desc, argc, argv);
}

static int write_cmd(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Copy from provided data buffer (default "\
		"buffer is stdin) to specified logical blocks on the given "\
		"device.";
	return submit_io(nvme_cmd_write, "write", desc, argc, argv);
}

static int verify_cmd(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	__u16 control = 0;
	__u8 lba_index, sts = 0, pif = 0;
	struct nvme_id_ns ns;
	struct nvme_nvm_id_ns nvm_ns;
	struct nvme_dev *dev;
	int err;

	const char *desc = "Verify specified logical blocks on the given device.";
	const char *force_unit_access_verify = "force device to commit cached data before performing the verify operation";
	const char *storage_tag_check = "This bit specifies the Storage Tag field shall "\
		"be checked as part of Verify operation";

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

	OPT_ARGS(opts) = {
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
		OPT_FLAG("storage-tag-check", 'C', &cfg.storage_tag_check, storage_tag_check),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	if (cfg.prinfo > 0xf) {
		err = EINVAL;
		goto close_dev;
	}

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
			fprintf(stderr, "get-namespace-id: %s\n", nvme_strerror(errno));
			goto close_dev;
		}
	}

	err = nvme_cli_identify_ns(dev, cfg.namespace_id, &ns);
	if (err < 0) {
		fprintf(stderr, "identify namespace: %s\n", nvme_strerror(errno));
		goto close_dev;
	} else if (err) {
		nvme_show_status(err);
		goto close_dev;
	}

	err = nvme_identify_ns_csi(dev_fd(dev), cfg.namespace_id, 0,
				   NVME_CSI_NVM, &nvm_ns);
	if (!err) {
		nvme_id_ns_flbas_to_lbaf_inuse(ns.flbas, &lba_index);
		sts = nvm_ns.elbaf[lba_index] & NVME_NVM_ELBAF_STS_MASK;
		pif = (nvm_ns.elbaf[lba_index] & NVME_NVM_ELBAF_PIF_MASK) >> 7;
	}

	if (invalid_tags(cfg.storage_tag, cfg.ref_tag, sts, pif)) {
		err = -EINVAL;
		goto close_dev;
	}

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
		fprintf(stderr, "verify: %s\n", nvme_strerror(errno));
	else if (err != 0)
		nvme_show_status(err);
	else
		printf("NVME Verify Success\n");

close_dev:
	dev_close(dev);
ret:
	return err;
}

static int sec_recv(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Obtain results of one or more "\
		"previously submitted security-sends. Results, and association "\
		"between Security Send and Receive, depend on the security "\
		"protocol field as they are defined by the security protocol "\
		"used. A Security Receive must follow a Security Send made with "\
		"the same security protocol.";
	const char *size = "size of buffer (prints to stdout on success)";
	const char *al = "allocation length (cf. SPC-4)";
	struct nvme_dev *dev;
	void *sec_buf = NULL;
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

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_desired),
		OPT_UINT("size",         'x', &cfg.size,         size),
		OPT_BYTE("nssf",         'N', &cfg.nssf,         nssf),
		OPT_BYTE("secp",         'p', &cfg.secp,         secp),
		OPT_SHRT("spsp",         's', &cfg.spsp,         spsp),
		OPT_UINT("al",           't', &cfg.al,           al),
		OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,   raw_dump),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	if (cfg.size) {
		if (posix_memalign(&sec_buf, getpagesize(), cfg.size)) {
			fprintf(stderr, "No memory for security size:%d\n",
								cfg.size);
			err = -ENOMEM;
			goto close_dev;
		}
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

	if (err < 0)
		fprintf(stderr, "security receive: %s\n", nvme_strerror(errno));
	else if (err != 0)
		nvme_show_status(err);
	else {
		printf("NVME Security Receive Command Success\n");
		if (!cfg.raw_binary) {
			d(sec_buf, cfg.size, 16, 1);
		} else if (cfg.size)
			d_raw((unsigned char *)sec_buf, cfg.size);
	}

	free(sec_buf);

close_dev:
	dev_close(dev);
ret:
	return err;
}

static int get_lba_status(int argc, char **argv, struct command *cmd,
		struct plugin *plugin)
{
	const char *desc = "Information about potentially unrecoverable LBAs.";
	const char *slba = "Starting LBA(SLBA) in 64-bit address of the first"\
			    " logical block addressed by this command";
	const char *mndw = "Maximum Number of Dwords(MNDW) specifies maximum"\
			    " number of dwords to return";
	const char *atype = "Action Type(ATYPE) specifies the mechanism"\
			     " the controller uses in determining the LBA"\
			     " Status Descriptors to return.";
	const char *rl = "Range Length(RL) specifies the length of the range"\
			  " of contiguous LBAs beginning at SLBA";

	enum nvme_print_flags flags;
	unsigned long buf_len;
	struct nvme_dev *dev;
	void *buf;
	int err;

	struct config {
		__u32	namespace_id;
		__u64	slba;
		__u32	mndw;
		__u8	atype;
		__u16	rl;
		__u32	timeout;
		char	*output_format;
	};

	struct config cfg = {
		.namespace_id	= 0,
		.slba		= 0,
		.mndw		= 0,
		.atype		= 0,
		.rl		= 0,
		.timeout	= 0,
		.output_format	= "normal",
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id,  namespace_desired),
		OPT_SUFFIX("start-lba",  's', &cfg.slba,          slba),
		OPT_UINT("max-dw",       'm', &cfg.mndw,          mndw),
		OPT_BYTE("action",       'a', &cfg.atype,         atype),
		OPT_SHRT("range-len",    'l', &cfg.rl,            rl),
		OPT_UINT("timeout",      't', &cfg.timeout,       timeout),
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto err;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_dev;

	if (!cfg.atype) {
		fprintf(stderr, "action type (--action) has to be given\n");
		err = -EINVAL;
		goto close_dev;
	}

	buf_len = (cfg.mndw + 1) * 4;
	buf = calloc(1, buf_len);
	if (!buf) {
		err = -ENOMEM;
		goto close_dev;
	}

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
		fprintf(stderr, "get lba status: %s\n", nvme_strerror(errno));
	free(buf);
close_dev:
	dev_close(dev);
err:
	return err;
}

static int capacity_mgmt(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Host software uses the Capacity Management command to "\
		"configure Endurance Groups and NVM Sets in an NVM subsystem by either " \
		"selecting one of a set of supported configurations or by specifying the "\
		"capacity of the Endurance Group or NVM Set to be created";
	const char *operation = "Operation to be performed by the controller";
	const char *element_id = "Value specific to the value of the Operation field.";
	const char *cap_lower = "Least significant 32 bits of the capacity in bytes of the "\
		"Endurance Group or NVM Set to be created";
	const char *cap_upper = "Most significant 32 bits of the capacity in bytes of the "\
		"Endurance Group or NVM Set to be created";

	struct nvme_dev *dev;
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

	OPT_ARGS(opts) = {
		OPT_BYTE("operation",   'o', &cfg.operation,    operation),
		OPT_SHRT("element-id",  'i', &cfg.element_id,   element_id),
		OPT_UINT("cap-lower",   'l', &cfg.dw11,		cap_lower),
		OPT_UINT("cap-upper",   'u', &cfg.dw12,         cap_upper),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	if (cfg.operation > 0xf) {
		fprintf(stderr, "invalid operation field: %u\n", cfg.operation);
		err = -1;
		goto close_dev;
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
		if (cfg.operation == 1) {
			printf("Created Element Identifier for Endurance Group is: %u\n", result);
		} else if (cfg.operation == 3) {
			printf("Created Element Identifier for NVM Set is: %u\n", result);
		}
	} else if (err > 0)
		nvme_show_status(err);
	else if (err < 0)
		fprintf(stderr, "capacity management: %s\n", nvme_strerror(errno));

close_dev:
	dev_close(dev);
ret:
	return err;
}

static int dir_receive(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Read directive parameters of the "\
			    "specified directive type.";
	const char *nsr = "namespace stream requested";

	enum nvme_print_flags flags = NORMAL;
	struct nvme_dev *dev;
	__u32 result;
	__u32 dw12 = 0;
	void *buf = NULL;
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

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id",  'n', &cfg.namespace_id,   namespace_id_desired),
		OPT_UINT("data-len",      'l', &cfg.data_len,       buf_len),
		OPT_FLAG("raw-binary",    'b', &cfg.raw_binary,     raw_directive),
		OPT_BYTE("dir-type",      'D', &cfg.dtype,          dtype),
		OPT_SHRT("dir-spec",      'S', &cfg.dspec,          dspec_w_dtype),
		OPT_BYTE("dir-oper",      'O', &cfg.doper,          doper),
		OPT_SHRT("req-resource",  'r', &cfg.nsr,            nsr),
		OPT_FLAG("human-readable",'H', &cfg.human_readable, human_readable_directive),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

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
			fprintf(stderr, "invalid directive operations for Identify Directives\n");
			err = -EINVAL;
			goto close_dev;
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
			fprintf(stderr, "invalid directive operations for Streams Directives\n");
			err = -EINVAL;
			goto close_dev;
		}
		break;
	default:
		fprintf(stderr, "invalid directive type\n");
		err = -EINVAL;
		goto close_dev;
	}

	if (cfg.data_len) {
		if (posix_memalign(&buf, getpagesize(), cfg.data_len)) {
			err = -ENOMEM;
			goto close_dev;
		}
		memset(buf, 0, cfg.data_len);
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
		nvme_directive_show(cfg.dtype, cfg.doper, cfg.dspec,
				    cfg.namespace_id, result, buf, cfg.data_len,
				    flags);
	else if (err > 0)
		nvme_show_status(err);
	else if (err < 0)
		fprintf(stderr, "dir-receive: %s\n", nvme_strerror(errno));

	free(buf);
close_dev:
	dev_close(dev);
ret:
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
	const char *desc = "The Lockdown command is used to control the "\
		"Command and Feature Lockdown capability which configures the "\
		"prohibition or allowance of execution of the specified command "\
		"or Set Features command targeting a specific Feature Identifier.";
	const char *ofi_desc = "Opcode or Feature Identifier(OFI) "\
		"specifies the command opcode or Set Features Feature Identifier "\
		"identified by the Scope field.";
	const char *ifc_desc = "[0-3] Interface (INF) field identifies the "\
		"interfaces affected by this command.";
	const char *prhbt_desc = "[0-1]Prohibit(PRHBT) bit specifies whether "\
		"to prohibit or allow the command opcode or Set Features Feature "\
		"Identifier specified by this command.";
	const char *scp_desc = "[0-15]Scope(SCP) field specifies the contents "\
		"of the Opcode or Feature Identifier field.";
	const char *uuid_desc = "UUID Index - If this field is set to a non-zero "\
		"value, then the value of this field is the index of a UUID in the UUID "\
		"List that is used by the command.If this field is cleared to 0h,"\
		"then no UUID index is specified";

	struct nvme_dev *dev;
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

	OPT_ARGS(opts) = {
		OPT_BYTE("ofi",		'o', &cfg.ofi,      ofi_desc),
		OPT_BYTE("ifc",		'f', &cfg.ifc,      ifc_desc),
		OPT_BYTE("prhbt",	'p', &cfg.prhbt,    prhbt_desc),
		OPT_BYTE("scp",		's', &cfg.scp,      scp_desc),
		OPT_BYTE("uuid",	'U', &cfg.uuid,     uuid_desc),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	/* check for input argument limit */
	if (cfg.ifc > 3) {
		fprintf(stderr, "invalid interface settings:%d\n", cfg.ifc);
		err = -1;
		goto close_dev;
	}
	if (cfg.prhbt > 1) {
		fprintf(stderr, "invalid prohibit settings:%d\n", cfg.prhbt);
		err = -1;
		goto close_dev;
	}
	if (cfg.scp > 15) {
		fprintf(stderr, "invalid scope settings:%d\n", cfg.scp);
		err = -1;
		goto close_dev;
	}
	if (cfg.uuid > 127) {
		fprintf(stderr, "invalid UUID index settings:%d\n", cfg.uuid);
		err = -1;
		goto close_dev;
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
		fprintf(stderr, "lockdown: %s\n", nvme_strerror(errno));
	else if (err > 0)
		nvme_show_status(err);
	else
		printf("Lockdown Command is Successful\n");

close_dev:
	dev_close(dev);
ret:
	return err;
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

	int flags;
	int mode = S_IRUSR | S_IWUSR |S_IRGRP | S_IWGRP| S_IROTH;
	void *data = NULL, *mdata = NULL;
	int err = 0, dfd, mfd;
	struct nvme_dev *dev;
	__u32 result;
	bool huge = false;
	const char *cmd_name = NULL;
	struct timeval start_time, end_time;

	struct config {
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

	struct config cfg = {
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

	OPT_ARGS(opts) = {
		OPT_BYTE("opcode",       'o', &cfg.opcode,       opcode),
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
		OPT_FLAG("latency",      'T', &cfg.latency,      latency),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		goto ret;

	if (cfg.opcode & 0x01)
		cfg.write = true;

	if (cfg.opcode & 0x02)
		cfg.read = true;

	if (cfg.write) {
		flags = O_RDONLY;
		dfd = mfd = STDIN_FILENO;
	}

	if (cfg.read) {
		flags = O_WRONLY | O_CREAT;
		dfd = mfd = STDOUT_FILENO;
	}

	if (strlen(cfg.input_file)) {
		dfd = open(cfg.input_file, flags, mode);
		if (dfd < 0) {
			perror(cfg.input_file);
			err = -EINVAL;
			goto close_dev;
		}
	}

	if (cfg.metadata && strlen(cfg.metadata)) {
		mfd = open(cfg.metadata, flags, mode);
		if (mfd < 0) {
			perror(cfg.metadata);
			err = -EINVAL;
			goto close_dfd;
		}
	}

	if (cfg.metadata_len) {
		mdata = malloc(cfg.metadata_len);
		if (!mdata) {
			err = -ENOMEM;
			goto close_mfd;
		}

		if (cfg.write) {
			if (read(mfd, mdata, cfg.metadata_len) < 0) {
				err = -errno;
				perror("failed to read metadata write buffer");
				goto free_metadata;
			}
		} else
			memset(mdata, cfg.prefill, cfg.metadata_len);
	}

	if (cfg.data_len) {
		data = nvme_alloc(cfg.data_len, &huge);
		if (!data) {
			err = -ENOMEM;
			goto free_metadata;
		}

		memset(data, cfg.prefill, cfg.data_len);
		if (!cfg.read && !cfg.write) {
			fprintf(stderr, "data direction not given\n");
			err = -EINVAL;
			goto free_data;
		} else if (cfg.write) {
			if (read(dfd, data, cfg.data_len) < 0) {
				err = -errno;
				fprintf(stderr, "failed to read write buffer "
						"%s\n", strerror(errno));
				goto free_data;
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
		goto free_data;

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
		printf("%s Command %s latency: %llu us\n",
			admin ? "Admin": "IO",
			strcmp(cmd_name, "Unknown") ? cmd_name: "Vendor Specific",
			elapsed_utime(start_time, end_time));

	if (err < 0)
		fprintf(stderr, "passthru: %s\n", nvme_strerror(errno));
	else if (err)
		nvme_show_status(err);
	else  {
		fprintf(stderr, "%s Command %s is Success and result: 0x%08x\n",
				admin ? "Admin": "IO",
				strcmp(cmd_name, "Unknown") ? cmd_name: "Vendor Specific",
				result);
		if (cfg.read && strlen(cfg.input_file)) {
			if (write(dfd, (void *)data, cfg.data_len) < 0)
				perror("failed to write data buffer");
			if (cfg.metadata_len && cfg.metadata)
				if (write(mfd, (void *)mdata, cfg.metadata_len) < 0)
					perror("failed to write metadata buffer");
		} else if (!cfg.raw_binary) {
			if (data && cfg.read && !err)
				d((unsigned char *)data, cfg.data_len, 16, 1);
		} else if (data && cfg.read)
			d_raw((unsigned char *)data, cfg.data_len);
	}
free_metadata:
	free(mdata);
free_data:
	nvme_free(data, huge);
close_dfd:
	if (strlen(cfg.input_file))
		close(dfd);
close_mfd:
	if (cfg.metadata && strlen(cfg.metadata))
		close(mfd);
close_dev:
	dev_close(dev);
ret:
	return err;
}

static int io_passthru(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Send a user-defined IO command to the specified "\
		"device via IOCTL passthrough, return results.";
	return passthru(argc, argv, false, desc, cmd);
}

static int admin_passthru(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Send a user-defined Admin command to the specified "\
		"device via IOCTL passthrough, return results.";
	return passthru(argc, argv, true, desc, cmd);
}

static int gen_hostnqn_cmd(int argc, char **argv, struct command *command, struct plugin *plugin)
{
	char *hostnqn;

	hostnqn = nvmf_hostnqn_generate();
	if (!hostnqn) {
		fprintf(stderr, "\"%s\" not supported. Install lib uuid and rebuild.\n",
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
		fprintf(stderr, "hostnqn is not available -- use nvme gen-hostnqn\n");
		return ENOENT;
	}

	fprintf(stdout, "%s\n", hostnqn);
	free(hostnqn);

	return 0;
}


static int gen_dhchap_key(int argc, char **argv, struct command *command, struct plugin *plugin)
{
	const char *desc = "Generate a DH-HMAC-CHAP host key usable "\
		"for NVMe In-Band Authentication.";
	const char *secret = "Optional secret (in hexadecimal characters) "\
		"to be used to initialize the host key.";
	const char *key_len = "Length of the resulting key "\
		"(32, 48, or 64 bytes).";
	const char *hmac = "HMAC function to use for key transformation "\
		"(0 = none, 1 = SHA-256, 2 = SHA-384, 3 = SHA-512).";
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

	OPT_ARGS(opts) = {
		OPT_STR("secret",	's', &cfg.secret,	secret),
		OPT_UINT("key-length",	'l', &cfg.key_len,	key_len),
		OPT_STR("nqn",		'n', &cfg.nqn,		nqn),
		OPT_UINT("hmac",	'm', &cfg.hmac,		hmac),
		OPT_END()
	};

	err = argconfig_parse(argc, argv, desc, opts);
	if (err)
		return err;

	if (cfg.hmac > 3) {
		fprintf(stderr, "Invalid HMAC identifier %u\n", cfg.hmac);
		return -EINVAL;
	}
	if (cfg.hmac > 0) {
		switch (cfg.hmac) {
		case 1:
			if (!cfg.key_len)
				cfg.key_len = 32;
			else if (cfg.key_len != 32) {
				fprintf(stderr, "Invalid key length %d for SHA(256)\n",
					cfg.key_len);
				return -EINVAL;
			}
			break;
		case 2:
			if (!cfg.key_len)
				cfg.key_len = 48;
			else if (cfg.key_len != 48) {
				fprintf(stderr, "Invalid key length %d for SHA(384)\n",
					cfg.key_len);
				return -EINVAL;
			}
			break;
		case 3:
			if (!cfg.key_len)
				cfg.key_len = 64;
			else if (cfg.key_len != 64) {
				fprintf(stderr, "Invalid key length %d for SHA(512)\n",
					cfg.key_len);
				return -EINVAL;
			}
			break;
		default:
			break;
		}
	} else if (!cfg.key_len)
		cfg.key_len = 32;

	if (cfg.key_len != 32 && cfg.key_len != 48 && cfg.key_len != 64) {
		fprintf(stderr, "Invalid key length %u\n", cfg.key_len);
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

		for (i = 0; i < strlen(cfg.secret); i+=2) {
			if (sscanf(&cfg.secret[i], "%02x", &c) != 1) {
				fprintf(stderr, "Invalid secret '%s'\n",
					cfg.secret);
				return -EINVAL;
			}
			raw_secret[secret_len++] = (unsigned char)c;
		}
		if (secret_len != cfg.key_len) {
			fprintf(stderr, "Invalid key length (%d bytes)\n",
				secret_len);
			return -EINVAL;
		}
	}

	if (!cfg.nqn) {
		cfg.nqn = nvmf_hostnqn_from_file();
		if (!cfg.nqn) {
			fprintf(stderr, "Could not read host NQN\n");
			return -ENOENT;
		}
	}

	if (nvme_gen_dhchap_key(cfg.nqn, cfg.hmac, cfg.key_len,
				raw_secret, key) < 0)
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
	const char *desc = "Check a DH-HMAC-CHAP host key for usability "\
		"for NVMe In-Band Authentication.";
	const char *key = "DH-HMAC-CHAP key (in hexadecimal characters) "\
		"to be validated.";

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

	OPT_ARGS(opts) = {
		OPT_STR("key", 'k', &cfg.key, key),
		OPT_END()
	};

	err = argconfig_parse(argc, argv, desc, opts);
	if (err)
		return err;

	if (!cfg.key) {
		fprintf(stderr, "Key not specified\n");
		return -EINVAL;
	}

	if (sscanf(cfg.key, "DHHC-1:%02x:*s", &hmac) != 1) {
		fprintf(stderr, "Invalid key header '%s'\n", cfg.key);
		return -EINVAL;
	}
	switch (hmac) {
	case 0:
		break;
	case 1:
		if (strlen(cfg.key) != 59) {
			fprintf(stderr, "Invalid key length for SHA(256)\n");
			return -EINVAL;
		}
		break;
	case 2:
		if (strlen(cfg.key) != 83) {
			fprintf(stderr, "Invalid key length for SHA(384)\n");
			return -EINVAL;
		}
		break;
	case 3:
		if (strlen(cfg.key) != 103) {
			fprintf(stderr, "Invalid key length for SHA(512)\n");
			return -EINVAL;
		}
		break;
	default:
		fprintf(stderr, "Invalid HMAC identifier %d\n", hmac);
		return -EINVAL;
		break;
	}

	err = base64_decode(cfg.key + 10, strlen(cfg.key) - 11,
			    decoded_key);
	if (err < 0) {
		fprintf(stderr, "Base64 decoding failed, error %d\n",
			err);
		return err;
	}
	decoded_len = err;
	if (decoded_len < 32) {
		fprintf(stderr, "Base64 decoding failed (%s, size %u)\n",
			cfg.key + 10, decoded_len);
		return -EINVAL;
	}
	decoded_len -= 4;
	if (decoded_len != 32 && decoded_len != 48 && decoded_len != 64) {
		fprintf(stderr, "Invalid key length %d\n", decoded_len);
		return -EINVAL;
	}
	crc = crc32(crc, decoded_key, decoded_len);
	key_crc = ((u_int32_t)decoded_key[decoded_len]) |
		((u_int32_t)decoded_key[decoded_len + 1] << 8) |
		((u_int32_t)decoded_key[decoded_len + 2] << 16) |
		((u_int32_t)decoded_key[decoded_len + 3] << 24);
	if (key_crc != crc) {
		fprintf(stderr, "CRC mismatch (key %08x, crc %08x)\n",
			key_crc, crc);
		return -EINVAL;
	}
	printf("Key is valid (HMAC %d, length %d, CRC %08x)\n",
	       hmac, decoded_len, crc);
	return 0;
}

static int gen_tls_key(int argc, char **argv, struct command *command, struct plugin *plugin)
{
	const char *desc = "Generate a TLS key in NVMe PSK Interchange format.";
	const char *secret = "Optional secret (in hexadecimal characters) "\
		"to be used for the TLS key.";
	const char *hmac = "HMAC function to use for the retained key "\
		"(1 = SHA-256, 2 = SHA-384).";

	unsigned char *raw_secret;
	char encoded_key[128];
	int key_len = 32;
	unsigned long crc = crc32(0L, NULL, 0);
	int err = 0;

	struct config {
		char		*secret;
		unsigned int	hmac;
	};

	struct config cfg = {
		.secret		= NULL,
		.hmac		= 1,
	};

	OPT_ARGS(opts) = {
		OPT_STR("secret",	's', &cfg.secret,	secret),
		OPT_UINT("hmac",	'm', &cfg.hmac,		hmac),
		OPT_END()
	};

	err = argconfig_parse(argc, argv, desc, opts);
	if (err)
		return err;
	if (cfg.hmac < 1 || cfg.hmac > 3) {
		fprintf(stderr, "Invalid HMAC identifier %u\n", cfg.hmac);
		return -EINVAL;
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

		for (i = 0; i < strlen(cfg.secret); i+=2) {
			if (sscanf(&cfg.secret[i], "%02x", &c) != 1) {
				fprintf(stderr, "Invalid secret '%s'\n",
					cfg.secret);
				return -EINVAL;
			}
			if (i >= key_len) {
				fprintf(stderr,
					"Skipping excess secret bytes\n");
				break;
			}
			raw_secret[secret_len++] = (unsigned char)c;
		}
		if (secret_len != key_len) {
			fprintf(stderr, "Invalid key length (%d bytes)\n",
				secret_len);
			return -EINVAL;
		}
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
	const char *key = "TLS key (in PSK Interchange format) "\
		"to be validated.";

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

	OPT_ARGS(opts) = {
		OPT_STR("key", 'k', &cfg.key, key),
		OPT_END()
	};

	err = argconfig_parse(argc, argv, desc, opts);
	if (err)
		return err;

	if (!cfg.key) {
		fprintf(stderr, "Key not specified\n");
		return -EINVAL;
	}

	if (sscanf(cfg.key, "NVMeTLSkey-1:%02x:*s", &hmac) != 1) {
		fprintf(stderr, "Invalid key header '%s'\n", cfg.key);
		return -EINVAL;
	}
	switch (hmac) {
	case 1:
		if (strlen(cfg.key) != 65) {
			fprintf(stderr, "Invalid key length %zu for SHA(256)\n",
				strlen(cfg.key));
			return -EINVAL;
		}
		break;
	case 2:
		if (strlen(cfg.key) != 89) {
			fprintf(stderr, "Invalid key length %zu for SHA(384)\n",
				strlen(cfg.key));
			return -EINVAL;
		}
		break;
	default:
		fprintf(stderr, "Invalid HMAC identifier %d\n", hmac);
		return -EINVAL;
		break;
	}

	err = base64_decode(cfg.key + 16, strlen(cfg.key) - 17,
			    decoded_key);
	if (err < 0) {
		fprintf(stderr, "Base64 decoding failed (%s, error %d)\n",
			cfg.key + 16, err);
		return err;
	}
	decoded_len = err;
	decoded_len -= 4;
	if (decoded_len != 32 && decoded_len != 48) {
		fprintf(stderr, "Invalid key length %d\n", decoded_len);
		return -EINVAL;
	}
	crc = crc32(crc, decoded_key, decoded_len);
	key_crc = ((u_int32_t)decoded_key[decoded_len]) |
		((u_int32_t)decoded_key[decoded_len + 1] << 8) |
		((u_int32_t)decoded_key[decoded_len + 2] << 16) |
		((u_int32_t)decoded_key[decoded_len + 3] << 24);
	if (key_crc != crc) {
		fprintf(stderr, "CRC mismatch (key %08x, crc %08x)\n",
			key_crc, crc);
		return -EINVAL;
	}
	printf("Key is valid (HMAC %d, length %d, CRC %08x)\n",
	       hmac, decoded_len, crc);
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
		char	*output_format;
		int	verbose;
		char	*ranking;
	};

	struct config cfg = {
		.output_format	= "normal",
		.verbose	= 0,
		.ranking	= "namespace",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_INCR("verbose",      'v', &cfg.verbose,       verbose),
		OPT_FMT("ranking",       'r', &cfg.ranking,       ranking),
		OPT_END()
	};

	err = argconfig_parse(argc, argv, desc, opts);
	if (err)
		return err;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		return err;
	if (cfg.verbose)
		flags |= VERBOSE;

	if (!strcmp(cfg.ranking, "namespace"))
		rank = NVME_CLI_TOPO_NAMESPACE;
	else if (!strcmp(cfg.ranking, "ctrl"))
		rank = NVME_CLI_TOPO_CTRL;
	else {
		fprintf(stderr, "Invalid ranking argument: %s\n",
			cfg.ranking);
		return -EINVAL;
	}

	r = nvme_create_root(stderr, map_log_level(cfg.verbose, false));
	if (!r) {
		fprintf(stderr, "Failed to create topology root: %s\n",
			nvme_strerror(errno));
		return -errno;
	}

	err = nvme_scan_topology(r, NULL, NULL);
	if (err < 0) {
		fprintf(stderr, "Failed to scan topology: %s\n",
			 nvme_strerror(errno));
		nvme_free_tree(r);
		return err;
	}

	nvme_show_topology(r, flags, rank);
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
	const char *desc = "Send Discovery Information Management command to a Discovery Controller (DC)";
	return nvmf_dim(desc, argc, argv);
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
