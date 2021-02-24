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

#ifdef LIBHUGETLBFS
#include <hugetlbfs.h>
#endif

#include <linux/fs.h>

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "common.h"
#include "nvme-print.h"
#include "nvme-ioctl.h"
#include "nvme-status.h"
#include "nvme-lightnvm.h"
#include "plugin.h"

#include "argconfig.h"
#include "fabrics.h"
#include "monitor.h"

#define CREATE_CMD
#include "nvme-builtin.h"

static struct stat nvme_stat;
const char *devicename;

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
		"device (ex: /dev/nvme0) or an nvme block device "\
		"(ex: /dev/nvme0n1).",
	.extensions = &builtin,
};

static __u16 nvme_feat_buf_len[0x100] = {
	[NVME_FEAT_LBA_RANGE]		= 4096,
	[NVME_FEAT_AUTO_PST]		= 256,
	[NVME_FEAT_HOST_MEM_BUF]	= 4096,
	[NVME_FEAT_HOST_ID]		= 8,
	[NVME_FEAT_PLM_CONFIG]		= 512,
	[NVME_FEAT_TIMESTAMP]		= 8,
	[NVME_FEAT_HOST_BEHAVIOR]	= 512
};

const char *output_format = "Output format: normal|json|binary";
static const char *output_format_no_binary = "Output format: normal|json";

static void *__nvme_alloc(size_t len, bool *huge)
{
	void *p;

	if (!posix_memalign(&p, getpagesize(), len)) {
		*huge = false;
		memset(p, 0, len);
		return p;
	}
	return NULL;
}

#define HUGE_MIN 0x80000

#ifdef LIBHUGETLBFS
void nvme_free(void *p, bool huge)
{
	if (huge)
		free_hugepage_region(p);
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

static bool is_chardev(void)
{
	return S_ISCHR(nvme_stat.st_mode);
}

static bool is_blkdev(void)
{
	return S_ISBLK(nvme_stat.st_mode);
}

static int open_dev(char *dev)
{
	int err, fd;

	devicename = basename(dev);
	err = open(dev, O_RDONLY);
	if (err < 0)
		goto perror;
	fd = err;

	err = fstat(fd, &nvme_stat);
	if (err < 0) {
		close(fd);
		goto perror;
	}
	if (!is_chardev() && !is_blkdev()) {
		fprintf(stderr, "%s is not a block or character device\n", dev);
		close(fd);
		return -ENODEV;
	}
	return fd;
perror:
	perror(dev);
	return err;
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

static int get_dev(int argc, char **argv)
{
	int ret;

	ret = check_arg_dev(argc, argv);
	if (ret)
		return ret;

	return open_dev(argv[optind]);
}

int parse_and_open(int argc, char **argv, const char *desc,
	const struct argconfig_commandline_options *opts)
{
	int ret;

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret)
		return ret;

	ret = get_dev(argc, argv);
	if (ret < 0)
		argconfig_print_help(desc, opts);

	return ret;
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

static int get_smart_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	struct nvme_smart_log smart_log;
	const char *desc = "Retrieve SMART log for the given device "\
			"(or optionally a namespace) in either decoded format "\
			"(default) or binary.";
	const char *namespace = "(optional) desired namespace";
	const char *raw = "output in binary format";
	const char *human_readable = "show info in readable format";
	enum nvme_print_flags flags;
	int err, fd;

	struct config {
		__u32 namespace_id;
		int   raw_binary;
		char *output_format;
		int   human_readable;
	};

	struct config cfg = {
		.namespace_id = NVME_NSID_ALL,
		.output_format = "normal",
	};


	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id",   'n', &cfg.namespace_id,   namespace),
		OPT_FMT("output-format",   'o', &cfg.output_format,  output_format),
		OPT_FLAG("raw-binary",     'b', &cfg.raw_binary,     raw),
		OPT_FLAG("human-readable", 'H', &cfg.human_readable, human_readable),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;
	if (cfg.raw_binary)
		flags = BINARY;
	if (cfg.human_readable)
		flags |= VERBOSE;

	err = nvme_smart_log(fd, cfg.namespace_id, &smart_log);
	if (!err)
		nvme_show_smart_log(&smart_log, cfg.namespace_id, devicename,
				    flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		perror("smart log");
close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int get_ana_log(int argc, char **argv, struct command *cmd,
		struct plugin *plugin)
{
	const char *desc = "Retrieve ANA log for the given device in " \
			    "decoded format (default), json or binary.";
	void *ana_log;
	int err, fd;
	int groups = 0; /* Right now get all the per ANA group NSIDS */
	size_t ana_log_len;
	struct nvme_id_ctrl ctrl;
	enum nvme_print_flags flags;

	struct config {
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;

	err = nvme_identify_ctrl(fd, &ctrl);
	if (err) {
		fprintf(stderr, "ERROR : nvme_identify_ctrl() failed 0x%x\n",
				err);
		goto close_fd;
	}

	ana_log_len = sizeof(struct nvme_ana_rsp_hdr) +
		le32_to_cpu(ctrl.nanagrpid) * sizeof(struct nvme_ana_group_desc);
	if (!(ctrl.anacap & (1 << 6)))
		ana_log_len += le32_to_cpu(ctrl.mnan) * sizeof(__le32);

	ana_log = malloc(ana_log_len);
	if (!ana_log) {
		perror("malloc");
		err = -ENOMEM;
		goto close_fd;
	}

	err = nvme_ana_log(fd, ana_log, ana_log_len, groups ? NVME_ANA_LOG_RGO : 0);
	if (!err) {
		nvme_show_ana_log(ana_log, devicename, flags, ana_log_len);
	} else if (err > 0)
		nvme_show_status(err);
	else
		perror("ana-log");
	free(ana_log);
close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int get_telemetry_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Retrieve telemetry log and write to binary file";
	const char *fname = "File name to save raw binary, includes header";
	const char *hgen = "Have the host tell the controller to generate the report";
	const char *cgen = "Gather report generated by the controller.";
	const char *dgen = "Pick which telemetry data area to report. Default is all. Valid options are 1, 2, 3.";
	const size_t bs = 512;
	struct nvme_telemetry_log_page_hdr *hdr;
	size_t full_size, offset = bs;
	int err = 0, fd, output;
	void *page_log;

	struct config {
		char *file_name;
		__u32 host_gen;
		int ctrl_init;
		int data_area;
	};
	struct config cfg = {
		.file_name = NULL,
		.host_gen = 1,
		.ctrl_init = 0,
		.data_area = 3,
	};

	OPT_ARGS(opts) = {
		OPT_FILE("output-file",     'o', &cfg.file_name, fname),
		OPT_UINT("host-generate",   'g', &cfg.host_gen,  hgen),
		OPT_FLAG("controller-init", 'c', &cfg.ctrl_init, cgen),
		OPT_UINT("data-area",       'd', &cfg.data_area, dgen),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	if (!cfg.file_name) {
		fprintf(stderr, "Please provide an output file!\n");
		err = -EINVAL;
		goto close_fd;
	}

	cfg.host_gen = !!cfg.host_gen;
	hdr = malloc(bs);
	page_log = malloc(bs);
	if (!hdr || !page_log) {
		perror("failed to allocate buf for log\n");
		err = -ENOMEM;
		goto free_mem;
	}
	memset(hdr, 0, bs);

	output = open(cfg.file_name, O_WRONLY | O_CREAT | O_TRUNC, 0666);
	if (output < 0) {
		fprintf(stderr, "Failed to open output file %s: %s!\n",
				cfg.file_name, strerror(errno));
		err = output;
		goto free_mem;
	}

	err = nvme_get_telemetry_log(fd, hdr, cfg.host_gen, cfg.ctrl_init, bs, 0);
	if (err < 0)
		perror("get-telemetry-log");
	else if (err > 0) {
		nvme_show_status(err);
		fprintf(stderr, "Failed to acquire telemetry header %d!\n", err);
		goto close_output;
	}

	err = write(output, (void *) hdr, bs);
	if (err != bs) {
		fprintf(stderr, "Failed to flush all data to file!\n");
		goto close_output;
	}

	switch (cfg.data_area) {
	case 1:
		full_size = (le16_to_cpu(hdr->dalb1) * bs) + offset;
		break;
	case 2:
		full_size = (le16_to_cpu(hdr->dalb2) * bs) + offset;
		break;
	case 3:
		full_size = (le16_to_cpu(hdr->dalb3) * bs) + offset;
		break;
	default:
		fprintf(stderr, "Invalid data area requested\n");
		err = -EINVAL;
		goto close_output;
	}

	/*
	 * Continuously pull data until the offset hits the end of the last
	 * block.
	 */
	while (offset != full_size) {
		err = nvme_get_telemetry_log(fd, page_log, 0, cfg.ctrl_init, bs, offset);
		if (err < 0) {
			perror("get-telemetry-log");
			break;
		} else if (err > 0) {
			fprintf(stderr, "Failed to acquire full telemetry log!\n");
			nvme_show_status(err);
			break;
		}

		err = write(output, (void *) page_log, bs);
		if (err != bs) {
			fprintf(stderr, "Failed to flush all data to file!\n");
			break;
		}
		err = 0;
		offset += bs;
	}

close_output:
	close(output);
free_mem:
	free(hdr);
	free(page_log);
close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int get_endurance_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	struct nvme_endurance_group_log endurance_log;
	const char *desc = "Retrieves endurance groups log page and prints the log.";
	const char *group_id = "The endurance group identifier";
	enum nvme_print_flags flags;
	int err, fd;

	struct config {
		char *output_format;
		__u16 group_id;
	};

	struct config cfg = {
		.output_format = "normal",
		.group_id = 0,
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_SHRT("group-id",     'g', &cfg.group_id,      group_id),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;

	err = nvme_endurance_log(fd, cfg.group_id, &endurance_log);
	if (!err)
		nvme_show_endurance_log(&endurance_log, cfg.group_id, devicename, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		perror("endurance log");
close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int get_effects_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Retrieve command effects log page and print the table.";
	const char *raw = "show log in binary format";
	const char *human_readable = "show log in readable format";
	struct nvme_effects_log_page effects;

	int err, fd;
	enum nvme_print_flags flags;

	struct config {
		int   raw_binary;
		int   human_readable;
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format",  'o', &cfg.output_format,  output_format),
		OPT_FLAG("human-readable",'H', &cfg.human_readable, human_readable),
		OPT_FLAG("raw-binary",    'b', &cfg.raw_binary,     raw),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;
	if (cfg.raw_binary)
		flags = BINARY;
	if (cfg.human_readable)
		flags |= VERBOSE;

	err = nvme_effects_log(fd, &effects);
	if (!err)
		nvme_show_effects_log(&effects, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		perror("effects log page");
close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
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
	int err, fd;

	struct config {
		__u32 log_entries;
		int   raw_binary;
		char *output_format;
	};

	struct config cfg = {
		.log_entries  = 64,
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_UINT("log-entries",  'e', &cfg.log_entries,   log_entries),
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,    raw),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;
	if (cfg.raw_binary)
		flags = BINARY;

	if (!cfg.log_entries) {
		fprintf(stderr, "non-zero log-entries is required param\n");
		err = -EINVAL;
		goto close_fd;
	}

	err = nvme_identify_ctrl(fd, &ctrl);
	if (err < 0) {
		perror("identify controller");
		goto close_fd;
	} else if (err) {
		fprintf(stderr, "could not identify controller\n");
		err = -ENODEV;
		goto close_fd;
	}

	cfg.log_entries = min(cfg.log_entries, ctrl.elpe + 1);
	err_log = calloc(cfg.log_entries, sizeof(struct nvme_error_log_page));
	if (!err_log) {
		perror("could not alloc buffer for error log\n");
		err = -ENOMEM;
		goto close_fd;
	}

	err = nvme_error_log(fd, cfg.log_entries, err_log);
	if (!err)
		nvme_show_error_log(err_log, cfg.log_entries, devicename, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		perror("error log");
	free(err_log);
close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int get_fw_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Retrieve the firmware log for the "\
		"specified device in either decoded format (default) or binary.";
	const char *raw = "use binary output";
	struct nvme_firmware_log_page fw_log;
	enum nvme_print_flags flags;
	int err, fd;

	struct config {
		int raw_binary;
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,    raw),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;
	if (cfg.raw_binary)
		flags = BINARY;

	err = nvme_fw_log(fd, &fw_log);
	if (!err)
		nvme_show_fw_log(&fw_log, devicename, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		perror("fw log");
close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int get_changed_ns_list_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	struct nvme_changed_ns_list_log changed_ns_list_log;
	const char *desc = "Retrieve Changed Namespaces log for the given device "\
			"in either decoded format "\
			"(default) or binary.";
	const char *raw = "output in binary format";
	enum nvme_print_flags flags;
	int err, fd;

	struct config {
		int   raw_binary;
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,    raw),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;
	if (cfg.raw_binary)
		flags = BINARY;

	err = nvme_changed_ns_list_log(fd, &changed_ns_list_log);
	if (!err)
		nvme_show_changed_ns_list_log(&changed_ns_list_log, devicename,
					      flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		perror("changed ns list log");
close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int get_pred_lat_per_nvmset_log(int argc, char **argv,
	struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Retrieve Predictable latency per nvm set log "\
			"page and prints it for the given device in either decoded " \
			"format(default),json or binary.";
	const char *nvmset_id = "NVM Set Identifier";
	const char *raw = "use binary output";
	struct nvme_predlat_per_nvmset_log_page plpns_log;
	enum nvme_print_flags flags;
	int err, fd;

	struct config {
		__u16 nvmset_id;
		char *output_format;
		int raw_binary;
	};

	struct config cfg = {
		.nvmset_id = 1,
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_SHRT("nvmset-id", 	 'i', &cfg.nvmset_id,     nvmset_id),
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_FLAG("raw-binary",   'b', &cfg.raw_binary, 	  raw),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;
	if (cfg.raw_binary)
		flags = BINARY;

	err = nvme_predictable_latency_per_nvmset_log(fd,
		cfg.nvmset_id, &plpns_log);
	if (!err)
		nvme_show_predictable_latency_per_nvmset(&plpns_log,
			cfg.nvmset_id, devicename, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		perror("predictable latency per nvm set");

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
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
	const char *rae = "Retain an Asynchronous Event";
	const char *raw = "use binary output";
	void *pea_log;
	struct nvme_id_ctrl ctrl;
	enum nvme_print_flags flags;
	int err, fd;
	__u32 log_size;

	struct config {
		__u64 log_entries;
		bool rae;
		char *output_format;
		int raw_binary;
	};

	struct config cfg = {
		.log_entries = 2044,
		.rae = false,
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_UINT("log-entries",  'e', &cfg.log_entries,   log_entries),
		OPT_FLAG("rae",          'r', &cfg.rae,           rae),
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,    raw),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;
	if (cfg.raw_binary)
		flags = BINARY;

	if (!cfg.log_entries) {
		fprintf(stderr, "non-zero log-entries is required param\n");
		err = -EINVAL;
		goto close_fd;
	}

	err = nvme_identify_ctrl(fd, &ctrl);
	if (err < 0) {
		perror("identify controller");
		goto close_fd;
	} else if (err) {
		nvme_show_status(err);
		goto close_fd;
	}

	cfg.log_entries = min(cfg.log_entries, le32_to_cpu(ctrl.nsetidmax));
	log_size = sizeof(__u64) + cfg.log_entries * sizeof(__u16);
	pea_log = calloc(log_size, 1);
	if (!pea_log) {
		perror("could not alloc buffer for predictable " \
			"latency event agggregate log entries\n");
		err = -ENOMEM;
		goto close_fd;
	}

	err = nvme_predictable_latency_event_agg_log(fd, pea_log, cfg.rae,
		log_size);
	if (!err)
		nvme_show_predictable_latency_event_agg_log(pea_log, cfg.log_entries,
			log_size, devicename, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		perror("predictable latency event gggregate log page");
	free(pea_log);

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
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
	const char *raw = "use binary output";
	void *pevent_log_info;
	struct nvme_persistent_event_log_head *pevent_log_head;
	enum nvme_print_flags flags;
	int err, fd;
	bool huge;

	struct config {
		__u8 action;
		__u32 log_len;
		int raw_binary;
		char *output_format;
	};

	struct config cfg = {
		.action = 0xff,
		.log_len = 0,
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_BYTE("action",       'a', &cfg.action,        action),
		OPT_UINT("log_len", 	 'l', &cfg.log_len,  	  log_len),
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,    raw),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;
	if (cfg.raw_binary)
		flags = BINARY;

	pevent_log_head = calloc(sizeof(*pevent_log_head), 1);
	if (!pevent_log_head) {
		perror("could not alloc buffer for persistent " \
			"event log header\n");
		err = -ENOMEM;
		goto close_fd;
	}

	err = nvme_persistent_event_log(fd, cfg.action,
			sizeof(*pevent_log_head), pevent_log_head);
	if (err < 0) {
		perror("persistent event log");
		goto close_fd;
	} else if (err) {
		nvme_show_status(err);
		goto close_fd;
	}

	if (cfg.action == NVME_PEVENT_LOG_RELEASE_CTX) {
		printf("Releasing Persistent Event Log Context\n");
		goto close_fd;
	}

	if (!cfg.log_len && cfg.action != NVME_PEVENT_LOG_EST_CTX_AND_READ) {
		cfg.log_len = le64_to_cpu(pevent_log_head->tll);
	} else if (!cfg.log_len && cfg.action == NVME_PEVENT_LOG_EST_CTX_AND_READ) {
		printf("Establishing Persistent Event Log Context\n");
		goto close_fd;
	}

	/*
	 * if header aleady read with context establish action 0x1,
	 * action shall not be 0x1 again in the subsequent request,
	 * until the current context is released by issuing action
	 * with 0x2, otherwise throws command sequence error, make
	 * it as zero to read the log page
	 */
	if (cfg.action == NVME_PEVENT_LOG_EST_CTX_AND_READ)
		cfg.action = NVME_PEVENT_LOG_READ;

	pevent_log_info = nvme_alloc(cfg.log_len, &huge);
	if (!pevent_log_info) {
		perror("could not alloc buffer for persistent event log page\n");
		err = -ENOMEM;
		goto close_fd;
	}
	err = nvme_persistent_event_log(fd, cfg.action,
		cfg.log_len, pevent_log_info);
	if (!err)
		nvme_show_persistent_event_log(pevent_log_info, cfg.action,
			cfg.log_len, devicename, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		perror("persistent event log");

	nvme_free(pevent_log_info, huge);

close_fd:
	free(pevent_log_head);
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
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
	const char *rae = "Retain an Asynchronous Event";
	const char *raw = "use binary output";
	void *endurance_log;
	struct nvme_id_ctrl ctrl;
	enum nvme_print_flags flags;
	int err, fd;
	__u32 log_size;

	struct config {
		__u64 log_entries;
		bool rae;
		char *output_format;
		int raw_binary;
	};

	struct config cfg = {
		.log_entries = 2044,
		.rae = false,
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_UINT("log-entries",  'e', &cfg.log_entries,   log_entries),
		OPT_FLAG("rae",          'r', &cfg.rae,           rae),
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,    raw),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;
	if (cfg.raw_binary)
		flags = BINARY;

	if (!cfg.log_entries) {
		fprintf(stderr, "non-zero log-entries is required param\n");
		err = -EINVAL;
		goto close_fd;
	}

	err = nvme_identify_ctrl(fd, &ctrl);
	if (err < 0) {
		perror("identify controller");
		goto close_fd;
	} else if (err) {
		fprintf(stderr, "could not identify controller\n");
		err = -ENODEV;
		goto close_fd;
	}

	cfg.log_entries = min(cfg.log_entries, le16_to_cpu(ctrl.endgidmax));
	log_size = sizeof(__u64) + cfg.log_entries * sizeof(__u16);
	endurance_log = calloc(log_size, 1);
	if (!endurance_log) {
		perror("could not alloc buffer for endurance group" \
			" event agggregate log entries\n");
		err = -ENOMEM;
		goto close_fd;
	}

	err = nvme_endurance_group_event_agg_log(fd, endurance_log, cfg.rae,
		log_size);
	if (!err)
		nvme_show_endurance_group_event_agg_log(endurance_log, cfg.log_entries,
			log_size, devicename, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		perror("endurance group event aggregate log page");
	free(endurance_log);

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int get_lba_status_log(int argc, char **argv,
		struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Retrieve Get LBA Status Info Log " \
			"and prints it, for the given device in either " \
			"decoded format(default),json or binary.";
	const char *rae = "Retain an Asynchronous Event";
	void *lab_status;
	enum nvme_print_flags flags;
	int err, fd;
	__u32 lslplen;

	struct config {
		bool rae;
		char *output_format;
	};

	struct config cfg = {
		.rae = false,
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FLAG("rae",          'r', &cfg.rae,           rae),
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;

	err = nvme_lba_status_log(fd, &lslplen, true, sizeof(__u32));
	if (err < 0) {
		perror("lba status log page");
		goto close_fd;
	} else if (err) {
		nvme_show_status(err);
		goto close_fd;
	}

	lab_status = calloc(lslplen, 1);
	if (!lab_status) {
		perror("could not alloc buffer for lba status log");
		err = -ENOMEM;
		goto close_fd;
	}

	err = nvme_lba_status_log(fd, lab_status, cfg.rae, lslplen);
	if (!err)
		nvme_show_lba_status_log(lab_status, lslplen, devicename, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		perror("lba status log page");
	free(lab_status);

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int get_resv_notif_log(int argc, char **argv,
	struct command *cmd, struct plugin *plugin)
{

	const char *desc = "Retrieve Reservation Notification " \
		"log page and prints it, for the given " \
		"device in either decoded format(default), " \
		"json or binary.";
	struct nvme_resv_notif_log resv;
	enum nvme_print_flags flags;
	int err, fd;

	struct config {
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;

	err = nvme_resv_notif_log(fd, &resv);
	if (!err)
		nvme_show_resv_notif_log(&resv, devicename, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		perror("resv notifi log");

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);

}

static int get_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Retrieve desired number of bytes "\
		"from a given log on a specified device in either "\
		"hex-dump (default) or binary format";
	const char *namespace_id = "desired namespace";
	const char *log_id = "identifier of log to retrieve";
	const char *log_len = "how many bytes to retrieve";
	const char *aen = "result of the aen, use to override log id";
	const char *lsp = "log specific field";
	const char *lpo = "log page offset specifies the location within a log page from where to start returning data";
	const char *lsi = "log specific identifier specifies an identifier that is required for a particular log page";
	const char *rae = "retain an asynchronous event";
	const char *raw = "output in raw format";
	const char *uuid_index = "UUID index";
	int err, fd;

	struct config {
		__u16 lsi;
		__u32 namespace_id;
		__u8  log_id;
		__u32 log_len;
		__u32 aen;
		__u64 lpo;
		__u8  lsp;
		__u8  uuid_index;
		int   rae;
		int   raw_binary;
	};

	struct config cfg = {
		.namespace_id = NVME_NSID_ALL,
		.log_id       = 0xff,
		.log_len      = 0,
		.lpo          = NVME_NO_LOG_LPO,
		.lsp          = NVME_NO_LOG_LSP,
		.lsi          = 0,
		.rae          = 0,
		.uuid_index   = 0,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id),
		OPT_BYTE("log-id",       'i', &cfg.log_id,       log_id),
		OPT_UINT("log-len",      'l', &cfg.log_len,      log_len),
		OPT_UINT("aen",          'a', &cfg.aen,          aen),
		OPT_SUFFIX("lpo",        'o', &cfg.lpo,          lpo),
		OPT_BYTE("lsp",          's', &cfg.lsp,          lsp),
		OPT_SHRT("lsi",          'S', &cfg.lsi,          lsi),
		OPT_FLAG("rae",          'r', &cfg.rae,          rae),
		OPT_BYTE("uuid-index",   'U', &cfg.uuid_index,   uuid_index),
		OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,   raw),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	if (cfg.aen) {
		cfg.log_len = 4096;
		cfg.log_id = (cfg.aen >> 16) & 0xff;
	}

	if (!cfg.log_len) {
		fprintf(stderr, "non-zero log-len is required param\n");
		err = -EINVAL;
	} else {
		unsigned char *log;

		log = malloc(cfg.log_len);
		if (!log) {
			perror("could not alloc buffer for log\n");
			err = -ENOMEM;
			goto close_fd;
		}

		err = nvme_get_log14(fd, cfg.namespace_id, cfg.log_id,
				     cfg.lsp, cfg.lpo, cfg.lsi, cfg.rae,
				     cfg.uuid_index, cfg.log_len, log);
		if (!err) {
			if (!cfg.raw_binary) {
				printf("Device:%s log-id:%d namespace-id:%#x\n",
				       devicename, cfg.log_id,
				       cfg.namespace_id);
				d(log, cfg.log_len, 16, 1);
			} else
				d_raw((unsigned char *)log, cfg.log_len);
		} else if (err > 0)
			nvme_show_status(err);
		else
			perror("log page");
		free(log);
	}
close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int sanitize_log(int argc, char **argv, struct command *command, struct plugin *plugin)
{
	const char *desc = "Retrieve sanitize log and show it.";
	const char *rae = "Retain an Asynchronous Event";
	const char *raw = "show log in binary format";
	const char *human_readable = "show log in readable format";
	struct nvme_sanitize_log_page sanitize_log;
	enum nvme_print_flags flags;
	int fd, err;

	struct config {
		bool  rae;
		int   raw_binary;
		int   human_readable;
		char *output_format;
	};

	struct config cfg = {
		.rae = false,
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FLAG("rae",           'r', &cfg.rae,            rae),
		OPT_FMT("output-format",  'o', &cfg.output_format,  output_format),
		OPT_FLAG("human-readable",'H', &cfg.human_readable, human_readable),
		OPT_FLAG("raw-binary",    'b', &cfg.raw_binary,     raw),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;
	if (cfg.raw_binary)
		flags = BINARY;
	if (cfg.human_readable)
		flags |= VERBOSE;

	err = nvme_sanitize_log(fd, cfg.rae, &sanitize_log);
	if (!err)
		nvme_show_sanitize_log(&sanitize_log, devicename, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		perror("sanitize status log");
close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int list_ctrl(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Show controller list information for the subsystem the "\
		"given device is part of, or optionally controllers attached to a specific namespace.";
	const char *controller = "controller to display";
	const char *namespace_id = "optional namespace attached to controller";
	int err, fd;
	struct nvme_controller_list *cntlist;
	enum nvme_print_flags flags;

	struct config {
		__u16 cntid;
		__u32 namespace_id;
		char *output_format;
	};

	struct config cfg = {
		.cntid = 0,
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_SHRT("cntid",        'c', &cfg.cntid,         controller),
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id,  namespace_id),
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;
	if (flags != JSON && flags != NORMAL) {
		err = -EINVAL;
		goto close_fd;
	}

	if (posix_memalign((void *)&cntlist, getpagesize(), 0x1000)) {
		fprintf(stderr, "can not allocate controller list payload\n");
		err = -ENOMEM;
		goto close_fd;
	}

	err = nvme_identify_ctrl_list(fd, cfg.namespace_id, cfg.cntid, cntlist);
	if (!err)
		nvme_show_list_ctrl(cntlist, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		perror("id controller list");

	free(cntlist);
close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int list_ns(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "For the specified controller handle, show the "\
		"namespace list in the associated NVMe subsystem, optionally starting with a given nsid.";
	const char *namespace_id = "first nsid returned list should start from";
	const char *csi = "I/O command set identifier";
	const char *all = "show all namespaces in the subsystem, whether attached or inactive";
	int err, fd;
	__le32 ns_list[1024];
	enum nvme_print_flags flags;

	struct config {
		__u32 namespace_id;
		int  all;
		__u8 csi;
		char *output_format;
	};

	struct config cfg = {
		.namespace_id = 1,
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id,  namespace_id),
		OPT_BYTE("csi",          'y', &cfg.csi,           csi),
		OPT_FLAG("all",          'a', &cfg.all,           all),
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format_no_binary),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;
	if (flags != JSON && flags != NORMAL) {
		err = -EINVAL;
		goto close_fd;
	}

	if (!cfg.namespace_id) {
		err = -EINVAL;
		fprintf(stderr, "invalid nsid parameter\n");
		goto close_fd;
	}

	err = nvme_identify_ns_list_csi(fd, cfg.namespace_id - 1, cfg.csi,
					!!cfg.all, ns_list);
	if (!err)
		nvme_show_list_ns(ns_list, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		perror("id namespace list");
close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
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
	const char *timeout = "timeout value, in milliseconds";
	int err, fd;

	struct config {
		__u32	namespace_id;
		__u32	timeout;
	};

	struct config cfg = {
		.namespace_id	= 0,
		.timeout	= NVME_IOCTL_TIMEOUT,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id),
		OPT_UINT("timeout",      't', &cfg.timeout,      timeout),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	if (!cfg.namespace_id) {
		err = cfg.namespace_id = nvme_get_nsid(fd);
		if (err < 0) {
			perror("get-namespace-id");
			goto close_fd;
		}
	}

	err = nvme_ns_delete(fd, cfg.namespace_id, cfg.timeout);
	if (!err)
		printf("%s: Success, deleted nsid:%d\n", cmd->name,
								cfg.namespace_id);
	else if (err > 0)
		nvme_show_status(err);
	else
		perror("delete namespace");

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int nvme_attach_ns(int argc, char **argv, int attach, const char *desc, struct command *cmd)
{
	int err, num, i, fd, list[2048];
	__u16 ctrlist[2048];

	const char *namespace_id = "namespace to attach";
	const char *cont = "optional comma-sep controller id list";

	struct config {
		char  *cntlist;
		__u32 namespace_id;
	};

	struct config cfg = {
		.cntlist = "",
		.namespace_id = 0,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id),
		OPT_LIST("controllers",  'c', &cfg.cntlist,      cont),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	if (!cfg.namespace_id) {
		fprintf(stderr, "%s: namespace-id parameter required\n",
						cmd->name);
		err = -EINVAL;
		goto close_fd;
	}

	num = argconfig_parse_comma_sep_array(cfg.cntlist, list, 2047);
	if (!num) {
		fprintf(stderr, "warning: empty controller-id list will result in no actual change in namespace attachment\n");
	}

	if (num == -1) {
		fprintf(stderr, "%s: controller id list is malformed\n",
						cmd->name);
		err = -EINVAL;
		goto close_fd;
	}

	for (i = 0; i < num; i++)
		ctrlist[i] = (uint16_t)list[i];

	err = nvme_ns_attachment(fd, cfg.namespace_id, num, ctrlist, attach);

	if (!err)
		printf("%s: Success, nsid:%d\n", cmd->name, cfg.namespace_id);
	else if (err > 0)
		nvme_show_status(err);
	else
		perror(attach ? "attach namespace" : "detach namespace");

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
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
	const char *timeout = "timeout value, in milliseconds";
	const char *bs = "target block size, specify only if \'FLBAS\' "\
		"value not entered";

	int err = 0, fd, i;
	struct nvme_id_ns ns;
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
		__u8  	csi;
	};

	struct config cfg = {
		.flbas		= 0xff,
		.anagrpid	= 0,
		.nvmsetid	= 0,
		.bs		= 0x00,
		.timeout	= NVME_IOCTL_TIMEOUT,
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
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	if (cfg.flbas != 0xff && cfg.bs != 0x00) {
		fprintf(stderr,
			"Invalid specification of both FLBAS and Block Size, please specify only one\n");
		err = -EINVAL;
		goto close_fd;
	}
	if (cfg.bs) {
		if ((cfg.bs & (~cfg.bs + 1)) != cfg.bs) {
			fprintf(stderr,
				"Invalid value for block size (%"PRIu64"). Block size must be a power of two\n",
				(uint64_t)cfg.bs);
			err = -EINVAL;
			goto close_fd;
		}
		err = nvme_identify_ns(fd, NVME_NSID_ALL, 0, &ns);
		if (err) {
			if (err < 0)
				perror("identify-namespace");
			else {
				fprintf(stderr, "identify failed\n");
				nvme_show_status(err);
			}
			goto close_fd;
		}
		for (i = 0; i < 16; ++i) {
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
		goto close_fd;
	}

	err = nvme_ns_create(fd, cfg.nsze, cfg.ncap, cfg.flbas, cfg.dps, cfg.nmic,
			    cfg.anagrpid, cfg.nvmsetid, cfg.csi, cfg.timeout,
			    &nsid);
	if (!err)
		printf("%s: Success, created nsid:%d\n", cmd->name, nsid);
	else if (err > 0)
		nvme_show_status(err);
	else
		perror("create namespace");

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int list_subsys(int argc, char **argv, struct command *cmd,
		struct plugin *plugin)
{
	struct nvme_topology t = { };
	enum nvme_print_flags flags;
	char *subsysnqn = NULL;
	const char *desc = "Retrieve information for subsystems";
	const char *verbose = "Increase output verbosity";
	__u32 ns_instance = 0;
	int err, nsid = 0;

	struct config {
		char *output_format;
		int verbose;
	};

	struct config cfg = {
		.output_format = "normal",
		.verbose = 0,
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format_no_binary),
		OPT_FLAG("verbose",      'v', &cfg.verbose,       verbose),
		OPT_END()
	};

	err = argconfig_parse(argc, argv, desc, opts);
	if (err < 0)
		goto ret;

	devicename = NULL;
	if (optind < argc) {
		char path[512];
		int id, fd;

		devicename = basename(argv[optind]);
		if (sscanf(devicename, "nvme%dn%d", &id, &ns_instance) != 2) {
			fprintf(stderr, "%s is not a NVMe namespace device\n",
				argv[optind]);
			err = -EINVAL;
			goto ret;
		}
		sprintf(path, "/dev/%s", devicename);
		fd = open(path, O_RDONLY);
		if (fd < 0) {
			fprintf(stderr, "Cannot read nsid from %s\n",
				devicename);
			err = -EINVAL;
			goto ret;
		}
		nsid = nvme_get_nsid(fd);
		close(fd);
		if (nsid < 0) {
			fprintf(stderr, "Cannot read nsid from %s\n",
				devicename);
			err = -EINVAL;
			goto ret;
		}
		sprintf(path, "/sys/block/%s/device", devicename);
		subsysnqn = get_nvme_subsnqn(path);
		if (!subsysnqn) {
			fprintf(stderr, "Cannot read subsys NQN from %s\n",
				devicename);
			err = -EINVAL;
			goto ret;
		}
		optind++;
	}

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto free;
	if (flags != JSON && flags != NORMAL) {
		err = -EINVAL;
		goto free;
	}
	if (cfg.verbose)
		flags |= VERBOSE;

	err = scan_subsystems(&t, subsysnqn, ns_instance, nsid, NULL);
	if (err) {
		fprintf(stderr, "Failed to scan namespaces\n");
		goto free;
	}
	nvme_show_subsystem_list(&t, flags);
free:
	free_topology(&t);
	free(subsysnqn);
ret:
	return nvme_status_to_errno(err, false);
}

static int list(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Retrieve basic information for all NVMe namespaces";
	const char *device_dir = "Additional directory to search for devices";
	const char *verbose = "Increase output verbosity";
	struct nvme_topology t = { };
	enum nvme_print_flags flags;
	int err = 0;

	struct config {
		char *device_dir;
		char *output_format;
		int verbose;
	};

	struct config cfg = {
		.device_dir = NULL,
		.output_format = "normal",
		.verbose = 0,
	};

	OPT_ARGS(opts) = {
		OPT_STRING("directory",  'd', "DIR",             &cfg.device_dir, device_dir),
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

	err = scan_subsystems(&t, NULL, 0, 0, cfg.device_dir);
	if (err) {
		fprintf(stderr, "Failed to scan namespaces\n");
		return err;
	}

	nvme_show_list_items(&t, flags);
	free_topology(&t);
	return 0;
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
	const char *raw = "show identify in binary format";
	const char *human_readable = "show identify in readable format";
	enum nvme_print_flags flags;
	struct nvme_id_ctrl ctrl;
	int err, fd;

	struct config {
		int vendor_specific;
		int raw_binary;
		int human_readable;
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FLAG("vendor-specific", 'v', &cfg.vendor_specific, vendor_specific),
		OPT_FMT("output-format",    'o', &cfg.output_format,   output_format),
		OPT_FLAG("raw-binary",      'b', &cfg.raw_binary,      raw),
		OPT_FLAG("human-readable",  'H', &cfg.human_readable,  human_readable),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;
	if (cfg.raw_binary)
		flags = BINARY;
	if (cfg.vendor_specific)
		flags |= VS;
	if (cfg.human_readable)
		flags |= VERBOSE;

	err = nvme_identify_ctrl(fd, &ctrl);
	if (!err)
		__nvme_show_id_ctrl(&ctrl, flags, vs);
	else if (err > 0)
		nvme_show_status(err);
	else
		perror("identify controller");
close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
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
	int fd, err = -1;

	struct config {
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format",  'o', &cfg.output_format,   output_format),
		OPT_END()
	};

	fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;

	err = nvme_identify_ctrl_nvm(fd, &ctrl_nvm);
	if (!err)
		nvme_show_id_ctrl_nvm(&ctrl_nvm, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		perror("nvm identify controller");
close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int ns_descs(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Send Namespace Identification Descriptors command to the "\
			    "given device, returns the namespace identification descriptors "\
			    "of the specific namespace in either human-readable or binary format.";
	const char *raw = "show descriptors in binary format";
	const char *namespace_id = "identifier of desired namespace";
	enum nvme_print_flags flags;
	int err, fd;
	void *nsdescs;

	struct config {
		__u32 namespace_id;
		int raw_binary;
		char *output_format;
	};

	struct config cfg = {
		.namespace_id = 0,
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id",  'n', &cfg.namespace_id,  namespace_id),
		OPT_FMT("output-format",  'o', &cfg.output_format, output_format),
		OPT_FLAG("raw-binary",    'b', &cfg.raw_binary,    raw),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;
	if (cfg.raw_binary)
		flags = BINARY;

	if (!cfg.namespace_id) {
		err = cfg.namespace_id = nvme_get_nsid(fd);
		if (err < 0) {
			perror("get-namespace-id");
			goto close_fd;
		}
	}

	if (posix_memalign(&nsdescs, getpagesize(), 0x1000)) {
		fprintf(stderr, "can not allocate controller list payload\n");
		err = -ENOMEM;
		goto close_fd;
	}

	err = nvme_identify_ns_descs(fd, cfg.namespace_id, nsdescs);
	if (!err)
		nvme_show_id_ns_descs(nsdescs, cfg.namespace_id, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		perror("identify namespace");
	free(nsdescs);
close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int id_ns(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Send an Identify Namespace command to the "\
		"given device, returns properties of the specified namespace "\
		"in either human-readable or binary format. Can also return "\
		"binary vendor-specific namespace attributes.";
	const char *force = "Return this namespace, even if not attaced (1.2 devices only)";
	const char *vendor_specific = "dump binary vendor fields";
	const char *raw = "show identify in binary format";
	const char *human_readable = "show identify in readable format";
	const char *namespace_id = "identifier of desired namespace";

	enum nvme_print_flags flags;
	struct nvme_id_ns ns;
	int err, fd;

	struct config {
		__u32 namespace_id;
		int   vendor_specific;
		int   raw_binary;
		int   human_readable;
		int   force;
		char *output_format;
	};

	struct config cfg = {
		.namespace_id    = 0,
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id",    'n', &cfg.namespace_id,    namespace_id),
		OPT_FLAG("force",           'f', &cfg.force,           force),
		OPT_FLAG("vendor-specific", 'v', &cfg.vendor_specific, vendor_specific),
		OPT_FLAG("raw-binary",      'b', &cfg.raw_binary,      raw),
		OPT_FMT("output-format",    'o', &cfg.output_format,   output_format),
		OPT_FLAG("human-readable",  'H', &cfg.human_readable,  human_readable),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;
	if (cfg.raw_binary)
		flags = BINARY;
	if (cfg.vendor_specific)
		flags |= VS;
	if (cfg.human_readable)
		flags |= VERBOSE;

	if (!cfg.namespace_id) {
		err = cfg.namespace_id = nvme_get_nsid(fd);
		if (err < 0) {
			perror("get-namespace-id");
			goto close_fd;
		}
	}

	err = nvme_identify_ns(fd, cfg.namespace_id, cfg.force, &ns);
	if (!err)
		nvme_show_id_ns(&ns, cfg.namespace_id, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		perror("identify namespace");
close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int id_ns_granularity(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Send an Identify Namespace Granularity List command to the "\
		"given device, returns namespace granularity list "\
		"in either human-readable or binary format.";

	struct nvme_id_ns_granularity_list *granularity_list;
	enum nvme_print_flags flags;
	int err, fd;

	struct config {
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;

	if (posix_memalign((void *)&granularity_list, getpagesize(), NVME_IDENTIFY_DATA_SIZE)) {
		fprintf(stderr, "can not allocate granularity list payload\n");
		err = -ENOMEM;
		goto close_fd;
	}

	err = nvme_identify_ns_granularity(fd, granularity_list);
	if (!err)
		nvme_show_id_ns_granularity_list(granularity_list, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		perror("identify namespace granularity");

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int id_nvmset(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Send an Identify NVM Set List command to the "\
		"given device, returns entries for NVM Set identifiers greater "\
		"than or equal to the value specified CDW11.NVMSETID "\
		"in either binary format or json format";
	const char *nvmset_id = "NVM Set Identify value";

	struct nvme_id_nvmset nvmset;
	enum nvme_print_flags flags;
	int err, fd;

	struct config {
		__u16 nvmset_id;
		char *output_format;
	};

	struct config cfg = {
		.nvmset_id = 0,
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_SHRT("nvmset_id",    'i', &cfg.nvmset_id,     nvmset_id),
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;

	err = nvme_identify_nvmset(fd, cfg.nvmset_id, &nvmset);
	if (!err)
		nvme_show_id_nvmset(&nvmset, cfg.nvmset_id, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		perror("identify nvm set list");

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
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
	int err, fd;

	struct config {
		int   raw_binary;
		int   human_readable;
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format",   'o', &cfg.output_format,  output_format),
		OPT_FLAG("raw-binary",     'b', &cfg.raw_binary,     raw),
		OPT_FLAG("human-readable", 'H', &cfg.human_readable, human_readable),
		OPT_END()
	};

	fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		return fd;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;
	if (cfg.raw_binary)
		flags = BINARY;
	if (cfg.human_readable)
		flags |= VERBOSE;

	err = nvme_identify_uuid(fd, &uuid_list);
	if (!err)
		nvme_show_id_uuid_list(&uuid_list, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		perror("identify UUID list");
close_fd:
	close(fd);
	return err;
}

static int id_iocs(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Send an Identify Command Set Data command to the "\
		"given device, returns properties of the specified controller "\
		"in either human-readable or binary format.";
	const char *controller_id = "identifier of desired controller";
	struct nvme_id_iocs iocs;
	int err, fd;

	struct config {
		__u16 cntid;
	};

	struct config cfg = {
		.cntid = 0xffff,
	};

	OPT_ARGS(opts) = {
		OPT_SHRT("controller-id", 'c', &cfg.cntid, controller_id),
		OPT_END()
	};

	fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0) {
		err = fd;
		goto ret;
	}

	err = nvme_identify_iocs(fd, cfg.cntid, &iocs);
	if (!err) {
		printf("NVMe Identify I/O Command Set:\n");
		nvme_show_id_iocs(&iocs);
	} else if (err > 0)
		nvme_show_status(err);
	else
		perror("NVMe Identify I/O Command Set");

	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int get_ns_id(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	int err = 0, nsid, fd;
	const char *desc = "Get namespce ID of a the block device.";

	OPT_ARGS(opts) = {
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	nsid = nvme_get_nsid(fd);
	if (nsid <= 0) {
		perror(devicename);
		err = errno;
		goto close_fd;
	}
	err = 0;
	printf("%s: namespace-id:%d\n", devicename, nsid);

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
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
	int fd, err;
	__u32 result, cdw10;

	struct config {
		__u16   cntlid;
		__u8    rt;
		__u8    act;
		__u16   nr;
	};

	struct config cfg = {
		.cntlid	  = 0,
		.rt	  = 0,
		.act	  = 0,
		.nr	  = 0,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("cntlid", 'c', &cfg.cntlid, cntlid),
		OPT_BYTE("rt",     'r', &cfg.rt,     rt),
		OPT_BYTE("act",    'a', &cfg.act,    act),
		OPT_SHRT("nr",     'n', &cfg.nr,     nr),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	cdw10 = cfg.act | (cfg.rt << 8) | (cfg.cntlid << 16);

	err = nvme_virtual_mgmt(fd, cdw10, cfg.nr, &result);
	if (!err) {
		printf("success, Number of Controller Resources Modified "\
			"(NRM):%#x\n", result);
	} else if (err > 0) {
		nvme_show_status(err);
	} else
		perror("virt-mgmt");

	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int primary_ctrl_caps(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Send an Identify Primary Controller Capabilities "\
		"command to the given device and report the information in a "\
		"decoded format (default), json or binary.";
	const char *human_readable = "show info in readable format";
	struct nvme_primary_ctrl_caps caps;

	int err, fd;
	enum nvme_print_flags flags;

	struct config {
		char *output_format;
		int human_readable;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format",   'o', &cfg.output_format,  output_format),
		OPT_FLAG("human-readable", 'H', &cfg.human_readable, human_readable),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;
	if (cfg.human_readable)
		flags |= VERBOSE;

	err = nvme_identify_primary_ctrl_caps(fd, &caps);
	if (!err)
		nvme_show_primary_ctrl_caps(&caps, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		perror("identify primary controller capabilities");
close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int list_secondary_ctrl(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Show secondary controller list associated with the primary controller "\
		"of the given device.";
	const char *controller = "lowest controller identifier to display";
	const char *namespace_id = "optional namespace attached to controller";
	const char *num_entries = "number of entries to retrieve";

	struct nvme_secondary_controllers_list *sc_list;
	enum nvme_print_flags flags;
	int err, fd;

	struct config {
		__u16 cntid;
		__u32 num_entries;
		__u32 namespace_id;
		char *output_format;
	};

	struct config cfg = {
		.cntid = 0,
		.namespace_id = 0,
		.output_format = "normal",
		.num_entries = ARRAY_SIZE(sc_list->sc_entry),
	};

	OPT_ARGS(opts) = {
		OPT_SHRT("cntid",        'c', &cfg.cntid,         controller),
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id,  namespace_id),
		OPT_UINT("num-entries",  'e', &cfg.num_entries,   num_entries),
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;

	if (!cfg.num_entries) {
		fprintf(stderr, "non-zero num-entries is required param\n");
		err = -EINVAL;
		goto close_fd;
	}

	if (posix_memalign((void *)&sc_list, getpagesize(), sizeof(*sc_list))) {
		fprintf(stderr, "can not allocate controller list payload\n");
		err = -ENOMEM;
		goto close_fd;
	}

	err = nvme_identify_secondary_ctrl_list(fd, cfg.namespace_id, cfg.cntid, sc_list);
	if (!err)
		nvme_show_list_secondary_ctrl(sc_list, cfg.num_entries, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		perror("id secondary controller list");

	free(sc_list);

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
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
	int fd, err;

	struct config {
		__u32 namespace_id;
		__u8 stc;
	};

	struct config cfg = {
		.namespace_id  = NVME_NSID_ALL,
		.stc = 0,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id",   'n', &cfg.namespace_id, namespace_id),
		OPT_BYTE("self-test-code", 's', &cfg.stc,          self_test_code),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = nvme_self_test_start(fd, cfg.namespace_id, cfg.stc);
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
		perror("Device self-test");

	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int self_test_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Retrieve the self-test log for the given device and given test "\
			"(or optionally a namespace) in either decoded format "\
			"(default) or binary.";
	const char *dst_entries = "Indicate how many DST log entries to be retrieved, "\
			"by default all the 20 entries will be retrieved";
	const char *verbose = "Increase output verbosity";

	struct nvme_self_test_log self_test_log;
	enum nvme_print_flags flags;
	int err, fd;
	__u32 log_size;

	struct config {
		__u8 dst_entries;
		char *output_format;
		int verbose;
	};

	struct config cfg = {
		.dst_entries = NVME_ST_REPORTS,
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_BYTE("dst-entries",  'e', &cfg.dst_entries,   dst_entries),
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_FLAG("verbose",      'v', &cfg.verbose,       verbose),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;
	if (cfg.verbose)
		flags |= VERBOSE;

	log_size = NVME_ST_LOG_HEAD_SIZE + cfg.dst_entries * NVME_ST_LOG_ENTRY_SIZE;
	err = nvme_self_test_log(fd, log_size, &self_test_log);
	if (!err)
		nvme_show_self_test_log(&self_test_log, cfg.dst_entries, log_size,
			devicename, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		perror("self test log");
close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int get_feature(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Read operating parameters of the "\
		"specified controller. Operating parameters are grouped "\
		"and identified by Feature Identifiers; each Feature "\
		"Identifier contains one or more attributes that may affect "\
		"behaviour of the feature. Each Feature has three possible "\
		"settings: default, saveable, and current. If a Feature is "\
		"saveable, it may be modified by set-feature. Default values "\
		"are vendor-specific and not changeable. Use set-feature to "\
		"change saveable Features.";
	const char *raw = "show feature in binary format";
	const char *namespace_id = "identifier of desired namespace";
	const char *feature_id = "feature identifier";
	const char *sel = "[0-3]: current/default/saved/supported";
	const char *data_len = "buffer len if data is returned through host memory buffer";
	const char *cdw11 = "dword 11 for interrupt vector config";
	const char *human_readable = "show feature in readable format";
	const char *uuid_index = "specify uuid index";
	int err, fd;
	__u32 result;
	void *buf = NULL;

	struct config {
		__u32 namespace_id;
		__u8  feature_id;
		__u8  sel;
		__u32 cdw11;
		__u8  uuid_index;
		__u32 data_len;
		int  raw_binary;
		int  human_readable;
	};

	struct config cfg = {
		.namespace_id = 0,
		.feature_id   = 0,
		.sel          = 0,
		.cdw11        = 0,
		.uuid_index   = 0,
		.data_len     = 0,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id",  'n', &cfg.namespace_id,   namespace_id),
		OPT_BYTE("feature-id",    'f', &cfg.feature_id,     feature_id),
		OPT_BYTE("sel",           's', &cfg.sel,            sel),
		OPT_UINT("data-len",      'l', &cfg.data_len,       data_len),
		OPT_FLAG("raw-binary",    'b', &cfg.raw_binary,     raw),
		OPT_UINT("cdw11",         'c', &cfg.cdw11,          cdw11),
		OPT_BYTE("uuid-index",    'U', &cfg.uuid_index,     uuid_index),
		OPT_FLAG("human-readable",'H', &cfg.human_readable, human_readable),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	if (!cfg.namespace_id) {
		err = cfg.namespace_id = nvme_get_nsid(fd);
		if (err < 0) {
			if (errno != ENOTTY) {
				perror("get-namespace-id");
				goto close_fd;
			}

			cfg.namespace_id = NVME_NSID_ALL;
		}
	}

	if (cfg.sel > 7) {
		fprintf(stderr, "invalid 'select' param:%d\n", cfg.sel);
		err = -EINVAL;
		goto close_fd;
	}
	if (!cfg.feature_id) {
		fprintf(stderr, "feature-id required param\n");
		err = -EINVAL;
		goto close_fd;
	}

	if (cfg.uuid_index > 128) {
		fprintf(stderr, "invalid uuid index param: %u\n", cfg.uuid_index);
		errno = EINVAL;
		err = -1;
		goto close_fd;
	}

	cfg.data_len = nvme_feat_buf_len[cfg.feature_id];

	/* check for Extended Host Identifier */
	if (cfg.feature_id == NVME_FEAT_HOST_ID && (cfg.cdw11 & 0x1))
		cfg.data_len = 16;

	if (cfg.sel == 3)
		cfg.data_len = 0;

	if (cfg.data_len) {
		if (posix_memalign(&buf, getpagesize(), cfg.data_len)) {
			fprintf(stderr, "can not allocate feature payload\n");
			err = -ENOMEM;
			goto close_fd;
		}
		memset(buf, 0, cfg.data_len);
	}

	err = nvme_get_feature(fd, cfg.namespace_id, cfg.feature_id, cfg.sel, cfg.cdw11,
			cfg.uuid_index, cfg.data_len, buf, &result);
	if (!err) {
		if (!cfg.raw_binary || !buf) {
			printf("get-feature:%#02x (%s), %s value:%#08x\n", cfg.feature_id,
				nvme_feature_to_string(cfg.feature_id),
				nvme_select_to_string(cfg.sel), result);
			if (cfg.sel == 3)
				nvme_show_select_result(result);
			else if (cfg.human_readable)
				nvme_feature_show_fields(cfg.feature_id, result, buf);
			else if (buf)
				d(buf, cfg.data_len, 16, 1);
		} else if (buf)
			d_raw(buf, cfg.data_len);
	} else if (err > 0) {
		nvme_show_status(err);
	} else
		perror("get-feature");

	free(buf);

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
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
	int err, fd, fw_fd = -1;
	unsigned int fw_size;
	struct stat sb;
	void *fw_buf, *buf;
	bool huge;

	struct config {
		char  *fw;
		__u32 xfer;
		__u32 offset;
	};

	struct config cfg = {
		.fw     = "",
		.xfer   = 4096,
		.offset = 0,
	};

	OPT_ARGS(opts) = {
		OPT_FILE("fw",     'f', &cfg.fw,     fw),
		OPT_UINT("xfer",   'x', &cfg.xfer,   xfer),
		OPT_UINT("offset", 'o', &cfg.offset, offset),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	fw_fd = open(cfg.fw, O_RDONLY);
	cfg.offset <<= 2;
	if (fw_fd < 0) {
		fprintf(stderr, "Failed to open firmware file %s: %s\n",
				cfg.fw, strerror(errno));
		err = -EINVAL;
		goto close_fd;
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
		perror("No memory for f/w size:\n");
		err = -ENOMEM;
		goto close_fw_fd;
	}

	buf = fw_buf;
	if (read(fw_fd, fw_buf, fw_size) != ((ssize_t)(fw_size))) {
		err = -errno;
		fprintf(stderr, "read :%s :%s\n", cfg.fw, strerror(errno));
		goto free;
	}

	while (fw_size > 0) {
		cfg.xfer = min(cfg.xfer, fw_size);

		err = nvme_fw_download(fd, cfg.offset, cfg.xfer, fw_buf);
		if (err < 0) {
			perror("fw-download");
			break;
		} else if (err != 0) {
			nvme_show_status(err);
			break;
		}
		fw_buf     += cfg.xfer;
		fw_size    -= cfg.xfer;
		cfg.offset += cfg.xfer;
	}
	if (!err)
		printf("Firmware download success\n");

free:
	nvme_free(buf, huge);
close_fw_fd:
	close(fw_fd);
close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
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
	int err, fd;

	struct config {
		__u8 slot;
		__u8 action;
		__u8 bpid;
	};

	struct config cfg = {
		.slot   = 0,
		.action = 0,
		.bpid   = 0,
	};

	OPT_ARGS(opts) = {
		OPT_BYTE("slot",   's', &cfg.slot,   slot),
		OPT_BYTE("action", 'a', &cfg.action, action),
		OPT_BYTE("bpid",   'b', &cfg.bpid,   bpid),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	if (cfg.slot > 7) {
		fprintf(stderr, "invalid slot:%d\n", cfg.slot);
		err = -EINVAL;
		goto close_fd;
	}
	if (cfg.action > 7 || cfg.action == 4 || cfg.action == 5) {
		fprintf(stderr, "invalid action:%d\n", cfg.action);
		err = -EINVAL;
		goto close_fd;
	}
	if (cfg.bpid > 1) {
		fprintf(stderr, "invalid boot partition id:%d\n", cfg.bpid);
		err = -EINVAL;
		goto close_fd;
	}

	err = nvme_fw_commit(fd, cfg.slot, cfg.action, cfg.bpid);
	if (err < 0)
		perror("fw-commit");
	else if (err != 0)
		switch (err & 0x7ff) {
		case NVME_SC_FW_NEEDS_CONV_RESET:
		case NVME_SC_FW_NEEDS_SUBSYS_RESET:
		case NVME_SC_FW_NEEDS_RESET:
			printf("Success activating firmware action:%d slot:%d",
			       cfg.action, cfg.slot);
			if (cfg.action == 6 || cfg.action == 7)
				printf(" bpid:%d", cfg.bpid);
			printf(", but firmware requires %s reset\n", nvme_fw_status_reset_type(err));
			break;
		default:
			nvme_show_status(err);
			break;
		}
	else {
		printf("Success committing firmware action:%d slot:%d",
		       cfg.action, cfg.slot);
		if (cfg.action == 6 || cfg.action == 7)
			printf(" bpid:%d", cfg.bpid);
		printf("\n");
	}

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int subsystem_reset(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Resets the NVMe subsystem\n";
	int err, fd;

	OPT_ARGS(opts) = {
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = nvme_subsystem_reset(fd);
	if (err < 0) {
		if (errno == ENOTTY)
			fprintf(stderr,
				"Subsystem-reset: NVM Subsystem Reset not supported.\n");
		else
			perror("Subsystem-reset");
	}

	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int reset(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Resets the NVMe controller\n";
	int err, fd;

	OPT_ARGS(opts) = {
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = nvme_reset_controller(fd);
	if (err < 0)
		perror("Reset");

	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int ns_rescan(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Rescans the NVMe namespaces\n";
	int err, fd;

	OPT_ARGS(opts) = {
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = nvme_ns_rescan(fd);
	if (err < 0)
		perror("Namespace Rescan");

	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int sanitize(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Send a sanitize command.";
	const char *no_dealloc_desc = "No deallocate after sanitize.";
	const char *oipbp_desc = "Overwrite invert pattern between passes.";
	const char *owpass_desc = "Overwrite pass count.";
	const char *ause_desc = "Allow unrestricted sanitize exit.";
	const char *sanact_desc = "Sanitize action.";
	const char *ovrpat_desc = "Overwrite pattern.";

	int fd, ret;

	struct config {
		int    no_dealloc;
		int    oipbp;
		__u8   owpass;
		int    ause;
		__u8   sanact;
		__u32  ovrpat;
	};

	struct config cfg = {
		.no_dealloc = 0,
		.oipbp = 0,
		.owpass = 0,
		.ause = 0,
		.sanact = 0,
		.ovrpat = 0,
	};

	OPT_ARGS(opts) = {
		OPT_FLAG("no-dealloc", 'd', &cfg.no_dealloc, no_dealloc_desc),
		OPT_FLAG("oipbp",      'i', &cfg.oipbp,      oipbp_desc),
		OPT_BYTE("owpass",     'n', &cfg.owpass,     owpass_desc),
		OPT_FLAG("ause",       'u', &cfg.ause,       ause_desc),
		OPT_BYTE("sanact",     'a', &cfg.sanact,     sanact_desc),
		OPT_UINT("ovrpat",     'p', &cfg.ovrpat,     ovrpat_desc),
		OPT_END()
	};

	ret = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	switch (cfg.sanact) {
	case NVME_SANITIZE_ACT_CRYPTO_ERASE:
	case NVME_SANITIZE_ACT_BLOCK_ERASE:
	case NVME_SANITIZE_ACT_EXIT:
	case NVME_SANITIZE_ACT_OVERWRITE:
		break;
	default:
		fprintf(stderr, "Invalid Sanitize Action\n");
		ret = -EINVAL;
		goto close_fd;
	}

	if (cfg.sanact == NVME_SANITIZE_ACT_EXIT) {
	       if (cfg.ause || cfg.no_dealloc) {
			fprintf(stderr, "SANACT is Exit Failure Mode\n");
			ret = -EINVAL;
			goto close_fd;
	       }
	}

	if (cfg.sanact == NVME_SANITIZE_ACT_OVERWRITE) {
		if (cfg.owpass >= 16) {
			fprintf(stderr, "OWPASS out of range [0-15]\n");
			ret = -EINVAL;
			goto close_fd;
		}
	} else {
		if (cfg.owpass || cfg.oipbp || cfg.ovrpat) {
			fprintf(stderr, "SANACT is not Overwrite\n");
			ret = -EINVAL;
			goto close_fd;
		}
	}

	ret = nvme_sanitize(fd, cfg.sanact, cfg.ause, cfg.owpass, cfg.oipbp,
			    cfg.no_dealloc, cfg.ovrpat);
	if (ret < 0)
		perror("sanitize");
	else if (ret > 0)
		nvme_show_status(ret);

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(ret, false);
}

static int show_registers(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Reads and shows the defined NVMe controller registers "\
					"in binary or human-readable format";
	const char *human_readable = "show info in readable format in case of "\
					"output_format == normal";

	enum nvme_print_flags flags;
	bool fabrics = true;
	int fd, err;
	void *bar;

	struct config {
		int human_readable;
		char *output_format;
	};

	struct config cfg = {
		.human_readable = 0,
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format",  'o', &cfg.output_format,  output_format),
		OPT_FLAG("human-readable",'H', &cfg.human_readable, human_readable),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;
	if (cfg.human_readable)
		flags |= VERBOSE;

	err = nvme_get_properties(fd, &bar);
	if (err) {
		bar = mmap_registers(devicename);
		fabrics = false;
		if (bar)
			err = 0;
	}
	if (!bar)
		goto close_fd;

	nvme_show_ctrl_registers(bar, fabrics, flags);
	if (fabrics)
		free(bar);
	else
		munmap(bar, getpagesize());
close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int get_property(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Reads and shows the defined NVMe controller property "\
			   "for NVMe over Fabric. Property offset must be one of:\n"
			   "CAP=0x0, VS=0x8, CC=0x14, CSTS=0x1c, NSSR=0x20";
	const char *offset = "offset of the requested property";
	const char *human_readable = "show property in readable format";

	int fd, err;
	uint64_t value;

	struct config {
		int offset;
		int human_readable;
	};

	struct config cfg = {
		.offset = -1,
		.human_readable = 0,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("offset",        'o', &cfg.offset,         offset),
		OPT_FLAG("human-readable",'H', &cfg.human_readable, human_readable),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	if (cfg.offset == -1) {
		fprintf(stderr, "offset required param\n");
		err = -EINVAL;
		goto close_fd;
	}

	err = nvme_get_property(fd, cfg.offset, &value);
	if (err < 0) {
		perror("get-property");
	} else if (!err) {
		nvme_show_single_property(cfg.offset, value, cfg.human_readable);
	} else if (err > 0) {
		nvme_show_status(err);
	}

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int set_property(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Writes and shows the defined NVMe controller property "\
			   "for NVMe ove Fabric";
	const char *offset = "the offset of the property";
	const char *value = "the value of the property to be set";
	int fd, err;

	struct config {
		int offset;
		int value;
	};

	struct config cfg = {
		.offset = -1,
		.value = -1,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("offset", 'o', &cfg.offset, offset),
		OPT_UINT("value",  'v', &cfg.value,  value),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	if (cfg.offset == -1) {
		fprintf(stderr, "offset required param\n");
		err = -EINVAL;
		goto close_fd;
	}
	if (cfg.value == -1) {
		fprintf(stderr, "value required param\n");
		err = -EINVAL;
		goto close_fd;
	}

	err = nvme_set_property(fd, cfg.offset, cfg.value);
	if (err < 0) {
		perror("set-property");
	} else if (!err) {
		printf("set-property: %02x (%s), value: %#08x\n", cfg.offset,
				nvme_register_to_string(cfg.offset), cfg.value);
	} else if (err > 0) {
		nvme_show_status(err);
	}

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int format(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Re-format a specified namespace on the "\
		"given device. Can erase all data in namespace (user "\
		"data erase) or delete data encryption key if specified. "\
		"Can also be used to change LBAF to change the namespaces reported physical block format.";
	const char *namespace_id = "identifier of desired namespace";
	const char *lbaf = "LBA format to apply (required)";
	const char *ses = "[0-2]: secure erase";
	const char *pil = "[0-1]: protection info location last/first 8 bytes of metadata";
	const char *pi = "[0-3]: protection info off/Type 1/Type 2/Type 3";
	const char *ms = "[0-1]: extended format off/on";
	const char *reset = "Automatically reset the controller after successful format";
	const char *timeout = "timeout value, in milliseconds";
	const char *bs = "target block size";
	const char *force = "The \"I know what I'm doing\" flag, skip confirmation before sending command";
	struct nvme_id_ns ns;
	struct nvme_id_ctrl ctrl;
	int err, fd, i;
	int block_size;
	__u8 prev_lbaf = 0;

	struct config {
		__u32 namespace_id;
		__u32 timeout;
		__u8  lbaf;
		__u8  ses;
		__u8  pi;
		__u8  pil;
		__u8  ms;
		__u64 bs;
		int reset;
		int force;
	};

	struct config cfg = {
		.namespace_id = 0,
		.timeout      = 600000,
		.lbaf         = 0xff,
		.ses          = 0,
		.pi           = 0,
		.reset        = 0,
		.force        = 0,
		.bs           = 0,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id),
		OPT_UINT("timeout",      't', &cfg.timeout,      timeout),
		OPT_BYTE("lbaf",         'l', &cfg.lbaf,         lbaf),
		OPT_BYTE("ses",          's', &cfg.ses,          ses),
		OPT_BYTE("pi",           'i', &cfg.pi,           pi),
		OPT_BYTE("pil",          'p', &cfg.pil,          pil),
		OPT_BYTE("ms",           'm', &cfg.ms,           ms),
		OPT_FLAG("reset",        'r', &cfg.reset,        reset),
		OPT_FLAG("force",        'f', &cfg.force,        force),
		OPT_SUFFIX("block-size", 'b', &cfg.bs,           bs),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	if (cfg.lbaf != 0xff && cfg.bs !=0) {
		fprintf(stderr,
			"Invalid specification of both LBAF and Block Size, please specify only one\n");
		err = -EINVAL;
		goto close_fd;
	}
	if (cfg.bs) {
		if ((cfg.bs & (~cfg.bs + 1)) != cfg.bs) {
			fprintf(stderr,
				"Invalid value for block size (%"PRIu64"), must be a power of two\n",
				       (uint64_t) cfg.bs);
			err = -EINVAL;
			goto close_fd;
		}
	}

	err = nvme_identify_ctrl(fd, &ctrl);
	if (err) {
		perror("identify-ctrl");
		goto close_fd;
	}

	if ((ctrl.fna & 1) == 1) {
		/*
		 * FNA bit 0 set to 1: all namespaces ... shall be configured with the same
		 * attributes and a format (excluding secure erase) of any namespace results in a
		 * format of all namespaces.
		 */
		cfg.namespace_id = NVME_NSID_ALL;
	} else if (!cfg.namespace_id) {
		err = cfg.namespace_id = nvme_get_nsid(fd);
		if (err < 0) {
			perror("get-namespace-id");
			goto close_fd;
		}
	}

	if (cfg.namespace_id == 0) {
		fprintf(stderr,
			"Invalid namespace ID, "
			"specify a namespace to format or use '-n 0xffffffff' "
			"to format all namespaces on this controller.\n");
		err = -EINVAL;
		goto close_fd;
	}

	if (cfg.namespace_id != NVME_NSID_ALL) {
		err = nvme_identify_ns(fd, cfg.namespace_id, 0, &ns);
		if (err) {
			if (err < 0)
				perror("identify-namespace");
			else {
				fprintf(stderr, "identify failed\n");
				nvme_show_status(err);
			}
			goto close_fd;
		}
		prev_lbaf = ns.flbas & 0xf;

		if (cfg.bs) {
			for (i = 0; i < 16; ++i) {
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
				goto close_fd;
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
		goto close_fd;
	}
	if (cfg.lbaf > 15) {
		fprintf(stderr, "invalid lbaf:%d\n", cfg.lbaf);
		err = -EINVAL;
		goto close_fd;
	}
	if (cfg.pi > 7) {
		fprintf(stderr, "invalid pi:%d\n", cfg.pi);
		err = -EINVAL;
		goto close_fd;
	}
	if (cfg.pil > 1) {
		fprintf(stderr, "invalid pil:%d\n", cfg.pil);
		err = -EINVAL;
		goto close_fd;
	}
	if (cfg.ms > 1) {
		fprintf(stderr, "invalid ms:%d\n", cfg.ms);
		err = -EINVAL;
		goto close_fd;
	}

	if (!cfg.force) {
		fprintf(stderr, "You are about to format %s, namespace %#x%s.\n",
			devicename, cfg.namespace_id,
			cfg.namespace_id == NVME_NSID_ALL ? "(ALL namespaces)" : "");
		nvme_show_relatives(devicename);
		fprintf(stderr, "WARNING: Format may irrevocably delete this device's data.\n"
			"You have 10 seconds to press Ctrl-C to cancel this operation.\n\n"
			"Use the force [--force|-f] option to suppress this warning.\n");
		sleep(10);
		fprintf(stderr, "Sending format operation ... \n");
	}

	err = nvme_format(fd, cfg.namespace_id, cfg.lbaf, cfg.ses, cfg.pi,
				cfg.pil, cfg.ms, cfg.timeout);
	if (err < 0)
		perror("format");
	else if (err != 0)
		nvme_show_status(err);
	else {
		printf("Success formatting namespace:%x\n", cfg.namespace_id);
		if (cfg.lbaf != prev_lbaf){
			if (is_chardev()) {
				if(ioctl(fd, NVME_IOCTL_RESCAN) < 0){
					fprintf(stderr, "failed to rescan namespaces\n");
					err = -errno;
					goto close_fd;
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
				if (ioctl(fd, BLKBSZSET, &block_size) < 0) {
					fprintf(stderr, "failed to set block size to %d\n",
							block_size);
					err = -errno;
					goto close_fd;
				}

				if(ioctl(fd, BLKRRPART) < 0) {
					fprintf(stderr, "failed to re-read partition table\n");
					err = -errno;
					goto close_fd;
				}
			}
		}
		if (cfg.reset && is_chardev())
			nvme_reset_controller(fd);
	}

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
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
	const char *namespace_id = "desired namespace";
	const char *feature_id = "feature identifier (required)";
	const char *data_len = "buffer length if data required";
	const char *data = "optional file for feature data (default stdin)";
	const char *value = "new value of feature (required)";
	const char *cdw12 = "feature cdw12, if used";
	const char *save = "specifies that the controller shall save the attribute";
	const char *uuid_index = "specify uuid index";
	int err;
	__u32 result;
	void *buf = NULL;
	int fd, ffd = STDIN_FILENO;
	char *endptr = NULL;
	uint64_t number = 0;

	struct config {
		char *file;
		__u32 namespace_id;
		__u8  feature_id;
		__u64 value;
		__u32 cdw12;
		__u8  uuid_index;
		__u32 data_len;
		int   save;
	};

	struct config cfg = {
		.file         = "",
		.namespace_id = 0,
		.feature_id   = 0,
		.value        = 0,
		.uuid_index   = 0,
		.data_len     = 0,
		.save         = 0,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id),
		OPT_BYTE("feature-id",   'f', &cfg.feature_id,   feature_id),
		OPT_SUFFIX("value",      'v', &cfg.value,        value),
		OPT_UINT("cdw12",        'c', &cfg.cdw12,        cdw12),
		OPT_BYTE("uuid-index",   'U', &cfg.uuid_index,   uuid_index),
		OPT_UINT("data-len",     'l', &cfg.data_len,     data_len),
		OPT_FILE("data",         'd', &cfg.file,         data),
		OPT_FLAG("save",         's', &cfg.save,         save),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	if (!cfg.namespace_id) {
		err = cfg.namespace_id = nvme_get_nsid(fd);
		if (err < 0) {
			if (errno != ENOTTY) {
				perror("get-namespace-id");
				goto close_fd;
			}

			cfg.namespace_id = NVME_NSID_ALL;
		}
	}

	if (!cfg.feature_id) {
		fprintf(stderr, "feature-id required param\n");
		err = -EINVAL;
		goto close_fd;
	}

	if (cfg.uuid_index > 128) {
		fprintf(stderr, "invalid uuid index param: %u\n", cfg.uuid_index);
		errno = EINVAL;
		err = -1;
		goto close_fd;
	}

	cfg.data_len = nvme_feat_buf_len[cfg.feature_id];

	if (cfg.data_len) {
		if (posix_memalign(&buf, getpagesize(), cfg.data_len)) {
			fprintf(stderr, "can not allocate feature payload\n");
			err = -ENOMEM;
			goto close_fd;
		}
		memset(buf, 0, cfg.data_len);
	}

	if (buf) {
	  /* if feature ID is 0x0E, get timestamp value by -v option */
        if (NVME_FEAT_TIMESTAMP == cfg.feature_id && cfg.value) {
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
	      /* if feature ID is 0x0E, then change string from file to integer */
            if (NVME_FEAT_TIMESTAMP == cfg.feature_id) {
                number = strtoul(buf, &endptr, STRTOUL_AUTO_BASE);
                memset(buf, 0, cfg.data_len);
                memcpy(buf, &number, NVME_FEAT_TIMESTAMP_DATA_SIZE);
            }
        }
	}

	err = nvme_set_feature(fd, cfg.namespace_id, cfg.feature_id, cfg.value,
			       cfg.cdw12, cfg.save, cfg.uuid_index, cfg.data_len, buf, &result);
	if (err < 0) {
		perror("set-feature");
	} else if (!err) {
		printf("set-feature:%#02x (%s), value:%#08"PRIx64", cdw12:%#08"PRIx32", \
			save:%#x\n", cfg.feature_id, nvme_feature_to_string(cfg.feature_id),
			(uint64_t)cfg.value, cfg.cdw12, cfg.save);
		if (cfg.feature_id == NVME_LBA_STATUS_INFO) {
			nvme_show_lba_status_info(result);
		}
		if (buf) {
			if (cfg.feature_id == NVME_FEAT_LBA_RANGE)
				nvme_show_lba_range((struct nvme_lba_range_type *)buf,
								result);
			else
				d(buf, cfg.data_len, 16, 1);
		}
	} else if (err > 0)
		nvme_show_status(err);

close_ffd:
	close(ffd);
free:
	free(buf);
close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
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
	const char *secp = "security protocol (cf. SPC-4)";
	const char *spsp = "security-protocol-specific (cf. SPC-4)";
	const char *tl = "transfer length (cf. SPC-4)";
	const char *namespace_id = "desired namespace";
	const char *nssf = "NVMe Security Specific Field";
	int err, fd, sec_fd = -1;
	void *sec_buf;
	unsigned int sec_size;

	struct config {
		__u32 namespace_id;
		char  *file;
		__u8  nssf;
		__u8  secp;
		__u16 spsp;
		__u32 tl;
	};

	struct config cfg = {
		.file = "",
		.secp = 0,
		.spsp = 0,
		.tl   = 0,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id),
		OPT_FILE("file",         'f', &cfg.file,         file),
		OPT_BYTE("nssf",         'N', &cfg.nssf,         nssf),
		OPT_BYTE("secp",         'p', &cfg.secp,         secp),
		OPT_SHRT("spsp",         's', &cfg.spsp,         spsp),
		OPT_UINT("tl",           't', &cfg.tl,           tl),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	sec_fd = open(cfg.file, O_RDONLY);
	if (sec_fd < 0) {
		fprintf(stderr, "Failed to open %s: %s\n",
				cfg.file, strerror(errno));
		err = -EINVAL;
		goto close_fd;
	}

	err = fstat(sec_fd, &sb);
	if (err < 0) {
		perror("fstat");
		goto close_sec_fd;
	}

	sec_size = sb.st_size;
	if (posix_memalign(&sec_buf, getpagesize(), sec_size)) {
		fprintf(stderr, "No memory for security size:%d\n", sec_size);
		err = -ENOMEM;
		goto close_sec_fd;
	}

	err = read(sec_fd, sec_buf, sec_size);
	if (err < 0) {
		err = -errno;
		fprintf(stderr, "Failed to read data from security file"
				" %s with %s\n", cfg.file, strerror(errno));
		goto free;
	}

	err = nvme_sec_send(fd, cfg.namespace_id, cfg.nssf, cfg.spsp, cfg.secp,
			cfg.tl, sec_size, sec_buf);
	if (err < 0)
		perror("security-send");
	else if (err != 0)
		nvme_show_status(err);
	else
		printf("NVME Security Send Command Success\n");

free:
	free(sec_buf);
close_sec_fd:
	close(sec_fd);
close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int dir_send(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Set directive parameters of the "\
			    "specified directive type.";
	const char *raw = "show directive in binary format";
	const char *namespace_id = "identifier of desired namespace";
	const char *data_len = "buffer len (if) data is returned";
	const char *dtype = "directive type";
	const char *dspec = "directive specification associated with directive type";
	const char *doper = "directive operation";
	const char *endir = "directive enable";
	const char *ttype = "target directive type to be enabled/disabled";
	const char *human_readable = "show directive in readable format";
	int err, fd;
	__u32 result;
	__u32 dw12 = 0;
	void *buf = NULL;
	int ffd = STDIN_FILENO;

	struct config {
		char *file;
		__u32 namespace_id;
		__u32 data_len;
		__u16 dspec;
		__u8  dtype;
		__u8  doper;
		__u16 endir;
		__u8  ttype;
		int  raw_binary;
		int  human_readable;
	};

	struct config cfg = {
		.file         = "",
		.namespace_id = 1,
		.data_len     = 0,
		.dspec        = 0,
		.dtype        = 0,
		.ttype        = 0,
		.doper        = 0,
		.endir        = 1,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id",  'n', &cfg.namespace_id,   namespace_id),
		OPT_UINT("data-len",      'l', &cfg.data_len,       data_len),
		OPT_BYTE("dir-type",      'D', &cfg.dtype,          dtype),
		OPT_BYTE("target-dir",    'T', &cfg.ttype,          ttype),
		OPT_SHRT("dir-spec",      'S', &cfg.dspec,          dspec),
		OPT_BYTE("dir-oper",      'O', &cfg.doper,          doper),
		OPT_SHRT("endir",         'e', &cfg.endir,          endir),
		OPT_FLAG("human-readable",'H', &cfg.human_readable, human_readable),
		OPT_FLAG("raw-binary",    'b', &cfg.raw_binary,     raw),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	switch (cfg.dtype) {
	case NVME_DIR_IDENTIFY:
		switch (cfg.doper) {
		case NVME_DIR_SND_ID_OP_ENABLE:
			if (!cfg.ttype) {
				fprintf(stderr, "target-dir required param\n");
				err = -EINVAL;
				goto close_fd;
			}
			dw12 = cfg.ttype << 8 | cfg.endir;
			break;
		default:
			fprintf(stderr, "invalid directive operations for Identify Directives\n");
			err = -EINVAL;
			goto close_fd;
		}
		break;
	case NVME_DIR_STREAMS:
		switch (cfg.doper) {
		case NVME_DIR_SND_ST_OP_REL_ID:
		case NVME_DIR_SND_ST_OP_REL_RSC:
			break;
		default:
			fprintf(stderr, "invalid directive operations for Streams Directives\n");
			err = -EINVAL;
			goto close_fd;
		}
		break;
	default:
		fprintf(stderr, "invalid directive type\n");
		err = -EINVAL;
		goto close_fd;
	}


	if (cfg.data_len) {
		if (posix_memalign(&buf, getpagesize(), cfg.data_len)) {
			err = -ENOMEM;
			goto close_fd;
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

	err = nvme_dir_send(fd, cfg.namespace_id, cfg.dspec, cfg.dtype, cfg.doper,
			cfg.data_len, dw12, buf, &result);
	if (err < 0) {
		perror("dir-send");
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
close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int write_uncor(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	int err, fd;
	const char *desc = "The Write Uncorrectable command is used to set a "\
			"range of logical blocks to invalid.";
	const char *namespace_id = "desired namespace";
	const char *start_block = "64-bit LBA of first block to access";
	const char *block_count = "number of blocks (zeroes based) on device to access";

	struct config {
		__u64 start_block;
		__u32 namespace_id;
		__u16 block_count;
	};

	struct config cfg = {
		.start_block     = 0,
		.namespace_id    = 0,
		.block_count     = 0,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id",  'n', &cfg.namespace_id, namespace_id),
		OPT_SUFFIX("start-block", 's', &cfg.start_block,  start_block),
		OPT_SHRT("block-count",   'c', &cfg.block_count,  block_count),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	if (!cfg.namespace_id) {
		err = cfg.namespace_id = nvme_get_nsid(fd);
		if (err < 0) {
			perror("get-namespace-id");
			goto close_fd;
		}
	}

	err = nvme_write_uncorrectable(fd, cfg.namespace_id, cfg.start_block,
					cfg.block_count);
	if (err < 0)
		perror("write uncorrectable");
	else if (err != 0)
		nvme_show_status(err);
	else
		printf("NVME Write Uncorrectable Success\n");

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int write_zeroes(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	int err, fd;
	__u16 control = 0;
	const char *desc = "The Write Zeroes command is used to set a "\
			"range of logical blocks to zero.";
	const char *namespace_id = "desired namespace";
	const char *start_block = "64-bit LBA of first block to access";
	const char *block_count = "number of blocks (zeroes based) on device to access";
	const char *limited_retry = "limit media access attempts";
	const char *force = "force device to commit data before command completes";
	const char *prinfo = "PI and check field";
	const char *ref_tag = "reference tag (for end to end PI)";
	const char *app_tag_mask = "app tag mask (for end to end PI)";
	const char *app_tag = "app tag (for end to end PI)";
	const char *deac = "Set DEAC bit, requesting controller to deallocate specified logical blocks";

	struct config {
		__u64 start_block;
		__u32 namespace_id;
		__u32 ref_tag;
		__u16 app_tag;
		__u16 app_tag_mask;
		__u16 block_count;
		__u8  prinfo;
		int   deac;
		int   limited_retry;
		int   force_unit_access;
	};

	struct config cfg = {
		.start_block     = 0,
		.block_count     = 0,
		.prinfo          = 0,
		.ref_tag         = 0,
		.app_tag_mask    = 0,
		.app_tag         = 0,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id",      'n', &cfg.namespace_id,      namespace_id),
		OPT_SUFFIX("start-block",     's', &cfg.start_block,       start_block),
		OPT_SHRT("block-count",       'c', &cfg.block_count,       block_count),
		OPT_FLAG("deac",              'd', &cfg.deac,              deac),
		OPT_FLAG("limited-retry",     'l', &cfg.limited_retry,     limited_retry),
		OPT_FLAG("force-unit-access", 'f', &cfg.force_unit_access, force),
		OPT_BYTE("prinfo",            'p', &cfg.prinfo,            prinfo),
		OPT_UINT("ref-tag",           'r', &cfg.ref_tag,           ref_tag),
		OPT_SHRT("app-tag-mask",      'm', &cfg.app_tag_mask,      app_tag_mask),
		OPT_SHRT("app-tag",           'a', &cfg.app_tag,           app_tag),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	if (cfg.prinfo > 0xf) {
		err = -EINVAL;
		goto close_fd;
	}

	control |= (cfg.prinfo << 10);
	if (cfg.limited_retry)
		control |= NVME_RW_LR;
	if (cfg.force_unit_access)
		control |= NVME_RW_FUA;
	if (cfg.deac)
		control |= NVME_RW_DEAC;
	if (!cfg.namespace_id) {
		err = cfg.namespace_id = nvme_get_nsid(fd);
		if (err < 0) {
			perror("get-namespace-id");
			goto close_fd;
		}
	}

	err = nvme_write_zeros(fd, cfg.namespace_id, cfg.start_block, cfg.block_count,
			control, cfg.ref_tag, cfg.app_tag, cfg.app_tag_mask);
	if (err < 0)
		perror("write-zeroes");
	else if (err != 0)
		nvme_show_status(err);
	else
		printf("NVME Write Zeroes Success\n");

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int dsm(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "The Dataset Management command is used by the host to "\
		"indicate attributes for ranges of logical blocks. This includes attributes "\
		"for discarding unused blocks, data read and write frequency, access size, and other "\
		"information that may be used to optimize performance and reliability.";
	const char *namespace_id = "identifier of desired namespace";
	const char *blocks = "Comma separated list of the number of blocks in each range";
	const char *starting_blocks = "Comma separated list of the starting block in each range";
	const char *context_attrs = "Comma separated list of the context attributes in each range";
	const char *ad = "Attribute Deallocate";
	const char *idw = "Attribute Integral Dataset for Write";
	const char *idr = "Attribute Integral Dataset for Read";
	const char *cdw11 = "All the command DWORD 11 attributes. Use instead of specifying individual attributes";

	int err, fd;
	uint16_t nr, nc, nb, ns;
	int ctx_attrs[256] = {0,};
	int nlbs[256] = {0,};
	unsigned long long slbas[256] = {0,};
	struct nvme_dsm_range *dsm;

	struct config {
		char  *ctx_attrs;
		char  *blocks;
		char  *slbas;
		int   ad;
		int   idw;
		int   idr;
		__u32 cdw11;
		__u32 namespace_id;
	};

	struct config cfg = {
		.ctx_attrs = "",
		.blocks = "",
		.slbas = "",
		.namespace_id = 0,
		.ad = 0,
		.idw = 0,
		.idr = 0,
		.cdw11 = 0,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id),
		OPT_LIST("ctx-attrs",    'a', &cfg.ctx_attrs,    context_attrs),
		OPT_LIST("blocks", 	 'b', &cfg.blocks,       blocks),
		OPT_LIST("slbs", 	 's', &cfg.slbas,        starting_blocks),
		OPT_FLAG("ad", 	         'd', &cfg.ad,           ad),
		OPT_FLAG("idw", 	 'w', &cfg.idw,          idw),
		OPT_FLAG("idr", 	 'r', &cfg.idr,          idr),
		OPT_UINT("cdw11",        'c', &cfg.cdw11,        cdw11),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	nc = argconfig_parse_comma_sep_array(cfg.ctx_attrs, ctx_attrs, ARRAY_SIZE(ctx_attrs));
	nb = argconfig_parse_comma_sep_array(cfg.blocks, nlbs, ARRAY_SIZE(nlbs));
	ns = argconfig_parse_comma_sep_array_long(cfg.slbas, slbas, ARRAY_SIZE(slbas));
	nr = max(nc, max(nb, ns));
	if (!nr || nr > 256) {
		fprintf(stderr, "No range definition provided\n");
		err = -EINVAL;
		goto close_fd;
	}

	if (!cfg.namespace_id) {
		err = cfg.namespace_id = nvme_get_nsid(fd);
		if (err < 0) {
			perror("get-namespace-id");
			goto close_fd;
		}
	}
	if (!cfg.cdw11)
		cfg.cdw11 = (cfg.ad << 2) | (cfg.idw << 1) | (cfg.idr << 0);

	dsm = nvme_setup_dsm_range(ctx_attrs, nlbs, slbas, nr);
	if (!dsm) {
		fprintf(stderr, "failed to allocate data set payload\n");
		err = -ENOMEM;
		goto close_fd;
	}

	err = nvme_dsm(fd, cfg.namespace_id, cfg.cdw11, dsm, nr);
	if (err < 0)
		perror("data-set management");
	else if (err != 0)
		nvme_show_status(err);
	else
		printf("NVMe DSM: success\n");

	free(dsm);

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int copy(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "The Copy command is used by the host to copy data "
			   "from one or more source logical block ranges to a "
			   "single consecutive destination logical block "
			   "range.";

	const char *d_nsid = "identifier of desired namespace";
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

	int err, fd;
	uint16_t nr, nb, ns, nrts, natms, nats;
	int nlbs[128] = { 0 };
	unsigned long long slbas[128] = {0,};
	int eilbrts[128] = { 0 };
	int elbatms[128] = { 0 };
	int elbats[128] = { 0 };
	struct nvme_copy_range *copy;

	struct config {
		__u32 namespace_id;
		__u64 sdlba;
		char  *nlbs;
		char  *slbas;
		__u32 ilbrt;
		char  *eilbrts;
		__u16 lbatm;
		char  *elbatms;
		__u16 lbat;
		char  *elbats;
		__u8  prinfow;
		__u8  prinfor;
		int   lr;
		int   fua;
		__u8  dtype;
		__u16 dspec;
		__u8  format;
	};

	struct config cfg = {
		.namespace_id = 0,
		.nlbs    = "",
		.slbas   = "",
		.eilbrts = "",
		.elbatms = "",
		.elbats  = "",
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id",	   'n', &cfg.namespace_id, 	d_nsid),
		OPT_SUFFIX("sdlba",                'd', &cfg.sdlba,   		d_sdlba),
		OPT_LIST("slbs",                   's', &cfg.slbas,   		d_slbas),
		OPT_LIST("blocks",                 'b', &cfg.nlbs,    		d_nlbs),
		OPT_FLAG("limited-retry",          'l', &cfg.lr,      		d_lr),
		OPT_FLAG("force-unit-access",      'f', &cfg.fua,     		d_fua),
		OPT_BYTE("prinfow",                'p', &cfg.prinfow, 		d_prinfow),
		OPT_BYTE("prinfor",                'P', &cfg.prinfor, 		d_prinfor),
		OPT_UINT("ref-tag",                'r', &cfg.ilbrt,   		d_ilbrt),
		OPT_LIST("expected-ref-tags",      'R', &cfg.eilbrts, 		d_eilbrts),
		OPT_SHRT("app-tag",                'a', &cfg.lbat,    		d_lbat),
		OPT_LIST("expected-app-tags",      'A', &cfg.elbats,  		d_elbats),
		OPT_SHRT("app-tag-mask",           'm', &cfg.lbatm,   		d_lbatm),
		OPT_LIST("expected-app-tag-masks", 'M', &cfg.elbatms, 		d_elbatms),
		OPT_BYTE("dir-type",               'T', &cfg.dtype,   		d_dtype),
		OPT_SHRT("dir-spec",               'S', &cfg.dspec,   		d_dspec),
		OPT_BYTE("format",                 'F', &cfg.format,  		d_format),
		OPT_END()
	};

	fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0) {
		err = fd;
		goto ret;
	}

	nb = argconfig_parse_comma_sep_array(cfg.nlbs, nlbs, ARRAY_SIZE(nlbs));
	ns = argconfig_parse_comma_sep_array_long(cfg.slbas, slbas, ARRAY_SIZE(slbas));
	nrts = argconfig_parse_comma_sep_array(cfg.eilbrts, eilbrts, ARRAY_SIZE(eilbrts));
	natms = argconfig_parse_comma_sep_array(cfg.elbatms, elbatms, ARRAY_SIZE(elbatms));
	nats = argconfig_parse_comma_sep_array(cfg.elbats, elbats, ARRAY_SIZE(elbats));

	nr = max(nb, max(ns, max(nrts, max(natms, nats))));
	if (!nr || nr > 128) {
		fprintf(stderr, "invalid range\n");
		err = -EINVAL;
		goto close_fd;
	}

	if (!cfg.namespace_id) {
		err = cfg.namespace_id = nvme_get_nsid(fd);
		if (err < 0) {
			perror("get-namespace-id");
			goto close_fd;
		}
	}

	copy = nvme_setup_copy_range(nlbs, slbas, eilbrts, elbatms, elbats, nr);
	if (!copy) {
		fprintf(stderr, "failed to allocate payload\n");
		err = -ENOMEM;
		goto close_fd;
	}

	err = nvme_copy(fd, cfg.namespace_id, copy, cfg.sdlba, nr, cfg.prinfor,
			cfg.prinfow, cfg.dtype, cfg.dspec, cfg.format, cfg.lr,
			cfg.fua, cfg.ilbrt, cfg.lbatm, cfg.lbat);
	if (err < 0)
		perror("NVMe Copy");
	else if (err != 0)
		nvme_show_status(err);
	else
		printf("NVMe Copy: success\n");

	free(copy);

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int flush(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Commit data and metadata associated with "\
		"given namespaces to nonvolatile media. Applies to all commands "\
		"finished before the flush was submitted. Additional data may also be "\
		"flushed by the controller, from any namespace, depending on controller and "\
		"associated namespace status.";
	const char *namespace_id = "identifier of desired namespace";
	int err, fd;

	struct config {
		__u32 namespace_id;
	};

	struct config cfg = {
		.namespace_id = 0,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	if (!cfg.namespace_id) {
		err = cfg.namespace_id = nvme_get_nsid(fd);
		if (err < 0) {
			perror("get-namespace-id");
			goto close_fd;
		}
	}

	err = nvme_flush(fd, cfg.namespace_id);
	if (err < 0)
		perror("flush");
	else if (err != 0)
		nvme_show_status(err);
	else
		printf("NVMe Flush: success\n");
close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int resv_acquire(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Obtain a reservation on a given "\
		"namespace. Only one reservation is allowed at a time on a "\
		"given namespace, though multiple controllers may register "\
		"with that namespace. Namespace reservation will abort with "\
		"status Reservation Conflict if the given namespace is "\
		"already reserved.";
	const char *namespace_id = "identifier of desired namespace";
	const char *crkey = "current reservation key";
	const char *prkey = "pre-empt reservation key";
	const char *rtype = "reservation type";
	const char *racqa = "reservation acquire action";
	const char *iekey = "ignore existing res. key";
	int err, fd;

	struct config {
		__u32 namespace_id;
		__u64 crkey;
		__u64 prkey;
		__u8  rtype;
		__u8  racqa;
		int   iekey;
	};

	struct config cfg = {
		.namespace_id = 0,
		.crkey        = 0,
		.prkey        = 0,
		.rtype        = 0,
		.racqa        = 0,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id),
		OPT_SUFFIX("crkey",      'c', &cfg.crkey,        crkey),
		OPT_SUFFIX("prkey",      'p', &cfg.prkey,        prkey),
		OPT_BYTE("rtype",        't', &cfg.rtype,        rtype),
		OPT_BYTE("racqa",        'a', &cfg.racqa,        racqa),
		OPT_FLAG("iekey",        'i', &cfg.iekey,        iekey),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	if (!cfg.namespace_id) {
		err = cfg.namespace_id = nvme_get_nsid(fd);
		if (err < 0) {
			perror("get-namespace-id");
			goto close_fd;
		}
	}
	if (cfg.racqa > 7) {
		fprintf(stderr, "invalid racqa:%d\n", cfg.racqa);
		err = -EINVAL;
		goto close_fd;
	}

	err = nvme_resv_acquire(fd, cfg.namespace_id, cfg.rtype, cfg.racqa,
				!!cfg.iekey, cfg.crkey, cfg.prkey);
	if (err < 0)
		perror("reservation acquire");
	else if (err != 0)
		nvme_show_status(err);
	else
		printf("NVME Reservation Acquire success\n");

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int resv_register(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Register, de-register, or "\
		"replace a controller's reservation on a given namespace. "\
		"Only one reservation at a time is allowed on any namespace.";
	const char *namespace_id = "identifier of desired namespace";
	const char *crkey = "current reservation key";
	const char *iekey = "ignore existing res. key";
	const char *nrkey = "new reservation key";
	const char *rrega = "reservation registration action";
	const char *cptpl = "change persistence through power loss setting";
	int err, fd;

	struct config {
		__u32 namespace_id;
		__u64 crkey;
		__u64 nrkey;
		__u8  rrega;
		__u8  cptpl;
		int   iekey;
	};

	struct config cfg = {
		.namespace_id = 0,
		.crkey        = 0,
		.nrkey        = 0,
		.rrega        = 0,
		.cptpl        = 0,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id),
		OPT_SUFFIX("crkey",      'c', &cfg.crkey,        crkey),
		OPT_SUFFIX("nrkey",      'k', &cfg.nrkey,        nrkey),
		OPT_BYTE("rrega",        'r', &cfg.rrega,        rrega),
		OPT_BYTE("cptpl",        'p', &cfg.cptpl,        cptpl),
		OPT_FLAG("iekey",        'i', &cfg.iekey,        iekey),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	if (!cfg.namespace_id) {
		err = cfg.namespace_id = nvme_get_nsid(fd);
		if (err < 0) {
			perror("get-namespace-id");
			goto close_fd;
		}
	}
	if (cfg.cptpl > 3) {
		fprintf(stderr, "invalid cptpl:%d\n", cfg.cptpl);
		err = -EINVAL;
		goto close_fd;
	}

	if (cfg.rrega > 7) {
		fprintf(stderr, "invalid rrega:%d\n", cfg.rrega);
		err = -EINVAL;
		goto close_fd;
	}

	err = nvme_resv_register(fd, cfg.namespace_id, cfg.rrega, cfg.cptpl,
				!!cfg.iekey, cfg.crkey, cfg.nrkey);
	if (err < 0)
		perror("reservation register");
	else if (err != 0)
		nvme_show_status(err);
	else
		printf("NVME Reservation  success\n");

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
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
	const char *namespace_id = "desired namespace";
	const char *crkey = "current reservation key";
	const char *iekey = "ignore existing res. key";
	const char *rtype = "reservation type";
	const char *rrela = "reservation release action";
	int err, fd;

	struct config {
		__u32 namespace_id;
		__u64 crkey;
		__u8  rtype;
		__u8  rrela;
		__u8  iekey;
	};

	struct config cfg = {
		.namespace_id = 0,
		.crkey        = 0,
		.rtype        = 0,
		.rrela        = 0,
		.iekey        = 0,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id),
		OPT_SUFFIX("crkey",      'c', &cfg.crkey,        crkey),
		OPT_BYTE("rtype",        't', &cfg.rtype,        rtype),
		OPT_BYTE("rrela",        'a', &cfg.rrela,        rrela),
		OPT_FLAG("iekey",        'i', &cfg.iekey,        iekey),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	if (!cfg.namespace_id) {
		err = cfg.namespace_id = nvme_get_nsid(fd);
		if (err < 0) {
			perror("get-namespace-id");
			goto close_fd;
		}
	}
	if (cfg.rrela > 7) {
		fprintf(stderr, "invalid rrela:%d\n", cfg.rrela);
		err = -EINVAL;
		goto close_fd;
	}

	err = nvme_resv_release(fd, cfg.namespace_id, cfg.rtype, cfg.rrela,
				!!cfg.iekey, cfg.crkey);
	if (err < 0)
		perror("reservation release");
	else if (err != 0)
		nvme_show_status(err);
	else
		printf("NVME Reservation Release success\n");

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int resv_report(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Returns Reservation Status data "\
		"structure describing any existing reservations on and the "\
		"status of a given namespace. Namespace Reservation Status "\
		"depends on the number of controllers registered for that "\
		"namespace.";
	const char *namespace_id = "identifier of desired namespace";
	const char *numd = "number of dwords to transfer";
	const char *cdw11 = "command dword 11 value";
	const char *raw = "dump output in binary format";

	struct nvme_reservation_status *status;
	enum nvme_print_flags flags;
	int err, fd, size;

	struct config {
		__u32 namespace_id;
		__u32 numd;
		__u32 cdw11;
		int   raw_binary;
		char *output_format;
	};

	struct config cfg = {
		.namespace_id = 0,
		.numd         = 0,
		.cdw11	      = 0,
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id",  'n', &cfg.namespace_id,   namespace_id),
		OPT_UINT("numd",          'd', &cfg.numd,           numd),
		OPT_UINT("cdw11",         'c', &cfg.cdw11,          cdw11),
		OPT_FMT("output-format",  'o', &cfg.output_format,  output_format),
		OPT_FLAG("raw-binary",    'b', &cfg.raw_binary,     raw),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;
	if (cfg.raw_binary)
		flags = BINARY;

	if (!cfg.namespace_id) {
		err = cfg.namespace_id = nvme_get_nsid(fd);
		if (err < 0) {
			perror("get-namespace-id");
			goto close_fd;
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
		goto close_fd;
	}
	memset(status, 0, size);

	err = nvme_resv_report(fd, cfg.namespace_id, cfg.numd, cfg.cdw11, status);
	if (!err)
		nvme_show_resv_report(status, size, cfg.cdw11, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		perror("reservation report");
	free(status);
close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
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
	int dfd, mfd, fd;
	int flags = opcode & 1 ? O_RDONLY : O_WRONLY | O_CREAT;
	int mode = S_IRUSR | S_IWUSR |S_IRGRP | S_IWGRP| S_IROTH;
	__u16 control = 0;
	__u32 dsmgmt = 0, nsid = 0;
	int logical_block_size = 0;
	long long buffer_size = 0, mbuffer_size = 0;
	bool huge;
	struct nvme_id_ns ns;
	__u8 lba_index, ms = 0;

	const char *start_block = "64-bit addr of first block to access";
	const char *block_count = "number of blocks (zeroes based) on device to access";
	const char *data_size = "size of data in bytes";
	const char *metadata_size = "size of metadata in bytes";
	const char *ref_tag = "reference tag (for end to end PI)";
	const char *data = "data file";
	const char *metadata = "metadata file";
	const char *prinfo = "PI and check field";
	const char *app_tag_mask = "app tag mask (for end to end PI)";
	const char *app_tag = "app tag (for end to end PI)";
	const char *limited_retry = "limit num. media access attempts";
	const char *latency = "output latency statistics";
	const char *force = "force device to commit data before command completes";
	const char *show = "show command before sending";
	const char *dry = "show command instead of sending";
	const char *dtype = "directive type (for write-only)";
	const char *dspec = "directive specific (for write-only)";
	const char *dsm = "dataset management attributes (lower 16 bits)";

	struct config {
		__u64 start_block;
		__u16 block_count;
		__u64 data_size;
		__u64 metadata_size;
		__u32 ref_tag;
		char  *data;
		char  *metadata;
		__u8  prinfo;
		__u8 dtype;
		__u16 dspec;
		__u16 dsmgmt;
		__u16 app_tag_mask;
		__u16 app_tag;
		int   limited_retry;
		int   force_unit_access;
		int   show;
		int   dry_run;
		int   latency;
	};

	struct config cfg = {
		.start_block     = 0,
		.block_count     = 0,
		.data_size       = 0,
		.metadata_size   = 0,
		.ref_tag         = 0,
		.data            = "",
		.metadata        = "",
		.prinfo          = 0,
		.app_tag_mask    = 0,
		.app_tag         = 0,
	};

	OPT_ARGS(opts) = {
		OPT_SUFFIX("start-block",     's', &cfg.start_block,       start_block),
		OPT_SHRT("block-count",       'c', &cfg.block_count,       block_count),
		OPT_SUFFIX("data-size",       'z', &cfg.data_size,         data_size),
		OPT_SUFFIX("metadata-size",   'y', &cfg.metadata_size,     metadata_size),
		OPT_UINT("ref-tag",           'r', &cfg.ref_tag,           ref_tag),
		OPT_FILE("data",              'd', &cfg.data,              data),
		OPT_FILE("metadata",          'M', &cfg.metadata,          metadata),
		OPT_BYTE("prinfo",            'p', &cfg.prinfo,            prinfo),
		OPT_SHRT("app-tag-mask",      'm', &cfg.app_tag_mask,      app_tag_mask),
		OPT_SHRT("app-tag",           'a', &cfg.app_tag,           app_tag),
		OPT_FLAG("limited-retry",     'l', &cfg.limited_retry,     limited_retry),
		OPT_FLAG("force-unit-access", 'f', &cfg.force_unit_access, force),
		OPT_BYTE("dir-type",          'T', &cfg.dtype,             dtype),
		OPT_SHRT("dir-spec",          'S', &cfg.dspec,             dspec),
		OPT_SHRT("dsm",               'D', &cfg.dsmgmt,            dsm),
		OPT_FLAG("show-command",      'v', &cfg.show,              show),
		OPT_FLAG("dry-run",           'w', &cfg.dry_run,           dry),
		OPT_FLAG("latency",           't', &cfg.latency,           latency),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	dfd = mfd = opcode & 1 ? STDIN_FILENO : STDOUT_FILENO;
	if (cfg.prinfo > 0xf) {
		err = -EINVAL;
		goto close_fd;
	}

	dsmgmt = cfg.dsmgmt;
	control |= (cfg.prinfo << 10);
	if (cfg.limited_retry)
		control |= NVME_RW_LR;
	if (cfg.force_unit_access)
		control |= NVME_RW_FUA;
	if (cfg.dtype) {
		if (cfg.dtype > 0xf) {
			fprintf(stderr, "Invalid directive type, %x\n",
				cfg.dtype);
			err = -EINVAL;
			goto close_fd;
		}
		control |= cfg.dtype << 4;
		dsmgmt |= ((__u32)cfg.dspec) << 16;
	}

	if (strlen(cfg.data)) {
		dfd = open(cfg.data, flags, mode);
		if (dfd < 0) {
			perror(cfg.data);
			err = -EINVAL;
			goto close_fd;
		}
		mfd = dfd;
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

	if (ioctl(fd, BLKSSZGET, &logical_block_size) < 0)
		goto close_mfd;

	buffer_size = (cfg.block_count + 1) * logical_block_size;
	if (cfg.data_size < buffer_size) {
		fprintf(stderr, "Rounding data size to fit block count (%lld bytes)\n",
				buffer_size);
	} else {
		buffer_size = cfg.data_size;
	}

	buffer = nvme_alloc(buffer_size, &huge);
	if (!buffer) {
		perror("can not allocate io payload\n");
		err = -ENOMEM;
		goto close_mfd;
	}

	if (cfg.metadata_size) {
		err = nsid = nvme_get_nsid(fd);
		if (err < 0) {
			perror("get-namespace-id");
			goto close_mfd;
		}
		err = nvme_identify_ns(fd, nsid, false, &ns);
		if (err) {
			nvme_show_status(err);
			goto free_buffer;
		} else if (err < 0) {
			perror("identify namespace");
			goto free_buffer;
		}
		lba_index = ns.flbas & NVME_NS_FLBAS_LBA_MASK;
		ms = ns.lbaf[lba_index].ms;
		mbuffer_size = (cfg.block_count + 1) * ms;
		if (ms && cfg.metadata_size < mbuffer_size) {
			fprintf(stderr, "Rounding metadata size to fit block count (%lld bytes)\n",
					mbuffer_size);
		} else {
			mbuffer_size = cfg.metadata_size;
		}
		mbuffer = malloc(mbuffer_size);
		if (!mbuffer) {
			perror("can not allocate buf for io metadata payload\n");
			err = -ENOMEM;
			goto free_buffer;
		}
		memset(mbuffer, 0, mbuffer_size);
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

	if (cfg.show) {
		printf("opcode       : %02x\n", opcode);
		printf("flags        : %02x\n", 0);
		printf("control      : %04x\n", control);
		printf("nblocks      : %04x\n", cfg.block_count);
		printf("metadata     : %"PRIx64"\n", (uint64_t)(uintptr_t)mbuffer);
		printf("addr         : %"PRIx64"\n", (uint64_t)(uintptr_t)buffer);
		printf("slba         : %"PRIx64"\n", (uint64_t)cfg.start_block);
		printf("dsmgmt       : %08x\n", dsmgmt);
		printf("reftag       : %08x\n", cfg.ref_tag);
		printf("apptag       : %04x\n", cfg.app_tag);
		printf("appmask      : %04x\n", cfg.app_tag_mask);
	}
	if (cfg.dry_run)
		goto free_mbuffer;

	gettimeofday(&start_time, NULL);
	err = nvme_io(fd, opcode, cfg.start_block, cfg.block_count, control, dsmgmt,
			cfg.ref_tag, cfg.app_tag, cfg.app_tag_mask, buffer, mbuffer);
	gettimeofday(&end_time, NULL);
	if (cfg.latency)
		printf(" latency: %s: %llu us\n",
			command, elapsed_utime(start_time, end_time));
	if (err < 0)
		perror("submit-io");
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
close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
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
	int err, fd;
	__u16 control = 0;
	const char *desc = "Verify specified logical blocks on the given device.";
	const char *namespace_id = "desired namespace";
	const char *start_block = "64-bit LBA of first block to access";
	const char *block_count = "number of blocks (zeroes based) on device to access";
	const char *limited_retry = "limit media access attempts";
	const char *force = "force device to commit cached data before performing the verify operation";
	const char *prinfo = "PI and check field";
	const char *ref_tag = "reference tag (for end to end PI)";
	const char *app_tag_mask = "app tag mask (for end to end PI)";
	const char *app_tag = "app tag (for end to end PI)";

	struct config {
		__u64 start_block;
		__u32 namespace_id;
		__u32 ref_tag;
		__u16 app_tag;
		__u16 app_tag_mask;
		__u16 block_count;
		__u8  prinfo;
		int   limited_retry;
		int   force_unit_access;
	};

	struct config cfg = {
		.namespace_id      = 0,
		.start_block       = 0,
		.block_count       = 0,
		.prinfo            = 0,
		.ref_tag           = 0,
		.app_tag           = 0,
		.app_tag_mask      = 0,
		.limited_retry     = 0,
		.force_unit_access = 0,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id",      'n', &cfg.namespace_id,      namespace_id),
		OPT_SUFFIX("start-block",     's', &cfg.start_block,       start_block),
		OPT_SHRT("block-count",       'c', &cfg.block_count,       block_count),
		OPT_FLAG("limited-retry",     'l', &cfg.limited_retry,     limited_retry),
		OPT_FLAG("force-unit-access", 'f', &cfg.force_unit_access, force),
		OPT_BYTE("prinfo",            'p', &cfg.prinfo,            prinfo),
		OPT_UINT("ref-tag",           'r', &cfg.ref_tag,           ref_tag),
		OPT_SHRT("app-tag",           'a', &cfg.app_tag,           app_tag),
		OPT_SHRT("app-tag-mask",      'm', &cfg.app_tag_mask,      app_tag_mask),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto err;

	if (cfg.prinfo > 0xf) {
		err = EINVAL;
		goto close_fd;
	}

	control |= (cfg.prinfo << 10);
	if (cfg.limited_retry)
		control |= NVME_RW_LR;
	if (cfg.force_unit_access)
		control |= NVME_RW_FUA;

	if (!cfg.namespace_id) {
		err = cfg.namespace_id = nvme_get_nsid(fd);
		if (err < 0) {
			perror("get-namespace-id");
			goto close_fd;
		}
	}

	err = nvme_verify(fd, cfg.namespace_id, cfg.start_block, cfg.block_count,
				control, cfg.ref_tag, cfg.app_tag, cfg.app_tag_mask);
	if (err < 0)
		perror("verify");
	else if (err != 0)
		nvme_show_status(err);
	else
		printf("NVME Verify Success\n");

close_fd:
	close(fd);
err:
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
	const char *secp = "security protocol (cf. SPC-4)";
	const char *spsp = "security-protocol-specific (cf. SPC-4)";
	const char *al = "allocation length (cf. SPC-4)";
	const char *raw = "dump output in binary format";
	const char *namespace_id = "desired namespace";
	const char *nssf = "NVMe Security Specific Field";
	int err, fd;
	void *sec_buf = NULL;

	struct config {
		__u32 namespace_id;
		__u32 size;
		__u8  secp;
		__u8  nssf;
		__u16 spsp;
		__u32 al;
		int   raw_binary;
	};

	struct config cfg = {
		.size = 0,
		.secp = 0,
		.spsp = 0,
		.al   = 0,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id),
		OPT_UINT("size",         'x', &cfg.size,         size),
		OPT_BYTE("nssf",         'N', &cfg.nssf,         nssf),
		OPT_BYTE("secp",         'p', &cfg.secp,         secp),
		OPT_SHRT("spsp",         's', &cfg.spsp,         spsp),
		OPT_UINT("al",           't', &cfg.al,           al),
		OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,   raw),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	if (cfg.size) {
		if (posix_memalign(&sec_buf, getpagesize(), cfg.size)) {
			fprintf(stderr, "No memory for security size:%d\n",
								cfg.size);
			err = -ENOMEM;
			goto close_fd;
		}
	}

	err = nvme_sec_recv(fd, cfg.namespace_id, cfg.nssf, cfg.spsp,
			cfg.secp, cfg.al, cfg.size, sec_buf);
	if (err < 0)
		perror("security receive");
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

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int get_lba_status(int argc, char **argv, struct command *cmd,
		struct plugin *plugin)
{
	const char *desc = "Information about potentially unrecoverable LBAs.";
	const char *namespace_id = "Desired Namespace";
	const char *slba = "Starting LBA(SLBA) in 64-bit address of the first"\
			    " logical block addressed by this command";
	const char *mndw = "Maximum Number of Dwords(MNDW) specifies maximum"\
			    " number of dwords to return";
	const char *atype = "Action Type(ATYPE) specifies the mechanism"\
			     " the controller uses in determining the LBA"\
			     " Status Descriptors to return.";
	const char *rl = "Range Length(RL) specifies the length of the range"\
			  " of contiguous LBAs beginning at SLBA";
	const char *timeout = "timeout value, in milliseconds";

	enum nvme_print_flags flags;
	unsigned long buf_len;
	int err, fd;
	void *buf;

	struct config {
		__u32 namespace_id;
		__u64 slba;
		__u32 mndw;
		__u8 atype;
		__u16 rl;
		__u32 timeout;
		char *output_format;
	};

	struct config cfg = {
		.namespace_id = 0,
		.slba = 0,
		.mndw = 0,
		.atype = 0,
		.rl = 0,
		.timeout      = 0,
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id,  namespace_id),
		OPT_SUFFIX("start-lba",  's', &cfg.slba,          slba),
		OPT_UINT("max-dw",       'm', &cfg.mndw,          mndw),
		OPT_BYTE("action",       'a', &cfg.atype,         atype),
		OPT_SHRT("range-len",    'l', &cfg.rl,            rl),
		OPT_UINT("timeout",      't', &cfg.timeout,       timeout),
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto err;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;

	if (!cfg.atype) {
		fprintf(stderr, "action type (--action) has to be given\n");
		err = -EINVAL;
		goto close_fd;
	}

	buf_len = (cfg.mndw + 1) * 4;
	buf = calloc(1, buf_len);
	if (!buf) {
		perror("could not alloc memory for get lba status");
		err = -ENOMEM;
		goto close_fd;
	}

	err = nvme_get_lba_status(fd, cfg.namespace_id, cfg.slba, cfg.mndw,
			cfg.atype, cfg.rl, buf, cfg.timeout);
	if (!err)
		nvme_show_lba_status(buf, buf_len, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		perror("get lba status");
	free(buf);
close_fd:
	close(fd);
err:
	return nvme_status_to_errno(err, false);
}

static int dir_receive(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Read directive parameters of the "\
			    "specified directive type.";
	const char *raw = "show directive in binary format";
	const char *namespace_id = "identifier of desired namespace";
	const char *data_len = "buffer len (if) data is returned";
	const char *dtype = "directive type";
	const char *dspec = "directive specification associated with directive type";
	const char *doper = "directive operation";
	const char *nsr = "namespace stream requested";
	const char *human_readable = "show directive in readable format";

	enum nvme_print_flags flags = NORMAL;
	int err, fd;
	__u32 result;
	__u32 dw12 = 0;
	void *buf = NULL;

	struct config {
		__u32 namespace_id;
		__u32 data_len;
		__u16 dspec;
		__u8  dtype;
		__u8  doper;
		__u16 nsr; /* dw12 for NVME_DIR_ST_RCVOP_STATUS */
		int  raw_binary;
		int  human_readable;
	};

	struct config cfg = {
		.namespace_id = 1,
		.data_len     = 0,
		.dspec        = 0,
		.dtype        = 0,
		.doper        = 0,
		.nsr          = 0,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id",  'n', &cfg.namespace_id,   namespace_id),
		OPT_UINT("data-len",      'l', &cfg.data_len,       data_len),
		OPT_FLAG("raw-binary",    'b', &cfg.raw_binary,     raw),
		OPT_BYTE("dir-type",      'D', &cfg.dtype,          dtype),
		OPT_SHRT("dir-spec",      'S', &cfg.dspec,          dspec),
		OPT_BYTE("dir-oper",      'O', &cfg.doper,          doper),
		OPT_SHRT("req-resource",  'r', &cfg.nsr,            nsr),
		OPT_FLAG("human-readable",'H', &cfg.human_readable, human_readable),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	if (cfg.human_readable)
		flags |= VERBOSE;
	if (cfg.raw_binary)
		flags = BINARY;

	switch (cfg.dtype) {
	case NVME_DIR_IDENTIFY:
		switch (cfg.doper) {
		case NVME_DIR_RCV_ID_OP_PARAM:
			if (!cfg.data_len)
				cfg.data_len = 4096;
			break;
		default:
			fprintf(stderr, "invalid directive operations for Identify Directives\n");
			err = -EINVAL;
			goto close_fd;
		}
		break;
	case NVME_DIR_STREAMS:
		switch (cfg.doper) {
		case NVME_DIR_RCV_ST_OP_PARAM:
			if (!cfg.data_len)
				cfg.data_len = 32;
			break;
		case NVME_DIR_RCV_ST_OP_STATUS:
			if (!cfg.data_len)
				cfg.data_len = 128 * 1024;
			break;
		case NVME_DIR_RCV_ST_OP_RESOURCE:
			dw12 = cfg.nsr;
			break;
		default:
			fprintf(stderr, "invalid directive operations for Streams Directives\n");
			err = -EINVAL;
			goto close_fd;
		}
		break;
	default:
		fprintf(stderr, "invalid directive type\n");
		err = -EINVAL;
		goto close_fd;
	}

	if (cfg.data_len) {
		if (posix_memalign(&buf, getpagesize(), cfg.data_len)) {
			err = -ENOMEM;
			goto close_fd;
		}
		memset(buf, 0, cfg.data_len);
	}

	err = nvme_dir_recv(fd, cfg.namespace_id, cfg.dspec, cfg.dtype, cfg.doper,
			cfg.data_len, dw12, buf, &result);
	if (!err)
		nvme_directive_show(cfg.dtype, cfg.doper, cfg.dspec,
				    cfg.namespace_id, result, buf, cfg.data_len,
				    flags);
	else if (err > 0)
		nvme_show_status(err);
	else if (err < 0)
		perror("dir-receive");

	free(buf);
close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

/* rpmb_cmd_option is defined in nvme-rpmb.c */
extern int rpmb_cmd_option(int, char **, struct command *, struct plugin *);
static int rpmb_cmd(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	return rpmb_cmd_option(argc, argv, cmd, plugin);
}

static int passthru(int argc, char **argv, int ioctl_cmd, uint8_t cmd_type,
	const char *desc, struct command *cmd)
{
	const char *opcode = "opcode (required)";
	const char *flags = "command flags";
	const char *rsvd = "value for reserved field";
	const char *namespace_id = "desired namespace";
	const char *data_len = "data I/O length (bytes)";
	const char *metadata_len = "metadata seg. length (bytes)";
	const char *timeout = "timeout value, in milliseconds";
	const char *cdw2 = "command dword 2 value";
	const char *cdw3 = "command dword 3 value";
	const char *cdw10 = "command dword 10 value";
	const char *cdw11 = "command dword 11 value";
	const char *cdw12 = "command dword 12 value";
	const char *cdw13 = "command dword 13 value";
	const char *cdw14 = "command dword 14 value";
	const char *cdw15 = "command dword 15 value";
	const char *input = "write/send file (default stdin)";
	const char *raw_binary = "dump output in binary format";
	const char *show = "print command before sending";
	const char *dry = "show command instead of sending";
	const char *re = "set dataflow direction to receive";
	const char *wr = "set dataflow direction to send";
	const char *prefill = "prefill buffers with known byte-value, default 0";
	const char *latency = "output latency statistics";

	void *data = NULL, *metadata = NULL;
	int err = 0, wfd = STDIN_FILENO, fd;
	__u32 result;
	bool huge;
	const char *cmd_name = NULL;
	struct timeval start_time, end_time;

	struct config {
		__u8  opcode;
		__u8  flags;
		__u16 rsvd;
		__u32 namespace_id;
		__u32 data_len;
		__u32 metadata_len;
		__u32 timeout;
		__u32 cdw2;
		__u32 cdw3;
		__u32 cdw10;
		__u32 cdw11;
		__u32 cdw12;
		__u32 cdw13;
		__u32 cdw14;
		__u32 cdw15;
		char  *input_file;
		int   raw_binary;
		int   show_command;
		int   dry_run;
		int   read;
		int   write;
		__u8  prefill;
		int   latency;
	};

	struct config cfg = {
		.opcode       = 0,
		.flags        = 0,
		.rsvd         = 0,
		.namespace_id = 0,
		.data_len     = 0,
		.metadata_len = 0,
		.timeout      = 0,
		.cdw2         = 0,
		.cdw3         = 0,
		.cdw10        = 0,
		.cdw11        = 0,
		.cdw12        = 0,
		.cdw13        = 0,
		.cdw14        = 0,
		.cdw15        = 0,
		.input_file   = "",
		.prefill      = 0,
	};

	OPT_ARGS(opts) = {
		OPT_BYTE("opcode",       'o', &cfg.opcode,       opcode),
		OPT_BYTE("flags",        'f', &cfg.flags,        flags),
		OPT_BYTE("prefill",      'p', &cfg.prefill,      prefill),
		OPT_SHRT("rsvd",         'R', &cfg.rsvd,         rsvd),
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id),
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
		OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,   raw_binary),
		OPT_FLAG("show-command", 's', &cfg.show_command, show),
		OPT_FLAG("dry-run",      'd', &cfg.dry_run,      dry),
		OPT_FLAG("read",         'r', &cfg.read,         re),
		OPT_FLAG("write",        'w', &cfg.write,        wr),
		OPT_FLAG("latency",      'T', &cfg.latency,      latency),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	if (strlen(cfg.input_file)) {
		wfd = open(cfg.input_file, O_RDONLY,
			   S_IRUSR | S_IRGRP | S_IROTH);
		if (wfd < 0) {
			perror(cfg.input_file);
			err = -EINVAL;
			goto close_fd;
		}
	}

	if (cfg.metadata_len) {
		metadata = malloc(cfg.metadata_len);
		if (!metadata) {
			perror("can not allocate metadata payload\n");
			err = -ENOMEM;
			goto close_wfd;
		}
		memset(metadata, cfg.prefill, cfg.metadata_len);
	}
	if (cfg.data_len) {
		data = nvme_alloc(cfg.data_len, &huge);
		if (!data) {
			perror("can not allocate data payload\n");
			err = -ENOMEM;
			goto free_metadata;
		}

		if (cfg.write && !(cfg.opcode & 0x01)) {
			fprintf(stderr, "warning: write flag set but write direction bit is not set in the opcode\n");
		}

		if (cfg.read && !(cfg.opcode & 0x02)) {
			fprintf(stderr, "warning: read flag set but read direction bit is not set in the opcode\n");
		}

		memset(data, cfg.prefill, cfg.data_len);
		if (!cfg.read && !cfg.write) {
			fprintf(stderr, "data direction not given\n");
			err = -EINVAL;
			goto free_data;
		} else if (cfg.write) {
			if (read(wfd, data, cfg.data_len) < 0) {
				err = -errno;
				fprintf(stderr, "failed to read write buffer "
						"%s\n", strerror(errno));
				goto free_data;
			}
		}
	}

	if (cfg.show_command) {
		printf("opcode       : %02x\n", cfg.opcode);
		printf("flags        : %02x\n", cfg.flags);
		printf("rsvd1        : %04x\n", cfg.rsvd);
		printf("nsid         : %08x\n", cfg.namespace_id);
		printf("cdw2         : %08x\n", cfg.cdw2);
		printf("cdw3         : %08x\n", cfg.cdw3);
		printf("data_len     : %08x\n", cfg.data_len);
		printf("metadata_len : %08x\n", cfg.metadata_len);
		printf("addr         : %"PRIx64"\n", (uint64_t)(uintptr_t)data);
		printf("metadata     : %"PRIx64"\n", (uint64_t)(uintptr_t)metadata);
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

	err = nvme_passthru(fd, ioctl_cmd, cfg.opcode, cfg.flags, cfg.rsvd,
				cfg.namespace_id, cfg.cdw2, cfg.cdw3, cfg.cdw10,
				cfg.cdw11, cfg.cdw12, cfg.cdw13, cfg.cdw14, cfg.cdw15,
				cfg.data_len, data, cfg.metadata_len, metadata,
				cfg.timeout, &result);

	gettimeofday(&end_time, NULL);
	cmd_name = nvme_cmd_to_string(cmd_type, cfg.opcode);
	if (cfg.latency)
		printf("%s Command %s latency: %llu us\n",
			cmd_type ? "Admin": "IO",
			strcmp(cmd_name, "Unknown") ? cmd_name: "Vendor Specific",
			elapsed_utime(start_time, end_time));

	if (err < 0)
		perror("passthru");
	else if (err)
		nvme_show_status(err);
	else  {
		fprintf(stderr, "%s Command %s is Success and result: 0x%08x\n",
				cmd_type ? "Admin": "IO",
				strcmp(cmd_name, "Unknown") ? cmd_name: "Vendor Specific",
				result);
		if (!cfg.raw_binary) {
			if (data && cfg.read && !err)
				d((unsigned char *)data, cfg.data_len, 16, 1);
		} else if (data && cfg.read)
			d_raw((unsigned char *)data, cfg.data_len);
	}
free_data:
	nvme_free(data, huge);
free_metadata:
	free(metadata);
close_wfd:
	if (strlen(cfg.input_file))
		close(wfd);
close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int io_passthru(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Send a user-defined IO command to the specified "\
		"device via IOCTL passthrough, return results.";
	return passthru(argc, argv, NVME_IOCTL_IO_CMD, 0, desc, cmd);
}

static int admin_passthru(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Send a user-defined Admin command to the specified "\
		"device via IOCTL passthrough, return results.";
	return passthru(argc, argv, NVME_IOCTL_ADMIN_CMD, 1, desc, cmd);
}

static int gen_hostnqn_cmd(int argc, char **argv, struct command *command, struct plugin *plugin)
{
	int ret;
	char uuid_str[37]; /* e.g. 1b4e28ba-2fa1-11d2-883f-0016d3cca427 + \0 */
#ifdef LIBUUID
	uuid_t uuid;
#endif

	ret = uuid_from_dmi(uuid_str);
	if (ret < 0)
		ret = uuid_from_systemd(uuid_str);
#ifdef LIBUUID
	if (ret < 0) {
		uuid_generate_random(uuid);
		uuid_unparse_lower(uuid, uuid_str);
		ret = 0;
	}
#endif
	if (ret < 0) {
		fprintf(stderr, "\"%s\" not supported. Install lib uuid and rebuild.\n",
			command->name);
		return -ENOTSUP;
	}
	printf("nqn.2014-08.org.nvmexpress:uuid:%s\n", uuid_str);
	return 0;
}

static int show_hostnqn_cmd(int argc, char **argv, struct command *command, struct plugin *plugin)
{
	char *hostnqn;

	hostnqn = hostnqn_read();
	if (hostnqn) {
		fputs(hostnqn, stdout);
		free(hostnqn);
		return 0;
	} else {
		fprintf(stderr, "hostnqn is not available -- use nvme gen-hostnqn\n");
		return -ENOENT;
	}
}

static int discover_cmd(int argc, char **argv, struct command *command, struct plugin *plugin)
{
	const char *desc = "Send Get Log Page request to Discovery Controller.";
	return fabrics_discover(desc, argc, argv, false);
}

static int connect_all_cmd(int argc, char **argv, struct command *command, struct plugin *plugin)
{
	const char *desc = "Discover NVMeoF subsystems and connect to them";
	return fabrics_discover(desc, argc, argv, true);
}

static int connect_cmd(int argc, char **argv, struct command *command, struct plugin *plugin)
{
	const char *desc = "Connect to NVMeoF subsystem";
	return fabrics_connect(desc, argc, argv);
}

static int disconnect_cmd(int argc, char **argv, struct command *command, struct plugin *plugin)
{
	const char *desc = "Disconnect from NVMeoF subsystem";
	return fabrics_disconnect(desc, argc, argv);
}

static int disconnect_all_cmd(int argc, char **argv, struct command *command, struct plugin *plugin)
{
	const char *desc = "Disconnect from all connected NVMeoF subsystems";
	return fabrics_disconnect_all(desc, argc, argv);
}

static int monitor_cmd(int argc, char **argv, struct command *command, struct plugin *plugin)
{
#ifdef HAVE_LIBUDEV
	const char *desc = "Monitor NVMeoF AEN events";

	return aen_monitor(desc, argc, argv);
#else
	fprintf(stderr, "nvme-cli built without libudev doesn't support the \"monitor\" subcommand\n");
	return EOPNOTSUPP;
#endif
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

	return err;
}
