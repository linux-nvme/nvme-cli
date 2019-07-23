/*
 * nvme.c -- NVM-Express command line utility.
 *
 * Copyright (c) 2014-2015, Intel Corporation.
 *
 * Written by Keith Busch <keith.busch@intel.com>
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

#include <linux/fs.h>

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>

#include "common.h"
#include "nvme-print.h"
#include "nvme-ioctl.h"
#include "nvme-status.h"
#include "nvme-lightnvm.h"
#include "plugin.h"

#include "argconfig.h"

#include "fabrics.h"

static struct stat nvme_stat;
const char *devicename;

static const char nvme_version_string[] = NVME_VERSION;

#define CREATE_CMD
#include "nvme-builtin.h"

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

static unsigned long long elapsed_utime(struct timeval start_time,
					struct timeval end_time)
{
	unsigned long long ret = (end_time.tv_sec - start_time.tv_sec) * 1000000 +
		(end_time.tv_usec - start_time.tv_usec);
	return ret;
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
	if (err < 0)
		goto perror;
	if (!S_ISCHR(nvme_stat.st_mode) && !S_ISBLK(nvme_stat.st_mode)) {
		fprintf(stderr, "%s is not a block or character device\n", dev);
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
	const struct argconfig_commandline_options *clo, void *cfg, size_t size)
{
	int ret;

	ret = argconfig_parse(argc, argv, desc, clo, cfg, size);
	if (ret)
		return ret;

	ret = get_dev(argc, argv);
	if (ret < 0)
		argconfig_print_help(desc, clo);

	return ret;
}

static const char *output_format = "Output format: normal|json|binary";

int validate_output_format(char *format)
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
	int err, fmt, fd;

	struct config {
		__u32 namespace_id;
		int   raw_binary;
		char *output_format;
	};

	struct config cfg = {
		.namespace_id = NVME_NSID_ALL,
		.output_format = "normal",
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id",  'n', "NUM", CFG_POSITIVE, &cfg.namespace_id,  required_argument, namespace},
		{"output-format", 'o', "FMT", CFG_STRING,   &cfg.output_format, required_argument, output_format },
		{"raw-binary",    'b', "",    CFG_NONE,     &cfg.raw_binary,    no_argument,       raw},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0) {
		err = fd;
		goto ret;
	}

	fmt = validate_output_format(cfg.output_format);
	if (fmt < 0) {
		err = fmt;
		goto close_fd;
	}
	if (cfg.raw_binary)
		fmt = BINARY;

	err = nvme_smart_log(fd, cfg.namespace_id, &smart_log);
	if (!err) {
		if (fmt == BINARY)
			d_raw((unsigned char *)&smart_log, sizeof(smart_log));
		else if (fmt == JSON)
			json_smart_log(&smart_log, cfg.namespace_id, devicename);
		else
			show_smart_log(&smart_log, cfg.namespace_id, devicename);
	} else if (err > 0)
		show_nvme_status(err);
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
	const char *desc = "Retrieve ANA log for the given device" \
			    "in either decoded format "\
			    "(default) or binary.";
	void *ana_log;
	int err, fmt, fd;
	int groups = 0; /* Right now get all the per ANA group NSIDS */
	size_t ana_log_len;
	struct nvme_id_ctrl ctrl;

	struct config {
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"output-format", 'o', "FMT", CFG_STRING,   &cfg.output_format, required_argument, output_format },
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, NULL, 0);
	if (fd < 0) {
		err = fd;
		goto ret;
	}

	fmt = validate_output_format(cfg.output_format);
	if (fmt < 0) {
		err = fmt;
		goto close_fd;
	}

	memset(&ctrl, 0, sizeof (struct nvme_id_ctrl));
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
		perror("malloc : ");
		err = -ENOMEM;
		goto close_fd;
	}

	err = nvme_ana_log(fd, ana_log, ana_log_len, groups ? NVME_ANA_LOG_RGO : 0);
	if (!err) {
		if (fmt == BINARY)
			d_raw((unsigned char *)ana_log, ana_log_len);
		else if (fmt == JSON)
			json_ana_log(ana_log, devicename);
		else
			show_ana_log(ana_log, devicename);
	} else if (err > 0)
		show_nvme_status(err);
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

	const struct argconfig_commandline_options command_line_options[] = {
		{"output-file",     'o', "FILE", CFG_STRING,   &cfg.file_name, required_argument, fname},
		{"host-generate",   'g', "NUM",  CFG_POSITIVE, &cfg.host_gen,  required_argument, hgen},
		{"controller-init", 'c', "",     CFG_NONE,     &cfg.ctrl_init, no_argument,       cgen},
		{"data-area",       'd', "NUM",  CFG_POSITIVE, &cfg.data_area, required_argument, dgen},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0) {
		err = fd;
		goto ret;
	}

	if (!cfg.file_name) {
		fprintf(stderr, "Please provide an output file!\n");
		err = -EINVAL;
		goto close_fd;
	}

	cfg.host_gen = !!cfg.host_gen;
	hdr = malloc(bs);
	page_log = malloc(bs);
	if (!hdr || !page_log) {
		fprintf(stderr, "Failed to allocate %zu bytes for log: %s\n",
				bs, strerror(errno));
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
		show_nvme_status(err);
		fprintf(stderr, "Failed to acquire telemetry header %d!\n", err);
		goto close_output;
	}

	err = write(output, (void *) hdr, bs);
	if (err != bs) {
		fprintf(stderr, "Failed to flush all data to file!");
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
		fprintf(stderr, "Invalid data area requested");
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
			show_nvme_status(err);
			break;
		}

		err = write(output, (void *) page_log, bs);
		if (err != bs) {
			fprintf(stderr, "Failed to flush all data to file!");
			break;
		}
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

	int err, fd;
	int fmt;

	struct config {
		char *output_format;
		__u16 group_id;
	};

	struct config cfg = {
		.output_format = "normal",
		.group_id = 0,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"output-format", 'o', "FMT", CFG_STRING, &cfg.output_format, required_argument, output_format},
		{"group-id",      'g', "NUM", CFG_SHORT,  &cfg.group_id,      required_argument, group_id},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0) {
		err = fd;
		goto ret;
	}

	fmt = validate_output_format(cfg.output_format);
	if (fmt < 0) {
		err = fmt;
		goto close_fd;
	}

	err = nvme_endurance_log(fd, cfg.group_id, &endurance_log);
	if (!err) {
		if (fmt == BINARY)
			d_raw((unsigned char *)&endurance_log, sizeof(endurance_log));
		else if (fmt == JSON)
			json_endurance_log(&endurance_log, cfg.group_id, devicename);
		else
			show_endurance_log(&endurance_log, cfg.group_id, devicename);
	} else if (err > 0)
		show_nvme_status(err);
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
	const char *raw_binary = "show infos in binary format";
	const char *human_readable = "show infos in readable format";
	struct nvme_effects_log_page effects;

	int err, fd;
	int fmt;
	unsigned int flags = 0;

	struct config {
		int   raw_binary;
		int   human_readable;
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"output-format", 'o', "FMT", CFG_STRING,   &cfg.output_format, required_argument, output_format},
		{"human-readable",'H', "",    CFG_NONE,     &cfg.human_readable,no_argument,       human_readable},
		{"raw-binary",    'b', "",    CFG_NONE,     &cfg.raw_binary,    no_argument,       raw_binary},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0) {
		err = fd;
		goto ret;
	}

	fmt = validate_output_format(cfg.output_format);
	if (fmt < 0) {
		err = fmt;
		goto close_fd;
	}
	if (cfg.raw_binary)
		fmt = BINARY;

	if (cfg.human_readable)
		flags |= HUMAN;

	err = nvme_effects_log(fd, &effects);
	if (!err) {
		if (fmt == BINARY)
			d_raw((unsigned char *)&effects, sizeof(effects));
		else if (fmt == JSON)
			json_effects_log(&effects, devicename);
		else
			show_effects_log(&effects, flags);
	}
	else if (err > 0)
		show_nvme_status(err);
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
	const char *raw_binary = "dump in binary format";
	struct nvme_id_ctrl ctrl;
	int err, fmt, fd;

	struct config {
		__u32 log_entries;
		int   raw_binary;
		char *output_format;
	};

	struct config cfg = {
		.log_entries  = 64,
		.output_format = "normal",
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"log-entries",   'e', "NUM", CFG_POSITIVE, &cfg.log_entries,   required_argument, log_entries},
		{"raw-binary",    'b', "",    CFG_NONE,     &cfg.raw_binary,    no_argument,       raw_binary},
		{"output-format", 'o', "FMT", CFG_STRING,   &cfg.output_format, required_argument, output_format },
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0) {
		err = fd;
		goto ret;
	}

	fmt = validate_output_format(cfg.output_format);
	if (fmt < 0) {
		err = fmt;
		goto close_fd;
	}
	if (cfg.raw_binary)
		fmt = BINARY;

	if (!cfg.log_entries) {
		fprintf(stderr, "non-zero log-entries is required param\n");
		err = -EINVAL;
		goto close_fd;
	}

	err = nvme_identify_ctrl(fd, &ctrl);
	if (err < 0)
		perror("identify controller");
	else if (err) {
		fprintf(stderr, "could not identify controller\n");
		err = -ENODEV;
	} else {
		struct nvme_error_log_page *err_log;

		cfg.log_entries = min(cfg.log_entries, ctrl.elpe + 1);
		err_log = calloc(cfg.log_entries, sizeof(struct nvme_error_log_page));
		if (!err_log) {
			fprintf(stderr, "could not alloc buffer for error log\n");
			err = -ENOMEM;
			goto close_fd;
		}

		err = nvme_error_log(fd, cfg.log_entries, err_log);
		if (!err) {
			if (fmt == BINARY)
				d_raw((unsigned char *)err_log, cfg.log_entries * sizeof(*err_log));
			else if (fmt == JSON)
				json_error_log(err_log, cfg.log_entries, devicename);
			else
				show_error_log(err_log, cfg.log_entries, devicename);
		}
		else if (err > 0)
			show_nvme_status(err);
		else
			perror("error log");
		free(err_log);
	}

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int get_fw_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Retrieve the firmware log for the "\
		"specified device in either decoded format (default) or binary.";
	const char *raw_binary = "use binary output";
	int err, fmt, fd;
	struct nvme_firmware_log_page fw_log;

	struct config {
		int raw_binary;
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"raw-binary",    'b', "",    CFG_NONE,   &cfg.raw_binary,    no_argument,       raw_binary},
		{"output-format", 'o', "FMT", CFG_STRING, &cfg.output_format, required_argument, output_format },
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0) {
		err = fd;
		goto ret;
	}

	fmt = validate_output_format(cfg.output_format);
	if (fmt < 0) {
		err = fmt;
		goto close_fd;
	}
	if (cfg.raw_binary)
		fmt = BINARY;

	err = nvme_fw_log(fd, &fw_log);
	if (!err) {
		if (fmt == BINARY)
			d_raw((unsigned char *)&fw_log, sizeof(fw_log));
		else if (fmt == JSON)
			json_fw_log(&fw_log, devicename);
		else
			show_fw_log(&fw_log, devicename);
	}
	else if (err > 0)
		show_nvme_status(err);
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
	int err, fmt, fd;

	struct config {
		int   raw_binary;
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"output-format", 'o', "FMT", CFG_STRING,   &cfg.output_format, required_argument, output_format },
		{"raw-binary",    'b', "",    CFG_NONE,     &cfg.raw_binary,    no_argument,       raw},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0) {
		err = fd;
		goto ret;
	}

	fmt = validate_output_format(cfg.output_format);
	if (fmt < 0) {
		err = fmt;
		goto close_fd;
	}

	if (cfg.raw_binary)
		fmt = BINARY;

	err = nvme_changed_ns_list_log(fd, &changed_ns_list_log);
	if (!err) {
		if (fmt == BINARY)
			d_raw((unsigned char *)changed_ns_list_log.log, sizeof(changed_ns_list_log.log));
		else if (fmt == JSON)
			json_changed_ns_list_log(&changed_ns_list_log, devicename);
		else
			show_changed_ns_list_log(&changed_ns_list_log, devicename);
	} else if (err > 0)
		show_nvme_status(err);
	else
		perror("changed ns list log");

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
	const char *rae = "retain an asynchronous event";
	const char *raw_binary = "output in raw format";
	int err, fd;

	struct config {
		__u32 namespace_id;
		__u32 log_id;
		__u32 log_len;
		__u32 aen;
		__u64 lpo;
		__u8  lsp;
		int   rae;
		int   raw_binary;
	};

	struct config cfg = {
		.namespace_id = NVME_NSID_ALL,
		.log_id       = 0xffffffff,
		.log_len      = 0,
		.lpo          = NVME_NO_LOG_LPO,
		.lsp          = NVME_NO_LOG_LSP,
		.rae          = 0,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id", 'n', "NUM", CFG_POSITIVE, &cfg.namespace_id, required_argument, namespace_id},
		{"log-id",       'i', "NUM", CFG_POSITIVE, &cfg.log_id,       required_argument, log_id},
		{"log-len",      'l', "NUM", CFG_POSITIVE, &cfg.log_len,      required_argument, log_len},
		{"aen",          'a', "NUM", CFG_POSITIVE, &cfg.aen,          required_argument, aen},
		{"raw-binary",   'b', "",    CFG_NONE,     &cfg.raw_binary,   no_argument,       raw_binary},
		{"lpo",          'o', "NUM", CFG_LONG,     &cfg.lpo,          required_argument, lpo},
		{"lsp",          's', "NUM", CFG_BYTE,     &cfg.lsp,          required_argument, lsp},
		{"rae",          'r', "",    CFG_NONE,     &cfg.rae,          no_argument,       rae},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0) {
		err = fd;
		goto ret;
	}

	if (cfg.aen) {
		cfg.log_len = 4096;
		cfg.log_id = (cfg.aen >> 16) & 0xff;
	}

	if (cfg.log_id > 0xff) {
		fprintf(stderr, "Invalid log identifier: %d. Valid range: 0-255\n", cfg.log_id);
		err = -EINVAL;
		goto close_fd;
	}

	if (!cfg.log_len) {
		fprintf(stderr, "non-zero log-len is required param\n");
		err = -EINVAL;
	} else {
		unsigned char *log;

		log = malloc(cfg.log_len);
		if (!log) {
			fprintf(stderr, "could not alloc buffer for log: %s\n",
					strerror(errno));
			err = -EINVAL;
			goto close_fd;
		}

		err = nvme_get_log13(fd, cfg.namespace_id, cfg.log_id,
				     cfg.lsp, cfg.lpo, 0, cfg.rae,
				     cfg.log_len, log);
		if (!err) {
			if (!cfg.raw_binary) {
				printf("Device:%s log-id:%d namespace-id:%#x\n",
				       devicename, cfg.log_id,
				       cfg.namespace_id);
				d(log, cfg.log_len, 16, 1);
			} else
				d_raw((unsigned char *)log, cfg.log_len);
		} else if (err > 0)
			show_nvme_status(err);
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
	const char *raw_binary = "show infos in binary format";
	const char *human_readable = "show infos in readable format";
	int fd;
	int ret;
	int fmt;
	unsigned int flags = 0;
	struct nvme_sanitize_log_page sanitize_log;

	struct config {
		int   raw_binary;
		int   human_readable;
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"output-format", 'o', "FMT", CFG_STRING,   &cfg.output_format, required_argument, output_format},
		{"human-readable",'H', "",    CFG_NONE,     &cfg.human_readable,no_argument,       human_readable},
		{"raw-binary",    'b', "",    CFG_NONE,     &cfg.raw_binary,    no_argument,       raw_binary},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0) {
		ret = fd;
		goto ret;
	}

	fmt = validate_output_format(cfg.output_format);
	if (fmt < 0) {
		ret = fmt;
		goto close_fd;
	}
	if (cfg.raw_binary)
		fmt = BINARY;

	if (cfg.human_readable)
		flags |= HUMAN;

	ret = nvme_sanitize_log(fd, &sanitize_log);
	if (!ret) {
		if (fmt == BINARY)
			d_raw((unsigned char *)&sanitize_log, sizeof(sanitize_log));
		else if (fmt == JSON)
			json_sanitize_log(&sanitize_log, devicename);
		else
			show_sanitize_log(&sanitize_log, flags, devicename);
	}
	else if (ret > 0)
		show_nvme_status(ret);
	else
		perror("sanitize status log");

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(ret, false);
}

static int list_ctrl(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Show controller list information for the subsystem the "\
		"given device is part of, or optionally controllers attached to a specific namespace.";
	const char *controller = "controller to display";
	const char *namespace_id = "optional namespace attached to controller";
	int err, i, fd;
	struct nvme_controller_list *cntlist;

	struct config {
		__u16 cntid;
		__u32 namespace_id;
	};

	struct config cfg = {
		.cntid = 0,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"cntid",        'c', "NUM", CFG_SHORT,    &cfg.cntid,        required_argument, controller},
		{"namespace-id", 'n', "NUM", CFG_POSITIVE, &cfg.namespace_id, required_argument, namespace_id},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0) {
		err = fd;
		goto ret;
	}

	if (posix_memalign((void *)&cntlist, getpagesize(), 0x1000)) {
		fprintf(stderr, "can not allocate controller list payload\n");
		err = -ENOMEM;
		goto close_fd;
	}

	err = nvme_identify_ctrl_list(fd, cfg.namespace_id, cfg.cntid, cntlist);
	if (!err) {
		__u16 num = le16_to_cpu(cntlist->num);

		for (i = 0; i < (min(num, 2048)); i++)
			printf("[%4u]:%#x\n", i, le16_to_cpu(cntlist->identifier[i]));
	}
	else if (err > 0)
		show_nvme_status(err);
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
	const char *all = "show all namespaces in the subsystem, whether attached or inactive";
	int err, i, fd;
	__le32 ns_list[1024];

	struct config {
		__u32 namespace_id;
		int  all;
	};

	struct config cfg = {
		.namespace_id = 1,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id", 'n', "NUM", CFG_POSITIVE, &cfg.namespace_id, required_argument, namespace_id},
		{"all",          'a', "",    CFG_NONE,     &cfg.all,          no_argument,       all},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0) {
		err = fd;
		goto ret;
	}

	if (!cfg.namespace_id) {
		err = -EINVAL;
		fprintf(stderr, "invalid nsid parameter\n");
		goto close_fd;
	}

	err = nvme_identify_ns_list(fd, cfg.namespace_id - 1, !!cfg.all,
				    ns_list);
	if (!err) {
		for (i = 0; i < 1024; i++)
			if (ns_list[i])
				printf("[%4u]:%#x\n", i, le32_to_cpu(ns_list[i]));
	} else if (err > 0) {
		show_nvme_status(err);
	} else {
		perror("id namespace list");
	}

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int get_nsid(int fd)
{
	int nsid = nvme_get_nsid(fd);

	if (nsid <= 0) {
		fprintf(stderr,
			"%s: failed to return namespace id\n",
			devicename);
	}
	return nsid < 0 ? 0 : nsid;
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
		.namespace_id    = 0,
		.timeout      = NVME_IOCTL_TIMEOUT,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id", 'n', "NUM",  CFG_POSITIVE, &cfg.namespace_id,    required_argument, namespace_id},
		{"timeout", 't', "NUM", CFG_POSITIVE,  &cfg.timeout, required_argument, timeout},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0) {
		err = fd;
		goto ret;
	}

	if (S_ISBLK(nvme_stat.st_mode)) {
		cfg.namespace_id = get_nsid(fd);
		if (cfg.namespace_id == 0) {
			err = -EINVAL;
			goto close_fd;
		}
	} else if (!cfg.namespace_id) {
		fprintf(stderr, "%s: namespace-id parameter required\n",
						cmd->name);
		err = -EINVAL;
		goto close_fd;
	}

	err = nvme_ns_delete(fd, cfg.namespace_id, cfg.timeout);
	if (!err)
		printf("%s: Success, deleted nsid:%d\n", cmd->name,
								cfg.namespace_id);
	else if (err > 0)
		show_nvme_status(err);
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
	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id", 'n', "NUM",  CFG_POSITIVE, &cfg.namespace_id, required_argument, namespace_id},
		{"controllers",  'c', "LIST", CFG_STRING,   &cfg.cntlist,      required_argument, cont},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0) {
		err = fd;
		goto ret;
	}

	if (!cfg.namespace_id) {
		fprintf(stderr, "%s: namespace-id parameter required\n",
						cmd->name);
		err = -EINVAL;
		goto close_fd;
	}

	num = argconfig_parse_comma_sep_array(cfg.cntlist,
					list, 2047);

    if (num == -1) {
		fprintf(stderr, "%s: controller id list is required\n",
						cmd->name);
		err = -EINVAL;
		goto close_fd;
    }

	for (i = 0; i < num; i++)
		ctrlist[i] = (uint16_t)list[i];

	if (attach)
		err = nvme_ns_attach_ctrls(fd, cfg.namespace_id, num, ctrlist);
	else
		err = nvme_ns_detach_ctrls(fd, cfg.namespace_id, num, ctrlist);

	if (!err)
		printf("%s: Success, nsid:%d\n", cmd->name, cfg.namespace_id);
	else if (err > 0)
		show_nvme_status(err);
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
	const char *nsze = "size of ns";
	const char *ncap = "capacity of ns";
	const char *flbas = "FLBA size";
	const char *dps = "data protection capabilities";
	const char *nmic = "multipath and sharing capabilities";
	const char *timeout = "timeout value, in milliseconds";
	const char *bs = "target block size";

	int err = 0, fd, i;
	struct nvme_id_ns ns;
	__u32 nsid;

	struct config {
		__u64	nsze;
		__u64	ncap;
		__u8	flbas;
		__u8	dps;
		__u8	nmic;
		__u64	bs;
		__u32	timeout;
	};

	struct config cfg = {
		.flbas = 0xff,
		.bs = 0x00,
		.timeout      = NVME_IOCTL_TIMEOUT,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"nsze",         's', "NUM", CFG_LONG_SUFFIX, &cfg.nsze,    required_argument, nsze},
		{"ncap",         'c', "NUM", CFG_LONG_SUFFIX, &cfg.ncap,    required_argument, ncap},
		{"flbas",        'f', "NUM", CFG_BYTE,        &cfg.flbas,   required_argument, flbas},
		{"dps",          'd', "NUM", CFG_BYTE,        &cfg.dps,     required_argument, dps},
		{"nmic",         'm', "NUM", CFG_BYTE,        &cfg.nmic,    required_argument, nmic},
		{"block-size",   'b', "NUM", CFG_LONG_SUFFIX, &cfg.bs,      required_argument, bs},
		{"timeout",      't', "NUM", CFG_POSITIVE,    &cfg.timeout, required_argument, timeout},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0) {
		err = fd;
		goto ret;
	}

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
				show_nvme_status(err);
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


	err = nvme_ns_create(fd, cfg.nsze, cfg.ncap, cfg.flbas, cfg.dps,
			     cfg.nmic, cfg.timeout, &nsid);
	if (!err)
		printf("%s: Success, created nsid:%d\n", cmd->name, nsid);
	else if (err > 0)
		show_nvme_status(err);
	else
		perror("create namespace");

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

char *nvme_char_from_block(char *block)
{
	char slen[16];
	unsigned len;

	if (strncmp("nvme", block, 4)) {
		fprintf(stderr, "Device %s is not a nvme device.", block);
		return NULL;
	}

	sscanf(block, "nvme%d", &len);
	sprintf(slen, "%d", len);
	block[4 + strlen(slen)] = 0;

	return block;
}

static void *get_registers(void)
{
	int fd;
	char *base, path[512];
	void *membase;

	base = nvme_char_from_block((char *)devicename);
	sprintf(path, "/sys/class/nvme/%s/device/resource0", base);
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		sprintf(path, "/sys/class/misc/%s/device/resource0", base);
		fd = open(path, O_RDONLY);
	}
	if (fd < 0) {
		fprintf(stderr, "%s did not find a pci resource, open failed %s\n",
				base, strerror(errno));
		return NULL;
	}

	membase = mmap(NULL, getpagesize(), PROT_READ, MAP_SHARED, fd, 0);
	if (membase == MAP_FAILED) {
		fprintf(stderr, "%s failed to map\n", base);
		membase = NULL;
	}

	close(fd);
	return membase;
}

static const char *subsys_dir = "/sys/class/nvme-subsystem/";

static char *get_nvme_subsnqn(char *path)
{
	char sspath[320];
	char *subsysnqn;
	int fd;
	int ret;

	snprintf(sspath, sizeof(sspath), "%s/subsysnqn", path);

	fd = open(sspath, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Failed to open %s: %s\n",
				sspath, strerror(errno));
		return NULL;
	}

	subsysnqn = calloc(1, 256);
	if (!subsysnqn)
		goto close_fd;

	ret = read(fd, subsysnqn, 256);
	if (ret < 0) {
		fprintf(stderr, "Failed to read %s: %s\n", sspath,
				strerror(errno));
		free(subsysnqn);
		subsysnqn = NULL;
	} else if (subsysnqn[strlen(subsysnqn) - 1] == '\n') {
		subsysnqn[strlen(subsysnqn) - 1] = '\0';
	}

close_fd:
	close(fd);

	return subsysnqn;
}

static char *get_nvme_ctrl_attr(char *path, const char *attr)
{
	char *attrpath;
	char *value;
	int fd;
	ssize_t ret;
	int i;

	ret = asprintf(&attrpath, "%s/%s", path, attr);
	if (ret < 0)
		return NULL;

	value = calloc(1, 1024);
	if (!value)
		goto err_free_path;

	fd = open(attrpath, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Failed to open %s: %s\n",
				attrpath, strerror(errno));
		goto err_free_value;
	}

	ret = read(fd, value, 1024);
	if (ret < 0) {
		fprintf(stderr, "read :%s :%s\n", attrpath, strerror(errno));
		goto err_close_fd;
	}

	if (value[strlen(value) - 1] == '\n')
		value[strlen(value) - 1] = '\0';

	for (i = 0; i < strlen(value); i++) {
		if (value[i] == ',' )
			value[i] = ' ';
	}

	close(fd);
	free(attrpath);

	return value;

err_close_fd:
	close(fd);
err_free_value:
	free(value);
err_free_path:
	free(attrpath);

	return NULL;
}

static int scan_ctrl_paths_filter(const struct dirent *d)
{
	int id, cntlid, nsid;

	if (d->d_name[0] == '.')
		return 0;

	if (strstr(d->d_name, "nvme")) {
		if (sscanf(d->d_name, "nvme%dc%dn%d", &id, &cntlid, &nsid) == 3)
			return 1;
		if (sscanf(d->d_name, "nvme%dn%d", &id, &nsid) == 2)
			return 1;
	}

	return 0;
}

static char *get_nvme_ctrl_path_ana_state(char *path, int nsid)
{
	struct dirent **paths;
	char *ana_state;
	int i, n;

	ana_state = calloc(1, 16);
	if (!ana_state)
		return NULL;

	n = scandir(path, &paths, scan_ctrl_paths_filter, alphasort);
	if (n <= 0) {
		free(ana_state);
		return NULL;
	}
	for (i = 0; i < n; i++) {
		int id, cntlid, ns, fd;
		ssize_t ret;
		char *ctrl_path;

		if (sscanf(paths[i]->d_name, "nvme%dc%dn%d",
			   &id, &cntlid, &ns) != 3) {
			if (sscanf(paths[i]->d_name, "nvme%dn%d",
				   &id, &ns) != 2) {
				continue;
			}
		}
		if (ns != nsid)
			continue;

		ret = asprintf(&ctrl_path, "%s/%s/ana_state",
			       path, paths[i]->d_name);
		if (ret < 0) {
			free(ana_state);
			ana_state = NULL;
			break;
		}
		fd = open(ctrl_path, O_RDONLY);
		if (fd < 0) {
			free(ctrl_path);
			free(ana_state);
			ana_state = NULL;
			break;
		}
		ret = read(fd, ana_state, 16);
		if (ret < 0) {
			fprintf(stderr, "Failed to read ANA state from %s\n",
				ctrl_path);
			free(ana_state);
			ana_state = NULL;
		} else if (ana_state[strlen(ana_state) - 1] == '\n')
			ana_state[strlen(ana_state) - 1] = '\0';
		close(fd);
		free(ctrl_path);
		break;
	}
	for (i = 0; i < n; i++)
		free(paths[i]);
	free(paths);
	return ana_state;
}

static int scan_ctrls_filter(const struct dirent *d)
{
	int id, nsid;

	if (d->d_name[0] == '.')
		return 0;

	if (strstr(d->d_name, "nvme")) {
		if (sscanf(d->d_name, "nvme%dn%d", &id, &nsid) == 2)
			return 0;
		return 1;
	}

	return 0;
}

static void free_ctrl_list_item(struct ctrl_list_item *ctrls)
{
	free(ctrls->name);
	free(ctrls->transport);
	free(ctrls->address);
	free(ctrls->state);
	free(ctrls->ana_state);
}

static int get_nvme_subsystem_info(char *name, char *path,
				struct subsys_list_item *item, __u32 nsid)
{
	char ctrl_path[512];
	struct dirent **ctrls;
	int n, i, ret = 1, ccnt = 0;

	item->subsysnqn = get_nvme_subsnqn(path);
	if (!item->subsysnqn) {
		fprintf(stderr, "failed to get subsystem nqn.\n");
		return ret;
	}

	item->name = strdup(name);

	n = scandir(path, &ctrls, scan_ctrls_filter, alphasort);
	if (n < 0) {
		fprintf(stderr, "failed to scan controller(s).\n");
		return ret;
	}

	item->ctrls = calloc(n, sizeof(struct ctrl_list_item));
	if (!item->ctrls) {
		fprintf(stderr, "failed to allocate subsystem controller(s)\n");
		goto free_ctrls;
	}

	item->nctrls = n;

	for (i = 0; i < n; i++) {
		item->ctrls[ccnt].name = strdup(ctrls[i]->d_name);

		snprintf(ctrl_path, sizeof(ctrl_path), "%s/%s", path,
			 item->ctrls[ccnt].name);

		item->ctrls[ccnt].address =
				get_nvme_ctrl_attr(ctrl_path, "address");
		if (!item->ctrls[ccnt].address) {
			fprintf(stderr, "failed to get controller[%d] address.\n", i);
			free_ctrl_list_item(&item->ctrls[ccnt]);
			continue;
		}

		item->ctrls[ccnt].transport =
				get_nvme_ctrl_attr(ctrl_path, "transport");
		if (!item->ctrls[ccnt].transport) {
			fprintf(stderr, "failed to get controller[%d] transport.\n", i);
			free_ctrl_list_item(&item->ctrls[ccnt]);
			continue;
		}

		item->ctrls[ccnt].state =
				get_nvme_ctrl_attr(ctrl_path, "state");
		if (!item->ctrls[ccnt].state) {
			fprintf(stderr, "failed to get controller[%d] state.\n", i);
			free_ctrl_list_item(&item->ctrls[ccnt]);
			continue;
		}

		if (nsid != NVME_NSID_ALL)
			item->ctrls[ccnt].ana_state =
				get_nvme_ctrl_path_ana_state(ctrl_path, nsid);
		ccnt++;
	}

	item->nctrls = ccnt;

	ret = 0;

free_ctrls:
	for (i = 0; i < n; i++)
		free(ctrls[i]);
	free(ctrls);

	return ret;

}

static int scan_subsys_filter(const struct dirent *d)
{
	char path[310];
	struct stat ss;
	int id;
	int tmp;

	if (d->d_name[0] == '.')
		return 0;

	/* sanity checking, probably unneeded */
	if (strstr(d->d_name, "nvme-subsys")) {
		snprintf(path, sizeof(path), "%s%s", subsys_dir, d->d_name);
		if (stat(path, &ss))
			return 0;
		if (!S_ISDIR(ss.st_mode))
			return 0;
		tmp = sscanf(d->d_name, "nvme-subsys%d", &id);
		if (tmp != 1)
			return 0;
		return 1;
	}

	return 0;
}

static void free_subsys_list_item(struct subsys_list_item *item)
{
	int i;

	for (i = 0; i < item->nctrls; i++)
		free_ctrl_list_item(&item->ctrls[i]);

	free(item->ctrls);
	free(item->subsysnqn);
	free(item->name);
}

void free_subsys_list(struct subsys_list_item *slist, int n)
{
	int i;

	for (i = 0; i < n; i++)
		free_subsys_list_item(&slist[i]);

	free(slist);
}

struct subsys_list_item *get_subsys_list(int *subcnt, char *subsysnqn,
					 __u32 nsid)
{
	char path[310];
	struct dirent **subsys;
	struct subsys_list_item *slist;
	int n, i, ret = 0;

	n = scandir(subsys_dir, &subsys, scan_subsys_filter, alphasort);
	if (n < 0) {
		fprintf(stderr, "no NVMe subsystem(s) detected.\n");
		return NULL;
	}

	slist = calloc(n, sizeof(struct subsys_list_item));
	if (!slist)
		goto free_subsys;

	for (i = 0; i < n; i++) {
		snprintf(path, sizeof(path), "%s%s", subsys_dir,
			subsys[i]->d_name);
		ret = get_nvme_subsystem_info(subsys[i]->d_name, path,
				&slist[*subcnt], nsid);
		if (ret) {
			fprintf(stderr,
				"%s: failed to get subsystem info: %s\n",
				path, strerror(errno));
			free_subsys_list_item(&slist[*subcnt]);
		} else if (subsysnqn &&
			   strncmp(slist[*subcnt].subsysnqn, subsysnqn, 255))
			free_subsys_list_item(&slist[*subcnt]);
		else
			(*subcnt)++;
	}

free_subsys:
	for (i = 0; i < n; i++)
		free(subsys[i]);
	free(subsys);

	return slist;
}

static int list_subsys(int argc, char **argv, struct command *cmd,
		struct plugin *plugin)
{
	struct subsys_list_item *slist;
	int fmt, ret, subcnt = 0;
	char *subsysnqn = NULL;
	const char *desc = "Retrieve information for subsystems";
	struct config {
		__u32 namespace_id;
		char *output_format;
	};

	struct config cfg = {
		.namespace_id  = NVME_NSID_ALL,
		.output_format = "normal",
	};

	const struct argconfig_commandline_options opts[] = {
		{"output-format", 'o', "FMT", CFG_STRING, &cfg.output_format,
			required_argument, "Output Format: normal|json"},
		{NULL}
	};

	ret = argconfig_parse(argc, argv, desc, opts, &cfg, sizeof(cfg));
	if (ret < 0)
		goto ret;

	devicename = NULL;
	if (optind < argc) {
		char path[512];
		int id;

		devicename = basename(argv[optind]);
		if (sscanf(devicename, "nvme%dn%d", &id,
			   &cfg.namespace_id) != 2) {
			fprintf(stderr, "%s is not a NVMe namespace device\n",
				argv[optind]);
			ret = -EINVAL;
			goto ret;
		}
		sprintf(path, "/sys/block/%s/device", devicename);
		subsysnqn = get_nvme_subsnqn(path);
		if (!subsysnqn) {
			fprintf(stderr, "Cannot read subsys NQN from %s\n",
				devicename);
			ret = -EINVAL;
			goto ret;
		}
		optind++;
	}

	if (ret < 0) {
		argconfig_print_help(desc, opts);
		goto free;
	}
	fmt = validate_output_format(cfg.output_format);
	if (fmt != JSON && fmt != NORMAL) {
		if (subsysnqn)
			free(subsysnqn);
		ret = -EINVAL;
		goto free;
	}

	slist = get_subsys_list(&subcnt, subsysnqn, cfg.namespace_id);

	if (fmt == JSON)
		json_print_nvme_subsystem_list(slist, subcnt);
	else
		show_nvme_subsystem_list(slist, subcnt);

	free_subsys_list(slist, subcnt);
free:
	if (subsysnqn)
		free(subsysnqn);

ret:
	return nvme_status_to_errno(ret, false);
}

static int get_nvme_info(int fd, struct list_item *item, const char *node)
{
	int err;

	err = nvme_identify_ctrl(fd, &item->ctrl);
	if (err)
		return err;
	item->nsid = nvme_get_nsid(fd);
	if (item->nsid <= 0)
		return item->nsid;
	err = nvme_identify_ns(fd, item->nsid,
			       0, &item->ns);
	if (err)
		return err;
	strcpy(item->node, node);
	item->block = S_ISBLK(nvme_stat.st_mode);

	return 0;
}

static const char *dev = "/dev/";

/* Assume every block device starting with /dev/nvme is an nvme namespace */
static int scan_dev_filter(const struct dirent *d)
{
	char path[264];
	struct stat bd;
	int ctrl, ns, part;

	if (d->d_name[0] == '.')
		return 0;

	if (strstr(d->d_name, "nvme")) {
		snprintf(path, sizeof(path), "%s%s", dev, d->d_name);
		if (stat(path, &bd))
			return 0;
		if (!S_ISBLK(bd.st_mode))
			return 0;
		if (sscanf(d->d_name, "nvme%dn%dp%d", &ctrl, &ns, &part) == 3)
			return 0;
		return 1;
	}
	return 0;
}

static int list(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	char path[264];
	struct dirent **devices;
	struct list_item *list_items;
	unsigned int list_cnt = 0;
	int fmt, ret, fd, i, n;
	const char *desc = "Retrieve basic information for all NVMe namespaces";
	struct config {
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	const struct argconfig_commandline_options opts[] = {
		{"output-format", 'o', "FMT", CFG_STRING, &cfg.output_format, required_argument, "Output Format: normal|json"},
		{NULL}
	};

	ret = argconfig_parse(argc, argv, desc, opts, &cfg, sizeof(cfg));
	if (ret < 0)
		goto ret;

	fmt = validate_output_format(cfg.output_format);

	if (fmt != JSON && fmt != NORMAL) {
		ret = -EINVAL;
		goto ret;
	}

	n = scandir(dev, &devices, scan_dev_filter, alphasort);
	if (n < 0) {
		fprintf(stderr, "no NVMe device(s) detected.\n");
		ret = n;
		goto ret;
	}

	list_items = calloc(n, sizeof(*list_items));
	if (!list_items) {
		fprintf(stderr, "can not allocate controller list payload\n");
		ret = -ENOMEM;
		goto cleanup_devices;
	}

	for (i = 0; i < n; i++) {
		snprintf(path, sizeof(path), "%s%s", dev, devices[i]->d_name);
		fd = open(path, O_RDONLY);
		if (fd < 0) {
			fprintf(stderr, "Failed to open %s: %s\n", path,
					strerror(errno));
			ret = -errno;
			goto cleanup_list_items;
		}
		ret = get_nvme_info(fd, &list_items[list_cnt], path);
		close(fd);
		if (ret == 0) {
			list_cnt++;
		}
		else if (ret > 0) {
			fprintf(stderr, "identify failed\n");
			show_nvme_status(ret);
		}
		else {
			fprintf(stderr, "%s: failed to obtain nvme info: %s\n",
					path, strerror(-ret));
		}
	}

	if (list_cnt) {
		if (fmt == JSON)
			json_print_list_items(list_items, list_cnt);
		else
			show_list_items(list_items, list_cnt);
	}

cleanup_list_items:
	free(list_items);

cleanup_devices:
	for (i = 0; i < n; i++)
		free(devices[i]);
	free(devices);
ret:
	return nvme_status_to_errno(ret, false);
}

int __id_ctrl(int argc, char **argv, struct command *cmd, struct plugin *plugin, void (*vs)(__u8 *vs, struct json_object *root))
{
	const char *desc = "Send an Identify Controller command to "\
		"the given device and report information about the specified "\
		"controller in human-readable or "\
		"binary format. May also return vendor-specific "\
		"controller attributes in hex-dump if requested.";
	const char *vendor_specific = "dump binary vendor infos";
	const char *raw_binary = "show infos in binary format";
	const char *human_readable = "show infos in readable format";
	int err, fmt, fd;
	unsigned int flags = 0;
	struct nvme_id_ctrl ctrl;

	struct config {
		int vendor_specific;
		int raw_binary;
		int human_readable;
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"vendor-specific", 'v', "",    CFG_NONE,   &cfg.vendor_specific, no_argument,       vendor_specific},
		{"raw-binary",      'b', "",    CFG_NONE,   &cfg.raw_binary,      no_argument,       raw_binary},
		{"human-readable",  'H', "",    CFG_NONE,   &cfg.human_readable,  no_argument,       human_readable},
		{"output-format",   'o', "FMT", CFG_STRING, &cfg.output_format,   required_argument, output_format },
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0) {
		err = fd;
		goto ret;
	}

	fmt = validate_output_format(cfg.output_format);
	if (fmt < 0) {
		err = fmt;
		goto close_fd;
	}
	if (cfg.raw_binary) {
		fprintf(stderr, "binary output\n");
		fmt = BINARY;
	}

	if (cfg.vendor_specific)
		flags |= VS;
	if (cfg.human_readable)
		flags |= HUMAN;

	err = nvme_identify_ctrl(fd, &ctrl);
	if (!err) {
		if (fmt == BINARY)
			d_raw((unsigned char *)&ctrl, sizeof(ctrl));
		else if (fmt == JSON)
			json_nvme_id_ctrl(&ctrl, flags, vs);
		else {
			printf("NVME Identify Controller:\n");
			__show_nvme_id_ctrl(&ctrl, flags, vs);
		}
	}
	else if (err > 0)
		show_nvme_status(err);
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

static int ns_descs(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Send Namespace Identification Descriptors command to the "\
			    "given device, returns the namespace identification descriptors "\
			    "of the specific namespace in either human-readable or binary format.";
	const char *raw_binary = "show infos in binary format";
	const char *namespace_id = "identifier of desired namespace";
	int err, fmt, fd;
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

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id",    'n', "NUM", CFG_POSITIVE, &cfg.namespace_id, required_argument, namespace_id},
		{"raw-binary",      'b', "",    CFG_NONE,     &cfg.raw_binary,      no_argument,       raw_binary},
		{"output-format",   'o', "FMT", CFG_STRING,   &cfg.output_format,   required_argument, output_format },
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0) {
		err = fd;
		goto ret;
	}

	fmt = validate_output_format(cfg.output_format);
	if (fmt < 0) {
		err = fmt;
		goto close_fd;
	}
	if (cfg.raw_binary)
		fmt = BINARY;
	if (!cfg.namespace_id) {
		cfg.namespace_id = get_nsid(fd);
		if (cfg.namespace_id == 0) {
			err = -EINVAL;
			goto close_fd;
		}
	}

	if (posix_memalign(&nsdescs, getpagesize(), 0x1000)) {
		fprintf(stderr, "can not allocate controller list payload\n");
		err = -ENOMEM;
		goto close_fd;
	}

	err = nvme_identify_ns_descs(fd, cfg.namespace_id, nsdescs);
	if (!err) {
		if (fmt == BINARY)
			d_raw((unsigned char *)nsdescs, 0x1000);
		else if (fmt == JSON)
			json_nvme_id_ns_descs(nsdescs);
		else {
			printf("NVME Namespace Identification Descriptors NS %d:\n", cfg.namespace_id);
			show_nvme_id_ns_descs(nsdescs);
		}
	}
	else if (err > 0)
		show_nvme_status(err);
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
	const char *vendor_specific = "dump binary vendor infos";
	const char *raw_binary = "show infos in binary format";
	const char *human_readable = "show infos in readable format";
	const char *namespace_id = "identifier of desired namespace";
	struct nvme_id_ns ns;
	int err, fmt, fd;
	unsigned int flags = 0;

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

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id",    'n', "NUM", CFG_POSITIVE, &cfg.namespace_id,    required_argument, namespace_id},
		{"force",           'f', "",    CFG_NONE,     &cfg.force,           no_argument,       force},
		{"vendor-specific", 'v', "",    CFG_NONE,     &cfg.vendor_specific, no_argument,       vendor_specific},
		{"raw-binary",      'b', "",    CFG_NONE,     &cfg.raw_binary,      no_argument,       raw_binary},
		{"human-readable",  'H', "",    CFG_NONE,     &cfg.human_readable,  no_argument,       human_readable},
		{"output-format",   'o', "FMT", CFG_STRING,   &cfg.output_format,   required_argument, output_format },
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0) {
		err = fd;
		goto ret;
	}

	fmt = validate_output_format(cfg.output_format);
	if (fmt < 0) {
		err = fmt;
		goto close_fd;
	}
	if (cfg.raw_binary)
		fmt = BINARY;
	if (cfg.vendor_specific)
		flags |= VS;
	if (cfg.human_readable)
		flags |= HUMAN;
	if (!cfg.namespace_id && S_ISBLK(nvme_stat.st_mode)) {
		cfg.namespace_id = get_nsid(fd);
		if (cfg.namespace_id == 0) {
			err = -EINVAL;
			goto close_fd;
		}
	}
	else if(!cfg.namespace_id)
		fprintf(stderr,
			"Error: requesting namespace-id from non-block device\n");

	err = nvme_identify_ns(fd, cfg.namespace_id, cfg.force, &ns);
	if (!err) {
		if (fmt == BINARY)
			d_raw((unsigned char *)&ns, sizeof(ns));
		else if (fmt == JSON)
			json_nvme_id_ns(&ns, flags);
		else {
			printf("NVME Identify Namespace %d:\n", cfg.namespace_id);
			show_nvme_id_ns(&ns, flags);
		}
	}
	else if (err > 0)
		show_nvme_status(err);
	else
		perror("identify namespace");

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
	int err, fmt, fd;
	struct nvme_id_nvmset nvmset;

	struct config {
		__u16 nvmset_id;
		char *output_format;
	};

	struct config cfg = {
		.nvmset_id = 0,
		.output_format = "normal",
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"nvmset_id",       'i', "NUM", CFG_POSITIVE, &cfg.nvmset_id,       required_argument, nvmset_id},
		{"output-format",   'o', "FMT", CFG_STRING,   &cfg.output_format,   required_argument, output_format },
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0) {
		err = fd;
		goto ret;
	}

	fmt = validate_output_format(cfg.output_format);
	if (fmt < 0) {
		err = fmt;
		goto close_fd;
	}

	err = nvme_identify_nvmset(fd, cfg.nvmset_id, &nvmset);
	if (!err) {
		if (fmt == BINARY)
			d_raw((unsigned char *)&nvmset, sizeof(nvmset));
		else if (fmt == JSON)
			json_nvme_id_nvmset(&nvmset, devicename);
		else {
			printf("NVME Identify NVM Set List %d:\n", cfg.nvmset_id);
			show_nvme_id_nvmset(&nvmset);
		}
	}
	else if (err > 0)
		show_nvme_status(err);
	else
		perror("identify nvm set list");

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int get_ns_id(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	int err = 0, nsid, fd;
	const char *desc = "Get namespce ID of a the block device.";

	const struct argconfig_commandline_options command_line_options[] = {
		{NULL},
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, NULL, 0);
	if (fd < 0) {
		err = fd;
		goto ret;
	}

	nsid = nvme_get_nsid(fd);
	if (nsid <= 0) {
		perror(devicename);
		err = errno;
		goto close_fd;
	}
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
	__u32 result;

	struct config {
		int     cntlid;
		int     rt;
		int     act;
		__u32   cdw10;
		__u32   cdw11;
	};

	struct config cfg = {
		.cntlid	  = 0,
		.rt	  = 0,
		.act	  = 0,
		.cdw10	  = 0,
		.cdw11	  = 0,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"cntlid",	'c', "NUM", CFG_POSITIVE, &cfg.cntlid, required_argument, cntlid},
		{"rt",		'r', "NUM", CFG_POSITIVE, &cfg.rt,     required_argument, rt},
		{"act",		'a', "NUM", CFG_POSITIVE, &cfg.act,    required_argument, act},
		{"nr",		'n', "NUM", CFG_POSITIVE, &cfg.cdw11,  required_argument, nr},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0) {
		err = fd;
		goto ret;
	}

	cfg.cdw10 = cfg.cntlid << 16;
	cfg.cdw10 = cfg.cdw10 | (cfg.rt << 8);
	cfg.cdw10 = cfg.cdw10 | cfg.act;

	err = nvme_virtual_mgmt(fd, cfg.cdw10, cfg.cdw11, &result);
	if (!err) {
		printf("success, Number of Resources allocated:%#x\n", result);
	} else if (err > 0) {
		show_nvme_status(err);
	} else
		perror("virt-mgmt");

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
	int err, fmt, fd;
	struct nvme_secondary_controllers_list *sc_list;

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

	const struct argconfig_commandline_options command_line_options[] = {
		{"cntid",         'c', "NUM", CFG_SHORT,    &cfg.cntid,         required_argument, controller},
		{"namespace-id",  'n', "NUM", CFG_POSITIVE, &cfg.namespace_id,  required_argument, namespace_id},
		{"num-entries",   'e', "NUM", CFG_POSITIVE, &cfg.num_entries,   required_argument, num_entries},
		{"output-format", 'o', "FMT", CFG_STRING,   &cfg.output_format, required_argument, output_format},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0) {
		err = fd;
		goto ret;
	}

	fmt = validate_output_format(cfg.output_format);
	if (fmt < 0) {
		err = fmt;
		goto close_fd;
	}

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
	if (!err) {
		if (fmt == BINARY)
			d_raw((unsigned char *)sc_list, sizeof(*sc_list));
		else if (fmt == JSON)
			json_nvme_list_secondary_ctrl(sc_list, cfg.num_entries);
		else
			show_nvme_list_secondary_ctrl(sc_list, cfg.num_entries);
	} else if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x) cntid:%d\n",
			nvme_status_to_string(err), err, cfg.cntid);
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
		__u32 cdw10;
	};

	struct config cfg = {
		.namespace_id  = NVME_NSID_ALL,
		.cdw10         = 0,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id",   'n', "NUM", CFG_POSITIVE, &cfg.namespace_id, required_argument, namespace_id},
		{"self-test-code", 's', "NUM", CFG_POSITIVE, &cfg.cdw10,        required_argument, self_test_code},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0) {
		err = fd;
		goto ret;
	}

	err = nvme_self_test_start(fd, cfg.namespace_id, cfg.cdw10);
	if (!err) {
		if ((cfg.cdw10 & 0xf) == 0xf)
			printf("Aborting device self-test operation\n");
		else
			printf("Device self-test started\n");
	} else if (err > 0) {
		show_nvme_status(err);
	} else
		perror("Device self-test");

	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int self_test_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	struct nvme_self_test_log self_test_log;
	const char *desc = "Retrieve the self-test log for the given device and given test "\
			"(or optionally a namespace) in either decoded format "\
			"(default) or binary.";
	int err, fmt, fd;

	struct config {
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"output-format", 'o', "FMT", CFG_STRING, &cfg.output_format, required_argument, output_format },
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0) {
		err = fd;
		goto ret;
	}

	fmt = validate_output_format(cfg.output_format);
	if (fmt < 0) {
		err = fmt;
		goto close_fd;
	}

	err = nvme_self_test_log(fd, &self_test_log);
	if (!err) {
		if (self_test_log.crnt_dev_selftest_compln == 100) {
			if (fmt == BINARY)
				d_raw((unsigned char *)&self_test_log, sizeof(self_test_log));
			else if (fmt == JSON)
				json_self_test_log(&self_test_log, devicename);
			else
				show_self_test_log(&self_test_log, devicename);
		} else {
			printf("Test is %d%% complete and is still in progress.\n",
				self_test_log.crnt_dev_selftest_compln);
		}
	} else if (err > 0) {
		show_nvme_status(err);
	} else {
		perror("self_test_log");
	}

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
	const char *raw_binary = "show infos in binary format";
	const char *namespace_id = "identifier of desired namespace";
	const char *feature_id = "feature identifier";
	const char *sel = "[0-3]: current/default/saved/supported";
	const char *data_len = "buffer len if data is returned through host memory buffer";
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

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id",   'n', "NUM", CFG_POSITIVE, &cfg.namespace_id,   required_argument, namespace_id},
		{"feature-id",     'f', "NUM", CFG_POSITIVE, &cfg.feature_id,     required_argument, feature_id},
		{"sel",            's', "NUM", CFG_BYTE,     &cfg.sel,            required_argument, sel},
		{"data-len",       'l', "NUM", CFG_POSITIVE, &cfg.data_len,       required_argument, data_len},
		{"raw-binary",     'b', "",    CFG_NONE,     &cfg.raw_binary,     no_argument,       raw_binary},
		{"cdw11",          'c', "NUM", CFG_POSITIVE, &cfg.cdw11,          required_argument, cdw11},
		{"human-readable", 'H', "",    CFG_NONE,     &cfg.human_readable, no_argument,       human_readable},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0) {
		err = fd;
		goto ret;
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

	switch (cfg.feature_id) {
	case NVME_FEAT_LBA_RANGE:
		cfg.data_len = 4096;
		break;
	case NVME_FEAT_AUTO_PST:
		cfg.data_len = 256;
		break;
	case NVME_FEAT_HOST_MEM_BUF:
		cfg.data_len = 4096;
		break;
	case NVME_FEAT_HOST_ID:
		cfg.data_len = 8;
		/* check for Extended Host Identifier */
		if (cfg.cdw11 & 0x1)
			cfg.data_len = 16;
		break;
	case NVME_FEAT_PLM_CONFIG:
		cfg.data_len = 512;
		break;
	case NVME_FEAT_TIMESTAMP:
		cfg.data_len = 8;
		break;
	}

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
			cfg.data_len, buf, &result);
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
		show_nvme_status(err);
	} else
		perror("get-feature");

	if (buf)
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

	const struct argconfig_commandline_options command_line_options[] = {
		{"fw",     'f', "FILE", CFG_STRING,   &cfg.fw,     required_argument, fw},
		{"xfer",   'x', "NUM",  CFG_POSITIVE, &cfg.xfer,   required_argument, xfer},
		{"offset", 'o', "NUM",  CFG_POSITIVE, &cfg.offset, required_argument, offset},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0) {
		err = fd;
		goto ret;
	}

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
	if (fw_size & 0x3) {
		fprintf(stderr, "Invalid size:%d for f/w image\n", fw_size);
		err = -EINVAL;
		goto close_fw_fd;
	}
	if (posix_memalign(&fw_buf, getpagesize(), fw_size)) {
		fprintf(stderr, "No memory for f/w size:%d\n", fw_size);
		err = -ENOMEM;
		goto close_fw_fd;
	}

	buf = fw_buf;
	if (cfg.xfer == 0 || cfg.xfer % 4096)
		cfg.xfer = 4096;
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
			show_nvme_status(err);
			break;
		}
		fw_buf     += cfg.xfer;
		fw_size    -= cfg.xfer;
		cfg.offset += cfg.xfer;
	}
	if (!err)
		printf("Firmware download success\n");

free:
	free(buf);
close_fw_fd:
	close(fw_fd);
close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static char *nvme_fw_status_reset_type(__u32 status)
{
	switch (status & 0x3ff) {
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

	const struct argconfig_commandline_options command_line_options[] = {
		{"slot",   's', "NUM", CFG_BYTE, &cfg.slot,   required_argument, slot},
		{"action", 'a', "NUM", CFG_BYTE, &cfg.action, required_argument, action},
		{"bpid",   'b', "NUM", CFG_BYTE, &cfg.bpid,   required_argument, bpid},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0) {
		err = fd;
		goto ret;
	}

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
		switch (err & 0x3ff) {
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
			show_nvme_status(err);
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

	const struct argconfig_commandline_options command_line_options[] = {
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, NULL, 0);
	if (fd < 0) {
		err = fd;
		goto ret;
	}

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

	const struct argconfig_commandline_options command_line_options[] = {
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, NULL, 0);
	if (fd < 0) {
		err = fd;
		goto ret;
	}

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

	const struct argconfig_commandline_options command_line_options[] = {
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, NULL, 0);
	if (fd < 0) {
		err = fd;
		goto ret;
	}

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

	int fd;
	int ret;

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

	const struct argconfig_commandline_options command_line_options[] = {
		{"no-dealloc", 'd', "",    CFG_NONE,     &cfg.no_dealloc, no_argument,       no_dealloc_desc},
		{"oipbp",      'i', "",    CFG_NONE,     &cfg.oipbp,      no_argument,       oipbp_desc},
		{"owpass",     'n', "NUM", CFG_BYTE,     &cfg.owpass,     required_argument, owpass_desc},
		{"ause",       'u', "",    CFG_NONE,     &cfg.ause,       no_argument,       ause_desc},
		{"sanact",     'a', "NUM", CFG_BYTE,     &cfg.sanact,     required_argument, sanact_desc},
		{"ovrpat",     'p', "NUM", CFG_POSITIVE, &cfg.ovrpat,     required_argument, ovrpat_desc},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, NULL, 0);
	if (fd < 0) {
		ret = fd;
		goto ret;
	}

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
		if (cfg.owpass > 16) {
			fprintf(stderr, "OWPASS out of range [0-16]\n");
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
		show_nvme_status(ret);

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
	void *bar;
	int fd, err, fmt;
	bool fabrics = true;
	const int reg_size = 0x50;  /* 00h to 4Fh */

	struct config {
		int human_readable;
		char *output_format;
	};

	struct config cfg = {
		.human_readable = 0,
		.output_format = "normal",
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"human-readable", 'H', "", CFG_NONE, &cfg.human_readable, no_argument, human_readable},
		{"output-format", 'o', "FMT", CFG_STRING, &cfg.output_format, required_argument, output_format},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0) {
		err = fd;
		goto ret;
	}

	fmt = validate_output_format(cfg.output_format);
	if (fmt < 0) {
		fprintf(stderr, "Invalid argument --output-format=%s\n",
				cfg.output_format);
		err = -fmt;
		goto close_fd;
	}

	if (cfg.human_readable && fmt != NORMAL) {
		fprintf(stderr, "Only --output-format=normal supports -H\n");
		err = -EINVAL;
		goto close_fd;
	}

	err = nvme_get_properties(fd, &bar);
	if (err) {
		bar = get_registers();
		fabrics = false;
		if (bar)
			err = 0;
	}
	if (!bar) {
		err = -ENODEV;
		goto close_fd;
	}

	if (fmt == BINARY)
		d_raw((unsigned char *) bar, reg_size);
	else if (fmt == JSON)
		json_ctrl_registers(bar);
	else
		show_ctrl_registers(bar, cfg.human_readable ? HUMAN : 0, fabrics);

	if (fabrics)
		free(bar);

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
	const char *human_readable = "show infos in readable format";

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

	const struct argconfig_commandline_options command_line_options[] = {
		{"offset", 'o', "NUM", CFG_POSITIVE, &cfg.offset, required_argument, offset},
		{"human-readable", 'H', "", CFG_NONE, &cfg.human_readable, no_argument, human_readable},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0) {
		err = fd;
		goto ret;
	}

	if (cfg.offset == -1) {
		fprintf(stderr, "offset required param");
		err = -EINVAL;
		goto close_fd;
	}

	err = nvme_get_property(fd, cfg.offset, &value);
	if (err < 0) {
		perror("get-property");
	} else if (!err) {
		show_single_property(cfg.offset, value, cfg.human_readable);
	} else if (err > 0) {
		show_nvme_status(err);
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

	const struct argconfig_commandline_options command_line_options[] = {
		{"offset", 'o', "NUM", CFG_POSITIVE, &cfg.offset, required_argument, offset},
		{"value", 'v', "NUM", CFG_POSITIVE, &cfg.value, required_argument, value},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0) {
		err = fd;
		goto ret;
	}

	if (cfg.offset == -1) {
		fprintf(stderr, "offset required param");
		err = -EINVAL;
		goto close_fd;
	}
	if (cfg.value == -1) {
		fprintf(stderr, "value required param");
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
		show_nvme_status(err);
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
	struct nvme_id_ns ns;
	int err, fd, i;
	__u8 prev_lbaf = 0;
	__u8 lbads = 0;

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
	};

	struct config cfg = {
		.namespace_id = NVME_NSID_ALL,
		.timeout      = 600000,
		.lbaf         = 0xff,
		.ses          = 0,
		.pi           = 0,
		.reset        = 0,
		.bs           = 0,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id", 'n', "NUM",  CFG_POSITIVE, &cfg.namespace_id, required_argument, namespace_id},
		{"timeout",      't', "NUM",  CFG_POSITIVE, &cfg.timeout,      required_argument, timeout},
		{"lbaf",         'l', "NUM",  CFG_BYTE,     &cfg.lbaf,         required_argument, lbaf},
		{"ses",          's', "NUM",  CFG_BYTE,     &cfg.ses,          required_argument, ses},
		{"pi",           'i', "NUM",  CFG_BYTE,     &cfg.pi,           required_argument, pi},
		{"pil",          'p', "NUM",  CFG_BYTE,     &cfg.pil,          required_argument, pil},
		{"ms",           'm', "NUM",  CFG_BYTE,     &cfg.ms,           required_argument, ms},
		{"reset",        'r', "",     CFG_NONE,     &cfg.reset,        no_argument,       reset},
		{"block-size",   'b', "NUM",  CFG_LONG_SUFFIX, &cfg.bs,        required_argument, bs},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0) {
		err = fd;
		goto ret;
	}

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
	if (S_ISBLK(nvme_stat.st_mode)) {
		cfg.namespace_id = get_nsid(fd);
		if (cfg.namespace_id == 0) {
			err = -EINVAL;
			goto close_fd;
		}
	}
	if (cfg.namespace_id != NVME_NSID_ALL) {
		err = nvme_identify_ns(fd, cfg.namespace_id, 0, &ns);
		if (err) {
			if (err < 0)
				perror("identify-namespace");
			else {
				fprintf(stderr, "identify failed\n");
				show_nvme_status(err);
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
					"LBAF corresponding to block size %"PRIu64"(LBAF %u) not found\n",
					(uint64_t)cfg.bs, lbads);
				fprintf(stderr,
					"Please correct block size, or specify LBAF directly\n");
				err = -EINVAL;
				goto close_fd;
			}
		} else  if (cfg.lbaf == 0xff)
			cfg.lbaf = prev_lbaf;
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

	err = nvme_format(fd, cfg.namespace_id, cfg.lbaf, cfg.ses, cfg.pi,
				cfg.pil, cfg.ms, cfg.timeout);
	if (err < 0)
		perror("format");
	else if (err != 0)
		show_nvme_status(err);
	else {
		printf("Success formatting namespace:%x\n", cfg.namespace_id);
		if (S_ISBLK(nvme_stat.st_mode) && ioctl(fd, BLKRRPART) < 0) {
			fprintf(stderr, "failed to re-read partition table\n");
			err = -errno;
			goto close_fd;
		}

		if (cfg.reset && S_ISCHR(nvme_stat.st_mode))
			nvme_reset_controller(fd);
	}

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

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
	int err;
	__u32 result;
	void *buf = NULL;
	int fd, ffd = STDIN_FILENO;

	struct config {
		char *file;
		__u32 namespace_id;
		__u32 feature_id;
		__u32 value;
		__u32 cdw12;
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

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id", 'n', "NUM",  CFG_POSITIVE, &cfg.namespace_id, required_argument, namespace_id},
		{"feature-id",   'f', "NUM",  CFG_POSITIVE, &cfg.feature_id,   required_argument, feature_id},
		{"value",        'v', "NUM",  CFG_POSITIVE, &cfg.value,        required_argument, value},
		{"cdw12",        'c', "NUM",  CFG_POSITIVE, &cfg.cdw12,        required_argument, cdw12},
		{"data-len",     'l', "NUM",  CFG_POSITIVE, &cfg.data_len,     required_argument, data_len},
		{"data",         'd', "FILE", CFG_STRING,   &cfg.file,         required_argument, data},
		{"save",         's', "",     CFG_NONE,     &cfg.save,         no_argument,       save},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0) {
		err = fd;
		goto ret;
	}

	if (!cfg.feature_id) {
		fprintf(stderr, "feature-id required param\n");
		err = -EINVAL;
		goto close_fd;
	}
	if (cfg.feature_id == NVME_FEAT_LBA_RANGE)
		cfg.data_len = 4096;
	if (cfg.data_len) {
		if (posix_memalign(&buf, getpagesize(), cfg.data_len)) {
			fprintf(stderr, "can not allocate feature payload\n");
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
					" file: %s\n", strerror(errno));
			goto close_ffd;
		}
	}

	err = nvme_set_feature(fd, cfg.namespace_id, cfg.feature_id, cfg.value,
			       cfg.cdw12, cfg.save, cfg.data_len, buf, &result);
	if (err < 0) {
		perror("set-feature");
	} else if (!err) {
		printf("set-feature:%02x (%s), value:%#08x\n", cfg.feature_id,
			nvme_feature_to_string(cfg.feature_id), cfg.value);
		if (buf) {
			if (cfg.feature_id == NVME_FEAT_LBA_RANGE)
				show_lba_range((struct nvme_lba_range_type *)buf,
								result);
			else
				d(buf, cfg.data_len, 16, 1);
		}
	} else if (err > 0)
		show_nvme_status(err);

close_ffd:
	close(ffd);
free:
	if (buf)
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
	__u32 result;

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

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id", 'n', "NUM",  CFG_POSITIVE, &cfg.namespace_id, required_argument, namespace_id},
		{"file",         'f', "FILE", CFG_STRING,   &cfg.file,         required_argument, file},
		{"nssf",         'N', "NUM",  CFG_BYTE,     &cfg.nssf,         required_argument, nssf},
		{"secp",         'p', "NUM",  CFG_BYTE,     &cfg.secp,         required_argument, secp},
		{"spsp",         's', "NUM",  CFG_SHORT,    &cfg.spsp,         required_argument, spsp},
		{"tl",           't', "NUM",  CFG_POSITIVE, &cfg.tl,           required_argument, tl},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0) {
		err = fd;
		goto ret;
	}

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
			cfg.tl, sec_size, sec_buf, &result);
	if (err < 0)
		perror("security-send");
	else if (err != 0)
		fprintf(stderr, "NVME Security Send Command Error:%d\n", err);
	else
		printf("NVME Security Send Command Success:%d\n", result);

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
	const char *raw_binary = "show infos in binary format";
	const char *namespace_id = "identifier of desired namespace";
	const char *data_len = "buffer len (if) data is returned";
	const char *dtype = "directive type";
	const char *dspec = "directive specification associated with directive type";
	const char *doper = "directive operation";
	const char *endir = "directive enable";
	const char *ttype = "target directive type to be enabled/disabled";
	const char *human_readable = "show infos in readable format";
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

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id",   'n', "NUM", CFG_POSITIVE, &cfg.namespace_id,   required_argument, namespace_id},
		{"data-len",       'l', "NUM", CFG_POSITIVE, &cfg.data_len,       required_argument, data_len},
		{"raw-binary",     'b', "FLAG",CFG_NONE,     &cfg.raw_binary,     no_argument,       raw_binary},
		{"dir-type",       'D', "NUM", CFG_BYTE,     &cfg.dtype,          required_argument, dtype},
		{"target-dir",     'T', "NUM", CFG_BYTE,     &cfg.ttype,          required_argument, ttype},
		{"dir-spec",       'S', "NUM", CFG_SHORT,    &cfg.dspec,          required_argument, dspec},
		{"dir-oper",       'O', "NUM", CFG_BYTE,     &cfg.doper,          required_argument, doper},
		{"endir",          'e', "NUM", CFG_SHORT,    &cfg.endir,          required_argument, endir},
		{"human-readable", 'H', "FLAG",CFG_NONE,     &cfg.human_readable, no_argument,       human_readable},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0) {
		err = fd;
		goto ret;
	}

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
	}
	else if (err > 0)
		show_nvme_status(err);

close_ffd:
	close(ffd);
free:
	if (buf)
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

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id", 'n', "NUM", CFG_POSITIVE,    &cfg.namespace_id, required_argument, namespace_id},
		{"start-block",  's', "NUM", CFG_LONG_SUFFIX, &cfg.start_block,  required_argument, start_block},
		{"block-count",  'c', "NUM", CFG_SHORT,       &cfg.block_count,  required_argument, block_count},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0) {
		err = fd;
		goto ret;
	}

	if (!cfg.namespace_id) {
		cfg.namespace_id = get_nsid(fd);
		if (cfg.namespace_id == 0) {
			err = -EINVAL;
			goto close_fd;
		}
	}

	err = nvme_write_uncorrectable(fd, cfg.namespace_id, cfg.start_block,
					cfg.block_count);
	if (err < 0)
		perror("write uncorrectable");
	else if (err != 0)
		show_nvme_status(err);
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

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id",      'n', "NUM", CFG_POSITIVE,    &cfg.namespace_id,      required_argument, namespace_id},
		{"start-block",       's', "NUM", CFG_LONG_SUFFIX, &cfg.start_block,       required_argument, start_block},
		{"block-count",       'c', "NUM", CFG_SHORT,       &cfg.block_count,       required_argument, block_count},
		{"deac",              'd', "",    CFG_NONE,        &cfg.deac,              no_argument,       deac},
		{"limited-retry",     'l', "",    CFG_NONE,        &cfg.limited_retry,     no_argument,       limited_retry},
		{"force-unit-access", 'f', "",    CFG_NONE,        &cfg.force_unit_access, no_argument,       force},
		{"prinfo",            'p', "NUM", CFG_BYTE,        &cfg.prinfo,            required_argument, prinfo},
		{"ref-tag",           'r', "NUM", CFG_POSITIVE,    &cfg.ref_tag,           required_argument, ref_tag},
		{"app-tag-mask",      'm', "NUM", CFG_SHORT,       &cfg.app_tag_mask,      required_argument, app_tag_mask},
		{"app-tag",           'a', "NUM", CFG_SHORT,       &cfg.app_tag,           required_argument, app_tag},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0) {
		err = fd;
		goto ret;
	}

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
		cfg.namespace_id = get_nsid(fd);
		if (cfg.namespace_id == 0) {
			err = -EINVAL;
			goto close_fd;
		}
	}

	err = nvme_write_zeros(fd, cfg.namespace_id, cfg.start_block, cfg.block_count,
			control, cfg.ref_tag, cfg.app_tag, cfg.app_tag_mask);
	if (err < 0)
		perror("write-zeroes");
	else if (err != 0)
		show_nvme_status(err);
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

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id", 'n', "NUM",  CFG_POSITIVE, &cfg.namespace_id, required_argument, namespace_id},
		{"ctx-attrs",    'a', "LIST", CFG_STRING,   &cfg.ctx_attrs,    required_argument, context_attrs},
		{"blocks", 	 'b', "LIST", CFG_STRING,   &cfg.blocks,       required_argument, blocks},
		{"slbs", 	 's', "LIST", CFG_STRING,   &cfg.slbas,        required_argument, starting_blocks},
		{"ad", 	         'd', "",     CFG_NONE,     &cfg.ad,           no_argument,       ad},
		{"idw", 	 'w', "",     CFG_NONE,     &cfg.idw,          no_argument,       idw},
		{"idr", 	 'r', "",     CFG_NONE,     &cfg.idr,          no_argument,       idr},
		{"cdw11",        'c', "NUM",  CFG_POSITIVE, &cfg.cdw11,        required_argument, cdw11},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0) {
		err = fd;
		goto ret;
	}

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
		cfg.namespace_id = get_nsid(fd);
		if (cfg.namespace_id == 0) {
			err = -EINVAL;
			goto close_fd;
		}
	}
	if (!cfg.cdw11)
		cfg.cdw11 = (cfg.ad << 2) | (cfg.idw << 1) | (cfg.idr << 0);

	dsm = nvme_setup_dsm_range((__u32 *)ctx_attrs, (__u32 *)nlbs, (__u64 *)slbas, nr);
	if (!dsm) {
		fprintf(stderr, "failed to allocate data set payload\n");
		err = -ENOMEM;
		goto close_fd;
	}

	err = nvme_dsm(fd, cfg.namespace_id, cfg.cdw11, dsm, nr);
	if (err < 0)
		perror("data-set management");
	else if (err != 0)
		show_nvme_status(err);
	else
		printf("NVMe DSM: success\n");

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
		.namespace_id = NVME_NSID_ALL,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id", 'n', "NUM",  CFG_POSITIVE,    &cfg.namespace_id, required_argument, namespace_id},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0) {
		err = fd;
		goto ret;
	}

	if (S_ISBLK(nvme_stat.st_mode)) {
		cfg.namespace_id = get_nsid(fd);
		if (cfg.namespace_id == 0) {
			err = -EINVAL;
			goto close_fd;
		}
	}

	err = nvme_flush(fd, cfg.namespace_id);
	if (err < 0)
		perror("flush");
	else if (err != 0)
		show_nvme_status(err);
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
	const char *racqa = "reservation acquiry action";
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

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id", 'n', "NUM", CFG_POSITIVE,    &cfg.namespace_id, required_argument, namespace_id},
		{"crkey",        'c', "NUM", CFG_LONG_SUFFIX, &cfg.crkey,        required_argument, crkey},
		{"prkey",        'p', "NUM", CFG_LONG_SUFFIX, &cfg.prkey,        required_argument, prkey},
		{"rtype",        't', "NUM", CFG_BYTE,        &cfg.rtype,        required_argument, rtype},
		{"racqa",        'a', "NUM", CFG_BYTE,        &cfg.racqa,        required_argument, racqa},
		{"iekey",        'i', "",    CFG_NONE,        &cfg.iekey,        no_argument,       iekey},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0) {
		err = fd;
		goto ret;
	}

	if (!cfg.namespace_id) {
		cfg.namespace_id = get_nsid(fd);
		if (cfg.namespace_id == 0) {
			err = -EINVAL;
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
		show_nvme_status(err);
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

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id", 'n', "NUM", CFG_POSITIVE,    &cfg.namespace_id, required_argument, namespace_id},
		{"crkey",        'c', "NUM", CFG_LONG_SUFFIX, &cfg.crkey,        required_argument, crkey},
		{"nrkey",        'k', "NUM", CFG_LONG_SUFFIX, &cfg.nrkey,        required_argument, nrkey},
		{"rrega",        'r', "NUM", CFG_BYTE,        &cfg.rrega,        required_argument, rrega},
		{"cptpl",        'p', "NUM", CFG_BYTE,        &cfg.cptpl,        required_argument, cptpl},
		{"iekey",        'i', "",    CFG_NONE,        &cfg.iekey,        no_argument,       iekey},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0) {
		err = fd;
		goto ret;
	}

	if (!cfg.namespace_id) {
		cfg.namespace_id = get_nsid(fd);
		if (cfg.namespace_id == 0) {
			err = -EINVAL;
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
		show_nvme_status(err);
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

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id", 'n', "NUM",  CFG_POSITIVE,    &cfg.namespace_id, required_argument, namespace_id},
		{"crkey",        'c', "NUM",  CFG_LONG_SUFFIX, &cfg.crkey,        required_argument, crkey},
		{"rtype",        't', "NUM",  CFG_BYTE,        &cfg.rtype,        required_argument, rtype},
		{"rrela",        'a', "NUM",  CFG_BYTE,        &cfg.rrela,        required_argument, rrela},
		{"iekey",        'i', "",     CFG_NONE,        &cfg.iekey,        no_argument, iekey},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0) {
		err = fd;
		goto ret;
	}

	if (!cfg.namespace_id) {
		cfg.namespace_id = get_nsid(fd);
		if (cfg.namespace_id == 0) {
			err = -EINVAL;
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
		show_nvme_status(err);
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
	const char *raw_binary = "dump output in binary format";

	int err, fmt, fd, size;
	struct nvme_reservation_status *status;

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

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id",  'n', "NUM", CFG_POSITIVE, &cfg.namespace_id,  required_argument, namespace_id},
		{"numd",          'd', "NUM", CFG_POSITIVE, &cfg.numd,          required_argument, numd},
		{"cdw11",         'c', "NUM", CFG_POSITIVE, &cfg.cdw11,         required_argument, cdw11},
		{"raw-binary",    'b', "",    CFG_NONE,     &cfg.raw_binary,    no_argument,       raw_binary},
		{"output-format", 'o', "FMT", CFG_STRING,   &cfg.output_format, required_argument, output_format },
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0) {
		err = fd;
		goto ret;
	}

	fmt = validate_output_format(cfg.output_format);
	if (fmt < 0) {
		err = fmt;
		goto close_fd;
	}
	if (cfg.raw_binary)
		fmt = BINARY;

	if (!cfg.namespace_id) {
		cfg.namespace_id = get_nsid(fd);
		if (cfg.namespace_id == 0) {
			err = -EINVAL;
			goto close_fd;
		}
	}
	if (!cfg.numd || cfg.numd >= (0x1000 >> 2))
		cfg.numd = (0x1000 >> 2) - 1;
	if (cfg.numd < 3)
		cfg.numd = 3; /* get the header fields at least */

	size = (cfg.numd + 1) << 2;

	if (posix_memalign((void **)&status, getpagesize(), size)) {
		fprintf(stderr, "No memory for resv report:%d\n", size);
		err = -ENOMEM;
		goto close_fd;
	}
	memset(status, 0, size);

	err = nvme_resv_report(fd, cfg.namespace_id, cfg.numd, cfg.cdw11, status);
	if (err < 0)
		perror("reservation report");
	else if (err != 0)
		fprintf(stderr, "NVME IO command error:%04x\n", err);
	else {
		if (fmt == BINARY)
			d_raw((unsigned char *)status, size);
		else if (fmt == JSON)
			json_nvme_resv_report(status, size, cfg.cdw11);
		else {
			printf("NVME Reservation Report success\n");
			show_nvme_resv_report(status, size, cfg.cdw11);
		}
	}
	free(status);

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
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
	__u32 dsmgmt = 0;
	int phys_sector_size = 0;
	long long buffer_size = 0;

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

	const struct argconfig_commandline_options command_line_options[] = {
		{"start-block",       's', "NUM",  CFG_LONG_SUFFIX, &cfg.start_block,       required_argument, start_block},
		{"block-count",       'c', "NUM",  CFG_SHORT,       &cfg.block_count,       required_argument, block_count},
		{"data-size",         'z', "NUM",  CFG_LONG_SUFFIX, &cfg.data_size,         required_argument, data_size},
		{"metadata-size",     'y', "NUM",  CFG_LONG_SUFFIX, &cfg.metadata_size,     required_argument, metadata_size},
		{"ref-tag",           'r', "NUM",  CFG_POSITIVE,    &cfg.ref_tag,           required_argument, ref_tag},
		{"data",              'd', "FILE", CFG_STRING,      &cfg.data,              required_argument, data},
		{"metadata",          'M', "FILE", CFG_STRING,      &cfg.metadata,          required_argument, metadata},
		{"prinfo",            'p', "NUM",  CFG_BYTE,        &cfg.prinfo,            required_argument, prinfo},
		{"app-tag-mask",      'm', "NUM",  CFG_SHORT,       &cfg.app_tag_mask,      required_argument, app_tag_mask},
		{"app-tag",           'a', "NUM",  CFG_SHORT,       &cfg.app_tag,           required_argument, app_tag},
		{"limited-retry",     'l', "",     CFG_NONE,        &cfg.limited_retry,     no_argument,       limited_retry},
		{"force-unit-access", 'f', "",     CFG_NONE,        &cfg.force_unit_access, no_argument,       force},
		{"dir-type",          'T', "NUM",  CFG_BYTE,        &cfg.dtype,             required_argument, dtype},
		{"dir-spec",          'S', "NUM",  CFG_SHORT,       &cfg.dspec,             required_argument, dspec},
		{"dsm",               'D', "NUM",  CFG_SHORT,       &cfg.dsmgmt,            required_argument, dsm},
		{"show-command",      'v', "",     CFG_NONE,        &cfg.show,              no_argument,       show},
		{"dry-run",           'w', "",     CFG_NONE,        &cfg.dry_run,           no_argument,       dry},
		{"latency",           't', "",     CFG_NONE,        &cfg.latency,           no_argument,       latency},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0) {
		err = fd;
		goto ret;
	}

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

	if (ioctl(fd, BLKPBSZGET, &phys_sector_size) < 0)
		goto close_mfd;

	buffer_size = (cfg.block_count + 1) * phys_sector_size;
	if (cfg.data_size < buffer_size) {
		fprintf(stderr, "Rounding data size to fit block count (%lld bytes)\n",
				buffer_size);
	} else {
		buffer_size = cfg.data_size;
	}

	if (posix_memalign(&buffer, getpagesize(), buffer_size)) {
		fprintf(stderr, "can not allocate io payload\n");
		err = -ENOMEM;
		goto close_mfd;
	}
	memset(buffer, 0, buffer_size);

	if (cfg.metadata_size) {
		mbuffer = malloc(cfg.metadata_size);
		if (!mbuffer) {
			fprintf(stderr, "can not allocate io metadata "
					"payload: %s\n", strerror(errno));
			err = -ENOMEM;
			goto free_buffer;
		}
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
		err = read(mfd, (void *)mbuffer, cfg.metadata_size);
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
		printf("rsvd         : %04x\n", 0);
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
		show_nvme_status(err);
	else {
		if (!(opcode & 1) && write(dfd, (void *)buffer, cfg.data_size) < 0) {
			fprintf(stderr, "write: %s: failed to write buffer to output file\n",
					strerror(errno));
			err = -EINVAL;
		} else if (!(opcode & 1) && cfg.metadata_size &&
				write(mfd, (void *)mbuffer, cfg.metadata_size) < 0) {
			fprintf(stderr, "write: %s: failed to write meta-data buffer to output file\n",
					strerror(errno));
			err = -EINVAL;
		} else
			fprintf(stderr, "%s: Success\n", command);
	}

free_mbuffer:
	if (cfg.metadata_size)
		free(mbuffer);
free_buffer:
	free(buffer);
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

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id",      'n', "NUM", CFG_POSITIVE,    &cfg.namespace_id,      required_argument, namespace_id},
		{"start-block",       's', "NUM", CFG_LONG_SUFFIX, &cfg.start_block,       required_argument, start_block},
		{"block-count",       'c', "NUM", CFG_SHORT,       &cfg.block_count,       required_argument, block_count},
		{"limited-retry",     'l', "",    CFG_NONE,        &cfg.limited_retry,     no_argument,       limited_retry},
		{"force-unit-access", 'f', "",    CFG_NONE,        &cfg.force_unit_access, no_argument,       force},
		{"prinfo",            'p', "NUM", CFG_BYTE,        &cfg.prinfo,            required_argument, prinfo},
		{"ref-tag",           'r', "NUM", CFG_POSITIVE,    &cfg.ref_tag,           required_argument, ref_tag},
		{"app-tag",           'a', "NUM", CFG_SHORT,       &cfg.app_tag,           required_argument, app_tag},
		{"app-tag-mask",      'm', "NUM", CFG_SHORT,       &cfg.app_tag_mask,      required_argument, app_tag_mask},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0)
		return fd;

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
		cfg.namespace_id = get_nsid(fd);
		if (cfg.namespace_id == 0) {
			err = EINVAL;
			goto close_fd;
		}
	}

	err = nvme_verify(fd, cfg.namespace_id, cfg.start_block, cfg.block_count,
				control, cfg.ref_tag, cfg.app_tag, cfg.app_tag_mask);
	if (err < 0)
		perror("verify");
	else if (err != 0)
		show_nvme_status(err);
	else
		printf("NVME Verify Success\n");

close_fd:
	close(fd);
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
	const char *raw_binary = "dump output in binary format";
	const char *namespace_id = "desired namespace";
	const char *nssf = "NVMe Security Specific Field";
	int err, fd;
	void *sec_buf = NULL;
	__u32 result;

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

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id", 'n', "NUM", CFG_POSITIVE, &cfg.namespace_id, required_argument, namespace_id},
		{"size",         'x', "NUM", CFG_POSITIVE, &cfg.size,         required_argument, size},
		{"nssf",         'N', "NUM", CFG_BYTE,     &cfg.nssf,         required_argument, nssf},
		{"secp",         'p', "NUM", CFG_BYTE,     &cfg.secp,         required_argument, secp},
		{"spsp",         's', "NUM", CFG_SHORT,    &cfg.spsp,         required_argument, spsp},
		{"al",           't', "NUM", CFG_POSITIVE, &cfg.al,           required_argument, al},
		{"raw-binary",   'b', "",    CFG_NONE,     &cfg.raw_binary,   no_argument,       raw_binary},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0) {
		err = fd;
		goto ret;
	}

	if (cfg.size) {
		if (posix_memalign(&sec_buf, getpagesize(), cfg.size)) {
			fprintf(stderr, "No memory for security size:%d\n",
								cfg.size);
			err = -ENOMEM;
			goto close_fd;
		}
	}

	err = nvme_sec_recv(fd, cfg.namespace_id, cfg.nssf, cfg.spsp,
			cfg.secp, cfg.al, cfg.size, sec_buf, &result);
	if (err < 0)
		perror("security receive");
	else if (err != 0)
		fprintf(stderr, "NVME Security Receive Command Error:%d\n",
									err);
	else {
		if (!cfg.raw_binary) {
			printf("NVME Security Receive Command Success:%d\n",
							result);
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

static int dir_receive(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Read directive parameters of the "\
			    "specified directive type.";
	const char *raw_binary = "show infos in binary format";
	const char *namespace_id = "identifier of desired namespace";
	const char *data_len = "buffer len (if) data is returned";
	const char *dtype = "directive type";
	const char *dspec = "directive specification associated with directive type";
	const char *doper = "directive operation";
	const char *nsr = "namespace stream requested";
	const char *human_readable = "show infos in readable format";
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

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id",   'n', "NUM", CFG_POSITIVE, &cfg.namespace_id,   required_argument, namespace_id},
		{"data-len",       'l', "NUM", CFG_POSITIVE, &cfg.data_len,       required_argument, data_len},
		{"raw-binary",     'b', "FLAG",CFG_NONE,     &cfg.raw_binary,     no_argument,       raw_binary},
		{"dir-type",       'D', "NUM", CFG_BYTE,     &cfg.dtype,          required_argument, dtype},
		{"dir-spec",       'S', "NUM", CFG_SHORT,    &cfg.dspec,          required_argument, dspec},
		{"dir-oper",       'O', "NUM", CFG_BYTE,     &cfg.doper,          required_argument, doper},
		{"req-resource",   'r', "NUM", CFG_SHORT,    &cfg.nsr,            required_argument, nsr},
		{"human-readable", 'H', "FLAG",CFG_NONE,     &cfg.human_readable, no_argument,       human_readable},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0) {
		err = fd;
		goto ret;
	}

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
	if (err < 0) {
		perror("dir-receive");
		goto free;
	}

	if (!err) {
		printf("dir-receive: type %#x, operation %#x, spec %#x, nsid %#x, result %#x \n",
				cfg.dtype, cfg.doper, cfg.dspec, cfg.namespace_id, result);
		if (cfg.human_readable)
			nvme_directive_show_fields(cfg.dtype, cfg.doper, result, buf);
		else {
			if (buf) {
				if (!cfg.raw_binary)
					d(buf, cfg.data_len, 16, 1);
				else
					d_raw(buf, cfg.data_len);
			}
		}
	}
	else if (err > 0)
		show_nvme_status(err);
free:
	if (cfg.data_len)
		free(buf);
close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int passthru(int argc, char **argv, int ioctl_cmd, const char *desc, struct command *cmd)
{
	void *data = NULL, *metadata = NULL;
	int err = 0, wfd = STDIN_FILENO, fd;
	__u32 result;

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
	const char *prefill = "prefill buffer with known byte-value, default 0";

	const struct argconfig_commandline_options command_line_options[] = {
		{"opcode",       'o', "NUM",  CFG_BYTE,     &cfg.opcode,       required_argument, opcode},
		{"flags",        'f', "NUM",  CFG_BYTE,     &cfg.flags,        required_argument, flags},
		{"prefill",      'p', "NUM",  CFG_BYTE,     &cfg.prefill,      required_argument, prefill},
		{"rsvd",         'R', "NUM",  CFG_SHORT,    &cfg.rsvd,         required_argument, rsvd},
		{"namespace-id", 'n', "NUM",  CFG_POSITIVE, &cfg.namespace_id, required_argument, namespace_id},
		{"data-len",     'l', "NUM",  CFG_POSITIVE, &cfg.data_len,     required_argument, data_len},
		{"metadata-len", 'm', "NUM",  CFG_POSITIVE, &cfg.metadata_len, required_argument, metadata_len},
		{"timeout",      't', "NUM",  CFG_POSITIVE, &cfg.timeout,      required_argument, timeout},
		{"cdw2",         '2', "NUM",  CFG_POSITIVE, &cfg.cdw2,         required_argument, cdw2},
		{"cdw3",         '3', "NUM",  CFG_POSITIVE, &cfg.cdw3,         required_argument, cdw3},
		{"cdw10",        '4', "NUM",  CFG_POSITIVE, &cfg.cdw10,        required_argument, cdw10},
		{"cdw11",        '5', "NUM",  CFG_POSITIVE, &cfg.cdw11,        required_argument, cdw11},
		{"cdw12",        '6', "NUM",  CFG_POSITIVE, &cfg.cdw12,        required_argument, cdw12},
		{"cdw13",        '7', "NUM",  CFG_POSITIVE, &cfg.cdw13,        required_argument, cdw13},
		{"cdw14",        '8', "NUM",  CFG_POSITIVE, &cfg.cdw14,        required_argument, cdw14},
		{"cdw15",        '9', "NUM",  CFG_POSITIVE, &cfg.cdw15,        required_argument, cdw15},
		{"input-file",   'i', "FILE", CFG_STRING,   &cfg.input_file,   required_argument, input},
		{"raw-binary",   'b', "",     CFG_NONE,     &cfg.raw_binary,   no_argument,       raw_binary},
		{"show-command", 's', "",     CFG_NONE,     &cfg.show_command, no_argument,       show},
		{"dry-run",      'd', "",     CFG_NONE,     &cfg.dry_run,      no_argument,       dry},
		{"read",         'r', "",     CFG_NONE,     &cfg.read,         no_argument,       re},
		{"write",        'w', "",     CFG_NONE,     &cfg.write,        no_argument,       wr},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0) {
		err = fd;
		goto ret;
	}

	if (strlen(cfg.input_file)){
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
			fprintf(stderr, "can not allocate metadata "
					"payload: %s\n", strerror(errno));
			err = -ENOMEM;
			goto close_wfd;
		}
	}
	if (cfg.data_len) {
		if (posix_memalign(&data, getpagesize(), cfg.data_len)) {
			fprintf(stderr, "can not allocate data payload\n");
			err = -ENOMEM;
			goto free_metadata;
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

	err = nvme_passthru(fd, ioctl_cmd, cfg.opcode, cfg.flags, cfg.rsvd,
				cfg.namespace_id, cfg.cdw2, cfg.cdw3, cfg.cdw10,
				cfg.cdw11, cfg.cdw12, cfg.cdw13, cfg.cdw14, cfg.cdw15,
				cfg.data_len, data, cfg.metadata_len, metadata,
				cfg.timeout, &result);
	if (err < 0)
		perror("passthru");
	else if (err)
		show_nvme_status(err);
	else  {
		if (!cfg.raw_binary) {
			fprintf(stderr, "NVMe command result:%08x\n", result);
			if (data && cfg.read && !err)
				d((unsigned char *)data, cfg.data_len, 16, 1);
		} else if (data && cfg.read)
			d_raw((unsigned char *)data, cfg.data_len);
	}

free_data:
	if (cfg.data_len)
		free(data);
free_metadata:
	if (cfg.metadata_len)
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
	return passthru(argc, argv, NVME_IOCTL_IO_CMD, desc, cmd);
}

static int admin_passthru(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Send a user-defined Admin command to the specified "\
		"device via IOCTL passthrough, return results.";
	return passthru(argc, argv, NVME_IOCTL_ADMIN_CMD, desc, cmd);
}

#ifdef LIBUUID
static int gen_hostnqn_cmd(int argc, char **argv, struct command *command, struct plugin *plugin)
{
	uuid_t uuid;
	char uuid_str[37]; /* e.g. 1b4e28ba-2fa1-11d2-883f-0016d3cca427 + \0 */

	uuid_generate_random(uuid);
	uuid_unparse_lower(uuid, uuid_str);
	printf("nqn.2014-08.org.nvmexpress:uuid:%s\n", uuid_str);
	return 0;
}
#else
static int gen_hostnqn_cmd(int argc, char **argv, struct command *command, struct plugin *plugin)
{
	fprintf(stderr, "\"%s\" not supported. Install lib uuid and rebuild.\n",
		command->name);
	return -ENOTSUP;
}
#endif

static int discover_cmd(int argc, char **argv, struct command *command, struct plugin *plugin)
{
	const char *desc = "Send Get Log Page request to Discovery Controller.";
	return discover(desc, argc, argv, false);
}

static int connect_all_cmd(int argc, char **argv, struct command *command, struct plugin *plugin)
{
	const char *desc = "Discover NVMeoF subsystems and connect to them";
	return discover(desc, argc, argv, true);
}

static int connect_cmd(int argc, char **argv, struct command *command, struct plugin *plugin)
{
	const char *desc = "Connect to NVMeoF subsystem";
	return connect(desc, argc, argv);
}

static int disconnect_cmd(int argc, char **argv, struct command *command, struct plugin *plugin)
{
	const char *desc = "Disconnect from NVMeoF subsystem";
	return disconnect(desc, argc, argv);
}

static int disconnect_all_cmd(int argc, char **argv, struct command *command, struct plugin *plugin)
{
	const char *desc = "Disconnect from all connected NVMeoF subsystems";
	return disconnect_all(desc, argc, argv);
}

void register_extension(struct plugin *plugin)
{
	plugin->parent = &nvme;

	nvme.extensions->tail->next = plugin;
	nvme.extensions->tail = plugin;
}

int main(int argc, char **argv)
{
	int ret;

	nvme.extensions->parent = &nvme;
	if (argc < 2) {
		general_help(&builtin);
		return 0;
	}
	setlocale(LC_ALL, "");

	ret = handle_plugin(argc - 1, &argv[1], nvme.extensions);
	if (ret == -ENOTTY)
		general_help(&builtin);

	return ret;
}
