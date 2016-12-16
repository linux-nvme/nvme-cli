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

#include <endian.h>
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

#include <linux/fs.h>

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>

#include "nvme-print.h"
#include "nvme-ioctl.h"
#include "nvme-lightnvm.h"
#include "plugin.h"

#include "argconfig.h"
#include "suffix.h"

#include "fabrics.h"

#define array_len(x) ((size_t)(sizeof(x) / sizeof(x[0])))
#define min(x, y) (x) > (y) ? (y) : (x)
#define max(x, y) (x) > (y) ? (x) : (y)

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

static int open_dev(const char *dev)
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
	if (ret) {
		fprintf(stderr, "expected nvme device (ex: /dev/nvme0), none provided\n");
		return ret;
	}

	return open_dev((const char *)argv[optind]);
}

int parse_and_open(int argc, char **argv, const char *desc,
	const struct argconfig_commandline_options *clo, void *cfg, size_t size)
{
	int ret;

	ret = argconfig_parse(argc, argv, desc, clo, cfg, size);
	if (ret)
		return ret;

	return get_dev(argc, argv);
}

static const char *output_format = "Output format: normal|json|binary";

enum {
	NORMAL,
	JSON,
	BINARY,
};

static int validate_output_format(char *format)
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
		.namespace_id = 0xffffffff,
		.output_format = "normal",
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id",  'n', "NUM", CFG_POSITIVE, &cfg.namespace_id,  required_argument, namespace},
		{"output-format", 'o', "FMT", CFG_STRING,   &cfg.output_format, required_argument, output_format },
		{"raw-binary",    'b', "",    CFG_NONE,     &cfg.raw_binary,    no_argument,       raw},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0)
		return fd;

	fmt = validate_output_format(cfg.output_format);
	if (fmt < 0)
		return fmt;
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
	}
	else if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x)\n",
					nvme_status_to_string(err), err);
	else
		perror("smart log");
	return err;
}

static int get_error_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Retrieve specified number of "\
		"error log entries from a given device (or "\
		"namespace) in either decoded format (default) or binary.";
	const char *namespace_id = "desired namespace";
	const char *log_entries = "number of entries to retrieve";
	const char *raw_binary = "dump in binary format";
	struct nvme_id_ctrl ctrl;
	int err, fmt, fd;

	struct config {
		__u32 namespace_id;
		__u32 log_entries;
		int   raw_binary;
		char *output_format;
	};

	struct config cfg = {
		.namespace_id = 0xffffffff,
		.log_entries  = 64,
		.output_format = "normal",
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id",  'n', "NUM", CFG_POSITIVE, &cfg.namespace_id,  required_argument, namespace_id},
		{"log-entries",   'e', "NUM", CFG_POSITIVE, &cfg.log_entries,   required_argument, log_entries},
		{"raw-binary",    'b', "",    CFG_NONE,     &cfg.raw_binary,    no_argument,       raw_binary},
		{"output-format", 'o', "FMT", CFG_STRING,   &cfg.output_format, required_argument, output_format },
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0)
		return fd;

	fmt = validate_output_format(cfg.output_format);
	if (fmt < 0)
		return fmt;
	if (cfg.raw_binary)
		fmt = BINARY;

	if (!cfg.log_entries) {
		fprintf(stderr, "non-zero log-entries is required param\n");
		return EINVAL;
	}

	err = nvme_identify_ctrl(fd, &ctrl);
	if (err < 0)
		perror("identify controller");
	else if (err) {
		fprintf(stderr, "could not identify controller\n");
		err = ENODEV;
	} else {
		struct nvme_error_log_page *err_log;

		cfg.log_entries = min(cfg.log_entries, ctrl.elpe + 1);
		err_log = calloc(cfg.log_entries, sizeof(struct nvme_error_log_page));
		if (!err_log) {
			fprintf(stderr, "could not alloc buffer for error log\n");
			return ENOMEM;
		}

		err = nvme_error_log(fd, cfg.namespace_id, cfg.log_entries, err_log);
		if (!err) {
			if (fmt == BINARY)
				d_raw((unsigned char *)err_log, sizeof(err_log));
			else if (fmt == JSON)
				json_error_log(err_log, cfg.log_entries, devicename);
			else
				show_error_log(err_log, cfg.log_entries, devicename);
		}
		else if (err > 0)
			fprintf(stderr, "NVMe Status:%s(%x)\n",
						nvme_status_to_string(err), err);
		else
			perror("error log");
		free(err_log);
	}
	return err;
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
	if (fd < 0)
		return fd;

	fmt = validate_output_format(cfg.output_format);
	if (fmt < 0)
		return fmt;
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
		fprintf(stderr, "NVMe Status:%s(%x)\n",
				nvme_status_to_string(err), err);
	else
		perror("fw log");
	return err;
}

static int get_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Retrieve desired number of bytes "\
		"from a given log on a specified device in either "\
		"hex-dump (default) or binary format";
	const char *namespace_id = "desired namespace";
	const char *log_id = "identifier of log to retrieve";
	const char *log_len = "how many bytes to retrieve";
	const char *raw_binary = "output in raw format";
	int err, fd;

	struct config {
		__u32 namespace_id;
		__u32 log_id;
		__u32 log_len;
		int   raw_binary;
	};

	struct config cfg = {
		.namespace_id = 0xffffffff,
		.log_id       = 0,
		.log_len      = 0,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id", 'n', "NUM", CFG_POSITIVE, &cfg.namespace_id, required_argument, namespace_id},
		{"log-id",       'i', "NUM", CFG_POSITIVE, &cfg.log_id,       required_argument, log_id},
		{"log-len",      'l', "NUM", CFG_POSITIVE, &cfg.log_len,      required_argument, log_len},
		{"raw-binary",   'b', "",    CFG_NONE,     &cfg.raw_binary,   no_argument,       raw_binary},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0)
		return fd;

	if (!cfg.log_len) {
		fprintf(stderr, "non-zero log-len is required param\n");
		return EINVAL;
	} else {
		unsigned char *log;

		log = malloc(cfg.log_len);
		if (!log) {
			fprintf(stderr, "could not alloc buffer for log\n");
			return EINVAL;
		}

		err = nvme_get_log(fd, cfg.namespace_id, cfg.log_id, cfg.log_len, log);
		if (!err) {
			if (!cfg.raw_binary) {
				printf("Device:%s log-id:%d namespace-id:%#x\n",
				       devicename, cfg.log_id,
				       cfg.namespace_id);
				d(log, cfg.log_len, 16, 1);
			} else
				d_raw((unsigned char *)log, cfg.log_len);
		} else if (err > 0)
			fprintf(stderr, "NVMe Status:%s(%x)\n",
						nvme_status_to_string(err), err);
		else
			perror("log page");
		free(log);
		return err;
	}
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
	if (fd < 0)
		return fd;

	if (posix_memalign((void *)&cntlist, getpagesize(), 0x1000)) {
		fprintf(stderr, "can not allocate controller list payload\n");
		return ENOMEM;
	}

	err = nvme_identify_ctrl_list(fd, cfg.namespace_id, cfg.cntid, cntlist);
	if (!err) {
		__u16 num = le16_to_cpu(cntlist->num);

		for (i = 0; i < (min(num, 2048)); i++)
			printf("[%4u]:%#x\n", i, le16_to_cpu(cntlist->identifier[i]));
	}
	else if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x) cntid:%d\n",
			nvme_status_to_string(err), err, cfg.cntid);
	else
		perror("id controller list");
	return err;
}

static int list_ns(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "For the specified device, show the "\
		"namespace list in a NVMe subsystem, optionally starting with a given namespace";
	const char *namespace_id = "namespace number returned list should to start after";
	const char *all = "show all namespaces in the subsystem, whether attached or inactive";
	int err, i, fd;
	__u32 ns_list[1024];

	struct config {
		__u32 namespace_id;
		int  all;
	};

	struct config cfg = {
		.namespace_id = 0,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id", 'n', "NUM", CFG_POSITIVE, &cfg.namespace_id, required_argument, namespace_id},
		{"all",          'a', "",    CFG_NONE,     &cfg.all,          no_argument,       all},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0)
		return fd;

	err = nvme_identify_ns_list(fd, cfg.namespace_id, !!cfg.all, ns_list);
	if (!err) {
		for (i = 0; i < 1024; i++)
			if (ns_list[i])
				printf("[%4u]:%#x\n", i, ns_list[i]);
	}
	else if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x) NSID:%d\n",
			nvme_status_to_string(err), err, cfg.namespace_id);
	else
		perror("id namespace list");
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
	int err, fd;

	struct config {
		__u32	namespace_id;
	};

	struct config cfg = {
		.namespace_id    = 0,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id", 'n', "NUM",  CFG_POSITIVE, &cfg.namespace_id,    required_argument, namespace_id},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0)
		return fd;

	if (!cfg.namespace_id) {
		fprintf(stderr, "%s: namespace-id parameter required\n",
						cmd->name);
		return EINVAL;
	}

	err = nvme_ns_delete(fd, cfg.namespace_id);
	if (!err)
		printf("%s: Success, deleted nsid:%d\n", cmd->name,
								cfg.namespace_id);
	else if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x)\n",
					nvme_status_to_string(err), err);
	else
		perror("delete namespace");
	return err;
}

static int nvme_attach_ns(int argc, char **argv, int attach, const char *desc, struct command *cmd)
{
	int err, num, i, fd, list[2048];
	__u16 ctrlist[2048];

	const char *namespace_id = "namespace to attach";
	const char *cont = "optional comma-sep controllers list";

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
	if (fd < 0)
		return fd;

	if (!cfg.namespace_id) {
		fprintf(stderr, "%s: namespace-id parameter required\n",
						cmd->name);
		return EINVAL;
	}

	num = argconfig_parse_comma_sep_array(cfg.cntlist,
					list, 2047);
	for (i = 0; i < num; i++)
		ctrlist[i] = (uint16_t)list[i];

	if (attach)	
		err = nvme_ns_attach_ctrls(fd, cfg.namespace_id, num, ctrlist);
	else
		err = nvme_ns_detach_ctrls(fd, cfg.namespace_id, num, ctrlist);

	if (!err)
		printf("%s: Success, nsid:%d\n", cmd->name, cfg.namespace_id);
	else if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x)\n",
					nvme_status_to_string(err), err);
	else
		perror(attach ? "attach namespace" : "detach namespace");
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
	const char *nsze = "size of ns";
	const char *ncap = "capacity of ns";
	const char *flbas = "FLBA size";
	const char *dps = "data protection capabilities";
	const char *nmic = "multipath and sharing capabilities";

	int err = 0, fd;
	__u32 nsid;

	struct config {
		__u64	nsze;
		__u64	ncap;
		__u8	flbas;
		__u8	dps;
		__u8	nmic;
	};

	struct config cfg = {
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"nsze",  's', "NUM", CFG_LONG_SUFFIX, &cfg.nsze,  required_argument, nsze},
		{"ncap",  'c', "NUM", CFG_LONG_SUFFIX, &cfg.ncap,  required_argument, ncap},
		{"flbas", 'f', "NUM", CFG_BYTE,        &cfg.flbas, required_argument, flbas},
		{"dps",   'd', "NUM", CFG_BYTE,        &cfg.dps,   required_argument, dps},
		{"nmic",  'm', "NUM", CFG_BYTE,        &cfg.nmic,  required_argument, nmic},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0)
		return fd;

	err = nvme_ns_create(fd, cfg.nsze, cfg.ncap, cfg.flbas, cfg.dps, cfg.nmic, &nsid);
	if (!err)
		printf("%s: Success, created nsid:%d\n", cmd->name, nsid);
	else if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x)\n",
					nvme_status_to_string(err), err);
	else
		perror("create namespace");
	return err;
}

static char *nvme_char_from_block(char *block)
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
	int pci_fd;
	char *base, path[512];
	void *membase;

	base = nvme_char_from_block((char *)devicename);
	sprintf(path, "/sys/class/nvme/%s/device/resource0", base);
	pci_fd = open(path, O_RDONLY);
	if (pci_fd < 0) {
		sprintf(path, "/sys/class/misc/%s/device/resource0", base);
		pci_fd = open(path, O_RDONLY);
	}
	if (pci_fd < 0) {
		fprintf(stderr, "%s did not find a pci resource\n", base);
		return NULL;
	}

	membase = mmap(NULL, getpagesize(), PROT_READ, MAP_SHARED, pci_fd, 0);
	if (membase == MAP_FAILED) {
		fprintf(stderr, "%s failed to map\n", base);
		return NULL;
	}
	return membase;
}

static void print_list_item(struct list_item list_item)
{
	long long int lba = 1 << list_item.ns.lbaf[(list_item.ns.flbas & 0x0f)].ds;
	double nsze       = le64_to_cpu(list_item.ns.nsze) * lba;
	double nuse       = le64_to_cpu(list_item.ns.nuse) * lba;

	const char *s_suffix = suffix_si_get(&nsze);
	const char *u_suffix = suffix_si_get(&nuse);
	const char *l_suffix = suffix_binary_get(&lba);

	char usage[128];
	char format[128];

	sprintf(usage,"%6.2f %2sB / %6.2f %2sB", nuse, u_suffix,
		nsze, s_suffix);
	sprintf(format,"%3.0f %2sB + %2d B", (double)lba, l_suffix,
		list_item.ns.lbaf[(list_item.ns.flbas & 0x0f)].ms);
	printf("%-16s %-*.*s %-*.*s %-9d %-26s %-16s %-.*s\n", list_item.node,
            (int)sizeof(list_item.ctrl.sn), (int)sizeof(list_item.ctrl.sn), list_item.ctrl.sn,
            (int)sizeof(list_item.ctrl.mn), (int)sizeof(list_item.ctrl.mn), list_item.ctrl.mn,
            list_item.nsid, usage, format, (int)sizeof(list_item.ctrl.fr), list_item.ctrl.fr);
}

static void print_list_items(struct list_item *list_items, unsigned len)
{
	unsigned i;

	printf("%-16s %-20s %-40s %-9s %-26s %-16s %-8s\n",
	    "Node", "SN", "Model", "Namespace", "Usage", "Format", "FW Rev");
	printf("%-16s %-20s %-40s %-9s %-26s %-16s %-8s\n",
            "----------------", "--------------------", "----------------------------------------",
            "---------", "--------------------------", "----------------", "--------");
	for (i = 0 ; i < len ; i++)
		print_list_item(list_items[i]);

}

static int get_nvme_info(int fd, struct list_item *item, const char *node)
{
	int err;

	err = nvme_identify_ctrl(fd, &item->ctrl);
	if (err)
		return err;
	item->nsid = nvme_get_nsid(fd);
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
	char path[256];
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
	char path[256];
	struct dirent **devices;
	struct list_item *list_items;
	unsigned int i, n, fd, ret;
	int fmt;
	const char *desc = "Retrieve basic information for the given device";
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

	argconfig_parse(argc, argv, desc, opts, &cfg, sizeof(cfg));
	fmt = validate_output_format(cfg.output_format);

	if (fmt != JSON && fmt != NORMAL)
		return -EINVAL;

	n = scandir(dev, &devices, scan_dev_filter, alphasort);
	if (n <= 0)
		return n;

	list_items = calloc(n, sizeof(*list_items));
	if (!list_items) {
		fprintf(stderr, "can not allocate controller list payload\n");
		return ENOMEM;
	}

	for (i = 0; i < n; i++) {
		snprintf(path, sizeof(path), "%s%s", dev, devices[i]->d_name);
		fd = open(path, O_RDONLY);
		ret = get_nvme_info(fd, &list_items[i], path);
		if (ret)
			return ret;
	}

	if (fmt == JSON)
		json_print_list_items(list_items, n);
	else
		print_list_items(list_items, n);

	for (i = 0; i < n; i++)
		free(devices[i]);
	free(devices);
	free(list_items);

	return 0;
}

static int get_nsid(int fd)
{
	int nsid = nvme_get_nsid(fd);

	if (nsid <= 0) {
		fprintf(stderr,
			"%s: failed to return namespace id\n",
			devicename);
		return errno;
	}
	return nsid;
}

int __id_ctrl(int argc, char **argv, struct command *cmd, struct plugin *plugin, void (*vs)(__u8 *vs))
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
	if (fd < 0)
		return fd;

	fmt = validate_output_format(cfg.output_format);
	if (fmt < 0)
		return fmt;
	if (cfg.raw_binary)
		fmt = BINARY;

	if (cfg.vendor_specific)
		flags |= VS;
	if (cfg.human_readable)
		flags |= HUMAN;

	err = nvme_identify_ctrl(fd, &ctrl);
	if (!err) {
		if (fmt == BINARY)
			d_raw((unsigned char *)&ctrl, sizeof(ctrl));
		else if (fmt == JSON)
			json_nvme_id_ctrl(&ctrl, flags);
		else {
			printf("NVME Identify Controller:\n");
			__show_nvme_id_ctrl(&ctrl, flags, vs);
		}
	}
	else if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x)\n",
				nvme_status_to_string(err), err);
	else
		perror("identify controller");

	return err;
}

static int id_ctrl(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	return __id_ctrl(argc, argv, cmd, plugin, NULL);
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
	if (fd < 0)
		return fd;

	fmt = validate_output_format(cfg.output_format);
	if (fmt < 0)
		return fmt;
	if (cfg.raw_binary)
		fmt = BINARY;
	if (cfg.vendor_specific)
		flags |= VS;
	if (cfg.human_readable)
		flags |= HUMAN;
	if (!cfg.namespace_id)
		cfg.namespace_id = get_nsid(fd);

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
		fprintf(stderr, "NVMe Status:%s(%x) NSID:%d\n",
			nvme_status_to_string(err), err, cfg.namespace_id);
	else
		perror("identify namespace");
	return err;
}

static int get_ns_id(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	int nsid, fd;

	fd = open_dev(argv[1]);
	nsid = nvme_get_nsid(fd);
	if (nsid <= 0) {
		perror(devicename);
		return errno;
	}
	printf("%s: namespace-id:%d\n", devicename, nsid);
	return 0;
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
		break;
	}
	
	if (cfg.data_len) {
		if (posix_memalign(&buf, getpagesize(), cfg.data_len)) {
			fprintf(stderr, "can not allocate feature payload\n");
			return ENOMEM;
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
			if (cfg.human_readable)
				nvme_feature_show_fields(cfg.feature_id, result, buf);
			else if (buf)
				d(buf, cfg.data_len, 16, 1);
		} else if (buf)
			d_raw(buf, cfg.data_len);
	} else if (err > 0) {
		fprintf(stderr, "NVMe Status:%s(%x)\n",
				nvme_status_to_string(err), err);
	} else
		perror("get-feature");

	if (buf)
		free(buf);
	return err;
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
	void *fw_buf;

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
	if (fd < 0)
		return fd;

	fw_fd = open(cfg.fw, O_RDONLY);
	cfg.offset <<= 2;
	if (fw_fd < 0) {
		fprintf(stderr, "no firmware file provided\n");
		return EINVAL;
	}

	err = fstat(fw_fd, &sb);
	if (err < 0) {
		perror("fstat");
		return errno;
	}

	fw_size = sb.st_size;
	if (fw_size & 0x3) {
		fprintf(stderr, "Invalid size:%d for f/w image\n", fw_size);
		return EINVAL;
	}
	if (posix_memalign(&fw_buf, getpagesize(), fw_size)) {
		fprintf(stderr, "No memory for f/w size:%d\n", fw_size);
		return ENOMEM;
	}
	if (cfg.xfer == 0 || cfg.xfer % 4096)
		cfg.xfer = 4096;
	if (read(fw_fd, fw_buf, fw_size) != ((ssize_t)(fw_size)))
		return EIO;

	while (fw_size > 0) {
		cfg.xfer = min(cfg.xfer, fw_size);

		err = nvme_fw_download(fd, cfg.offset, cfg.xfer, fw_buf);
		if (err < 0) {
			perror("fw-download");
			break;
		} else if (err != 0) {
			fprintf(stderr, "NVME Admin command error:%s(%x)\n",
					nvme_status_to_string(err), err);
			break;
		}
		fw_buf     += cfg.xfer;
		fw_size    -= cfg.xfer;
		cfg.offset += cfg.xfer;
	}
	if (!err)
		printf("Firmware download success\n");
	return err;
}

static char *nvme_fw_status_reset_type(__u32 status)
{
	switch (status) {
	case NVME_SC_FW_NEEDS_CONV_RESET:	return "conventional";
	case NVME_SC_FW_NEEDS_SUBSYS_RESET:	return "subsystem";
	case NVME_SC_FW_NEEDS_RESET:		return "any controller";
	default:				return "unknown";
	}
}

static int fw_activate(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Verify downloaded firmware image and "\
		"commit to specific firmware slot. Device is not automatically "\
		"reset following firmware activation. A reset may be issued "\
		"with an 'echo 1 > /sys/class/nvme/nvmeX/reset_controller'. "\
		"Ensure nvmeX is the device you just activated before reset.";
	const char *slot = "firmware slot to activate";
	const char *action = "[0-2]: replacement action";
	int err, fd;

	struct config {
		__u8 slot;
		__u8 action;
	};

	struct config cfg = {
		.slot   = 0,
		.action = 0,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"slot",   's', "NUM", CFG_BYTE, &cfg.slot,   required_argument, slot},
		{"action", 'a', "NUM", CFG_BYTE, &cfg.action, required_argument, action},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0)
		return fd;

	if (cfg.slot > 7) {
		fprintf(stderr, "invalid slot:%d\n", cfg.slot);
		return EINVAL;
	}
	if (cfg.action > 3) {
		fprintf(stderr, "invalid action:%d\n", cfg.action);
		return EINVAL;
	}

	err = nvme_fw_activate(fd, cfg.slot, cfg.action);
	if (err < 0)
		perror("fw-activate");
	else if (err != 0)
		switch (err) {
		case NVME_SC_FW_NEEDS_CONV_RESET:
		case NVME_SC_FW_NEEDS_SUBSYS_RESET:
		case NVME_SC_FW_NEEDS_RESET:
			printf("Success activating firmware action:%d slot:%d, but firmware requires %s reset\n",
			       cfg.action, cfg.slot, nvme_fw_status_reset_type(err));
			break;
		default:
			fprintf(stderr, "NVME Admin command error:%s(%x)\n",
						nvme_status_to_string(err), err);
			break;
		}
	else
		printf("Success activating firmware action:%d slot:%d\n",
		       cfg.action, cfg.slot);
	return err;
}

static int clear_args(int argc, char **argv)
{
	int opt, long_index;

	while ((opt = getopt_long(argc, (char **)argv, "", NULL,
					&long_index)) != -1);
	return get_dev(argc, argv);
}

static int subsystem_reset(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	int err, fd;

	fd = clear_args(argc, argv);
	err = nvme_subsystem_reset(fd);
	if (err < 0) {
		perror("Subsystem-reset");
		return errno;
	}
	return err;
}

static int reset(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	int err, fd;

	fd = clear_args(argc, argv);
	err = nvme_reset_controller(fd);
	if (err < 0) {
		perror("Reset");
		return errno;
	}
	return err;
}

static int show_registers(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Reads and shows the defined NVMe controller registers "\
					"in binary or human-readable format";
	const char *human_readable = "show info in readable format";
	void *bar;
	int fd;

	struct config {
		int human_readable;
	};

	struct config cfg = {
		.human_readable = 0,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"human-readable", 'H', "", CFG_NONE, &cfg.human_readable, no_argument, human_readable},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0)
		return fd;

	bar = get_registers();
	if (!bar)
		return ENODEV;

	show_ctrl_registers(bar, cfg.human_readable ? HUMAN : 0);
	return 0;
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
	int err, fd;

	struct config {
		__u32 namespace_id;
		__u32 timeout;
		__u8  lbaf;
		__u8  ses;
		__u8  pi;
		__u8  pil;
		__u8  ms;
		int reset;
	};

	struct config cfg = {
		.namespace_id = 0xffffffff,
		.timeout      = 120000,
		.lbaf         = 0,
		.ses          = 0,
		.pi           = 0,
		.reset        = 0,
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
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0)
		return fd;

	/* ses & pi checks set to 7 for forward-compatibility */
	if (cfg.ses > 7) {
		fprintf(stderr, "invalid secure erase settings:%d\n", cfg.ses);
		return EINVAL;
	}
	if (cfg.lbaf > 15) {
		fprintf(stderr, "invalid lbaf:%d\n", cfg.lbaf);
		return EINVAL;
	}
	if (cfg.pi > 7) {
		fprintf(stderr, "invalid pi:%d\n", cfg.pi);
		return EINVAL;
	}
	if (cfg.pil > 1) {
		fprintf(stderr, "invalid pil:%d\n", cfg.pil);
		return EINVAL;
	}
	if (cfg.ms > 1) {
		fprintf(stderr, "invalid ms:%d\n", cfg.ms);
		return EINVAL;
	}
	if (S_ISBLK(nvme_stat.st_mode))
		cfg.namespace_id = get_nsid(fd);

	err = nvme_format(fd, cfg.namespace_id, cfg.lbaf, cfg.ses, cfg.pi,
				cfg.pil, cfg.ms, cfg.timeout);
	if (err < 0)
		perror("format");
	else if (err != 0)
		fprintf(stderr, "NVME Admin command error:%s(%x)\n",
					nvme_status_to_string(err), err);
	else {
		printf("Success formatting namespace:%x\n", cfg.namespace_id);
		ioctl(fd, BLKRRPART);
		if (cfg.reset && S_ISCHR(nvme_stat.st_mode))
			nvme_reset_controller(fd);
	}
	return err;
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
	const char *feature_id = "hex feature name (required)";
	const char *data_len = "buffer length if data required";
	const char *data = "optional file for feature data (default stdin)";
	const char *value = "new value of feature (required)";
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
		{"data-len",     'l', "NUM",  CFG_POSITIVE, &cfg.data_len,     required_argument, data_len},
		{"data",         'd', "FILE", CFG_STRING,   &cfg.file,         required_argument, data},
		{"save",         's', "",     CFG_NONE,     &cfg.save,         no_argument, save},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0)
		return fd;

	if (!cfg.feature_id) {
		fprintf(stderr, "feature-id required param\n");
		return EINVAL;
	}
	if (cfg.feature_id == NVME_FEAT_LBA_RANGE)
		cfg.data_len = 4096;
	if (cfg.data_len) {
		if (posix_memalign(&buf, getpagesize(), cfg.data_len)) {
			fprintf(stderr, "can not allocate feature payload\n");
			return ENOMEM;
		}
		memset(buf, 0, cfg.data_len);
	}

	if (buf) {
		if (strlen(cfg.file)) {
			ffd = open(cfg.file, O_RDONLY);
			if (ffd <= 0) {
				fprintf(stderr, "no firmware file provided\n");
				return -EINVAL;
			}
		}
		if (read(ffd, (void *)buf, cfg.data_len) < 0) {
			fprintf(stderr, "failed to read data buffer from input file\n");
			return EINVAL;
		}
	}

	err = nvme_set_feature(fd, cfg.namespace_id, cfg.feature_id, cfg.value, cfg.save,
				cfg.data_len, buf, &result);
	if (err < 0) {
		perror("set-feature");
		return errno;
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
		fprintf(stderr, "NVMe Status:%s(%x)\n",
				nvme_status_to_string(err), err);
	if (buf)
		free(buf);
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
	if (fd < 0)
		return fd;

	sec_fd = open(cfg.file, O_RDONLY);
	if (sec_fd < 0) {
		fprintf(stderr, "no firmware file provided\n");
		return EINVAL;
	}

	err = fstat(sec_fd, &sb);
	if (err < 0) {
		perror("fstat");
		return errno;
	}

	sec_size = sb.st_size;
	if (posix_memalign(&sec_buf, getpagesize(), sec_size)) {
		fprintf(stderr, "No memory for security size:%d\n", sec_size);
		return ENOMEM;
	}

	err = nvme_sec_send(fd, cfg.namespace_id, cfg.nssf, cfg.spsp, cfg.secp,
			cfg.tl, sec_size, sec_buf, &result);
	if (err < 0)
		perror("security-send");
	else if (err != 0)
		fprintf(stderr, "NVME Security Send Command Error:%d\n", err);
	else
		printf("NVME Security Send Command Success:%d\n", result);
	return err;
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
	if (fd < 0)
		return fd;

	if (!cfg.namespace_id)
		cfg.namespace_id = get_nsid(fd);

	err = nvme_write_uncorrectable(fd, cfg.namespace_id, cfg.start_block,
					cfg.block_count);
	if (err < 0)
		perror("write uncorrectable");
	else if (err != 0)
		fprintf(stderr, "NVME IO command error:%s(%x)\n",
					nvme_status_to_string(err), err);
	else
		printf("NVME Write Uncorrectable Success\n");
	return err;
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

	struct config {
		__u64 start_block;
		__u32 namespace_id;
		__u32 ref_tag;
		__u32 app_tag;
		__u16 block_count;
		__u8  prinfo;
		__u8  app_tag_mask;
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
		{"limited-retry",     'l', "",    CFG_NONE,        &cfg.limited_retry,     no_argument,       limited_retry},
		{"force-unit-access", 'f', "",    CFG_NONE,        &cfg.force_unit_access, no_argument,       force},
		{"prinfo",            'p', "NUM", CFG_BYTE,        &cfg.prinfo,            required_argument, prinfo},
		{"ref-tag",           'r', "NUM", CFG_POSITIVE,    &cfg.ref_tag,           required_argument, ref_tag},
		{"app-tag-mask",      'm', "NUM", CFG_BYTE,        &cfg.app_tag_mask,      required_argument, app_tag_mask},
		{"app-tag",           'a', "NUM", CFG_POSITIVE,    &cfg.app_tag,           required_argument, app_tag},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0)
		return fd;

	if (cfg.prinfo > 0xf)
		return EINVAL;

	control |= (cfg.prinfo << 10);
	if (cfg.limited_retry)
		control |= NVME_RW_LR;
	if (cfg.force_unit_access)
		control |= NVME_RW_FUA;
	if (!cfg.namespace_id)
		cfg.namespace_id = get_nsid(fd);

	err = nvme_write_zeros(fd, cfg.namespace_id, cfg.start_block, cfg.block_count,
			control, cfg.ref_tag, cfg.app_tag, cfg.app_tag_mask);
	if (err < 0)
		perror("write-zeroes");
	else if (err != 0)
		fprintf(stderr, "NVME IO command error:%s(%x)\n",
					nvme_status_to_string(err), err);
	else
		printf("NVME Write Zeroes Success\n");
	return err;
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
	if (fd < 0)
		return fd;

	nc = argconfig_parse_comma_sep_array(cfg.ctx_attrs, ctx_attrs, array_len(ctx_attrs));
	nb = argconfig_parse_comma_sep_array(cfg.blocks, nlbs, array_len(nlbs));
	ns = argconfig_parse_comma_sep_array_long(cfg.slbas, slbas, array_len(slbas));
	nr = max(nc, max(nb, ns));
	if (!nr || nr > 256) {
		fprintf(stderr, "No range definition provided\n");
		return EINVAL;
	}

	if (!cfg.namespace_id)
		cfg.namespace_id = get_nsid(fd);
	if (!cfg.cdw11)
		cfg.cdw11 = (cfg.ad << 2) | (cfg.idw << 1) | (cfg.idr << 0);

	dsm = nvme_setup_dsm_range((__u32 *)ctx_attrs, (__u32 *)nlbs, (__u64 *)slbas, nr);
	if (!dsm) {
		fprintf(stderr, "failed to allocate data set payload\n");
		return ENOMEM;
	}

	err = nvme_dsm(fd, cfg.namespace_id, cfg.cdw11, dsm, nr);
	if (err < 0)
		perror("data-set management");
	else if (err != 0)
		fprintf(stderr, "NVME IO command error:%s(%x)\n",
				nvme_status_to_string(err), err);
	else
		printf("NVMe DSM: success\n");
	return err;
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
		.namespace_id = 0xffffffff,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id", 'n', "NUM",  CFG_POSITIVE,    &cfg.namespace_id, required_argument, namespace_id},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0)
		return fd;

	err = nvme_flush(fd, cfg.namespace_id);
	if (err < 0)
		perror("flush");
	else if (err != 0)
		fprintf(stderr, "NVME IO command error:%s(%x)\n",
				nvme_status_to_string(err), err);
	else
		printf("NVMe Flush: success\n");
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
	const char *namespace_id = "identifier of desired namespace";
	const char *crkey = "current reservation key";
	const char *prkey = "pre-empt reservation key";
	const char *rtype = "hex reservation type";
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
	if (fd < 0)
		return fd;

	if (!cfg.namespace_id)
		cfg.namespace_id = get_nsid(fd);
	if (cfg.racqa > 7) {
		fprintf(stderr, "invalid racqa:%d\n", cfg.racqa);
		return EINVAL;
	}

	err = nvme_resv_acquire(fd, cfg.namespace_id, cfg.rtype, cfg.racqa,
				!!cfg.iekey, cfg.crkey, cfg.prkey);
	if (err < 0)
		perror("reservation acquire");
	else if (err != 0)
		fprintf(stderr, "NVME IO command error:%s(%x)\n", nvme_status_to_string(err), err);
	else
		printf("NVME Reservation Acquire success\n");
	return err;
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
	if (fd < 0)
		return fd;

	if (!cfg.namespace_id)
		cfg.namespace_id = get_nsid(fd);
	if (cfg.cptpl > 3) {
		fprintf(stderr, "invalid cptpl:%d\n", cfg.cptpl);
		return EINVAL;
	}

	err = nvme_resv_register(fd, cfg.namespace_id, cfg.rrega, cfg.cptpl,
				!!cfg.iekey, cfg.crkey, cfg.nrkey);
	if (err < 0)
		perror("reservation register");
	else if (err != 0)
		fprintf(stderr, "NVME IO command error:%s(%x)\n", nvme_status_to_string(err), err);
	else
		printf("NVME Reservation  success\n");
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
	const char *namespace_id = "desired namespace";
	const char *crkey = "current reservation key";
	const char *iekey = "ignore existing res. key";
	const char *rtype = "hex reservation type";
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
		{"iekey",        'i', "NUM",  CFG_BYTE,        &cfg.iekey,        required_argument, iekey},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0)
		return fd;

	if (!cfg.namespace_id)
		cfg.namespace_id = get_nsid(fd);
	if (cfg.iekey > 1) {
		fprintf(stderr, "invalid iekey:%d\n", cfg.iekey);
		return EINVAL;
	}
	if (cfg.rrela > 7) {
		fprintf(stderr, "invalid rrela:%d\n", cfg.rrela);
		return EINVAL;
	}

	err = nvme_resv_release(fd, cfg.namespace_id, cfg.rtype, cfg.rrela,
				!!cfg.iekey, cfg.crkey);
	if (err < 0)
		perror("reservation release");
	else if (err != 0)
		fprintf(stderr, "NVME IO command error:%s(%x)\n", nvme_status_to_string(err), err);
	else
		printf("NVME Reservation Release success\n");
	return err;
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
	const char *raw_binary = "dump output in binary format";

	int err, fmt, fd;
	struct nvme_reservation_status *status;

	struct config {
		__u32 namespace_id;
		__u32 numd;
		int   raw_binary;
		char *output_format;
	};

	struct config cfg = {
		.namespace_id = 0,
		.numd         = 0,
		.output_format = "normal",
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id",  'n', "NUM", CFG_POSITIVE, &cfg.namespace_id,  required_argument, namespace_id},
		{"numd",          'd', "NUM", CFG_POSITIVE, &cfg.numd,          required_argument, numd},
		{"raw-binary",    'b', "",    CFG_NONE,     &cfg.raw_binary,    no_argument,       raw_binary},
		{"output-format", 'o', "FMT", CFG_STRING,   &cfg.output_format, required_argument, output_format },
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0)
		return fd;

	fmt = validate_output_format(cfg.output_format);
	if (fmt < 0)
		return fmt;
	if (cfg.raw_binary)
		fmt = BINARY;

	if (!cfg.namespace_id)
		cfg.namespace_id = get_nsid(fd);
	if (!cfg.numd || cfg.numd > (0x1000 >> 2))
		cfg.numd = 0x1000 >> 2;

	if (posix_memalign((void **)&status, getpagesize(), cfg.numd << 2)) {
		fprintf(stderr, "No memory for resv report:%d\n", cfg.numd << 2);
		return ENOMEM;
	}

	err = nvme_resv_report(fd, cfg.namespace_id, cfg.numd, status);
	if (err < 0)
		perror("reservation report");
	else if (err != 0)
		fprintf(stderr, "NVME IO command error:%04x\n", err);
	else {
		if (fmt == BINARY)
			d_raw((unsigned char *)status, cfg.numd << 2);
		else if (fmt == JSON)
			json_nvme_resv_report(status);
		else {
			printf("NVME Reservation Report success\n");
			show_nvme_resv_report(status);
		}
	}
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

	struct config {
		__u64 start_block;
		__u16 block_count;
		__u64 data_size;
		__u64 metadata_size;
		__u32 ref_tag;
		char  *data;
		char  *metadata;
		__u8  prinfo;
		__u8  app_tag_mask;
		__u32 app_tag;
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
		{"app-tag-mask",      'm', "NUM",  CFG_BYTE,        &cfg.app_tag_mask,      required_argument, app_tag_mask},
		{"app-tag",           'a', "NUM",  CFG_POSITIVE,    &cfg.app_tag,           required_argument, app_tag},
		{"limited-retry",     'l', "",     CFG_NONE,        &cfg.limited_retry,     no_argument,       limited_retry},
		{"force-unit-access", 'f', "",     CFG_NONE,        &cfg.force_unit_access, no_argument,       force},
		{"show-command",      'v', "",     CFG_NONE,        &cfg.show,              no_argument,       show},
		{"dry-run",           'w', "",     CFG_NONE,        &cfg.dry_run,           no_argument,       dry},
		{"latency",           't', "",     CFG_NONE,        &cfg.latency,           no_argument,       latency},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0)
		return fd;

	dfd = mfd = opcode & 1 ? STDIN_FILENO : STDOUT_FILENO;
	if (cfg.prinfo > 0xf)
		return EINVAL;
	control |= (cfg.prinfo << 10);
	if (cfg.limited_retry)
		control |= NVME_RW_LR;
	if (cfg.force_unit_access)
		control |= NVME_RW_FUA;
	if (strlen(cfg.data)){
		dfd = open(cfg.data, flags, mode);
		if (dfd < 0) {
			perror(cfg.data);
			return EINVAL;
		}
		mfd = dfd;
	}
	if (strlen(cfg.metadata)){
		mfd = open(cfg.metadata, flags, mode);
		if (mfd < 0) {
			perror(cfg.data);
			return EINVAL;
		}
	}

	if (!cfg.data_size)	{
		fprintf(stderr, "data size not provided\n");
		return EINVAL;
	}

	if (ioctl(fd, BLKPBSZGET, &phys_sector_size) < 0)
		return errno;

	buffer_size = (cfg.block_count + 1) * phys_sector_size;
	if (cfg.data_size < buffer_size) {
		fprintf(stderr, "Rounding data size to fit block count (%lld bytes)\n",
				buffer_size);
	} else {
		buffer_size = cfg.data_size;
	}

	if (posix_memalign(&buffer, getpagesize(), buffer_size)) {
		fprintf(stderr, "can not allocate io payload\n");
		return ENOMEM;
	}
	memset(buffer, 0, cfg.data_size);

	if (cfg.metadata_size) {
		mbuffer = malloc(cfg.metadata_size);
		if (!mbuffer) {
 			free(buffer);
			fprintf(stderr, "can not allocate io metadata payload\n");
			return ENOMEM;
		}
	}

	if ((opcode & 1) && read(dfd, (void *)buffer, cfg.data_size) < 0) {
		fprintf(stderr, "failed to read data buffer from input file\n");
		err = EINVAL;
		goto free_and_return;
	}

	if ((opcode & 1) && cfg.metadata_size &&
				read(mfd, (void *)mbuffer, cfg.metadata_size) < 0) {
		fprintf(stderr, "failed to read meta-data buffer from input file\n");
		err = EINVAL;
		goto free_and_return;
	}

	if (cfg.show) {
		printf("opcode       : %02x\n", opcode);
		printf("flags        : %02x\n", 0);
		printf("control      : %04x\n", control);
		printf("nblocks      : %04x\n", cfg.block_count);
		printf("rsvd         : %04x\n", 0);
		printf("metadata     : %"PRIx64"\n", (uint64_t)(uintptr_t)mbuffer);
		printf("addr         : %"PRIx64"\n", (uint64_t)(uintptr_t)buffer);
		printf("sbla         : %"PRIx64"\n", (uint64_t)cfg.start_block);
		printf("dsmgmt       : %08x\n", 0);
		printf("reftag       : %08x\n", cfg.ref_tag);
		printf("apptag       : %04x\n", cfg.app_tag);
		printf("appmask      : %04x\n", cfg.app_tag_mask);
		if (cfg.dry_run)
			goto free_and_return;
	}

	gettimeofday(&start_time, NULL);
	err = nvme_io(fd, opcode, cfg.start_block, cfg.block_count, control, 0,
			cfg.ref_tag, cfg.app_tag, cfg.app_tag_mask, buffer, mbuffer);
	gettimeofday(&end_time, NULL);
	if (cfg.latency)
		printf(" latency: %s: %llu us\n",
			command, elapsed_utime(start_time, end_time));
	if (err < 0)
		perror("submit-io");
	else if (err)
		printf("%s:%s(%04x)\n", command, nvme_status_to_string(err), err);
	else {
		if (!(opcode & 1) && write(dfd, (void *)buffer, cfg.data_size) < 0) {
			fprintf(stderr, "failed to write buffer to output file\n");
			err = EINVAL;
			goto free_and_return;
		} else if (!(opcode & 1) && cfg.metadata_size &&
				write(mfd, (void *)mbuffer, cfg.metadata_size) < 0) {
			fprintf(stderr, "failed to write meta-data buffer to output file\n");
			err = EINVAL;
			goto free_and_return;
		} else
			fprintf(stderr, "%s: Success\n", command);
	}
 free_and_return:
	free(buffer);
	if (cfg.metadata_size)
		free(mbuffer);
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
	if (fd < 0)
		return fd;

	if (cfg.size) {
		if (posix_memalign(&sec_buf, getpagesize(), cfg.size)) {
			fprintf(stderr, "No memory for security size:%d\n",
								cfg.size);
			return ENOMEM;
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
			d_raw((unsigned char *)&sec_buf, cfg.size);
	}
	return err;
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

	const char *opcode = "hex opcode (required)";
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
	if (fd < 0)
		return fd;

	if (strlen(cfg.input_file)){
		wfd = open(cfg.input_file, O_RDONLY,
			   S_IRUSR | S_IRGRP | S_IROTH);
		if (wfd < 0) {
			perror(cfg.input_file);
			return EINVAL;
		}
	}

	if (cfg.metadata_len)
		metadata = malloc(cfg.metadata_len);
	if (cfg.data_len) {
		if (posix_memalign(&data, getpagesize(), cfg.data_len)) {
			fprintf(stderr, "can not allocate data payload\n");
			return ENOMEM;
		}

		memset(data, cfg.prefill, cfg.data_len);
		if (!cfg.read && !cfg.write) {
			fprintf(stderr, "data direction not given\n");
			err = EINVAL;
			goto free_and_return;
		} else if (cfg.write) {
			if (read(wfd, data, cfg.data_len) < 0) {
				fprintf(stderr, "failed to read write buffer\n");
				err = EINVAL;
				goto free_and_return;
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
		if (cfg.dry_run)
			goto free_and_return;
	}

	err = nvme_passthru(fd, ioctl_cmd, cfg.opcode, cfg.flags, cfg.rsvd,
				cfg.namespace_id, cfg.cdw2, cfg.cdw3, cfg.cdw10,
				cfg.cdw11, cfg.cdw12, cfg.cdw13, cfg.cdw14, cfg.cdw15,
				cfg.data_len, data, cfg.metadata_len, metadata,
				cfg.timeout, &result);
	if (err < 0)
		perror("passthru");
	else if (err)
		fprintf(stderr, "NVMe Status:%s(%x) Command Result:%08x\n",
				nvme_status_to_string(err), err, result);
	else  {
		if (!cfg.raw_binary) {
			fprintf(stderr, "NVMe command result:%08x\n", result);
			if (data && cfg.read && !err)
				d((unsigned char *)data, cfg.data_len, 16, 1);
		} else if (data && cfg.read)
			d_raw((unsigned char *)data, cfg.data_len);
	}
	return err;
free_and_return:
	free(data);
	free(metadata);
	return err;
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
