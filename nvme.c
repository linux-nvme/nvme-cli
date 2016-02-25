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
#ifdef LIBUDEV_EXISTS
#include <libudev.h>
#endif

#include <linux/fs.h>

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>

#include "nvme-print.h"
#include "nvme-ioctl.h"

#include "src/argconfig.h"
#include "src/suffix.h"

#define array_len(x) ((size_t)(sizeof(x) / sizeof(x[0])))
#define min(x, y) (x) > (y) ? (y) : (x)
#define max(x, y) (x) > (y) ? (x) : (y)

static int fd;
static struct stat nvme_stat;
static const char *devicename;

static const char nvme_version_string[] = NVME_VERSION;

#define COMMAND_LIST \
	ENTRY(LIST, "list", "List all NVMe devices and namespaces on machine", list) \
	ENTRY(ID_CTRL, "id-ctrl", "Send NVMe Identify Controller", id_ctrl) \
	ENTRY(ID_NS, "id-ns", "Send NVMe Identify Namespace, display structure", id_ns) \
	ENTRY(LIST_NS, "list-ns", "Send NVMe Identify List, display structure", list_ns) \
	ENTRY(CREATE_NS, "create-ns", "Creates a namespace with the provided parameters", create_ns) \
	ENTRY(DELETE_NS, "delete-ns", "Deletes a namespace from the controller", delete_ns) \
	ENTRY(ATTACH_NS, "attach-ns", "Attaches a namespace to requested controller(s)", attach_ns) \
	ENTRY(DETACH_NS, "detach-ns", "Detaches a namespace from requested controller(s)", detach_ns) \
	ENTRY(LIST_CTRL, "list-ctrl", "Send NVMe Identify Controller List, display structure", list_ctrl) \
	ENTRY(GET_NS_ID, "get-ns-id", "Retrieve the namespace ID of opened block device", get_ns_id) \
	ENTRY(GET_LOG, "get-log", "Generic NVMe get log, returns log in raw format", get_log) \
	ENTRY(GET_FW_LOG, "fw-log", "Retrieve FW Log, show it", get_fw_log) \
	ENTRY(GET_SMART_LOG, "smart-log", "Retrieve SMART Log, show it", get_smart_log) \
	ENTRY(GET_ADDITIONAL_SMART_LOG, "smart-log-add", "Retrieve additional SMART Log, show it", get_additional_smart_log) \
	ENTRY(GET_ERR_LOG, "error-log", "Retrieve Error Log, show it", get_error_log) \
	ENTRY(GET_FEATURE, "get-feature", "Get feature and show the resulting value", get_feature) \
	ENTRY(SET_FEATURE, "set-feature", "Set a feature and show the resulting value", set_feature) \
	ENTRY(FORMAT, "format", "Format namespace with new block format", format) \
	ENTRY(FW_ACTIVATE, "fw-activate", "Activate new firmware slot", fw_activate) \
	ENTRY(FW_DOWNLOAD, "fw-download", "Download new firmware", fw_download) \
	ENTRY(ADMIN_PASSTHRU, "admin-passthru", "Submit arbitrary admin command, return results", admin_passthru) \
	ENTRY(IO_PASSTHRU, "io-passthru", "Submit an arbitrary IO command, return results", io_passthru) \
	ENTRY(SECURITY_SEND, "security-send", "Submit a Security Send command, return results", sec_send) \
	ENTRY(SECURITY_RECV, "security-recv", "Submit a Security Receive command, return results", sec_recv) \
	ENTRY(RESV_ACQUIRE, "resv-acquire", "Submit a Reservation Acquire, return results", resv_acquire) \
	ENTRY(RESV_REGISTER, "resv-register", "Submit a Reservation Register, return results", resv_register) \
	ENTRY(RESV_RELEASE, "resv-release", "Submit a Reservation Release, return results", resv_release) \
	ENTRY(RESV_REPORT, "resv-report", "Submit a Reservation Report, return results", resv_report) \
	ENTRY(DSM, "dsm", "Submit a Data Set Management command, return results", dsm) \
	ENTRY(FLUSH, "flush", "Submit a Flush command, return results", flush) \
	ENTRY(COMPARE, "compare", "Submit a Compare command, return results", compare) \
	ENTRY(READ_CMD, "read", "Submit a read command, return results", read_cmd) \
	ENTRY(WRITE_CMD, "write", "Submit a write command, return results", write_cmd) \
	ENTRY(REGISTERS, "show-regs", "Shows the controller registers. Requires admin character device", show_registers) \
	ENTRY(VERSION, "version", "Shows the program version", version) \
	ENTRY(HELP, "help", "Display this help", help)

#define ENTRY(i, n, h, f) \
static int f(int argc, char **argv);
COMMAND_LIST
#undef ENTRY

enum {
	#define ENTRY(i, n, h, f) i,
	COMMAND_LIST
	#undef ENTRY
	NUM_COMMANDS
};

struct command {
	char *name;
	char *help;
	char *path;
	char *man;
	int (*fn)(int argc, char **argv);
};

struct command commands[] = {
	#define ENTRY(i, n, h, f)\
	{ \
		.name = n, \
		.help = h, \
		.fn = f, \
		.path = "Documentation/nvme-"n".1", \
		.man = "nvme-"n, \
	},
	COMMAND_LIST
	#undef ENTRY
};

static unsigned long long elapsed_utime(struct timeval start_time,
					struct timeval end_time)
{
	unsigned long long ret = (end_time.tv_sec - start_time.tv_sec)*1000000 +
		(end_time.tv_usec - start_time.tv_usec);
	return ret;
}

static void open_dev(const char *dev)
{
	int err;
	devicename = basename(dev);
	fd = open(dev, O_RDONLY);
	if (fd < 0)
		goto perror;

	err = fstat(fd, &nvme_stat);
	if (err < 0)
		goto perror;
	if (!S_ISCHR(nvme_stat.st_mode) && !S_ISBLK(nvme_stat.st_mode)) {
		fprintf(stderr, "%s is not a block or character device\n", dev);
		exit(ENODEV);
	}
	return;
 perror:
	perror(dev);
	exit(errno);
}

static void get_dev(int optind, int argc, char **argv)
{
	if (optind >= argc) {
		errno = EINVAL;
		perror(argv[0]);
		exit(errno);
	}
	open_dev((const char *)argv[optind]);
}
static int get_smart_log(int argc, char **argv)
{
	struct nvme_smart_log smart_log;
	const char *desc = "smart-log: retrieve SMART log for the given "\
		"device (or optionally, namespace) in either hex-dump "\
		"(default) or binary format.";
	const char *namespace = "(optional) desired namespace";
	const char *raw = "output in binary format";
	int err;

	struct config {
		__u32 namespace_id;
		__u8  raw_binary;
	};
	struct config cfg;

	const struct config defaults = {
		.namespace_id = 0xffffffff,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id", "NUM", CFG_POSITIVE, &defaults.namespace_id, required_argument, namespace},
		{"n",            "NUM", CFG_POSITIVE, &defaults.namespace_id, required_argument, namespace},
		{"raw-binary",   "",    CFG_NONE,     &defaults.raw_binary,   no_argument,       raw},
		{"b",            "",    CFG_NONE,     &defaults.raw_binary,   no_argument,       raw},
		{0}
	};

	argconfig_parse(argc, argv, desc, command_line_options,
			&defaults, &cfg, sizeof(cfg));

	get_dev(1, argc, argv);

	err = nvme_smart_log(fd, cfg.namespace_id, &smart_log);
	if (!err) {
		if (!cfg.raw_binary)
			show_smart_log(&smart_log, cfg.namespace_id, devicename);
		else
			d_raw((unsigned char *)&smart_log, sizeof(smart_log));
	}
	else if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x)\n",
					nvme_status_to_string(err), err);
	return err;
}

static int get_additional_smart_log(int argc, char **argv)
{
	struct nvme_additional_smart_log smart_log;
	int err;
	char *desc = "Get additional smart log (optionally, "\
		      "for the specified namspace), and show it.";
	const char *namespace = "(optional) desired namespace";
	const char *raw = "dump output in binary format";
	struct config {
		__u32 namespace_id;
		__u8  raw_binary;
	};
	struct config cfg;

	const struct config defaults = {
		.namespace_id = 0xffffffff,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id", "NUM", CFG_POSITIVE, &defaults.namespace_id, required_argument, namespace},
		{"n",            "NUM", CFG_POSITIVE, &defaults.namespace_id, required_argument, namespace},
		{"raw-binary",   "",    CFG_NONE,     &defaults.raw_binary,   no_argument,       raw},
		{"b",            "",    CFG_NONE,     &defaults.raw_binary,   no_argument,       raw},
		{0}
	};
	argconfig_parse(argc, argv, desc, command_line_options,
			&defaults, &cfg, sizeof(cfg));
	get_dev(1, argc, argv);

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

static int get_error_log(int argc, char **argv)
{
	const char *desc = "error-log: retrieve specified number of "\
		"error log entries from a given device (or "\
		"namespace) in either hex-dump (default) or binary format.";
	const char *namespace_id = "desired namespace";
	const char *log_entries = "number of entries to retrieve";
	const char *raw_binary = "dump in binary format";
	struct nvme_id_ctrl ctrl;
	int err;

	struct config {
		__u32 namespace_id;
		__u32 log_entries;
		__u8  raw_binary;
	};
	struct config cfg;

	const struct config defaults = {
		.namespace_id = 0xffffffff,
		.log_entries  = 64,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id", "NUM",  CFG_POSITIVE, &defaults.namespace_id, required_argument, namespace_id},
		{"n",            "NUM",  CFG_POSITIVE, &defaults.namespace_id, required_argument, namespace_id},
		{"log-entries",  "NUM",  CFG_POSITIVE, &defaults.log_entries,  required_argument, log_entries},
		{"e",            "NUM",  CFG_POSITIVE, &defaults.log_entries,  required_argument, log_entries},
		{"raw-binary",   "",     CFG_NONE,     &defaults.raw_binary,   no_argument,       raw_binary},
		{"b",            "",     CFG_NONE,     &defaults.raw_binary,   no_argument,       raw_binary},
		{0}
	};

	argconfig_parse(argc, argv, desc, command_line_options,
			&defaults, &cfg, sizeof(cfg));

	get_dev(1, argc, argv);
	if (!cfg.log_entries) {
		fprintf(stderr, "non-zero log-entries is required param\n");
		return EINVAL;
	}

	err = nvme_identify_ctrl(fd, &ctrl);
	cfg.log_entries = min(cfg.log_entries, ctrl.elpe + 1);
	if (err) {
		fprintf(stderr, "could not identify controller\n");
		return ENODEV;
	} else {
		struct nvme_error_log_page err_log[cfg.log_entries];

		err = nvme_error_log(fd, cfg.namespace_id, cfg.log_entries, err_log);
		if (!err) {
			if (!cfg.raw_binary)
				show_error_log(err_log, cfg.log_entries, devicename);
			else
				d_raw((unsigned char *)err_log, sizeof(err_log));
		}
		else if (err > 0)
			fprintf(stderr, "NVMe Status:%s(%x)\n",
						nvme_status_to_string(err), err);
	}
	return err;
}

static int get_fw_log(int argc, char **argv)
{
	const char *desc = "fw-log: retrieve the firmware log for the "\
		"specified device in either hex-dump (default) or binary "\
		"format.";
	const char *raw_binary = "use binary output";
	int err;
	struct nvme_firmware_log_page fw_log;

	struct config {
		__u8  raw_binary;
	};
	struct config cfg;

	const struct config defaults = {
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"raw-binary", "",   CFG_NONE, &defaults.raw_binary,   no_argument,       raw_binary},
		{"b",          "",   CFG_NONE, &defaults.raw_binary,   no_argument,       raw_binary},
		{0}
	};

	argconfig_parse(argc, argv, desc, command_line_options,
			&defaults, &cfg, sizeof(cfg));

	get_dev(1, argc, argv);

	err = nvme_fw_log(fd, &fw_log);
	if (!err) {
		if (!cfg.raw_binary)
			show_fw_log(&fw_log, devicename);
		else
			d_raw((unsigned char *)&fw_log, sizeof(fw_log));
	}
	else if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x)\n",
				nvme_status_to_string(err), err);
	else
		perror("fw log");
	return err;
}

static int get_log(int argc, char **argv)
{
	const char *desc = "get-log: retrieve desired number of bytes "\
		"from a given log on a specified device in either "\
		"hex-dump (default) or binary format";
	const char *namespace_id = "desired namespace";
	const char *log_id = "name of log to retrieve";
	const char *log_len = "how many bytes to retrieve";
	const char *raw_binary = "output in raw format";
	int err;

	struct config {
		__u32 namespace_id;
		__u32 log_id;
		__u32 log_len;
		__u8  raw_binary;
	};
	struct config cfg;

	const struct config defaults = {
		.namespace_id = 0xffffffff,
		.log_id       = 0,
		.log_len      = 0,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id", "NUM",  CFG_POSITIVE, &defaults.namespace_id, required_argument, namespace_id},
		{"n",            "NUM",  CFG_POSITIVE, &defaults.namespace_id, required_argument, namespace_id},
		{"log-id",       "NUM",  CFG_POSITIVE, &defaults.log_id,       required_argument, log_id},
		{"i",            "NUM",  CFG_POSITIVE, &defaults.log_id,       required_argument, log_id},
		{"log-len",      "NUM",  CFG_POSITIVE, &defaults.log_len,      required_argument, log_len},
		{"l",            "NUM",  CFG_POSITIVE, &defaults.log_len,      required_argument, log_len},
		{"raw-binary",   "",     CFG_NONE,     &defaults.raw_binary,   no_argument,       raw_binary},
		{"b",            "",     CFG_NONE,     &defaults.raw_binary,   no_argument,       raw_binary},
		{0}
	};

	argconfig_parse(argc, argv, desc, command_line_options,
			&defaults, &cfg, sizeof(cfg));

	get_dev(1, argc, argv);

	if (!cfg.log_len) {
		fprintf(stderr, "non-zero log-len is required param\n");
		return EINVAL;
	} else {
		unsigned char log[cfg.log_len];

		err = nvme_log(fd, cfg.namespace_id, cfg.log_id, cfg.log_len, log);
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
		return err;
	}
}

static int list_ctrl(int argc, char **argv)
{
	const char *desc = "list-ctrl: show controller information for the "\
		"given device (and optionally, namespace)";
	const char *controller = "controller to display";
	const char *namespace_id = "optional namespace attached to controller";
	int err, i;
	struct nvme_controller_list *cntlist;

	struct config {
		__u16 cntid;
		__u32 namespace_id;
	};
	struct config cfg;

	const struct config defaults = {
		.cntid = 0,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"cntid",        "NUM", CFG_SHORT,    &defaults.cntid,        required_argument, controller},
		{"c",            "NUM", CFG_SHORT,    &defaults.cntid,        required_argument, controller},
		{"namespace-id", "NUM", CFG_POSITIVE, &defaults.namespace_id, required_argument, namespace_id},
		{"n",            "NUM", CFG_POSITIVE, &defaults.namespace_id, required_argument, namespace_id},
		{0}
	};

	argconfig_parse(argc, argv, desc, command_line_options,
			&defaults, &cfg, sizeof(cfg));

	get_dev(1, argc, argv);

	if (posix_memalign((void *)&cntlist, getpagesize(), 0x1000))
		return ENOMEM;

	err = nvme_identify_ctrl_list(fd, cfg.namespace_id, cfg.cntid, cntlist);
	if (!err) {
		for (i = 0; i < (min(cntlist->num, 2048)); i++)
			printf("[%4u]:%#x\n", i, cntlist->identifier[i]);
	}
	else if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x) cntid:%d\n",
			nvme_status_to_string(err), err, cfg.cntid);
	return err;
}

static int list_ns(int argc, char **argv)
{
	const char *desc = "list-ns: for the specified device, show the "\
		"namespace list (optionally starting with a given namespace)";
	const char *namespace_id = "namespace to start after";
	const char *all = "show all namespaces in the subsystem, whether attached or inactive";
	int err, i;
	__u32 ns_list[1024];

	struct config {
		__u32 namespace_id;
		__u8  all;
	};
	struct config cfg;

	const struct config defaults = {
		.namespace_id = 0,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id", "NUM",  CFG_POSITIVE, &defaults.namespace_id, required_argument, namespace_id},
		{"n",            "NUM",  CFG_POSITIVE, &defaults.namespace_id, required_argument, namespace_id},
		{"all",          "",     CFG_NONE,     &defaults.all,          no_argument,       all},
		{"a",            "",     CFG_NONE,     &defaults.all,          no_argument,       all},
		{0}
	};

	argconfig_parse(argc, argv, desc, command_line_options,
			&defaults, &cfg, sizeof(cfg));

	get_dev(1, argc, argv);

	err = nvme_identify_ns_list(fd, cfg.namespace_id, !!cfg.all, ns_list);
	if (!err) {
		for (i = 0; i < 1024; i++)
			if (ns_list[i])
				printf("[%4u]:%#x\n", i, ns_list[i]);
	}
	else if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x) NSID:%d\n",
			nvme_status_to_string(err), err, cfg.namespace_id);
	return err;
}

static int delete_ns(int argc, char **argv)
{
	const char *desc = "delete-ns: delete the given namespace by "\
		"sending a namespace management command to "\
		"the given device. All controllers should be detached from "\
		"the namespace prior to namespace deletion. A namespace ID "\
		"becomes inactive when that namespace is detached (or, if "\
		"the namespace is not already inactive, once deleted).";
	const char *namespace_id = "namespace to delete";
	int err;

	struct config {
		__u32	namespace_id;
	};
	struct config cfg;

	const struct config defaults = {
		.namespace_id    = 0,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id",    "NUM",  CFG_POSITIVE, &defaults.namespace_id,    required_argument, namespace_id},
		{"n",               "NUM",  CFG_POSITIVE, &defaults.namespace_id,    required_argument, namespace_id},
		{0}
	};

	argconfig_parse(argc, argv, desc, command_line_options,
			&defaults, &cfg, sizeof(cfg));

	if (!cfg.namespace_id) {
		fprintf(stderr, "%s: namespace-id parameter required\n",
						commands[DELETE_NS].name);
		return EINVAL;
	}
	get_dev(1, argc, argv);

	err = nvme_ns_delete(fd, cfg.namespace_id);
	if (!err)
		printf("%s: Success, deleted nsid:%d\n", commands[DELETE_NS].name,
								cfg.namespace_id);
	else if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x)\n",
					nvme_status_to_string(err), err);
	else
		fprintf(stderr, "system error:(%x)\n", err);
	return err;
}

static int nvme_attach_ns(int argc, char **argv, int attach, const char *desc)
{
	char *name = commands[attach ? ATTACH_NS : DETACH_NS].name;
	int err, num, i, list[2048];
	__u16 ctrlist[2048];

	const char *namespace_id = "namespace to attach";
	const char *cont = "optional comma-sep controllers list";

	struct config {
		char  *cntlist;
		__u32 namespace_id;
	};
	struct config cfg;

	const struct config defaults = {
		.cntlist = "",
		.namespace_id = 0,
	};
	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id",    "NUM",  CFG_POSITIVE, &defaults.namespace_id,    required_argument, namespace_id},
		{"n",               "NUM",  CFG_POSITIVE, &defaults.namespace_id,    required_argument, namespace_id},
		{"controllers",     "LIST", CFG_STRING, &defaults.cntlist,    required_argument, cont},
		{"c",               "LIST", CFG_STRING, &defaults.cntlist,    required_argument, cont},
		{0}
	};

	argconfig_parse(argc, argv, desc, command_line_options,
			&defaults, &cfg, sizeof(cfg));
	if (!cfg.namespace_id) {
		fprintf(stderr, "%s: namespace-id parameter required\n",
						name);
		return EINVAL;
	}
	num = argconfig_parse_comma_sep_array(cfg.cntlist,
					list, 2047);
	for (i = 0; i < num; i++)
		ctrlist[i] = ((uint16_t)list[i]);

	get_dev(1, argc, argv);

	if (attach)	
		err = nvme_ns_attach_ctrls(fd, cfg.namespace_id, num, ctrlist);
	else
		err = nvme_ns_detach_ctrls(fd, cfg.namespace_id, num, ctrlist);

	if (!err)
		printf("%s: Success, nsid:%d\n", name, cfg.namespace_id);
	else if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x)\n",
					nvme_status_to_string(err), err);
	else
		fprintf(stderr, "system error:(%x)\n", err);
	return err;
}

static int attach_ns(int argc, char **argv)
{
	const char *desc = "attach-ns: attach the given namespace to the "\
		"given controller or comma-sep list of controllers. ID of the "\
		"given namespace becomes active upon attachment to a "\
		"controller. A namespace must be attached to a controller "\
		"before IO commands may be directed to that namespace.";
	return nvme_attach_ns(argc, argv, 1, desc);
}

static int detach_ns(int argc, char **argv)
{
	const char *desc = "detach-ns: detach the given namespace from the "\
		"given controller; de-activates the given namespace's ID. A "\
		"namespace must be attached to a controller before IO "\
		"commands may be directed to that namespace.";
	return nvme_attach_ns(argc, argv, 0, desc);
}

static int create_ns(int argc, char **argv)
{
	const char *desc = "create-ns: send a namespace management command "\
		"to the specified device to create a namespace with the given "\
		"parameters. The next available namespace ID is used for the "\
		"create operation. Note that create-ns does not attach the "\
		"namespace to a controller, the attach-ns command is needed.";
	int err = 0;
	__u32 nsid;

	struct config {
		__u64	nsze;
		__u64	ncap;
		__u8	flbas;
		__u8	dps;
		__u8	nmic;
	};
	struct config cfg;

	const struct config defaults = {
	};

	const char *nsze = "size of ns";
	const char *ncap = "capacity of ns";
	const char *flbas = "FLBA size";
	const char *dps = "data protection capabilities";
	const char *nmic = "multipath and sharing capabilities";

	const struct argconfig_commandline_options command_line_options[] = {
		{"nsze",            "NUM", CFG_LONG_SUFFIX, &defaults.nsze,  required_argument, nsze},
		{"s",               "NUM", CFG_LONG_SUFFIX, &defaults.nsze,  required_argument, nsze},
		{"ncap",            "NUM", CFG_LONG_SUFFIX, &defaults.ncap,  required_argument, ncap},
		{"c",               "NUM", CFG_LONG_SUFFIX, &defaults.ncap,  required_argument, ncap},
		{"flbas",           "NUM", CFG_BYTE,        &defaults.flbas, required_argument, flbas},
		{"f",               "NUM", CFG_BYTE,        &defaults.flbas, required_argument, flbas},
		{"dps",             "NUM", CFG_BYTE,        &defaults.dps,   required_argument, dps},
		{"d",               "NUM", CFG_BYTE,        &defaults.dps,   required_argument, dps},
		{"nmic",            "NUM", CFG_BYTE,        &defaults.nmic,  required_argument, nmic},
		{"m",               "NUM", CFG_BYTE,        &defaults.nmic,  required_argument, nmic},
		{0}
	};

	argconfig_parse(argc, argv, desc, command_line_options,
			&defaults, &cfg, sizeof(cfg));

	get_dev(1, argc, argv);

	err = nvme_ns_create(fd, cfg.nsze, cfg.ncap, cfg.flbas, cfg.dps, cfg.nmic, &nsid);
	if (!err)
		printf("%s: Success, created nsid:%d\n", commands[CREATE_NS].name,
								nsid);
	else if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x)\n",
					nvme_status_to_string(err), err);
	return err;
}

static char *nvme_char_from_block(char *block)
{
	char slen[16];
	unsigned len;
	if (strncmp("nvme", block, 4)) {
		fprintf(stderr,"Device %s is not a nvme device.", block);
		exit(-1);
	}
	sscanf(block,"nvme%d", &len);
	sprintf(slen,"%d", len);
	block[4+strlen(slen)] = 0;
	return block;
}

static void get_registers(struct nvme_bar **bar, unsigned char_only)
{
	int pci_fd;
	char *base, path[512];
	void *membase;

	if (char_only && !S_ISCHR(nvme_stat.st_mode)) {
		fprintf(stderr, "%s is not a character device\n", devicename);
		exit(ENODEV);
	}

	base = nvme_char_from_block(basename(devicename));

	sprintf(path, "/sys/class/nvme/%s/device/resource0", base);
	pci_fd = open(path, O_RDONLY);
	if (pci_fd < 0) {
		sprintf(path, "/sys/class/misc/%s/device/resource0", base);
		pci_fd = open(path, O_RDONLY);
	}
	if (pci_fd < 0) {
		fprintf(stderr, "%s did not find a pci resource\n", devicename);
		exit(ENODEV);
	}

	membase = mmap(0, getpagesize(), PROT_READ, MAP_SHARED, pci_fd, 0);
	if (!membase) {
		fprintf(stderr, "%s failed to map\n", devicename);
		exit(ENODEV);
	}
	*bar = membase;
}

struct list_item {
	char                node[1024];
	struct nvme_id_ctrl ctrl;
	int                 nsid;
	struct nvme_id_ns   ns;
	unsigned            block;
	__le32              ver;
};

#ifdef LIBUDEV_EXISTS
/* For pre NVMe 1.2 devices we must get the version from the BAR, not the
 * ctrl_id.*/
static void get_version(struct list_item* list_item)
{
	struct nvme_bar *bar;

	list_item->ver = list_item->ctrl.ver;
	if (list_item->ctrl.ver)
		return;
	get_registers(&bar, 0);
	list_item->ver = bar->vs;
}

static void print_list_item(struct list_item list_item)
{

	double nsze       = list_item.ns.nsze;
	double nuse       = list_item.ns.nuse;
	long long int lba = list_item.ns.lbaf[(list_item.ns.flbas & 0x0f)].ds;

	lba  = (1 << lba);
	nsze *= lba;
	nuse *= lba;

	const char *s_suffix = suffix_si_get(&nsze);
	const char *u_suffix = suffix_si_get(&nuse);
	const char *l_suffix = suffix_binary_get(&lba);

	char usage[128];
	sprintf(usage,"%6.2f %2sB / %6.2f %2sB", nuse, u_suffix,
		nsze, s_suffix);
	char format[128];
	sprintf(format,"%3.0f %2sB + %2d B", (double)lba, l_suffix,
		list_item.ns.lbaf[(list_item.ns.flbas & 0x0f)].ms);
	char version[128];
	sprintf(version,"%d.%d", (list_item.ver >> 16),
		(list_item.ver >> 8) & 0xff);

	fprintf(stdout, "%-16s %-20.20s %-8s %-8d %-26s %-16s %-.8s\n", list_item.node,
		list_item.ctrl.mn, version, list_item.nsid, usage, format, list_item.ctrl.fr);
}

static void print_list_items(struct list_item *list_items, unsigned len)
{
	unsigned i;

	fprintf(stdout,"%-16s %-20s %-8s %-8s %-26s %-16s %-8s\n",
		"Node","Model","Version","Namepace", "Usage", "Format", "FW Rev");
	fprintf(stdout,"%-16s %-20s %-8s %-8s %-26s %-16s %-8s\n",
            "----------------","--------------------","--------","--------",
            "--------------------------","----------------","--------");
	for (i = 0 ; i < len ; i++)
		print_list_item(list_items[i]);

}
#else
static int list(int argc, char **argv)
{
	fprintf(stderr,"nvme-list: libudev not detected, install and rebuild.\n");
	return -1;
}
#endif

#ifdef LIBUDEV_EXISTS
#define MAX_LIST_ITEMS 256
static int list(int argc, char **argv)
{
	struct udev *udev;
	struct udev_enumerate *enumerate;
	struct udev_list_entry *devices, *dev_list_entry;
	struct udev_device *dev;

	struct list_item list_items[MAX_LIST_ITEMS];
	unsigned count=0;

	udev = udev_new();
	if (!udev) {
		perror("nvme-list: Cannot create udev context.");
		return errno;
	}

	enumerate = udev_enumerate_new(udev);
	udev_enumerate_add_match_subsystem(enumerate, "block");
	udev_enumerate_add_match_property(enumerate, "DEVTYPE", "disk");
	udev_enumerate_scan_devices(enumerate);
	devices = udev_enumerate_get_list_entry(enumerate);
	udev_list_entry_foreach(dev_list_entry, devices) {
		int err;
		const char *path, *node;
		path = udev_list_entry_get_name(dev_list_entry);
		dev  = udev_device_new_from_syspath(udev, path);
		node = udev_device_get_devnode(dev);
		if (strstr(node,"nvme")!=NULL){
			open_dev(node);
			err = nvme_identify_ctrl(fd, &list_items[count].ctrl);
			if (err > 0)
				return err;
			list_items[count].nsid = nvme_get_nsid(fd);
			err = nvme_identify_ns(fd, list_items[count].nsid,
						0, &list_items[count].ns);
			if (err > 0)
				return err;
			strcpy(list_items[count].node, node);
			list_items[count].block = S_ISBLK(nvme_stat.st_mode);
			get_version(&list_items[count]);
			count++;
		}
	}
	udev_enumerate_unref(enumerate);
	udev_unref(udev);

	if (count)
		print_list_items(list_items, count);
	else
		fprintf(stdout,"No NVMe devices detected.\n");

	return 0;
}
#endif

static int id_ctrl(int argc, char **argv)
{
	const char *desc = "id-ctrl: send an Identify Controller command to "\
		"the given device and report information about the specified "\
		"controller in human-readable or "\
		"binary format. Can also return binary vendor-specific "\
		"controller attributes.";
	const char *vendor_specific = "dump binary vendor infos";
	const char *raw_binary = "show infos in binary format";
	const char *human_readable = "show infos in readable format";
	int err;
	unsigned int flags = 0;
	struct nvme_id_ctrl ctrl;

	struct config {
		__u8  vendor_specific;
		__u8  raw_binary;
		__u8  human_readable;
	};
	struct config cfg;

	const struct config defaults = {
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"vendor-specific", "", CFG_NONE, &defaults.vendor_specific, no_argument, vendor_specific},
		{"v",               "", CFG_NONE, &defaults.vendor_specific, no_argument, vendor_specific},
		{"raw-binary",      "", CFG_NONE, &defaults.raw_binary,      no_argument, raw_binary},
		{"b",               "", CFG_NONE, &defaults.raw_binary,      no_argument, raw_binary},
		{"human-readable",  "", CFG_NONE, &defaults.human_readable,  no_argument, human_readable},
		{"H",               "", CFG_NONE, &defaults.human_readable,  no_argument, human_readable},
		{0}
	};

	argconfig_parse(argc, argv, desc, command_line_options,
			&defaults, &cfg, sizeof(cfg));

	if (cfg.vendor_specific)
		flags |= VS;
	if (cfg.human_readable)
		flags |= HUMAN;

	get_dev(1, argc, argv);

	err = nvme_identify_ctrl(fd, &ctrl);
	if (!err) {
		if (cfg.raw_binary) {
			d_raw((unsigned char *)&ctrl, sizeof(ctrl));
		} else {
			printf("NVME Identify Controller:\n");
			show_nvme_id_ctrl(&ctrl, flags);
		}
	}
	else if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x)\n",
				nvme_status_to_string(err), err);

	return err;
}

static int id_ns(int argc, char **argv)
{
	const char *desc = "id-ns: send an Identify Namespace command to the "\
		"given device, returns properties of the specified namespace "\
		"in either human-readable or binary format. Can also return "\
		"binary vendor-specific namespace attributes.";
	const char *vendor_specific = "dump binary vendor infos";
	const char *raw_binary = "show infos in binary format";
	const char *human_readable = "show infos in readable format";
	const char *namespace_id = "name of desired namespace";
	struct nvme_id_ns ns;
	int err;
	unsigned int flags = 0;

	struct config {
		__u32 namespace_id;
		__u8  vendor_specific;
		__u8  raw_binary;
		__u8  human_readable;
	};
	struct config cfg;

	const struct config defaults = {
		.namespace_id    = 0,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id",    "NUM", CFG_POSITIVE, &defaults.namespace_id,    required_argument, namespace_id},
		{"n",               "NUM", CFG_POSITIVE, &defaults.namespace_id,    required_argument, namespace_id},
		{"vendor-specific", "",    CFG_NONE,     &defaults.vendor_specific, no_argument,       vendor_specific},
		{"v",               "",    CFG_NONE,     &defaults.vendor_specific, no_argument,       vendor_specific},
		{"raw-binary",      "",    CFG_NONE,     &defaults.raw_binary,      no_argument,       raw_binary},
		{"b",               "",    CFG_NONE,     &defaults.raw_binary,      no_argument,       raw_binary},
		{"human-readable",  "",    CFG_NONE,     &defaults.human_readable,  no_argument,       human_readable},
		{"H",               "",    CFG_NONE,     &defaults.human_readable,  no_argument,       human_readable},
		{0}
	};

	argconfig_parse(argc, argv, desc, command_line_options,
			&defaults, &cfg, sizeof(cfg));

	if (cfg.vendor_specific)
		flags |= VS;
	if (cfg.human_readable)
		flags |= HUMAN;

	get_dev(1, argc, argv);

	if (!cfg.namespace_id) {
		if (!S_ISBLK(nvme_stat.st_mode)) {
			fprintf(stderr,
				"%s: non-block device requires namespace-id param\n",
				devicename);
			exit(ENOTBLK);
		}
		cfg.namespace_id = nvme_get_nsid(fd);
		if (cfg.namespace_id <= 0) {
			perror(devicename);
			exit(errno);
		}
	}
	err = nvme_identify_ns(fd, cfg.namespace_id, 0, &ns);
	if (!err) {
		if (cfg.raw_binary)
			d_raw((unsigned char *)&ns, sizeof(ns));
		else {
			printf("NVME Identify Namespace %d:\n", cfg.namespace_id);
			show_nvme_id_ns(&ns, flags);
		}
	}
	else if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x) NSID:%d\n",
			nvme_status_to_string(err), err, cfg.namespace_id);
	return err;
}

static int get_ns_id(int argc, char **argv)
{
	int nsid;

	open_dev(argv[1]);
	if (!S_ISBLK(nvme_stat.st_mode)) {
		fprintf(stderr, "%s: requesting nsid from non-block device\n",
								devicename);
		exit(ENOTBLK);
	}
	nsid = nvme_get_nsid(fd);
	if (nsid <= 0) {
		perror(devicename);
		exit(errno);
	}
	printf("%s: namespace-id:%d\n", devicename, nsid);
	return 0;
}

static int get_feature(int argc, char **argv)
{
	const char *desc = "get-feature: read operating parameters of the "\
		"specified controller. Operating parameters are grouped "\
		"and identified by Feature Identifiers; each Feature "\
		"Identifier contains one or more attributes that may affect "\
		"behaviour of the feature. Each Feature has three possible "\
		"settings: default, saveable, and current. If a Feature is "\
		"saveable, it may be modified by set-feature. Default values "\
		"are vendor-specific and not changeable. Use set-feature to "\
		"change saveable Features.";
	const char *raw_binary = "show infos in binary format";
	const char *namespace_id = "name of desired namespace";
	const char *feature_id = "hexadecimal feature name";
	const char *sel = "[0-3]: curr./default/saved/supp.";
	const char *data_len = "buffer len (if) data is returned";
	const char *cdw11 = "dword 11 for interrupt vector config";
	const char *human_readable = "show infos in readable format";
	int err;
	__u32 result;
	void *buf = NULL;

	struct config {
		__u32 namespace_id;
		__u32 feature_id;
		__u8  sel;
		__u32 cdw11;
		__u32 data_len;
		__u8  raw_binary;
		__u8  human_readable;
	};
	struct config cfg;

	const struct config defaults = {
		.namespace_id = 1,
		.feature_id   = 0,
		.sel          = 0,
		.cdw11        = 0,
		.data_len     = 0,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id", "NUM",  CFG_POSITIVE, &defaults.namespace_id, required_argument, namespace_id},
		{"n",            "NUM",  CFG_POSITIVE, &defaults.namespace_id, required_argument, namespace_id},
		{"feature-id",   "NUM",  CFG_POSITIVE, &defaults.feature_id,   required_argument, feature_id},
		{"f",            "NUM",  CFG_POSITIVE, &defaults.feature_id,   required_argument, feature_id},
		{"sel",          "NUM",  CFG_BYTE,     &defaults.sel,          required_argument, sel},
		{"s",            "NUM",  CFG_BYTE,     &defaults.sel,          required_argument, sel},
		{"data-len",     "NUM",  CFG_POSITIVE, &defaults.data_len,     required_argument, data_len},
		{"l",            "NUM",  CFG_POSITIVE, &defaults.data_len,     required_argument, data_len},
		{"raw-binary",   "",     CFG_NONE,     &defaults.raw_binary,   no_argument,       raw_binary},
		{"b",            "",     CFG_NONE,     &defaults.raw_binary,   no_argument,       raw_binary},
		{"cdw11",        "NUM",  CFG_POSITIVE, &defaults.cdw11,        required_argument, cdw11},
		{"human-readable",  "",  CFG_NONE,     &defaults.human_readable,  no_argument,    human_readable},
		{"H",               "",  CFG_NONE,     &defaults.human_readable,  no_argument, human_readable},
		{0}
	};

	argconfig_parse(argc, argv, desc, command_line_options,
			&defaults, &cfg, sizeof(cfg));

	get_dev(1, argc, argv);

	if (cfg.sel > 7) {
		fprintf(stderr, "invalid 'select' param:%d\n", cfg.sel);
		return EINVAL;
	}
	if (!cfg.feature_id) {
		fprintf(stderr, "feature-id required param\n");
		return EINVAL;
	}
	
	switch (cfg.feature_id)
	{
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
	
	if (cfg.data_len)
		buf = malloc(cfg.data_len);

	err = nvme_get_feature(fd, cfg.namespace_id, cfg.feature_id, cfg.sel, cfg.cdw11,
			cfg.data_len, buf, &result);
	if (!err) { 
		printf("get-feature: 0x%02X (%s), %s value: %#08x\n", cfg.feature_id, 
				nvme_feature_to_string(cfg.feature_id),
				nvme_select_to_string(cfg.sel), result); 
		if (cfg.human_readable)
			nvme_feature_show_fields(cfg.feature_id, result, buf);
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
		fprintf(stderr, "NVMe Status:%s(%x)\n",
				nvme_status_to_string(err), err);
	if (buf)
		free(buf);
	return err;
}

static int fw_download(int argc, char **argv)
{
	const char *desc = "fw-download: copy all or part of a firmware to "\
		"a controller for future update. Optionally, specify how "\
		"many KiB of the firmware to transfer at once (offset will "\
		"start at 0 and automatically adjust based on xfer size "\
		"unless fw is split across multiple files). May be submitted "\
		"while outstanding commands exist on the Admin and IO "\
		"Submission Queues. Activate downloaded firmware with "\
		"fw-activate and reset the device to apply the downloaded firmware.";
	const char *fw = "firmware file (required)";
	const char *xfer = "transfer chunksize limit";
	const char *offset = "starting dword offset, default 0";
	int err, fw_fd = -1;
	unsigned int fw_size;
	struct stat sb;
	void *fw_buf;

	struct config {
		char  *fw;
		__u32 xfer;
		__u32 offset;
	};
	struct config cfg;

	const struct config defaults = {
		.fw     = "",
		.xfer   = 4096,
		.offset = 0,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"fw",     "FILE", CFG_STRING,   &defaults.fw,     required_argument, fw},
		{"f",      "FILE", CFG_STRING,   &defaults.fw,     required_argument, fw},
		{"xfer",   "NUM",  CFG_POSITIVE, &defaults.xfer,   required_argument, xfer},
		{"x",      "NUM",  CFG_POSITIVE, &defaults.xfer,   required_argument, xfer},
		{"offset", "NUM",  CFG_POSITIVE, &defaults.offset, required_argument, offset},
		{"o",      "NUM",  CFG_POSITIVE, &defaults.offset, required_argument, offset},
		{0}
	};

	argconfig_parse(argc, argv, desc, command_line_options,
			&defaults, &cfg, sizeof(cfg));

	get_dev(1, argc, argv);

	fw_fd = open(cfg.fw, O_RDONLY);
	cfg.offset <<= 2;
	if (fw_fd < 0) {
		fprintf(stderr, "no firmware file provided\n");
		return EINVAL;
	}
	err = fstat(fw_fd, &sb);
	if (err < 0) {
		perror("fstat");
		exit(errno);
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
			exit(errno);
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

static int fw_activate(int argc, char **argv)
{
	const char *desc = "fw-activate: verify downloaded firmware image and "\
		"commit to specific firmware slot. Device is not automatically "\
		"reset following firmware activation. A reset may be issued "\
		"with an 'echo 1 > /sys/class/misc/nvmeX/device/reset'. "\
		"Ensure nvmeX is the device you just activated before reset.";
	const char *slot = "firmware slot to activate";
	const char *action = "[0-2]: replacement action";
	int err;

	struct config {
		__u8 slot;
		__u8 action;
	};
	struct config cfg;

	const struct config defaults = {
		.slot   = 0,
		.action = 0,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"slot",   "NUM", CFG_BYTE, &defaults.slot,   required_argument, slot},
		{"s",      "NUM", CFG_BYTE, &defaults.slot,   required_argument, slot},
		{"action", "NUM", CFG_BYTE, &defaults.action, required_argument, action},
		{"a",      "NUM", CFG_BYTE, &defaults.action, required_argument, action},
		{0}
	};

	argconfig_parse(argc, argv, desc, command_line_options,
			&defaults, &cfg, sizeof(cfg));

	get_dev(1, argc, argv);

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
		if (err == NVME_SC_FIRMWARE_NEEDS_RESET)
			printf("Success activating firmware action:%d slot:%d, but a conventional reset is required\n",
			       cfg.action, cfg.slot);
		else
			fprintf(stderr, "NVME Admin command error:%s(%x)\n",
						nvme_status_to_string(err), err);
	else
		printf("Success activating firmware action:%d slot:%d\n",
		       cfg.action, cfg.slot);
	return err;
}

static int show_registers(int argc, char **argv)
{
	int opt, long_index;
	struct nvme_bar *bar;
	static struct option opts[] = {};

	while ((opt = getopt_long(argc, (char **)argv, "", opts,
					&long_index)) != -1);
	get_dev(optind, argc, argv);

	get_registers(&bar, 1);
	printf("cap     : %"PRIx64"\n", (uint64_t)bar->cap);
	printf("version : %x\n", bar->vs);
	printf("intms   : %x\n", bar->intms);
	printf("intmc   : %x\n", bar->intmc);
	printf("cc      : %x\n", bar->cc);
	printf("csts    : %x\n", bar->csts);
	printf("nssr    : %x\n", bar->nssr);
	printf("aqa     : %x\n", bar->aqa);
	printf("asq     : %"PRIx64"\n", (uint64_t)bar->asq);
	printf("acq     : %"PRIx64"\n", (uint64_t)bar->acq);
	printf("cmbloc  : %x\n", bar->cmbloc);
	printf("cmbsz   : %x\n", bar->cmbsz);

	return 0;
}

static int format(int argc, char **argv)
{
	const char *desc = "format: re-format a specified namespace on the "\
		"given device. Can erase all data in namespace (user "\
		"data erase) or delete data encryption key if specified. "\
		"Can also be used to change LBAF such that device may "\
		"disappear from all lists since capacity superficially "\
		"appears to be 0.";
	const char *namespace_id = "name of desired namespace";
	const char *lbaf = "LBA format to apply (req'd)";
	const char *ses = "[0-2]: secure erase";
	const char *pil = "[0-3]: protection info location";
	const char *pi = "[0-1]: protection info off/on";
	const char *ms = "[0-1]: extended format off/on";
	const char *timeout = "timeout value";
	int err;
	struct nvme_admin_cmd cmd;

	struct config {
		__u32 namespace_id;
		__u32 timeout;
		__u8  lbaf;
		__u8  ses;
		__u8  pi;
		__u8  pil;
		__u8  ms;
	};
	struct config cfg;

	const struct config defaults = {
		.namespace_id = 0xffffffff,
		.timeout      = 120000,
		.lbaf         = 0,
		.ses          = 0,
		.pi           = 0,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id", "NUM",  CFG_POSITIVE, &defaults.namespace_id, required_argument, namespace_id},
		{"n",            "NUM",  CFG_POSITIVE, &defaults.namespace_id, required_argument, namespace_id},
		{"timeout",      "NUM",  CFG_POSITIVE, &defaults.timeout,      required_argument, timeout},
		{"t",            "NUM",  CFG_POSITIVE, &defaults.timeout,      required_argument, timeout},
		{"lbaf",         "NUM",  CFG_BYTE,     &defaults.lbaf,         required_argument, lbaf},
		{"l",            "NUM",  CFG_BYTE,     &defaults.lbaf,         required_argument, lbaf},
		{"ses",          "NUM",  CFG_BYTE,     &defaults.ses,          required_argument, ses},
		{"s",            "NUM",  CFG_BYTE,     &defaults.ses,          required_argument, ses},
		{"pi",           "NUM",  CFG_BYTE,     &defaults.pi,           required_argument, pi},
		{"i",            "NUM",  CFG_BYTE,     &defaults.pi,           required_argument, pi},
		{"pil",          "NUM",  CFG_BYTE,     &defaults.pil,          required_argument, pil},
		{"p",            "NUM",  CFG_BYTE,     &defaults.pil,          required_argument, pil},
		{"ms",           "NUM",  CFG_BYTE,     &defaults.ms,           required_argument, ms},
		{"m",            "NUM",  CFG_BYTE,     &defaults.ms,           required_argument, ms},
		{0}
	};

	argconfig_parse(argc, argv, desc, command_line_options,
			&defaults, &cfg, sizeof(cfg));

	get_dev(1, argc, argv);

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
	if (S_ISBLK(nvme_stat.st_mode)) {
		cfg.namespace_id = nvme_get_nsid(fd);
		if (cfg.namespace_id <= 0) {
			fprintf(stderr,
				"%s: failed to return namespace id\n",
				devicename);
			return errno;
		}
	}

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = nvme_admin_format_nvm;
	cmd.nsid   = cfg.namespace_id;
	cmd.cdw10  = (cfg.lbaf << 0) | (cfg.ms << 4) | (cfg.pi << 5) | (cfg.pil << 8) | (cfg.ses << 9);
	cmd.timeout_ms = cfg.timeout;

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
	}
	return err;
}

static int set_feature(int argc, char **argv)
{
	const char *desc = "set-feature: modify the saveable/changeable "\
		"current operating parameters of the controller. Operating "\
		"parameters are grouped and identified by Feature "\
		"Identifiers. Feature settings can be applied to the entire "\
		"controller and all associated namespaces, or to only a few "\
		"namespace(s) associated with the controller. Default values "\
		"for each Feature are vendor-specific and may not be modified."\
		"Use get-feature to determine which Features are supported by "\
		"the controller and are saveable/changeable.";
	const char *namespace_id = "desired namespace";
	const char *feature_id = "hex feature name (req'd)";
	const char *data_len = "buffer len (if) data returned";
	const char *data = "optional file (default stdin)";
	const char *value = "new value of feature (req'd)";
	int err;
	__u32 result;
	void *buf = NULL;
	int fd = STDIN_FILENO;

	struct config {
		char *file;
		__u32 namespace_id;
		__u32 feature_id;
		__u32 value;
		__u32 data_len;
	};
	struct config cfg;

	const struct config defaults = {
		.file         = "",
		.namespace_id = 0,
		.feature_id   = 0,
		.value        = 0,
		.data_len     = 0,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id", "NUM",  CFG_POSITIVE, &defaults.namespace_id, required_argument, namespace_id},
		{"n",            "NUM",  CFG_POSITIVE, &defaults.namespace_id, required_argument, namespace_id},
		{"feature-id",   "NUM",  CFG_POSITIVE, &defaults.feature_id,   required_argument, feature_id},
		{"f",            "NUM",  CFG_POSITIVE, &defaults.feature_id,   required_argument, feature_id},
		{"value",        "NUM",  CFG_POSITIVE, &defaults.value,        required_argument, value},
		{"v",            "NUM",  CFG_POSITIVE, &defaults.value,        required_argument, value},
		{"data-len",     "NUM",  CFG_POSITIVE, &defaults.data_len,     required_argument, data_len},
		{"l",            "NUM",  CFG_POSITIVE, &defaults.data_len,     required_argument, data_len},
		{"data",         "FILE", CFG_STRING,   &defaults.file,         required_argument, data},
		{"d",            "FILE", CFG_STRING,   &defaults.file,         required_argument, data},
		{0}
	};

	argconfig_parse(argc, argv, desc, command_line_options,
			&defaults, &cfg, sizeof(cfg));

	get_dev(1, argc, argv);

	if (cfg.value == -1) {
		fprintf(stderr, "feature value required param\n");
		return EINVAL;
	}
	if (!cfg.feature_id) {
		fprintf(stderr, "feature-id required param\n");
		return EINVAL;
	}
	if (cfg.feature_id == NVME_FEAT_LBA_RANGE)
		cfg.data_len = 4096;
	if (cfg.data_len)
		buf = malloc(cfg.data_len);
	if (buf) {
		if (strlen(cfg.file)) {
			fd = open(cfg.file, O_RDONLY);
			if (fd <= 0) {
				fprintf(stderr, "no firmware file provided\n");
				return -EINVAL;
			}
		}
		if (read(fd, (void *)buf, cfg.data_len) < 0) {
			fprintf(stderr, "failed to read data buffer from input file\n");
			return EINVAL;
		}
	}

	err = nvme_set_feature(fd, cfg.namespace_id, cfg.feature_id, cfg.value, 0,
				cfg.data_len, buf, &result);
	if (!err) {
		printf("set-feature:%d(%s), value:%#08x\n", cfg.feature_id,
			nvme_feature_to_string(cfg.feature_id), result);
		if (buf) {
			if (cfg.feature_id == NVME_FEAT_LBA_RANGE)
				show_lba_range((struct nvme_lba_range_type *)buf,
								result);
			else
				d(buf, cfg.data_len, 16, 1);
		}
	}
	else if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x)\n",
				nvme_status_to_string(err), err);
	if (buf)
		free(buf);
	return err;
}

static int sec_send(int argc, char **argv)
{
	struct stat sb;
	const char *desc = "security-send: transfer security protocol data to "\
		"a controller. Security Receives for the same protocol should be "\
		"performed after Security Sends. The security protocol field "\
		"associates Security Sends (security-send) and Security Receives "\
		"(security-recv).";
	const char *file = "transfer payload";
	const char *secp = "security protocol (cf. SPC-4)";
	const char *spsp = "security-protocol-specific (cf. SPC-4)";
	const char *tl = "transfer length (cf. SPC-4)";
	int err, sec_fd = -1;
	void *sec_buf;
	unsigned int sec_size;
	__u32 result;

	struct config {
		char  *file;
		__u8  secp;
		__u16 spsp;
		__u32 tl;
	};
	struct config cfg;

	const struct config defaults = {
		.file = "",
		.secp = 0,
		.spsp = 0,
		.tl   = 0,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"file",       "FILE",  CFG_STRING,   &defaults.file,       required_argument, file},
		{"f",          "FILE",  CFG_STRING,   &defaults.file,       required_argument, file},
		{"secp",       "NUM",   CFG_BYTE,     &defaults.secp,       required_argument, secp},
		{"p",          "NUM",   CFG_BYTE,     &defaults.secp,       required_argument, secp},
		{"spsp",       "NUM",   CFG_SHORT,    &defaults.spsp,       required_argument, spsp},
		{"s",          "NUM",   CFG_SHORT,    &defaults.spsp,       required_argument, spsp},
		{"tl",         "NUM",   CFG_POSITIVE, &defaults.tl,         required_argument, tl},
		{"t",          "NUM",   CFG_POSITIVE, &defaults.tl,         required_argument, tl},
		{0}
	};

	argconfig_parse(argc, argv, desc, command_line_options,
			&defaults, &cfg, sizeof(cfg));

	get_dev(1, argc, argv);

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

	err = nvme_sec_send(fd,
			0 /* FIXME: add nsid param */,
			0 /* FIXME: add nssf */,
			cfg.spsp, cfg.secp, cfg.tl, sec_size, sec_buf, &result);
	if (err < 0)
		return errno;
	else if (err != 0)
		fprintf(stderr, "NVME Security Send Command Error:%d\n", err);
	else
		printf("NVME Security Send Command Success:%d\n", result);
	return err;
}

static int dsm(int argc, char **argv)
{
	const char *desc = "dsm: The Dataset Management command is used by the host to "\
		"indicate attributes for ranges of logical blocks. This includes attributes "\
		"like frequency that data is read or written, access size, and other "\
		"information that may be used to optimize performance and reliability.";
	const char *namespace_id = "name of desired namespace";
	const char *blocks = "Comma separated list of the number of blocks in each range";
	const char *starting_blocks = "Comma separated list of the starting block in each range";
	const char *context_attrs = "Comma separated list of the context attributes in each range";
	const char *ad = "Attribute Deallocate";
	const char *idw = "Attribute Integral Dataset for Write";
	const char *idr = "Attribute Integral Dataset for Read";
	const char *cdw11 = "All the command command dword 11 attribuets. Use instead of specifying individual attributes";

	int err;
	uint16_t nr, nc, nb, ns;
	int ctx_attrs[256] = {0,};
	int nlbs[256] = {0,};
	unsigned long long slbas[256] = {0,};
	struct nvme_dsm_range *dsm;

	struct config {
		char  *ctx_attrs;
		char  *blocks;
		char  *slbas;
		int  ad;
		int  idw;
		int  idr;
		__u32 cdw11;
		__u32 namespace_id;
	};
	struct config cfg;

	const struct config defaults = {
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
		{"namespace-id", "NUM",  CFG_POSITIVE,  &defaults.namespace_id, required_argument, namespace_id},
		{"n",            "NUM",  CFG_POSITIVE,  &defaults.namespace_id, required_argument, namespace_id},
		{"ctx-attrs",    "LIST", CFG_STRING,    &defaults.ctx_attrs,    required_argument, context_attrs},
		{"a",            "LIST", CFG_STRING,    &defaults.ctx_attrs,    required_argument, context_attrs},
		{"blocks", 	 "LIST", CFG_STRING,    &defaults.blocks,       required_argument, blocks},
		{"b", 	         "LIST", CFG_STRING,    &defaults.blocks,       required_argument, blocks},
		{"slbs", 	 "LIST", CFG_STRING,    &defaults.slbas,        required_argument, starting_blocks},
		{"s", 	         "LIST", CFG_STRING,    &defaults.slbas,        required_argument, starting_blocks},
		{"ad", 	         "FLAG", CFG_NONE,      &defaults.ad,           no_argument,       ad},
		{"d", 	         "FLAG", CFG_NONE,      &defaults.ad,           no_argument,       ad},
		{"idw", 	 "FLAG", CFG_NONE,      &defaults.idw,          no_argument,       idw},
		{"w", 	         "FLAG", CFG_NONE,      &defaults.idw,          no_argument,       idw},
		{"idr", 	 "FLAG", CFG_NONE,      &defaults.idr,          no_argument,       idr},
		{"r", 	         "FLAG", CFG_NONE,      &defaults.idr,          no_argument,       idr},
		{"cdw11",        "NUM",  CFG_POSITIVE,  &defaults.namespace_id, required_argument, cdw11},
		{"c",            "NUM",  CFG_POSITIVE,  &defaults.namespace_id, required_argument, cdw11},
		{0}
	};

	argconfig_parse(argc, argv, desc, command_line_options,
			&defaults, &cfg, sizeof(cfg));
	get_dev(1, argc, argv);

	nc = argconfig_parse_comma_sep_array(cfg.ctx_attrs, ctx_attrs, array_len(ctx_attrs));
	nb = argconfig_parse_comma_sep_array(cfg.blocks, nlbs, array_len(nlbs));
	ns = argconfig_parse_comma_sep_array_long(cfg.slbas, slbas, array_len(slbas));
	nr = max(nc, max(nb, ns));
	if (!nr || nr > 256) {
		fprintf(stderr, "No range definition provided\n");
		return EINVAL;
	}

	if (!cfg.namespace_id) {
		if (!S_ISBLK(nvme_stat.st_mode)) {
			fprintf(stderr,
				"%s: non-block device requires namespace-id param\n",
				devicename);
			exit(ENOTBLK);
		}
		cfg.namespace_id = nvme_get_nsid(fd);
		if (cfg.namespace_id <= 0) {
			fprintf(stderr,
				"%s: failed to return namespace id\n",
				devicename);
			return errno;
		}
	}

	if (!cfg.cdw11)
		cfg.cdw11 = (cfg.ad << 2) | (cfg.idw << 1) | (cfg.idr << 0);

	dsm = nvme_setup_dsm_range((__u32 *)ctx_attrs, (__u32 *)nlbs, (__u64 *)slbas, nr);

	err = nvme_dsm(fd, cfg.namespace_id, cfg.cdw11, dsm, nr);
	if (err < 0) {
		fprintf(stderr, "error:%x\n", err);
		return errno;
	} else if (err != 0)
		fprintf(stderr, "NVME IO command error:%s(%x)\n",
				nvme_status_to_string(err), err);
	else
		printf("NVMe DSM: success\n");
	return 0;
}

static int flush(int argc, char **argv)
{
	const char *desc = "flush: commit data and metadata associated with "\
	"given namespaces to nonvolatile media. Applies to all commands "\
	"finished before the flush was submitted. Additional data may also be "\
	"flushed by the controller, from any namespace, depending on controller and "\
	"associated namespace status.";
	const char *namespace_id = "name of desired namespace";
	int err;

	struct config {
		__u32 namespace_id;
	};
	struct config cfg;

	const struct config defaults = {
		.namespace_id = 0xffffffff,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id", "NUM",  CFG_POSITIVE,    &defaults.namespace_id, required_argument, namespace_id},
		{"n",            "NUM",  CFG_POSITIVE,    &defaults.namespace_id, required_argument, namespace_id},
		{0}
	};

	argconfig_parse(argc, argv, desc, command_line_options,
			&defaults, &cfg, sizeof(cfg));

	get_dev(1, argc, argv);

	err = nvme_flush(fd, cfg.namespace_id);
	if (err < 0)
		return errno;
	else if (err != 0)
		fprintf(stderr, "NVME IO command error:%s(%x)\n",
				nvme_status_to_string(err), err);
	else
		printf("NVMe Flush: success\n");
	return 0;
}

static int resv_acquire(int argc, char **argv)
{
	const char *desc = "resv-acquire: obtain a reservation on a given "\
		"namespace. Only one reservation is allowed at a time on a "\
		"given namespace, though multiple controllers may register "\
		"with that namespace. Namespace reservation will abort with "\
		"status Reservation Conflict if the given namespace is "\
		"already reserved.";
	const char *namespace_id = "name of desired namespace";
	const char *crkey = "current reservation key";
	const char *prkey = "pre-empt reservation key";
	const char *rtype = "hex reservation type";
	const char *racqa = "reservation acquiry action";
	const char *iekey = "ignore existing res. key";
	int err;

	struct config {
		__u32 namespace_id;
		__u64 crkey;
		__u64 prkey;
		__u8  rtype;
		__u8  racqa;
		__u8  iekey;
	};
	struct config cfg;

	const struct config defaults = {
		.namespace_id = 0,
		.crkey        = 0,
		.prkey        = 0,
		.rtype        = 0,
		.racqa        = 0,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id", "NUM",  CFG_POSITIVE,    &defaults.namespace_id, required_argument, namespace_id},
		{"n",            "NUM",  CFG_POSITIVE,    &defaults.namespace_id, required_argument, namespace_id},
		{"crkey",        "NUM",  CFG_LONG_SUFFIX, &defaults.crkey,        required_argument, crkey},
		{"c",            "NUM",  CFG_LONG_SUFFIX, &defaults.crkey,        required_argument, crkey},
		{"prkey",        "NUM",  CFG_LONG_SUFFIX, &defaults.prkey,        required_argument, prkey},
		{"p",            "NUM",  CFG_LONG_SUFFIX, &defaults.prkey,        required_argument, prkey},
		{"rtype",        "NUM",  CFG_BYTE,        &defaults.rtype,        required_argument, rtype},
		{"t",            "NUM",  CFG_BYTE,        &defaults.rtype,        required_argument, rtype},
		{"racqa",        "NUM",  CFG_BYTE,        &defaults.racqa,        required_argument, racqa},
		{"a",            "NUM",  CFG_BYTE,        &defaults.racqa,        required_argument, racqa},
		{"iekey",        "",     CFG_NONE,        &defaults.iekey,        no_argument,       iekey},
		{"i",            "",     CFG_NONE,        &defaults.iekey,        no_argument,       iekey},
		{0}
	};

	argconfig_parse(argc, argv, desc, command_line_options,
			&defaults, &cfg, sizeof(cfg));

	get_dev(1, argc, argv);

	if (!cfg.namespace_id) {
		if (!S_ISBLK(nvme_stat.st_mode)) {
			fprintf(stderr,
				"%s: non-block device requires namespace-id param\n",
				devicename);
			exit(ENOTBLK);
		}
		cfg.namespace_id = nvme_get_nsid(fd);
		if (cfg.namespace_id <= 0) {
			fprintf(stderr,
				"%s: failed to return namespace id\n",
				devicename);
			return errno;
		}
	}
	if (cfg.racqa > 7) {
		fprintf(stderr, "invalid racqa:%d\n", cfg.racqa);
		return EINVAL;
	}

	err = nvme_resv_acquire(fd, cfg.namespace_id, cfg.rtype, cfg.racqa,
				!!cfg.iekey, cfg.crkey, cfg.prkey);
	if (err < 0)
		return errno;
	else if (err != 0)
		fprintf(stderr, "NVME IO command error:%04x\n", err);
	else
		printf("NVME Reservation Acquire success\n");
	return 0;
}

static int resv_register(int argc, char **argv)
{
	const char *desc = "resv-register: register, de-register, or "\
		"replace a controller's reservation on a given namespace. "\
		"Only one reservation at a time is allowed on any namespace.";
	const char *namespace_id = "name of desired namespace";
	const char *crkey = "current reservation key";
	const char *iekey = "ignore existing res. key";
	const char *nrkey = "new reservation key";
	const char *rrega = "reservation registration action";
	const char *cptpl = "change persistence through power loss setting";
	int err;

	struct config {
		__u32 namespace_id;
		__u64 crkey;
		__u64 nrkey;
		__u8  rrega;
		__u8  cptpl;
		__u8  iekey;
	};
	struct config cfg;

	const struct config defaults = {
		.namespace_id = 0,
		.crkey        = 0,
		.nrkey        = 0,
		.rrega        = 0,
		.cptpl        = 0,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id", "NUM",  CFG_POSITIVE,    &defaults.namespace_id, required_argument, namespace_id},
		{"n",            "NUM",  CFG_POSITIVE,    &defaults.namespace_id, required_argument, namespace_id},
		{"crkey",        "NUM",  CFG_LONG_SUFFIX, &defaults.crkey,        required_argument, crkey},
		{"c",            "NUM",  CFG_LONG_SUFFIX, &defaults.crkey,        required_argument, crkey},
		{"nrkey",        "NUM",  CFG_LONG_SUFFIX, &defaults.nrkey,        required_argument, nrkey},
		{"k",            "NUM",  CFG_LONG_SUFFIX, &defaults.nrkey,        required_argument, nrkey},
		{"rrega",        "NUM",  CFG_BYTE,        &defaults.rrega,        required_argument, rrega},
		{"r",            "NUM",  CFG_BYTE,        &defaults.rrega,        required_argument, rrega},
		{"cptpl",        "NUM",  CFG_BYTE,        &defaults.cptpl,        required_argument, cptpl},
		{"p",            "NUM",  CFG_BYTE,        &defaults.cptpl,        required_argument, cptpl},
		{"iekey",        "",     CFG_NONE,        &defaults.iekey,        no_argument,       iekey},
		{"i",            "",     CFG_NONE,        &defaults.iekey,        no_argument,       iekey},
		{0}
	};

	argconfig_parse(argc, argv, desc, command_line_options,
			&defaults, &cfg, sizeof(cfg));

	get_dev(1, argc, argv);

	if (!cfg.namespace_id) {
		if (!S_ISBLK(nvme_stat.st_mode)) {
			fprintf(stderr,
				"%s: non-block device requires namespace-id param\n",
				devicename);
			exit(ENOTBLK);
		}
		cfg.namespace_id = nvme_get_nsid(fd);
		if (cfg.namespace_id <= 0) {
			fprintf(stderr,
				"%s: failed to return namespace id\n",
				devicename);
			return errno;
		}
	}
	if (cfg.cptpl > 3) {
		fprintf(stderr, "invalid cptpl:%d\n", cfg.cptpl);
		return EINVAL;
	}

	err = nvme_resv_register(fd, cfg.namespace_id, cfg.rrega, cfg.cptpl,
				!!cfg.iekey, cfg.crkey, cfg.nrkey);
	if (err < 0)
		return errno;
	else if (err != 0)
		fprintf(stderr, "NVME IO command error:%04x\n", err);
	else
		printf("NVME Reservation  success\n");
	return 0;
}

static int resv_release(int argc, char **argv)
{
	const char *desc = "resv-release: releases reservation held on a "\
		"namespace by the given controller. If rtype != current reser"\
		"vation type, release fails. If the given controller holds no "\
		"reservation on the namespace/is not the namespace's current "\
		"reservation holder, the release command completes with no "\
		"effect. If the reservation type is not Write Exclusive or "\
		"Exclusive Access, all registrants on the namespace except "\
		"the issuing controller are notified.";
	const char *namespace_id = "desired namespace";
	const char *crkey = "current reservation key";
	const char *iekey = "ignore existing res. key";
	const char *rtype = "hex reservation type";
	const char *rrela = "reservation release action";
	int err;

	struct config {
		__u32 namespace_id;
		__u64 crkey;
		__u8  rtype;
		__u8  rrela;
		__u8  iekey;
	};
	struct config cfg;

	const struct config defaults = {
		.namespace_id = 0,
		.crkey        = 0,
		.rtype        = 0,
		.rrela        = 0,
		.iekey        = 0,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id", "NUM",  CFG_POSITIVE,    &defaults.namespace_id, required_argument, namespace_id},
		{"n",            "NUM",  CFG_POSITIVE,    &defaults.namespace_id, required_argument, namespace_id},
		{"crkey",        "NUM",  CFG_LONG_SUFFIX, &defaults.crkey,        required_argument, crkey},
		{"c",            "NUM",  CFG_LONG_SUFFIX, &defaults.crkey,        required_argument, crkey},
		{"rtype",        "NUM",  CFG_BYTE,        &defaults.rtype,        required_argument, rtype},
		{"t",            "NUM",  CFG_BYTE,        &defaults.rtype,        required_argument, rtype},
		{"rrela",        "NUM",  CFG_BYTE,        &defaults.rrela,        required_argument, rrela},
		{"a",            "NUM",  CFG_BYTE,        &defaults.rrela,        required_argument, rrela},
		{"iekey",        "NUM",  CFG_BYTE,        &defaults.iekey,        required_argument, iekey},
		{"i",            "NUM",  CFG_BYTE,        &defaults.iekey,        required_argument, iekey},
		{0}
	};

	argconfig_parse(argc, argv, desc, command_line_options,
			&defaults, &cfg, sizeof(cfg));

	get_dev(1, argc, argv);

	if (!cfg.namespace_id) {
		if (!S_ISBLK(nvme_stat.st_mode)) {
			fprintf(stderr,
				"%s: non-block device requires namespace-id param\n",
				devicename);
			exit(ENOTBLK);
		}
		cfg.namespace_id = nvme_get_nsid(fd);
		if (cfg.namespace_id <= 0) {
			fprintf(stderr,
				"%s: failed to return namespace id\n",
				devicename);
			return errno;
		}
	}
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
		return errno;
	else if (err != 0)
		fprintf(stderr, "NVME IO command error:%04x\n", err);
	else
		printf("NVME Reservation Register success\n");
	return 0;
}

static int resv_report(int argc, char **argv)
{
	const char *desc = "resv-report: returns Reservation Status data "\
		"structure describing any existing reservations on and the "\
		"status of a given namespace. Namespace Reservation Status "\
		"depends on the number of controllers registered for that "\
		"namespace.";
	const char *namespace_id = "name of desired namespace";
	const char *numd = "number of dwords to transfer";
	const char *raw_binary = "dump output in binary format";

	int err;
	struct nvme_reservation_status *status;

	struct config {
		__u32 namespace_id;
		__u32 numd;
		__u8  raw_binary;
	};
	struct config cfg;

	const struct config defaults = {
		.namespace_id = 0,
		.numd         = 0,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id", "NUM",  CFG_POSITIVE, &defaults.namespace_id, required_argument, namespace_id},
		{"n",            "NUM",  CFG_POSITIVE, &defaults.namespace_id, required_argument, namespace_id},
		{"numd",         "NUM",  CFG_POSITIVE, &defaults.numd,         required_argument, numd},
		{"d",            "NUM",  CFG_POSITIVE, &defaults.numd,         required_argument, numd},
		{"raw-binary",   "",     CFG_NONE,     &defaults.raw_binary,   no_argument,       raw_binary},
		{"b",            "",     CFG_NONE,     &defaults.raw_binary,   no_argument,       raw_binary},
		{0}
	};

	argconfig_parse(argc, argv, desc, command_line_options,
			&defaults, &cfg, sizeof(cfg));

	get_dev(1, argc, argv);

	if (!cfg.namespace_id) {
		if (!S_ISBLK(nvme_stat.st_mode)) {
			fprintf(stderr,
				"%s: non-block device requires namespace-id param\n",
				devicename);
			exit(ENOTBLK);
		}
		cfg.namespace_id = nvme_get_nsid(fd);
		if (cfg.namespace_id <= 0) {
			fprintf(stderr,
				"%s: failed to return namespace id\n",
				devicename);
			return errno;
		}
	}
	if (!cfg.numd || cfg.numd > (0x1000 >> 2))
		cfg.numd = 0x1000 >> 2;

	if (posix_memalign((void **)&status, getpagesize(), cfg.numd << 2)) {
		fprintf(stderr, "No memory for resv report:%d\n", cfg.numd << 2);
		return ENOMEM;
	}

	err = nvme_resv_report(fd, cfg.namespace_id, cfg.numd, status);
	if (err < 0)
		return errno;
	else if (err != 0)
		fprintf(stderr, "NVME IO command error:%04x\n", err);
	else {
		if (!cfg.raw_binary) {
			printf("NVME Reservation Report success\n");
			show_nvme_resv_report(status);
		} else
			d_raw((unsigned char *)status, cfg.numd << 2);
	}
	return 0;
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

	const char *start_block = "64-bit addr of first block to access";
	const char *block_count = "number of blocks on device to access";
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
	const char *force = "return data before command completes";
	const char *show = "show command before sending";
	const char *dry = "show command instead of sending";

	struct config {
		__u64 start_block;
		__u16 block_count;
		__u32 data_size;
		__u32 metadata_size;
		__u32 ref_tag;
		char  *data;
		char  *metadata;
		__u8  prinfo;
		__u8  app_tag_mask;
		__u32 app_tag;
		__u8  limited_retry;
		__u8  force_unit_access;
		__u8  show;
		__u8  dry_run;
		__u8  latency;
	};
	struct config cfg;

	const struct config defaults = {
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
		{"start-block",       "NUM",  CFG_LONG_SUFFIX, &defaults.start_block,       required_argument, start_block},
		{"s",                 "NUM",  CFG_LONG_SUFFIX, &defaults.start_block,       required_argument, start_block},
		{"block-count",       "NUM",  CFG_SHORT,       &defaults.block_count,       required_argument, block_count},
		{"c",                 "NUM",  CFG_SHORT,       &defaults.block_count,       required_argument, block_count},
		{"data-size",         "NUM",  CFG_LONG_SUFFIX, &defaults.data_size,         required_argument, data_size},
		{"z",                 "NUM",  CFG_LONG_SUFFIX, &defaults.data_size,         required_argument, data_size},
		{"metadata-size",     "NUM",  CFG_LONG_SUFFIX, &defaults.metadata_size,     required_argument, metadata_size},
		{"y",                 "NUM",  CFG_LONG_SUFFIX, &defaults.metadata_size,     required_argument, metadata_size},
		{"ref-tag",           "NUM",  CFG_POSITIVE,    &defaults.ref_tag,           required_argument, ref_tag},
		{"r",                 "NUM",  CFG_POSITIVE,    &defaults.ref_tag,           required_argument, ref_tag},
		{"data",              "FILE", CFG_STRING,      &defaults.data,              required_argument, data},
		{"d",                 "FILE", CFG_STRING,      &defaults.data,              required_argument, data},
		{"metadata",          "FILE", CFG_STRING,      &defaults.metadata,          required_argument, metadata},
		{"M",                 "FILE", CFG_STRING,      &defaults.metadata,          required_argument, metadata},
		{"prinfo",            "NUM",  CFG_BYTE,        &defaults.prinfo,            required_argument, prinfo},
		{"p",                 "NUM",  CFG_BYTE,        &defaults.prinfo,            required_argument, prinfo},
		{"app-tag-mask",      "NUM",  CFG_BYTE,        &defaults.app_tag_mask,      required_argument, app_tag_mask},
		{"m",                 "NUM",  CFG_BYTE,        &defaults.app_tag_mask,      required_argument, app_tag_mask},
		{"app-tag",           "NUM",  CFG_POSITIVE,    &defaults.app_tag,           required_argument, app_tag},
		{"a",                 "NUM",  CFG_POSITIVE,    &defaults.app_tag,           required_argument, app_tag},
		{"limited-retry",     "",     CFG_NONE,        &defaults.limited_retry,     no_argument,       limited_retry},
		{"l",                 "",     CFG_NONE,        &defaults.limited_retry,     no_argument,       limited_retry},
		{"force-unit-access", "",     CFG_NONE,        &defaults.force_unit_access, no_argument,       force},
		{"f",                 "",     CFG_NONE,        &defaults.force_unit_access, no_argument,       force},
		{"show-command",      "",     CFG_NONE,        &defaults.show,              no_argument,       show},
		{"v",                 "",     CFG_NONE,        &defaults.show,              no_argument,       show},
		{"dry-run",           "",     CFG_NONE,        &defaults.dry_run,           no_argument,       dry},
		{"w",                 "",     CFG_NONE,        &defaults.dry_run,           no_argument,       dry},
		{"latency",           "",     CFG_NONE,        &defaults.latency,           no_argument,       latency},
		{"t",                 "",     CFG_NONE,        &defaults.latency,           no_argument,       latency},
		{0}
	};

	dfd = mfd = opcode & 1 ? STDIN_FILENO : STDOUT_FILENO;
	argconfig_parse(argc, argv, desc, command_line_options,
			&defaults, &cfg, sizeof(cfg));

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
	get_dev(1, argc, argv);

	if (!cfg.data_size)	{
		fprintf(stderr, "data size not provided\n");
		return EINVAL;
	}

	buffer = malloc(cfg.data_size);
	if (!buffer)
		return ENOMEM;

	if (cfg.metadata_size) {
		mbuffer = malloc(cfg.metadata_size);
		if (!mbuffer)
			return ENOMEM;
	}

	if ((opcode & 1) && read(dfd, (void *)buffer, cfg.data_size) < 0) {
		fprintf(stderr, "failed to read data buffer from input file\n");
		free(buffer);
		return EINVAL;
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
		printf("metadata     : %"PRIx64"\n", (uint64_t)mbuffer);
		printf("addr         : %"PRIx64"\n", (uint64_t)buffer);
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
		fprintf(stdout, " latency: %s: %llu us\n",
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

static int compare(int argc, char **argv)
{
	const char *desc = "compare: diff specified logical blocks on "\
		"device with specified data buffer; return failure if buffer "\
		"and block(s) are dissimilar";
	return submit_io(nvme_cmd_compare, "compare", desc, argc, argv);
}

static int read_cmd(int argc, char **argv)
{
	const char *desc = "read: copy specified logical blocks on the given "\
		"device to specified data buffer (default buffer is stdout).";
	return submit_io(nvme_cmd_read, "read", desc, argc, argv);
}

static int write_cmd(int argc, char **argv)
{
	const char *desc = "write: copy from provided data buffer (default "\
		"buffer is stdin) to specified logical blocks on the given "\
		"device.";
	return submit_io(nvme_cmd_write, "write", desc, argc, argv);
}

static int sec_recv(int argc, char **argv)
{
	const char *desc = "security-recv: obtain results of one or more "\
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
	int err;
	void *sec_buf = NULL;
	__u32 result;

	struct config {
		__u32 size;
		__u8  secp;
		__u16 spsp;
		__u32 al;
		__u8  raw_binary;
	};
	struct config cfg;

	const struct config defaults = {
		.size = 0,
		.secp = 0,
		.spsp = 0,
		.al   = 0,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"size",       "NUM",  CFG_POSITIVE, &defaults.size,       required_argument, size},
		{"x",          "NUM",  CFG_POSITIVE, &defaults.size,       required_argument, size},
		{"secp",       "NUM",  CFG_BYTE,     &defaults.secp,       required_argument, secp},
		{"p",          "NUM",  CFG_BYTE,     &defaults.secp,       required_argument, secp},
		{"spsp",       "NUM",  CFG_SHORT,    &defaults.spsp,       required_argument, spsp},
		{"s",          "NUM",  CFG_SHORT,    &defaults.spsp,       required_argument, spsp},
		{"al",         "NUM",  CFG_POSITIVE, &defaults.al,         required_argument, al},
		{"t",          "NUM",  CFG_POSITIVE, &defaults.al,         required_argument, al},
		{"raw-binary", "",     CFG_NONE,     &defaults.raw_binary, no_argument,       raw_binary},
		{"b",          "",     CFG_NONE,     &defaults.raw_binary, no_argument,       raw_binary},
		{0}
	};

	argconfig_parse(argc, argv, desc, command_line_options,
			&defaults, &cfg, sizeof(cfg));

	get_dev(1, argc, argv);

	if (cfg.size) {
		if (posix_memalign(&sec_buf, getpagesize(), cfg.size)) {
			fprintf(stderr, "No memory for security size:%d\n",
								cfg.size);
			return ENOMEM;
		}
	}

	err = nvme_sec_recv(fd,
			0 /* FIXME: namespace_id */,
			0 /* FIXME: nssf */,
			cfg.spsp, cfg.secp, cfg.al, cfg.size, sec_buf, &result);
	if (err < 0)
		return errno;
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

static int passthru(int argc, char **argv, int ioctl_cmd)
{
	int err = 0, wfd = STDIN_FILENO;
	const char *desc = "[io/admin]-passthru: send a user-specified IO or "\
		"admin command to the specified device via IOCTL passthrough, "\
		"return results";
	void *data = NULL, *metadata = NULL;
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
		__u8  raw_binary;
		__u8  show_command;
		__u8  dry_run;
		__u8  read;
		__u8  write;
	};
	struct config cfg;

	const struct config defaults = {
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
	};

	const char *opcode = "hex opcode (required)";
	const char *flags = "command flags";
	const char *rsvd = "value for reserved field";
	const char *namespace_id = "desired namespace";
	const char *data_len = "data I/O length (bytes)";
	const char *metadata_len = "metadata seg. length (bytes)";
	const char *timeout = "timeout value";
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

	const struct argconfig_commandline_options command_line_options[] = {
		{"opcode",       "NUM",  CFG_BYTE,     &defaults.opcode,       required_argument, opcode},
		{"o",            "NUM",  CFG_BYTE,     &defaults.opcode,       required_argument, opcode},
		{"flags",        "NUM",  CFG_BYTE,     &defaults.flags,        required_argument, flags},
		{"f",            "NUM",  CFG_BYTE,     &defaults.flags,        required_argument, flags},
		{"rsvd",         "NUM",  CFG_SHORT,    &defaults.rsvd,         required_argument, rsvd},
		{"R",            "NUM",  CFG_SHORT,    &defaults.rsvd,         required_argument, rsvd},
		{"namespace-id", "NUM",  CFG_POSITIVE, &defaults.namespace_id, required_argument, namespace_id},
		{"n",            "NUM",  CFG_POSITIVE, &defaults.namespace_id, required_argument, namespace_id},
		{"data-len",     "NUM",  CFG_POSITIVE, &defaults.data_len,     required_argument, data_len},
		{"l",            "NUM",  CFG_POSITIVE, &defaults.data_len,     required_argument, data_len},
		{"metadata-len", "NUM",  CFG_POSITIVE, &defaults.metadata_len, required_argument, metadata_len},
		{"m",            "NUM",  CFG_POSITIVE, &defaults.metadata_len, required_argument, metadata_len},
		{"timeout",      "NUM",  CFG_POSITIVE, &defaults.timeout,      required_argument, timeout},
		{"t",            "NUM",  CFG_POSITIVE, &defaults.timeout,      required_argument, timeout},
		{"cdw2",         "NUM",  CFG_POSITIVE, &defaults.cdw2,         required_argument, cdw2},
		{"2",            "NUM",  CFG_POSITIVE, &defaults.cdw2,         required_argument, cdw2},
		{"cdw3",         "NUM",  CFG_POSITIVE, &defaults.cdw3,         required_argument, cdw3},
		{"3",            "NUM",  CFG_POSITIVE, &defaults.cdw3,         required_argument, cdw3},
		{"cdw10",        "NUM",  CFG_POSITIVE, &defaults.cdw10,        required_argument, cdw10},
		{"4",            "NUM",  CFG_POSITIVE, &defaults.cdw10,        required_argument, cdw10},
		{"cdw11",        "NUM",  CFG_POSITIVE, &defaults.cdw11,        required_argument, cdw11},
		{"5",            "NUM",  CFG_POSITIVE, &defaults.cdw11,        required_argument, cdw11},
		{"cdw12",        "NUM",  CFG_POSITIVE, &defaults.cdw12,        required_argument, cdw12},
		{"6",            "NUM",  CFG_POSITIVE, &defaults.cdw12,        required_argument, cdw12},
		{"cdw13",        "NUM",  CFG_POSITIVE, &defaults.cdw13,        required_argument, cdw13},
		{"7",            "NUM",  CFG_POSITIVE, &defaults.cdw13,        required_argument, cdw13},
		{"cdw14",        "NUM",  CFG_POSITIVE, &defaults.cdw14,        required_argument, cdw14},
		{"8",            "NUM",  CFG_POSITIVE, &defaults.cdw14,        required_argument, cdw14},
		{"cdw15",        "NUM",  CFG_POSITIVE, &defaults.cdw15,        required_argument, cdw15},
		{"9",            "NUM",  CFG_POSITIVE, &defaults.cdw15,        required_argument, cdw15},
		{"input-file",   "FILE", CFG_STRING,   &defaults.input_file,   required_argument, input},
		{"i",            "FILE", CFG_STRING,   &defaults.input_file,   required_argument, input},
		{"raw-binary",   "",     CFG_NONE,     &defaults.raw_binary,   no_argument,       raw_binary},
		{"b",            "",     CFG_NONE,     &defaults.raw_binary,   no_argument,       raw_binary},
		{"show-command", "",     CFG_NONE,     &defaults.show_command, no_argument,       show},
		{"s",            "",     CFG_NONE,     &defaults.show_command, no_argument,       show},
		{"dry-run",      "",     CFG_NONE,     &defaults.dry_run,      no_argument,       dry},
		{"d",            "",     CFG_NONE,     &defaults.dry_run,      no_argument,       dry},
		{"read",         "",     CFG_NONE,     &defaults.read,         no_argument,       re},
		{"r",            "",     CFG_NONE,     &defaults.read,         no_argument,       re},
		{"write",        "",     CFG_NONE,     &defaults.write,        no_argument,       wr},
		{"w",            "",     CFG_NONE,     &defaults.write,        no_argument,       wr},
		{0}
	};

	argconfig_parse(argc, argv, desc, command_line_options,
			&defaults, &cfg, sizeof(cfg));

	if (strlen(cfg.input_file)){
		wfd = open(cfg.input_file, O_RDONLY,
			   S_IRUSR | S_IRGRP | S_IROTH);
		if (wfd < 0) {
			perror(cfg.input_file);
			return EINVAL;
		}
	}

	get_dev(1, argc, argv);
	if (cfg.metadata_len)
		metadata = malloc(cfg.metadata_len);
	if (cfg.data_len) {
		data = malloc(cfg.data_len);
		if (!cfg.read && !cfg.write) {
			fprintf(stderr, "data direction not given\n");
			err = EINVAL;
			goto free_and_return;
		}
		if (cfg.read && cfg.write) {
			fprintf(stderr, "command can't be both read and write\n");
			err = EINVAL;
			goto free_and_return;
		}
		if (cfg.write) {
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
		printf("addr         : %"PRIx64"\n", (uint64_t)data);
		printf("metadata     : %"PRIx64"\n", (uint64_t)metadata);
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
		printf("NVMe Status:%s Command Result:%08x\n",
				nvme_status_to_string(err), result);
	else  {
		if (!cfg.raw_binary) {
			printf("NVMe command result:%08x\n", result);
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

static int io_passthru(int argc, char **argv)
{
	return passthru(argc, argv, NVME_IOCTL_IO_CMD);
}

static int admin_passthru(int argc, char **argv)
{
	return passthru(argc, argv, NVME_IOCTL_ADMIN_CMD);
}

static void usage(char *cmd)
{
	fprintf(stdout, "usage: %s <command> [<device>] [<args>]\n", cmd);
}

static void command_help(const char *cmd)
{
	unsigned i;
	struct command *c;

	for (i = 0; i < NUM_COMMANDS; i++) {
		c = &commands[i];
		if (strcmp(c->name, cmd))
			continue;
		exit(execlp("man", "man", c->man, (char *)NULL));
	}
	fprintf(stderr, "No entry for nvme sub-command %s\n", cmd);
}

static void general_help()
{
	unsigned i;

	printf("%s\n", nvme_version_string);
	usage("nvme");
	printf("\n");
	printf("'<device>' / '/dev/nvmeX' may be either an NVMe character "\
	       "device (ex: /dev/nvme0)\n or an nvme block device (ex: /d"\
	       "ev/nvme0n1)\n\n");
	printf("The following are all implemented sub-commands:\n");
	for (i = 0; i < NUM_COMMANDS; i++)
		printf("  %-*s %s\n", 15, commands[i].name, commands[i].help);
	printf("\n");
	printf("See 'nvme help <command>' for more information on a specific command.\n");
}

static int version(int argc, char **argv)
{
	printf("nvme version %s\n", nvme_version_string);
	return 0;
}

static int help(int argc, char **argv)
{
	if (argc == 1)
		general_help();
	else
		command_help(argv[1]);
	return 0;
}

static void handle_internal_command(int argc, char **argv)
{
	unsigned i;
	struct command *cmd;
	char *str = argv[0];

	/* translate --help and --version into commands */
	while (*str == '-')
		str++;

	for (i = 0; i < NUM_COMMANDS; i++) {
		cmd = &commands[i];
		if (strcmp(str, cmd->name))
			continue;
		exit(cmd->fn(argc, argv));
	}
	fprintf(stderr, "unknown command '%s'\n", argv[0]);
	help(1, NULL);
	exit(1);
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		usage(argv[0]);
		return 0;
	}
	setlocale(LC_ALL, "");
	handle_internal_command(argc - 1, &argv[1]);
	return 0;
}
