/*
 * Copyright (c) 2017 Eideticom Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA  02110-1301, USA.
 *
 *   Author: Stephen Bates <sbates@raithlin.com>
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include "linux/nvme_ioctl.h"

#include "nvme.h"
#include "nvme-print.h"
#include "nvme-ioctl.h"
#include "plugin.h"
#include "json.h"

#include "argconfig.h"
#include "suffix.h"
#include <sys/ioctl.h>
#define CREATE_CMD
#include "eid-nvme.h"

static const char *dev = "/dev/";

struct eid_noload {
	__le32           acc_status;
	char             hls[12];
	char             acc_name[64];
	__le32           acc_ver;
	char             acc_cfg[24];
	__le32           acc_priv_len;
	char             acc_priv[3600];
};

static unsigned eid_check_item(struct list_item *item)
{
	if (strstr(item->ctrl.mn, "Eideticom") == NULL)
		return 0;

	return 1;
}

static void eid_print_list_item(struct list_item list_item)
{
	struct eid_noload *eid =
		(struct eid_noload *) &list_item.ns.vs;
	
	printf("%-16s %-64.64s %-8.8u 0x%-8.8x\n", list_item.node,
	       eid->acc_name, (unsigned int) eid->acc_ver,
	       (unsigned int) eid->acc_status);
}

static void eid_print_list_items(struct list_item *list_items, unsigned len)
{
	unsigned i;

	printf("%-16s %-64s %-8s %-10s\n",
	       "Node", "Accelerator Name", "Version", "Status");
	printf("%-16s %-64s %-8s %-10s\n",
	       "----------------",
	       "----------------------------------------------------------------",
	       "--------", "----------");
	for (i = 0 ; i < len ; i++)
		eid_print_list_item(list_items[i]);
}

static void eid_show_nvme_id_ns(struct nvme_id_ns *ns)
{
	struct eid_noload *eid =
		(struct eid_noload *) &ns->vs;

	printf("acc_status : 0x%-8.8x\n", eid->acc_status);
	printf("acc_name   : %s\n", eid->acc_name);
//	char             hls[12];
//	char             acc_name[64];
//	__le32           acc_ver;
//	char             acc_cfg[24];
//	__le32           acc_priv_len;

}


/*
 * List all the Eideticom namespaces in the system and identify the
 * accerlation functio provided by that namespace. We base this off
 * the Huawei code. Ideally we'd refactor this a bit. That is a TBD. 
 */

static int eid_list(int argc, char **argv, struct command *command,
		    struct plugin *plugin)
{
	char path[264];
	struct dirent **devices;
	struct list_item *list_items;
	unsigned int i, n, fd, ret, eid_num;
	int fmt;
	
	const char *desc = "Retrieve basic information for any Eideticom " \
		"namespaces in the systrem";
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

	if (fmt == JSON) {
		fprintf(stderr, "json not yet supported for eid_list\n");
		return -EINVAL;
	}

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

	eid_num = 0;
	for (i = 0; i < n; i++) {
		snprintf(path, sizeof(path), "%s%s", dev, devices[i]->d_name);
		fd = open(path, O_RDONLY);
		ret = get_nvme_info(fd, &list_items[eid_num], path);
		if (ret)
			return ret;
		if (eid_check_item(&list_items[eid_num]))
			eid_num++;
	}

	if (eid_num > 0)
		eid_print_list_items(list_items, eid_num);

	for (i = 0; i < n; i++)
		free(devices[i]);
	free(devices);
	free(list_items);

	return 0;
}

static int eid_id_ns(int argc, char **argv, struct command *command,
		     struct plugin *plugin)
{
	const char *desc = "Send an Identify Namespace command to the "\
		"given device, returns properties of the specified namespace "\
		"in human-readable format. Fails on non-Eideticom namespaces";
	const char *namespace_id = "identifier of desired namespace";
	struct nvme_id_ns ns;
	struct stat nvme_stat;

	int err, fd;

	struct config {
		__u32 namespace_id;
	};

	struct config cfg = {
		.namespace_id    = 0,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id",    'n', "NUM", CFG_POSITIVE, &cfg.namespace_id,    required_argument, namespace_id},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0)
		return fd;

	err = fstat(fd, &nvme_stat);
	if (err < 0)
		return err;

	if (!cfg.namespace_id && S_ISBLK(nvme_stat.st_mode))
		cfg.namespace_id = nvme_get_nsid(fd);
	else if(!cfg.namespace_id)
		fprintf(stderr,
			"Error: requesting namespace-id from non-block device\n");

	err = nvme_identify_ns(fd, cfg.namespace_id, 0, &ns);
	if (!err) {
		printf("NVME Identify Namespace %d:\n", cfg.namespace_id);
		eid_show_nvme_id_ns(&ns);
	}
	else if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x) NSID:%d\n",
			nvme_status_to_string(err), err, cfg.namespace_id);
	else
		perror("identify namespace");
	return err;
}
