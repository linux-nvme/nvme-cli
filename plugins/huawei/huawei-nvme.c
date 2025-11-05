// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2017-2019 Huawei Corporation or its affiliates.
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
 *   Author:  Zou Ming<zouming.zouming@huawei.com>,
 *				Yang Feng <philip.yang@huawei.com>
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>

#include <sys/stat.h>

#include "common.h"
#include "nvme.h"
#include "libnvme.h"
#include "plugin.h"

#include "util/suffix.h"

#define CREATE_CMD
#include "huawei-nvme.h"

#define HW_SSD_PCI_VENDOR_ID 0x19E5
#define ARRAY_NAME_LEN 80
#define NS_NAME_LEN    40

#define MIN_ARRAY_NAME_LEN 16
#define MIN_NS_NAME_LEN 16

struct huawei_list_item {
	char                node[1024];
	struct nvme_id_ctrl ctrl;
	unsigned int        nsid;
	struct nvme_id_ns   ns;
	unsigned int        block;
	char                ns_name[NS_NAME_LEN];
	char                array_name[ARRAY_NAME_LEN];
	bool                huawei_device;
};

struct huawei_list_element_len {
	unsigned int node;
	unsigned int ns_name;
	unsigned int nguid;
	unsigned int ns_id;
	unsigned int usage;
	unsigned int array_name;
};

static int huawei_get_nvme_info(struct nvme_transport_handle *hdl,
				struct huawei_list_item *item, const char *node)
{
	int err;
	int len;
	struct stat nvme_stat_info;

	memset(item, 0, sizeof(*item));

	err = nvme_identify_ctrl(hdl, &item->ctrl);
	if (err)
		return err;

	/*identify huawei device*/
	if (strstr(item->ctrl.mn, "Huawei") == NULL &&
	    le16_to_cpu(item->ctrl.vid) != HW_SSD_PCI_VENDOR_ID) {
		item->huawei_device = false;
		return 0;
	}

	item->huawei_device = true;
	err = nvme_get_nsid(hdl, &item->nsid);
	err = nvme_identify_ns(hdl, item->nsid, &item->ns);
	if (err)
		return err;

	err = fstat(nvme_transport_handle_get_fd(hdl), &nvme_stat_info);
	if (err < 0)
		return err;

	strncpy(item->node, node, sizeof(item->node));
	item->node[sizeof(item->node) - 1] = '\0';
	item->block = S_ISBLK(nvme_stat_info.st_mode);

	if (item->ns.vs[0] == 0) {
		len = snprintf(item->ns_name, NS_NAME_LEN, "%s", "----");
		if (len < 0)
			return -EINVAL;
	} else {
		memcpy(item->ns_name, item->ns.vs, NS_NAME_LEN);
		item->ns_name[NS_NAME_LEN - 1] = '\0';
	}

	if (item->ctrl.vs[0] == 0) {
		len = snprintf(item->array_name, ARRAY_NAME_LEN, "%s", "----");
		if (len < 0)
			return -EINVAL;
	} else {
		memcpy(item->array_name, item->ctrl.vs, ARRAY_NAME_LEN);
		item->array_name[ARRAY_NAME_LEN - 1] = '\0';
	}
	return 0;
}

#ifdef CONFIG_JSONC
static void format(char *formatter, size_t fmt_sz, char *tofmt, size_t tofmtsz)
{
	fmt_sz = snprintf(formatter, fmt_sz, "%-*.*s", (int)tofmtsz, (int)tofmtsz, tofmt);

	/* trim() the obnoxious trailing white lines */
	while (fmt_sz) {
		if (formatter[fmt_sz - 1] != ' ' && formatter[fmt_sz - 1] != '\0') {
			formatter[fmt_sz] = '\0';
			break;
		}
		fmt_sz--;
	}
}

static void huawei_json_print_list_items(struct huawei_list_item *list_items,
					 unsigned int len)
{
	struct json_object *root;
	struct json_object *devices;
	struct json_object *device_attrs;
	char formatter[128] = { 0 };
	int index, i = 0;

	root = json_create_object();
	devices = json_create_array();
	for (i = 0; i < len; i++) {
		device_attrs = json_create_object();

		json_object_add_value_string(device_attrs,
						 "DevicePath",
						 list_items[i].node);

		if (sscanf(list_items[i].node, "/dev/nvme%d", &index) == 1)
			json_object_add_value_int(device_attrs,
						  "Index",
						  index);

		format(formatter, sizeof(formatter),
		       list_items[i].ns_name,
		       sizeof(list_items[i].ns_name));

		json_object_add_value_string(device_attrs,
						 "NS Name",
						 formatter);

		format(formatter, sizeof(formatter),
		       list_items[i].array_name,
		       sizeof(list_items[i].array_name));

		json_object_add_value_string(device_attrs,
					     "Array Name",
					     formatter);

		json_array_add_value_object(devices, device_attrs);
	}
	json_object_add_value_array(root, "Devices", devices);
	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}
#endif /* CONFIG_JSONC */

static void huawei_print_list_head(struct huawei_list_element_len element_len)
{
	char dash[128];
	int i;

	for (i = 0; i < 128; i++)
		dash[i] = '-';
	dash[127] = '\0';

	printf("%-*.*s %-*.*s %-*.*s %-*.*s %-*.*s %-*.*s\n",
		element_len.node, element_len.node, "Node",
		element_len.ns_name, element_len.ns_name, "NS Name",
		element_len.nguid, element_len.nguid, "Nguid",
		element_len.ns_id, element_len.ns_id, "NS ID",
		element_len.usage, element_len.usage, "Usage",
		element_len.array_name, element_len.array_name, "Array Name");

	printf("%-.*s %-.*s %-.*s %-.*s %-.*s %-.*s\n",
		element_len.node, dash, element_len.ns_name, dash,
		element_len.nguid, dash, element_len.ns_id, dash,
		element_len.usage, dash, element_len.array_name, dash);
}

static void huawei_print_list_item(struct huawei_list_item *list_item,
				   struct huawei_list_element_len element_len)
{
	__u8 lba_index;

	nvme_id_ns_flbas_to_lbaf_inuse(list_item->ns.flbas, &lba_index);
	unsigned long long lba = 1ULL << list_item->ns.lbaf[lba_index].ds;
	double nsze       = le64_to_cpu(list_item->ns.nsze) * lba;
	double nuse       = le64_to_cpu(list_item->ns.nuse) * lba;

	const char *s_suffix = suffix_si_get(&nsze);
	const char *u_suffix = suffix_si_get(&nuse);

	char usage[128];
	char nguid_buf[2 * sizeof(list_item->ns.nguid) + 1];
	char *nguid = nguid_buf;
	int i;

	sprintf(usage, "%6.2f %2sB / %6.2f %2sB", nuse, u_suffix, nsze, s_suffix);

	memset(nguid, 0, sizeof(nguid_buf));
	for (i = 0; i < sizeof(list_item->ns.nguid); i++)
		nguid += sprintf(nguid, "%02x", list_item->ns.nguid[i]);

	printf("%-*.*s %-*.*s %-*.*s %-*d %-*.*s %-*.*s\n",
		element_len.node, element_len.node, list_item->node,
		element_len.ns_name, element_len.ns_name, list_item->ns_name,
		element_len.nguid, element_len.nguid, nguid_buf,
		element_len.ns_id, list_item->nsid,
		element_len.usage, element_len.usage, usage,
		element_len.array_name, element_len.array_name,
		list_item->array_name);

}

static unsigned int choose_len(unsigned int old_len, unsigned int cur_len, unsigned int default_len)
{
	unsigned int temp_len;

	temp_len = (cur_len > default_len) ? cur_len : default_len;
	if (temp_len > old_len)
		return temp_len;
	return old_len;
}

static unsigned int huawei_get_ns_len(struct huawei_list_item *list_items, unsigned int len,
				      unsigned int default_len)
{
	int i;
	unsigned int min_len = default_len;

	for (i = 0 ; i < len ; i++)
		min_len = choose_len(min_len, strlen(list_items->ns_name), default_len);

	return min_len;
}

static int huawei_get_array_len(struct huawei_list_item *list_items, unsigned int len,
				unsigned int default_len)
{
	int i;
	int min_len = default_len;

	for (i = 0 ; i < len ; i++)
		min_len = choose_len(min_len, strlen(list_items->array_name), default_len);

	return min_len;
}

static void huawei_print_list_items(struct huawei_list_item *list_items, unsigned int len)
{
	unsigned int i;
	struct huawei_list_element_len element_len;

	element_len.node = 16;
	element_len.nguid = 2 * sizeof(list_items->ns.nguid) + 1;
	element_len.ns_id = 9;
	element_len.usage = 26;
	element_len.ns_name = huawei_get_ns_len(list_items, len, MIN_NS_NAME_LEN);
	element_len.array_name = huawei_get_array_len(list_items, len, MIN_ARRAY_NAME_LEN);

	huawei_print_list_head(element_len);

	for (i = 0 ; i < len ; i++)
		huawei_print_list_item(&list_items[i], element_len);
}

static int huawei_list(int argc, char **argv, struct command *command,
		       struct plugin *plugin)
{
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx =
		nvme_create_global_ctx(stdout, DEFAULT_LOGLEVEL);
	char path[264];
	struct dirent **devices;
	struct huawei_list_item *list_items;
	unsigned int i, n, ret;
	unsigned int huawei_num = 0;
	nvme_print_flags_t fmt;
	const char *desc = "Retrieve basic information for the given huawei device";
	struct config {
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format, "Output Format: normal|json"),
		OPT_END()
	};

	if (!ctx)
		return -ENOMEM;

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret)
		return ret;

	ret = validate_output_format(cfg.output_format, &fmt);
	if (ret < 0 || (fmt != JSON && fmt != NORMAL))
		return ret;

	n = scandir("/dev", &devices, nvme_namespace_filter, alphasort);
	if (n <= 0)
		return n;

	list_items = calloc(n, sizeof(*list_items));
	if (!list_items) {
		fprintf(stderr, "can not allocate controller list payload\n");
		ret = ENOMEM;
		goto out_free_devices;
	}

	for (i = 0; i < n; i++) {
		_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;

		snprintf(path, sizeof(path), "/dev/%s", devices[i]->d_name);
		ret = nvme_open(ctx, path, &hdl);
		if (ret) {
			fprintf(stderr, "Cannot open device %s: %s\n",
				path, strerror(-ret));
			continue;
		}
		ret = huawei_get_nvme_info(hdl, &list_items[huawei_num], path);
		if (ret)
			goto out_free_list_items;

		if (list_items[huawei_num].huawei_device == true)
			huawei_num++;
	}

	if (huawei_num > 0) {
#ifdef CONFIG_JSONC
		if (fmt == JSON)
			huawei_json_print_list_items(list_items, huawei_num);
		else
#endif /* CONFIG_JSONC */
			huawei_print_list_items(list_items, huawei_num);
	}
out_free_list_items:
	free(list_items);
out_free_devices:
	for (i = 0; i < n; i++)
		free(devices[i]);
	free(devices);

	return ret;
}

static void huawei_do_id_ctrl(__u8 *vs, struct json_object *root)
{
	char array_name[ARRAY_NAME_LEN + 1] = {0};

	memcpy(array_name, vs, ARRAY_NAME_LEN);
	if (root)
		json_object_add_value_string(root, "array name", strlen(array_name) > 1 ? array_name : "NULL");
	else
		printf("array name : %s\n", strlen(array_name) > 1 ? array_name : "NULL");
}

static int huawei_id_ctrl(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	return __id_ctrl(argc, argv, cmd, plugin, huawei_do_id_ctrl);
}
