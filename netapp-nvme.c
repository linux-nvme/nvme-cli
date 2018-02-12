/*
* Copyright (c) 2018 NetApp, Inc.
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
*/

#include <stdio.h>
#include <dirent.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "nvme.h"
#include "nvme-ioctl.h"
#include "json.h"

#include "suffix.h"

#define CREATE_CMD
#include "netapp-nvme.h"

enum {
	NNORMAL,
	NJSON,
	NCOLUMN,
};

static const char *dev_path = "/dev/";

struct smdevice_info {
	int			nsid;
	struct nvme_id_ctrl	ctrl;
	struct nvme_id_ns	ns;
	char			dev[265];
};

#define ARRAY_LABEL_LEN		60
#define VOLUME_LABEL_LEN	60

/*
 * Format of the string isn't tightly controlled yet. For now, squash UCS-2 into
 * ASCII. dst buffer must be at least count + 1 bytes long
 */
static void netapp_convert_string(char *dst, char *src, unsigned int count)
{
	int i;

	if (!dst || !src || !count)
		return;

	memset(dst, 0, count + 1);
	for (i = 0; i < count; i++)
		dst[i] = src[i * 2 + 1];
}

static void netapp_nguid_to_str(char *str, __u8 *nguid)
{
	int i;

	memset(str, 0, 33);
	for (i = 0; i < 16; i++)
		str += sprintf(str, "%02x", nguid[i]);
}

static void netapp_smdevice_json(struct json_array *devices, char *devname,
		char *arrayname, char *volname, int nsid, char *nguid,
		char *ctrl, char *astate, char *size, long long lba,
		long long nsze)
{
	struct json_object *device_attrs;

	device_attrs = json_create_object();
	json_object_add_value_string(device_attrs, "Device", devname);
	json_object_add_value_string(device_attrs, "Array_Name", arrayname);
	json_object_add_value_string(device_attrs, "Volume_Name", volname);
	json_object_add_value_int(device_attrs, "NSID", nsid);
	json_object_add_value_string(device_attrs, "Volume_ID", nguid);
	json_object_add_value_string(device_attrs, "Controller", ctrl);
	json_object_add_value_string(device_attrs, "Access_State", astate);
	json_object_add_value_string(device_attrs, "Size", size);
	json_object_add_value_int(device_attrs, "LBA_Data_Size", lba);
	json_object_add_value_int(device_attrs, "Namespace_Size", nsze);

	json_array_add_value_object(devices, device_attrs);
}

static void netapp_smdevices_print(struct smdevice_info *devices, int count, int format)
{
	struct json_object *root = NULL;
	struct json_array *json_devices = NULL;
	int i, slta;
	char array_label[ARRAY_LABEL_LEN / 2 + 1];
	char volume_label[VOLUME_LABEL_LEN / 2 + 1];
	char nguid_str[33];
	char basestr[] = "%s, Array Name %s, Volume Name %s, NSID %d, "
			"Volume ID %s, Controller %c, Access State %s, %s\n";
	char columnstr[] = "%-16s %-30s %-30s %4d %32s  %c   %-12s %9s\n";
	char *formatstr = basestr; // default to "normal" output format

	if (format == NCOLUMN) {
		/* for column output, change output string and print column headers */
		formatstr = columnstr;
		printf("%-16s %-30s %-30s %-4s %-32s %-4s %-12s %-9s\n",
			"Device", "Array Name", "Volume Name", "NSID",
			"Volume ID", "Ctrl", "Access State", " Size");
		printf("%-16s %-30s %-30s %-4s %-32s %-4s %-12s %-9s\n",
			"----------------", "------------------------------",
			"------------------------------", "----",
			"--------------------------------", "----",
			"------------", "---------");
	}
	else if (format == NJSON) {
		/* prepare for json output */
		root = json_create_object();
		json_devices = json_create_array();
	}

	for (i = 0; i < count; i++) {
		long long int lba = 1 << devices[i].ns.lbaf[(devices[i].ns.flbas & 0x0F)].ds;
		double nsze = le64_to_cpu(devices[i].ns.nsze) * lba;
		const char *s_suffix = suffix_si_get(&nsze);
		char size[128];

		sprintf(size, "%.2f%sB", nsze, s_suffix);
		netapp_convert_string(array_label, (char *)&devices[i].ctrl.vs[20],
					ARRAY_LABEL_LEN / 2);
		slta = devices[i].ctrl.vs[0] & 0x1;
		netapp_convert_string(volume_label, (char *)devices[i].ns.vs,
					VOLUME_LABEL_LEN / 2);
		netapp_nguid_to_str(nguid_str, devices[i].ns.nguid);
		if (format == NJSON)
			netapp_smdevice_json(json_devices, devices[i].dev,
				array_label, volume_label, devices[i].nsid,
				nguid_str, slta ? "A" : "B", "unknown", size,
				lba, le64_to_cpu(devices[i].ns.nsze));
		else
			printf(formatstr, devices[i].dev, array_label,
				volume_label, devices[i].nsid, nguid_str,
				slta ? 'A' : 'B', "unknown", size);
	}

	if (format == NJSON) {
		/* complete the json output */
		json_object_add_value_array(root, "SMdevices", json_devices);
		json_print_object(root, NULL);
	}
}

static int netapp_smdevices_get_info(int fd, struct smdevice_info *item,
				     const char *dev)
{
	int err;

	err = nvme_identify_ctrl(fd, &item->ctrl);
	if (err) {
		fprintf(stderr, "Identify Controler failed to %s (%s)\n", dev,
			strerror(err));
		return 0;
	}

	if (strncmp("NetApp E-Series", item->ctrl.mn, 15) != 0)
		return 0; // not the right model of controller

	item->nsid = nvme_get_nsid(fd);
	err = nvme_identify_ns(fd, item->nsid, 0, &item->ns);
	if (err) {
		fprintf(stderr, "Unable to identify namespace for %s (%s)\n",
			dev, strerror(err));
		return 0;
	}
	strncpy(item->dev, dev, sizeof(item->dev));

	return 1;
}

static int netapp_nvme_filter(const struct dirent *d)
{
	char path[264];
	struct stat bd;
	int ctrl, ns, partition;

	if (d->d_name[0] == '.')
		return 0;

	if (strstr(d->d_name, "nvme")) {
		snprintf(path, sizeof(path), "%s%s", dev_path, d->d_name);
		if (stat(path, &bd))
			return 0;
		if (!S_ISBLK(bd.st_mode))
			return 0;
		if (sscanf(d->d_name, "nvme%dn%d", &ctrl, &ns) != 2)
			return 0;
		if (sscanf(d->d_name, "nvme%dn%dp%d", &ctrl, &ns, &partition) == 3)
			return 0;
		return 1;
	}
	return 0;
}

static int netapp_output_format(char *format)
{
	if (!format)
		return -EINVAL;
	if (!strcmp(format, "normal"))
		return NNORMAL;
	if (!strcmp(format, "json"))
		return NJSON;
	if (!strcmp(format, "column"))
		return NCOLUMN;
	return -EINVAL;
}

/* handler for 'nvme netapp smdevices' */
static int netapp_smdevices(int argc, char **argv, struct command *command,
		struct plugin *plugin)
{
	const char *desc = "Display information about E-Series volumes.";
	struct config {
		char *output_format;
	};
	struct config cfg = {
		.output_format = "normal",
	};
	struct dirent **devices;
	int num, i, fd, ret, fmt;
	struct smdevice_info *smdevices;
	char path[264];
	int num_smdevices = 0;

	const struct argconfig_commandline_options opts[] = {
		{"output-format", 'o', "FMT", CFG_STRING, &cfg.output_format,
			required_argument, "Output Format: normal|json|column"},
		{NULL}
	};

	ret = argconfig_parse(argc, argv, desc, opts, &cfg, sizeof(cfg));
	if (ret < 0)
		return ret;

	fmt = netapp_output_format(cfg.output_format);
	if (fmt != NNORMAL && fmt != NCOLUMN && fmt != NJSON) {
		fprintf(stderr, "Unrecognized output format: %s\n", cfg.output_format);
		return -EINVAL;
	}

	num = scandir(dev_path, &devices, netapp_nvme_filter, alphasort);
	if (num <= 0) {
		fprintf(stderr, "No NVMe devices detected.\n");
		return num;
	}

	smdevices = calloc(num, sizeof(*smdevices));
	if (!smdevices) {
		fprintf(stderr, "Unable to allocate memory for devices.\n");
		return ENOMEM;
	}

	for (i = 0; i < num; i++) {
		snprintf(path, sizeof(path), "%s%s", dev_path,
			devices[i]->d_name);
		fd = open(path, O_RDONLY);
		if (fd < 0) {
			fprintf(stderr, "Unable to open %s: %s\n", path,
				strerror(errno));
			continue;
		}

		num_smdevices += netapp_smdevices_get_info(fd,
						&smdevices[num_smdevices], path);
		close(fd);
	}

	if (num_smdevices)
		netapp_smdevices_print(smdevices, num_smdevices, fmt);

	for (i = 0; i < num; i++)
		free(devices[i]);
	free(devices);
	free(smdevices);
	return 0;
}
