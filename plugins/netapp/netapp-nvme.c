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
#include <sys/ioctl.h>

#include "nvme.h"
#include "nvme-ioctl.h"

#include "suffix.h"

#define CREATE_CMD
#include "netapp-nvme.h"

#define ONTAP_C2_LOG_ID		0xC2
#define ONTAP_C2_LOG_SIZE	4096
#define ONTAP_LABEL_LEN		260
#define ONTAP_NS_PATHLEN	525

enum {
	NNORMAL,
	NJSON,
	NCOLUMN,
};

enum {
	ONTAP_C2_LOG_SUPPORTED_LSP	= 0x0,
	ONTAP_C2_LOG_NSINFO_LSP		= 0x1,
};

enum {
	ONTAP_VSERVER_TLV		= 0x11,
	ONTAP_VOLUME_TLV		= 0x12,
	ONTAP_NS_TLV			= 0x13,
};

static const char *dev_path = "/dev/";

struct smdevice_info {
	int			nsid;
	struct nvme_id_ctrl	ctrl;
	struct nvme_id_ns	ns;
	char			dev[265];
};

struct ontapdevice_info {
	int			nsid;
	struct nvme_id_ctrl	ctrl;
	struct nvme_id_ns	ns;
	char			nsdesc[4096];
	unsigned char		log_data[ONTAP_C2_LOG_SIZE];
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
	/* the json routines won't accept empty strings */
	if (strlen(dst) == 0 && count)
		dst[0] = ' ';
}

static void netapp_nguid_to_str(char *str, __u8 *nguid)
{
	int i;

	memset(str, 0, 33);
	for (i = 0; i < 16; i++)
		str += sprintf(str, "%02x", nguid[i]);
}

static void netapp_get_ns_size(char *size, long long *lba,
		struct nvme_id_ns *ns)
{
	*lba = 1 << ns->lbaf[(ns->flbas & 0x0F)].ds;
	double nsze = le64_to_cpu(ns->nsze) * (*lba);
	const char *s_suffix = suffix_si_get(&nsze);

	sprintf(size, "%.2f%sB", nsze, s_suffix);
}

static void netapp_uuid_to_str(char *str, void *data)
{
#ifdef LIBUUID
	uuid_t uuid;
	struct nvme_ns_id_desc *desc = data;

	memcpy(uuid, data + sizeof(*desc), 16);
	uuid_unparse_lower(uuid, str);
#endif
}

static void ontap_labels_to_str(char *dst, char *src, int count)
{
	int i;

	memset(dst, 0, ONTAP_LABEL_LEN);
	for (i = 0; i < count; i++) {
		if (src[i] >= '!' && src[i] <= '~')
			dst[i] = src[i];
		else
			break;
	}
	dst[i] = '\0';
}

static void netapp_get_ontap_labels(char *vsname, char *nspath,
		unsigned char *log_data)
{
	int lsp, tlv, label_len;
	char *vserver_name, *volume_name, *namespace_name;
	char vol_name[ONTAP_LABEL_LEN], ns_name[ONTAP_LABEL_LEN];
	const char *ontap_vol = "/vol/";
	int i, j;

	/* get the lsp */
	lsp = (*(__u8 *)&log_data[16]) & 0x0F;
	if (lsp != ONTAP_C2_LOG_NSINFO_LSP)
		/* lsp not related to nsinfo */
		return;

	/* get the vserver tlv and name */
	tlv = *(__u8 *)&log_data[32];
	if (tlv == ONTAP_VSERVER_TLV) {
		label_len = (*(__u16 *)&log_data[34]) * 4;
		vserver_name = (char *)&log_data[36];
		ontap_labels_to_str(vsname, vserver_name, label_len);
	} else {
		/* not the expected vserver tlv */
		fprintf(stderr, "Unable to fetch ONTAP vserver name\n");
		return;
	}

	i = 36 + label_len;
	j = i + 2;
	/* get the volume tlv and name */
	tlv = *(__u8 *)&log_data[i];
	if (tlv == ONTAP_VOLUME_TLV) {
		label_len = (*(__u16 *)&log_data[j]) * 4;
		volume_name = (char *)&log_data[j + 2];
		ontap_labels_to_str(vol_name, volume_name, label_len);
	} else {
		/* not the expected volume tlv */
		fprintf(stderr, "Unable to fetch ONTAP volume name\n");
		return;
	}

	i += 4 + label_len;
	j += 4 + label_len;
	/* get the namespace tlv and name */
	tlv = *(__u8 *)&log_data[i];
	if (tlv == ONTAP_NS_TLV) {
		label_len = (*(__u16 *)&log_data[j]) * 4;
		namespace_name = (char *)&log_data[j + 2];
		ontap_labels_to_str(ns_name, namespace_name, label_len);
	} else {
		/* not the expected namespace tlv */
		fprintf(stderr, "Unable to fetch ONTAP namespace name\n");
		return;
	}

	snprintf(nspath, ONTAP_NS_PATHLEN, "%s%s%s%s", ontap_vol,
			vol_name, "/", ns_name);
}

static void netapp_smdevice_json(struct json_object *devices, char *devname,
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

static void netapp_ontapdevice_json(struct json_object *devices, char *devname,
		char *vsname, char *nspath, int nsid, char *uuid,
		char *size, long long lba, long long nsze)
{
	struct json_object *device_attrs;

	device_attrs = json_create_object();
	json_object_add_value_string(device_attrs, "Device", devname);
	json_object_add_value_string(device_attrs, "Vserver", vsname);
	json_object_add_value_string(device_attrs, "Namespace_Path", nspath);
	json_object_add_value_int(device_attrs, "NSID", nsid);
	json_object_add_value_string(device_attrs, "UUID", uuid);
	json_object_add_value_string(device_attrs, "Size", size);
	json_object_add_value_int(device_attrs, "LBA_Data_Size", lba);
	json_object_add_value_int(device_attrs, "Namespace_Size", nsze);

	json_array_add_value_object(devices, device_attrs);
}

static void netapp_smdevices_print(struct smdevice_info *devices, int count, int format)
{
	struct json_object *root = NULL;
	struct json_object *json_devices = NULL;
	int i, slta;
	char array_label[ARRAY_LABEL_LEN / 2 + 1];
	char volume_label[VOLUME_LABEL_LEN / 2 + 1];
	char nguid_str[33];
	char basestr[] = "%s, Array Name %s, Volume Name %s, NSID %d, "
			"Volume ID %s, Controller %c, Access State %s, %s\n";
	char columnstr[] = "%-16s %-30s %-30s %4d %32s  %c   %-12s %9s\n";
	char *formatstr = basestr; /* default to "normal" output format */

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
		json_devices = json_create_object();
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

static void netapp_ontapdevices_print(struct ontapdevice_info *devices,
		int count, int format)
{
	struct json_object *root = NULL;
	struct json_object *json_devices = NULL;
	char vsname[ONTAP_LABEL_LEN] = " ";
	char nspath[ONTAP_NS_PATHLEN] = " ";
	long long lba;
	char size[128];
	char uuid_str[37] = " ";
	int i;

	char basestr[] = "%s, Vserver %s, Namespace Path %s, NSID %d, UUID %s, %s\n";
	char columnstr[] = "%-16s %-25s %-50s %-4d %-38s %-9s\n";

	/* default to 'normal' output format */
	char *formatstr = basestr;

	if (format == NCOLUMN) {
		/* change output string and print column headers */
		formatstr = columnstr;
		printf("%-16s %-25s %-50s %-4s %-38s %-9s\n",
				"Device", "Vserver", "Namespace Path",
				"NSID", "UUID", "Size");
		printf("%-16s %-25s %-50s %-4s %-38s %-9s\n",
				"----------------", "-------------------------",
				"--------------------------------------------------",
				"----", "--------------------------------------",
				"---------");
	} else if (format == NJSON) {
		/* prepare for json output */
		root = json_create_object();
		json_devices = json_create_object();
	}

	for (i = 0; i < count; i++) {

		netapp_get_ns_size(size, &lba, &devices[i].ns);
		netapp_uuid_to_str(uuid_str, devices[i].nsdesc);
		netapp_get_ontap_labels(vsname, nspath, devices[i].log_data);

		if (format == NJSON) {
			netapp_ontapdevice_json(json_devices, devices[i].dev,
					vsname, nspath, devices[i].nsid,
					uuid_str, size, lba,
					le64_to_cpu(devices[i].ns.nsze));
		} else
			printf(formatstr, devices[i].dev, vsname, nspath,
					devices[i].nsid, uuid_str, size);
	}

	if (format == NJSON) {
		/* complete the json output */
		json_object_add_value_array(root, "ONTAPdevices", json_devices);
		json_print_object(root, NULL);
	}
}

static int nvme_get_ontap_c2_log(int fd, __u32 nsid, void *buf, __u32 buflen)
{
	struct nvme_admin_cmd get_log;
	int err;

	memset(buf, 0, buflen);
	memset(&get_log, 0, sizeof(struct nvme_admin_cmd));

	get_log.opcode = nvme_admin_get_log_page;
	get_log.nsid = nsid;
	get_log.addr = (__u64)(uintptr_t)buf;
	get_log.data_len = buflen;

	__u32 numd = (get_log.data_len >> 2) - 1;
	__u32 numdu = numd >> 16;
	__u32 numdl = numd & 0xFFFF;

	get_log.cdw10 = ONTAP_C2_LOG_ID | (numdl << 16);
	get_log.cdw10 |= ONTAP_C2_LOG_NSINFO_LSP << 8;
	get_log.cdw11 = numdu;

	err = nvme_submit_admin_passthru(fd, &get_log);
	if (err) {
		fprintf(stderr, "ioctl error %0x\n", err);
		return 1;
	}

	return 0;
}

static int netapp_smdevices_get_info(int fd, struct smdevice_info *item,
				     const char *dev)
{
	int err;

	err = nvme_identify_ctrl(fd, &item->ctrl);
	if (err) {
		fprintf(stderr, "Identify Controller failed to %s (%s)\n", dev,
			strerror(err));
		return 0;
	}

	if (strncmp("NetApp E-Series", item->ctrl.mn, 15) != 0)
		return 0; /* not the right model of controller */

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

static int netapp_ontapdevices_get_info(int fd, struct ontapdevice_info *item,
		const char *dev)
{
	int err;

	err = nvme_identify_ctrl(fd, &item->ctrl);
	if (err) {
		fprintf(stderr, "Identify Controller failed to %s (%s)\n",
				dev, strerror(err));
		return 0;
	}

	if (strncmp("NetApp ONTAP Controller", item->ctrl.mn, 23) != 0)
		/* not the right controller model */
		return 0;

	item->nsid = nvme_get_nsid(fd);

	err = nvme_identify_ns(fd, item->nsid, 0, &item->ns);
	if (err) {
		fprintf(stderr, "Unable to identify namespace for %s (%s)\n",
				dev, strerror(err));
		return 0;
	}

	err = nvme_identify_ns_descs(fd, item->nsid, item->nsdesc);
	if (err) {
		fprintf(stderr, "Unable to identify namespace descriptor for %s (%s)\n",
				dev, strerror(err));
		return 0;
	}

	err = nvme_get_ontap_c2_log(fd, item->nsid, item->log_data, ONTAP_C2_LOG_SIZE);
	if (err) {
		fprintf(stderr, "Unable to get log page data for %s (%s)\n",
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

	struct dirent **devices;
	int num, i, fd, ret, fmt;
	struct smdevice_info *smdevices;
	char path[264];
	int num_smdevices = 0;

	struct config {
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format, "Output Format: normal|json|column"),
		OPT_END()
	};

	ret = argconfig_parse(argc, argv, desc, opts);
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

/* handler for 'nvme netapp ontapdevices' */
static int netapp_ontapdevices(int argc, char **argv, struct command *command,
		struct plugin *plugin)
{
	const char *desc = "Display information about ONTAP devices.";
	struct dirent **devices;
	int num, i, fd, ret, fmt;
	struct ontapdevice_info *ontapdevices;
	char path[264];
	int num_ontapdevices = 0;

	struct config {
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format, "Output Format: normal|json|column"),
		OPT_END()
	};

	ret = argconfig_parse(argc, argv, desc, opts);
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

	ontapdevices = calloc(num, sizeof(*ontapdevices));
	if (!ontapdevices) {
		fprintf(stderr, "Unable to allocate memory for devices.\n");
		return -ENOMEM;
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

		num_ontapdevices += netapp_ontapdevices_get_info(fd,
				&ontapdevices[num_ontapdevices], path);

		close(fd);
	}

	if (num_ontapdevices)
		netapp_ontapdevices_print(ontapdevices, num_ontapdevices, fmt);

	for (i = 0; i < num; i++)
		free(devices[i]);
	free(devices);
	free(ontapdevices);
	return 0;
}
