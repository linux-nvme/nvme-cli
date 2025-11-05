// SPDX-License-Identifier: GPL-2.0-or-later
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
#include <libgen.h>

#include "common.h"
#include "nvme.h"
#include "libnvme.h"

#include "util/suffix.h"

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
	ONTAP_C2_LOG_PLATFORM_LSP	= 0x2,
};

enum {
	ONTAP_VSERVER_NAME_TLV		= 0x11,
	ONTAP_VOLUME_NAME_TLV		= 0x12,
	ONTAP_NS_NAME_TLV		= 0x13,
	ONTAP_NS_PATH_TLV		= 0x14,
};

static const char *dev_path = "/dev/";

struct smdevice_info {
	unsigned int		nsid;
	struct nvme_id_ctrl	ctrl;
	struct nvme_id_ns	ns;
	char			dev[265];
};

struct ontapdevice_info {
	unsigned int		nsid;
	struct nvme_id_ctrl	ctrl;
	struct nvme_id_ns	ns;
	unsigned char		uuid[NVME_UUID_LEN];
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

static void netapp_get_ns_size(char *size, unsigned long long *lba,
		struct nvme_id_ns *ns)
{
	__u8 lba_index;

	nvme_id_ns_flbas_to_lbaf_inuse(ns->flbas, &lba_index);
	*lba = 1ULL << ns->lbaf[lba_index].ds;
	double nsze = le64_to_cpu(ns->nsze) * (*lba);
	const char *s_suffix = suffix_si_get(&nsze);

	sprintf(size, "%.2f%sB", nsze, s_suffix);
}

static void netapp_get_ns_attrs(char *size, char *used, char *blk_size,
		char *version, unsigned long long *lba,
		struct nvme_id_ctrl *ctrl, struct nvme_id_ns *ns)
{
	__u8 lba_index;

	nvme_id_ns_flbas_to_lbaf_inuse(ns->flbas, &lba_index);
	*lba = 1ULL << ns->lbaf[lba_index].ds;

	/* get the namespace size */
	double nsze = le64_to_cpu(ns->nsze) * (*lba);
	const char *s_suffix = suffix_si_get(&nsze);

	sprintf(size, "%.2f%sB", nsze, s_suffix);

	/* get the namespace utilization */
	double nuse = le64_to_cpu(ns->nuse) * (*lba);
	const char *u_suffix = suffix_si_get(&nuse);

	sprintf(used, "%.2f%sB", nuse, u_suffix);

	/* get the namespace block size */
	long long addr = 1LL << ns->lbaf[lba_index].ds;
	const char *l_suffix = suffix_binary_get(&addr);

	sprintf(blk_size, "%u%sB", (unsigned int)addr, l_suffix);

	/* get the firmware version */
	int i, max = sizeof(ctrl->fr);

	memcpy(version, ctrl->fr, max);
	version[max] = '\0';
	/* strip trailing whitespaces */
	for (i = max - 1; i >= 0 && version[i] == ' '; i--)
		version[i] = '\0';
}

static void ontap_get_subsysname(char *subnqn, char *subsysname,
		 struct nvme_id_ctrl *ctrl)
{
	char *subname;
	int i, len = sizeof(ctrl->subnqn);

	/* get the target NQN */
	memcpy(subnqn, ctrl->subnqn, len);
	subnqn[len] = '\0';

	/* strip trailing whitespaces */
	for (i = len - 1; i >= 0 && subnqn[i] == ' '; i--)
		subnqn[i] = '\0';

	/* get the subsysname from the target NQN */
	subname = strrchr(subnqn, '.');
	if (subname) {
		subname++;
		len = strlen(subname);
		memcpy(subsysname, subname, len);
		subsysname[len] = '\0';
	} else
		fprintf(stderr, "Unable to fetch ONTAP subsystem name\n");
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
	char *vserver_name, *volume_name, *namespace_name, *namespace_path;
	char vol_name[ONTAP_LABEL_LEN], ns_name[ONTAP_LABEL_LEN];
	char ns_path[ONTAP_LABEL_LEN];
	bool nspath_tlv_available = false;
	const char *ontap_vol = "/vol/";
	int i, j;

	/* get the lsp */
	lsp = (*(__u8 *)&log_data[16]) & 0x0F;
	if (lsp != ONTAP_C2_LOG_NSINFO_LSP)
		/* lsp not related to nsinfo */
		return;

	/* get the vserver name tlv */
	tlv = *(__u8 *)&log_data[32];
	if (tlv == ONTAP_VSERVER_NAME_TLV) {
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
	/* get the volume name tlv */
	tlv = *(__u8 *)&log_data[i];
	if (tlv == ONTAP_VOLUME_NAME_TLV) {
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
	/* get the namespace name tlv */
	tlv = *(__u8 *)&log_data[i];
	if (tlv == ONTAP_NS_NAME_TLV) {
		label_len = (*(__u16 *)&log_data[j]) * 4;
		namespace_name = (char *)&log_data[j + 2];
		ontap_labels_to_str(ns_name, namespace_name, label_len);
	} else {
		/* not the expected namespace tlv */
		fprintf(stderr, "Unable to fetch ONTAP namespace name\n");
		return;
	}

	i += 4 + label_len;
	j += 4 + label_len;
	/* get the namespace path tlv if available */
	tlv = *(__u8 *)&log_data[i];
	if (tlv == ONTAP_NS_PATH_TLV) {
		nspath_tlv_available = true;
		label_len = (*(__u16 *)&log_data[j]) * 4;
		namespace_path = (char *)&log_data[j + 2];
		ontap_labels_to_str(ns_path, namespace_path, label_len);
	}

	if (nspath_tlv_available) {
		/* set nspath from the corresponding ns_path string */
		snprintf(nspath, ONTAP_NS_PATHLEN, "%s", ns_path);
	} else {
		/* set nspath by concatenating ontap_vol with ns_name */
		snprintf(nspath, ONTAP_NS_PATHLEN, "%s%s%s%s", ontap_vol,
			vol_name, "/", ns_name);
	}
}

static void netapp_smdevice_json(struct json_object *devices, char *devname,
		char *arrayname, char *volname, int nsid, char *nguid,
		char *ctrl, char *astate, char *version, unsigned long long lba,
		unsigned long long nsze, unsigned long long nuse)
{
	struct json_object *device_attrs;
	unsigned long long ns_size = nsze * lba;

	device_attrs = json_create_object();
	json_object_add_value_string(device_attrs, "Device", devname);
	json_object_add_value_string(device_attrs, "Array_Name", arrayname);
	json_object_add_value_string(device_attrs, "Volume_Name", volname);
	json_object_add_value_int(device_attrs, "NSID", nsid);
	json_object_add_value_string(device_attrs, "Volume_ID", nguid);
	json_object_add_value_string(device_attrs, "Controller", ctrl);
	json_object_add_value_string(device_attrs, "Access_State", astate);
	json_object_add_value_uint64(device_attrs, "LBA_Size", lba);
	json_object_add_value_uint64(device_attrs, "Namespace_Size", ns_size);
	json_object_add_value_string(device_attrs, "Version", version);

	json_array_add_value_object(devices, device_attrs);
}

static void netapp_ontapdevice_json(struct json_object *devices, char *devname,
		char *vsname, char *subsysname, char *nspath, int nsid,
		char *uuid, unsigned long long lba, char *version,
		unsigned long long nsze, unsigned long long nuse)
{
	struct json_object *device_attrs;
	unsigned long long ns_size = nsze * lba;
	unsigned long long used_size = nuse * lba;

	device_attrs = json_create_object();
	json_object_add_value_string(device_attrs, "Device", devname);
	json_object_add_value_string(device_attrs, "Vserver", vsname);
	json_object_add_value_string(device_attrs, "Subsystem", subsysname);
	json_object_add_value_string(device_attrs, "Namespace_Path", nspath);
	json_object_add_value_int(device_attrs, "NSID", nsid);
	json_object_add_value_string(device_attrs, "UUID", uuid);
	json_object_add_value_uint64(device_attrs, "LBA_Size", lba);
	json_object_add_value_uint64(device_attrs, "Namespace_Size", ns_size);
	json_object_add_value_uint64(device_attrs, "UsedBytes", used_size);
	json_object_add_value_string(device_attrs, "Version", version);

	json_array_add_value_object(devices, device_attrs);
}

static void netapp_smdevices_print_verbose(struct smdevice_info *devices,
		int count, int format, const char *devname)
{
	int i, slta;
	char array_label[ARRAY_LABEL_LEN / 2 + 1];
	char volume_label[VOLUME_LABEL_LEN / 2 + 1];
	char nguid_str[33];
	unsigned long long lba;
	char size[128], used[128];
	char blk_size[128], version[9];

	char *formatstr = NULL;
	char basestr[] =
		"%s, Array Name %s, Volume Name %s, NSID %d, Volume ID %s, "
		"Controller %c, Access State %s, Size %s, Format %s, Version %s\n";
	char columnstr[] =
		"%-16s %-30s %-30s %4d %32s  %c   %-12s %-9s %-9s %-9s\n";

	if (format == NNORMAL)
		formatstr = basestr;
	else if (format == NCOLUMN) {
		/* print column headers and change the output string */
		printf("%-16s %-30s %-30s %-4s %-32s %-4s %-12s %-9s %-9s %-9s\n",
			"Device", "Array Name", "Volume Name", "NSID",
			"Volume ID", "Ctrl", "Access State", " Size",
			"Format", "Version");
		printf("%-16s %-30s %-30s %-4s %-32s %-4s %-12s %-9s %-9s %-9s\n",
			"----------------", "------------------------------",
			"------------------------------", "----",
			"--------------------------------", "----",
			"------------", "---------",
			"---------", "---------");
		formatstr = columnstr;
	}

	for (i = 0; i < count; i++) {
		if (devname && !strcmp(devname, basename(devices[i].dev))) {
			/* found the device, fetch info for that alone */
			netapp_get_ns_attrs(size, used, blk_size, version,
					&lba, &devices[i].ctrl, &devices[i].ns);
			netapp_convert_string(array_label,
					(char *)&devices[i].ctrl.vs[20],
					ARRAY_LABEL_LEN / 2);
			slta = devices[i].ctrl.vs[0] & 0x1;
			netapp_convert_string(volume_label,
					(char *)devices[i].ns.vs,
					VOLUME_LABEL_LEN / 2);
			netapp_nguid_to_str(nguid_str, devices[i].ns.nguid);

			printf(formatstr, devices[i].dev, array_label,
					volume_label, devices[i].nsid,
					nguid_str,
					slta ? 'A' : 'B', "unknown", size,
					blk_size, version);
			return;
		}
	}

	for (i = 0; i < count; i++) {
		/* fetch info and print for all devices */
		netapp_get_ns_attrs(size, used, blk_size, version,
				&lba, &devices[i].ctrl, &devices[i].ns);
		netapp_convert_string(array_label,
				(char *)&devices[i].ctrl.vs[20],
				ARRAY_LABEL_LEN / 2);
		slta = devices[i].ctrl.vs[0] & 0x1;
		netapp_convert_string(volume_label,
				(char *)devices[i].ns.vs,
				VOLUME_LABEL_LEN / 2);
		netapp_nguid_to_str(nguid_str, devices[i].ns.nguid);

		printf(formatstr, devices[i].dev, array_label,
				volume_label, devices[i].nsid,
				nguid_str,
				slta ? 'A' : 'B', "unknown", size,
				blk_size, version);
	}
}

static void netapp_smdevices_print_regular(struct smdevice_info *devices,
		int count, int format, const char *devname)
{
	int i, slta;
	char array_label[ARRAY_LABEL_LEN / 2 + 1];
	char volume_label[VOLUME_LABEL_LEN / 2 + 1];
	char nguid_str[33];
	unsigned long long lba;
	char size[128];

	char *formatstr = NULL;
	char basestr[] =
	    "%s, Array Name %s, Volume Name %s, NSID %d, Volume ID %s, Controller %c, Access State %s, %s\n";
	char columnstr[] = "%-16s %-30s %-30s %4d %32s  %c   %-12s %9s\n";

	if (format == NNORMAL)
		formatstr = basestr;
	else if (format == NCOLUMN) {
		/* print column headers and change the output string */
		printf("%-16s %-30s %-30s %-4s %-32s %-4s %-12s %-9s\n",
			"Device", "Array Name", "Volume Name", "NSID",
			"Volume ID", "Ctrl", "Access State", " Size");
		printf("%-16s %-30s %-30s %-4s %-32s %-4s %-12s %-9s\n",
			"----------------", "------------------------------",
			"------------------------------", "----",
			"--------------------------------", "----",
			"------------", "---------");
		formatstr = columnstr;
	}

	for (i = 0; i < count; i++) {
		if (devname && !strcmp(devname, basename(devices[i].dev))) {
			/* found the device, fetch info for that alone */
			netapp_get_ns_size(size, &lba, &devices[i].ns);
			netapp_convert_string(array_label,
					(char *)&devices[i].ctrl.vs[20],
					ARRAY_LABEL_LEN / 2);
			slta = devices[i].ctrl.vs[0] & 0x1;
			netapp_convert_string(volume_label,
					(char *)devices[i].ns.vs,
					VOLUME_LABEL_LEN / 2);
			netapp_nguid_to_str(nguid_str, devices[i].ns.nguid);

			printf(formatstr, devices[i].dev, array_label,
					volume_label, devices[i].nsid,
					nguid_str,
					slta ? 'A' : 'B', "unknown", size);
			return;
		}
	}

	for (i = 0; i < count; i++) {
		/* fetch info for all devices */
		netapp_get_ns_size(size, &lba, &devices[i].ns);
		netapp_convert_string(array_label,
				(char *)&devices[i].ctrl.vs[20],
				ARRAY_LABEL_LEN / 2);
		slta = devices[i].ctrl.vs[0] & 0x1;
		netapp_convert_string(volume_label, (char *)devices[i].ns.vs,
				VOLUME_LABEL_LEN / 2);
		netapp_nguid_to_str(nguid_str, devices[i].ns.nguid);

		printf(formatstr, devices[i].dev, array_label,
				volume_label, devices[i].nsid, nguid_str,
				slta ? 'A' : 'B', "unknown", size);
	}
}

static void netapp_smdevices_print_json(struct smdevice_info *devices,
		int count, const char *devname)
{
	struct json_object *root = NULL;
	struct json_object *json_devices = NULL;
	int i, slta;
	char array_label[ARRAY_LABEL_LEN / 2 + 1];
	char volume_label[VOLUME_LABEL_LEN / 2 + 1];
	char nguid_str[33];
	unsigned long long lba;
	char size[128], used[128];
	char blk_size[128], version[9];

	/* prepare for the json output */
	root = json_create_object();
	json_devices = json_create_array();

	for (i = 0; i < count; i++) {
		if (devname && !strcmp(devname, basename(devices[i].dev))) {
			/* found the device, fetch info for that alone */
			netapp_get_ns_attrs(size, used, blk_size, version,
					&lba, &devices[i].ctrl, &devices[i].ns);
			netapp_convert_string(array_label,
					(char *)&devices[i].ctrl.vs[20],
					ARRAY_LABEL_LEN / 2);
			slta = devices[i].ctrl.vs[0] & 0x1;
			netapp_convert_string(volume_label,
					(char *)devices[i].ns.vs,
					VOLUME_LABEL_LEN / 2);
			netapp_nguid_to_str(nguid_str, devices[i].ns.nguid);
			netapp_smdevice_json(json_devices, devices[i].dev,
					array_label, volume_label,
					devices[i].nsid, nguid_str,
					slta ? "A" : "B", "unknown",
					version, lba,
					le64_to_cpu(devices[i].ns.nsze),
					le64_to_cpu(devices[i].ns.nuse));
			goto out;
		}
	}

	for (i = 0; i < count; i++) {
		/* fetch info for all devices */
		netapp_get_ns_attrs(size, used, blk_size, version,
				&lba, &devices[i].ctrl, &devices[i].ns);
		netapp_convert_string(array_label,
				(char *)&devices[i].ctrl.vs[20],
				ARRAY_LABEL_LEN / 2);
		slta = devices[i].ctrl.vs[0] & 0x1;
		netapp_convert_string(volume_label,
				(char *)devices[i].ns.vs,
				VOLUME_LABEL_LEN / 2);
		netapp_nguid_to_str(nguid_str, devices[i].ns.nguid);
		netapp_smdevice_json(json_devices, devices[i].dev,
				array_label, volume_label, devices[i].nsid,
				nguid_str, slta ? "A" : "B", "unknown",
				version, lba,
				le64_to_cpu(devices[i].ns.nsze),
				le64_to_cpu(devices[i].ns.nuse));
	}

out:
	/* complete the json output */
	json_object_add_value_array(root, "SMdevices", json_devices);
	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static void netapp_ontapdevices_print_verbose(struct ontapdevice_info *devices,
		int count, int format, const char *devname)
{
	char vsname[ONTAP_LABEL_LEN] = " ";
	char nspath[ONTAP_NS_PATHLEN] = " ";
	unsigned long long lba;
	char size[128], used[128];
	char blk_size[128], version[9];
	char uuid_str[37] = " ";
	char subnqn[257], subsysname[65];
	int i;

	char *formatstr = NULL;
	char basestr[] =
		"%s, Vserver %s, Subsystem %s, Namespace Path %s, NSID %d, "
		"UUID %s, Size %s, Used %s, Format %s, Version %s\n";
	char columnstr[] = "%-16s %-25s %-25s %-50s %-4d %-38s %-9s %-9s %-9s %-9s\n";

	if (format == NNORMAL)
		formatstr = basestr;
	else if (format == NCOLUMN) {
		printf("%-16s %-25s %-25s %-50s %-4s %-38s %-9s %-9s %-9s %-9s\n",
				"Device", "Vserver", "Subsystem", "Namespace Path",
				"NSID", "UUID", "Size", "Used",
				"Format", "Version");
		printf("%-16s %-25s %-25s %-50s %-4s %-38s %-9s %-9s %-9s %-9s\n",
			"----------------", "-------------------------",
			"-------------------------",
			"--------------------------------------------------",
			"----", "--------------------------------------",
			"---------", "---------", "---------", "---------");
		formatstr = columnstr;
	}

	for (i = 0; i < count; i++) {
		if (devname && !strcmp(devname, basename(devices[i].dev))) {
			/* found the device, fetch and print for that alone */
			netapp_get_ns_attrs(size, used, blk_size, version,
					&lba, &devices[i].ctrl, &devices[i].ns);
			ontap_get_subsysname(subnqn, subsysname,
					&devices[i].ctrl);
			nvme_uuid_to_string(devices[i].uuid, uuid_str);
			netapp_get_ontap_labels(vsname, nspath,
					devices[i].log_data);

			printf(formatstr, devices[i].dev, vsname, subsysname,
					nspath, devices[i].nsid, uuid_str,
					size, used, blk_size, version);
			return;
		}
	}

	for (i = 0; i < count; i++) {
		/* fetch info and print for all devices */
		netapp_get_ns_attrs(size, used, blk_size, version,
				&lba, &devices[i].ctrl, &devices[i].ns);
		ontap_get_subsysname(subnqn, subsysname,
				&devices[i].ctrl);
		nvme_uuid_to_string(devices[i].uuid, uuid_str);
		netapp_get_ontap_labels(vsname, nspath, devices[i].log_data);

		printf(formatstr, devices[i].dev, vsname, subsysname,
				nspath, devices[i].nsid, uuid_str,
				size, used, blk_size, version);
	}
}

static void netapp_ontapdevices_print_regular(struct ontapdevice_info *devices,
		int count, int format, const char *devname)
{
	char vsname[ONTAP_LABEL_LEN] = " ";
	char nspath[ONTAP_NS_PATHLEN] = " ";
	unsigned long long lba;
	char size[128];
	char uuid_str[37] = " ";
	char subnqn[257], subsysname[65];
	int i;

	char *formatstr = NULL;
	char basestr[] =
		"%s, Vserver %s, Subsystem %s, Namespace Path %s, NSID %d, UUID %s, %s\n";
	char columnstr[] = "%-16s %-25s %-25s %-50s %-4d %-38s %-9s\n";

	if (format == NNORMAL)
		formatstr = basestr;
	else if (format == NCOLUMN) {
		printf("%-16s %-25s %-25s %-50s %-4s %-38s %-9s\n",
			"Device", "Vserver", "Subsystem", "Namespace Path",
			"NSID", "UUID", "Size");
		printf("%-16s %-25s %-25s %-50s %-4s %-38s %-9s\n",
			"----------------", "-------------------------",
			"-------------------------",
			"--------------------------------------------------",
			"----", "--------------------------------------",
			"---------");
		formatstr = columnstr;
	}

	for (i = 0; i < count; i++) {
		if (devname && !strcmp(devname, basename(devices[i].dev))) {
			/* found the device, fetch and print for that alone */
			netapp_get_ns_size(size, &lba, &devices[i].ns);
			nvme_uuid_to_string(devices[i].uuid, uuid_str);
			netapp_get_ontap_labels(vsname, nspath,
					devices[i].log_data);
			ontap_get_subsysname(subnqn, subsysname,
					&devices[i].ctrl);

			printf(formatstr, devices[i].dev, vsname, subsysname,
					nspath, devices[i].nsid, uuid_str, size);
			return;
		}
	}

	for (i = 0; i < count; i++) {
		/* fetch info and print for all devices */
		netapp_get_ns_size(size, &lba, &devices[i].ns);
		nvme_uuid_to_string(devices[i].uuid, uuid_str);
		netapp_get_ontap_labels(vsname, nspath, devices[i].log_data);
		ontap_get_subsysname(subnqn, subsysname, &devices[i].ctrl);

		printf(formatstr, devices[i].dev, vsname, subsysname,
				nspath, devices[i].nsid, uuid_str, size);
	}
}

static void netapp_ontapdevices_print_json(struct ontapdevice_info *devices,
		int count, const char *devname)
{
	struct json_object *root = NULL;
	struct json_object *json_devices = NULL;
	char vsname[ONTAP_LABEL_LEN] = " ";
	char nspath[ONTAP_NS_PATHLEN] = " ";
	unsigned long long lba;
	char size[128], used[128];
	char blk_size[128], version[9];
	char uuid_str[37] = " ";
	char subnqn[257], subsysname[65];
	int i;

	/* prepare for the json output */
	root = json_create_object();
	json_devices = json_create_array();

	for (i = 0; i < count; i++) {
		if (devname && !strcmp(devname, basename(devices[i].dev))) {
			/* found the device, fetch info for that alone */
			netapp_get_ns_attrs(size, used, blk_size, version,
					&lba, &devices[i].ctrl, &devices[i].ns);
			ontap_get_subsysname(subnqn, subsysname,
					&devices[i].ctrl);
			nvme_uuid_to_string(devices[i].uuid, uuid_str);
			netapp_get_ontap_labels(vsname, nspath,
					devices[i].log_data);

			netapp_ontapdevice_json(json_devices, devices[i].dev,
					vsname, subsysname, nspath,
					devices[i].nsid, uuid_str, lba, version,
					le64_to_cpu(devices[i].ns.nsze),
					le64_to_cpu(devices[i].ns.nuse));
			goto out;
		}
	}

	for (i = 0; i < count; i++) {
		/* fetch info for all devices */
		netapp_get_ns_attrs(size, used, blk_size, version,
				&lba, &devices[i].ctrl, &devices[i].ns);
		ontap_get_subsysname(subnqn, subsysname,
				&devices[i].ctrl);
		nvme_uuid_to_string(devices[i].uuid, uuid_str);
		netapp_get_ontap_labels(vsname, nspath, devices[i].log_data);

		netapp_ontapdevice_json(json_devices, devices[i].dev,
				vsname, subsysname, nspath,
				devices[i].nsid, uuid_str, lba, version,
				le64_to_cpu(devices[i].ns.nsze),
				le64_to_cpu(devices[i].ns.nuse));
	}

out:
	/* complete the json output */
	json_object_add_value_array(root, "ONTAPdevices", json_devices);
	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static int nvme_get_ontap_c2_log(struct nvme_transport_handle *hdl, __u32 nsid, void *buf, __u32 buflen)
{
	struct nvme_passthru_cmd get_log;
	int err;

	memset(buf, 0, buflen);
	memset(&get_log, 0, sizeof(struct nvme_passthru_cmd));

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

	err = nvme_submit_admin_passthru(hdl, &get_log, NULL);
	if (err) {
		fprintf(stderr, "ioctl error %0x\n", err);
		return 1;
	}

	return 0;
}

static int netapp_smdevices_get_info(struct nvme_transport_handle *hdl,
				     struct smdevice_info *item,
				     const char *dev)
{
	int err;

	err = nvme_identify_ctrl(hdl, &item->ctrl);
	if (err) {
		fprintf(stderr,
			"Identify Controller failed to %s (%s)\n", dev,
			err < 0 ? strerror(-err) :
			nvme_status_to_string(err, false));
		return 0;
	}

	if (strncmp("NetApp E-Series", item->ctrl.mn, 15) != 0)
		return 0; /* not the right model of controller */

	err = nvme_get_nsid(hdl, &item->nsid);
	err = nvme_identify_ns(hdl, item->nsid, &item->ns);
	if (err) {
		fprintf(stderr,
			"Unable to identify namespace for %s (%s)\n",
			dev, err < 0 ? strerror(-err) :
			nvme_status_to_string(err, false));
		return 0;
	}
	strncpy(item->dev, dev, sizeof(item->dev) - 1);

	return 1;
}

static int netapp_ontapdevices_get_info(struct nvme_transport_handle *hdl,
					struct ontapdevice_info *item,
					const char *dev)
{
	int err;
	void *nsdescs;

	err = nvme_identify_ctrl(hdl, &item->ctrl);
	if (err) {
		fprintf(stderr, "Identify Controller failed to %s (%s)\n",
			dev, err < 0 ? strerror(-err) :
			nvme_status_to_string(err, false));
		return 0;
	}

	if (strncmp("NetApp ONTAP Controller", item->ctrl.mn, 23) != 0)
		/* not the right controller model */
		return 0;

	err = nvme_get_nsid(hdl, &item->nsid);

	err = nvme_identify_ns(hdl, item->nsid, &item->ns);
	if (err) {
		fprintf(stderr, "Unable to identify namespace for %s (%s)\n",
			dev, err < 0 ? strerror(-err) :
			nvme_status_to_string(err, false));
		return 0;
	}

	if (posix_memalign(&nsdescs, getpagesize(), 0x1000)) {
		fprintf(stderr, "Cannot allocate controller list payload\n");
		return 0;
	}

	memset(nsdescs, 0, 0x1000);

	err = nvme_identify_ns_descs(hdl, item->nsid, nsdescs);
	if (err) {
		fprintf(stderr, "Unable to identify namespace descriptor for %s (%s)\n",
			dev, err < 0 ? strerror(-err) :
			nvme_status_to_string(err, false));
		free(nsdescs);
		return 0;
	}

	memcpy(item->uuid, nsdescs + sizeof(struct nvme_ns_id_desc), sizeof(item->uuid));
	free(nsdescs);

	err = nvme_get_ontap_c2_log(hdl, item->nsid, item->log_data, ONTAP_C2_LOG_SIZE);
	if (err) {
		fprintf(stderr, "Unable to get log page data for %s (%s)\n",
			dev, err < 0 ? strerror(-err) :
			nvme_status_to_string(err, false));
		return 0;
	}

	strncpy(item->dev, dev, sizeof(item->dev) - 1);

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
#ifdef CONFIG_JSONC
	if (!strcmp(format, "json"))
		return NJSON;
#endif /* CONFIG_JSONC */
	if (!strcmp(format, "column"))
		return NCOLUMN;
	return -EINVAL;
}

/* handler for 'nvme netapp smdevices' */
static int netapp_smdevices(int argc, char **argv, struct command *command,
			    struct plugin *plugin)
{
	const char *desc = "Display information about E-Series volumes.";
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = nvme_create_global_ctx(stdout, DEFAULT_LOGLEVEL);
	struct dirent **devices;
	int num, i, ret, fmt;
	struct smdevice_info *smdevices;
	char path[264];
	char *devname = NULL;
	int num_smdevices = 0;
	struct nvme_transport_handle *hdl;

	struct config {
		bool verbose;
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FLAG("verbose", 'v', &cfg.verbose, "Increase output verbosity"),
		OPT_FMT("output-format", 'o', &cfg.output_format, "Output Format: normal|json|column"),
		OPT_END()
	};

	if (!ctx)
		return -ENOMEM;

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
		fprintf(stderr, "No smdevices detected\n");
		return num;
	}

	if (optind < argc)
		devname = basename(argv[optind++]);

	if (devname) {
		int subsys_num, nsid;
		struct stat st;
		char path[512];

		if (sscanf(devname, "nvme%dn%d", &subsys_num, &nsid) != 2) {
			fprintf(stderr, "Invalid device name %s\n", devname);
			return -EINVAL;
		}

		sprintf(path, "/dev/%s", devname);
		if (stat(path, &st) != 0) {
			fprintf(stderr, "%s does not exist\n", path);
			return -EINVAL;
		}
	}

	smdevices = calloc(num, sizeof(*smdevices));
	if (!smdevices) {
		fprintf(stderr, "Unable to allocate memory for devices\n");
		return -ENOMEM;
	}

	for (i = 0; i < num; i++) {
		snprintf(path, sizeof(path), "%s%s", dev_path,
			devices[i]->d_name);
		ret = nvme_open(ctx, path, &hdl);
		if (ret) {
			fprintf(stderr, "Unable to open %s: %s\n", path,
				strerror(-ret));
			continue;
		}

		num_smdevices += netapp_smdevices_get_info(hdl,
						&smdevices[num_smdevices], path);
		nvme_close(hdl);
	}

	if (num_smdevices) {
		if (fmt == NNORMAL || fmt == NCOLUMN) {
			if (argconfig_parse_seen(opts, "verbose"))
				netapp_smdevices_print_verbose(smdevices,
						num_smdevices, fmt, devname);
			else
				netapp_smdevices_print_regular(smdevices,
						num_smdevices, fmt, devname);
		}
		else if (fmt == NJSON)
			netapp_smdevices_print_json(smdevices,
					num_smdevices, devname);
	} else
		fprintf(stderr, "No smdevices detected\n");

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
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = nvme_create_global_ctx(stdout, DEFAULT_LOGLEVEL);
	const char *desc = "Display information about ONTAP devices.";
	struct dirent **devices;
	int num, i, ret, fmt;
	struct ontapdevice_info *ontapdevices;
	char path[264];
	char *devname = NULL;
	int num_ontapdevices = 0;
	struct nvme_transport_handle *hdl;

	struct config {
		bool verbose;
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FLAG("verbose", 'v', &cfg.verbose, "Increase output verbosity"),
		OPT_FMT("output-format", 'o', &cfg.output_format, "Output Format: normal|json|column"),
		OPT_END()
	};

	if (!ctx)
		return -ENOMEM;

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret < 0)
		return ret;

	fmt = netapp_output_format(cfg.output_format);
	if (fmt != NNORMAL && fmt != NCOLUMN && fmt != NJSON) {
		fprintf(stderr, "Unrecognized output format: %s\n", cfg.output_format);
		return -EINVAL;
	}

	if (optind < argc)
		devname = basename(argv[optind++]);

	if (devname) {
		int subsys_num, nsid;
		struct stat st;
		char path[512];

		if (sscanf(devname, "nvme%dn%d", &subsys_num, &nsid) != 2) {
			fprintf(stderr, "Invalid device name %s\n", devname);
			return -EINVAL;
		}

		sprintf(path, "/dev/%s", devname);
		if (stat(path, &st) != 0) {
			fprintf(stderr, "%s does not exist\n", path);
			return -EINVAL;
		}
	}

	num = scandir(dev_path, &devices, netapp_nvme_filter, alphasort);
	if (num <= 0) {
		fprintf(stderr, "No ontapdevices detected\n");
		return num;
	}

	ontapdevices = calloc(num, sizeof(*ontapdevices));
	if (!ontapdevices) {
		fprintf(stderr, "Unable to allocate memory for devices\n");
		return -ENOMEM;
	}

	for (i = 0; i < num; i++) {
		snprintf(path, sizeof(path), "%s%s", dev_path,
				devices[i]->d_name);
		ret = nvme_open(ctx, path, &hdl);
		if (ret) {
			fprintf(stderr, "Unable to open %s: %s\n", path,
					strerror(-ret));
			continue;
		}

		num_ontapdevices += netapp_ontapdevices_get_info(hdl,
				&ontapdevices[num_ontapdevices], path);

		nvme_close(hdl);
	}

	if (num_ontapdevices) {
		if (fmt == NNORMAL || fmt == NCOLUMN) {
			if (argconfig_parse_seen(opts, "verbose"))
				netapp_ontapdevices_print_verbose(ontapdevices,
						num_ontapdevices, fmt, devname);
			else
				netapp_ontapdevices_print_regular(ontapdevices,
						num_ontapdevices, fmt, devname);
		}
		else if (fmt == NJSON)
			netapp_ontapdevices_print_json(ontapdevices,
					num_ontapdevices, devname);
	} else
		fprintf(stderr, "No ontapdevices detected\n");

	for (i = 0; i < num; i++)
		free(devices[i]);
	free(devices);
	free(ontapdevices);
	return 0;
}
