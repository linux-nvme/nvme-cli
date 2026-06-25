// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * Copyright (c) 2025 Micron Technology, Inc.
 *
 * Authors: Broc Going <bgoing@micron.com>
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>

#include <libnvme.h>

#include "common.h"
#include "micron-utils.h"
#include "util/cleanup.h"

static int ReadSysFile(const char *file, unsigned short *id)
{
	int ret = 0;
	char idstr[32] = { '\0' };
	int fd = open(file, O_RDONLY);

	if (fd < 0) {
		perror(file);
		return fd;
	}

	ret = read(fd, idstr, sizeof(idstr));
	close(fd);
	if (ret < 0)
		perror("read");
	else
		*id = strtol(idstr, NULL, 16);

	return ret;
}

int micron_get_pci_ids(
	struct libnvme_global_ctx *ctx, struct libnvme_transport_handle *hdl,
	unsigned short *vid, unsigned short *did)
{
	char id_path[512];
	__cleanup_free char *ctrl_sysfs_dir = micron_get_ctrl_sysfs_dir(ctx, hdl);

	if (ctrl_sysfs_dir) {
		snprintf(id_path, sizeof(id_path), "%s/device/vendor",
			ctrl_sysfs_dir);
		ReadSysFile(id_path, vid);

		snprintf(id_path, sizeof(id_path), "%s/device/device",
			ctrl_sysfs_dir);
		ReadSysFile(id_path, did);
	} else {
		fprintf(stderr, "Unable to find sysfs dir for %s\n",
			libnvme_transport_handle_get_name(hdl));
		return -EINVAL;
	}

	return 0;
}

int micron_get_pcie_aer_errors(struct libnvme_transport_handle *hdl,
	__u32 *correctable_errors, __u32 *uncorrectable_errors)
{
	int bus = 0, domain = 0, device = 0, function = 0;
	char strTempFile[1024], strTempFile2[1024], cmdbuf[1024];
	char buf[8] = { 0 };
	char *businfo = NULL;
	__cleanup_free char *devicename = NULL;
	ssize_t sLinkSize = 0;
	FILE *fp;
	char *res;

	devicename = micron_get_ns_name(hdl);
	if (!strstr(devicename, "nvme")) {
		printf("Invalid device specified!\n");
		return -EINVAL;
	}
	sprintf(strTempFile, "/sys/block/%s/device", devicename);
	memset(strTempFile2, 0x0, 1024);
	sLinkSize = readlink(strTempFile, strTempFile2, 1023);
	if (sLinkSize < 0) {
		printf("Failed to read device\n");
		return -errno;
	}
	if (strstr(strTempFile2, "../../nvme")) {
		sprintf(strTempFile, "/sys/block/%s/device/device", devicename);
		memset(strTempFile2, 0x0, 1024);
		sLinkSize = readlink(strTempFile, strTempFile2, 1023);
		if (sLinkSize < 0) {
			printf("Failed to read device\n");
			return -errno;
		}
	}
	businfo = strrchr(strTempFile2, '/');
	if (sscanf(businfo, "/%x:%x:%x.%x", &domain, &bus, &device,
		   &function) != 4)
		domain = bus = device = function = 0;
	sprintf(cmdbuf, "setpci -s %x:%x.%x ECAP_AER+10.L", bus, device,
		function);
	fp = popen(cmdbuf, "r");
	if (!fp) {
		printf("Failed to retrieve error count\n");
		return -EIO;
	}
	res = fgets(buf, sizeof(buf), fp);
	if (!res) {
		printf("Failed to retrieve error count\n");
		pclose(fp);
		return -EIO;
	}
	pclose(fp);
	*correctable_errors = (__u32)strtol(buf, NULL, 16);

	sprintf(cmdbuf, "setpci -s %x:%x.%x ECAP_AER+0x4.L", bus, device,
		function);
	fp = popen(cmdbuf, "r");
	if (!fp) {
		printf("Failed to retrieve error count\n");
		return -EIO;
	}
	res = fgets(buf, sizeof(buf), fp);
	if (!res) {
		printf("Failed to retrieve error count\n");
		pclose(fp);
		return -EIO;
	}
	pclose(fp);
	*uncorrectable_errors = (__u32)strtol(buf, NULL, 16);

	return 0;
}

int micron_clear_pcie_aer_correctable_errors(
	struct libnvme_transport_handle *hdl)
{
	int err, bus = 0, domain = 0, device = 0, function = 0;
	char strTempFile[1024], strTempFile2[1024], cmdbuf[1024];
	char *businfo = NULL;
	__cleanup_free char *devicename = NULL;
	ssize_t sLinkSize = 0;
	char correctable[8] = { 0 };
	FILE *fp;
	char *res;

	devicename = micron_get_ns_name(hdl);
	if (!strstr(devicename, "nvme")) {
		printf("Invalid device specified!\n");
		return -EINVAL;
	}
	err = snprintf(strTempFile, sizeof(strTempFile),
				   "/sys/block/%s/device", devicename);
	if (err < 0)
		return err;

	memset(strTempFile2, 0x0, 1024);
	sLinkSize = readlink(strTempFile, strTempFile2, 1023);
	if (sLinkSize < 0) {
		printf("Failed to read device\n");
		return -errno;
	}
	if (strstr(strTempFile2, "../../nvme")) {
		err = snprintf(strTempFile, sizeof(strTempFile),
					   "/sys/block/%s/device/device", devicename);
		if (err < 0)
			return err;
		memset(strTempFile2, 0x0, 1024);
		sLinkSize = readlink(strTempFile, strTempFile2, 1023);
		if (sLinkSize < 0) {
			printf("Failed to read device\n");
			return -errno;
		}
	}
	businfo = strrchr(strTempFile2, '/');
	if (sscanf(businfo, "/%x:%x:%x.%x", &domain, &bus, &device, &function) != 4)
		domain = bus = device = function = 0;
	sprintf(cmdbuf, "setpci -s %x:%x.%x ECAP_AER+0x10.L=0xffffffff", bus,
			device, function);
	fp = popen(cmdbuf, "r");
	if (!fp) {
		printf("Failed to clear error count\n");
		return -1;
	}
	pclose(fp);

	sprintf(cmdbuf, "setpci -s %x:%x.%x ECAP_AER+0x10.L", bus, device,
			function);
	fp = popen(cmdbuf, "r");
	if (!fp) {
		printf("Failed to retrieve error count\n");
		return -1;
	}
	res = fgets(correctable, sizeof(correctable), fp);
	if (!res) {
		printf("Failed to retrieve error count\n");
		pclose(fp);
		return -1;
	}
	pclose(fp);
	printf("Device correctable errors cleared!\n");
	printf("Device correctable errors detected: %s\n", correctable);
	return 0;
}

void micron_write_os_config_to_file(const char *file_name)
{
	FILE *fpOSConfig = NULL;
	char strBuffer[1024];
	int i;

	struct {
		const char *strcmdHeader;
		const char *strCommand;
	} cmdArray[] = {
		{ "SYSTEM INFORMATION", "uname -a >> %s" },
		{ "LINUX KERNEL MODULE INFORMATION", "lsmod >> %s" },
		{ "LINUX SYSTEM MEMORY INFORMATION", "cat /proc/meminfo >> %s" },
		{ "SYSTEM INTERRUPT INFORMATION", "cat /proc/interrupts >> %s" },
		{ "CPU INFORMATION", "cat /proc/cpuinfo >> %s" },
		{ "IO MEMORY MAP INFORMATION", "cat /proc/iomem >> %s" },
		{ "MAJOR NUMBER AND DEVICE GROUP", "cat /proc/devices >> %s" },
		{ "KERNEL DMESG", "dmesg >> %s" },
		{ "/VAR/LOG/MESSAGES", "cat /var/log/messages >> %s" }
	};

	for (i = 0; i < (int)(ARRAY_SIZE(cmdArray)); i++) {
		fpOSConfig = fopen(file_name, "a+");
		if (fpOSConfig) {
			fprintf(fpOSConfig,
				"\n\n\n\n%s\n-----------------------------------------------\n",
				cmdArray[i].strcmdHeader);
			fclose(fpOSConfig);
			fpOSConfig = NULL;
		}
		snprintf(strBuffer, sizeof(strBuffer) - 1,
				 cmdArray[i].strCommand, file_name);
		if (system(strBuffer))
			fprintf(stderr, "Failed to send \"%s\"\n", strBuffer);
	}
}
