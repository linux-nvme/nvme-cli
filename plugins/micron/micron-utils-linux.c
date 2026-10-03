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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/klog.h>
#include <sys/utsname.h>

#include <libnvme.h>

#include <ccan/array_size/array_size.h>

#include <shared/fs-util.h>
#include <shared/io-util.h>
#include <shared/pci-util.h>

#include "micron-utils.h"
#include "nvme-print.h"
#include "src/cleanup.h"
#include "src/global-ctx.h"

/*
 * Resolves ctrl_name (e.g. "nvme0") to its PCI AER capability.
 * Return: 0 on success (with *out_fd and *out_aer_offset set), negative
 * errno otherwise.
 */
static int open_aer_cap(const char *ctrl_name, int flags,
	int *out_fd, unsigned int *out_aer_offset)
{
	__cleanup_free char *ctrl_dir = NULL;
	__cleanup_fd int fd = -1;
	int offset;
	int ret;

	ret = nvme_sysfs_ctrl_path(ctrl_name, &ctrl_dir);
	if (ret)
		return ret;

	fd = shr_pci_open_class_config(ctrl_dir, flags);
	if (fd < 0) {
		nvme_show_perror("%s/device/config", ctrl_dir);
		return fd;
	}

	offset = shr_pci_find_ext_cap(fd, SHR_PCI_EXT_CAP_ID_AER);
	if (offset < 0) {
		nvme_show_error("Device has no PCIe AER capability");
		return offset;
	}

	*out_fd = fd;
	fd = -1; /* ownership moves to the caller */
	*out_aer_offset = (unsigned int)offset;
	return 0;
}

int micron_get_pcie_aer_errors(struct libnvme_transport_handle *hdl,
	__u32 *correctable_errors, __u32 *uncorrectable_errors)
{
	__cleanup_free char *ctrl_name = micron_get_ctrl_name(hdl);
	__cleanup_fd int fd = -1;
	unsigned int aer;
	int ret;

	if (!ctrl_name)
		return -EINVAL;

	ret = open_aer_cap(ctrl_name, O_RDONLY, &fd, &aer);
	if (ret)
		return ret;

	ret = shr_pci_config_read32(fd, aer + SHR_PCI_AER_COR_STATUS_OFF,
				     correctable_errors);
	if (ret) {
		nvme_show_error("Failed to retrieve error count");
		return ret;
	}

	ret = shr_pci_config_read32(fd, aer + SHR_PCI_AER_UNCOR_STATUS_OFF,
				     uncorrectable_errors);
	if (ret) {
		nvme_show_error("Failed to retrieve error count");
		return ret;
	}

	return 0;
}

int micron_clear_pcie_aer_correctable_errors(
	struct libnvme_transport_handle *hdl)
{
	__cleanup_free char *ctrl_name = micron_get_ctrl_name(hdl);
	__cleanup_fd int fd = -1;
	unsigned int aer;
	__u32 correctable;
	int ret;

	if (!ctrl_name)
		return -EINVAL;

	ret = open_aer_cap(ctrl_name, O_RDWR, &fd, &aer);
	if (ret)
		return ret;

	/* Writing all 1s clears the write-1-to-clear status bits. */
	ret = shr_pci_config_write32(fd, aer + SHR_PCI_AER_COR_STATUS_OFF,
				      0xffffffff);
	if (ret) {
		nvme_show_error("Failed to clear error count");
		return ret;
	}

	ret = shr_pci_config_read32(fd, aer + SHR_PCI_AER_COR_STATUS_OFF,
				     &correctable);
	if (ret) {
		nvme_show_error("Failed to retrieve error count");
		return ret;
	}
	nvme_show_verbose_result("Device correctable errors cleared!");
	nvme_show_result("Device correctable errors detected: %08x",
			  correctable);
	return 0;
}

/* Generous but bounded: this is a human-readable support dump, not a
 * guarantee of capturing every byte of a possibly huge /proc file or log.
 */
#define OS_CONFIG_CAPTURE_MAX (1 << 20)

static int append_file_contents(int out_fd, const char *path)
{
	__cleanup_fd int fd = open(path, O_RDONLY);
	__cleanup_free char *buf = NULL;
	int ret;

	if (fd < 0)
		return -errno;

	buf = malloc(OS_CONFIG_CAPTURE_MAX);
	if (!buf)
		return -ENOMEM;

	ret = shr_read_all(fd, buf, OS_CONFIG_CAPTURE_MAX);
	if (ret)
		return ret;

	return shr_write_all(out_fd, buf, strlen(buf));
}

static int append_uname(int out_fd)
{
	struct utsname uts;
	char line[512];
	int n;

	if (uname(&uts))
		return -errno;

	n = snprintf(line, sizeof(line), "%s %s %s %s %s\n",
		     uts.sysname, uts.nodename, uts.release, uts.version,
		     uts.machine);
	if (n < 0)
		return -errno;
	if ((size_t)n >= sizeof(line))
		n = sizeof(line) - 1;

	return shr_write_all(out_fd, line, (size_t)n);
}

/*
 * man 2 syslog documents these action numbers; <sys/klog.h> declares
 * klogctl() but, oddly, not the actions it takes.
 */
#define SYSLOG_ACTION_READ_ALL     3
#define SYSLOG_ACTION_SIZE_BUFFER 10

static int append_dmesg(int out_fd)
{
	__cleanup_free char *buf = NULL;
	int len;

	len = klogctl(SYSLOG_ACTION_SIZE_BUFFER, NULL, 0);
	if (len <= 0 || len > OS_CONFIG_CAPTURE_MAX)
		len = OS_CONFIG_CAPTURE_MAX;

	buf = malloc(len);
	if (!buf)
		return -ENOMEM;

	len = klogctl(SYSLOG_ACTION_READ_ALL, buf, len);
	if (len < 0)
		return -errno;

	return shr_write_all(out_fd, buf, (size_t)len);
}

enum os_config_kind {
	OS_CONFIG_FILE,
	OS_CONFIG_UNAME,
	OS_CONFIG_DMESG,
};

struct os_config_item {
	const char *header;
	enum os_config_kind kind;
	const char *path;
};

static const struct os_config_item os_config_items[] = {
	{ "SYSTEM INFORMATION", OS_CONFIG_UNAME, NULL },
	{ "LINUX KERNEL MODULE INFORMATION", OS_CONFIG_FILE, "/proc/modules" },
	{ "LINUX SYSTEM MEMORY INFORMATION", OS_CONFIG_FILE, "/proc/meminfo" },
	{ "SYSTEM INTERRUPT INFORMATION", OS_CONFIG_FILE, "/proc/interrupts" },
	{ "CPU INFORMATION", OS_CONFIG_FILE, "/proc/cpuinfo" },
	{ "IO MEMORY MAP INFORMATION", OS_CONFIG_FILE, "/proc/iomem" },
	{ "MAJOR NUMBER AND DEVICE GROUP", OS_CONFIG_FILE, "/proc/devices" },
	{ "KERNEL DMESG", OS_CONFIG_DMESG, NULL },
	{ "/VAR/LOG/MESSAGES", OS_CONFIG_FILE, "/var/log/messages" },
};

void micron_write_os_config_to_file(const char *file_name)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(os_config_items); i++) {
		const struct os_config_item *item = &os_config_items[i];
		__cleanup_fd int out_fd = -1;
		FILE *header_file;
		int ret;

		header_file = fopen(file_name, "a+");
		if (header_file) {
			fprintf(header_file,
				"\n\n\n\n%s\n-----------------------------------------------\n",
				item->header);
			fclose(header_file);
		}

		out_fd = shr_open_rawdata(file_name,
					   O_WRONLY | O_CREAT | O_APPEND, 0644);
		if (out_fd < 0) {
			nvme_show_error("Failed to open \"%s\": %s",
				file_name, strerror(errno));
			continue;
		}

		switch (item->kind) {
		case OS_CONFIG_UNAME:
			ret = append_uname(out_fd);
			break;
		case OS_CONFIG_DMESG:
			ret = append_dmesg(out_fd);
			break;
		case OS_CONFIG_FILE:
		default:
			ret = append_file_contents(out_fd, item->path);
			break;
		}
		if (ret)
			nvme_show_error("Failed to capture \"%s\": %s",
				item->header, strerror(-ret));
	}
}

void micron_get_os_string(char *buf, size_t len)
{
	struct utsname un;

	if (!buf || !len)
		return;
	buf[0] = '\0';

	if (uname(&un))
		return;

	snprintf(buf, len, "%s %s %s", un.sysname, un.release, un.machine);
}
