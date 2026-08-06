// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2026 Micron Technology, Inc.
 *
 * Authors: Broc Going <bgoing@micron.com>
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <nvme/types.h>

#include "nvme-print.h"

static int read_pci_attr(const char *dir, const char *attr, __u32 *out)
{
	char path[512];
	char buf[32] = { '\0' };
	char *endptr;
	int len, fd, ret;
	unsigned long val;

	if (!out)
		return 0;

	snprintf(path, sizeof(path), "%s/device/%s", dir, attr);

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		ret = -errno;
		if (errno != ENOENT)
			nvme_show_error("Failed to open %s: %s", path,
				libnvme_strerror(errno));
		return ret;
	}

	len = read(fd, buf, sizeof(buf) - 1);
	if (len < 0) {
		ret = -errno;
		nvme_show_error("Failed to read %s: %s", path,
			libnvme_strerror(errno));
		close(fd);
		return ret;
	}
	close(fd);

	val = strtoul(buf, &endptr, 16);
	if (endptr == buf) {
		nvme_show_error("Failed to parse hex value from %s: %s",
			path, buf);
		return -EINVAL;
	}
	*out = (__u32)val;

	return 0;
}

int __nvme_get_sysfs_dir(__attribute__((__unused__)) struct libnvme_global_ctx *ctx,
		const char *ctrl_name, char **sysfs_dir)
{
	if (asprintf(sysfs_dir, "/sys/class/nvme/%s", ctrl_name) < 0)
		return -ENOMEM;

	return 0;
}

int __nvme_get_pci_ids(const char *sysfs_dir,
		__u32 *vid, __u32 *did,
		__u32 *subsys_vid, __u32 *subsys_did,
		__u32 *class_code)
{
	int res, ret = 0;

	/* Attempt all reads. Return the first error encountered, if any. */
	ret = read_pci_attr(sysfs_dir, "vendor", vid);
	res = read_pci_attr(sysfs_dir, "device", did);
	ret = ret ? ret : res;
	res = read_pci_attr(sysfs_dir, "subsystem_vendor", subsys_vid);
	ret = ret ? ret : res;
	res = read_pci_attr(sysfs_dir, "subsystem_device", subsys_did);
	ret = ret ? ret : res;
	res = read_pci_attr(sysfs_dir, "class", class_code);
	ret = ret ? ret : res;

	return ret;
}
