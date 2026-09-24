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

#include <libnvme.h>

#include <shared/compiler-attributes-util.h>

#include "cleanup.h"
#include "global-ctx.h"
#include "nvme-print.h"

static int read_pci_attr(const char *dir, const char *attr, __u32 *out)
{
	__cleanup_free char *path = NULL;
	char buf[32] = { '\0' };
	char *endptr;
	int len, fd, ret;
	unsigned long val;

	if (!out)
		return 0;

	if (asprintf(&path, "%s/device/%s", dir, attr) < 0)
		return -ENOMEM;

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

int __nvme_get_pci_id_source(__shr_unused struct libnvme_global_ctx *ctx,
		const char *ctrl_name, char **source)
{
	return nvme_sysfs_ctrl_path(ctrl_name, source);
}

int __nvme_get_pci_ids(const char *source,
		__u32 *vid, __u32 *did,
		__u32 *subsys_vid, __u32 *subsys_did,
		__u32 *class_code)
{
	int res, ret = 0;

	/* On Linux, source is the controller's sysfs directory. */

	/* Attempt all reads. Return the first error encountered, if any. */
	ret = read_pci_attr(source, "vendor", vid);
	res = read_pci_attr(source, "device", did);
	ret = ret ? ret : res;
	res = read_pci_attr(source, "subsystem_vendor", subsys_vid);
	ret = ret ? ret : res;
	res = read_pci_attr(source, "subsystem_device", subsys_did);
	ret = ret ? ret : res;
	res = read_pci_attr(source, "class", class_code);
	ret = ret ? ret : res;

	return ret;
}
