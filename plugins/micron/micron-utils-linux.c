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
