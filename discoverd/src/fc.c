// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <daemon-util/log.h>
#include <shared/cleanup-util.h>

#include "fc.h"
#include "sysfs.h"

#define FC_NVME_DISCOVERY_PATH \
	"/sys/class/fc/fc_udev_device/nvme_discovery"

int fc_kickstart(void)
{
	__cleanup_free char *path = sysfs_path(FC_NVME_DISCOVERY_PATH);
	int fd, ret;

	if (!path)
		return -ENOMEM;

	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0) {
		if (errno == ENOENT)
			return 0; // no FC HBA present — not an error
		log_err("%s: open(%s): %s", __func__, path, strerror(errno));
		return -errno;
	}

	ret = write(fd, "add", 3);
	if (ret < 0) {
		log_err("%s: write: %s", __func__, strerror(errno));
		close(fd);
		return -errno;
	}

	close(fd);
	return 0;
}
