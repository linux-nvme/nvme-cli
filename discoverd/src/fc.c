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

#include "fc.h"
#include "log.h"

#define FC_NVME_DISCOVERY_PATH \
	"/sys/class/fc/fc_udev_device/nvme_discovery"

int fc_kickstart(void)
{
	int fd, ret;

	fd = open(FC_NVME_DISCOVERY_PATH, O_WRONLY | O_CLOEXEC);
	if (fd < 0) {
		if (errno == ENOENT)
			return 0; // no FC HBA present — not an error
		disc_err("%s: open(%s): %s", __func__,
			 FC_NVME_DISCOVERY_PATH, strerror(errno));
		return -errno;
	}

	ret = write(fd, "add", 3);
	if (ret < 0) {
		disc_err("%s: write: %s", __func__, strerror(errno));
		close(fd);
		return -errno;
	}

	close(fd);
	return 0;
}
