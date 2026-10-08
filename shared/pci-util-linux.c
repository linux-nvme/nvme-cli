// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE LLC
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#include "cleanup-util.h"
#include "pci-util.h"

int shr_pci_open_class_config(const char *dev_class_dir, int flags)
{
	__cleanup_free char *config_path = NULL;
	int fd;

	if (asprintf(&config_path, "%s/device/config", dev_class_dir) < 0)
		return -ENOMEM;

	fd = open(config_path, flags);
	if (fd < 0)
		return -errno;

	return fd;
}

int shr_pci_config_read32(int fd, unsigned int offset, uint32_t *val)
{
	unsigned char buf[4];
	ssize_t n;

	n = pread(fd, buf, sizeof(buf), offset);
	if (n < 0)
		return -errno;
	if (n != (ssize_t)sizeof(buf))
		return -EIO;

	*val = (uint32_t)buf[0] | (uint32_t)buf[1] << 8 |
	       (uint32_t)buf[2] << 16 | (uint32_t)buf[3] << 24;
	return 0;
}

int shr_pci_config_write32(int fd, unsigned int offset, uint32_t val)
{
	unsigned char buf[4] = {
		val & 0xff, (val >> 8) & 0xff,
		(val >> 16) & 0xff, (val >> 24) & 0xff,
	};
	ssize_t n;

	n = pwrite(fd, buf, sizeof(buf), offset);
	if (n < 0)
		return -errno;
	if (n != (ssize_t)sizeof(buf))
		return -EIO;

	return 0;
}

int shr_pci_find_ext_cap(int fd, uint16_t cap_id)
{
	unsigned int offset = 0x100;
	int i, ret;

	/*
	 * The list can't legally hold more entries than there is config
	 * space to hold them in; bound the walk so a malformed or
	 * adversarial header can't turn this into an infinite loop.
	 */
	for (i = 0; offset && i < 256; i++) {
		uint32_t header;

		ret = shr_pci_config_read32(fd, offset, &header);
		if (ret)
			return ret;

		/* An all-zero or all-ones header means nothing is there. */
		if (header == 0 || header == 0xffffffff)
			break;

		if ((header & 0xffff) == cap_id)
			return (int)offset;

		offset = (header >> 20) & 0xfff;
	}

	return -ENOENT;
}
