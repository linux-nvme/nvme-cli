// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 Micron Technology, Inc.
 *
 * Authors: Brandon Capener <bcapener@micron.com>
 */

#include <errno.h>
#include <stdio.h>
#include <strings.h>

#include "cleanup.h"
#include "compiler-attributes.h"
#include "private.h"

static bool __is_controller_path(const char *device_path)
{
	/*
	 * Controller device paths point to the PCI device, and begin with
	 * "\\?\pci". Namespace device paths point to the disk device and begin
	 * "\\.\PhysicalDrive".
	 */
	return strncasecmp(device_path, "\\\\?\\pci", 7) == 0;
}

static __libnvme_unused int __libnvme_transport_handle_open_direct(
	struct libnvme_transport_handle *hdl, const char *name)
{
	__cleanup_free char *device_path = NULL;

	/* Parse and open direct device */
	hdl->type = LIBNVME_TRANSPORT_HANDLE_TYPE_DIRECT;

	/* Convert device name to Windows path */
	if (strncmp(name, "\\\\.\\", 4) == 0
	    || strncmp(name, "\\\\?\\", 4) == 0) {
		/* Already a Windows device path */
		device_path = strdup(name);
		if (!device_path)
			return -ENOMEM;
	} else {
		/* Assume it's a device name, prepend Windows device prefix */
		/* PhysicalDriveN format */
		size_t len = strlen(name) + 5;
		int ret;

		device_path = malloc(len);
		if (!device_path)
			return -ENOMEM;
		ret = snprintf(device_path, len, "\\\\.\\%s", name);
		if (ret < 0 || (size_t)ret >= len)
			return -EINVAL;
	}

	hdl->fd = CreateFileA(device_path,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		NULL,
		OPEN_EXISTING,
		0,
		NULL);

	if (hdl->fd == INVALID_HANDLE_VALUE) {
		int err = GetLastError();
		/* Map Windows error to errno */
		switch (err) {
		case ERROR_FILE_NOT_FOUND:
		case ERROR_PATH_NOT_FOUND:
			return -ENOENT;
		case ERROR_ACCESS_DENIED:
			return -EACCES;
		default:
			return -EIO;
		}
	}

	/* Mark st_mode based on device type for compatibility with Linux. */
	memset(&hdl->stat, 0, sizeof(hdl->stat));
	hdl->stat.st_mode =
		(__is_controller_path(device_path) ? S_IFCHR : S_IFBLK) | 0600;
	hdl->stat.st_nlink = 1;

	/* Windows doesn't distinguish 32/64-bit ioctl, always 64-bit capable */
	hdl->ioctl_admin_state = IOCTL_STATE_IOCTL64;
	hdl->ioctl_io_state = IOCTL_STATE_IOCTL64;

	return 0;
}

__libnvme_public int libnvme_open(struct libnvme_global_ctx *ctx,
				  const char *name,
				  struct libnvme_transport_handle **hdlp)
{
	return -ENOTSUP;
}

__libnvme_public void libnvme_close(struct libnvme_transport_handle *hdl)
{
}
