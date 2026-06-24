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
#include "cleanup.h"
#include "ioctl.h"
#include "lib.h"
#include "private.h"
#include "private-ctrl-map.h"
#include "util.h"

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
	struct libnvme_transport_handle *hdl;
	__cleanup_free char *mapped_name = NULL;
	int ret;
	const struct ctrl_map_entry *ctrl_entry;

	if (strstr(name, "/dev/"))
		name = libnvme_basename(name);

	ctrl_entry = libnvme_ctrl_map_lookup(name);
	if (ctrl_entry) {
		const char *n_pos = strchr(name + 4, 'n');
		__u32 nsid;

		if (n_pos && sscanf(n_pos, "n%u", &nsid) == 1) {
			ret = libnvme_ctrl_map_entry_map_nsid_to_drive_path(
				ctrl_entry, nsid, &mapped_name);
		} else {
			ret = libnvme_ctrl_map_entry_get_ctrl_path(
				ctrl_entry, &mapped_name);
		}
		if (ret)
			return ret;
	}

	hdl = __libnvme_create_transport_handle(ctx);
	if (!hdl)
		return -ENOMEM;

	/* Handle test devices */
	if (!strncmp(name, "NVME_TEST_FD", 12)) {
		hdl->name = strdup(name);
		if (!hdl->name) {
			free(hdl);
			return -ENOMEM;
		}

		hdl->type = LIBNVME_TRANSPORT_HANDLE_TYPE_DIRECT;
		hdl->fd = LIBNVME_TEST_FD;

		if (!strcmp(name, "NVME_TEST_FD64"))
			hdl->ioctl_admin_state = IOCTL_STATE_IOCTL64;

		*hdlp = hdl;
		return 0;
	}

	/* MI transport not supported on Windows */
	if (!strncmp(name, "mctp:", strlen("mctp:"))) {
		libnvme_close(hdl);
		return -ENOTSUP;
	}

	ret = __libnvme_transport_handle_open_direct(hdl, mapped_name ?
		mapped_name : name);

	free(mapped_name);
	mapped_name = NULL;

	if (ret) {
		libnvme_close(hdl);
		return ret;
	}

	/* For PhysicalDrive names, create the nvmeXnY-style name. */
	ctrl_entry = libnvme_ctrl_map_lookup_by_physdrive(name);
	if (ctrl_entry) {
		__u32 nsid;

		if (libnvme_get_nsid(hdl, &nsid) == 0 &&
		    asprintf(&mapped_name, "%sn%d",
			     libnvme_ctrl_map_entry_get_ctrl_name(ctrl_entry),
			     nsid) > 0)
			name = mapped_name;
	}

	/* Store the nvmeX or nvmeXnY-style name in hdl->name. */
	hdl->name = strdup(name);
	if (!hdl->name) {
		libnvme_close(hdl);
		return -ENOMEM;
	}

	*hdlp = hdl;

	return 0;
}

__libnvme_public void libnvme_close(struct libnvme_transport_handle *hdl)
{
	bool is_test_fd;

	if (!hdl)
		return;

	is_test_fd = hdl->type == LIBNVME_TRANSPORT_HANDLE_TYPE_DIRECT &&
		hdl->fd == LIBNVME_TEST_FD &&
		hdl->name && !strncmp(hdl->name, "NVME_TEST_FD", 12);

	free(hdl->name);

	switch (hdl->type) {
	case LIBNVME_TRANSPORT_HANDLE_TYPE_DIRECT:
		/* Close Windows HANDLE if valid */
		if (!is_test_fd && hdl->fd && hdl->fd != INVALID_HANDLE_VALUE)
			CloseHandle(hdl->fd);
		free(hdl);
		break;
	case LIBNVME_TRANSPORT_HANDLE_TYPE_MI:
		/* MI not supported on Windows */
		free(hdl);
		break;
	case LIBNVME_TRANSPORT_HANDLE_TYPE_UNKNOWN:
		free(hdl);
		break;
	}
}
