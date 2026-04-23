// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2025 Micron Technology, Inc.
 *
 * Authors: Brandon Capener <bcapener@micron.com>
 */

#include "private.h"
#include "nvme/lib.h"
#include "compiler-attributes.h"


static time_t __filetime_to_time_t(const FILETIME *ft)
{
	ULARGE_INTEGER ull;

	ull.LowPart = ft->dwLowDateTime;
	ull.HighPart = ft->dwHighDateTime;

	/*
	 * Windows FILETIME is in 100-nanosecond intervals since Jan 1, 1601.
	 * Convert to seconds and adjust to Unix epoch (seconds since Jan 1, 1970).
	 */
	return (time_t)((ull.QuadPart / 10000000ULL) - 11644473600ULL);
}

/* fstat implementation for Windows device HANDLE */
static int __handle_fstat(HANDLE fd, struct stat *buf)
{
	BY_HANDLE_FILE_INFORMATION file_info;
	DWORD file_type;

	if (!buf) {
		errno = EINVAL;
		return -1;
	}

	/* Check for invalid handle */
	if (fd == INVALID_HANDLE_VALUE || fd == NULL) {
		errno = EBADF;
		return -1;
	}

	/*
	 * GetFileInformationByHandle() does not work for all device HANDLEs
	 * (e.g. raw \\\\.\\PhysicalDriveN). For those, fall back to file type.
	 */
	if (!GetFileInformationByHandle(fd, &file_info)) {
		file_type = GetFileType(fd);
		if (file_type == FILE_TYPE_DISK || file_type == FILE_TYPE_CHAR) {
			memset(buf, 0, sizeof(*buf));
			buf->st_mode = S_IFBLK | 0600;
			buf->st_nlink = 1;
			return 0;
		}

		errno = EBADF;
		return -1;
	}

	/* Fill in the stat structure */
	memset(buf, 0, sizeof(*buf));

	/* Convert Windows file attributes to stat mode */
	if (file_info.dwFileAttributes & FILE_ATTRIBUTE_DEVICE)
		/* Mark as block device for libnvme_transport_handle_is_ns. */
		buf->st_mode = S_IFBLK | 0600;
	else if (file_info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		buf->st_mode = S_IFDIR | 0755;
	else
		buf->st_mode = S_IFREG | 0644;

	/* File size */
	buf->st_size = (((off_t)file_info.nFileSizeHigh << 32)
					| file_info.nFileSizeLow);

	/* Number of hard links */
	buf->st_nlink = file_info.nNumberOfLinks;

	/* Convert FILETIME to time_t for timestamps */
	buf->st_mtime = __filetime_to_time_t(&file_info.ftLastWriteTime);
	buf->st_atime = __filetime_to_time_t(&file_info.ftLastAccessTime);
	buf->st_ctime = __filetime_to_time_t(&file_info.ftCreationTime);

	return 0;
}

static int __libnvme_transport_handle_open_direct(struct libnvme_transport_handle *hdl, const char *name)
{
	char device_path[MAX_PATH];

	/* Parse and open direct device */
	hdl->type = LIBNVME_TRANSPORT_HANDLE_TYPE_DIRECT;

	/* Convert device name to Windows path */
	if (strncmp(name, "\\\\.\\", 4) == 0) {
		/* Already a Windows device path */
		snprintf(device_path, sizeof(device_path), "%s", name);
	} else {
		/* Assume it's a device name, prepend Windows device prefix */
		/* PhysicalDriveN format */
		snprintf(device_path, sizeof(device_path), "\\\\.\\%s", name);
	}

	hdl->fd = CreateFile(device_path,
		GENERIC_READ,
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

	__handle_fstat(hdl->fd, &hdl->stat);

	/* Windows doesn't distinguish 32/64-bit ioctl, assume 64-bit capable */
	hdl->ioctl_admin64 = true;
	hdl->ioctl_io64 = true;

	return 0;
}

/* Transport handle operations (linux.c) */
__public int libnvme_open(struct libnvme_global_ctx *ctx, const char *name,
	      struct libnvme_transport_handle **hdlp)
{
	struct libnvme_transport_handle *hdl;
	int ret;

	hdl = __libnvme_create_transport_handle(ctx);
	if (!hdl)
		return -ENOMEM;

	hdl->name = strdup(name);
	if (!hdl->name) {
		free(hdl);
		return -ENOMEM;
	}

	/* Handle test devices */
	if (!strncmp(name, "NVME_TEST_FD", 12)) {
		hdl->type = LIBNVME_TRANSPORT_HANDLE_TYPE_DIRECT;
		hdl->fd = LIBNVME_TEST_FD;

		if (!strcmp(name, "NVME_TEST_FD64"))
			hdl->ioctl_admin64 = true;

		*hdlp = hdl;
		return 0;
	}

	/* MI transport not supported on Windows */
	if (!strncmp(name, "mctp:", strlen("mctp:"))) {
		libnvme_close(hdl);
		return -ENOTSUP;
	}

	ret = __libnvme_transport_handle_open_direct(hdl, name);

	if (ret) {
		libnvme_close(hdl);
		return ret;
	}

	*hdlp = hdl;

	return 0;
}

__public void libnvme_close(struct libnvme_transport_handle *hdl)
{
	bool is_test_fd;

	if (!hdl)
		return;

	is_test_fd = hdl->type == LIBNVME_TRANSPORT_HANDLE_TYPE_DIRECT &&
		hdl->fd == LIBNVME_TEST_FD &&
		!strncmp(hdl->name, "NVME_TEST_FD", 12);

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
