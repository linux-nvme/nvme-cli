// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2025 Micron Technology, Inc.
 *
 * Authors: Brandon Capener <bcapener@micron.com>
 */

#include "private.h"
#include "nvme/linux.h"


static int __nvme_transport_handle_open_direct(struct nvme_transport_handle *hdl, const char *name)
{
	char device_path[MAX_PATH];
	HANDLE h;

	/* Parse and open direct device */
	hdl->type = NVME_TRANSPORT_HANDLE_TYPE_DIRECT;

	/* Convert device name to Windows path */
	if (strncmp(name, "\\\\.\\", 4) == 0) {
		/* Already a Windows device path */
		snprintf(device_path, sizeof(device_path), "%s", name);
	} else {
		/* Assume it's a device name, prepend Windows device prefix */
		/* PhysicalDriveN format */
		snprintf(device_path, sizeof(device_path), "\\\\.\\%s", name);
	}

	h = CreateFile(device_path,
		GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		NULL,
		OPEN_EXISTING,
		0,
		NULL);

	if (h == INVALID_HANDLE_VALUE) {
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

	hdl->fd = h;

	nvme_fstat(hdl->fd, &hdl->stat);

	/* Windows doesn't distinguish 32/64-bit ioctl, assume 64-bit capable */
	hdl->ioctl64 = true;

	return 0;
}

/* Transport handle operations (linux.c) */
int nvme_open(struct nvme_global_ctx *ctx, const char *name,
	      struct nvme_transport_handle **hdlp)
{
	struct nvme_transport_handle *hdl;
	int ret;

	hdl = __nvme_create_transport_handle(ctx);
	if (!hdl)
		return -ENOMEM;

	hdl->name = strdup(name);
	if (!hdl->name) {
		free(hdl);
		return -ENOMEM;
	}

	/* Handle test devices */
	if (!strncmp(name, "NVME_TEST_FD", 12)) {
		hdl->type = NVME_TRANSPORT_HANDLE_TYPE_DIRECT;
		hdl->fd = TEST_FD;

		if (!strcmp(name, "NVME_TEST_FD64"))
			hdl->ioctl64 = true;

		*hdlp = hdl;
		return 0;
	}

	/* MI transport not supported on Windows */
	if (!strncmp(name, "mctp:", strlen("mctp:"))) {
		nvme_close(hdl);
		return -ENOTSUP;
	} else {
		ret = __nvme_transport_handle_open_direct(hdl, name);
	}

	if (ret) {
		nvme_close(hdl);
		return ret;
	}

	*hdlp = hdl;

	return 0;
}

void nvme_close(struct nvme_transport_handle *hdl)
{
	if (!hdl)
		return;

	free(hdl->name);

	switch (hdl->type) {
	case NVME_TRANSPORT_HANDLE_TYPE_DIRECT:
		/* Close Windows HANDLE if valid */
		if (hdl->fd && hdl->fd != TEST_FD)
			CloseHandle(hdl->fd);
		free(hdl);
		break;
	case NVME_TRANSPORT_HANDLE_TYPE_MI:
		/* MI not supported on Windows */
		free(hdl);
		break;
	case NVME_TRANSPORT_HANDLE_TYPE_UNKNOWN:
		free(hdl);
		break;
	}
}

/* Platform-specific fstat wrapper for nvme_fd_t */
int nvme_fstat(nvme_fd_t fd, struct stat *buf)
{
	BY_HANDLE_FILE_INFORMATION file_info;
	ULARGE_INTEGER ull;

	if (!buf) {
		errno = EINVAL;
		return -1;
	}

	/* Check for invalid handle */
	if (fd == INVALID_HANDLE_VALUE || fd == NULL) {
		errno = EBADF;
		return -1;
	}

	/* Get file information from Windows handle */
	if (!GetFileInformationByHandle(fd, &file_info)) {
		errno = EBADF;
		return -1;
	}

	/* Fill in the stat structure */
	memset(buf, 0, sizeof(*buf));

	/* Convert Windows file attributes to stat mode */
	if (file_info.dwFileAttributes & FILE_ATTRIBUTE_DEVICE)
		/* Windows device files should be marked as block devices */
		/* This is used by nvme_verify_chr to check device type */
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
	/* Windows FILETIME is 100-nanosecond intervals since Jan 1, 1601 */
	/* Unix time_t is seconds since Jan 1, 1970 */
	ull.LowPart = file_info.ftLastWriteTime.dwLowDateTime;
	ull.HighPart = file_info.ftLastWriteTime.dwHighDateTime;
	buf->st_mtime = (time_t)((ull.QuadPart / 10000000ULL) - 11644473600ULL);

	ull.LowPart = file_info.ftLastAccessTime.dwLowDateTime;
	ull.HighPart = file_info.ftLastAccessTime.dwHighDateTime;
	buf->st_atime = (time_t)((ull.QuadPart / 10000000ULL) - 11644473600ULL);

	ull.LowPart = file_info.ftCreationTime.dwLowDateTime;
	ull.HighPart = file_info.ftCreationTime.dwHighDateTime;
	buf->st_ctime = (time_t)((ull.QuadPart / 10000000ULL) - 11644473600ULL);

	return 0;
}
