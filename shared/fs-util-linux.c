// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "fs-util.h"

const char *shr_dev_null(void)
{
	return "/dev/null";
}

int shr_fsync(int fd)
{
	if (fsync(fd) < 0)
		return -errno;
	return 0;
}

int shr_getpagesize(void)
{
	return getpagesize();
}

int shr_mkdir(const char *path, mode_t mode)
{
	if (mkdir(path, mode) < 0)
		return -errno;
	return 0;
}

int shr_mkstemp(char *template)
{
	int fd;

	/*
	 * mkostemp() sets O_CLOEXEC atomically but its glibc declaration is
	 * gated behind _GNU_SOURCE; fall back to mkstemp() + fcntl() where
	 * _GNU_SOURCE is not defined (e.g. the musl-style CI build).
	 */
#ifdef _GNU_SOURCE
	fd = mkostemp(template, O_CLOEXEC);
	if (fd < 0)
		return -errno;
#else
	fd = mkstemp(template);
	if (fd < 0)
		return -errno;
	if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
		int e = -errno;

		close(fd);
		unlink(template);
		return e;
	}
#endif
	return fd;
}

void shr_fsync_dir(const char *path)
{
	int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);

	if (fd >= 0) {
		fsync(fd);
		close(fd);
	}
}

int shr_unlink(const char *path)
{
	if (unlink(path) < 0)
		return -errno;
	return 0;
}

int shr_rmdir(const char *path)
{
	if (rmdir(path) < 0)
		return -errno;
	return 0;
}

bool shr_fd_is_open(int fd)
{
	return fcntl(fd, F_GETFD) != -1;
}

int shr_close(int fd)
{
	if (close(fd) < 0)
		return -errno;
	return 0;
}

char *shr_dirname(char *path)
{
	return dirname(path);
}
