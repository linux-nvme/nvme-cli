// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(_WIN32)
#include <direct.h>
#define mkdir(path, mode) ((void)(mode), _mkdir(path))
#endif

#include "fs-util.h"

int mkdir_p(const char *path, mode_t mode)
{
	char buf[PATH_MAX];
	char *p;
	size_t len;

	len = strlen(path);
	if (len >= sizeof(buf))
		return -ENAMETOOLONG;
	memcpy(buf, path, len + 1);
	if (len && buf[len - 1] == '/')
		buf[len - 1] = '\0';

	for (p = buf + 1; *p; p++) {
		if (*p != '/')
			continue;
		*p = '\0';
		if (mkdir(buf, mode) < 0 && errno != EEXIST)
			return -errno;
		*p = '/';
	}
	return mkdir(buf, mode) == 0 || errno == EEXIST ? 0 : -errno;
}

#if defined(_WIN32)
int mkstemp_cloexec(char *template)
{
	return -ENOSYS;
}
#else
int mkstemp_cloexec(char *template)
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
#endif

#if defined(_WIN32)
void fsync_dir(const char *path)
{
}
#else
void fsync_dir(const char *path)
{
	int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);

	if (fd >= 0) {
		fsync(fd);
		close(fd);
	}
}
#endif

char *path_basename(const char *path)
{
	char *p = (char *)strrchr(path, '/');

	return p ? p + 1 : (char *)path;
}
