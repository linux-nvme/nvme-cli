// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <direct.h>
#include <errno.h>
#include <fcntl.h>
#include <io.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <windows.h>

#include "cleanup-util.h"
#include "compiler-attributes-util.h"
#include "fs-util.h"

#ifndef O_BINARY
#define O_BINARY 0
#endif
#ifndef O_NOINHERIT
#define O_NOINHERIT 0
#endif

int shr_mkdir(const char *path, __shr_unused mode_t mode)
{
	if (_mkdir(path) < 0)
		return -errno;
	return 0;
}

int shr_mkstemp(char *template)
{
	static const char chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	int len;
	int i, attempts;
	unsigned int seed;

	if (!template) {
		errno = EINVAL;
		return -EINVAL;
	}

	len = strlen(template);
	if (len < 6 || strcmp(&template[len - 6], "XXXXXX") != 0) {
		errno = EINVAL;
		return -EINVAL;
	}

	seed = GetTickCount() ^ GetCurrentThreadId() ^ GetCurrentProcessId();

	for (attempts = 0; attempts < 1000; attempts++) {
		unsigned int val = seed;

		for (i = 0; i < 6; i++) {
			val = val * 1103515245 + 12345;
			template[len - 6 + i] =
				chars[val % (sizeof(chars) - 1)];
		}
		seed += val;

		int fd = open(template, O_RDWR | O_CREAT | O_EXCL |
			O_BINARY | O_NOINHERIT, 0600);
		if (fd >= 0)
			return fd;

		if (errno != EEXIST)
			return -errno;
	}

	errno = EEXIST;
	return -EEXIST;
}

void shr_fsync_dir(const char *path)
{
}

int shr_unlink(const char *path)
{
	if (_unlink(path) < 0)
		return -errno;
	return 0;
}

int shr_rmdir(const char *path)
{
	if (_rmdir(path) < 0)
		return -errno;
	return 0;
}

bool shr_fd_is_open(int fd)
{
	return _get_osfhandle(fd) != -1;
}

int shr_close(int fd)
{
	if (_close(fd) < 0)
		return -errno;
	return 0;
}

const char *shr_dev_null(void)
{
	return "NUL";
}

int shr_fsync(int fd)
{
	if (_commit(fd) < 0)
		return -errno;
	return 0;
}

int shr_getpagesize(void)
{
	SYSTEM_INFO si;

	GetSystemInfo(&si);
	return si.dwPageSize;
}

char *shr_dirname(char *path)
{
	char *end;
	char *slash;

	if (!path || !*path)
		return ".";

	end = path + strlen(path) - 1;
	while (end > path && *end == '/')
		end--;

	if (end == path && *end == '/')
		return "/";

	slash = end;
	while (slash > path && *slash != '/')
		slash--;

	if (*slash != '/')
		return ".";

	while (slash > path && *(slash - 1) == '/')
		slash--;

	if (slash == path)
		return "/";

	*slash = '\0';
	return path;
}
