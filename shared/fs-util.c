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
#include <stdio.h>
#include <stdlib.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(_WIN32)
#include <direct.h>
#include <fcntl.h>
#include <io.h>
#include <windows.h>

#define mkdir(path, mode) ((void)(mode), _mkdir(path))
#endif

#include "fs-util.h"

int shr_mkdir_p(const char *path, mode_t mode)
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

#ifdef _WIN32
int shr_tmpnam(char *path, size_t size)
{
	DWORD len;

	len = GetTempPathA((DWORD)size, path);
	if (len == 0 || len >= size)
		return -EIO;

	return 0;
}
#else
int shr_tmpnam(char *path, size_t size)
{
	const char *tmp;

	tmp = getenv("TMPDIR");
	if (!tmp)
		tmp = "/tmp";

	if (snprintf(path, size, "%s/", tmp) >= (int)size)
		return -ENAMETOOLONG;

	return 0;
}
#endif

#if defined(_WIN32)
int shr_mkstemp(char *template)
{
	HANDLE h;
	char *slash;
	char prefix[4] = "tmp";
	char tmpname[MAX_PATH];
	int fd;

	/*
	 * GetTempFileName() needs a directory and a short prefix. The caller
	 * already provided the directory through the template, so extract it.
	 */
	slash = strrchr(template, '\\');
	if (!slash)
		slash = strrchr(template, '/');
	if (!slash)
		return -EINVAL;

	*slash = '\0';

	if (!GetTempFileNameA(template, prefix, 0, tmpname)) {
		*slash = '\\';
		return -EIO;
	}

	/*
	 * Replace the caller's template with the generated name.
	 */
	*slash = '\\';
	strncpy(template, tmpname, MAX_PATH - 1);
	template[MAX_PATH - 1] = '\0';

	h = CreateFileA(template,
			GENERIC_READ | GENERIC_WRITE,
			0,
			NULL,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_TEMPORARY,
			NULL);
	if (h == INVALID_HANDLE_VALUE) {
		DeleteFileA(template);
		return -EIO;
	}

	fd = _open_osfhandle((intptr_t)h, _O_RDWR);
	if (fd < 0) {
		CloseHandle(h);
		DeleteFileA(template);
		return -errno;
	}

	return fd;
}
#else
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
#endif

#if defined(_WIN32)
void shr_fsync_dir(const char *path)
{
}
#else
void shr_fsync_dir(const char *path)
{
	int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);

	if (fd >= 0) {
		fsync(fd);
		close(fd);
	}
}
#endif

char *shr_basename(const char *path)
{
	char *p = (char *)strrchr(path, '/');

	return p ? p + 1 : (char *)path;
}
