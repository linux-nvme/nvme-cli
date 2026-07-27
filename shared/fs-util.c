// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <errno.h>
#include <limits.h>
#include <string.h>
#include <sys/stat.h>

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
