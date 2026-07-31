// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cleanup.h"
#include "fs-util.h"

int shr_mkdir_p(const char *path, mode_t mode)
{
	char buf[PATH_MAX];
	char *p;
	size_t len;
	int ret;

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
		ret = shr_mkdir(buf, mode);
		if (ret < 0 && ret != -EEXIST)
			return ret;
		*p = '/';
	}
	ret = shr_mkdir(buf, mode);
	return (ret == 0 || ret == -EEXIST) ? 0 : ret;
}

int shr_mkdir_from_fname(const char *file, mode_t mode)
{
	__cleanup_free char *file_copy = NULL;
	char *parent;

	file_copy = strdup(file);
	if (!file_copy)
		return -ENOMEM;

	parent = shr_dirname(file_copy);
	return shr_mkdir_p(parent, mode);
}

char *shr_basename(const char *path)
{
	char *p = (char *)strrchr(path, '/');

	return p ? p + 1 : (char *)path;
}
