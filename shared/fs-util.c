// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cleanup-util.h"
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

static char *join_path(const char *dir, const char *path)
{
	char *out;
	size_t len;

	if (!dir)
		return strdup(path);
	if (!path || !*path)
		return strdup(dir);

	len = strlen(dir) + 1 + strlen(path) + 1;
	out = malloc(len);
	if (!out)
		return NULL;
	snprintf(out, len, "%s/%s", dir, path);

	return out;
}

unsigned char *shr_read_file(const char *dir, const char *path, long *size, int retries)
{
	__cleanup_free char *file_path = NULL;
	unsigned char *buf = NULL;
	FILE *file = NULL;
	size_t n;
	int i;

	file_path = join_path(dir, path);
	if (!file_path)
		return NULL;

	for (i = 0; i < retries; i++) {
		file = fopen(file_path, "rb");
		if (file)
			break;
		sleep((unsigned int)(retries > 1));
	}
	if (!file)
		return NULL;

	fseek(file, 0, SEEK_END);
	*size = ftell(file);
	if (*size <= 0) {
		fclose(file);
		return NULL;
	}
	fseek(file, 0, SEEK_SET);

	buf = malloc(*size);
	if (!buf) {
		fclose(file);
		return NULL;
	}

	n = fread(buf, 1, *size, file);
	fclose(file);

	if (n != (size_t)*size) {
		free(buf);
		return NULL;
	}

	return buf;
}
