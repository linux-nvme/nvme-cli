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
		*p = '/';
		if (ret < 0 && ret != -EEXIST)
			return ret;
	}
	ret = shr_mkdir(buf, mode);
	return (ret == 0 || ret == -EEXIST) ? 0 : ret;
}

int shr_mkdir_from_fname(const char *file, mode_t mode)
{
	__cleanup_free char *file_copy = NULL;
	char *parent;
	size_t len = strlen(file);

	/*
	 * A trailing '/' means there is no file name to strip and the path is
	 * a directory in full. dirname() cannot be used for it: it removes
	 * the trailing '/' before the last component, so "a/b/" would come
	 * back as "a" and leave "a/b" uncreated.
	 */
	if (len && file[len - 1] == '/')
		return shr_mkdir_p(file, mode);

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

size_t shr_dir_prefix_len(const char *path)
{
	return (size_t)(shr_basename(path) - path);
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

int shr_read_file(const char *dir, const char *path, long *size, int retries,
		   unsigned char **out)
{
	__cleanup_free char *file_path = NULL;
	unsigned char *buf;
	FILE *file = NULL;
	long file_size;
	size_t n;
	int ret = -EIO;
	int i;

	file_path = join_path(dir, path);
	if (!file_path)
		return -ENOMEM;

	for (i = 0; i < retries; i++) {
		file = fopen(file_path, "rb");
		if (file)
			break;
		ret = -errno;
		sleep((unsigned int)(retries > 1));
	}
	if (!file)
		return ret;

	if (fseek(file, 0, SEEK_END) < 0 || (file_size = ftell(file)) < 0) {
		ret = -errno;
		goto close_file;
	}
	if (file_size == 0) {
		ret = -ENODATA;
		goto close_file;
	}
	fseek(file, 0, SEEK_SET);

	buf = malloc(file_size);
	if (!buf) {
		ret = -ENOMEM;
		goto close_file;
	}

	n = fread(buf, 1, file_size, file);
	if (n != (size_t)file_size) {
		free(buf);
		ret = -EIO;
		goto close_file;
	}

	*size = file_size;
	*out = buf;
	ret = 0;

close_file:
	fclose(file);
	return ret;
}

int shr_read_file_as_string(const char *dir, const char *path, long *size, int retries,
			     char **out)
{
	__cleanup_free unsigned char *raw = NULL;
	char *str;
	long raw_size = 0;
	int ret;

	ret = shr_read_file(dir, path, &raw_size, retries, &raw);
	if (ret < 0 && ret != -ENODATA)
		return ret;

	str = malloc(raw_size + 1);
	if (!str)
		return -ENOMEM;
	if (raw_size)
		memcpy(str, raw, raw_size);
	str[raw_size] = '\0';

	if (size)
		*size = raw_size;

	*out = str;
	return 0;
}
