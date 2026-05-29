// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 * 	    Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libnvme.h>

#include "cleanup.h"
#include "cleanup-linux.h"
#include "private.h"
#include "compiler-attributes.h"

static int __nvme_set_attr(const char *path, const char *value)
{
	__cleanup_fd int fd = -1;

	fd = open(path, O_WRONLY);
	if (fd < 0) {
#if 0
		libnvme_msg(LIBNVME_LOG_DEBUG, "Failed to open %s: %s\n", path,
			 strerror(errno));
#endif
		return -errno;
	}
	return write(fd, value, strlen(value));
}

int libnvme_set_attr(const char *dir, const char *attr, const char *value)
{
	__cleanup_free char *path = NULL;
	int ret;

	ret = asprintf(&path, "%s/%s", dir, attr);
	if (ret < 0)
		return -ENOMEM;

	return __nvme_set_attr(path, value);
}

static char *__nvme_get_attr(const char *path)
{
	char value[4096] = { 0 };
	int ret, fd;
	int saved_errno;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return NULL;

	ret = read(fd, value, sizeof(value) - 1);
	saved_errno = errno;
	close(fd);
	if (ret < 0) {
		errno = saved_errno;
		return NULL;
	}
	errno = 0;
	if (!strlen(value))
		return NULL;

	if (value[strlen(value) - 1] == '\n')
		value[strlen(value) - 1] = '\0';
	while (strlen(value) > 0 && value[strlen(value) - 1] == ' ')
		value[strlen(value) - 1] = '\0';

	return strlen(value) ? strdup(value) : NULL;
}

__libnvme_public char *libnvme_get_attr(const char *dir, const char *attr)
{
	__cleanup_free char *path = NULL;
	int ret;

	ret = asprintf(&path, "%s/%s", dir, attr);
	if (ret < 0)
		return NULL;

	return __nvme_get_attr(path);
}

__libnvme_public char *libnvme_get_subsys_attr(
		libnvme_subsystem_t s, const char *attr)
{
	return libnvme_get_attr(libnvme_subsystem_get_sysfs_dir(s), attr);
}

__libnvme_public char *libnvme_get_ctrl_attr(libnvme_ctrl_t c, const char *attr)
{
	return libnvme_get_attr(libnvme_ctrl_get_sysfs_dir(c), attr);
}

__libnvme_public char *libnvme_get_ns_attr(libnvme_ns_t n, const char *attr)
{
	return libnvme_get_attr(libnvme_ns_get_sysfs_dir(n), attr);
}

__libnvme_public char *libnvme_get_path_attr(libnvme_path_t p, const char *attr)
{
	return libnvme_get_attr(libnvme_path_get_sysfs_dir(p), attr);
}


