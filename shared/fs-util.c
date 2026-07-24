// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "fs-util.h"

int mkdir_p(const char *path, mode_t mode)
{
	char buf[256];
	char *p;
	size_t len;

	snprintf(buf, sizeof(buf), "%s", path);
	len = strlen(buf);
	if (len && buf[len - 1] == '/')
		buf[len - 1] = '\0';

	for (p = buf + 1; *p; p++) {
		if (*p == '/') {
			*p = '\0';
			mkdir(buf, mode);
			*p = '/';
		}
	}
	return mkdir(buf, mode) == 0 || errno == EEXIST ? 0 : -errno;
}
