// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <errno.h>

#include "fs-util.h"

int shr_mkstemp(char *template)
{
	return -ENOTSUP;
}

void shr_fsync_dir(const char *path)
{
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
