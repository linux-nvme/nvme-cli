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
	return -ENOSYS;
}

void shr_fsync_dir(const char *path)
{
}
