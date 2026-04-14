// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

#pragma once

#include <dirent.h>
#include <stdio.h>
#include <unistd.h>

#include "cleanup.h"

static inline DEFINE_CLEANUP_FUNC(cleanup_file, FILE *, fclose)
#define __cleanup_file __cleanup(cleanup_file)

static inline DEFINE_CLEANUP_FUNC(cleanup_dir, DIR *, closedir)
#define __cleanup_dir __cleanup(cleanup_dir)

static inline void cleanup_fd(int *fd)
{
	if (*fd >= 0)
		close(*fd);
}
#define __cleanup_fd __cleanup(cleanup_fd)
