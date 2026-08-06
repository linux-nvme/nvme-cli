// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

#pragma once

#include <dirent.h>

#include "cleanup.h"

static inline DEFINE_CLEANUP_FUNC(cleanup_dir, DIR *, closedir)
#define __cleanup_dir __cleanup(cleanup_dir)
