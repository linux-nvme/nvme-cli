// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2025 Micron Technology, Inc.
 *
 * Main platform abstraction entry point.
 * Replaces the scattered #ifdef WIN32 conditionals throughout the codebase.
 */

#ifndef _LIBNVME_PLATFORM_INCLUDES_H
#define _LIBNVME_PLATFORM_INCLUDES_H

/* Standard includes needed everywhere */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "platform/types.h"

/* Platform-specific includes */
#ifdef _WIN32
    #include "platform/windows.h"
#else
    #include "platform/linux.h"
#endif

#endif /* _LIBNVME_PLATFORM_INCLUDES_H */