// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2025 Micron Technology, Inc.
 *
 * Common platform-specific includes and definitions.
 */

#pragma once

#include "platform/types.h"

/* Platform-specific includes */
#ifdef _WIN32
    #include "platform/windows.h"
#else
    #include "platform/linux.h"
#endif
