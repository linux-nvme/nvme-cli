// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 Micron Technology, Inc.
 *
 * Linux platform-specific definitions and includes.
 */

#pragma once

typedef int libnvme_fd_t;
#define TEST_FD 0xFD
#define INIT_FD -1

/* Platform initialization - no-op on Linux */
static inline void libnvme_init(void) {}
