/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 Micron Technology, Inc.
 *
 * Cross-platform compatibility definitions, types, and utilities.
 *
 * Authors: Brandon Capener <bcapener@micron.com>
 */
#pragma once

#if defined(_WIN32)

#define WIN32_LEAN_AND_MEAN	/* keeps windows.h from including winsock */
#include <windows.h>

typedef HANDLE libnvme_fd_t;
#define LIBNVME_INVALID_FD INVALID_HANDLE_VALUE
#define LIBNVME_TEST_FD ((HANDLE)0xFD)

#else

typedef int libnvme_fd_t;
#define LIBNVME_INVALID_FD -1
#define LIBNVME_TEST_FD 0xFD

#endif
