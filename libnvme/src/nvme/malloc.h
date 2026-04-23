/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 Micron Technology, Inc.
 *
 * Cross-platform compatibility for malloc.h.
 * Provides functionality that may be missing on some platforms.
 * Compatibility is not comprehensive. Only functionality required by
 * nvme-cli and libnvme is included.
 *
 * Authors: Brandon Capener <bcapener@micron.com>
 */
#pragma once

#include <malloc.h>

#if defined(_WIN32)
#define malloc_usable_size _msize
#endif
