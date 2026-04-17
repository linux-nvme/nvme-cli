/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 Micron Technology, Inc.
 *
 * Cross-platform compatibility for mkdir (sys/stat.h).
 *
 * Authors: Broc Going <bgoing@micron.com>
 */
#pragma once

#if defined(_WIN32) || defined(_WIN64)

#include <direct.h>

/* Windows mkdir doesn't take the mode parameter */
#define mkdir(path, mode) _mkdir(path)

#endif
