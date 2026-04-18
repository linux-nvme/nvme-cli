/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 Micron Technology, Inc.
 *
 * Cross-platform compatibility for fcntl.h.
 *
 * Authors: Broc Going <bgoing@micron.com>
 */
#pragma once

#include <fcntl.h>

/*
 * O_BINARY is required for Windows to avoid line ending translations.
 * Define it as 0 on platforms where it is not defined so that it can be used
 * but will have no effect.
 */
#ifndef O_BINARY
#define O_BINARY 0
#endif
