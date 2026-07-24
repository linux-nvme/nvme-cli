/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */
#pragma once

#include <sys/types.h>

/*
 * Create path and every missing parent directory, like "mkdir -p".
 * Return: 0 on success (including if path already exists as a directory),
 * -errno otherwise.
 */
int mkdir_p(const char *path, mode_t mode);
