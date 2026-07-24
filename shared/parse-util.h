/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */
#pragma once

#include <stdbool.h>

/*
 * Parse a boolean string using the systemd parse_boolean() convention:
 * 1/yes/y/true/t/on, 0/no/n/false/f/off (case-insensitive).
 * Return: 0 on success (*out set), -EINVAL if value matches neither list.
 */
int parse_bool(const char *value, bool *out);
