/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) Micron, Inc 2024.
 *
 * Authors: Chaithanya Shoba <ashoba@micron.com>
 */
#pragma once

/*
 * Convert a single hexadecimal digit ('0'-'9', 'a'-'f', 'A'-'F') to its
 * integer value. Return: 0-15, or -1 if c is not a hex digit.
 */
int shr_hex_to_int(char c);

/*
 * Decode a hex string into the raw bytes it represents. An odd number of
 * digits is treated as if left-padded with a leading '0'.
 * Return: a newly allocated buffer (caller must free), or NULL on error.
 */
char *shr_hex_to_ascii(const char *hex);
