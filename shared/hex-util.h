/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) Micron, Inc 2024.
 *
 * Authors: Chaithanya Shoba <ashoba@micron.com>
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>

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

/* shr_bin_to_hex(): upper case digits, the last byte first */
#define SHR_HEX_UPPER	(1 << 0)
#define SHR_HEX_REVERSE	(1 << 1)

/*
 * Write the @len bytes at @src to @dst of @size bytes as a string of two
 * hexadecimal digits per byte. @flags are SHR_HEX_* values: upper case
 * digits, and the bytes from the last to the first, e.g. for a little
 * endian GUID.
 * Return: the length of the string, or -E2BIG if @size is less than
 * 2 * @len + 1, in which case @dst is the empty string (if @size isn't 0).
 */
int shr_bin_to_hex(char *dst, size_t size, const void *src, size_t len,
		   unsigned int flags);
