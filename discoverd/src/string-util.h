/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */
#pragma once

#include <ctype.h>
#include <stdbool.h>
#include <string.h>

/*
 * String equality, for the common case where both s1 and s2 are already
 * known to be non-NULL - reads better than strcmp(...) == 0 at the call
 * site. Like strcmp() itself, passing NULL is undefined; use streq0()
 * below if either side might be NULL.
 */
#define streq(s1, s2) (strcmp((s1), (s2)) == 0)

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

/*
 * NULL-safe string equality: two NULLs are equal, one NULL and one
 * non-NULL are never equal, otherwise this is strcmp() == 0.
 */
static inline bool streq0(const char *s1, const char *s2)
{
	if (s1 == s2)
		return true;
	if (!s1 || !s2)
		return false;
	return !strcmp(s1, s2);
}

/*
 * Trim leading and trailing whitespace from s in place and return a
 * pointer to the first non-whitespace character. s itself is modified:
 * the byte after the last non-whitespace character is overwritten with
 * '\0'.
 */
static inline char *trim(char *s)
{
	char *end;

	s += strspn(s, " \t\n\r\v\f");
	end = s + strlen(s);
	while (end > s && isspace((unsigned char)end[-1]))
		end--;
	*end = '\0';
	return s;
}
