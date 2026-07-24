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
#include <strings.h>

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

/* Case-insensitive sibling of streq0(). */
static inline bool streqcase0(const char *s1, const char *s2)
{
	if (s1 == s2)
		return true;
	if (!s1 || !s2)
		return false;
	return !strcasecmp(s1, s2);
}

/* Allocation-checking strdup() that returns NULL for a NULL input. */
static inline char *xstrdup(const char *s)
{
	return s ? strdup(s) : NULL;
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
