/* SPDX-License-Identifier: LGPL-2.1-or-later */
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

#ifndef HAVE_STRSEP
/* strsep() is missing on some platforms (e.g. mingw/MSVC runtimes). */
static inline char *strsep(char **stringp, const char *delim)
{
	char *s, *end;

	if (!stringp || !*stringp)
		return NULL;

	s = *stringp;
	end = s + strcspn(s, delim);

	if (*end)
		*end++ = '\0';
	else
		end = NULL;

	*stringp = end;
	return s;
}
#endif

/*
 * NULL-safe string equality: two NULLs are equal, one NULL and one
 * non-NULL are never equal, otherwise this is strcmp() == 0.
 */
static inline bool shr_streq0(const char *s1, const char *s2)
{
	if (s1 == s2)
		return true;
	if (!s1 || !s2)
		return false;
	return !strcmp(s1, s2);
}

/* Case-insensitive sibling of shr_streq0(). */
static inline bool shr_streqcase0(const char *s1, const char *s2)
{
	if (s1 == s2)
		return true;
	if (!s1 || !s2)
		return false;
	return !strcasecmp(s1, s2);
}

/* Allocation-checking strdup() that returns NULL for a NULL input. */
static inline char *shr_xstrdup(const char *s)
{
	return s ? strdup(s) : NULL;
}

/*
 * Trim trailing whitespace from s in place: the byte after the last
 * non-whitespace character is overwritten with '\0'. Returns s.
 */
static inline char *shr_rtrim(char *s)
{
	char *end = s + strlen(s);

	while (end > s && isspace((unsigned char)end[-1]))
		end--;
	*end = '\0';
	return s;
}

/*
 * Return a pointer to the first non-whitespace character in s. s itself
 * is not modified.
 */
static inline char *shr_ltrim(char *s)
{
	return s + strspn(s, " \t\n\r\v\f");
}

/*
 * Trim leading and trailing whitespace from s in place and return a
 * pointer to the first non-whitespace character. s itself is modified:
 * the byte after the last non-whitespace character is overwritten with
 * '\0'.
 */
static inline char *shr_trim(char *s)
{
	return shr_ltrim(shr_rtrim(s));
}

/* True if s is non-empty and every character is alphanumeric, '_', or '-'. */
static inline bool shr_valid_name(const char *s)
{
	const char *p;

	if (!s || !*s)
		return false;
	for (p = s; *p; p++) {
		if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
		    (*p >= '0' && *p <= '9') || *p == '_' || *p == '-')
			continue;
		return false;
	}
	return true;
}

/*
 * If s starts with prefix, return a pointer within s just past the match.
 * NULL otherwise.
 */
static inline char *shr_startswith(const char *s, const char *prefix)
{
	size_t l = strlen(prefix);

	if (!strncmp(s, prefix, l))
		return (char *)s + l;

	return NULL;
}

/*
 * Strip leading/trailing blanks and a trailing "# comment" from the
 * key=value line kv, in place. Return a pointer to the stripped string.
 */
static inline char *shr_kv_strip(char *kv)
{
	char *s;

	kv[strcspn(kv, "\n\r")] = '\0';

	/* Remove leading newline and spaces */
	kv += strspn(kv, " \t\n\r");

	/* Skip comments and empty lines */
	if (*kv == '#' || *kv == '\0') {
		*kv = '\0';
		return kv;
	}

	/* Remove trailing newline chars */
	kv[strcspn(kv, "\n\r")] = '\0';

	/* Delete trailing comments (including spaces/tabs that precede the #)*/
	s = &kv[strcspn(kv, "#")];
	*s-- = '\0';
	while (s >= kv && (*s == ' ' || *s == '\t'))
		*s-- = '\0';

	return kv;
}

/*
 * If kv is a whole-word match for "key" at the start of a key=value line,
 * return a pointer to the first character of value (past spaces/tabs/'=').
 * NULL otherwise.
 */
static inline char *shr_kv_keymatch(const char *kv, const char *key)
{
	char *value;

	value = shr_startswith(kv, key);
	if (value && (*value == ' ' || *value == '\t' || *value == '='))
		return value + strspn(value, " \t=");

	return NULL;
}
