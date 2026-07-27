// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

/*
 * Operates on a private copy of the complete input text instead of
 * fixed-size line buffers, so there is no line-length limit and line
 * numbers stay accurate. Only the total input size is limited.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "ini.h"
#include "string-util.h"

#define INI_FILE_MAX (1 * 1024 * 1024) /* 1 MiB cap on one config file */

/*
 * Classify one trimmed line and report it through the callback. Exactly
 * one of four things happens, tested in this order:
 *
 *   1. blank line or "# comment"  ->  no event;
 *   2. "[name]"                   ->  SECTION event, @section updated;
 *   3. "key = value"              ->  KV event in the current @section;
 *   4. anything else              ->  JUNK event, reported verbatim.
 */
static int ini_line(char *s, char **section, unsigned int line,
		     ini_parse_fn callback, void *user_data)
{
	char *end, *eq, *key, *value;

	if (!*s || *s == '#')
		return 0;

	if (*s == '[') {
		end = strchr(s, ']');
		if (!end) {
			*section = NULL;
			return callback(INI_JUNK, NULL, s, NULL, line,
					 user_data);
		}

		if (end == trim(s + 1) || *trim(end + 1)) {
			*section = NULL;
			return callback(INI_JUNK, NULL, s, NULL, line,
					 user_data);
		}

		*end = '\0';
		*section = trim(s + 1);

		return callback(INI_SECTION, *section, *section, NULL, line,
				 user_data);
	}

	eq = strchr(s, '=');
	if (!eq || eq == s)
		return callback(INI_JUNK, *section, s, NULL, line, user_data);

	*eq = '\0';
	key = trim(s);
	value = trim(eq + 1);

	return callback(INI_KV, *section, key, value, line, user_data);
}

static int parse_lines(char *buf, ini_parse_fn callback, void *user_data)
{
	char *section = NULL;
	unsigned int line = 0;
	char *p = buf;
	int ret = 0;

	while (p && !ret) {
		char *nl = strchr(p, '\n');

		if (nl)
			*nl = '\0';
		line++;
		ret = ini_line(trim(p), &section, line, callback, user_data);
		p = nl ? nl + 1 : NULL;
	}

	return ret;
}

int ini_parse_buf(const char *text, ini_parse_fn callback, void *user_data)
{
	char *copy;
	int ret;

	if (!text || !callback)
		return -EINVAL;

	copy = strdup(text);
	if (!copy)
		return -ENOMEM;

	ret = parse_lines(copy, callback, user_data);
	free(copy);

	return ret;
}

int ini_parse_file(const char *path, ini_parse_fn callback, void *user_data)
{
	FILE *f;
	char *text;
	struct stat st;
	size_t len;
	int ret;

	if (!path || !callback)
		return -EINVAL;

	f = fopen(path, "r");
	if (!f)
		return -errno;

	if (fstat(fileno(f), &st) < 0) {
		ret = -errno;
		goto close_file;
	}
	if (!S_ISREG(st.st_mode)) {
		ret = S_ISDIR(st.st_mode) ? -EISDIR : -EINVAL;
		goto close_file;
	}
	if (st.st_size > INI_FILE_MAX) {
		ret = -EFBIG;
		goto close_file;
	}

	len = (size_t)st.st_size;
	text = malloc(len + 1);
	if (!text) {
		ret = -ENOMEM;
		goto close_file;
	}
	len = fread(text, 1, len, f);
	if (ferror(f)) {
		ret = -EIO;
		goto free_text;
	}
	text[len] = '\0';

	/* Embedded NUL bytes make the input ambiguous; reject non-text content. */
	if (memchr(text, '\0', len)) {
		ret = -EINVAL;
		goto free_text;
	}

	ret = parse_lines(text, callback, user_data);

free_text:
	free(text);
close_file:
	fclose(f);

	return ret;
}
