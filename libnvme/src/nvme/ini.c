// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026, Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <Martin.Belanger@dell.com>
 */

/*
 * Internal INI reader.
 *
 * The reader operates on a private copy of the complete input text instead of
 * fixed-size line buffers. This avoids line-length limits and keeps line
 * numbers accurate. Only the total input size is limited.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "cleanup.h"
#include "cleanup-linux.h"
#include "ini.h"
#include "private-fabrics.h"

#define INI_FILE_MAX (1 * 1024 * 1024) /* 1 MiB cap on one config file */

/*
 * Classify one trimmed line and report it through the callback.  Exactly one
 * of four things can happen, tested in this order:
 *
 *   1. blank line or "# comment"  ->  no event;
 *   2. "[name]"                   ->  SECTION event, @section updated;
 *   3. "key = value"              ->  KV event in the current @section;
 *   4. anything else              ->  JUNK event, the line reported verbatim
 *                                     so the consumer can decide how harshly
 *                                     to treat it.
 *
 * Every line is validated before it is modified, so a junk line reaches the
 * callback exactly as it appears in the file.  @section points into the
 * caller's buffer and carries the current section across calls; a malformed
 * section header resets it, so the lines below a broken header are reported
 * with no section rather than misattributed to the previous one.
 */
static int ini_line(char *s, char **section, unsigned int line,
		    libnvmf_ini_fn callback, void *user_data)
{
	char *end, *eq, *key, *value;

	/* Case 1: not an event. */
	if (!*s || *s == '#')
		return 0;

	/* Case 2: a section header... */
	if (*s == '[') {
		end = strchr(s, ']');
		if (!end) {
			*section = NULL;
			return callback(LIBNVMF_INI_JUNK, NULL, s, NULL,
					line, user_data);
		}

		/* ...unless the name is empty, or followed by text. */
		if (end == libnvmf_trim(s + 1) || *libnvmf_trim(end + 1)) {
			*section = NULL;
			return callback(LIBNVMF_INI_JUNK, NULL, s, NULL,
					line, user_data);
		}

		/*
		 * Cut the ']' and trim once more: only with it gone can a
		 * space before it ("[ foo ]") be stripped from the name.
		 */
		*end = '\0';
		*section = libnvmf_trim(s + 1);

		return callback(LIBNVMF_INI_SECTION, *section, *section,
				NULL, line, user_data);
	}

	/* Case 3: an assignment... */
	eq = strchr(s, '=');

	/*
	 * ...unless there is no '=' at all, or no key left of it (@s is
	 * already trimmed, so an empty key means '=' comes first).
	 */
	if (!eq || eq == s)
		return callback(LIBNVMF_INI_JUNK, *section, s, NULL, line,
				user_data);

	*eq = '\0';
	key = libnvmf_trim(s);
	value = libnvmf_trim(eq + 1);

	return callback(LIBNVMF_INI_KV, *section, key, value, line,
			user_data);
}

/*
 * The tokenizing loop, over a buffer the caller already owns and may
 * modify in place.
 */
static int parse_lines(char *buf, libnvmf_ini_fn callback, void *user_data)
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
		ret = ini_line(libnvmf_trim(p), &section, line, callback,
			       user_data);
		p = nl ? nl + 1 : NULL;
	}

	return ret;
}

int libnvmf_ini_parse_buf(struct libnvme_global_ctx *ctx, const char *text,
		libnvmf_ini_fn callback, void *user_data)
{
	__cleanup_free char *copy = NULL;

	if (!ctx || !text || !callback)
		return -EINVAL;

	copy = strdup(text);
	if (!copy)
		return -ENOMEM;

	return parse_lines(copy, callback, user_data);
}

int libnvmf_ini_parse_file(struct libnvme_global_ctx *ctx, const char *path,
		libnvmf_ini_fn callback, void *user_data)
{
	__cleanup_free char *text = NULL;
	__cleanup_file FILE *f = NULL;
	struct stat st;
	size_t len;

	if (!ctx || !path || !callback)
		return -EINVAL;

	f = fopen(path, "r");
	if (!f)
		return -errno;

	if (fstat(fileno(f), &st) < 0)
		return -errno;
	if (!S_ISREG(st.st_mode))
		return S_ISDIR(st.st_mode) ? -EISDIR : -EINVAL;
	if (st.st_size > INI_FILE_MAX)
		return -EFBIG;

	len = (size_t)st.st_size;
	text = malloc(len + 1);
	if (!text)
		return -ENOMEM;
	len = fread(text, 1, len, f);
	if (ferror(f))
		return -EIO;
	text[len] = '\0';

	/*
	 * Embedded NUL bytes make the input ambiguous; reject non-text content.
	 */
	if (memchr(text, '\0', len))
		return -EINVAL;

	return parse_lines(text, callback, user_data);
}
