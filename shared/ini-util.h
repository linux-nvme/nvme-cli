/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */
#pragma once

/*
 * A minimal INI-format reader, shared by libnvme (nvme-fabrics.conf) and
 * nvme-cli (nvme-cli.conf), and usable by any other consumer of this
 * library.
 *
 * The parser handles only the INI syntax: section headers, "key = value"
 * pairs, comments starting with '#', and empty lines. An empty value is
 * distinguished from a missing key. The parser does not interpret
 * sections or keys and enforces no configuration rules; that is left to
 * the caller's callback.
 */

enum shr_ini_event {
	SHR_INI_SECTION,	/* a section header; @key is the section name */
	SHR_INI_KV,		/* a "key = value" line; an empty value is "" */
	SHR_INI_JUNK,	/* a malformed line; @key is the trimmed text */
};

/*
 * Called for each parsed line. Comments and empty lines are ignored.
 *
 * @section contains the current section name. It is NULL before the
 * first section header. For a SECTION event, @section contains the new
 * section name. A malformed section header clears the current section,
 * so following lines are reported with @section == NULL rather than
 * being misattributed to the previous one.
 *
 * @line contains the line number.
 *
 * A non-zero return value stops parsing and is returned by
 * shr_ini_parse_buf()/shr_ini_parse_file().
 */
typedef int (*shr_ini_parse_fn)(enum shr_ini_event event, const char *section,
			     const char *key, const char *value,
			     unsigned int line, void *user_data);

/*
 * Parse @text, calling @callback for each section header and key/value
 * pair. @text is not modified; the parser works on a private copy.
 *
 * Returns 0 on success, a negative errno on failure, or @callback's
 * non-zero return value if it stopped parsing early.
 */
int shr_ini_parse_buf(const char *text, shr_ini_parse_fn callback,
		void *user_data);

/*
 * Parse @path like shr_ini_parse_buf(). A missing file is reported as
 * -ENOENT so callers can treat an absent configuration as empty rather
 * than an error.
 */
int shr_ini_parse_file(const char *path, shr_ini_parse_fn callback,
		void *user_data);
