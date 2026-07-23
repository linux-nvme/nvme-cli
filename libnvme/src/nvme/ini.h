/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of libnvme.
 * Copyright (c) 2026, Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <Martin.Belanger@dell.com>
 */
#pragma once

/*
 * Internal INI parser for nvme-fabrics.conf.
 *
 * The parser handles only the INI syntax. It recognizes section headers,
 * key-value pairs in the form "key = value", comments starting with '#',
 * and empty lines. Empty values are returned as an empty string and are
 * distinguished from missing keys.
 *
 * The parser does not interpret sections or keys and does not enforce
 * configuration rules. Validation, duplicate handling, and precedence rules
 * are implemented by the caller through the consumer callback.
 */

struct libnvme_global_ctx;

enum libnvmf_ini_event {
	LIBNVMF_INI_SECTION,	/* a section header; @key is the section name */
	LIBNVMF_INI_KV,		/* a "key = value" line; an empty value is "" */
	LIBNVMF_INI_JUNK,	/* a malformed line; @key is the trimmed text */
};

/*
 * Called for each parsed line. Comments and empty lines are ignored.
 *
 * @section contains the current section name. It is NULL before the first
 * section header. For a SECTION event, @section contains the new section
 * name.
 *
 * If a section header is malformed, the current section is cleared. Following
 * lines are reported with @section == NULL to avoid assigning them to an
 * invalid section.
 *
 * @line contains the line number.
 *
 * A non-zero return value stops parsing and is returned by
 * libnvmf_ini_parse_*().
 */
typedef int (*libnvmf_ini_fn)(enum libnvmf_ini_event event,
		const char *section, const char *key, const char *value,
		unsigned int line, void *user_data);

int libnvmf_ini_parse_buf(struct libnvme_global_ctx *ctx, const char *text,
		libnvmf_ini_fn callback, void *user_data);
int libnvmf_ini_parse_file(struct libnvme_global_ctx *ctx, const char *path,
		libnvmf_ini_fn callback, void *user_data);
