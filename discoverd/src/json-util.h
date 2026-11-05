/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE LLC
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */
#pragma once

#include <stdio.h>

/* Write @s as a JSON string, or null for NULL. */
static inline void json_string(FILE *f, const char *s)
{
	const unsigned char *p;

	if (!s) {
		fputs("null", f);
		return;
	}

	fputc('"', f);
	for (p = (const unsigned char *)s; *p; p++) {
		if (*p == '"' || *p == '\\')
			fprintf(f, "\\%c", *p);
		else if (*p < 0x20)
			fprintf(f, "\\u%04x", *p);
		else
			fputc(*p, f);
	}
	fputc('"', f);
}
