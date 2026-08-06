// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

#include <stdbool.h>
#include <string.h>

#include "wrap-util.h"

void shr_print_word_wrapped(const char *s, int indent, int start, FILE *stream)
{
	const int width = 76;
	bool at_line_start = start <= indent;
	int col = start;

	while (col < indent) {
		putc(' ', stream);
		col++;
	}

	while (*s) {
		if (*s == '\n') {
			putc('\n', stream);
			for (col = 0; col < indent; col++)
				putc(' ', stream);
			at_line_start = true;
			s++;
			continue;
		}

		if (*s == ' ') {
			if (!at_line_start) {
				putc(' ', stream);
				col++;
			}
			s++;
			continue;
		}

		size_t word_len = strcspn(s, " \n");

		if (!at_line_start && col + (int)word_len > width) {
			putc('\n', stream);
			for (col = 0; col < indent; col++)
				putc(' ', stream);
			at_line_start = true;
		}

		fwrite(s, 1, word_len, stream);
		col += (int)word_len;
		at_line_start = false;
		s += word_len;
	}
}
