// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) Micron, Inc 2024.
 *
 * Authors: Chaithanya Shoba <ashoba@micron.com>
 */

#include <stdlib.h>
#include <string.h>

#include "hex-util.h"

int shr_hex_to_int(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	else if (c >= 'A' && c <= 'F')
		return 10 + (c - 'A');
	else if (c >= 'a' && c <= 'f')
		return 10 + (c - 'a');
	else
		return -1;
}

char *shr_hex_to_ascii(const char *hex)
{
	int hex_length = strlen(hex);
	char *text = NULL;

	if (hex_length > 0) {
		int symbol_count;
		int odd_hex_count = hex_length % 2 == 1;

		if (odd_hex_count)
			symbol_count = (hex_length / 2) + 1;
		else
			symbol_count = hex_length / 2;

		text = malloc(symbol_count + 1);
		if (!text)
			return NULL;

		int last_index = hex_length - 1;

		for (int i = last_index; i >= 0; --i) {
			if ((last_index - i) % 2 != 0) {
				int hi = shr_hex_to_int(hex[i]);
				int lo = shr_hex_to_int(hex[i + 1]);

				if (hi < 0 || lo < 0) {
					free(text);
					return NULL;
				}

				if (odd_hex_count)
					text[i / 2 + 1] = 16 * hi + lo;
				else
					text[i / 2] = 16 * hi + lo;
			} else if (i == 0) {
				int dec = shr_hex_to_int(hex[0]);

				if (dec < 0) {
					free(text);
					return NULL;
				}

				text[0] = dec;
			}
		}

		text[symbol_count] = '\0';
	}

	return text;
}
