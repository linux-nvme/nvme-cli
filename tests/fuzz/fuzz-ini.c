// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

/*
 * Fuzz the INI parser, which reads nvme-cli.conf, nvme-fabrics.conf and
 * the configs of the daemons: the input is the text of a file.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <shared/ini-util.h>

#include "fuzz.h"

static int event(enum shr_ini_event event, const char *section,
		 const char *key, const char *value, unsigned int line,
		 void *user_data)
{
	size_t *n = user_data;

	/* touch every string the parser hands out */
	*n += section ? strlen(section) : 0;
	*n += key ? strlen(key) : 0;
	*n += value ? strlen(value) : 0;
	*n += line + event;

	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char *text = malloc(size + 1);
	size_t n = 0;

	if (!text)
		return 0;
	memcpy(text, data, size);
	text[size] = '\0';

	shr_ini_parse_buf(text, event, &n);

	free(text);
	return 0;
}
