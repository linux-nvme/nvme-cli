// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

#include <stdio.h>
#include <stdlib.h>

#include "string-util.h"

char *shr_escape(const char *s)
{
	const unsigned char *p;
	size_t n = 1;
	char *e, *q;

	for (p = (const unsigned char *)s; *p; p++)
		n += (*p < 0x20 || *p == 0x7f) ? 4 : 1;

	e = malloc(n);
	if (!e)
		return NULL;

	for (p = (const unsigned char *)s, q = e; *p; p++) {
		if (*p < 0x20 || *p == 0x7f)
			q += snprintf(q, 5, "\\x%02x", *p);
		else
			*q++ = *p;
	}
	*q = '\0';

	return e;
}
