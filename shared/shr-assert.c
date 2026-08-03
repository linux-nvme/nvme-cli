// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */
#include <stdio.h>
#include <stdlib.h>

#include "shr-assert.h"

void shr_assert_fail(const char *file, int line, const char *cond)
{
	fflush(NULL);
	fprintf(stderr, "%s:%d: assertion failed: %s\n", file, line, cond);
	fflush(NULL);
	exit(EXIT_FAILURE);
}
