// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */
#include <unistd.h>

#include "term-util.h"

char *shr_getpass(const char *prompt)
{
	return getpass(prompt);
}
