// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */
#include "sandbox-util.h"

/* Windows has no fork(), so the parsers run in process. */
void shr_sandbox_enable(bool enable)
{
}

int shr_sandbox_run(int (*fn)(void *arg), void *arg,
		const struct shr_sandbox_region *regions, unsigned int nr)
{
	return fn(arg);
}
