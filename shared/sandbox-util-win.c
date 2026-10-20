// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */
#include <stdlib.h>

#include "sandbox-util.h"

/* Windows has no fork(), so the code runs in process. */
void shr_sandbox_enable(bool enable)
{
}

int shr_sandbox_begin(struct shr_sandbox_output *out)
{
	*out = (struct shr_sandbox_output){};
	return SHR_SANDBOX_OFF;
}

void shr_sandbox_end(const void *buf, size_t len)
{
	abort();
}
