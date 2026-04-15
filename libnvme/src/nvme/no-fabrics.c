// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

#include "private-fabrics.h"

bool traddr_is_hostname(struct libnvme_global_ctx *ctx,
		const char *transport, const char *traddr)
{
	return false;
}
__public void libnvmf_default_config(struct libnvme_fabrics_config *cfg)
{
}
