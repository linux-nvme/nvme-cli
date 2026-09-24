// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <errno.h>

#include "mdns.h"

int mdns_start(sd_event *event, const struct mdns_callbacks *callbacks,
	       void *user_data, struct mdns_ctx **mctxp)
{
	return -ENOSYS;
}

void mdns_stop(struct mdns_ctx *mctx)
{
}
