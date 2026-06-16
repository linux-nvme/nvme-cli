// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 Micron Technology, Inc.
 *
 * Authors: Brandon Capener <bcapener@micron.com>
 */

#include <errno.h>
#include <stdio.h>
#include <strings.h>

#include "compiler-attributes.h"
#include "private.h"


__libnvme_public int libnvme_open(struct libnvme_global_ctx *ctx,
				  const char *name,
				  struct libnvme_transport_handle **hdlp)
{
	return -ENOTSUP;
}

__libnvme_public void libnvme_close(struct libnvme_transport_handle *hdl)
{
}
