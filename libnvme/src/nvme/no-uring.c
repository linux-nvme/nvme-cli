// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */


#include <errno.h>

#include <libnvme.h>

#include "private.h"
#include "compiler-attributes.h"

int libnvme_open_uring(struct libnvme_global_ctx *ctx)
{
	return -ENOTSUP;
}
void libnvme_close_uring(struct libnvme_global_ctx *ctx)
{
}

int __libnvme_transport_handle_open_uring(struct libnvme_transport_handle *hdl)
{
	hdl->ctx->uring_state = LIBNVME_IO_URING_STATE_NOT_AVAILABLE;
	return -ENOTSUP;
}

int libnvme_submit_admin_passthru_async(struct libnvme_transport_handle *hdl,
		struct libnvme_passthru_cmd *cmd)
{
	return -ENOTSUP;
}

__public int libnvme_wait_admin_passthru(
		__unused struct libnvme_transport_handle *hdl)
{
	return 0;
}

__public int libnvme_wait_io_passthru(
		__unused struct libnvme_transport_handle *hdl)
{
	return 0;
}
