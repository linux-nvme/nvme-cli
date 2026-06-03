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

int libnvme_open_uring(__libnvme_unused struct libnvme_transport_handle *hdl)
{
	return -ENOTSUP;
}
void libnvme_close_uring(__libnvme_unused struct libnvme_transport_handle *hdl)
{
}

int __libnvme_transport_handle_open_uring(struct libnvme_transport_handle *hdl)
{
	hdl->uring_state = LIBNVME_IO_URING_STATE_NOT_AVAILABLE;

	return -ENOTSUP;
}

__libnvme_public int libnvme_submit_admin_passthru_async(
		__libnvme_unused struct libnvme_transport_handle *hdl,
		__libnvme_unused struct libnvme_passthru_cmd *cmd,
		__libnvme_unused void *cookie)
{
	if (hdl->uring_state == LIBNVME_IO_URING_STATE_UNKNOWN)
		return __libnvme_transport_handle_open_uring(hdl);

	return -ENOTSUP;
}

__libnvme_public int libnvme_submit_io_passthru_async(
		__libnvme_unused struct libnvme_transport_handle *hdl,
		__libnvme_unused struct libnvme_passthru_cmd *cmd,
		__libnvme_unused void *cookie)
{
	if (hdl->uring_state == LIBNVME_IO_URING_STATE_UNKNOWN)
		return __libnvme_transport_handle_open_uring(hdl);

	return -ENOTSUP;
}

__libnvme_public int libnvme_reap_passthru_async(
		__libnvme_unused struct libnvme_transport_handle *hdl,
		__libnvme_unused struct libnvme_passthru_completion *completion)
{
	return -ENOTSUP;
}

__libnvme_public int libnvme_wait_passthru(
		__libnvme_unused struct libnvme_transport_handle *hdl)
{
	return -ENOTSUP;
}
