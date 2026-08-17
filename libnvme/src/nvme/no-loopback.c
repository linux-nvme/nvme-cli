// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */
#include <errno.h>

#include <libnvme.h>

#include "loopback.h"

int libnvme_open_loopback(struct libnvme_global_ctx *ctx,
		struct libnvme_transport_handle **hdlp)
{
	return -ENOTSUP;
}

void libnvme_loopback_set_admin_cmds(struct libnvme_transport_handle *hdl,
		const struct libnvme_loopback_cmd *cmds, size_t len)
{
}

void libnvme_loopback_set_io_cmds(struct libnvme_transport_handle *hdl,
		const struct libnvme_loopback_cmd *cmds, size_t len)
{
}

void libnvme_loopback_end(struct libnvme_transport_handle *hdl)
{
}

int __libnvme_loopback_admin_passthru(struct libnvme_transport_handle *hdl,
		struct libnvme_passthru_cmd *cmd)
{
	return -ENOTSUP;
}

int __libnvme_loopback_io_passthru(struct libnvme_transport_handle *hdl,
		struct libnvme_passthru_cmd *cmd)
{
	return -ENOTSUP;
}
