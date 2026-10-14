// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */
#include <errno.h>
#include <stdlib.h>

#include "nvme/private.h"

int __libnvme_transport_handle_open_privsep(
		struct libnvme_transport_handle *hdl, const char *name,
		int flags)
{
	return -ENOTSUP;
}

void __libnvme_transport_handle_close_privsep(
		struct libnvme_transport_handle *hdl)
{
	free(hdl);
}

int __libnvme_privsep_admin_passthru(struct libnvme_transport_handle *hdl,
		struct libnvme_passthru_cmd *cmd)
{
	return -ENOTSUP;
}

int __libnvme_privsep_io_passthru(struct libnvme_transport_handle *hdl,
		struct libnvme_passthru_cmd *cmd)
{
	return -ENOTSUP;
}

int __libnvme_privsep_op(struct libnvme_transport_handle *hdl, __u32 op,
		const void *arg, size_t arg_len, void *out, size_t out_len,
		__u64 *result)
{
	return -ENOTSUP;
}

int __libnvme_privsep_sed_ioctl(struct libnvme_transport_handle *hdl,
		__u32 request, const void *arg, size_t size)
{
	return -ENOTSUP;
}
