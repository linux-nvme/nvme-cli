// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

#include <errno.h>

#include <compiler-attributes.h>

#include <libnvme.h>

#include "private.h"

__shr_public int libnvme_reset_subsystem(
		__shr_unused struct libnvme_transport_handle *hdl)
{
	return -ENOTSUP;
}

__shr_public int libnvme_reset_ctrl(
		__shr_unused struct libnvme_transport_handle *hdl)
{
	return -ENOTSUP;
}

__shr_public int libnvme_rescan_ns(
		__shr_unused struct libnvme_transport_handle *hdl)
{
	return -ENOTSUP;
}

__shr_public int libnvme_get_nsid(
		__shr_unused struct libnvme_transport_handle *hdl,
		__shr_unused __u32 *nsid)
{
	return -ENOTSUP;
}

__shr_public int libnvme_update_block_size(
		__shr_unused struct libnvme_transport_handle *hdl,
		__shr_unused int block_size)
{
	return -ENOTSUP;
}

__shr_public int libnvme_exec_admin_passthru(
		__shr_unused struct libnvme_transport_handle *hdl,
		__shr_unused struct libnvme_passthru_cmd *cmd)
{
	return -ENOTSUP;
}

__shr_public int libnvme_exec_io_passthru(
		__shr_unused struct libnvme_transport_handle *hdl,
		__shr_unused struct libnvme_passthru_cmd *cmd)
{
	return -ENOTSUP;
}
