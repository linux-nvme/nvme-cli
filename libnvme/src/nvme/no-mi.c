// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

#include <errno.h>

#include <libnvme.h>

#include "compiler-attributes.h"

__libnvme_public const char *libnvme_mi_status_to_string(int status)
{
	return "MI support disabled";
}

int __libnvme_transport_handle_open_mi(struct libnvme_transport_handle *hdl,
		const char *devname)
{
	return -ENOTSUP;
}

int __libnvme_transport_handle_init_mi(struct libnvme_transport_handle *hdl)
{
	return -ENOTSUP;
}

void __libnvme_transport_handle_close_mi(struct libnvme_transport_handle *hdl)
{
}

int libnvme_mi_admin_admin_passthru(struct libnvme_transport_handle *hdl,
		struct libnvme_passthru_cmd *cmd)
{
	return -ENOTSUP;
}
