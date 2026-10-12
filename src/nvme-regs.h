/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file is part of nvme-cli.
 *
 * Copyright (c) 2014-2015, Intel Corporation.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Keith Busch <kbusch@kernel.org>
 *          Daniel Wagner <dwagner@suse.com>
 */
#pragma once

#include <libnvme.h>

/*
 * Returns a copy of the controller registers in a page-sized buffer, which
 * the caller must free(), or NULL if they cannot be read.
 */
void *read_registers(struct libnvme_transport_handle *hdl);
