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

#include <stdbool.h>

#include <libnvme.h>

void *mmap_registers(struct libnvme_transport_handle *hdl, bool writable);
int munmap_registers(void *addr);
