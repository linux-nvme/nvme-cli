// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 *
 * Copyright (c) 2014-2015, Intel Corporation.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Keith Busch <kbusch@kernel.org>
 *          Daniel Wagner <dwagner@suse.com>
 */
#include <stdlib.h>

#include <libnvme.h>

#include <shared/fs-util.h>

#include "nvme-regs.h"

void *read_registers(struct libnvme_transport_handle *hdl)
{
	int size = shr_getpagesize();
	void *bar;

	bar = calloc(1, size);
	if (!bar)
		return NULL;

	if (libnvme_read_regs(hdl, NVME_REG_CAP, bar + NVME_REG_CAP,
			      NVME_REG_CRTO + sizeof(uint32_t)) ||
	    libnvme_read_regs(hdl, NVME_REG_PMRCAP, bar + NVME_REG_PMRCAP,
			      NVME_REG_PMRMSCU + sizeof(uint32_t) -
			      NVME_REG_PMRCAP)) {
		free(bar);
		return NULL;
	}

	return bar;
}
