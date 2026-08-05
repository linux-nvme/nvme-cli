// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

#include <errno.h>
#include <stdio.h>

#include <ccan/endian/endian.h>

#include <compiler-attributes.h>

#include "lib.h"

#include "ctrl-sysfs.c"

#ifdef CONFIG_FABRICS
#	include "ctrl-sysfs-custom-fabrics.c"
#else
#	include "ctrl-sysfs-custom-no-fabrics.c"
#endif

int libnvme_ctrl_load_identity(struct libnvme_ctrl *c)
{
	struct nvme_id_ctrl id_ctrl;
	int ret;

	ret = libnvme_ctrl_identify(c, &id_ctrl);
	if (ret != 0)
		return ret;

	if (asprintf(&c->sysfs->cntrltype, "%u", id_ctrl.cntrltype) < 0)
		return -ENOMEM;

	if (asprintf(&c->sysfs->cntlid, "%u", le16_to_cpu(id_ctrl.cntlid)) < 0)
		return -ENOMEM;

	if (asprintf(&c->sysfs->dctype, "%u", id_ctrl.dctype) < 0)
		return -ENOMEM;

	return 0;
}

int libnvme_ctrl_load_phy_slot(__shr_unused struct libnvme_ctrl *c)
{
	/* FreeBSD has no PCIe physical slot sysfs equivalent. */
	return 0;
}
