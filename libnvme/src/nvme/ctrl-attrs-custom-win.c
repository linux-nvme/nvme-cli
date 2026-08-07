// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026, Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <Martin.Belanger@dell.com>
 */

#include <ccan/endian/endian.h>
#include <errno.h>

#include "lib.h"
#include "private-ctrl-map.h"

#include "generated/ctrl-attrs.c"

#ifdef CONFIG_FABRICS
#	include "ctrl-attrs-custom-fabrics.c"
#else
#	include "ctrl-attrs-custom-no-fabrics.c"
#endif

int libnvme_ctrl_load_identity(struct libnvme_ctrl *c)
{
	struct nvme_id_ctrl id_ctrl;
	struct ctrl_map_entry *ctrl_entry;
	int ret;

	ret = libnvme_ctrl_identify(c, &id_ctrl);
	if (ret != 0) {
		libnvme_msg(c->ctx, LIBNVME_LOG_ERR,
			"Failed to identify ctrl %s, error %d\n",
			c->name, ret);
		return ret;
	}

	ctrl_entry = libnvme_ctrl_map_lookup(c->ctx, c->name);
	if (!ctrl_entry) {
		libnvme_msg(c->ctx, LIBNVME_LOG_ERR,
			"Failed to find ctrl map entry for ctrl %s\n",
			c->name);
		return -ENOENT;
	}

	ret = libnvme_ctrl_map_entry_set_id_ctrl(ctrl_entry, &id_ctrl);
	if (ret != 0) {
		libnvme_msg(c->ctx, LIBNVME_LOG_ERR,
			"Failed to update ctrl map for ctrl %s, error %d\n",
			c->name, ret);
		return ret;
	}

	c->attrs->firmware = libnvme_ctrl_map_entry_get_firmware(ctrl_entry);
	if (!c->attrs->firmware)
		return -ENOMEM;

	c->attrs->model = libnvme_ctrl_map_entry_get_model(ctrl_entry);
	if (!c->attrs->model)
		return -ENOMEM;

	c->attrs->serial = libnvme_ctrl_map_entry_get_serial(ctrl_entry);
	if (!c->attrs->serial)
		return -ENOMEM;

	if (asprintf(&c->attrs->cntrltype, "%u", id_ctrl.cntrltype) < 0)
		return -ENOMEM;

	if (asprintf(&c->attrs->cntlid, "%u", le16_to_cpu(id_ctrl.cntlid)) < 0)
		return -ENOMEM;

	if (asprintf(&c->attrs->dctype, "%u", id_ctrl.dctype) < 0)
		return -ENOMEM;

	return 0;
}

int libnvme_ctrl_load_phy_slot(__shr_unused struct libnvme_ctrl *c)
{
	/* Windows has no equivalent of a PCIe physical slot lookup. */
	return 0;
}
