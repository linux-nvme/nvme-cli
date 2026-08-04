// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026, Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <Martin.Belanger@dell.com>
 */

#include <dirent.h>
#include <errno.h>

#include "cleanup-linux.h"
#include "lib.h"

#include "ctrl-sysfs.c"

#ifdef CONFIG_FABRICS
#	include "ctrl-sysfs-custom-fabrics.c"
#else
#	include "ctrl-sysfs-custom-no-fabrics.c"
#endif

int libnvme_ctrl_load_identity(struct libnvme_ctrl *c)
{
	c->sysfs->firmware = libnvme_get_ctrl_attr(c, "firmware_rev");
	c->sysfs->model = libnvme_get_ctrl_attr(c, "model");
	c->sysfs->serial = libnvme_get_ctrl_attr(c, "serial");
	c->sysfs->cntrltype = libnvme_get_ctrl_attr(c, "cntrltype");
	c->sysfs->cntlid = libnvme_get_ctrl_attr(c, "cntlid");
	c->sysfs->dctype = libnvme_get_ctrl_attr(c, "dctype");

	return 0;
}

int libnvme_ctrl_load_phy_slot(struct libnvme_ctrl *c)
{
	const char *slots_sysfs_dir = libnvme_slots_sysfs_dir(c->ctx);
	__cleanup_free char *target_addr = NULL;
	__cleanup_dir DIR *slots_dir = NULL;
	struct dirent *entry;
	int ret;

	if (!c->address)
		return 0;

	slots_dir = opendir(slots_sysfs_dir);
	if (!slots_dir) {
		ret = -errno;
		libnvme_msg(c->ctx, LIBNVME_LOG_WARN,
			"failed to open slots dir %s\n", slots_sysfs_dir);
		return ret;
	}

	target_addr = strndup(c->address, 10);
	while ((entry = readdir(slots_dir))) {
		__cleanup_free char *path = NULL;
		__cleanup_free char *addr = NULL;

		if (entry->d_type != DT_DIR ||
		    !strncmp(entry->d_name, ".", 1) ||
		    !strncmp(entry->d_name, "..", 2))
			continue;

		ret = asprintf(&path, "%s/%s", slots_sysfs_dir, entry->d_name);
		if (ret < 0)
			return -ENOMEM;

		/* some directories don't have an address entry */
		addr = libnvme_get_attr(path, "address");
		if (!addr)
			continue;
		if (strcmp(addr, target_addr))
			continue;

		c->sysfs->phy_slot = strdup(entry->d_name);
		return 0;
	}

	return 0;
}
