// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <sys/types.h>

#include <nvme/types.h>

#include "nvme-pci-ids.h"

/*
 * FreeBSD has no sysfs, so there is no directory to hand back here.
 * Instead, smuggle the controller name (e.g. "nvme0") through the
 * 'sysfs_dir' out-param -- __nvme_get_pci_ids() below uses it to build
 * the "dev.nvme.<N>.%pnpinfo" sysctl name nvme(4) publishes the PCI IDs
 * under.
 */
int __nvme_get_sysfs_dir(__attribute__((__unused__)) struct libnvme_global_ctx *ctx,
		const char *ctrl_name, char **sysfs_dir)
{
	*sysfs_dir = strdup(ctrl_name);
	if (!*sysfs_dir)
		return -ENOMEM;

	return 0;
}

int __nvme_get_pci_ids(const char *sysfs_dir,
		__u32 *vid, __u32 *did,
		__u32 *subsys_vid, __u32 *subsys_did,
		__u32 *class_code)
{
	unsigned int instance;
	char oid[64], pnpinfo[256] = "";
	char *p;
	size_t len = sizeof(pnpinfo) - 1;
	unsigned int v = 0, d = 0, sv = 0, sd = 0, cls = 0;

	if (sscanf(sysfs_dir, "nvme%u", &instance) != 1)
		return -EINVAL;

	snprintf(oid, sizeof(oid), "dev.nvme.%u.%%pnpinfo", instance);
	if (sysctlbyname(oid, pnpinfo, &len, NULL, 0) < 0)
		return -errno;
	pnpinfo[len] = '\0';

	/*
	 * pnpinfo is a space-separated "key=value" list, e.g.:
	 *   vendor=0x1b36 device=0x0010 subvendor=0x1af4 subdevice=0x1100 class=0x010802
	 */
	p = strstr(pnpinfo, "vendor=");
	if (p)
		sscanf(p, "vendor=%x", &v);
	p = strstr(pnpinfo, "device=");
	if (p)
		sscanf(p, "device=%x", &d);
	p = strstr(pnpinfo, "subvendor=");
	if (p)
		sscanf(p, "subvendor=%x", &sv);
	p = strstr(pnpinfo, "subdevice=");
	if (p)
		sscanf(p, "subdevice=%x", &sd);
	p = strstr(pnpinfo, "class=");
	if (p)
		sscanf(p, "class=%x", &cls);

	if (vid)
		*vid = v;
	if (did)
		*did = d;
	if (subsys_vid)
		*subsys_vid = sv;
	if (subsys_did)
		*subsys_did = sd;
	if (class_code)
		*class_code = cls;

	return 0;
}
