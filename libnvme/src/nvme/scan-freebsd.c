// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <shared/compiler-attributes-util.h>

#include <libnvme.h>

#include "private.h"

#define DEV_DIR "/dev"

/*
 * FreeBSD's nvme(4) driver creates one controller device per controller
 * (/dev/nvmeX) and one namespace device per namespace (/dev/nvmeXnY),
 * both character devices -- there is no sysfs to enumerate, so this
 * filters dirent entries straight out of /dev instead.
 */

static int scan_dev_dir(int (*filter)(const struct dirent *),
		struct dirent ***entries)
{
	int ret;

	ret = scandir(DEV_DIR, entries, filter, alphasort);
	if (ret < 0)
		return -errno;

	return ret;
}

static int filter_ctrl(const struct dirent *d)
{
	unsigned int instance;
	int consumed = -1;

	sscanf(d->d_name, "nvme%u%n", &instance, &consumed);
	return consumed > 0 && (size_t)consumed == strlen(d->d_name);
}

/*
 * Only matches the Linux-compatible "nvmeXnY" namespace naming this
 * port targets throughout (see the file comment above and
 * tree-freebsd.c's own header comment). FreeBSD's native nvme(4) naming
 * predates that mode and instead uses "nvmeXnsY" ("ns" for namespace);
 * a system that only exposes that older naming -- rather than both --
 * will scan as having no namespaces. Not handled here: mapping it in
 * without risking double-counting a namespace that appears under both
 * names needs verifying on real (non-Linux-compat) hardware first.
 */
static int filter_ns(const struct dirent *d)
{
	unsigned int instance, nsid;
	int consumed = -1;

	sscanf(d->d_name, "nvme%un%u%n", &instance, &nsid, &consumed);
	return consumed > 0 && (size_t)consumed == strlen(d->d_name);
}

__shr_public int libnvme_scan_subsystems(
		__shr_unused struct libnvme_global_ctx *ctx,
		__shr_unused struct dirent ***subsys)
{
	return 0;
}

__shr_public int libnvme_scan_subsystem_namespaces(
		__shr_unused struct libnvme_subsystem *s,
		__shr_unused struct dirent ***ns)
{
	return 0;
}

__shr_public int libnvme_scan_ctrls(
		__shr_unused struct libnvme_global_ctx *ctx,
		struct dirent ***ctrls)
{
	return scan_dev_dir(filter_ctrl, ctrls);
}

__shr_public int libnvme_scan_ctrl_namespace_paths(
		__shr_unused struct libnvme_ctrl *c,
		__shr_unused struct dirent ***paths)
{
	return 0;
}

__shr_public int libnvme_scan_ctrl_namespaces(
		struct libnvme_ctrl *c,
		struct dirent ***ns)
{
	struct dirent **entries;
	unsigned int instance;
	int i, j, ret;

	if (sscanf(c->name, "nvme%u", &instance) != 1)
		return -EINVAL;

	ret = scan_dev_dir(filter_ns, &entries);
	if (ret < 0)
		return ret;

	for (i = 0, j = 0; i < ret; i++) {
		unsigned int ns_instance, nsid;

		sscanf(entries[i]->d_name, "nvme%un%u",
				&ns_instance, &nsid);
		if (ns_instance != instance) {
			free(entries[i]);
			continue;
		}
		entries[j++] = entries[i];
	}

	*ns = entries;
	return j;
}

__shr_public int libnvme_scan_ns_head_paths(
		__shr_unused struct libnvme_ns_head *head,
		__shr_unused struct dirent ***paths)
{
	return 0;
}
