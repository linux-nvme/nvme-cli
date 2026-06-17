// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 Micron Technology, Inc.
 *
 * Authors: Brandon Capener <bcapener@micron.com>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libnvme.h>

#include "private.h"
#include "compiler-attributes.h"

__libnvme_public int libnvme_scan_subsystems(
	__libnvme_unused struct dirent ***subsys)
{
	return 0;
}

__libnvme_public int libnvme_scan_subsystem_namespaces(
	__libnvme_unused libnvme_subsystem_t s,
	__libnvme_unused struct dirent ***ns)
{
	return 0;
}

__libnvme_public int libnvme_scan_ctrls(struct dirent ***ctrls)
{
	return -ENOTSUP;
}

__libnvme_public int libnvme_scan_ctrl_namespace_paths(
	__libnvme_unused libnvme_ctrl_t c,
	__libnvme_unused struct dirent ***paths)
{
	return 0;
}

__libnvme_public int libnvme_scan_ctrl_namespaces(libnvme_ctrl_t c,
						  struct dirent ***ns)
{
	return -ENOTSUP;
}

__libnvme_public int libnvme_scan_ns_head_paths(
	__libnvme_unused libnvme_ns_head_t head,
	__libnvme_unused struct dirent ***paths)
{
	return 0;
}
