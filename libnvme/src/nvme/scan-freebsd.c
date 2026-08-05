// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

#include <dirent.h>

#include <compiler-attributes.h>

#include <libnvme.h>

#include "private.h"

__shr_public int libnvme_scan_subsystems(
		__shr_unused struct libnvme_global_ctx *ctx,
		__shr_unused struct dirent ***subsys)
{
	return 0;
}

__shr_public int libnvme_scan_subsystem_namespaces(
		__shr_unused libnvme_subsystem_t s,
		__shr_unused struct dirent ***ns)
{
	return 0;
}

__shr_public int libnvme_scan_ctrls(
		__shr_unused struct libnvme_global_ctx *ctx,
		__shr_unused struct dirent ***ctrls)
{
	return 0;
}

__shr_public int libnvme_scan_ctrl_namespace_paths(
		__shr_unused libnvme_ctrl_t c,
		__shr_unused struct dirent ***paths)
{
	return 0;
}

__shr_public int libnvme_scan_ctrl_namespaces(
		__shr_unused libnvme_ctrl_t c,
		__shr_unused struct dirent ***ns)
{
	return 0;
}

__shr_public int libnvme_scan_ns_head_paths(
		__shr_unused libnvme_ns_head_t head,
		__shr_unused struct dirent ***paths)
{
	return 0;
}
