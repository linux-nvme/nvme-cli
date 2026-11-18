// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 *
 * Linked instead of kmod-util.c when nvme-cli is built without libkmod, so
 * kernel modules are not loaded.
 */
#include <errno.h>

#include "kmod-util.h"

int shr_kmod_load_module(const char *name)
{
	return -ENOTSUP;
}
