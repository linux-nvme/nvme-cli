/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */
#pragma once

/*
 * Load the kernel module @name the way "modprobe @name" does, honoring the
 * blacklist, unless it is loaded or built in already, and wait up to two
 * seconds for it to become live.
 *
 * This uses libkmod, which is loaded at runtime on Linux.
 *
 * Return: 0 on success, -ENOTSUP when nvme-cli was built without libkmod or
 * it is not installed or cannot be set up, -errno otherwise (the module
 * cannot be found or loaded, or it doesn't become live in time).
 */
int shr_kmod_load_module(const char *name);
