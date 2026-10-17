/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */
#pragma once

struct command;
struct plugin_call;
struct libnvme_global_ctx;

/*
 * nvme_privsep_init() - Drop the privileges before anything else runs
 * @call: the command line, as plugin_lookup() found it
 *
 * When root runs nvme-cli with SUDO_UID/SUDO_GID or
 * NVME_PRIVSEP_UID/NVME_PRIVSEP_GID set and the command @call runs does
 * not need root, starts the privilege separation helper and drops the
 * privileges to that user. Otherwise, and without privilege separation
 * support, nvme-cli keeps running as it was started. Call it first in
 * main(), right after the lookup, before anything else parses input.
 *
 * Return: 0 on success, a negative error code if the helper could not be
 * started or the privileges could not be dropped.
 */
int nvme_privsep_init(const struct plugin_call *call);

/*
 * nvme_privsep_check() - Check that a command can run
 * @cmd: command about to run
 *
 * Return: 0, or -EPERM if @cmd needs root but the privileges were dropped.
 */
int nvme_privsep_check(struct command *cmd);

/*
 * nvme_privsep_attach() - Open the devices of a context through the helper
 * @ctx: global context
 *
 * Does nothing when no helper runs.
 */
void nvme_privsep_attach(struct libnvme_global_ctx *ctx);
