/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */
#pragma once

#include <nvme/lib-types.h>

/**
 * DOC: privsep.h
 *
 * Privilege separation
 *
 * A privileged process starts the helper with libnvme_privsep_spawn() and
 * then drops its privileges. A global context with an attached helper
 * opens devices through the helper. The helper issues the ioctls and
 * returns the raw results.
 */

struct libnvme_privsep;

/**
 * libnvme_privsep_spawn() - Start the privilege separation helper
 * @helper:	Path of the helper binary or NULL for the installed helper
 * @psp:	On success, the helper channel
 *
 * Starts the helper as a child process and checks that it speaks the same
 * protocol version. The helper inherits the credentials of the caller, so
 * call this function before dropping privileges.
 *
 * Return: 0 on success or a negative error code otherwise.
 */
int libnvme_privsep_spawn(const char *helper, struct libnvme_privsep **psp);

/**
 * libnvme_privsep_free() - Stop the privilege separation helper
 * @ps:		Helper channel
 *
 * Closes the channel and waits for the helper to exit. All transport
 * handles opened through the helper must be closed before.
 */
void libnvme_privsep_free(struct libnvme_privsep *ps);

/**
 * libnvme_set_privsep() - Open devices through the helper
 * @ctx:	&struct libnvme_global_ctx object
 * @ps:		Helper channel or NULL to open devices directly
 *
 * libnvme_open() on @ctx returns transport handles which forward the
 * commands to the helper. MI endpoints are not affected. Several contexts
 * can share one helper channel. The channel must outlive the contexts and
 * their transport handles. Commands on one channel must not be issued
 * concurrently.
 */
void libnvme_set_privsep(struct libnvme_global_ctx *ctx,
		struct libnvme_privsep *ps);
