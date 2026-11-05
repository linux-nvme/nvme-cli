/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE LLC
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */
#pragma once

#include <stdbool.h>
#include <stdio.h>
#include <systemd/sd-event.h>

#include "events.h"

/*
 * The control socket of a test. It replaces the udev monitors: the test
 * plays the kernel and sends the uevents, and asks when the daemon is done
 * with them.
 *
 * One request per line, one reply line per request:
 *
 *   uevent SUBSYSTEM ACTION DEVNAME [KEY=VALUE...]
 *	Handle the uevent as if udev had sent it. DEVNAME "-" is none.
 *	Reply "ok".
 *   sync
 *	Reply "ok" once everything that is ready is processed: nothing in
 *	the event loop is pending and no work runs in a worker. A timer that
 *	has not expired yet, such as a retry, is not waited for.
 *   dump
 *	Reply with one JSON object that describes the daemon's state.
 *
 * A request that cannot be parsed is answered with "error MESSAGE".
 * Requests are handled in order: the requests after a "sync" wait for its
 * reply.
 */
struct control_callbacks {
	void (*uevent)(const struct uevent *ev, void *user_data);
	// Whether work runs outside the event loop.
	bool (*busy)(void *user_data);
	// Write the state as one JSON object, without a newline.
	void (*dump)(FILE *f, void *user_data);
};

struct control;

/*
 * Listen on the Unix socket @path. Returns 0 or a negative errno.
 */
int control_start(sd_event *event, const char *path,
		  const struct control_callbacks *callbacks, void *user_data,
		  struct control **ret);

void control_stop(struct control *c);
