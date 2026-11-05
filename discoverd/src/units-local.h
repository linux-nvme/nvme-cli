/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE LLC
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */
#pragma once

#include <stdbool.h>
#include <systemd/sd-event.h>

#include "unit-spec.h"
#include "units.h"

/*
 * A stand-in for systemd's transient units, for tests: the units run in
 * nvme-discoverd itself.
 *
 * A start runs ExecStart= and then ExecStartPost=, a stop runs ExecStop=
 * and then ExecStopPost=, as systemd does for a Type=oneshot unit. The
 * commands run synchronously; the job result is reported from the event
 * loop afterwards, as JobRemoved is. A unit that failed, or a unit
 * without RemainAfterExit= that finished, is collected
 * (CollectMode=inactive-or-failed).
 *
 * The loaded units are kept on disk, so they outlive the daemon as
 * transient units do, and a test can play the shutdown with them:
 *
 *   DIR/<unit>/description
 *   DIR/<unit>/exec_start          argv, one argument per line
 *   DIR/<unit>/exec_start_post     shell commands, if any
 *   DIR/<unit>/exec_stop
 *   DIR/<unit>/exec_stop_post
 *   DIR/<unit>/remain_after_exit   present for a connection unit
 *   DIR/journal                    one JSON object per line and operation
 *
 * The journal records "start" with the whole unit, "result" with "done"
 * or "failed", and "stop", "restart" and "reset-failed".
 */
struct local_units;

/*
 * Keep the units in @dir and report job results to @callback. Returns
 * NULL on error.
 */
struct local_units *local_units_new(sd_event *event, const char *dir,
				    unit_job_callback callback,
				    void *user_data);
void local_units_free(struct local_units *lu);

/* Start @spec. -EEXIST if a unit of that name is loaded. */
int local_units_start(struct local_units *lu, const struct unit_spec *spec);

/* Stop and start a loaded unit again. -ENOENT if it is not loaded. */
int local_units_restart(struct local_units *lu, const char *unit_name);

/* Stop a loaded unit. -ENOENT if it is not loaded. */
int local_units_stop(struct local_units *lu, const char *unit_name);

/* Failed units are collected at once: only recorded. */
int local_units_reset_failed(struct local_units *lu, const char *unit_name);

bool local_units_exists(struct local_units *lu, const char *unit_name);
