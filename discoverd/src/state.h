/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */
#pragma once

/*
 * State file management.
 *
 * Layout:
 *   RUNDIR/nvme/discoverd/
 *     units/<unit-name>.devid      — kernel device name written by nvme connect
 *     controllers/<devid>/unit     — transient unit name for this controller
 */

#define STATE_RUN_DIR    RUNDIR "/nvme/discoverd"
#define STATE_UNITS_DIR  STATE_RUN_DIR "/units"
#define STATE_CTRLS_DIR  STATE_RUN_DIR "/controllers"

/* Ensure the runtime directories exist. Call once at startup. */
int state_init(void);

/*
 * Read the unit name from a controller's state directory.
 * Returns an allocated string or NULL. Caller must free.
 */
char *state_read_unit(const char *devid);

/*
 * Remove a controller's state directory. Called by discoverd when the
 * device is removed and the unit was cleaned up by ExecStopPost= (as
 * belt-and-suspenders in case ExecStopPost= did not run).
 */
void state_remove_ctrl(const char *devid);

/*
 * Remove a unit's .devid file (units/<%N>.devid). The ".service" suffix
 * is stripped from @unit_name to match the systemd %N specifier used to
 * name it. Called from the KOBJ_REMOVE handler — ExecStopPost= normally
 * removes it, but the kernel-removal path tears the controller down
 * directly.
 */
void state_remove_devid(const char *unit_name);

/*
 * Enumerate all device IDs that have a state directory.
 * Returns a NULL-terminated array of strings; caller must free each and
 * the array itself. Returns NULL on error.
 */
char **state_list_ctrls(void);
