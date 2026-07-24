/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */
#pragma once

#include <stdbool.h>
#include <systemd/sd-bus.h>
#include <systemd/sd-event.h>

#include <nvme/config.h>

#include "tid.h"

/*
 * Bound on how long systemd waits for ExecStop= (nvme disconnect) before it
 * SIGTERMs the job.  This must exceed realistic disconnect time, not undershoot
 * it: a healthy disconnect can take 30-40 s on large configs (~200 namespaces,
 * 8 paths, 80 CPUs) and longer still beyond that, so too low a bound would kill
 * a disconnect that is still making progress and leave the controller
 * half-torn-down.  Generous default; this should become a discoverd.conf knob
 * so large deployments can raise it further.
 */
#define DISCONNECT_TIMEOUT_SEC 300

/* systemd D-Bus destination and path. */
#define SYSTEMD_BUS_NAME  "org.freedesktop.systemd1"
#define SYSTEMD_OBJ_PATH  "/org/freedesktop/systemd1"
#define SYSTEMD_MGR_IFACE "org.freedesktop.systemd1.Manager"

/* Result of a StartTransient / RestartUnit / StopUnit job. */
typedef void (*unit_job_cback)(const char *unit_name,
			       bool success, void *user_data);

struct unit_mgr;

/*
 * Create a unit manager.  Attaches to the given sd_bus connection and
 * sd_event loop.  unit_job_cback is called for every JobRemoved signal.
 * nvme_path is the nvme binary the transient units exec; NULL or "" selects the
 * build-time default (NVME_PATH).  The string is borrowed, not copied, so it
 * must outlive the unit manager (e.g. a pointer into argv).
 */
struct unit_mgr *unit_mgr_new(sd_bus *bus, sd_event *event,
			      unit_job_cback cback, void *user_data,
			      const char *nvme_path);
void unit_mgr_free(struct unit_mgr *mgr);

/*
 * Create a transient DC connection unit.  @params carries the resolved
 * connect parameters to emit (may be NULL for none) — see
 * libnvmf_connect_args_emit() in <nvme/config.h>.
 * If is_nbft is true, uses --owner nbft; otherwise --owner discoverd.
 */
int unit_start_dc(struct unit_mgr *mgr, const struct libnvmf_tid *t,
		  const struct libnvmf_params *params, bool is_nbft);

/*
 * Create a transient IOC connection unit.  @params carries the resolved
 * connect parameters to emit (may be NULL for none).
 */
int unit_start_ioc(struct unit_mgr *mgr, const struct libnvmf_tid *t,
		   const struct libnvmf_params *params, bool is_nbft);

/* Restart an existing unit (reconnect with baked-in parameters). */
int unit_restart(struct unit_mgr *mgr, const char *unit_name);

/* Stop a unit (triggers ExecStop= disconnect). */
int unit_stop(struct unit_mgr *mgr, const char *unit_name);

/* Reset a failed unit so it can be started again. */
int unit_reset_failed(struct unit_mgr *mgr, const char *unit_name);
