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

#include "events.h"
#include "tid.h"

/*
 * Bound on how long systemd waits for ExecStop= (nvme disconnect) before it
 * SIGTERMs the job.  This must exceed realistic disconnect time, not undershoot
 * it: a healthy disconnect can take 30-40 s on large configs (~200 namespaces,
 * 8 paths, 80 CPUs) and longer still beyond that, so too low a bound would kill
 * a disconnect that is still making progress and leave the controller
 * half-torn-down.  Generous default; this should become an nvme-discoverd
 * config knob so large deployments can raise it further.
 */
#define DISCONNECT_TIMEOUT_SEC 300

/* systemd D-Bus destination and path. */
#define SYSTEMD_BUS_NAME  "org.freedesktop.systemd1"
#define SYSTEMD_OBJ_PATH  "/org/freedesktop/systemd1"
#define SYSTEMD_MGR_IFACE "org.freedesktop.systemd1.Manager"
#define SYSTEMD_NO_SUCH_UNIT "org.freedesktop.systemd1.NoSuchUnit"

/* Result of a StartTransient / RestartUnit / StopUnit job. */
typedef void (*unit_job_callback)(const char *unit_name,
			       bool success, void *user_data);

struct unit_mgr;

/*
 * The owner of a connection unit's controller, the --owner of its nvme.
 * The unit of a pre-OS I/O controller never disconnects it.
 */
enum unit_owner {
	UNIT_OWNER_DISCOVERD,
	UNIT_OWNER_PRE_OS,
};

/*
 * Create a unit manager.  Attaches to the given sd_bus connection and
 * sd_event loop.  unit_job_callback is called for every JobRemoved signal.
 * nvme_path is the nvme binary the transient units exec; NULL or "" selects the
 * build-time default (NVME_PATH).  The string is borrowed, not copied, so it
 * must outlive the unit manager (e.g. a pointer into argv).
 */
struct unit_mgr *unit_mgr_new(sd_bus *bus, sd_event *event,
			      unit_job_callback callback, void *user_data,
			      const char *nvme_path);
/*
 * Create a unit manager that runs the units in nvme-discoverd itself and
 * keeps them in @dir, for tests. See units-local.h.
 */
struct unit_mgr *unit_mgr_new_local(sd_event *event, const char *dir,
				     unit_job_callback callback,
				     void *user_data, const char *nvme_path);
void unit_mgr_free(struct unit_mgr *mgr);
/*
 * Pass --set-options=@opts to every nvme the units run, e.g. the test
 * directories of the daemon. Returns 0 or -ENOMEM.
 */
int unit_mgr_set_nvme_options(struct unit_mgr *mgr, const char *opts);

/*
 * Create a transient DC connection unit.  @params carries the resolved
 * connect parameters to emit (may be NULL for none) — see
 * libnvmf_connect_args_emit() in <nvme/config.h>.
 * @owner is the controller's owner (enum unit_owner).
 */
int unit_start_dc(struct unit_mgr *mgr, const struct libnvmf_tid *t,
		  const struct libnvmf_params *params, enum unit_owner owner);

/*
 * Create a transient IOC connection unit.  @params carries the resolved
 * connect parameters to emit (may be NULL for none).
 */
int unit_start_ioc(struct unit_mgr *mgr, const struct libnvmf_tid *t,
		   const struct libnvmf_params *params, enum unit_owner owner);

/*
 * Run "nvme connect-all" once over the existing connection to DC
 * @devname, as 70-nvmf-autoconnect.rules does. No --owner is given.
 * The unit goes away when the command exits. Starting it again while it
 * runs replaces the running instance.
 */
int unit_start_connect_all(struct unit_mgr *mgr, const char *devname,
			   const struct dc_addr *addr);

/*
 * Restart an existing unit (reconnect with baked-in parameters). Fails if
 * systemd no longer has the unit.
 */
int unit_restart(struct unit_mgr *mgr, const char *unit_name);

/* Stop a unit (triggers ExecStop= disconnect). */
int unit_stop(struct unit_mgr *mgr, const char *unit_name);

/* Reset a failed unit so it can be started again. */
int unit_reset_failed(struct unit_mgr *mgr, const char *unit_name);

/*
 * Is @unit_name loaded by systemd? Any error other than "no such unit"
 * reports true: starting a unit that is really there fails with -EEXIST,
 * and the recovery for that stops the unit, which disconnects.
 */
bool unit_exists(struct unit_mgr *mgr, const char *unit_name);

/*
 * Read the kernel device name (e.g. "nvme3") that @unit_name's connect
 * recorded. Returns NULL if none was recorded. Caller must free.
 */
char *unit_read_devid(const char *unit_name);
