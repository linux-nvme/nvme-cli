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

/* Forward declarations — full headers included by each .c file as needed. */
struct libnvme_global_ctx;
struct libnvmf_config;
struct discoverd_config;
struct cache;
struct unit_mgr;
struct events_ctx;

/*
 * Top-level discoverd application context. Created once at startup and
 * freed at shutdown. Every subsystem receives a pointer to this struct
 * rather than individual parameters, so adding new resources never
 * requires changing function signatures across the codebase.
 */
struct discoverd_ctx {
	struct libnvme_global_ctx *nvme_ctx;     // libnvme logging/scanning
	const char                *conf_path;    // discoverd.conf path in use
	struct discoverd_config   *cfg;          // parsed discoverd.conf
	struct libnvmf_config     *fabrics_cfg;  // resolved fabrics config
	struct cache              *cache;        // NBFT + config + DLP cache
	sd_event                  *event;        // sd_event main loop
	sd_bus                    *bus;          // D-Bus connection to systemd
	struct unit_mgr           *umgr;         // transient unit manager
	struct events_ctx         *evts;         // udev event monitor
	bool                       force_debug;  // --debug forces DEBUG
};
