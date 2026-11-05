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
struct inventory;
struct unit_mgr;
struct events_ctx;
struct mdns_ctx;
struct dmn_resolver;
struct dmn_work_pool;
struct control;

/*
 * Top-level discoverd application context. Created once at startup and
 * freed at shutdown. Every subsystem receives a pointer to this struct
 * rather than individual parameters, so adding new resources never
 * requires changing function signatures across the codebase.
 */
struct discoverd_ctx {
	struct libnvme_global_ctx *nvme_ctx;     // libnvme logging/scanning
	char                      *hostnqn;      // default host identity
	char                      *hostid;       // default host identity
	const char                *conf_path;    // nvme-discoverd's conf path
	struct discoverd_config   *cfg;          // parsed @conf_path
	char                      *fabrics_conf_path; // NULL: libnvme's default
	struct libnvmf_config     *fabrics_cfg;  // resolved fabrics config
	struct inventory          *inventory;    // NBFT + config + DLP cache
	sd_event                  *event;        // sd_event main loop
	sd_bus                    *bus;          // D-Bus connection to systemd
	struct unit_mgr           *umgr;         // transient unit manager
	struct events_ctx         *evts;         // udev event monitor
	struct mdns_ctx           *mdns;         // mDNS discovery, or NULL
	struct dmn_resolver       *resolver;     // config host name lookups
	struct dmn_work_pool      *dlp_pool;     // DLP reads
	struct control            *control;      // test control socket, or NULL
	bool                       force_debug;  // --debug forces DEBUG
};
