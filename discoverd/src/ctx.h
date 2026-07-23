/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */
#pragma once

#include <stdbool.h>

#include <systemd/sd-event.h>

/* Forward declarations — full headers included by each .c file as needed. */
struct libnvme_global_ctx;
struct discoverd_config;

/*
 * Top-level discoverd application context. Created once at startup and
 * freed at shutdown. Every subsystem receives a pointer to this struct
 * rather than individual parameters, so adding new resources never
 * requires changing function signatures across the codebase.
 */
struct discoverd_ctx {
	struct libnvme_global_ctx *nvme_ctx;    // libnvme logging/scanning
	const char                *conf_path;   // discoverd.conf path in use
	struct discoverd_config   *cfg;         // parsed discoverd.conf
	sd_event                  *event;       // sd_event main loop
	bool                       force_debug; // --debug forces DEBUG
};
