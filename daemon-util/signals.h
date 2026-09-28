/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */
#pragma once

#include <systemd/sd-event.h>

typedef void (*dmn_reload_callback)(void *user_data);

/*
 * Handle SIGHUP, SIGTERM and SIGINT through @event. SIGTERM and SIGINT
 * exit the event loop. SIGHUP calls @reload between the RELOADING=1 and
 * READY=1 notifications that Type=notify-reload requires.
 * The signals are read from a signalfd. All callbacks, including @reload,
 * run from the event loop, not in signal context.
 * Return: 0 on success, a negative errno otherwise.
 */
int dmn_add_signal_handlers(sd_event *event, dmn_reload_callback reload,
			    void *user_data);
