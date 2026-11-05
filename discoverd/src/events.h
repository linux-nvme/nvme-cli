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

#include "tid.h"

/* Address of a connected DC, as its uevent reports it. */
struct dc_addr {
	const char *transport;
	const char *traddr;
	const char *trsvcid;
	const char *host_traddr;
	const char *host_iface;
};

/*
 * The parts of a uevent nvme-discoverd uses. The udev monitor fills it in
 * from an sd_device; a test injects its own.
 */
struct uevent {
	const char *subsystem; // "nvme" or "fc"
	const char *action;    // "add", "remove" or "change"
	const char *devname;   // the sysname, e.g. "nvme3"
	// The value of property @key, or NULL if the uevent has none.
	const char *(*property)(const struct uevent *ev, const char *key);
	void *data;            // for property()
};

/*
 * Callbacks from the events layer to the main orchestrator.
 * All callbacks are called from the event loop thread.
 */
struct events_callbacks {
	/*
	 * nvmeX device appeared with cntrltype=="discovery".
	 * Called after the ~1 s sysfs soak.
	 */
	void (*dc_add)(const char *devname, void *user_data);

	/*
	 * DC sent NVME_AEN=="0x70f002" (DLP changed) or was rediscovered
	 * after a ctrl-loss (NVME_EVENT=="rediscover"). Caller should
	 * re-fetch the DLP for the named device. @addr is the DC's address
	 * as the uevent reports it.
	 */
	void (*dc_changed)(const char *devname, const struct dc_addr *addr,
			   void *user_data);

	/*
	 * nvmeX device appeared with cntrltype=="io".
	 * The event can be processed before ExecStartPost= of the transient
	 * unit wrote the state directory; the unit's job completion links
	 * the device then.
	 */
	void (*ioc_add)(const char *devname, void *user_data);

	/*
	 * nvmeX device was removed by the kernel.
	 * Caller is responsible for state cleanup and reconnect decisions.
	 */
	void (*nvme_remove)(const char *devname, void *user_data);

	/*
	 * FC kickstart produced a discovery event (FC_EVENT=="nvmediscovery").
	 * t contains the TID built from the uevent properties; caller must
	 * not free t.
	 */
	void (*fc_discovery)(const struct libnvmf_tid *t, void *user_data);
};

struct events_ctx;

/*
 * Start monitoring udev events. The bus must already be attached to the
 * event loop by the caller. Without @udev, no monitor is started and only
 * events_dispatch() delivers events, for a test. Returns an opaque context
 * on success; the caller must call events_stop() when done.
 */
struct events_ctx *events_start(sd_event *event,
				const struct events_callbacks *callbacks,
				void *user_data, bool udev);

void events_stop(struct events_ctx *ctx);

/* Handle @ev as if the udev monitor had received it. */
void events_dispatch(struct events_ctx *ctx, const struct uevent *ev);
