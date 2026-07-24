/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */
#pragma once

#include <stdbool.h>
#include <systemd/sd-device.h>
#include <systemd/sd-event.h>

#include "tid.h"

/*
 * Callbacks from the events layer to the main orchestrator.
 * All callbacks are called from the event loop thread.
 */
struct events_cbacks {
	/*
	 * nvmeX device appeared with cntrltype=="discovery".
	 * Called after the ~1 s sysfs soak. t contains the TID read from
	 * sysfs; caller must not free t (it is freed by the events layer
	 * after the callback returns).
	 */
	void (*dc_add)(const char *devname, const struct libnvmf_tid *t,
		       void *user_data);

	/*
	 * DC sent NVME_AEN=="0x70f002" (DLP changed) or was rediscovered
	 * after a ctrl-loss (NVME_EVENT=="rediscover"). Caller should
	 * re-fetch the DLP for the named device.
	 */
	void (*dc_changed)(const char *devname, void *user_data);

	/*
	 * nvmeX device appeared with cntrltype=="io".
	 * The state directory is already created by ExecStartPost= inside
	 * the transient unit; this callback just confirms the connection.
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
 * event loop by the caller. Returns an opaque context on success; the
 * caller must call events_stop() when done.
 */
struct events_ctx *events_start(sd_event *event,
				const struct events_cbacks *cbacks,
				void *user_data);

void events_stop(struct events_ctx *ctx);

/*
 * Build a TID from an nvme controller's sysfs attributes (transport,
 * address, subsysnqn, ...). If @is_dc is non-NULL, *is_dc is set true when
 * the controller's cntrltype is "discovery". Returns an allocated TID, or
 * NULL if the mandatory attributes are missing. Shared by the event
 * monitor and the startup audit.
 */
struct libnvmf_tid *tid_from_sysfs(sd_device *dev, bool *is_dc);
