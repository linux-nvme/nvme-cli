// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <systemd/sd-device.h>
#include <systemd/sd-event.h>

#include <daemon-util/log.h>
#include <shared/cleanup-util.h>
#include <shared/string-util.h>

#include "events.h"
#include "sysfs.h"
#include "tid.h"

/* Sysfs soak delay: kernel sysfs attributes settle ~1 s after the add uevent. */
#define SOAK_DELAY_USEC (UINT64_C(1000000))

/* NVMe AEN for "Discovery Log Page Changed" (NVMe Base Spec §5.2.4.2). */
#define NVME_AEN_DLP_CHANGED "0x70f002"

struct soak_entry {
	struct soak_entry *next;
	char *devname;
	sd_event_source *timer;
	struct events_ctx *ctx;
};

struct events_ctx {
	sd_event *event;
	struct events_callbacks callbacks;
	void *user_data;
	sd_device_monitor *nvme_monitor;
	sd_device_monitor *fc_monitor;
	struct soak_entry *soaking;
};

static void soak_entry_free(struct soak_entry *e)
{
	if (!e)
		return;
	sd_event_source_unref(e->timer);
	free(e->devname);
	free(e);
}

static void soak_unlink(struct events_ctx *ctx, struct soak_entry *entry)
{
	struct soak_entry **ep;

	for (ep = &ctx->soaking; *ep; ep = &(*ep)->next) {
		if (*ep == entry) {
			*ep = entry->next;
			return;
		}
	}
}

static int soak_timeout(sd_event_source *src __attribute__((unused)),
			  uint64_t usec __attribute__((unused)),
			  void *user_data)
{
	struct soak_entry *e = user_data;
	struct events_ctx *ctx = e->ctx;
	__cleanup_free char *cntrltype = NULL;
	__cleanup_free char *path = sysfs_nvme_path(e->devname);

	if (!path)
		goto out;

	if (access(path, F_OK) < 0) {
		// Device disappeared during soak — treat as removal.
		if (ctx->callbacks.nvme_remove)
			ctx->callbacks.nvme_remove(e->devname, ctx->user_data);
		goto out;
	}

	cntrltype = sysfs_nvme_attr(e->devname, "cntrltype");

	if (shr_streq0(cntrltype, "discovery")) {
		if (ctx->callbacks.dc_add)
			ctx->callbacks.dc_add(e->devname, ctx->user_data);
	} else if (shr_streq0(cntrltype, "io")) {
		if (ctx->callbacks.ioc_add)
			ctx->callbacks.ioc_add(e->devname, ctx->user_data);
	}

out:
	soak_unlink(ctx, e);
	soak_entry_free(e);
	return 0;
}

static int schedule_soak(struct events_ctx *ctx, const char *devname)
{
	struct soak_entry *e;
	uint64_t now;
	int r;

	e = calloc(1, sizeof(*e));
	if (!e)
		return -ENOMEM;

	e->devname = strdup(devname);
	e->ctx = ctx;
	if (!e->devname) {
		soak_entry_free(e);
		return -ENOMEM;
	}

	r = sd_event_now(ctx->event, CLOCK_BOOTTIME, &now);
	if (r < 0) {
		soak_entry_free(e);
		return r;
	}

	r = sd_event_add_time(ctx->event, &e->timer, CLOCK_BOOTTIME,
			      now + SOAK_DELAY_USEC, 0,
			      soak_timeout, e);
	if (r < 0) {
		soak_entry_free(e);
		return r;
	}

	e->next = ctx->soaking;
	ctx->soaking = e;
	return 0;
}

static const char *uevent_get(const struct uevent *ev, const char *key)
{
	return ev->property ? ev->property(ev, key) : NULL;
}

static void handle_nvme(struct events_ctx *ctx, const struct uevent *ev)
{
	__cleanup_free char *cntrltype = NULL;
	const char *nvme_event, *nvme_aen;

	if (shr_streq0(ev->action, "add")) {
		// Schedule a soak timer; the soak callback reads cntrltype
		// and calls the appropriate add handler.
		schedule_soak(ctx, ev->devname);
		return;
	}

	if (shr_streq0(ev->action, "remove")) {
		if (ctx->callbacks.nvme_remove)
			ctx->callbacks.nvme_remove(ev->devname, ctx->user_data);
		return;
	}

	if (!shr_streq0(ev->action, "change"))
		return;

	/*
	 * Two relevant CHANGE events:
	 *   NVME_AEN=="0x70f002"      — DLP changed AEN
	 *   NVME_EVENT=="rediscover"  — ctrl reconnected after loss
	 * Both are handled the same way: re-fetch the DLP.
	 */
	nvme_aen = uevent_get(ev, "NVME_AEN");
	nvme_event = uevent_get(ev, "NVME_EVENT");

	if (!shr_streq0(nvme_aen, NVME_AEN_DLP_CHANGED)) {
		if (!shr_streq0(nvme_event, "rediscover"))
			return;
		cntrltype = sysfs_nvme_attr(ev->devname, "cntrltype");
		if (!shr_streq0(cntrltype, "discovery"))
			return;
	}

	if (ctx->callbacks.dc_changed) {
		struct dc_addr addr = {
			.transport   = uevent_get(ev, "NVME_TRTYPE"),
			.traddr      = uevent_get(ev, "NVME_TRADDR"),
			.trsvcid     = uevent_get(ev, "NVME_TRSVCID"),
			.host_traddr = uevent_get(ev, "NVME_HOST_TRADDR"),
			.host_iface  = uevent_get(ev, "NVME_HOST_IFACE"),
		};

		ctx->callbacks.dc_changed(ev->devname, &addr, ctx->user_data);
	}
}

static void handle_fc(struct events_ctx *ctx, const struct uevent *ev)
{
	const char *traddr, *host_traddr;
	struct libnvmf_tid *t;

	if (!shr_streq0(uevent_get(ev, "FC_EVENT"), "nvmediscovery"))
		return;

	/*
	 * Properties set by the kernel FC nvme-discovery uevent
	 * (nvme_fc_signal_discovery_scan(), drivers/nvme/host/fc.c).
	 * Note the "NVMEFC_" prefix, not "NVME_" - and the kernel never
	 * sends TRSVCID or NQN for this event: FC has no port concept,
	 * and the target is identified by address only, not by NQN.
	 */
	traddr = uevent_get(ev, "NVMEFC_TRADDR");
	host_traddr = uevent_get(ev, "NVMEFC_HOST_TRADDR");

	if (!traddr)
		return;

	/*
	 * The kernel only fires this uevent for a remote port that
	 * advertised FC_PORT_ROLE_NVME_DISCOVERY, so every instance of
	 * this event is, by the kernel's own gating, a DC - there is no
	 * NQN to check, and no well-known port to default either way.
	 */
	t = tid_new("fc", traddr, NULL,
		    "nqn.2014-08.org.nvmexpress.discovery",
		    host_traddr, NULL, NULL, NULL, true);
	if (!t)
		return;

	if (ctx->callbacks.fc_discovery)
		ctx->callbacks.fc_discovery(t, ctx->user_data);

	tid_free(t);
}

void events_dispatch(struct events_ctx *ctx, const struct uevent *ev)
{
	if (!ctx || !ev->subsystem || !ev->action)
		return;

	if (shr_streq0(ev->subsystem, "nvme") && ev->devname)
		handle_nvme(ctx, ev);
	else if (shr_streq0(ev->subsystem, "fc"))
		handle_fc(ctx, ev);
}

/* A uevent from udev: the properties are the sd_device's. */
static const char *sd_device_property(const struct uevent *ev,
				      const char *key)
{
	const char *val = NULL;

	sd_device_get_property_value(ev->data, key, &val);
	return val;
}

static int monitor_handler(sd_device_monitor *monitor, sd_device *dev,
			   void *user_data)
{
	struct uevent ev = {
		.property = sd_device_property,
		.data = dev,
	};
	sd_device_action_t action;

	(void)monitor;

	if (sd_device_get_action(dev, &action) < 0)
		return 0;
	switch (action) {
	case SD_DEVICE_ADD:
		ev.action = "add";
		break;
	case SD_DEVICE_REMOVE:
		ev.action = "remove";
		break;
	case SD_DEVICE_CHANGE:
		ev.action = "change";
		break;
	default:
		return 0;
	}

	if (sd_device_get_subsystem(dev, &ev.subsystem) < 0)
		return 0;
	sd_device_get_sysname(dev, &ev.devname);

	events_dispatch(user_data, &ev);
	return 0;
}

struct events_ctx *events_start(sd_event *event,
				const struct events_callbacks *callbacks,
				void *user_data)
{
	struct events_ctx *ctx;
	int r;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return NULL;

	ctx->event = event;
	ctx->callbacks = *callbacks;
	ctx->user_data = user_data;

	// nvme subsystem monitor
	r = sd_device_monitor_new(&ctx->nvme_monitor);
	if (r < 0)
		goto err;
	r = sd_device_monitor_filter_add_match_subsystem_devtype(
		ctx->nvme_monitor, "nvme", NULL);
	if (r < 0)
		goto err;
	r = sd_device_monitor_attach_event(ctx->nvme_monitor, event);
	if (r < 0)
		goto err;
	r = sd_device_monitor_start(ctx->nvme_monitor, monitor_handler, ctx);
	if (r < 0)
		goto err;

	// FC subsystem monitor
	r = sd_device_monitor_new(&ctx->fc_monitor);
	if (r < 0)
		goto err;
	r = sd_device_monitor_filter_add_match_subsystem_devtype(
		ctx->fc_monitor, "fc", NULL);
	if (r < 0)
		goto err;
	r = sd_device_monitor_attach_event(ctx->fc_monitor, event);
	if (r < 0)
		goto err;
	r = sd_device_monitor_start(ctx->fc_monitor, monitor_handler, ctx);
	if (r < 0)
		goto err;

	return ctx;
err:
	log_err("%s: %s", __func__, strerror(-r));
	events_stop(ctx);
	return NULL;
}

void events_stop(struct events_ctx *ctx)
{
	struct soak_entry *e, *next;

	if (!ctx)
		return;

	for (e = ctx->soaking; e; e = next) {
		next = e->next;
		soak_entry_free(e);
	}

	sd_device_monitor_unref(ctx->nvme_monitor);
	sd_device_monitor_unref(ctx->fc_monitor);
	free(ctx);
}
