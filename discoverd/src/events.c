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
#include <systemd/sd-device.h>
#include <systemd/sd-event.h>

#include "events.h"
#include "log.h"
#include "tid.h"

/* Sysfs soak delay: kernel sysfs attributes settle ~1 s after the add uevent. */
#define SOAK_DELAY_USEC (UINT64_C(1000000))

/* NVMe AEN for "Discovery Log Page Changed" (NVMe Base Spec §5.2.4.2). */
#define NVME_AEN_DLP_CHANGED "0x70f002"

struct soak_entry {
	struct soak_entry *next;
	char *syspath;
	char *devname;
	sd_event_source *timer;
	struct events_ctx *ctx;
};

struct events_ctx {
	sd_event *event;
	struct events_cbacks cbacks;
	void *user_data;
	sd_device_monitor *nvme_monitor;
	sd_device_monitor *fc_monitor;
	struct soak_entry *soaking;
};

/*
 * Extract a named field from a comma-separated "key=value,..." string such
 * as the address sysattr: "traddr=192.0.2.1,trsvcid=4420,src_addr=10.0.0.1".
 * Returns an allocated string on success, NULL if not found.
 */
static char *extract_addr_field(const char *address, const char *key)
{
	char search[64];
	const char *p, *end;
	size_t len;

	if (!address || !key)
		return NULL;

	snprintf(search, sizeof(search), "%s=", key);
	p = strstr(address, search);
	if (!p)
		return NULL;

	p += strlen(search);
	end = strchr(p, ',');
	len = end ? (size_t)(end - p) : strlen(p);
	if (!len)
		return NULL;

	return strndup(p, len);
}

/*
 * Build a TID from sysfs attributes of an nvme device.
 * Returns NULL on error (e.g. required attributes missing).
 */
struct libnvmf_tid *tid_from_sysfs(sd_device *dev, bool *is_dc)
{
	const char *transport = NULL, *address = NULL;
	const char *subsysnqn = NULL, *hostnqn = NULL;
	const char *host_iface = NULL, *cntrltype = NULL;
	char *traddr = NULL, *trsvcid = NULL, *host_traddr = NULL;
	struct libnvmf_tid *t = NULL;

	if (is_dc)
		*is_dc = false;

	sd_device_get_sysattr_value(dev, "transport", &transport);
	sd_device_get_sysattr_value(dev, "address", &address);
	sd_device_get_sysattr_value(dev, "subsysnqn", &subsysnqn);
	sd_device_get_sysattr_value(dev, "hostnqn", &hostnqn);
	sd_device_get_sysattr_value(dev, "host_iface", &host_iface);
	sd_device_get_sysattr_value(dev, "cntrltype", &cntrltype);

	if (!transport || !address || !subsysnqn)
		return NULL;

	traddr = extract_addr_field(address, "traddr");
	trsvcid = extract_addr_field(address, "trsvcid");

	// host_traddr may appear as "src_addr" in some kernel versions; try both
	host_traddr = extract_addr_field(address, "host_traddr");
	if (!host_traddr)
		host_traddr = extract_addr_field(address, "src_addr");

	if (traddr) {
		bool dc = streq0(cntrltype, "discovery");

		t = tid_new(transport, traddr, trsvcid, subsysnqn,
			    host_traddr, host_iface, hostnqn, dc);
		if (is_dc)
			*is_dc = dc;
	}

	free(traddr);
	free(trsvcid);
	free(host_traddr);
	return t;
}

static void soak_entry_free(struct soak_entry *e)
{
	if (!e)
		return;
	sd_event_source_unref(e->timer);
	free(e->syspath);
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
	sd_device *dev = NULL;
	const char *cntrltype = NULL;
	struct libnvmf_tid *t;

	if (sd_device_new_from_syspath(&dev, e->syspath) < 0) {
		// Device disappeared during soak — treat as removal.
		if (ctx->cbacks.nvme_remove)
			ctx->cbacks.nvme_remove(e->devname, ctx->user_data);
		goto out;
	}

	sd_device_get_sysattr_value(dev, "cntrltype", &cntrltype);

	if (streq0(cntrltype, "discovery")) {
		t = tid_from_sysfs(dev, NULL);
		if (t) {
			if (ctx->cbacks.dc_add)
				ctx->cbacks.dc_add(e->devname, t,
						   ctx->user_data);
			tid_free(t);
		}
	} else if (streq0(cntrltype, "io")) {
		if (ctx->cbacks.ioc_add)
			ctx->cbacks.ioc_add(e->devname, ctx->user_data);
	}

	sd_device_unref(dev);
out:
	soak_unlink(ctx, e);
	soak_entry_free(e);
	return 0;
}

static int schedule_soak(struct events_ctx *ctx, sd_device *dev,
			  const char *devname)
{
	struct soak_entry *e;
	const char *syspath = NULL;
	uint64_t now;
	int r;

	sd_device_get_syspath(dev, &syspath);
	if (!syspath)
		return -EINVAL;

	e = calloc(1, sizeof(*e));
	if (!e)
		return -ENOMEM;

	e->syspath = strdup(syspath);
	e->devname = strdup(devname);
	e->ctx = ctx;
	if (!e->syspath || !e->devname) {
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

static int nvme_monitor_handler(sd_device_monitor *monitor __attribute__((unused)),
				sd_device *dev, void *user_data)
{
	struct events_ctx *ctx = user_data;
	sd_device_action_t action;
	const char *devname = NULL, *cntrltype = NULL;
	const char *nvme_event = NULL, *nvme_aen = NULL;

	if (sd_device_get_action(dev, &action) < 0)
		return 0;
	if (sd_device_get_sysname(dev, &devname) < 0)
		return 0;

	switch (action) {
	case SD_DEVICE_ADD:
		// Schedule a soak timer; the soak callback reads cntrltype
		// and calls the appropriate add handler.
		schedule_soak(ctx, dev, devname);
		break;

	case SD_DEVICE_REMOVE:
		if (ctx->cbacks.nvme_remove)
			ctx->cbacks.nvme_remove(devname, ctx->user_data);
		break;

	case SD_DEVICE_CHANGE:
		/*
		 * Two relevant CHANGE events:
		 *   NVME_AEN=="0x70f002"      — DLP changed AEN
		 *   NVME_EVENT=="rediscover"  — ctrl reconnected after loss
		 * Both are handled the same way: re-fetch the DLP.
		 */
		sd_device_get_property_value(dev, "NVME_AEN", &nvme_aen);
		sd_device_get_property_value(dev, "NVME_EVENT", &nvme_event);
		sd_device_get_sysattr_value(dev, "cntrltype", &cntrltype);

		if (streq0(nvme_aen, NVME_AEN_DLP_CHANGED) ||
		    (streq0(nvme_event, "rediscover") &&
		     streq0(cntrltype, "discovery"))) {
			if (ctx->cbacks.dc_changed)
				ctx->cbacks.dc_changed(devname, ctx->user_data);
		}
		break;

	default:
		break;
	}

	return 0;
}

static int fc_monitor_handler(sd_device_monitor *monitor __attribute__((unused)),
			       sd_device *dev, void *user_data)
{
	struct events_ctx *ctx = user_data;
	const char *fc_event = NULL;
	const char *traddr = NULL, *host_traddr = NULL;
	struct libnvmf_tid *t;

	sd_device_get_property_value(dev, "FC_EVENT", &fc_event);
	if (!streq0(fc_event, "nvmediscovery"))
		return 0;

	/*
	 * Properties set by the kernel FC nvme-discovery uevent
	 * (nvme_fc_signal_discovery_scan(), drivers/nvme/host/fc.c).
	 * Note the "NVMEFC_" prefix, not "NVME_" - and the kernel never
	 * sends TRSVCID or NQN for this event: FC has no port concept,
	 * and the target is identified by address only, not by NQN.
	 */
	sd_device_get_property_value(dev, "NVMEFC_TRADDR", &traddr);
	sd_device_get_property_value(dev, "NVMEFC_HOST_TRADDR", &host_traddr);

	if (!traddr)
		return 0;

	/*
	 * The kernel only fires this uevent for a remote port that
	 * advertised FC_PORT_ROLE_NVME_DISCOVERY, so every instance of
	 * this event is, by the kernel's own gating, a DC - there is no
	 * NQN to check, and no well-known port to default either way.
	 */
	t = tid_new("fc", traddr, NULL,
		    "nqn.2014-08.org.nvmexpress.discovery",
		    host_traddr, NULL, NULL, true);
	if (!t)
		return 0;

	if (ctx->cbacks.fc_discovery)
		ctx->cbacks.fc_discovery(t, ctx->user_data);

	tid_free(t);
	return 0;
}

struct events_ctx *events_start(sd_event *event,
				const struct events_cbacks *cbacks,
				void *user_data)
{
	struct events_ctx *ctx;
	int r;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return NULL;

	ctx->event = event;
	ctx->cbacks = *cbacks;
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
	r = sd_device_monitor_start(ctx->nvme_monitor,
				    nvme_monitor_handler, ctx);
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
	r = sd_device_monitor_start(ctx->fc_monitor,
				    fc_monitor_handler, ctx);
	if (r < 0)
		goto err;

	return ctx;
err:
	disc_err("%s: %s", __func__, strerror(-r));
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
