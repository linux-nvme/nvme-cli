// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <errno.h>
#include <net/if.h>
#include <stdlib.h>
#include <systemd/sd-device.h>

#include <ccan/list/list.h>

#include "log.h"
#include "netif.h"

struct tracked_iface {
	struct list_node entry;
	int ifindex;
};

struct netif_ctx {
	struct netif_callbacks callbacks;
	void *user_data;
	sd_device_monitor *monitor;
	struct list_head tracked; // candidates reported with iface_add
};

bool netif_is_candidate(unsigned int flags)
{
	return (flags & IFF_UP) && (flags & IFF_MULTICAST) &&
	       !(flags & IFF_LOOPBACK);
}

static struct tracked_iface *tracked_find(struct netif_ctx *nctx, int ifindex)
{
	struct tracked_iface *e;

	list_for_each(&nctx->tracked, e, entry) {
		if (e->ifindex == ifindex)
			return e;
	}

	return NULL;
}

static unsigned int device_flags(sd_device *dev)
{
	const char *val = NULL;

	sd_device_get_sysattr_value(dev, "flags", &val);

	return val ? (unsigned int)strtoul(val, NULL, 0) : 0;
}

/*
 * Bring the tracked state of one interface in line with @candidate. This
 * is the only place that calls iface_add and iface_remove.
 */
static void reconcile(struct netif_ctx *nctx, int ifindex, const char *ifname,
		      bool candidate)
{
	struct tracked_iface *e = tracked_find(nctx, ifindex);

	if (candidate && !e) {
		e = calloc(1, sizeof(*e));
		if (!e) {
			disc_err("%s: out of memory", ifname);
			return;
		}
		e->ifindex = ifindex;
		list_add(&nctx->tracked, &e->entry);
		if (nctx->callbacks.iface_add)
			nctx->callbacks.iface_add(ifindex, ifname,
						  nctx->user_data);
	} else if (!candidate && e) {
		list_del(&e->entry);
		free(e);
		if (nctx->callbacks.iface_remove)
			nctx->callbacks.iface_remove(ifindex, ifname,
						     nctx->user_data);
	}
}

static void reconcile_device(struct netif_ctx *nctx, sd_device *dev,
			     bool removed)
{
	const char *ifname = NULL;
	int ifindex;

	if (sd_device_get_sysname(dev, &ifname) < 0)
		return;
	if (sd_device_get_ifindex(dev, &ifindex) < 0)
		return;

	reconcile(nctx, ifindex, ifname,
		  !removed && netif_is_candidate(device_flags(dev)));
}

static int net_monitor_handler(
		sd_device_monitor *monitor __attribute__((unused)),
		sd_device *dev, void *user_data)
{
	sd_device_action_t action;

	if (sd_device_get_action(dev, &action) < 0)
		return 0;

	reconcile_device(user_data, dev, action == SD_DEVICE_REMOVE);

	return 0;
}

static int enumerate_existing(struct netif_ctx *nctx)
{
	sd_device_enumerator *en = NULL;
	sd_device *dev;
	int r;

	r = sd_device_enumerator_new(&en);
	if (r < 0)
		return r;
	r = sd_device_enumerator_add_match_subsystem(en, "net", true);
	if (r < 0)
		goto out;

	for (dev = sd_device_enumerator_get_device_first(en); dev;
	     dev = sd_device_enumerator_get_device_next(en))
		reconcile_device(nctx, dev, false);
out:
	sd_device_enumerator_unref(en);

	return r;
}

int netif_start(sd_event *event, const struct netif_callbacks *callbacks,
		void *user_data, struct netif_ctx **nctxp)
{
	struct netif_ctx *nctx;
	int r;

	nctx = calloc(1, sizeof(*nctx));
	if (!nctx)
		return -ENOMEM;

	nctx->callbacks = *callbacks;
	nctx->user_data = user_data;
	list_head_init(&nctx->tracked);

	r = sd_device_monitor_new(&nctx->monitor);
	if (r < 0)
		goto err;
	r = sd_device_monitor_filter_add_match_subsystem_devtype(
		nctx->monitor, "net", NULL);
	if (r < 0)
		goto err;
	r = sd_device_monitor_attach_event(nctx->monitor, event);
	if (r < 0)
		goto err;
	r = sd_device_monitor_start(nctx->monitor, net_monitor_handler, nctx);
	if (r < 0)
		goto err;

	r = enumerate_existing(nctx);
	if (r < 0)
		goto err;

	*nctxp = nctx;

	return 0;
err:
	netif_stop(nctx);

	return r;
}

void netif_stop(struct netif_ctx *nctx)
{
	struct tracked_iface *e, *next;

	if (!nctx)
		return;

	list_for_each_safe(&nctx->tracked, e, next, entry)
		free(e);

	sd_device_monitor_unref(nctx->monitor);
	free(nctx);
}
