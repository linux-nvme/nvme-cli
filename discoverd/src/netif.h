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

/*
 * Network interface tracking. Reports the interfaces that are candidates
 * for mDNS: IFF_UP and IFF_MULTICAST set, IFF_LOOPBACK clear.
 *
 * systemd-resolved's BrowseServices method browses one interface at a
 * time. Browsing all interfaces with ifindex=0 requires systemd-resolved
 * >= v260. nvme-discoverd supports >= v258, so it tracks the interfaces
 * itself.
 */
struct netif_callbacks {
	/*
	 * An interface became a candidate. Called from netif_start() for
	 * each candidate already present, then on hotplug and flag changes.
	 */
	void (*iface_add)(int ifindex, const char *ifname, void *user_data);

	/*
	 * A reported candidate was removed or is no longer a candidate.
	 * Never called for an interface that iface_add did not report.
	 */
	void (*iface_remove)(int ifindex, const char *ifname, void *user_data);
};

struct netif_ctx;

/* Returns 0 or a negative errno. Free *@nctxp with netif_stop(). */
int netif_start(sd_event *event, const struct netif_callbacks *callbacks,
		void *user_data, struct netif_ctx **nctxp);

void netif_stop(struct netif_ctx *nctx);

/* Whether an interface with these IFF_* flags is an mDNS candidate. */
bool netif_is_candidate(unsigned int flags);
