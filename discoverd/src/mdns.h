/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */
#pragma once

#include <systemd/sd-event.h>

/*
 * mDNS (TP8009) discovery through systemd-resolved's io.systemd.Resolve
 * Varlink interface.
 *
 * Two version requirements apply:
 *
 *   - Build time: the sd_varlink client API exists since libsystemd v257.
 *     An older libsystemd, or -Dmdns=disabled, builds no-mdns.c instead.
 *   - Run time: the BrowseServices and ResolveService methods exist since
 *     systemd-resolved v258. mdns_start() asks the running
 *     systemd-resolved whether it has BrowseServices, because distributions
 *     backport features and a version number is not reliable.
 */

struct mdns_ctx;

struct mdns_callbacks {
	/*
	 * A DC endpoint was found. @transport is "tcp" or "rdma", from the
	 * TXT record's p= key. @nqn is the TXT record's nqn= key, or NULL.
	 */
	void (*service_add)(const char *traddr, const char *trsvcid,
			    const char *transport, const char *nqn,
			    const char *ifname, int ifindex, void *user_data);

	/* A reported DC endpoint, or its interface, disappeared. */
	void (*service_remove)(const char *traddr, const char *trsvcid,
			       const char *transport, const char *nqn,
			       const char *ifname, int ifindex,
			       void *user_data);
};

/*
 * Start mDNS discovery. Returns 0, or a negative errno:
 *   -ENOSYS      nvme-discoverd was built without mDNS support.
 *   -EOPNOTSUPP  systemd-resolved has no BrowseServices method.
 * Free *@mctxp with mdns_stop().
 */
int mdns_start(sd_event *event, const struct mdns_callbacks *callbacks,
	       void *user_data, struct mdns_ctx **mctxp);

void mdns_stop(struct mdns_ctx *mctx);
