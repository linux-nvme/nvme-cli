// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <systemd/sd-json.h>
#include <systemd/sd-varlink.h>

#include "mdns.h"

#define RESOLVE_VARLINK_ADDRESS "/run/systemd/resolve/io.systemd.Resolve"
#define RESOLVE_INTERFACE       "io.systemd.Resolve"
#define VARLINK_GET_DESCRIPTION "org.varlink.service.GetInterfaceDescription"

struct mdns_ctx {
	struct mdns_callbacks callbacks;
	void *user_data;
	sd_varlink *link;
};

/*
 * Returns 0 if io.systemd.Resolve has a BrowseServices method, -EOPNOTSUPP
 * if not, or another negative errno.
 */
static int resolved_has_browse_services(sd_varlink *link)
{
	sd_json_variant *reply = NULL;
	const char *error_id = NULL;
	sd_json_variant *desc;
	const char *text;
	int r;

	r = sd_varlink_callbo(link, VARLINK_GET_DESCRIPTION, &reply, &error_id,
			      SD_JSON_BUILD_PAIR_STRING("interface",
							RESOLVE_INTERFACE));
	if (r < 0)
		return r;
	if (error_id)
		return -EPROTO;

	desc = sd_json_variant_by_key(reply, "description");
	text = desc ? sd_json_variant_string(desc) : NULL;
	if (!text || !strstr(text, "method BrowseServices("))
		return -EOPNOTSUPP;

	return 0;
}

int mdns_start(sd_event *event, const struct mdns_callbacks *callbacks,
	       void *user_data, struct mdns_ctx **mctxp)
{
	struct mdns_ctx *mctx;
	int r;

	mctx = calloc(1, sizeof(*mctx));
	if (!mctx)
		return -ENOMEM;

	mctx->callbacks = *callbacks;
	mctx->user_data = user_data;

	r = sd_varlink_connect_address(&mctx->link, RESOLVE_VARLINK_ADDRESS);
	if (r < 0)
		goto err;

	r = sd_varlink_attach_event(mctx->link, event,
				    SD_EVENT_PRIORITY_NORMAL);
	if (r < 0)
		goto err;

	r = resolved_has_browse_services(mctx->link);
	if (r < 0)
		goto err;

	*mctxp = mctx;

	return 0;
err:
	mdns_stop(mctx);

	return r;
}

void mdns_stop(struct mdns_ctx *mctx)
{
	if (!mctx)
		return;

	sd_varlink_flush_close_unref(mctx->link);
	free(mctx);
}
