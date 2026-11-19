/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Functions exported by the id plugin. Plugins using them must add 'id' to
 * plugin_needs, see plugins/meson.build.
 */
#pragma once

#include <libnvme.h>

#include "args.h"
#include "nvme-json.h"
#include "plugin.h"

/*
 * Implement the id-ctrl command. @vs decodes the vendor specific data for
 * -V/--vendor-specific.
 */
int __id_ctrl(int argc, char **argv, struct command *acmd,
	struct plugin *plugin,
	void (*vs)(uint8_t *vs, struct json_object *root));

void nvme_show_id_ctrl(struct libnvme_global_ctx *ctx,
	struct libnvme_transport_handle *hdl, struct nvme_id_ctrl *ctrl,
	nvme_print_flags_t flags, void (*vendor_show)(__u8 *vs,
	struct json_object *root));
