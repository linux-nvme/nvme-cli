/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Functions exported by the id plugin. Plugins using them must add 'id' to
 * plugin_needs, see plugins/meson.build.
 */
#pragma once

#include <libnvme.h>

#include "nvme-json.h"
#include "plugin.h"

/*
 * Implement the id-ctrl command. @vs decodes the vendor specific data for
 * -V/--vendor-specific.
 */
int __id_ctrl(int argc, char **argv, struct command *acmd,
	struct plugin *plugin,
	void (*vs)(uint8_t *vs, struct json_object *root));
