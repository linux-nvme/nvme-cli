/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

#include <errno.h>
#include <stdio.h>

#include <libnvme.h>

#include "argconfig.h"
#include "cleanup.h"
#include "global-ctx.h"
#include "nvme-cmds.h"
#include "nvme-json.h"
#include "nvme-print.h"
#include "plugin.h"

#include "plugins/ocp/ocp-print.h"
#include "plugins/ocp/ocp-smart-extended-log.h"
#include "plugins/ocp/ocp-utils.h"

static int monitor_smart(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc =
		"Retrieve SMART/health data for cloud fleet monitoring scripts. Combines the "
		"standard NVMe SMART log with the OCP SMART/health extended log (LID 0xC0) "
		"when the device supports it; OCP support is auto-detected. In JSON output, "
		"fields are always found under the same top-level keys ('smart_log', "
		"optionally 'ocp_smart_extended_log') regardless of the device, so scripts "
		"get a predictable shape across a mixed fleet.";

	__cleanup_libnvme_free struct nvme_smart_log *smart_log = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	struct ocp_smart_extended_log ocp_log;
	const char *devname;
	nvme_print_flags_t flags;
	bool has_ocp;
	int err;

	NVME_ARGS(opts);

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (nvme_args.verbose)
		flags |= VERBOSE;

	devname = libnvme_transport_handle_get_name(hdl);

	smart_log = libnvme_alloc(sizeof(*smart_log));
	if (!smart_log)
		return -ENOMEM;

	err = nvme_get_log_smart(hdl, NVME_NSID_ALL, smart_log);
	if (err) {
		nvme_show_err(err, "smart log");
		return err;
	}

	has_ocp = ocp_is_supported(hdl);
	if (has_ocp && ocp_get_smart_extended_log(hdl, &ocp_log))
		has_ocp = false;

	if (nvme_is_output_format_json()) {
		struct json_object *root = json_create_object();

		json_object_add_value_string(root, "device", devname);
		json_object_add_value_bool(root, "ocp_supported", has_ocp);
		json_object_add_value_object(root, "smart_log",
			nvme_smart_log_to_json(smart_log, NVME_NSID_ALL));
		if (has_ocp)
			json_object_add_value_object(root, "ocp_smart_extended_log",
				ocp_smart_extended_log_to_json(&ocp_log,
					nvme_args.output_format_ver));

		json_print_object(root, NULL);
		printf("\n");
		json_free_object(root);
	} else {
		nvme_show_smart_log(smart_log, NVME_NSID_ALL, devname, flags);
		if (has_ocp)
			ocp_smart_extended_log(&ocp_log, nvme_args.output_format_ver, flags);
	}

	return 0;
}

static struct command monitor_smart_cmd = {
	.name = "smart",
	.help = "Retrieve combined standard + OCP SMART/health monitoring data "
		"(auto-detects OCP support)",
	.fn = monitor_smart,
};

static struct command *commands[] = {
	&monitor_smart_cmd,
	NULL,
};

static struct plugin plugin = {
	.name = "monitor",
	.desc = "Cloud fleet health monitoring helpers",
	.version = NVME_VERSION,
	.core = true,
	.group = "Discovery & Logging",
};

static void __shr_constructor register_plugin(void)
{
	plugin_add_group(&plugin, NULL, commands);
	register_extension(&plugin);
}
