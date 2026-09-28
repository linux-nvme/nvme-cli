// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>

#include <systemd/sd-daemon.h>
#include <systemd/sd-event.h>

#include <daemon-util/log.h>
#include <daemon-util/signals.h>
#include <nvme/lib.h>

#include "config.h"

struct keysd_ctx {
	struct libnvme_global_ctx *nvme_ctx; // libnvme logging
	const char *conf_path;               // nvme-keysd's conf path
	struct keysd_config *cfg;            // parsed @conf_path
	sd_event *event;                     // sd_event main loop
	bool force_debug;                    // --debug forces DEBUG
};

static struct keysd_ctx ctx;

static void apply_log_level(void)
{
	int level = ctx.force_debug ? DMN_LOG_DEBUG : ctx.cfg->debug_level;

	dmn_log_set_level(level);
	libnvme_set_logging_level(ctx.nvme_ctx, level, false, false);
}

static void reload_config(void *user_data __attribute__((unused)))
{
	struct keysd_config *new_cfg;

	new_cfg = config_load(ctx.conf_path);
	if (!new_cfg) {
		log_err("failed to reload config");
		return;
	}
	config_free(ctx.cfg);
	ctx.cfg = new_cfg;
	apply_log_level();
}

static void usage(const char *prog)
{
	printf("Usage: %s [OPTIONS]\n"
	       "\n"
	       "  --config FILE, -c FILE  nvme-keysd configuration file\n"
	       "                          (default: " KEYSD_CONF_PATH ")\n"
	       "  --debug, -d             enable debug logging (journal + libnvme)\n"
	       "  --help, -h              show this help and exit\n",
	       prog);
}

int main(int argc, char **argv)
{
	static const struct option long_opts[] = {
		{ "config", required_argument, NULL, 'c' },
		{ "debug",  no_argument,       NULL, 'd' },
		{ "help",   no_argument,       NULL, 'h' },
		{ NULL, 0, NULL, 0 },
	};
	char *config_path_abs = NULL;
	int r, c;

	while ((c = getopt_long(argc, argv, "c:dh", long_opts, NULL)) != -1) {
		switch (c) {
		case 'c':
			free(config_path_abs);
			config_path_abs = realpath(optarg, NULL);
			if (!config_path_abs) {
				fprintf(stderr,
					"--config: cannot resolve '%s': %s\n",
					optarg, strerror(errno));
				return 1;
			}
			break;
		case 'd':
			ctx.force_debug = true;
			break;
		case 'h':
			usage(argv[0]);
			return 0;
		default:
			fprintf(stderr, "Try '%s --help'.\n", argv[0]);
			return 1;
		}
	}
	ctx.conf_path = config_path_abs ? config_path_abs : KEYSD_CONF_PATH;

	// Key material must never end up in a core dump.
	if (prctl(PR_SET_DUMPABLE, 0) < 0) {
		fprintf(stderr, "prctl(PR_SET_DUMPABLE): %s\n",
			strerror(errno));
		return 1;
	}

	if (ctx.force_debug)
		dmn_log_set_level(DMN_LOG_DEBUG);

	r = sd_event_default(&ctx.event);
	if (r < 0) {
		log_err("sd_event_default: %s", strerror(-r));
		return 1;
	}

	ctx.nvme_ctx = libnvme_create_global_ctx();
	if (!ctx.nvme_ctx) {
		log_err("libnvme_create_global_ctx: failed");
		return 1;
	}

	ctx.cfg = config_load(ctx.conf_path);
	if (!ctx.cfg) {
		log_err("config_load: failed");
		return 1;
	}
	apply_log_level();

	if (dmn_add_signal_handlers(ctx.event, reload_config, NULL) < 0)
		return 1;

	sd_notify(0, "READY=1");
	log_info("started");

	r = sd_event_loop(ctx.event);
	if (r < 0)
		log_err("sd_event_loop: %s", strerror(-r));

	config_free(ctx.cfg);
	libnvme_free_global_ctx(ctx.nvme_ctx);
	sd_event_unref(ctx.event);
	free(config_path_abs);

	return r < 0 ? 1 : 0;
}
