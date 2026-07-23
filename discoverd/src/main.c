// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <systemd/sd-daemon.h>
#include <systemd/sd-event.h>

#include <nvme/lib.h>

#include "config.h"
#include "ctx.h"
#include "log.h"
#include "state.h"

static struct discoverd_ctx ctx;

/*
 * Apply the effective log level to both discoverd and its in-process libnvme
 * context. A command-line --debug (ctx.force_debug) forces DEBUG and
 * overrides the config; otherwise the configured debug-level (default INFO)
 * is used. Called at startup after config_load() and again after a SIGHUP
 * reload, since the libnvme context outlives any single config.
 */
static void apply_log_level(void)
{
	int level = ctx.force_debug ? DISC_LOG_DEBUG : ctx.cfg->debug_level;

	log_set_level(level);
	libnvme_set_logging_level(ctx.nvme_ctx, level, false, false);
}

static int sighup_handler(sd_event_source *src __attribute__((unused)),
			  const struct signalfd_siginfo *si __attribute__((unused)),
			  void *user_data __attribute__((unused)))
{
	struct discoverd_config *new_cfg;

	sd_notify(0, "RELOADING=1\n"
		     "STATUS=Reloading configuration...");

	new_cfg = config_load(ctx.conf_path);
	if (!new_cfg) {
		disc_err("failed to reload config");
		sd_notify(0, "READY=1");
		return 0;
	}

	config_free(ctx.cfg);
	ctx.cfg = new_cfg;
	apply_log_level();

	sd_notify(0, "READY=1");
	return 0;
}

/* Graceful shutdown: leave the event loop so main()'s cleanup runs. */
static int sigterm_handler(sd_event_source *src __attribute__((unused)),
			   const struct signalfd_siginfo *si __attribute__((unused)),
			   void *user_data __attribute__((unused)))
{
	sd_event_exit(ctx.event, 0);
	return 0;
}

int main(int argc, char **argv)
{
	static const struct option long_opts[] = {
		{ "config", required_argument, NULL, 'c' },
		{ "debug",  no_argument,       NULL, 'd' },
		{ "help",   no_argument,       NULL, 'h' },
		{ NULL, 0, NULL, 0 },
	};
	const char *config_path = NULL;
	char *config_path_abs = NULL;
	bool debug = false;
	sigset_t mask;
	int r, c;

	while ((c = getopt_long(argc, argv, "c:dh", long_opts, NULL)) != -1) {
		switch (c) {
		case 'c':
			config_path = optarg;
			break;
		case 'd':
			debug = true;
			break;
		case 'h':
			printf("Usage: %s [OPTIONS]\n"
			       "\n"
			       "All options are optional; specify one only to override its default.\n"
			       "  --config FILE, -c FILE  discoverd configuration file\n"
			       "                          (default: " DISCOVERD_CONF_PATH ")\n"
			       "  --debug, -d             enable debug logging (journal + libnvme)\n"
			       "  --help, -h              show this help and exit\n",
			       argv[0]);
			return 0;
		default:
			fprintf(stderr, "Try '%s --help'.\n", argv[0]);
			return 1;
		}
	}

	if (debug)
		log_set_level(DISC_LOG_DEBUG);
	ctx.force_debug = debug;

	/*
	 * Resolve --config to an absolute path so a SIGHUP reload (which may
	 * run with a different working directory) reads the same file, and
	 * fail fast if it does not exist. Without --config, the build-time
	 * default is used verbatim (config_load() tolerates its absence).
	 */
	if (config_path) {
		config_path_abs = realpath(config_path, NULL);
		if (!config_path_abs) {
			fprintf(stderr, "--config: cannot resolve '%s': %s\n",
				config_path, strerror(errno));
			return 1;
		}
	}
	ctx.conf_path = config_path_abs ? config_path_abs : DISCOVERD_CONF_PATH;

	r = sd_event_default(&ctx.event);
	if (r < 0) {
		disc_err("sd_event_default: %s", strerror(-r));
		return 1;
	}

	r = state_init();
	if (r < 0) {
		disc_err("state_init: %s", strerror(-r));
		return 1;
	}

	ctx.nvme_ctx = libnvme_create_global_ctx();
	if (!ctx.nvme_ctx) {
		disc_err("libnvme_create_global_ctx: failed");
		return 1;
	}
	libnvme_set_logging_level(ctx.nvme_ctx,
				  debug ? LIBNVME_LOG_DEBUG : LIBNVME_LOG_ERR,
				  false, false);

	ctx.cfg = config_load(ctx.conf_path);
	if (!ctx.cfg) {
		disc_err("config_load: failed");
		return 1;
	}

	/* Now that debug-level has been read, apply the effective log level. */
	apply_log_level();

	/* Block these from normal delivery; handle them via sd_event. */
	sigemptyset(&mask);
	sigaddset(&mask, SIGHUP);
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGINT);
	sigprocmask(SIG_BLOCK, &mask, NULL);

	r = sd_event_add_signal(ctx.event, NULL, SIGHUP, sighup_handler, NULL);
	if (r < 0) {
		disc_err("sd_event_add_signal(SIGHUP): %s", strerror(-r));
		return 1;
	}

	/* SIGTERM (systemctl stop) and SIGINT (Ctrl-C) → graceful shutdown. */
	r = sd_event_add_signal(ctx.event, NULL, SIGTERM, sigterm_handler, NULL);
	if (r < 0) {
		disc_err("sd_event_add_signal(SIGTERM): %s", strerror(-r));
		return 1;
	}
	r = sd_event_add_signal(ctx.event, NULL, SIGINT, sigterm_handler, NULL);
	if (r < 0) {
		disc_err("sd_event_add_signal(SIGINT): %s", strerror(-r));
		return 1;
	}

	sd_notify(0, "READY=1");

	r = sd_event_loop(ctx.event);
	if (r < 0)
		disc_err("sd_event_loop: %s", strerror(-r));

	free(config_path_abs);
	config_free(ctx.cfg);
	libnvme_free_global_ctx(ctx.nvme_ctx);
	sd_event_unref(ctx.event);

	return r < 0 ? 1 : 0;
}
