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

#include <daemon-util/log.h>
#include <nvme/lib.h>

#include "config.h"
#include "import.h"

struct keysd_ctx {
	struct libnvme_global_ctx *nvme_ctx; // libnvme logging
	const char *conf_path;               // nvme-keysd's conf path
	const char *fabrics_conf;            // NULL: libnvme's default
	const char *creds_dir;               // encrypted credentials
	struct keysd_config *cfg;            // parsed @conf_path
	bool force_debug;                    // --debug forces DEBUG
	bool should_start;                   // --should-start: test, exit
};

static struct keysd_ctx ctx;

static void apply_log_level(void)
{
	int level = ctx.force_debug ? DMN_LOG_DEBUG : ctx.cfg->debug_level;

	dmn_log_set_level(level);
	libnvme_set_logging_level(ctx.nvme_ctx, level, false, false);
}

static bool should_start(void)
{
	if (import_needed(ctx.nvme_ctx, ctx.fabrics_conf))
		return true;

	log_info("no entry with a key source, nothing to do");

	return false;
}

static void usage(const char *prog)
{
	printf("Usage: %s [OPTIONS]\n"
	       "\n"
	       "  --config FILE, -c FILE  nvme-keysd configuration file\n"
	       "                          (default: " KEYSD_CONF_PATH ")\n"
	       "  --fabrics-config FILE   NVMe-oF configuration file\n"
	       "                          (default: libnvme's default)\n"
	       "  --creds-dir DIR         encrypted credentials\n"
	       "                          (default: " KEYSD_CREDS_DIR ")\n"
	       "  --should-start          exit 0 if there is work to do,\n"
	       "                          1 otherwise\n"
	       "  --debug, -d             enable debug logging (journal + libnvme)\n"
	       "  --help, -h              show this help and exit\n",
	       prog);
}

int main(int argc, char **argv)
{
	static const struct option long_opts[] = {
		{ "config",         required_argument, NULL, 'c' },
		{ "fabrics-config", required_argument, NULL, 'J' },
		{ "creds-dir",      required_argument, NULL, 'C' },
		{ "should-start",   no_argument,       NULL, 'S' },
		{ "debug",          no_argument,       NULL, 'd' },
		{ "help",           no_argument,       NULL, 'h' },
		{ NULL, 0,          NULL, 0 },
	};
	char *config_path_abs = NULL;
	char *fabrics_path_abs = NULL;
	char *creds_path_abs = NULL;
	int r, c;

	while ((c = getopt_long(argc, argv, "c:dh", long_opts,
				NULL)) != -1) {
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
		case 'C':
			free(creds_path_abs);
			creds_path_abs = realpath(optarg, NULL);
			if (!creds_path_abs) {
				fprintf(stderr,
					"--creds-dir: cannot resolve '%s': %s\n",
					optarg, strerror(errno));
				return 1;
			}
			break;
		case 'd':
			ctx.force_debug = true;
			break;
		case 'S':
			ctx.should_start = true;
			break;
		case 'J':
			free(fabrics_path_abs);
			fabrics_path_abs = realpath(optarg, NULL);
			if (!fabrics_path_abs) {
				fprintf(stderr,
					"--fabrics-config: cannot resolve '%s': %s\n",
					optarg, strerror(errno));
				return 1;
			}
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
	ctx.fabrics_conf = fabrics_path_abs;
	ctx.creds_dir = creds_path_abs ? creds_path_abs : KEYSD_CREDS_DIR;

	// Key material must never end up in a core dump.
	if (prctl(PR_SET_DUMPABLE, 0) < 0) {
		fprintf(stderr, "prctl(PR_SET_DUMPABLE): %s\n",
			strerror(errno));
		return 1;
	}

	if (ctx.force_debug)
		dmn_log_set_level(DMN_LOG_DEBUG);

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

	// Exit 1, never 255: systemd skips the unit on 1, but fails it on 255.
	if (ctx.should_start) {
		r = should_start() ? 0 : 1;
		config_free(ctx.cfg);
		libnvme_free_global_ctx(ctx.nvme_ctx);
		free(config_path_abs);
		free(fabrics_path_abs);
		free(creds_path_abs);

		return r;
	}

	import_keys(ctx.nvme_ctx, ctx.fabrics_conf, ctx.creds_dir);
	log_info("keys imported, exiting");

	config_free(ctx.cfg);
	libnvme_free_global_ctx(ctx.nvme_ctx);
	free(config_path_abs);
	free(fabrics_path_abs);
	free(creds_path_abs);

	return 0;
}
