// SPDX-License-Identifier: LGPL-2.1-or-later
/**
 * This file is part of libnvme.
 * Copyright (c) 2024 Daniel Wagner, SUSE LLC
 */

#include "options.h"

#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libnvme.h>

static bool config_dump(struct libnvme_global_ctx *ctx, const char *file)
{
	bool pass = false;
	int err;

	err = libnvme_scan_topology(ctx, NULL, NULL);
	if (err < 0 && err != -ENOENT)
		goto out;

	err = libnvme_read_config(ctx, file);
	if (err)
		goto out;

	err = libnvme_dump_config(ctx, STDOUT_FILENO);
	if (err)
		goto out;

	pass = true;

out:
	return pass;
}

int main(int argc, char *argv[])
{
	struct libnvme_global_ctx *ctx;
	const char *config_file = NULL;
	bool pass;

	ctx = libnvme_create_global_ctx();
	if (!ctx)
		return EXIT_FAILURE;

	libnvme_set_logging_level(ctx, LIBNVME_LOG_ERR, false, false);

	if (parse_args(ctx, argc, argv)) {
		libnvme_free_global_ctx(ctx);
		return EXIT_FAILURE;
	}

	config_file = argv[optind];

	pass = config_dump(ctx, config_file);

	libnvme_free_global_ctx(ctx);
	fflush(stdout);

	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
