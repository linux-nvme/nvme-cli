// SPDX-License-Identifier: LGPL-2.1-or-later
/**
 * This file is part of libnvme.
 * Copyright (c) 2024 Daniel Wagner, SUSE LLC
 */

#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libnvme.h>

enum {
	OPT_SET_OPTIONS = 1000,
};

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [OPTIONS]\n"
		"\n"
		"Options:\n"
		"  --set-options key=value[,key=value...]\n",
		prog);
}

static int set_options(struct libnvme_global_ctx *ctx,
		      const char *key, const char *value)
{
	if (!strcmp(key, "test-sysfs-dir"))
		return libnvme_set_test_sysfs_dir(ctx, value);

	fprintf(stderr, "Unknown option '%s'\n", key);
	return -EINVAL;
}

static int parse_set_options(struct libnvme_global_ctx *ctx, char *arg)
{
	char *tok;

	while ((tok = strsep(&arg, ","))) {
		char *val;
		int err;

		if (!*tok)
			continue;

		val = strchr(tok, '=');
		if (!val) {
			fprintf(stderr, "Invalid option '%s'\n", tok);
			return -EINVAL;
		}

		*val++ = '\0';

		err = set_options(ctx, tok, val);
		if (err)
			return err;
	}

	return 0;
}

static bool tree_dump(struct libnvme_global_ctx *ctx)
{
	bool pass = false;
	int err;

	err = libnvme_scan_topology(ctx, NULL, NULL);
	if (err && err != -ENOENT && err != -EACCES) {
		fprintf(stderr, "libnvme_scan_topology failed: %d\n", err);
		goto out;
	}

	if (libnvme_dump_tree(ctx))
		goto out;

	printf("\n");
	pass = true;

out:
	return pass;
}

int main(int argc, char *argv[])
{
	static const struct option long_options[] = {
		{ "set-options", required_argument, NULL, OPT_SET_OPTIONS },
		{ NULL, 0, NULL, 0 }
	};

	struct libnvme_global_ctx *ctx;
	bool pass;
	int c;

	ctx = libnvme_create_global_ctx();
	if (!ctx)
		return EXIT_FAILURE;

	libnvme_set_logging_file(ctx, stdout);
	libnvme_set_logging_level(ctx, LIBNVME_LOG_ERR, false, false);

	while ((c = getopt_long(argc, argv, "", long_options, NULL)) != -1) {
		switch (c) {
		case OPT_SET_OPTIONS:
			if (parse_set_options(ctx, optarg)) {
				libnvme_free_global_ctx(ctx);
				return EXIT_FAILURE;
			}
			break;

		default:
			usage(argv[0]);
			libnvme_free_global_ctx(ctx);
			return EXIT_FAILURE;
		}
	}

	pass = tree_dump(ctx);

	libnvme_free_global_ctx(ctx);
	fflush(stdout);

	return pass ? EXIT_SUCCESS : EXIT_FAILURE;
}
