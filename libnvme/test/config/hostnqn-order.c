// SPDX-License-Identifier: LGPL-2.1-or-later
/**
 * This file is part of libnvme.
 * Copyright (c) 2024 Daniel Wagner, SUSE LLC
 */

#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <libnvme.h>

#include "nvme/private.h"
#include "nvme/private-fabrics.h"

enum {
	OPT_SET_OPTIONS = 1000,
};

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [OPTIONS] <config-file>\n"
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

static bool json_config(struct libnvme_global_ctx *ctx, char *file)
{
	char *hostnqn, *hostid, *hnqn, *hid;
	int err;

	setenv("LIBNVME_HOSTNQN", "", 1);
	setenv("LIBNVME_HOSTID", "", 1);

	/* We need to read the config in before we scan */
	err = libnvme_read_config(ctx, file);
	if (err)
		return false;

	err = libnvme_scan_topology(ctx, NULL, NULL);
	if (err && err != -ENOENT)
		return false;

	hostnqn = "nqn.2014-08.org.nvmexpress:uuid:2cd2c43b-a90a-45c1-a8cd-86b33ab273b5";
	hostid = "2cd2c43b-a90a-45c1-a8cd-86b33ab273b5";

	err = libnvmf_host_get_ids(ctx, NULL, NULL, &hnqn, &hid);
	if (err)
		return false;

	if (strcmp(hostnqn, hnqn)) {
		printf("json config hostnqn '%s' does not match '%s'\n", hostnqn, hnqn);
		return false;
	}
	if (strcmp(hostid, hid)) {
		printf("json config hostid '%s' does not match '%s'\n", hostid, hid);
		return false;
	}

	free(hnqn);
	free(hid);

	return true;
}

static bool command_line(struct libnvme_global_ctx *ctx)
{
	char *hostnqn, *hostid, *hnqn, *hid;
	int err;

	err = libnvme_refresh_topology(ctx);
	if (err && err != -ENOENT)
		return false;

	hostnqn = "nqn.2014-08.org.nvmexpress:uuid:ce4fee3e-c02c-11ee-8442-830d068a36c6";
	hostid = "ce4fee3e-c02c-11ee-8442-830d068a36c6";

	err = libnvmf_host_get_ids(ctx, hostnqn, hostid, &hnqn, &hid);
	if (err)
		return false;

	if (strcmp(hostnqn, hnqn)) {
		printf("json config hostnqn '%s' does not match '%s'\n", hostnqn, hnqn);
		return false;
	}
	if (strcmp(hostid, hid)) {
		printf("json config hostid '%s' does not match '%s'\n", hostid, hid);
		return false;
	}

	free(hnqn);
	free(hid);

	return true;
}

static bool from_file(struct libnvme_global_ctx *ctx)
{
	char *hostnqn, *hostid, *hnqn, *hid;
	int err;

	hostnqn = "nqn.2014-08.org.nvmexpress:uuid:ce4fee3e-c02c-11ee-8442-830d068a36c6";
	hostid = "ce4fee3e-c02c-11ee-8442-830d068a36c6";

	setenv("LIBNVME_HOSTNQN", hostnqn, 1);
	setenv("LIBNVME_HOSTID", hostid, 1);

	err = libnvme_refresh_topology(ctx);
	if (err && err != ENOENT)
		return false;

	err = libnvmf_host_get_ids(ctx, NULL, NULL, &hnqn, &hid);
	if (err)
		return false;

	if (strcmp(hostnqn, hnqn)) {
		printf("json config hostnqn '%s' does not match '%s'\n", hostnqn, hnqn);
		return false;
	}
	if (strcmp(hostid, hid)) {
		printf("json config hostid '%s' does not match '%s'\n", hostid, hid);
		return false;
	}

	free(hnqn);
	free(hid);

	return true;
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

	if (optind >= argc) {
		usage(argv[0]);
		libnvme_free_global_ctx(ctx);
		return EXIT_FAILURE;
	}

	pass = json_config(ctx, argv[optind]);
	pass &= command_line(ctx);
	pass &= from_file(ctx);
	fflush(stdout);

	libnvme_free_global_ctx(ctx);

	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
