// SPDX-License-Identifier: LGPL-2.1-or-later
/**
 * This file is part of libnvme.
 * Copyright (c) 2024 Daniel Wagner, SUSE LLC
 */

#include "options.h"

#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <libnvme.h>

#include "nvme/private.h"

static bool json_config(struct libnvme_global_ctx *ctx, char *file)
{
	char *hnqn, *hid;
	int err;

	/* We need to read the config in before we scan */
	err = libnvme_read_config(ctx, file);
	if (err)
		return false;

	err = libnvmf_host_get_ids(ctx, NULL, NULL, &hnqn, &hid);
	if (err)
		return false;

	if (strcmp(hosts[1].hostnqn, hnqn)) {
		printf("json config hostnqn '%s' does not match '%s'\n",
			hosts[1].hostnqn, hnqn);
		return false;
	}
	if (strcmp(hosts[1].hostid, hid)) {
		printf("json config hostid '%s' does not match '%s'\n",
			hosts[1].hostid, hid);
		return false;
	}

	free(hnqn);
	free(hid);

	return true;
}

static bool command_line(struct libnvme_global_ctx *ctx)
{
	char *hnqn, *hid;
	int err;

	err = libnvme_refresh_topology(ctx);
	if (err && err != -ENOENT)
		return false;

	err = libnvmf_host_get_ids(ctx, hosts[0].hostnqn, hosts[0].hostid,
		 &hnqn, &hid);
	if (err)
		return false;

	if (strcmp(hosts[0].hostnqn, hnqn)) {
		printf("json config hostnqn '%s' does not match '%s'\n",
			hosts[0].hostnqn, hnqn);
		return false;
	}
	if (strcmp(hosts[0].hostid, hid)) {
		printf("json config hostid '%s' does not match '%s'\n",
			hosts[0].hostid, hid);
		return false;
	}

	free(hnqn);
	free(hid);

	return true;
}

static bool from_file(struct libnvme_global_ctx *ctx)
{
	char *hnqn, *hid;
	int err;

	libnvme_global_ctx_set_hostnqn(ctx, hosts[0].hostnqn);
	libnvme_global_ctx_set_hostid(ctx, hosts[0].hostid);

	err = libnvme_refresh_topology(ctx);
	if (err && err != ENOENT)
		return false;

	err = libnvmf_host_get_ids(ctx, NULL, NULL, &hnqn, &hid);
	if (err)
		return false;

	if (strcmp(hosts[0].hostnqn, hnqn)) {
		printf("json config hostnqn '%s' does not match '%s'\n",
			hosts[0].hostnqn, hnqn);
		return false;
	}
	if (strcmp(hosts[0].hostid, hid)) {
		printf("json config hostid '%s' does not match '%s'\n",
			hosts[0].hostid, hid);
		return false;
	}

	free(hnqn);
	free(hid);

	return true;
}

int main(int argc, char *argv[])
{
	struct libnvme_global_ctx *ctx;
	bool pass;

	ctx = libnvme_create_global_ctx();
	if (!ctx)
		return EXIT_FAILURE;

	if (parse_args(ctx, argc, argv)) {
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
