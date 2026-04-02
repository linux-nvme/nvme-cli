// SPDX-License-Identifier: LGPL-2.1-or-later
/**
 * This file is part of libnvme.
 * Copyright (c) 2024 Daniel Wagner, SUSE LLC
 */

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <libnvme.h>

static bool command_line(void)
{
	struct libnvme_global_ctx *ctx;
	bool pass = false;
	int err;
	char *hostnqn, *hostid, *hnqn, *hid;

	ctx = libnvme_create_global_ctx(stderr, LOG_ERR);
	if (!ctx)
		return false;

	err = libnvme_scan_topology(ctx, NULL, NULL);
	if (err && err != ENOENT)
		goto out;

	hostnqn = "nqn.2014-08.org.nvmexpress:uuid:ce4fee3e-c02c-11ee-8442-830d068a36c6";
	hostid = "ce4fee3e-c02c-11ee-8442-830d068a36c6";

	err = libnvme_host_get_ids(ctx, hostnqn, hostid, &hnqn, &hid);
	if (err)
		goto out;

	if (strcmp(hostnqn, hnqn)) {
		printf("json config hostnqn '%s' does not match '%s'\n", hostnqn, hnqn);
		goto out;
	}
	if (strcmp(hostid, hid)) {
		printf("json config hostid '%s' does not match '%s'\n", hostid, hid);
		goto out;
	}

	free(hnqn);
	free(hid);

	pass = true;

out:
	libnvme_free_global_ctx(ctx);
	return pass;
}

static bool json_config(char *file)
{
	struct libnvme_global_ctx *ctx;
	bool pass = false;
	int err;
	char *hostnqn, *hostid, *hnqn, *hid;

	setenv("LIBNVME_HOSTNQN", "", 1);
	setenv("LIBNVME_HOSTID", "", 1);

	ctx = libnvme_create_global_ctx(stderr, LOG_ERR);
	if (!ctx)
		return false;

	/* We need to read the config in before we scan */
	err = libnvme_read_config(ctx, file);
	if (err)
		goto out;

	err = libnvme_scan_topology(ctx, NULL, NULL);
	if (err && err != ENOENT)
		goto out;

	hostnqn = "nqn.2014-08.org.nvmexpress:uuid:2cd2c43b-a90a-45c1-a8cd-86b33ab273b5";
	hostid = "2cd2c43b-a90a-45c1-a8cd-86b33ab273b5";

	err = libnvme_host_get_ids(ctx, NULL, NULL, &hnqn, &hid);
	if (err)
		goto out;

	if (strcmp(hostnqn, hnqn)) {
		printf("json config hostnqn '%s' does not match '%s'\n", hostnqn, hnqn);
		goto out;
	}
	if (strcmp(hostid, hid)) {
		printf("json config hostid '%s' does not match '%s'\n", hostid, hid);
		goto out;
	}

	free(hnqn);
	free(hid);

	pass = true;

out:
	libnvme_free_global_ctx(ctx);
	return pass;
}

static bool from_file(void)
{
	struct libnvme_global_ctx *ctx;
	bool pass = false;
	int err;
	char *hostnqn, *hostid, *hnqn, *hid;

	hostnqn = "nqn.2014-08.org.nvmexpress:uuid:ce4fee3e-c02c-11ee-8442-830d068a36c6";
	hostid = "ce4fee3e-c02c-11ee-8442-830d068a36c6";

	setenv("LIBNVME_HOSTNQN", hostnqn, 1);
	setenv("LIBNVME_HOSTID", hostid, 1);

	ctx = libnvme_create_global_ctx(stderr, LOG_ERR);
	if (!ctx)
		return false;

	err = libnvme_scan_topology(ctx, NULL, NULL);
	if (err && err != ENOENT)
		goto out;

	err = libnvme_host_get_ids(ctx, NULL, NULL, &hnqn, &hid);
	if (err)
		goto out;

	if (strcmp(hostnqn, hnqn)) {
		printf("json config hostnqn '%s' does not match '%s'\n", hostnqn, hnqn);
		goto out;
	}
	if (strcmp(hostid, hid)) {
		printf("json config hostid '%s' does not match '%s'\n", hostid, hid);
		goto out;
	}

	free(hnqn);
	free(hid);

	pass = true;

out:
	libnvme_free_global_ctx(ctx);
	return pass;
}

int main(int argc, char *argv[])
{
	bool pass;

	pass = command_line();
	pass &= json_config(argv[1]);
	pass &= from_file();
	fflush(stdout);

	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
