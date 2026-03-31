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
	struct nvme_global_ctx *ctx;
	bool pass = false;
	int err;
	char *hostnqn, *hnqn;

	ctx = nvme_create_global_ctx(stderr, LOG_ERR);
	if (!ctx)
		return false;

	err = nvme_scan_topology(ctx, NULL, NULL);
	if (err && err != ENOENT)
		goto out;

	hostnqn = "nqn.2014-08.org.nvmexpress:uuid:ce4fee3e-c02c-11ee-8442-830d068a36c6";

	err = nvme_host_resolve_hostnqn(ctx, hostnqn, &hnqn);
	if (err)
		goto out;

	if (strcmp(hostnqn, hnqn)) {
		printf("json config hostnqn '%s' does not match '%s'\n", hostnqn, hnqn);
		goto out;
	}

	free(hnqn);

	pass = true;

out:
	nvme_free_global_ctx(ctx);
	return pass;
}

static bool json_config(char *file)
{
	struct nvme_global_ctx *ctx;
	bool pass = false;
	int err;
	char *hostnqn, *hnqn;

	setenv("LIBNVME_HOSTNQN", "", 1);

	ctx = nvme_create_global_ctx(stderr, LOG_ERR);
	if (!ctx)
		return false;

	/* We need to read the config in before we scan */
	err = nvme_read_config(ctx, file);
	if (err)
		goto out;

	err = nvme_scan_topology(ctx, NULL, NULL);
	if (err && err != ENOENT)
		goto out;

	hostnqn = "nqn.2014-08.org.nvmexpress:uuid:2cd2c43b-a90a-45c1-a8cd-86b33ab273b5";

	err = nvme_host_resolve_hostnqn(ctx, NULL, &hnqn);
	if (err)
		goto out;

	if (strcmp(hostnqn, hnqn)) {
		printf("json config hostnqn '%s' does not match '%s'\n", hostnqn, hnqn);
		goto out;
	}

	free(hnqn);

	pass = true;

out:
	nvme_free_global_ctx(ctx);
	return pass;
}

static bool from_file(void)
{
	struct nvme_global_ctx *ctx;
	bool pass = false;
	int err;
	char *hostnqn, *hnqn;

	hostnqn = "nqn.2014-08.org.nvmexpress:uuid:ce4fee3e-c02c-11ee-8442-830d068a36c6";

	setenv("LIBNVME_HOSTNQN", hostnqn, 1);

	ctx = nvme_create_global_ctx(stderr, LOG_ERR);
	if (!ctx)
		return false;

	err = nvme_scan_topology(ctx, NULL, NULL);
	if (err && err != ENOENT)
		goto out;

	err = nvme_host_resolve_hostnqn(ctx, NULL, &hnqn);
	if (err)
		goto out;

	if (strcmp(hostnqn, hnqn)) {
		printf("json config hostnqn '%s' does not match '%s'\n", hostnqn, hnqn);
		goto out;
	}

	free(hnqn);

	pass = true;

out:
	nvme_free_global_ctx(ctx);
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
