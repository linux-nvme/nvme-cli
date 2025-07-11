// SPDX-License-Identifier: LGPL-2.1-or-later
/**
 * This file is part of libnvme.
 * Copyright (c) 2024 Daniel Wagner, SUSE LLC
 */

#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>

#include <libnvme.h>

static bool tree_dump(void)
{
	struct nvme_global_ctx *ctx;
	bool pass = false;
	int err;

	ctx = nvme_create_global_ctx(stdout, LOG_ERR);
	if (!ctx)
		return false;

	err = nvme_scan_topology(ctx, NULL, NULL);
	if (err && err != ENOENT)
		goto out;

	if (nvme_dump_tree(ctx))
		goto out;
	printf("\n");

	pass = true;

out:
	nvme_free_global_ctx(ctx);
	return pass;
}

int main(int argc, char *argv[])
{
	bool pass = true;

	pass = tree_dump();
	fflush(stdout);

	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
