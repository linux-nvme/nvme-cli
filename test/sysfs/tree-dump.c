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
	bool pass = false;
	nvme_root_t r;
	int err;

	r = nvme_create_root(stdout, LOG_ERR);
	if (!r)
		return false;

	err = nvme_scan_topology(r, NULL, NULL);
	if (err) {
		if (errno != ENOENT)
			goto out;
	}

	if (nvme_dump_tree(r))
		goto out;
	printf("\n");

	pass = true;

out:
	nvme_free_tree(r);
	return pass;
}

int main(int argc, char *argv[])
{
	bool pass = true;

	pass = tree_dump();
	fflush(stdout);

	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
