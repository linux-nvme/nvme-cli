// SPDX-License-Identifier: LGPL-2.1-or-later
/**
 * This file is part of libnvme.
 * Copyright (c) 2024 Daniel Wagner, SUSE LLC
 */

#include <assert.h>

#include <libnvme.h>

int main(int argc, char *argv[])
{
	nvme_root_t r;

	r = nvme_create_root(stdout, LOG_ERR);
	assert(r);

	assert(nvme_scan_topology(r, NULL, NULL) == 0);

	assert(nvme_dump_tree(r) == 0);
	printf("\n");

	nvme_free_tree(r);
}
