// SPDX-License-Identifier: LGPL-2.1-or-later
/**
 * This file is part of libnvme.
 * Copyright (c) 2024 Daniel Wagner, SUSE LLC
 */

#include "nvme/tree.h"
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include <ccan/array_size/array_size.h>

#include <libnvme.h>
#include <nvme/private.h>

static bool test_sysfs(const char *path, const char *filename)
{
	FILE *f;
	nvme_root_t r;
	int err;

	f = fopen(filename, "w");
	if (!f)
		return false;

	r = nvme_create_root(f, LOG_ERR);
	assert(r);

	err = nvme_scan_topology(r, NULL, NULL);
	if (!err)
		nvme_dump_tree(r);
	fprintf(f, "\n");

	nvme_free_tree(r);
	fclose(f);

	return err == 0;
}

static bool compare_content(const char *filename1, const char *filename2)
{
	FILE *f1, *f2;
	char c1, c2;
	bool pass = false;

	f1 = fopen(filename1, "r");
	if (!f1)
		return false;

	f2 = fopen(filename2, "r");
	if (!f2) {
		fclose(f1);
		return false;
	}

	do {
		c1 = getc(f1);
		c2 = getc(f2);
		if (c1 != c2)
			goto out;
	} while (c1 != EOF || c2 != EOF);

	if (c1 == c2)
		pass = true;
out:
	fclose(f1);
	fclose(f2);

	return pass;
}

int main(int argc, char *argv[])
{
	bool pass = true;

	if (argc < 4) {
		fprintf(stderr, "usage: test-sysfs SYSFS_DIR OUTPUT_FILE COMPARE_FILE\n");
		return EXIT_FAILURE;
	}

	pass &= test_sysfs(argv[1], argv[2]);
	pass &= compare_content(argv[2], argv[3]);

	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
