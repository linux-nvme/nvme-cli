// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <shared/fs-util.h>

#include "stop.h"

static char root[] = "/tmp/test-stop-XXXXXX";

static bool check(bool cond, const char *what)
{
	printf(" - %s [%s]\n", what, cond ? "PASS" : "FAIL");
	return cond;
}

static void put(const char *rel, const char *content)
{
	char path[PATH_MAX];
	FILE *f;

	snprintf(path, sizeof(path), "%s/%s", root, rel);
	if (shr_mkdir_from_fname(path, 0755) < 0) {
		perror(path);
		exit(1);
	}
	if (!content)
		return;
	f = fopen(path, "w");
	if (!f) {
		perror(path);
		exit(1);
	}
	fputs(content, f);
	fclose(f);
}

static void mounts(const char *line)
{
	char buf[512];

	snprintf(buf, sizeof(buf), "22 1 0:21 / /proc rw - proc proc rw\n%s",
		 line ? line : "");
	put("proc/self/mountinfo", buf);
}

int main(void)
{
	bool pass = true;

	if (!mkdtemp(root)) {
		perror("mkdtemp");
		return 1;
	}

	// nvme0: no native multipath, one partitioned namespace.
	put("sys/class/nvme/nvme0/nvme0n1/", NULL);
	put("sys/class/block/nvme0n1/dev", "259:0\n");
	put("sys/class/block/nvme0n1/holders/", NULL);
	put("sys/class/block/nvme0n1/nvme0n1p1/partition", "1\n");
	put("sys/class/block/nvme0n1p1/dev", "259:1\n");

	// nvme1: native multipath, LVM on the namespace.
	put("sys/class/nvme/nvme1/nvme1c1n1/", NULL);
	put("sys/class/nvme-subsystem/nvme-subsys1/nvme1/", NULL);
	put("sys/class/nvme-subsystem/nvme-subsys1/nvme1n1/", NULL);
	put("sys/class/block/nvme1n1/dev", "259:2\n");
	put("sys/class/block/nvme1n1/holders/dm-0/", NULL);
	put("sys/class/block/dm-0/dev", "253:0\n");

	put("proc/swaps",
	    "Filename\tType\tSize\tUsed\tPriority\n");

	printf("test_stop_ctrl_in_use:\n");

	mounts(NULL);
	pass &= check(!stop_ctrl_in_use(root, "nvme0"),
		      "nothing mounted: nvme0 not in use");
	pass &= check(!stop_ctrl_in_use(root, "nvme1"),
		      "nothing mounted: nvme1 not in use");

	mounts("30 1 259:0 / /mnt rw - xfs /dev/nvme0n1 rw\n");
	pass &= check(stop_ctrl_in_use(root, "nvme0"),
		      "namespace mounted: in use");
	pass &= check(!stop_ctrl_in_use(root, "nvme1"),
		      "other controller's namespace mounted: not in use");

	mounts("30 1 259:1 / / rw - xfs none rw\n");
	pass &= check(stop_ctrl_in_use(root, "nvme0"),
		      "partition mounted: in use");

	mounts("30 1 253:0 / /data rw - ext4 none rw\n");
	pass &= check(stop_ctrl_in_use(root, "nvme1"),
		      "LVM on a multipath namespace mounted: in use");
	pass &= check(!stop_ctrl_in_use(root, "nvme0"),
		      "LVM on another subsystem mounted: not in use");

	pass &= check(!stop_ctrl_in_use(root, "nvme9"),
		      "unknown controller: not in use");

	// nvme2: more namespaces than any fixed-size set would hold.
	put("sys/class/nvme/nvme2/", NULL);
	for (int i = 1; i <= 1000; i++) {
		char rel[64], dev[32];

		snprintf(rel, sizeof(rel), "sys/class/nvme/nvme2/nvme2n%d/", i);
		put(rel, NULL);
		snprintf(rel, sizeof(rel), "sys/class/block/nvme2n%d/dev", i);
		snprintf(dev, sizeof(dev), "259:%d\n", 1000 + i);
		put(rel, dev);
	}
	mounts("30 1 259:2000 / /big rw - xfs none rw\n");
	pass &= check(stop_ctrl_in_use(root, "nvme2"),
		      "1000th of 1000 namespaces mounted: in use");

	shr_rmdir_recursive(root);

	return pass ? 0 : 1;
}
