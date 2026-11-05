// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE LLC
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <nvme/fabrics.h>

#include <shared/fs-util.h>
#include <shared/string-util.h>

#include "sysfs.h"

#define DC_NQN		"nqn.2014-08.org.nvmexpress.discovery"
#define IOC_NQN		"nqn.1992-08.com.example:sn.xxxx:subsystem.vol1"
#define HOST_NQN	"nqn.2014-08.org.nvmexpress:uuid:c0ffee00-0000-0000-0000-000000000001"

static const char *root;

static bool failed;

static void check_str(const char *name, const char *got, const char *want)
{
	if (shr_streq0(got, want)) {
		printf(" - %s [PASS]\n", name);
		return;
	}

	printf(" - %s: got '%s', want '%s' [FAIL]\n", name,
	       got ? got : "(null)", want ? want : "(null)");
	failed = true;
}

static void check_bool(const char *name, bool got, bool want)
{
	if (got == want) {
		printf(" - %s [PASS]\n", name);
		return;
	}

	printf(" - %s: got %d, want %d [FAIL]\n", name, got, want);
	failed = true;
}

/* Write one attribute of a fake controller, the way the kernel shows it. */
static void write_attr(const char *devname, const char *attr,
		       const char *value)
{
	char path[512];
	FILE *f;

	snprintf(path, sizeof(path), "%s/sys/class/nvme/%s", root, devname);
	if (shr_mkdir_p(path, 0755)) {
		printf("mkdir %s failed\n", path);
		exit(EXIT_FAILURE);
	}

	snprintf(path, sizeof(path), "%s/sys/class/nvme/%s/%s", root,
		 devname, attr);
	f = fopen(path, "w");
	if (!f) {
		printf("cannot write %s\n", path);
		exit(EXIT_FAILURE);
	}
	fprintf(f, "%s\n", value);
	fclose(f);
}

static void test_paths(void)
{
	char want[512];
	char *p;

	printf("paths:\n");

	sysfs_set_root(NULL);
	p = sysfs_nvme_path("nvme3");
	check_str("real nvme path", p, "/sys/class/nvme/nvme3");
	free(p);

	sysfs_set_root(root);
	p = sysfs_nvme_path("nvme3");
	snprintf(want, sizeof(want), "%s/sys/class/nvme/nvme3", root);
	check_str("rerooted nvme path", p, want);
	free(p);

	p = sysfs_path("/sys/firmware/acpi/tables");
	snprintf(want, sizeof(want), "%s/sys/firmware/acpi/tables", root);
	check_str("rerooted path", p, want);
	free(p);
}

static void test_attr(void)
{
	char *v;

	printf("attributes:\n");

	write_attr("nvme0", "state", "live");
	v = sysfs_nvme_attr("nvme0", "state");
	check_str("trailing newline dropped", v, "live");
	free(v);

	v = sysfs_nvme_attr("nvme0", "missing");
	check_str("missing attribute", v, NULL);
	free(v);

	v = sysfs_nvme_attr("nvme9", "state");
	check_str("missing controller", v, NULL);
	free(v);
}

static void test_tid(void)
{
	struct libnvmf_tid *t;
	bool is_dc = true;

	printf("tid_from_sysfs:\n");

	write_attr("nvme1", "transport", "tcp");
	write_attr("nvme1", "address",
		   "traddr=192.0.2.1,trsvcid=4420,src_addr=192.0.2.100");
	write_attr("nvme1", "subsysnqn", IOC_NQN);
	write_attr("nvme1", "hostnqn", HOST_NQN);
	write_attr("nvme1", "cntrltype", "io");

	t = tid_from_sysfs("nvme1", &is_dc);
	check_bool("I/O controller", t != NULL, true);
	if (t) {
		check_bool("not a DC", is_dc, false);
		check_str("traddr", libnvmf_tid_get_traddr(t), "192.0.2.1");
		check_str("trsvcid", libnvmf_tid_get_trsvcid(t), "4420");
		check_str("src_addr as host_traddr",
			  libnvmf_tid_get_host_traddr(t), "192.0.2.100");
		check_str("subsysnqn", libnvmf_tid_get_subsysnqn(t), IOC_NQN);
		libnvmf_tid_free(t);
	}

	write_attr("nvme2", "transport", "fc");
	write_attr("nvme2", "address",
		   "traddr=nn-0x1:pn-0x2,host_traddr=nn-0x3:pn-0x4");
	write_attr("nvme2", "subsysnqn", DC_NQN);
	write_attr("nvme2", "cntrltype", "discovery");

	t = tid_from_sysfs("nvme2", &is_dc);
	check_bool("discovery controller", t != NULL, true);
	if (t) {
		check_bool("is a DC", is_dc, true);
		check_str("host_traddr", libnvmf_tid_get_host_traddr(t),
			  "nn-0x3:pn-0x4");
		libnvmf_tid_free(t);
	}

	// No address: not a controller that can be matched.
	write_attr("nvme3", "transport", "tcp");
	write_attr("nvme3", "subsysnqn", IOC_NQN);
	t = tid_from_sysfs("nvme3", &is_dc);
	check_bool("no address", t == NULL, true);
	libnvmf_tid_free(t);
}

int main(void)
{
	char tmpl[] = "/tmp/discoverd-sysfs-test-XXXXXX";
	int ret;

	root = mkdtemp(tmpl);
	if (!root) {
		perror("mkdtemp");
		return EXIT_FAILURE;
	}

	test_paths();
	test_attr();
	test_tid();

	sysfs_set_root(NULL);
	ret = shr_rmdir_recursive(root);
	if (ret)
		printf("cannot remove %s\n", root);

	return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}
