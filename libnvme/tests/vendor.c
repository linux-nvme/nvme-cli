// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 SUSE LLC
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 *
 * The vendor defaults of vendor.d: the parser, the precedence of the
 * files, the udev-style match and the attributes written, against a test
 * sysfs and a test base directory.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <shared/fs-util.h>

#include <nvme/lib.h>

#include "nvme/private.h"
#include "nvme/private-fabrics.h"

static char root[64];
static char lib_dir[512], run_dir[512], etc_dir[512];

static bool failed;

/* The directories in their order: /etc, /run, /usr/lib */
static struct libnvmf_vendor_defaults *load_all(struct libnvme_global_ctx *ctx)
{
	const char *dirs[3];

	dirs[0] = etc_dir;
	dirs[1] = run_dir;
	dirs[2] = lib_dir;
	return libnvmf_vendor_load(ctx, dirs, 3);
}

static void check_str(const char *name, const char *got, const char *want)
{
	if (got && !strcmp(got, want)) {
		printf(" - %s [PASS]\n", name);
		return;
	}
	printf(" - %s: got '%s', want '%s' [FAIL]\n", name,
	       got ? got : "(null)", want);
	failed = true;
}

static void check_uint(const char *name, unsigned int got, unsigned int want)
{
	if (got == want) {
		printf(" - %s [PASS]\n", name);
		return;
	}
	printf(" - %s: got %u, want %u [FAIL]\n", name, got, want);
	failed = true;
}

static void write_file(const char *path, const char *text)
{
	FILE *f = fopen(path, "w");

	if (!f || fputs(text, f) < 0) {
		printf("cannot write %s\n", path);
		failed = true;
	}
	if (f)
		fclose(f);
}

static void mkdir_or_fail(const char *path)
{
	if (shr_mkdir_p(path, 0755)) {
		printf("mkdir %s failed\n", path);
		failed = true;
	}
}

static void write_in(const char *dir, const char *name, const char *text)
{
	char path[1024];

	snprintf(path, sizeof(path), "%s/%s", dir, name);
	write_file(path, text);
}

static void remove_in(const char *dir, const char *name)
{
	char path[1024];

	snprintf(path, sizeof(path), "%s/%s", dir, name);
	unlink(path);
}

/*
 * A controller in the test sysfs, with its subsystem, which has the
 * controller as a child, as nvme-subsystem devices do. The model is
 * padded with spaces: udev ignores trailing whitespace, and so must the
 * match.
 */
static void add_ctrl(const char *devname, const char *model,
		     const char *transport, const char *subsystype)
{
	char path[1024], text[128];

	snprintf(path, sizeof(path), "%s/sys/class/nvme/%s", root, devname);
	mkdir_or_fail(path);
	snprintf(text, sizeof(text), "%-40s\n", model);
	write_in(path, "model", text);
	snprintf(text, sizeof(text), "%s\n", transport);
	write_in(path, "transport", text);
	write_in(path, "ctrl_loss_tmo", "600\n");

	snprintf(path, sizeof(path),
		 "%s/sys/class/nvme-subsystem/sub-%s/%s", root, devname,
		 devname);
	mkdir_or_fail(path);
	snprintf(path, sizeof(path), "%s/sys/class/nvme-subsystem/sub-%s",
		 root, devname);
	snprintf(text, sizeof(text), "%s\n", subsystype);
	write_in(path, "subsystype", text);
	write_in(path, "iopolicy", "numa\n");
}

static void check_attr(const char *name, const char *devname,
		       const char *attr, const char *want)
{
	char path[1024], buf[64] = "";
	FILE *f;

	if (!strcmp(attr, "iopolicy"))
		snprintf(path, sizeof(path),
			 "%s/sys/class/nvme-subsystem/sub-%s/iopolicy", root,
			 devname);
	else
		snprintf(path, sizeof(path), "%s/sys/class/nvme/%s/%s", root,
			 devname, attr);
	f = fopen(path, "r");
	if (f) {
		if (!fgets(buf, sizeof(buf), f))
			buf[0] = '\0';
		fclose(f);
	}
	buf[strcspn(buf, "\n")] = '\0';
	check_str(name, f ? buf : NULL, want);
}

static void test_parse(struct libnvme_global_ctx *ctx)
{
	struct libnvmf_vendor_defaults *vd;
	static const char * const none[] = { "/nonexistent" };
	char path[1024];

	printf("parse:\n");
	write_in(lib_dir, "a.conf",
		 "# comment\n"
		 "[Model]\nmodel = A\niopolicy = round-robin\n"
		 "[Model]\nmodel = A\ntransport = tcp\nctrl-loss-tmo = -1\n"
		 /* no model, no value, unknown section and key: dropped */
		 "[Model]\niopolicy = numa\n"
		 "[Model]\nmodel = B\n"
		 "[Other]\nmodel = C\niopolicy = numa\n"
		 "[Model]\nmodel = D\nfoo = bar\niopolicy = numa\n");
	write_in(lib_dir, "b.conf", "[Model]\nmodel = E\niopolicy = numa\n");
	vd = load_all(ctx);
	check_uint("valid sections of two files", libnvmf_vendor_count(vd), 4);
	libnvmf_vendor_free(vd);

	/*
	 * A file of the same name in /etc replaces the shipped one (here an
	 * empty one, which turns it off); another name adds to them.
	 */
	write_in(etc_dir, "b.conf", "");
	write_in(etc_dir, "c.conf", "[Model]\nmodel = F\niopolicy = numa\n");
	vd = load_all(ctx);
	check_uint("same name in etc replaces, new name adds",
		   libnvmf_vendor_count(vd), 4);
	libnvmf_vendor_free(vd);

	/* A link to /dev/null in /run turns off the shipped file. */
	snprintf(path, sizeof(path), "%s/a.conf", run_dir);
	if (symlink("/dev/null", path))
		failed = true;
	vd = load_all(ctx);
	check_uint("link to /dev/null masks", libnvmf_vendor_count(vd), 1);
	libnvmf_vendor_free(vd);
	unlink(path);

	vd = libnvmf_vendor_load(ctx, none, 1);
	check_uint("no directories, no defaults", libnvmf_vendor_count(vd), 0);
	libnvmf_vendor_free(vd);

	remove_in(lib_dir, "a.conf");
	remove_in(lib_dir, "b.conf");
	remove_in(etc_dir, "b.conf");
	remove_in(etc_dir, "c.conf");
}

/*
 * All files are read in the order of their names, whatever their
 * directory: an admin's file sorted before a shipped one loses to it, one
 * sorted after it wins.
 */
static void test_order(struct libnvme_global_ctx *ctx)
{
	struct libnvmf_vendor_defaults *vd;

	printf("order:\n");
	write_in(lib_dir, "50-x.conf",
		 "[Model]\nmodel = Order\niopolicy = round-robin\n");
	write_in(etc_dir, "10-x.conf",
		 "[Model]\nmodel = Order\niopolicy = numa\n");
	add_ctrl("nvme30", "Order", "tcp", "nvm");
	vd = load_all(ctx);
	libnvmf_vendor_apply(ctx, vd, "nvme30", false);
	libnvmf_vendor_free(vd);
	check_attr("10- in etc before 50- shipped: shipped wins", "nvme30",
		   "iopolicy", "round-robin");

	write_in(etc_dir, "90-x.conf",
		 "[Model]\nmodel = Order\niopolicy = queue-depth\n");
	vd = load_all(ctx);
	libnvmf_vendor_apply(ctx, vd, "nvme30", false);
	libnvmf_vendor_free(vd);
	check_attr("90- in etc after 50- shipped: etc wins", "nvme30",
		   "iopolicy", "queue-depth");

	remove_in(lib_dir, "50-x.conf");
	remove_in(etc_dir, "10-x.conf");
	remove_in(etc_dir, "90-x.conf");
}

static void test_apply(struct libnvme_global_ctx *ctx)
{
	struct libnvmf_vendor_defaults *vd;
	char devname[16];
	int i;

	printf("apply:\n");
	/* The match of 71-nvmf-netapp.rules, and udev's patterns */
	write_in(lib_dir, "netapp.conf",
		 "[Model]\nmodel = NetApp ONTAP Controller\n"
		 "iopolicy = queue-depth\n"
		 "[Model]\nmodel = NetApp ONTAP Controller\ntransport = tcp\n"
		 "ctrl-loss-tmo = -1\n");
	write_in(lib_dir, "pattern.conf",
		 "[Model]\nmodel = Glob*\ntransport = rdma|tcp\n"
		 "iopolicy = round-robin\nctrl-loss-tmo = 30\n"
		 "[Model]\nmodel = Alt?A|Alt?B\niopolicy = round-robin\n"
		 "[Model]\nmodel = Later\niopolicy = numa\n"
		 "[Model]\nmodel = Later\niopolicy = round-robin\n");

	add_ctrl("nvme1", "NetApp ONTAP Controller", "tcp", "nvm");
	add_ctrl("nvme2", "NetApp ONTAP Controller", "fc", "nvm");
	add_ctrl("nvme3", "NetApp ONTAP Controller", "tcp", "discovery");
	add_ctrl("nvme4", "Glob Array 9000", "rdma", "nvm");
	add_ctrl("nvme5", "Glob Array 9000", "fc", "nvm");
	add_ctrl("nvme6", "Alt-B", "tcp", "nvm");
	add_ctrl("nvme7", "Later", "tcp", "nvm");
	add_ctrl("nvme8", "Other Model", "tcp", "nvm");
	add_ctrl("nvme9", "NetApp ONTAP Controller", "tcp", "nvm");

	vd = load_all(ctx);
	for (i = 1; i <= 8; i++) {
		snprintf(devname, sizeof(devname), "nvme%d", i);
		libnvmf_vendor_apply(ctx, vd, devname, false);
	}
	libnvmf_vendor_apply(ctx, vd, "nvme9", true);
	libnvmf_vendor_free(vd);

	check_attr("exact model, padded in sysfs: iopolicy", "nvme1",
		   "iopolicy", "queue-depth");
	check_attr("exact model and transport: ctrl_loss_tmo", "nvme1",
		   "ctrl_loss_tmo", "-1");
	check_attr("other transport: iopolicy still", "nvme2", "iopolicy",
		   "queue-depth");
	check_attr("other transport: no ctrl_loss_tmo", "nvme2",
		   "ctrl_loss_tmo", "600");
	check_attr("discovery subsystem: no iopolicy", "nvme3", "iopolicy",
		   "numa");
	check_attr("glob model, alternative transport", "nvme4", "iopolicy",
		   "round-robin");
	check_attr("glob model, alternative transport: ctrl_loss_tmo",
		   "nvme4", "ctrl_loss_tmo", "30");
	check_attr("glob model, transport not among the alternatives",
		   "nvme5", "iopolicy", "numa");
	check_attr("second alternative of the model", "nvme6", "iopolicy",
		   "round-robin");
	check_attr("the later section wins", "nvme7", "iopolicy",
		   "round-robin");
	check_attr("another model keeps its values", "nvme8", "iopolicy",
		   "numa");
	check_attr("keep_ctrl_loss_tmo: iopolicy set", "nvme9", "iopolicy",
		   "queue-depth");
	check_attr("keep_ctrl_loss_tmo: ctrl_loss_tmo kept", "nvme9",
		   "ctrl_loss_tmo", "600");

	/*
	 * A malformed section header ends the [Model] before it: its keys
	 * don't change that model.
	 */
	write_in(lib_dir, "junk.conf",
		 "[Model]\nmodel = JunkA\niopolicy = round-robin\n"
		 "[Other\nmodel = JunkB\n");
	add_ctrl("nvme10", "JunkA", "tcp", "nvm");
	add_ctrl("nvme11", "JunkB", "tcp", "nvm");
	vd = load_all(ctx);
	libnvmf_vendor_apply(ctx, vd, "nvme10", false);
	libnvmf_vendor_apply(ctx, vd, "nvme11", false);
	libnvmf_vendor_free(vd);
	check_attr("before a malformed header: applied", "nvme10", "iopolicy",
		   "round-robin");
	check_attr("after a malformed header: not that model", "nvme11",
		   "iopolicy", "numa");
	remove_in(lib_dir, "junk.conf");
}

/*
 * What the connect path calls: the defaults of the test base directory,
 * loaded once; a ctrl_loss_tmo other than the default is the
 * connection's own.
 */
static void test_apply_connected(struct libnvme_global_ctx *ctx)
{
	printf("apply after connect:\n");
	add_ctrl("nvme20", "NetApp ONTAP Controller", "tcp", "nvm");
	add_ctrl("nvme21", "NetApp ONTAP Controller", "tcp", "nvm");
	libnvmf_vendor_apply_connected(ctx, 20, 600);
	libnvmf_vendor_apply_connected(ctx, 21, 30);
	check_attr("default ctrl_loss_tmo: the vendor's", "nvme20",
		   "ctrl_loss_tmo", "-1");
	check_attr("own ctrl_loss_tmo: kept", "nvme21", "ctrl_loss_tmo",
		   "600");
	check_attr("own ctrl_loss_tmo: iopolicy set", "nvme21", "iopolicy",
		   "queue-depth");
}

int main(void)
{
	struct libnvme_global_ctx *ctx;

	snprintf(root, sizeof(root), "/tmp/libnvme-vendor-XXXXXX");
	if (!mkdtemp(root)) {
		perror("mkdtemp");
		return EXIT_FAILURE;
	}
	/* The sandbox layout of libnvme_set_test_base_dir() */
	snprintf(lib_dir, sizeof(lib_dir), "%s/usr/vendor.d", root);
	snprintf(run_dir, sizeof(run_dir), "%s/run/vendor.d", root);
	snprintf(etc_dir, sizeof(etc_dir), "%s/vendor.d", root);
	mkdir_or_fail(lib_dir);
	mkdir_or_fail(run_dir);
	mkdir_or_fail(etc_dir);

	ctx = libnvme_create_global_ctx();
	if (!ctx || libnvme_set_test_base_dir(ctx, root) ||
	    libnvme_set_test_sysfs_dir(ctx, root)) {
		printf("cannot set up the sandbox\n");
		return EXIT_FAILURE;
	}

	test_parse(ctx);
	test_order(ctx);
	test_apply(ctx);
	test_apply_connected(ctx);

	libnvme_free_global_ctx(ctx);
	if (shr_rmdir_recursive(root))
		printf("cannot remove %s\n", root);
	return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}
