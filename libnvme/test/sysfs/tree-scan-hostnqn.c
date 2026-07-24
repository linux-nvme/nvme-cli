// SPDX-License-Identifier: LGPL-2.1-or-later
/**
 * This file is part of libnvme.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 * Authors: Martin Belanger <martin.belanger@dell.com>
 *
 * libnvmf_host_get_ids()'s host-tree fallback tier is now populated purely
 * by sysfs-discovered controllers -- the legacy JSON config reader, the
 * only other populator, is gone. Confirm it still resolves correctly
 * against a real captured sysfs snapshot: the same fallback the old
 * JSON-config-driven hostnqn-order test covered, exercised from the
 * topology-scan angle instead.
 *
 * Kept as its own fabrics-gated binary, separate from tree-scan.c: that one
 * builds unconditionally (PCIe topology scanning needs no fabrics support),
 * but libnvmf_host_get_ids() and <nvme/fabrics.h> are only available when
 * the fabrics build option is enabled.
 */

#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libnvme.h>
#include <nvme/fabrics.h>

enum {
	OPT_SET_OPTIONS = 1000,
};

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [OPTIONS]\n"
		"\n"
		"Options:\n"
		"  --set-options key=value[,key=value...]\n",
		prog);
}

/*
 * hostnqn/hostid are accepted but deliberately ignored, not applied to ctx:
 * this test wants the sysfs-discovered fallback tier to actually decide the
 * answer. Leaving ctx's own hostnqn/hostid unset doesn't risk falling
 * through to the real /etc/nvme/hostnqn on the machine running the test --
 * these PCIe fixtures carry no hostnqn sysfs attribute, so
 * libnvme_scan_topology() itself falls back to the fixed
 * NVME_DEFAULT_HOSTNQN placeholder while building the host tree, which the
 * host-tree fallback tier then finds.  Accepted (not rejected) only so this
 * binary stays compatible with tree-diff.sh's shared invocation.
 */
static int set_options(struct libnvme_global_ctx *ctx,
		      const char *key, const char *value)
{
	if (!strcmp(key, "test-sysfs-dir"))
		return libnvme_set_test_sysfs_dir(ctx, value);

	if (!strcmp(key, "hostnqn") || !strcmp(key, "hostid"))
		return 0;

	fprintf(stderr, "Unknown option '%s'\n", key);
	return -EINVAL;
}

static int parse_set_options(struct libnvme_global_ctx *ctx, char *arg)
{
	char *tok;

	while ((tok = strsep(&arg, ","))) {
		char *val;
		int err;

		if (!*tok)
			continue;

		val = strchr(tok, '=');
		if (!val) {
			fprintf(stderr, "Invalid option '%s'\n", tok);
			return -EINVAL;
		}

		*val++ = '\0';

		err = set_options(ctx, tok, val);
		if (err)
			return err;
	}

	return 0;
}

static bool resolve_and_print(struct libnvme_global_ctx *ctx)
{
	char *hostnqn = NULL, *hostid = NULL;
	int err;

	err = libnvme_scan_topology(ctx, NULL, NULL);
	if (err && err != -ENOENT && err != -EACCES) {
		fprintf(stderr, "libnvme_scan_topology failed: %d\n", err);
		return false;
	}

	err = libnvmf_host_get_ids(ctx, NULL, NULL, &hostnqn, &hostid);
	if (err) {
		fprintf(stderr, "libnvmf_host_get_ids failed: %d\n", err);
		return false;
	}

	printf("resolved host: hostnqn=%s hostid=%s\n", hostnqn, hostid);

	free(hostnqn);
	free(hostid);

	return true;
}

int main(int argc, char *argv[])
{
	static const struct option long_options[] = {
		{ "set-options", required_argument, NULL, OPT_SET_OPTIONS },
		{ NULL, 0, NULL, 0 }
	};

	struct libnvme_global_ctx *ctx;
	bool pass;
	int c;

	ctx = libnvme_create_global_ctx();
	if (!ctx)
		return EXIT_FAILURE;

	libnvme_set_logging_file(ctx, stdout);
	libnvme_set_logging_level(ctx, LIBNVME_LOG_ERR, false, false);

	while ((c = getopt_long(argc, argv, "", long_options, NULL)) != -1) {
		switch (c) {
		case OPT_SET_OPTIONS:
			if (parse_set_options(ctx, optarg)) {
				libnvme_free_global_ctx(ctx);
				return EXIT_FAILURE;
			}
			break;

		default:
			usage(argv[0]);
			libnvme_free_global_ctx(ctx);
			return EXIT_FAILURE;
		}
	}

	pass = resolve_and_print(ctx);

	libnvme_free_global_ctx(ctx);
	fflush(stdout);

	return pass ? EXIT_SUCCESS : EXIT_FAILURE;
}
