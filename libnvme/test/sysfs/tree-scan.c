// SPDX-License-Identifier: LGPL-2.1-or-later
/**
 * This file is part of libnvme.
 * Copyright (c) 2024 Daniel Wagner, SUSE LLC
 */

#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libnvme.h>

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

static int set_options(struct libnvme_global_ctx *ctx,
		      const char *key, const char *value)
{
	if (!strcmp(key, "test-sysfs-dir"))
		return libnvme_set_test_sysfs_dir(ctx, value);

	if (!strcmp(key, "hostnqn")) {
		libnvme_global_ctx_set_hostnqn(ctx, value);
		return 0;
	}

	if (!strcmp(key, "hostid")) {
		libnvme_global_ctx_set_hostid(ctx, value);
		return 0;
	}

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

static void print_ctrl(libnvme_ctrl_t c, const char *indent)
{
	const char *value;

	printf("%sctrl %s transport=%s", indent,
	       libnvme_ctrl_get_name(c), libnvme_ctrl_get_transport(c));

	value = libnvme_ctrl_get_traddr(c);
	if (value)
		printf(" traddr=%s", value);
	value = libnvme_ctrl_get_host_traddr(c);
	if (value)
		printf(" host_traddr=%s", value);
	value = libnvme_ctrl_get_host_iface(c);
	if (value)
		printf(" host_iface=%s", value);
	value = libnvme_ctrl_get_trsvcid(c);
	if (value)
		printf(" trsvcid=%s", value);

	printf("\n");
}

static unsigned int print_subsys_multipath(libnvme_subsystem_t s)
{
	libnvme_ns_t n;
	libnvme_path_t p;
	unsigned int i = 0;

	libnvme_subsystem_for_each_ns(s, n) {
		printf("    ns %u %s\n", libnvme_ns_get_nsid(n),
		       libnvme_ns_get_name(n));

		libnvme_namespace_for_each_path(n, p) {
			printf("      path %s ana=%s numa=%s qdepth=%d\n",
			       libnvme_path_get_name(p),
			       libnvme_path_get_ana_state(p),
			       libnvme_path_get_numa_nodes(p),
			       libnvme_path_get_queue_depth(p));
			print_ctrl(libnvme_path_get_ctrl(p), "        ");
		}
		i++;
	}

	return i;
}

static void print_subsys_non_multipath(libnvme_subsystem_t s)
{
	libnvme_ctrl_t c;
	libnvme_ns_t n;

	libnvme_subsystem_for_each_ctrl(s, c) {
		libnvme_ctrl_for_each_ns(c, n) {
			printf("    ns %u %s\n", libnvme_ns_get_nsid(n),
			       libnvme_ns_get_name(n));
			print_ctrl(c, "      ");
		}
	}
}

static void print_subsys(libnvme_subsystem_t s)
{
	printf("  subsystem %s %s\n", libnvme_subsystem_get_name(s),
	       libnvme_subsystem_get_subsysnqn(s));

	if (!print_subsys_multipath(s))
		print_subsys_non_multipath(s);
}

static void print_tree(struct libnvme_global_ctx *ctx)
{
	libnvme_host_t h;

	libnvme_for_each_host(ctx, h) {
		libnvme_subsystem_t s;
		const char *hostid, *hostsymname;

		printf("host %s", libnvme_host_get_hostnqn(h));
		hostid = libnvme_host_get_hostid(h);
		if (hostid)
			printf(" hostid=%s", hostid);
		hostsymname = libnvme_host_get_hostsymname(h);
		if (hostsymname)
			printf(" hostsymname=%s", hostsymname);
		printf("\n");

		libnvme_for_each_subsystem(h, s)
			print_subsys(s);
	}
}

static bool tree_scan(struct libnvme_global_ctx *ctx)
{
	int err;

	err = libnvme_scan_topology(ctx, NULL, NULL);
	if (err && err != -ENOENT && err != -EACCES) {
		fprintf(stderr, "libnvme_scan_topology failed: %d\n", err);
		return false;
	}

	print_tree(ctx);

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

	pass = tree_scan(ctx);

	libnvme_free_global_ctx(ctx);
	fflush(stdout);

	return pass ? EXIT_SUCCESS : EXIT_FAILURE;
}
