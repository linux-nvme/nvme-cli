// SPDX-License-Identifier: LGPL-2.1-or-later
/**
 * This file is part of libnvme.
 * Copyright (c) 2026 Daniel Wagner, SUSE LLC
 */

#include "options.h"

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libnvme.h>

struct host_info hosts[MAX_HOSTS];

enum {
	OPT_SET_OPTIONS = 1000,
};

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [OPTIONS] [config-file]\n"
		"\n"
		"Options:\n"
		"  --set-options key=value[,key=value...]\n",
		prog);
}

static int set_option(struct libnvme_global_ctx *ctx,
		      const char *key, const char *value)
{
	unsigned int idx;

	if (!strcmp(key, "test-sysfs-dir"))
		return libnvme_set_test_sysfs_dir(ctx, value);

	for (idx = 0; idx < MAX_HOSTS; idx++) {
		char name[16];

		snprintf(name, sizeof(name), "hostnqn_%u", idx + 1);
		if (!strcmp(key, name)) {
			free(hosts[idx].hostnqn);
			hosts[idx].hostnqn = strdup(value);
			return hosts[idx].hostnqn ? 0 : -ENOMEM;
		}

		snprintf(name, sizeof(name), "hostid_%u", idx + 1);
		if (!strcmp(key, name)) {
			free(hosts[idx].hostid);
			hosts[idx].hostid = strdup(value);
			return hosts[idx].hostid ? 0 : -ENOMEM;
		}
	}

	if (!strcmp(key, "hostnqn")) {
		free(hosts[0].hostnqn);
		hosts[0].hostnqn = strdup(value);
		return hosts[0].hostnqn ? 0 : -ENOMEM;
	}

	if (!strcmp(key, "hostid")) {
		free(hosts[0].hostid);
		hosts[0].hostid = strdup(value);
		return hosts[0].hostid ? 0 : -ENOMEM;
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

		err = set_option(ctx, tok, val);
		if (err)
			return err;
	}

	return 0;
}

int parse_args(struct libnvme_global_ctx *ctx, int argc, char *argv[])
{
	static const struct option long_options[] = {
		{ "set-options", required_argument, NULL, OPT_SET_OPTIONS },
		{ NULL, 0, NULL, 0 }
	};
	int err, c;

	while ((c = getopt_long(argc, argv, "", long_options, NULL)) != -1) {
		switch (c) {
		case OPT_SET_OPTIONS:
			err = parse_set_options(ctx, optarg);
			if (err)
				return err;
			break;

		default:
			usage(argv[0]);
			return -EINVAL;
		}
	}

	return 0;
}
