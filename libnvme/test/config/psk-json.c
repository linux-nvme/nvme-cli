// SPDX-License-Identifier: LGPL-2.1-or-later
/**
 * This file is part of libnvme.
 * Copyright (c) 2024 Daniel Wagner, SUSE LLC
 */

#include "options.h"

#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libnvme.h>

#include "nvme/tree.h"

static bool import_export_key(struct libnvme_global_ctx *ctx, libnvme_ctrl_t c)
{
	unsigned char version, hmac, *key;
	char *encoded_key;
	size_t len;
	int ret;

	ret = libnvmf_import_tls_key_versioned(ctx, libnvme_ctrl_get_tls_key(c),
					    &version, &hmac, &len, &key);
	if (ret) {
		printf("ERROR: libnvmf_import_tls_key_versioned failed with %d\n",
		       ret);
		return false;

	}

	ret = libnvmf_export_tls_key_versioned(ctx, version, hmac, key, len,
					    &encoded_key);
	free(key);
	if (ret) {
		printf("ERROR: libnvmf_export_tls_key_versioned failed with %d\n",
		       ret);
		return false;
	}

	libnvme_ctrl_set_tls_key(c, encoded_key);

	free(encoded_key);

	return true;
}

static bool psk_json_test(struct libnvme_global_ctx *ctx, const char *file)
{
	libnvme_host_t h;
	libnvme_subsystem_t s;
	libnvme_ctrl_t c;

	if (libnvme_read_config(ctx, file))
		return false;

	libnvme_for_each_host(ctx, h)
		libnvme_for_each_subsystem(h, s)
			libnvme_subsystem_for_each_ctrl(s, c)
				if (!import_export_key(ctx, c))
					return false;

	return !libnvme_dump_config(ctx, STDOUT_FILENO);
}

int main(int argc, char *argv[])
{
	struct libnvme_global_ctx *ctx;
	const char *config_file = NULL;
	bool pass;

	ctx = libnvme_create_global_ctx();
	if (!ctx)
		return EXIT_FAILURE;

	libnvme_set_logging_level(ctx, LIBNVME_LOG_ERR, false, false);

	if (parse_args(ctx, argc, argv)) {
		libnvme_free_global_ctx(ctx);
		return EXIT_FAILURE;
	}

	config_file = argv[optind];

	pass = psk_json_test(ctx, config_file);
	fflush(stdout);

	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
