// SPDX-License-Identifier: LGPL-2.1-or-later
/**
 * This file is part of libnvme.
 * Copyright (c) 2024 Daniel Wagner, SUSE LLC
 */

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libnvme.h>

#include "nvme/linux.h"
#include "nvme/tree.h"

static bool import_export_key(struct libnvme_global_ctx *ctx, libnvme_ctrl_t c)
{
	unsigned char version, hmac, *key;
	char *encoded_key;
	size_t len;
	int ret;

	ret = libnvme_import_tls_key_versioned(ctx, libnvme_ctrl_get_tls_key(c),
					    &version, &hmac, &len, &key);
	if (ret) {
		printf("ERROR: libnvme_import_tls_key_versioned failed with %d\n",
		       ret);
		return false;

	}

	ret = libnvme_export_tls_key_versioned(ctx, version, hmac, key, len,
					    &encoded_key);
	free(key);
	if (ret) {
		printf("ERROR: libnvme_export_tls_key_versioned failed with %d\n",
		       ret);
		return false;
	}

	libnvme_ctrl_set_tls_key(c, encoded_key);

	free(encoded_key);

	return true;
}

static bool psk_json_test(char *file)
{
	struct libnvme_global_ctx *ctx;
	bool pass = false;
	libnvme_host_t h;
	libnvme_subsystem_t s;
	libnvme_ctrl_t c;
	int err;

	ctx = libnvme_create_global_ctx(stderr, LOG_ERR);
	if (!ctx)
		return false;

	err = libnvme_read_config(ctx, file);
	if (err)
		goto out;


	libnvme_for_each_host(ctx, h)
		libnvme_for_each_subsystem(h, s)
			libnvme_subsystem_for_each_ctrl(s, c)
				if (!import_export_key(ctx, c))
					goto out;

	err = libnvme_dump_config(ctx, STDOUT_FILENO);
	if (err)
		goto out;

	pass = true;

out:
	libnvme_free_global_ctx(ctx);
	return pass;
}

int main(int argc, char *argv[])
{
	bool pass;

	pass = psk_json_test(argv[1]);
	fflush(stdout);

	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
