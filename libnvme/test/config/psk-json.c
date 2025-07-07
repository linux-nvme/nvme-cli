// SPDX-License-Identifier: LGPL-2.1-or-later
/**
 * This file is part of libnvme.
 * Copyright (c) 2024 Daniel Wagner, SUSE LLC
 */

#include "nvme/linux.h"
#include "nvme/tree.h"
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>

#include <libnvme.h>

static bool import_export_key(nvme_ctrl_t c)
{
	unsigned char version, hmac, *key;
	char *encoded_key;
	size_t len;

	key = nvme_import_tls_key_versioned(nvme_ctrl_get_tls_key(c),
					    &version, &hmac, &len);
	if (!key) {
		printf("ERROR: nvme_import_tls_key_versioned failed with %d\n",
		       errno);
		return false;

	}

	encoded_key = nvme_export_tls_key_versioned(version, hmac, key, len);
	free(key);
	if (!encoded_key) {
		printf("ERROR: nvme_export_tls_key_versioned failed with %d\n",
		       errno);
		return false;
	}

	nvme_ctrl_set_tls_key(c, encoded_key);

	free(encoded_key);

	return true;
}

static bool psk_json_test(char *file)
{
	struct nvme_global_ctx *ctx;
	bool pass = false;
	nvme_host_t h;
	nvme_subsystem_t s;
	nvme_ctrl_t c;
	int err;

	ctx = nvme_create_global_ctx(stderr, LOG_ERR);
	if (!ctx)
		return false;

	err = nvme_read_config(ctx, file);
	if (err)
		goto out;


	nvme_for_each_host(ctx, h)
		nvme_for_each_subsystem(h, s)
			nvme_subsystem_for_each_ctrl(s, c)
				if (!import_export_key(c))
					goto out;

	err = nvme_dump_config(ctx);
	if (err)
		goto out;

	pass = true;

out:
	nvme_free_global_ctx(ctx);
	return pass;
}

int main(int argc, char *argv[])
{
	bool pass;

	pass = psk_json_test(argv[1]);
	fflush(stdout);

	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
