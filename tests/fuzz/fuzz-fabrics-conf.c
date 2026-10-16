// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

/*
 * Fuzz nvme-fabrics.conf: the input is the text of the file, which
 * libnvme parses into endpoints. The parser reads a path, so each input
 * goes to a temporary file first.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <nvme/lib.h>

#include "fuzz.h"

#include "nvme/config-ini.h"

static struct libnvme_global_ctx *ctx;
static char path[32];

static void cleanup(void)
{
	unlink(path);
	libnvme_free_global_ctx(ctx);
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	int fd;

	(void)argc;
	(void)argv;
	ctx = libnvme_create_global_ctx();
	snprintf(path, sizeof(path), "fuzz-fabrics-conf-XXXXXX");
	fd = mkstemp(path);
	if (!ctx || fd < 0)
		abort();
	close(fd);
	atexit(cleanup);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct libnvmf_conf_file *file = NULL;
	FILE *f = fopen(path, "wb");

	if (!f)
		return 0;
	fwrite(data, 1, size, f);
	fclose(f);

	if (!libnvmf_conf_file_parse(ctx, path, &file))
		libnvmf_conf_file_free(file);

	return 0;
}
