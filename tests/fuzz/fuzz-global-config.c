// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

/*
 * Fuzz nvme-cli.conf: the input is the text of the file, which sets the
 * global options.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "fuzz.h"

#include "args.h"
#include "global-config.h"

struct nvme_args nvme_args;

static const struct nvme_args defaults = {
	.output_format = "normal",
	.output_format_ver = 2,
	.timeout = 5000,
	.supported_output_formats = NORMAL,
};

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;
	nvme_args_register();
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char *text = malloc(size + 1);

	if (!text)
		return 0;
	memcpy(text, data, size);
	text[size] = '\0';

	nvme_args = defaults;
	nvme_load_global_config_buf(text, "fuzz");
	nvme_global_config_free();

	free(text);
	return 0;
}
