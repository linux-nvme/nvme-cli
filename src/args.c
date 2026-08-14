// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

#include <errno.h>
#include <string.h>

#include <libnvme.h>

#include "args.h"
#include "argconfig.h"
#include "nvme-print.h"

struct nvme_args nvme_args = {
	.output_format = "normal",
	.output_format_ver = 2,
	.timeout = 0,
	.supported_output_formats = DEFAULT_OUTPUT_FORMATS,
};

const char *latency = "output latency statistics";
const char *namespace_desired = "desired namespace";
const char *namespace_id_desired = "identifier of desired namespace";
const char *uuid_index = "UUID index";

int parse_args(int argc, char *argv[], const char *desc,
	       struct argconfig_commandline_options *opts)
{
	int ret;

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret)
		return ret;

	nvme_show_init();

	return 0;
}

int validate_output_format(const char *format, nvme_print_flags_t *flags)
{
	nvme_print_flags_t f;
	nvme_print_flags_t supported_formats = nvme_args.supported_output_formats;

	if (!format)
		return -EINVAL;

	if (!strcmp(format, "normal"))
		f = NORMAL;
#ifdef CONFIG_JSONC
	else if (!strcmp(format, "json") && (supported_formats & JSON))
		f = JSON;
#endif /* CONFIG_JSONC */
	else if (!strcmp(format, "binary") && (supported_formats & BINARY))
		f = BINARY;
	else if (!strcmp(format, "tabular") && (supported_formats & TABULAR))
		f = TABULAR;
	else
		return -EINVAL;

	*flags = f;

	return 0;
}

bool nvme_is_output_format_normal(void)
{
	nvme_print_flags_t flags;

	if (validate_output_format(nvme_args.output_format, &flags))
		return false;

	return flags == NORMAL;
}

bool nvme_is_output_format_json(void)
{
	nvme_print_flags_t flags;

	if (validate_output_format(nvme_args.output_format, &flags))
		return false;

	return flags == JSON;
}
