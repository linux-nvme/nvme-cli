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

#include "argconfig.h"
#include "args.h"
#include "nvme-print.h"
#include "plugin.h"

struct nvme_args nvme_args = {
	.output_format = "normal",
	.output_format_ver = 2,
	.timeout = 0,
	.supported_output_formats = DEFAULT_OUTPUT_FORMATS,
};

const char *uuid_index = "UUID index";
const char *namespace_id_desired = "identifier of desired namespace";

/*
 * The operand of the current command: the device, or nothing. A missing
 * or an extra operand is a usage error.
 */
static int check_device(void)
{
	int max = nvme_args.device_operand == COMMAND_NO_DEVICE ? 0 : 1;
	int nr = argconfig_nr_operands();

	if (nvme_args.device_operand == COMMAND_DEVICE && !nr)
		return argconfig_usage_error("missing <device>");
	if (nr > max)
		return argconfig_usage_error("unexpected argument '%s'",
					     argconfig_operand(max));

	nvme_args.device = argconfig_operand(0);
	return 0;
}

int parse_cmdline(int argc, char *argv[], const char *desc,
		  struct argconfig_commandline_options *opts)
{
	int ret;

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret)
		return ret;

	return check_device();
}

int parse_args(int argc, char *argv[], const char *desc,
	       struct argconfig_commandline_options *opts)
{
	int ret;

	ret = parse_cmdline(argc, argv, desc, opts);
	if (ret)
		return ret;

	if (nvme_args.supported_output_formats & OUTPUT_FORMATS_CUSTOM) {
		nvme_args.output_flags = NORMAL;
	} else {
		ret = validate_output_format(nvme_args.output_format,
					     &nvme_args.output_flags);
		if (ret < 0) {
			nvme_show_error("Invalid output format");
			return ret;
		}
	}

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
