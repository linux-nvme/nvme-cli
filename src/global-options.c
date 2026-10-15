// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 *
 * The options every command accepts, registered once with argconfig.
 */

#include <stdio.h>

#include "argconfig.h"
#include "args.h"

static char output_format_help[64];

static struct argconfig_commandline_options global_options[] = {
	OPT_INCR("verbose", 'v', &nvme_args.verbose,
		 "Increase output verbosity"),
	OPT_FLAG("quiet", 0, &nvme_args.quiet,
		 "suppress informational output"),
	OPT_FMT("output-format", 'o', &nvme_args.output_format,
		output_format_help),
	OPT_UINT("timeout", 0, &nvme_args.timeout,
		 "timeout value, in milliseconds"),
	OPT_FLAG("dry-run", 0, &nvme_args.dry_run,
		 "show command instead of executing"),
	OPT_FLAG("no-retries", 0, &nvme_args.no_retries,
		 "disable retry logic on errors"),
	OPT_FLAG("no-ioctl-probing", 0, &nvme_args.no_ioctl_probing,
		 "disable 64-bit IOCTL support probing"),
	OPT_UINT("output-format-version", 0, &nvme_args.output_format_ver,
		 "output format version: 1|2"),
	/* the spelling of --verbose of older versions */
	OPT_INCR("human-readable", 'H', &nvme_args.verbose, NULL, NULL,
		 true),
	OPT_STRING("set-options", 0, "KEY=VALUE", &nvme_args.set_options,
		   "set a libnvme library option (key=value[,key=value,...]);"),
	OPT_END()
};

/* Register the options every command accepts */
void nvme_args_register(void)
{
	nvme_args_set_output_formats(DEFAULT_OUTPUT_FORMATS, NULL);
	argconfig_set_global_options(global_options);
}

/*
 * The output formats the current command supports. The help text lists
 * them, a command which parses --output-format itself describes its own.
 */
void nvme_args_set_output_formats(nvme_print_flags_t formats,
				  const char *custom_desc)
{
	formats &= ~OUTPUT_FORMATS_NORMAL;
	nvme_args.supported_output_formats = formats;
	if (formats & OUTPUT_FORMATS_CUSTOM) {
		snprintf(output_format_help, sizeof(output_format_help), "%s",
			 custom_desc);
		return;
	}
	snprintf(output_format_help, sizeof(output_format_help),
		 "Output format: normal%s%s%s",
		 formats & JSON ? "|json" : "",
		 formats & BINARY ? "|binary" : "",
		 formats & TABULAR ? "|tabular" : "");
}
