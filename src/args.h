// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

#pragma once

#include <inttypes.h>
#include <stdbool.h>

#include "argconfig.h"

typedef uint32_t nvme_print_flags_t;

struct nvme_args {
	char *output_format;
	unsigned int verbose;
	bool quiet;
	uint32_t timeout;
	bool dry_run;
	bool no_retries;
	bool no_ioctl_probing;
	unsigned int output_format_ver;
	nvme_print_flags_t supported_output_formats;
	const char *set_options;
};
extern struct nvme_args nvme_args;

enum nvme_print_flags {
	NORMAL		= 0,
	VERBOSE		= 1 << 0,	/* verbosely decode complex values for humans */
	JSON		= 1 << 1,	/* display in json format */
	VS		= 1 << 2,	/* hex dump vendor specific data areas */
	BINARY		= 1 << 3,	/* binary dump raw bytes */
	TABULAR		= 1 << 4,	/* prints aligned columns for easy reading */
};

#ifdef CONFIG_JSONC
#define DEFAULT_OUTPUT_FORMATS (NORMAL | JSON | BINARY)
#define DEFAULT_OUTPUT_FORMAT_DESC "Output format: normal|json|binary"
#else /* CONFIG_JSONC */
#define DEFAULT_OUTPUT_FORMATS (NORMAL | BINARY)
#define DEFAULT_OUTPUT_FORMAT_DESC "Output format: normal|binary"
#endif /* CONFIG_JSONC */

/*
 * the ordering of the arguments matters, as the argument parser uses the first
 * match, thus any command which defines -t shorthand will match first.
 */
#define NVME_ARGS_OUTPUT_FORMATS(n, of_mask, of_desc, ...)                             \
	nvme_args.supported_output_formats = of_mask;                                  \
	struct argconfig_commandline_options n[] = {                                   \
		OPT_GROUP("Options"),                                                  \
		##__VA_ARGS__,                                                         \
		OPT_GROUP("Global options"),                                           \
		OPT_INCR("verbose",      'v', &nvme_args.verbose,                      \
                         "Increase output verbosity"),                                 \
		OPT_FLAG("quiet",        0, &nvme_args.quiet,                          \
                         "suppress output messages, overwrites verbose mode"),         \
		OPT_FMT("output-format", 'o', &nvme_args.output_format, of_desc),      \
		OPT_UINT("timeout",        0, &nvme_args.timeout,                      \
                         "timeout value, in milliseconds"),                            \
		OPT_FLAG("dry-run",        0, &nvme_args.dry_run,                      \
                         "show command instead of executing"),                         \
		OPT_FLAG("no-retries",     0, &nvme_args.no_retries,                   \
			 "disable retry logic on errors"),                             \
		OPT_FLAG("no-ioctl-probing", 0, &nvme_args.no_ioctl_probing,           \
			 "disable 64-bit IOCTL support probing"),                      \
		OPT_UINT("output-format-version", 0, &nvme_args.output_format_ver,     \
			 "output format version: 1|2"),                                \
		OPT_FLAG("human-readable", 'H', &nvme_args.verbose, NULL, NULL, true), \
		OPT_STRING("set-options",    0, "KEY=VALUE",                           \
			 &nvme_args.set_options,                                       \
			 "set a libnvme library option (key=value[,key=value,...]);"), \
		OPT_END()                                                              \
	}

#define NVME_ARGS(n, ...)                   \
	NVME_ARGS_OUTPUT_FORMATS(n,         \
		DEFAULT_OUTPUT_FORMATS,     \
		DEFAULT_OUTPUT_FORMAT_DESC, \
		##__VA_ARGS__)

extern const char *uuid_index;
extern const char *namespace_id_desired;

int parse_args(int argc, char *argv[], const char *desc,
	       struct argconfig_commandline_options *opts);
int validate_output_format(const char *format, nvme_print_flags_t *flags);
bool nvme_is_output_format_normal(void);
bool nvme_is_output_format_json(void);
