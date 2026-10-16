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
	int verbose;
	bool quiet;
	uint32_t timeout;
	bool dry_run;
	bool no_retries;
	bool no_ioctl_probing;
	unsigned int output_format_ver;
	nvme_print_flags_t supported_output_formats;
	/* --output-format of the current command, set by parse_args() */
	nvme_print_flags_t output_flags;
	const char *set_options;
	/* the operand of the current command, enum command_device */
	int device_operand;
	/* the device it was given, set by parse_args(), or NULL */
	char *device;
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

/*
 * The command parses --output-format itself, for names other than the
 * ones above. parse_args() does not check it then.
 */
#define OUTPUT_FORMATS_CUSTOM	(1U << 31)
/*
 * Only the normal output. NORMAL is 0 and a struct command without output
 * formats gets the default ones.
 */
#define OUTPUT_FORMATS_NORMAL	(1U << 30)

#ifdef CONFIG_JSONC
#define DEFAULT_OUTPUT_FORMATS (NORMAL | JSON | BINARY)
#define DEFAULT_OUTPUT_FORMAT_DESC "Output format: normal|json|binary"
#else /* CONFIG_JSONC */
#define DEFAULT_OUTPUT_FORMATS (NORMAL | BINARY)
#define DEFAULT_OUTPUT_FORMAT_DESC "Output format: normal|binary"
#endif /* CONFIG_JSONC */

/*
 * The command's options. The global options are registered once with
 * argconfig (nvme_args_register()) and accepted by every command; a
 * command's own option with the same short or long name takes precedence.
 * The output formats a command supports are declared in its struct
 * command.
 */
#define NVME_ARGS(n, ...)					\
	struct argconfig_commandline_options n[] = {		\
		OPT_GROUP("Options"),				\
		##__VA_ARGS__,					\
		OPT_END()					\
	}

extern struct argconfig_opt_val nvme_nsid_values[];
extern struct argconfig_opt_val nvme_timeout_values[];
extern const char *uuid_index;
extern const char *namespace_id_desired;

void nvme_args_register(void);
void nvme_args_set_output_formats(nvme_print_flags_t formats,
				  const char *custom_desc);
int parse_args(int argc, char *argv[], const char *desc,
	       struct argconfig_commandline_options *opts);
int validate_output_format(const char *format, nvme_print_flags_t *flags);
bool nvme_is_output_format_normal(void);
bool nvme_is_output_format_json(void);
