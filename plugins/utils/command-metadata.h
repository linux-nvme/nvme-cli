/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2026 Micron Technology, Inc.
 *
 * Command/option metadata dump: emits every command and its options as JSON.
 * See command-metadata.c for details.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "plugin.h"
#include "util/argconfig.h"

/*
 * A single command-line option, copied from struct argconfig_commandline_options.
 * String fields and the opt_val table are deep-copied (and owned) because they
 * may point at command-local storage that is freed once the command's fn
 * returns; see command_metadata_copy_options().
 */
struct command_metadata_option {
	const char *option;		/* long name; "" for a group separator */
	char short_option;		/* 0 if none */
	const char *meta;		/* metavar / value placeholder ("NUM"/"FMT"/...) or NULL */
	enum argconfig_types config_type;
	int argument_type;		/* no_/required_/optional_argument */
	const char *help;
	const struct argconfig_opt_val *opt_val; /* NULL or .str==NULL terminated */
	bool hidden;			/* not shown in help/completion */
};

struct command_metadata_command {
	const char *name;
	const char *alias;		/* may be NULL */
	const char *help;
	struct command_metadata_option *options;	/* heap array */
	size_t num_options;
	bool captured;			/* hook fired -> options valid */
};

struct command_metadata_plugin {
	const char *name;		/* NULL for the builtin plugin */
	const char *desc;
	struct command_metadata_command *commands;	/* heap array */
	size_t num_commands;
};

struct command_metadata_program {
	const char *name;
	const char *version;
	const char *desc;
	struct command_metadata_plugin *plugins;	/* heap array, builtin first */
	size_t num_plugins;
};

/*
 * Entry point for the `nvme dump-command-metadata` subcommand. Builds the
 * command/option model by walking the program's plugin/command tree and
 * writes it to stdout as JSON, a machine-readable description of the CLI
 * surface for tooling (completion generators, docs, drift checks). Returns 0
 * on success, negative errno on failure.
 */
int dump_command_metadata(struct program *prog);
