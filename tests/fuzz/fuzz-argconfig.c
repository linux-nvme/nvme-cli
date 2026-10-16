// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

/*
 * Fuzz the command line parser: the input is split at NUL bytes into the
 * arguments of a command, which is parsed against a table with every kind
 * of option, and against the global options alone.
 */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fuzz.h"

#include "argconfig.h"

#define MAX_ARGS 64

static struct {
	bool flag, gflag;
	char *str, *optstr;
	int incr, num, enm;
	uint8_t byte, named;
	uint16_t shrt;
	uint32_t uint, timeout;
	uint64_t lng, suffix;
	double dbl;
} v;

static struct {
	bool flag;
	uint32_t uint;
} shared_tmpl, bound;

static struct argconfig_opt_val names[] = {
	VAL_BYTE("one", 1),
	VAL_BYTE("two", 2),
	VAL_BYTE("three", 3),
	VAL_END()
};

static struct argconfig_opt_val enums[] = {
	VAL_ENUM("host", 1),
	VAL_ENUM("controller", 2),
	VAL_ENUM("ctrl-init", 3),
	VAL_END()
};

static struct argconfig_opt_val timeouts[] = {
	VAL_UINT("infinite", UINT32_MAX),
	VAL_UINT("-1", UINT32_MAX),
	VAL_END()
};

static struct argconfig_commandline_options shared[] = {
	OPT_FLAG("shared-flag", 'S', &shared_tmpl.flag, "shared flag"),
	OPT_UINT("shared-uint", 0, &shared_tmpl.uint, "shared uint"),
	OPT_END()
};

static struct argconfig_commandline_options globals[] = {
	OPT_INCR("verbose", 'v', &v.incr, "verbose"),
	OPT_FMT("output-format", 'o', &v.str, "format"),
	OPT_UINT("timeout", 0, &v.timeout, "timeout", timeouts),
	OPT_FLAG("dry-run", 0, &v.gflag, "dry run"),
	OPT_INCR("human-readable", 'H', &v.incr, NULL,
		 .deprecated = "--verbose/-v"),
	OPT_END()
};

static int parse(int argc, char **argv)
{
	struct argconfig_commandline_options *b;
	int ret, i;

	b = argconfig_bind(shared, &shared_tmpl, sizeof(shared_tmpl), &bound);
	if (!b)
		return 0;

	{
		struct argconfig_commandline_options opts[] = {
			OPT_FLAG("flag", 'f', &v.flag, "flag",
				 .old_name = "old-flag"),
			OPT_STRING("string", 's', "STR", &v.str, "string"),
			OPT_STRING_OPTIONAL("optional", 'O', "STR", &v.optstr,
					    "optional"),
			OPT_INT("int", 'i', &v.num, "int"),
			OPT_BYTE("byte", 'b', &v.byte, "byte"),
			OPT_BYTE("named", 'n', &v.named, "named", names),
			OPT_SHRT("short", 'w', &v.shrt, "short"),
			OPT_UINT("uint", 'u', &v.uint, "uint"),
			OPT_LONG("long", 'l', &v.lng, "long"),
			OPT_SUFFIX("suffix", 'z', &v.suffix, "suffix"),
			OPT_DOUBLE("double", 'd', &v.dbl, "double"),
			OPT_ENUM("enum", 'e', &v.enm, "enum", enums),
			OPT_GROUP("Group"),
			OPT_INCLUDE(b, "Included options"),
			OPT_END()
		};

		ret = argconfig_parse(argc, argv, "fuzz", opts);
		if (!ret) {
			for (i = 0; i < argconfig_nr_operands(); i++)
				(void)strlen(argconfig_operand(i));
			(void)argconfig_given(opts, &v.uint);
			(void)argconfig_given(opts, &bound.uint);
		}
	}
	free(b);

	argconfig_parse_global(argc, argv, NULL, &i);

	return ret;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;
	argconfig_set_global_options(globals);
	argconfig_append_usage("fuzz [OPTIONS]");
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char *argv[MAX_ARGS + 1];
	int argc = 1;
	size_t i, start = 0;

	argv[0] = strdup("prog");
	for (i = 0; i <= size && argc < MAX_ARGS; i++) {
		if (i == size || !data[i]) {
			/* each argument in its own allocation, for ASan */
			argv[argc] = malloc(i - start + 1);
			memcpy(argv[argc], data + start, i - start);
			argv[argc][i - start] = '\0';
			argc++;
			start = i + 1;
		}
	}
	argv[argc] = NULL;

	memset(&v, 0, sizeof(v));
	memset(&bound, 0, sizeof(bound));
	parse(argc, argv);

	for (i = 0; i < (size_t)argc; i++)
		free(argv[i]);

	return 0;
}
