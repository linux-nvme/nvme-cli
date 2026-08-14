// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright 2014 PMC-Sierra, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */

/*
 *
 *   Author: Logan Gunthorpe
 *
 *   Date:   Oct 23 2014
 *
 *   Description:
 *     Functions for parsing command line options.
 *
 */

#include <errno.h>
#include <getopt.h>
#include <locale.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libnvme.h>

#include "argconfig.h"
#include "cleanup.h"
#include <shared/suffix-util.h>
#include <shared/wrap-util.h>

static bool is_null_or_empty(const char *s)
{
	return !s || !*s;
}

static const char *append_usage_str = "";

void argconfig_append_usage(const char *str)
{
	append_usage_str = str;
}

static void show_option(const struct argconfig_commandline_options *option)
{
	char buffer[0x1000];
	char *b = buffer;

	b += sprintf(b, "  [ ");
	if (option->option) {
		b += sprintf(b, " --%s", option->option);
		if (option->argument_type == optional_argument)
			b += sprintf(b, "[=<%s>]", option->meta ? option->meta : "arg");
		if (option->argument_type == required_argument)
			b += sprintf(b, "=<%s>", option->meta ? option->meta : "arg");
		if (option->short_option)
			b += sprintf(b, ",");
	}
	if (option->short_option) {
		b += sprintf(b, " -%c", option->short_option);
		if (option->argument_type == optional_argument)
			b += sprintf(b, " [<%s>]", option->meta ? option->meta : "arg");
		if (option->argument_type == required_argument)
			b += sprintf(b, " <%s>", option->meta ? option->meta : "arg");
	}
	b += sprintf(b, " ] ");

	fprintf(stderr, "%s", buffer);
	if (option->help) {
		shr_print_word_wrapped("--- ", 40, b - buffer, stderr);
		shr_print_word_wrapped(option->help, 44, 44, stderr);
	}
	fprintf(stderr, "\n");
}

void argconfig_print_help(const char *program_desc,
			  struct argconfig_commandline_options *s)
{
	const char *pending_header = "Options";
	bool header_printed = false;

	fprintf(stderr, "\033[1mUsage: %s\033[0m\n\n",
		append_usage_str);

	shr_print_word_wrapped(program_desc, 0, 0, stderr);
	fprintf(stderr, "\n");

	if (!s || !s->option)
		return;

	for (; s->option; s++) {
		if (s->config_type == CFG_GROUP_SEPARATOR) {
			pending_header = s->help;
			header_printed = false;
			continue;
		}
		if (!header_printed) {
			fprintf(stderr, "\n\033[1m%s:\033[0m\n", pending_header);
			header_printed = true;
		}
		if (!s->hidden)
			show_option(s);
	}
}

static int argconfig_error(char *type, const char *opt, const char *arg)
{
	fprintf(stderr, "Expected %s argument for '%s' but got '%s'!\n", type, opt, arg);
	return -EINVAL;
}

static int argconfig_parse_type(struct argconfig_commandline_options *s)
{
	void *value = s->default_value;
	char *endptr;
	int ret = 0;

	errno = 0;    /* To distinguish success/failure after strtol/stroul call */

	switch (s->config_type) {
	case CFG_STRING:
		*(char **)value = optarg;
		break;
	case CFG_INT:
		*(int *)value = strtol(optarg, &endptr, 0);
		if (errno || optarg == endptr)
			ret = argconfig_error("integer", s->option, optarg);
		break;
	case CFG_BYTE: {
		unsigned long tmp = strtoul(optarg, &endptr, 0);

		if (errno || tmp >= 1 << 8 || optarg == endptr)
			ret = argconfig_error("byte", s->option, optarg);
		else
			*(uint8_t *)value = tmp;
		break;
	}
	case CFG_SHORT: {
		unsigned long tmp = strtoul(optarg, &endptr, 0);

		if (errno || tmp >= 1 << 16 || optarg == endptr)
			ret = argconfig_error("short", s->option, optarg);
		else
			*(uint16_t *)value = tmp;
		break;
	}
	case CFG_POSITIVE: {
		uint32_t tmp = strtoul(optarg, &endptr, 0);

		if (errno || optarg == endptr)
			ret = argconfig_error("word", s->option, optarg);
		else
			*(uint32_t *)value = tmp;
		break;
	}
	case CFG_INCREMENT:
		*(int *)value += 1;
		break;
	case CFG_LONG:
		*(unsigned long *)value = strtoul(optarg, &endptr, 0);
		if (errno || optarg == endptr)
			ret = argconfig_error("long integer", s->option, optarg);
		break;
	case CFG_LONG_SUFFIX:
		ret = shr_suffix_binary_parse(optarg, &endptr, (uint64_t *)value);
		if (ret)
			argconfig_error("long suffixed integer", s->option, optarg);
		break;
	case CFG_DOUBLE:
		*(double *)value = strtod(optarg, &endptr);
		if (errno || optarg == endptr)
			ret = argconfig_error("float", s->option, optarg);
		break;
	case CFG_FLAG:
		*(bool *)value = true;
		break;
	case CFG_GROUP_SEPARATOR:
		break;
	}

	return ret;
}

static void argconfig_set_opt_val(enum argconfig_types type, union argconfig_val *opt_val, void *val)
{
	switch (type) {
	case CFG_FLAG:
		*(bool *)val = opt_val->bool_val;
		break;
	case CFG_LONG_SUFFIX:
		*(uint64_t *)val = opt_val->long_suffix;
		break;
	case CFG_POSITIVE:
		*(uint32_t *)val = opt_val->positive;
		break;
	case CFG_INT:
		*(int *)val = opt_val->int_val;
		break;
	case CFG_LONG:
		*(unsigned long *)val = opt_val->long_val;
		break;
	case CFG_DOUBLE:
		*(double *)val = opt_val->double_val;
		break;
	case CFG_BYTE:
		*(uint8_t *)val = opt_val->byte;
		break;
	case CFG_SHORT:
		*(uint16_t *)val = opt_val->short_val;
		break;
	case CFG_INCREMENT:
		*(int *)val = opt_val->increment;
		break;
	case CFG_STRING:
		*(char **)val = opt_val->string;
		break;
	case CFG_GROUP_SEPARATOR:
		break;
	}
}

static struct argconfig_opt_val *
argconfig_match_val(struct argconfig_opt_val *v, const char *str)
{
	size_t len = strlen(str);
	struct argconfig_opt_val *match = NULL;

	for (; v->str; v++) {
		if (strncasecmp(str, v->str, len))
			continue;

		if (len == strlen(v->str))
			return v;

		if (match)
			return NULL; /* multiple matches; input is ambiguous */

		match = v;
	}

	return match;
}

static int argconfig_parse_val(struct argconfig_commandline_options *s)
{
	struct argconfig_opt_val *v = s->opt_val;

	if (v)
		v = argconfig_match_val(v, optarg);
	if (!v)
		return argconfig_parse_type(s);

	argconfig_set_opt_val(v->type, &v->val, s->default_value);
	return 0;
}

static bool argconfig_check_verbose(struct argconfig_commandline_options *s)
{
	for (; s && s->option; s++) {
		if (!strcmp(s->option, "verbose") &&
		    s->config_type == CFG_INCREMENT)
			return s->seen;
	}

	return false;
}

static argconfig_parse_hook_fn argconfig_parse_hook;

void argconfig_set_parse_hook(argconfig_parse_hook_fn hook)
{
	argconfig_parse_hook = hook;
}

int argconfig_parse(int argc, char *argv[], const char *program_desc,
		    struct argconfig_commandline_options *options)
{
	__cleanup_free char *short_opts = NULL;
	__cleanup_free struct option *long_opts = NULL;
	__cleanup_free int *long_opt_map = NULL;
	struct argconfig_commandline_options *s;
	int c, long_opt_index = 0, opt_index = 0, short_index = 0, options_count = 0;
	int ret = 0;

	if (argconfig_parse_hook)
		return argconfig_parse_hook(argc, argv, program_desc, options);

	errno = 0;
	for (s = options; s->option; s++)
		options_count++;

	long_opts = calloc(options_count + 2, sizeof(struct option));
	short_opts = calloc(options_count * 3 + 3, sizeof(*short_opts));
	long_opt_map = calloc(options_count + 2, sizeof(*long_opt_map));

	if (!long_opts || !short_opts || !long_opt_map) {
		fprintf(stderr, "failed to allocate memory for opts: %s\n", libnvme_strerror(errno));
		return -errno;
	}

	for (s = options, opt_index = 0; s->option; s++, opt_index++) {
		s->seen = false;
		if (s->config_type == CFG_GROUP_SEPARATOR)
			continue;
		if (s->short_option) {
			short_opts[short_index++] = s->short_option;
			if (s->argument_type == required_argument ||
			    s->argument_type == optional_argument)
				short_opts[short_index++] = ':';
			if (s->argument_type == optional_argument)
				short_opts[short_index++] = ':';
		}
		if (!is_null_or_empty(s->option)) {
			long_opts[long_opt_index].name = s->option;
			long_opts[long_opt_index].has_arg = s->argument_type;
			long_opt_map[long_opt_index] = opt_index;
			long_opt_index++;
		}
	}

	long_opts[long_opt_index].name = "help";
	long_opts[long_opt_index].val = 'h';

	short_opts[short_index++] = '?';
	short_opts[short_index] = 'h';

	optind = 0;
	while ((c = getopt_long_only(argc, argv, short_opts, long_opts, &long_opt_index)) != -1) {
		if (c) {
			if (c == '?' || c == 'h') {
				argconfig_print_help(program_desc, options);
				ret = -EINVAL;
				break;
			}
			for (opt_index = 0; opt_index < options_count; opt_index++) {
				if (c == options[opt_index].short_option)
					break;
			}
			if (opt_index == options_count)
				continue;
		} else {
			opt_index = long_opt_map[long_opt_index];
		}

		s = &options[opt_index];
		s->seen = true;

		if (!s->default_value)
			continue;

		ret = argconfig_parse_val(s);
		if (ret)
			break;
	}

	if (!argconfig_check_verbose(options))
		setlocale(LC_ALL, "C");

	return ret;
}

/*
 * Parse global (pre-subcommand) options from argc/argv. Stops at the first
 * non-option argument (i.e. the subcommand name) so that subcommand-specific
 * options are left in place for the subcommand dispatcher. After a successful
 * call, optind points to the first non-option argument (the subcommand).
 *
 * Returns 0 on success, negative errno on failure.
 */
int argconfig_parse_global(int argc, char *argv[],
			   struct argconfig_commandline_options *options)
{
	__cleanup_free char *short_opts = NULL;
	__cleanup_free struct option *long_opts = NULL;
	__cleanup_free int *long_opt_map = NULL;
	struct argconfig_commandline_options *s;
	int c, long_opt_index = 0, opt_index = 0;
	int short_index = 0, options_count = 0;
	int ret = 0;

	errno = 0;
	for (s = options; s->option; s++)
		options_count++;

	long_opts = calloc(options_count + 2, sizeof(struct option));
	/* '+' prefix: stop at the first non-option argument (the subcommand) */
	short_opts = calloc(options_count * 3 + 4, sizeof(*short_opts));
	long_opt_map = calloc(options_count + 2, sizeof(*long_opt_map));

	if (!long_opts || !short_opts || !long_opt_map) {
		fprintf(stderr, "failed to allocate memory for opts: %s\n",
			libnvme_strerror(errno));
		return -errno;
	}

	short_opts[short_index++] = '+';

	for (s = options, opt_index = 0; s->option; s++, opt_index++) {
		s->seen = false;
		if (s->config_type == CFG_GROUP_SEPARATOR)
			continue;
		if (s->short_option) {
			short_opts[short_index++] = s->short_option;
			if (s->argument_type == required_argument ||
			    s->argument_type == optional_argument)
				short_opts[short_index++] = ':';
			if (s->argument_type == optional_argument)
				short_opts[short_index++] = ':';
		}
		if (!is_null_or_empty(s->option)) {
			long_opts[long_opt_index].name = s->option;
			long_opts[long_opt_index].has_arg = s->argument_type;
			long_opt_map[long_opt_index] = opt_index;
			long_opt_index++;
		}
	}

	optind = 0;
	while ((c = getopt_long(argc, argv, short_opts,
			long_opts, &long_opt_index)) != -1) {
		 if (c == '?' || c == ':') {
 			ret = -EINVAL;
 			break;
 		}
		if (c) {
			for (opt_index = 0; opt_index < options_count;
					opt_index++) {
				if (c == options[opt_index].short_option)
					break;
			}
 			if (opt_index == options_count) {
 				ret = -EINVAL;
 				break;
			}
		} else {
			opt_index = long_opt_map[long_opt_index];
		}

		s = &options[opt_index];
		s->seen = true;

		if (!s->default_value)
			continue;

		ret = argconfig_parse_val(s);
		if (ret)
			break;
	}

	return ret;
}

bool argconfig_parse_seen(struct argconfig_commandline_options *s,
			  const char *option)
{
	for (; s && s->option; s++) {
		if (!strcmp(s->option, option))
			return s->seen;
	}

	return false;
}
