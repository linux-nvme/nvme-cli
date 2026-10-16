// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * A frozen copy of the getopt based argconfig parser, as it was before
 * argconfig got its own parser. test-argconfig-diff compares both, so any
 * change in behaviour shows up. Help output and the locale side effect
 * are left out. The test compares the parsing of the command line, so the
 * value conversion is the one of argconfig, which uses the strict number
 * parsers of shared/parse-util.
 */

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libnvme.h>

#include <shared/parse-util.h>
#include <shared/suffix-util.h>

#include "../../../src/argconfig.h"
#include "../../../src/cleanup.h"
#include "argconfig-getopt-ref.h"

/* getopt's has_arg for an option */
static int has_arg(struct argconfig_commandline_options *s)
{
	switch (s->argument_type) {
	case ARGCONFIG_ARG_REQUIRED:
		return required_argument;
	case ARGCONFIG_ARG_OPTIONAL:
		return optional_argument;
	default:
		return no_argument;
	}
}

static bool is_null_or_empty(const char *s)
{
	return !s || !*s;
}

/* The value conversion of argconfig, see argconfig_parse_type() */
static int argconfig_parse_type(struct argconfig_commandline_options *s,
				char *arg)
{
	void *value = s->default_value;
	char *endptr;
	uint64_t u;
	int64_t i;
	double d;
	int ret = 0;

	if (!arg && s->config_type != CFG_STRING &&
	    s->config_type != CFG_FLAG && s->config_type != CFG_INCREMENT)
		return -EINVAL;

	switch (s->config_type) {
	case CFG_STRING:
		*(char **)value = arg;
		break;
	case CFG_INT:
		ret = shr_parse_s64(arg, INT_MIN, INT_MAX, &i);
		if (!ret)
			*(int *)value = i;
		break;
	case CFG_BYTE:
		ret = shr_parse_u64(arg, UINT8_MAX, &u);
		if (!ret)
			*(uint8_t *)value = u;
		break;
	case CFG_SHORT:
		ret = shr_parse_u64(arg, UINT16_MAX, &u);
		if (!ret)
			*(uint16_t *)value = u;
		break;
	case CFG_POSITIVE:
		ret = shr_parse_u64(arg, UINT32_MAX, &u);
		if (!ret)
			*(uint32_t *)value = u;
		break;
	case CFG_INCREMENT:
		*(int *)value += 1;
		break;
	case CFG_ENUM:
		ret = -EINVAL;
		break;
	case CFG_LONG:
		ret = shr_parse_u64(arg, UINT64_MAX, &u);
		if (!ret)
			*(uint64_t *)value = u;
		break;
	case CFG_LONG_SUFFIX:
		if (!isdigit((unsigned char)*arg))
			return -EINVAL;
		ret = shr_suffix_binary_parse(arg, &endptr, &u);
		if (!ret)
			*(uint64_t *)value = u;
		break;
	case CFG_DOUBLE:
		ret = shr_parse_double(arg, &d);
		if (!ret)
			*(double *)value = d;
		break;
	case CFG_FLAG:
		*(bool *)value = true;
		break;
	case CFG_GROUP_SEPARATOR:
	case CFG_INCLUDE:
		break;
	}

	return ret ? -EINVAL : 0;
}

static void argconfig_set_opt_val(enum argconfig_types type,
				  union argconfig_val *opt_val, void *val)
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
	case CFG_ENUM:
		*(int *)val = opt_val->int_val;
		break;
	case CFG_LONG:
		*(uint64_t *)val = opt_val->long_val;
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
	case CFG_INCLUDE:
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

static int argconfig_parse_val(struct argconfig_commandline_options *s,
			       char *arg)
{
	struct argconfig_opt_val *v = s->opt_val;

	if (v)
		v = argconfig_match_val(v, arg);
	if (!v)
		return argconfig_parse_type(s, arg);

	argconfig_set_opt_val(v->type, &v->val, s->default_value);
	return 0;
}

int ref_argconfig_parse(int argc, char *argv[],
			struct argconfig_commandline_options *options,
			char ***operands, int *nr_operands)
{
	__cleanup_free char *short_opts = NULL;
	__cleanup_free struct option *long_opts = NULL;
	__cleanup_free int *long_opt_map = NULL;
	struct argconfig_commandline_options *s;
	int c, long_opt_index = 0, opt_index = 0, short_index = 0;
	int options_count = 0;
	int ret = 0;

	errno = 0;
	for (s = options; s->option; s++)
		options_count++;

	long_opts = calloc(options_count + 2, sizeof(struct option));
	short_opts = calloc(options_count * 3 + 3, sizeof(*short_opts));
	long_opt_map = calloc(options_count + 2, sizeof(*long_opt_map));

	if (!long_opts || !short_opts || !long_opt_map) {
		fprintf(stderr, "failed to allocate memory for opts: %s\n",
			libnvme_strerror(errno));
		return -errno;
	}

	for (s = options, opt_index = 0; s->option; s++, opt_index++) {
		s->seen = false;
		if (s->config_type == CFG_GROUP_SEPARATOR)
			continue;
		if (s->short_option) {
			short_opts[short_index++] = s->short_option;
			if (s->argument_type == ARGCONFIG_ARG_REQUIRED ||
			    s->argument_type == ARGCONFIG_ARG_OPTIONAL)
				short_opts[short_index++] = ':';
			if (s->argument_type == ARGCONFIG_ARG_OPTIONAL)
				short_opts[short_index++] = ':';
		}
		if (!is_null_or_empty(s->option)) {
			long_opts[long_opt_index].name = s->option;
			long_opts[long_opt_index].has_arg = has_arg(s);
			long_opt_map[long_opt_index] = opt_index;
			long_opt_index++;
		}
	}

	long_opts[long_opt_index].name = "help";
	long_opts[long_opt_index].val = 'h';

	short_opts[short_index++] = '?';
	short_opts[short_index] = 'h';

	optind = 0;
	while ((c = getopt_long_only(argc, argv, short_opts, long_opts,
				      &long_opt_index)) != -1) {
		if (c) {
			if (c == '?' || c == 'h') {
				ret = -EINVAL;
				break;
			}
			for (opt_index = 0; opt_index < options_count;
			     opt_index++) {
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

		ret = argconfig_parse_val(s, optarg);
		if (ret)
			break;
	}

	*operands = &argv[optind];
	*nr_operands = argc - optind;

	return ret;
}

/* Global options: stop at the first non-option argument. */
int ref_argconfig_parse_global(int argc, char *argv[],
			   struct argconfig_commandline_options *options,
			   int *argind)
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
			if (s->argument_type == ARGCONFIG_ARG_REQUIRED ||
			    s->argument_type == ARGCONFIG_ARG_OPTIONAL)
				short_opts[short_index++] = ':';
			if (s->argument_type == ARGCONFIG_ARG_OPTIONAL)
				short_opts[short_index++] = ':';
		}
		if (!is_null_or_empty(s->option)) {
			long_opts[long_opt_index].name = s->option;
			long_opts[long_opt_index].has_arg = has_arg(s);
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

		ret = argconfig_parse_val(s, optarg);
		if (ret)
			break;
	}

	*argind = optind;

	return ret;
}
