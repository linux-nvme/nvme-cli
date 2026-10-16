// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * A frozen copy of the getopt based argconfig parser, as it was before
 * argconfig got its own parser. test-argconfig-diff compares both, so any
 * change in behaviour shows up. Help output and the locale side effect
 * are left out. The test compares the parsing of the command line, so the
 * value conversion follows the rules of argconfig: unsigned options reject
 * negative numbers, and a word is at most UINT32_MAX.
 */

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libnvme.h>

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

static int argconfig_error(char *type, const char *opt, const char *arg)
{
	fprintf(stderr, "Expected %s argument for '%s' but got '%s'!\n",
		type, opt, arg);
	return -EINVAL;
}

static bool argconfig_negative(const char *arg)
{
	while (isspace((unsigned char)*arg))
		arg++;

	return *arg == '-';
}

static int argconfig_parse_type(struct argconfig_commandline_options *s,
				char *arg)
{
	void *value = s->default_value;
	char *endptr;
	int ret = 0;

	/* To distinguish success/failure after strtol/stroul call */
	errno = 0;

	switch (s->config_type) {
	case CFG_BYTE:
	case CFG_SHORT:
	case CFG_POSITIVE:
	case CFG_LONG:
	case CFG_LONG_SUFFIX:
		if (argconfig_negative(arg))
			return argconfig_error("non-negative number", s->option,
					       arg);
		break;
	default:
		break;
	}

	switch (s->config_type) {
	case CFG_STRING:
		*(char **)value = arg;
		break;
	case CFG_INT:
		*(int *)value = strtol(arg, &endptr, 0);
		if (errno || arg == endptr || *endptr)
			ret = argconfig_error("integer", s->option, arg);
		break;
	case CFG_BYTE: {
		unsigned long tmp = strtoul(arg, &endptr, 0);

		if (errno || tmp >= 1 << 8 || arg == endptr || *endptr)
			ret = argconfig_error("byte", s->option, arg);
		else
			*(uint8_t *)value = tmp;
		break;
	}
	case CFG_SHORT: {
		unsigned long tmp = strtoul(arg, &endptr, 0);

		if (errno || tmp >= 1 << 16 || arg == endptr || *endptr)
			ret = argconfig_error("short", s->option, arg);
		else
			*(uint16_t *)value = tmp;
		break;
	}
	case CFG_POSITIVE: {
		unsigned long long tmp = strtoull(arg, &endptr, 0);

		if (errno || tmp > UINT32_MAX || arg == endptr || *endptr)
			ret = argconfig_error("word", s->option, arg);
		else
			*(uint32_t *)value = tmp;
		break;
	}
	case CFG_INCREMENT:
		*(int *)value += 1;
		break;
	case CFG_ENUM:
		ret = argconfig_error("name", s->option, arg);
		break;
	case CFG_LONG:
		*(uint64_t *)value = strtoull(arg, &endptr, 0);
		if (errno || arg == endptr || *endptr)
			ret = argconfig_error("long integer", s->option, arg);
		break;
	case CFG_LONG_SUFFIX:
		ret = shr_suffix_binary_parse(arg, &endptr, (uint64_t *)value);
		if (ret)
			argconfig_error("long suffixed integer", s->option,
					arg);
		break;
	case CFG_DOUBLE:
		*(double *)value = strtod(arg, &endptr);
		if (errno || arg == endptr || *endptr)
			ret = argconfig_error("float", s->option, arg);
		break;
	case CFG_FLAG:
		*(bool *)value = true;
		break;
	case CFG_GROUP_SEPARATOR:
		break;
	}

	return ret;
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
