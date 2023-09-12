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

#include "argconfig.h"
#include "suffix.h"

#include <errno.h>
#include <inttypes.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdbool.h>
#include <locale.h>

static const char *append_usage_str = "";
static bool argconfig_output_format_json;

static int argconfig_parse_val(struct argconfig_commandline_options *s, struct option *option,
			       int index);

void argconfig_append_usage(const char *str)
{
	append_usage_str = str;
}

void print_word_wrapped(const char *s, int indent, int start, FILE *stream)
{
	const int width = 76;
	const char *c, *t;
	int next_space = -1;
	int last_line = indent;

	while (start < indent) {
		putc(' ', stream);
		start++;
	}

	for (c = s; *c != 0; c++) {
		if (*c == '\n')
			goto new_line;

		if (*c == ' ' || next_space < 0) {
			next_space = 0;
			for (t = c + 1; *t != 0 && *t != ' '; t++)
				next_space++;

			if (((int)(c - s) + start + next_space) > (last_line - indent + width)) {
				int i;
new_line:
				last_line = (int) (c-s) + start;
				putc('\n', stream);
				for (i = 0; i < indent; i++)
					putc(' ', stream);
				start = indent;
				continue;
			}
		}
		putc(*c, stream);
	}
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
		print_word_wrapped("--- ", 40, b - buffer, stderr);
		print_word_wrapped(option->help, 44, 44, stderr);
	}
	fprintf(stderr, "\n");
}

void argconfig_print_help(const char *program_desc,
			  struct argconfig_commandline_options *s)
{
	fprintf(stderr, "\033[1mUsage: %s\033[0m\n\n",
		append_usage_str);

	print_word_wrapped(program_desc, 0, 0, stderr);
	fprintf(stderr, "\n");

	if (!s || !s->option)
		return;

	fprintf(stderr, "\n\033[1mOptions:\033[0m\n");
	for (; s && s->option; s++)
		show_option(s);
}

static int argconfig_error(char *type, const char *opt, const char *arg)
{
	fprintf(stderr, "Expected %s argument for '%s' but got '%s'!\n", type, opt, arg);
	return -EINVAL;
}

int argconfig_parse_byte(const char *opt, const char *str, unsigned char *val)
{
	char *endptr;
	unsigned long tmp = strtoul(str, &endptr, 0);

	if (errno || tmp >= 1 << 8 || str == endptr)
		return argconfig_error("byte", opt, str);

	*val = tmp;

	return 0;
}

static int argconfig_parse_type(struct argconfig_commandline_options *s, struct option *option,
				int index)
{
	void *value = (void *)(char *)s->default_value;
	char *endptr;
	int ret = 0;

	errno = 0;    /* To distinguish success/failure after strtol/stroul call */

	switch (s->config_type) {
	case CFG_STRING:
		*((char **)value) = optarg;
		break;
	case CFG_SIZE:
		*((size_t *)value) = strtol(optarg, &endptr, 0);
		if (errno || optarg == endptr)
			ret = argconfig_error("integer", option[index].name, optarg);
		break;
	case CFG_INT:
		*((int *)value) = strtol(optarg, &endptr, 0);
		if (errno || optarg == endptr)
			ret = argconfig_error("integer", option[index].name, optarg);
		break;
	case CFG_BYTE:
		ret = argconfig_parse_byte(option[index].name, optarg, (uint8_t *)value);
		break;
	case CFG_SHORT: {
		unsigned long tmp = strtoul(optarg, &endptr, 0);

		if (errno || tmp >= 1 << 16 || optarg == endptr)
			ret = argconfig_error("short", option[index].name, optarg);
		else
			*((uint16_t *)value) = tmp;
		break;
	}
	case CFG_POSITIVE: {
		uint32_t tmp = strtoul(optarg, &endptr, 0);

		if (errno || optarg == endptr)
			ret = argconfig_error("word", option[index].name, optarg);
		else
			*((uint32_t *)value) = tmp;
		break;
	}
	case CFG_INCREMENT:
		*((int *)value) += 1;
		break;
	case CFG_LONG:
		*((unsigned long *)value) = strtoul(optarg, &endptr, 0);
		if (errno || optarg == endptr)
			ret = argconfig_error("long integer", option[index].name, optarg);
		break;
	case CFG_LONG_SUFFIX:
		ret = suffix_binary_parse(optarg, &endptr, (uint64_t *)value);
		if (ret)
			argconfig_error("long suffixed integer", option[index].name, optarg);
		break;
	case CFG_DOUBLE:
		*((double *)value) = strtod(optarg, &endptr);
		if (errno || optarg == endptr)
			ret = argconfig_error("float", option[index].name, optarg);
		break;
	case CFG_FLAG:
		*((bool *)value) = true;
		break;
	default:
		break;
	}

	return ret;
}

static int argconfig_get_val_len(struct argconfig_opt_val *opt_val, const char *str)
{
	struct argconfig_opt_val *v;
	int len;
	int match;

	for (len = 1; len <= strlen(str); len++) {
		match = 0;
		for (v = opt_val; v && v->str; v++) {
			if (!strncasecmp(str, v->str, len))
				match++;
		}
		if (match == 1)
			break;
	}

	return len;
}

static int argconfig_set_opt_val(enum argconfig_types type, union argconfig_val *opt_val, void *val)
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
	default:
		break;
	}

	return 0;
}

static int argconfig_parse_val(struct argconfig_commandline_options *s, struct option *option,
			       int index)
{
	const char *str = optarg;
	void *val = s->default_value;
	int len = strlen(optarg);
	struct argconfig_opt_val *v;
	int val_len;

	for (v = s->opt_val; v && v->str; v++) {
		val_len = argconfig_get_val_len(s->opt_val, v->str);
		if (strncasecmp(str, v->str, len > val_len ? len : val_len))
			continue;
		return argconfig_set_opt_val(v->type, &v->val, val);
	}

	return argconfig_parse_type(s, option, index);
}

void argconfig_set_output_format_json(bool enable)
{
	argconfig_output_format_json = enable;
}

bool argconfig_get_output_format_json(void)
{
	return argconfig_output_format_json;
}

static bool argconfig_check_output_format_json(struct argconfig_commandline_options *s)
{
	for (; s && s->option; s++) {
		if (strcmp(s->option, "output-format") || s->config_type != CFG_STRING)
			continue;
		if (!strcmp(*(char **)s->default_value, "json"))
			return true;
	}

	return false;
}

static bool argconfig_check_human_readable(struct argconfig_commandline_options *s)
{
	for (; s && s->option; s++) {
		if (!strcmp(s->option, "human-readable") && s->config_type == CFG_FLAG)
			return s->seen;
	}

	return false;
}

static void argconfig_parse_short_opt(int c)
{
	if (c == 'j')
		argconfig_set_output_format_json(true);
}

int argconfig_parse(int argc, char *argv[], const char *program_desc,
		    struct argconfig_commandline_options *options)
{
	char *short_opts;
	struct option *long_opts;
	struct argconfig_commandline_options *s;
	int c, option_index = 0, short_index = 0, options_count = 0;
	int ret = 0;

	errno = 0;
	for (s = options; s->option; s++)
		options_count++;

	long_opts = calloc(1, sizeof(struct option) * (options_count + 3));
	short_opts = calloc(1, sizeof(*short_opts) * (options_count * 3 + 5));

	if (!long_opts || !short_opts) {
		fprintf(stderr, "failed to allocate memory for opts: %s\n", strerror(errno));
		ret = -errno;
		goto out;
	}

	for (s = options; s->option && option_index < options_count; s++) {
		if (s->short_option) {
			short_opts[short_index++] = s->short_option;
			if (s->argument_type == required_argument ||
			    s->argument_type == optional_argument)
				short_opts[short_index++] = ':';
			if (s->argument_type == optional_argument)
				short_opts[short_index++] = ':';
		}
		if (s->option && strlen(s->option)) {
			long_opts[option_index].name = s->option;
			long_opts[option_index].has_arg = s->argument_type;
		}
		s->seen = false;
		option_index++;
	}

	long_opts[option_index].name = "help";
	long_opts[option_index++].val = 'h';

	long_opts[option_index].name = "json";
	long_opts[option_index].val = 'j';

	short_opts[short_index++] = '?';
	short_opts[short_index++] = 'h';
	short_opts[short_index] = 'j';

	optind = 0;
	while ((c = getopt_long_only(argc, argv, short_opts, long_opts, &option_index)) != -1) {
		if (c) {
			if (c == '?' || c == 'h') {
				argconfig_print_help(program_desc, options);
				ret = -EINVAL;
				break;
			}
			if (option_index >= options_count)
				argconfig_parse_short_opt(c);
			for (option_index = 0; option_index < options_count; option_index++) {
				if (c == options[option_index].short_option)
					break;
			}
			if (option_index == options_count ||
			    !strcmp(options[option_index].option, "json"))
				argconfig_parse_short_opt(c);
			if (option_index == options_count)
				continue;
		}

		s = &options[option_index];
		s->seen = true;

		if (!s->default_value)
			continue;

		if (s->opt_val)
			ret = argconfig_parse_val(s, long_opts, option_index);
		else
			ret = argconfig_parse_type(s, long_opts, option_index);
		if (ret)
			break;
	}

	if (argconfig_check_output_format_json(options))
		argconfig_set_output_format_json(true);

	if (!argconfig_check_human_readable(options))
		setlocale(LC_ALL, "C");

out:
	free(short_opts);
	free(long_opts);
	return ret;
}

int argconfig_parse_comma_sep_array(char *string, int *val, unsigned int max_length)
{
	int ret = 0;
	unsigned long v;
	char *tmp;
	char *p;

	if (!string || !strlen(string))
		return 0;

	tmp = strtok(string, ",");
	if (!tmp)
		return 0;

	v = strtoul(tmp, &p, 0);
	if (*p != 0)
		return -1;
	if (v > UINT_MAX) {
		fprintf(stderr, "%s out of range\n", tmp);
		return -1;
	}
	val[ret] = v;

	ret++;
	while (1) {
		tmp = strtok(NULL, ",");

		if (tmp == NULL)
			return ret;

		if (ret >= max_length)
			return -1;

		v = strtoul(tmp, &p, 0);
		if (*p != 0)
			return -1;
		if (v > UINT_MAX) {
			fprintf(stderr, "%s out of range\n", tmp);
			return -1;
		}
		val[ret] = v;
		ret++;
	}
}

int argconfig_parse_comma_sep_array_short(char *string, unsigned short *val,
					  unsigned int max_length)
{
	int ret = 0;
	unsigned long v;
	char *tmp;
	char *p;

	if (!string || !strlen(string))
		return 0;

	tmp = strtok(string, ",");
	if (!tmp)
		return 0;

	v = strtoul(tmp, &p, 0);
	if (*p != 0)
		return -1;
	if (v > UINT16_MAX) {
		fprintf(stderr, "%s out of range\n", tmp);
		return -1;
	}
	val[ret] = v;
	ret++;

	while (1) {
		tmp = strtok(NULL, ",");
		if (tmp == NULL)
			return ret;

		if (ret >= max_length)
			return -1;

		v = strtoul(tmp, &p, 0);
		if (*p != 0)
			return -1;
		if (v > UINT16_MAX) {
			fprintf(stderr, "%s out of range\n", tmp);
			return -1;
		}
		val[ret] = v;
		ret++;
	}
}

int argconfig_parse_comma_sep_array_long(char *string, unsigned long long *val,
					 unsigned int max_length)
{
	int ret = 0;
	char *tmp;
	char *p;

	if (!string || !strlen(string))
		return 0;

	tmp = strtok(string, ",");
	if (tmp == NULL)
		return 0;

	val[ret] = strtoll(tmp, &p, 0);
	if (*p != 0)
		return -1;
	ret++;
	while (1) {
		tmp = strtok(NULL, ",");

		if (tmp == NULL)
			return ret;

		if (ret >= max_length)
			return -1;

		val[ret] = strtoll(tmp, &p, 0);
		if (*p != 0)
			return -1;
		ret++;
	}
}

#define DEFINE_ARGCONFIG_PARSE_COMMA_SEP_ARRAY_UINT_FUNC(size)		\
int argconfig_parse_comma_sep_array_u##size(char *string,		\
					    __u##size *val,		\
					    unsigned int max_length)	\
{									\
	int ret = 0;							\
	uintmax_t v;							\
	char *tmp;							\
	char *p;							\
									\
	if (!string || !strlen(string))				\
		return 0;						\
									\
	tmp = strtok(string, ",");					\
	if (!tmp)							\
		return 0;						\
									\
	v = strtoumax(tmp, &p, 0);					\
	if (*p != 0)							\
		return -1;						\
	if (v > UINT##size##_MAX) {					\
		fprintf(stderr, "%s out of range\n", tmp);		\
		return -1;						\
	}								\
	val[ret] = v;							\
									\
	ret++;								\
	while (1) {							\
		tmp = strtok(NULL, ",");				\
									\
		if (tmp == NULL)					\
			return ret;					\
									\
		if (ret >= max_length)					\
			return -1;					\
									\
		v = strtoumax(tmp, &p, 0);				\
		if (*p != 0)						\
			return -1;					\
		if (v > UINT##size##_MAX) {				\
			fprintf(stderr, "%s out of range\n", tmp);	\
			return -1;					\
		}							\
		val[ret] = v;						\
		ret++;							\
	}								\
}

DEFINE_ARGCONFIG_PARSE_COMMA_SEP_ARRAY_UINT_FUNC(16);
DEFINE_ARGCONFIG_PARSE_COMMA_SEP_ARRAY_UINT_FUNC(32);
DEFINE_ARGCONFIG_PARSE_COMMA_SEP_ARRAY_UINT_FUNC(64);

bool argconfig_parse_seen(struct argconfig_commandline_options *s,
			  const char *option)
{
	for (; s && s->option; s++) {
		if (!strcmp(s->option, option))
			return s->seen;
	}

	return false;
}
