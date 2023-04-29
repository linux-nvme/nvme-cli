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

#if __has_attribute(__fallthrough__)
#define fallthrough __attribute__((__fallthrough__))
#else
#define fallthrough do {} while (0)
#endif

static char END_DEFAULT[] = "__end_default__";

static const char *append_usage_str = "";

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
	const char *fopts = NULL;
	FILE *f;
	int ret = 0;
	char **opts = ((char **)value);
	int remaining_space = CFG_MAX_SUBOPTS - 2;

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
	case CFG_BOOL: {
		int tmp = strtol(optarg, &endptr, 0);
		if (errno || tmp < 0 || tmp > 1 || optarg == endptr)
			ret = argconfig_error("0 or 1", option[index].name, optarg);
		else
			*((int *)value) = tmp;
		break;
	}
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
		ret = suffix_binary_parse(optarg, &endptr, (uint64_t*)value);
		if (ret)
			argconfig_error("long suffixed integer", option[index].name, optarg);
		break;
	case CFG_DOUBLE:
		*((double *)value) = strtod(optarg, &endptr);
		if (errno || optarg == endptr)
			ret = argconfig_error("float", option[index].name, optarg);
		break;
	case CFG_SUBOPTS:
		*opts = END_DEFAULT;
		opts += 2;
		ret = argconfig_parse_subopt_string(optarg, opts, remaining_space);
		if (ret) {
			if (ret == 2)
				fprintf(stderr, "Error Parsing Sub-Options: Too many options!\n");
			else
				fprintf(stderr, "Error Parsing Sub-Options\n");
			ret = -EINVAL;
		}
		break;
	case CFG_FILE_A:
		fopts = "a";
		fallthrough;
	case CFG_FILE_R:
		if (!fopts)
			fopts = "r";
		fallthrough;
	case CFG_FILE_W:
		if (!fopts)
			fopts = "w";
		fallthrough;
	case CFG_FILE_AP:
		if (!fopts)
			fopts = "a+";
		fallthrough;
	case CFG_FILE_RP:
		if (!fopts)
			fopts = "r+";
		fallthrough;
	case CFG_FILE_WP:
		if (!fopts)
			fopts = "w+";
		f = fopen(optarg, fopts);
		if (!f) {
			fprintf(stderr, "Unable to open %s file: %s\n", s->option, optarg);
			ret = -EINVAL;
		} else {
			*((FILE **)value) = f;
		}
		break;
	case CFG_FLAG:
		*((bool *)value) = true;
		break;
	default:
		break;
	}

	return ret;
}

bool argconfig_output_format_json(bool set)
{
	static bool output_format_json = false;

	if (set)
		output_format_json = true;

	return output_format_json;
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
			if (c == 'j')
				argconfig_output_format_json(true);
			for (option_index = 0; option_index < options_count; option_index++) {
				if (c == options[option_index].short_option)
					break;
			}
			if (option_index == options_count)
				continue;
		}

		s = &options[option_index];
		s->seen = true;

		if (!s->default_value)
			continue;

		ret = argconfig_parse_type(s, long_opts,option_index);
		if (ret)
			break;
	}

	if (argconfig_check_output_format_json(options))
		argconfig_output_format_json(true);

out:
	free(short_opts);
	free(long_opts);
	return ret;
}

int argconfig_parse_subopt_string(char *string, char **options,
				  size_t max_options)
{
	char **o = options;
	char *tmp;
	size_t toklen;

	if (!string || !strlen(string)) {
		*(o++) = NULL;
		*(o++) = NULL;
		return 0;
	}

	tmp = calloc(strlen(string) + 2, 1);
	if (!tmp)
		return 1;
	strcpy(tmp, string);

	toklen = strcspn(tmp, "=");

	if (!toklen) {
		free(tmp);
		return 1;
	}

	*(o++) = tmp;
	tmp[toklen] = 0;
	tmp += toklen + 1;

	while (1) {
		if (*tmp == '"' || *tmp == '\'' || *tmp == '[' || *tmp == '(' ||
		    *tmp == '{') {

			tmp++;
			toklen = strcspn(tmp, "\"'])}");

			if (!toklen)
				return 1;

			*(o++) = tmp;
			tmp[toklen] = 0;
			tmp += toklen + 1;

			toklen = strcspn(tmp, ";:,");
			tmp[toklen] = 0;
			tmp += toklen + 1;
		} else {
			toklen = strcspn(tmp, ";:,");

			if (!toklen)
				return 1;

			*(o++) = tmp;
			tmp[toklen] = 0;
			tmp += toklen + 1;
		}

		toklen = strcspn(tmp, "=");

		if (!toklen)
			break;

		*(o++) = tmp;
		tmp[toklen] = 0;
		tmp += toklen + 1;

		if ((o - options) > (max_options - 2))
			return 2;
	}

	*(o++) = NULL;
	*(o++) = NULL;

	return 0;
}

int argconfig_parse_comma_sep_array(char *string, int *val,
					 unsigned max_length)
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
					  unsigned max_length)
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

int argconfig_parse_comma_sep_array_long(char *string,
					      unsigned long long *val,
					      unsigned max_length)
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

bool argconfig_parse_seen(struct argconfig_commandline_options *s,
			  const char *option)
{
	for (; s && s->option; s++) {
		if (!strcmp(s->option, option))
			return s->seen;
	}

	return false;
}
