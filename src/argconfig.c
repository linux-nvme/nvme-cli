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

#include <ctype.h>
#include <errno.h>
#include <locale.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libnvme.h>

#include <shared/suffix-util.h>
#include <shared/wrap-util.h>

#include "argconfig.h"
#include "cleanup.h"

static bool is_null_or_empty(const char *s)
{
	return !s || !*s;
}

static const char *append_usage_str = "";

/*
 * Options every command accepts, registered once instead of being added to
 * each command's table. They are looked up before the command's own
 * options, so a global option means the same for every command; a command
 * must not use their names.
 */
static struct argconfig_commandline_options *global_options;

void argconfig_set_global_options(struct argconfig_commandline_options *options)
{
	global_options = options;
}

struct argconfig_commandline_options *argconfig_get_global_options(void)
{
	return global_options;
}

/* The global options, unless they are the table itself */
static struct argconfig_commandline_options *
argconfig_globals(struct argconfig_commandline_options *options)
{
	return options == global_options ? NULL : global_options;
}

void argconfig_append_usage(const char *str)
{
	append_usage_str = str;
}

/* "nvme" and "id ctrl" of the current command, for the usage errors */
static const char *command_prog;
static const char *command_path;
/* argv[0] of the current parse, if no command is set */
static const char *parse_argv0 = "";

void argconfig_set_command(const char *prog, const char *path)
{
	command_prog = prog;
	command_path = path;
}

static const char *command_name(void)
{
	return command_path ? command_path : parse_argv0;
}

static void print_label(const char *name)
{
	fprintf(stderr, "%s%s:%s ", argconfig_esc(stderr, ARGCONFIG_RED), name,
		argconfig_esc(stderr, ARGCONFIG_RESET));
}

/* "<command>: " before an error of the current command, if one runs */
void argconfig_print_error_label(void)
{
	if (command_path)
		print_label(command_path);
}

/* The synopsis and where to find the help, after a usage error */
void argconfig_print_usage(void)
{
	fprintf(stderr, "Usage: %s\n", append_usage_str);
	if (command_prog && command_path)
		fprintf(stderr, "Try '%s %s --help' for more information.\n",
			command_prog, command_path);
}

/* A usage error of the current command, followed by its usage */
int argconfig_usage_error(const char *fmt, ...)
{
	va_list ap;

	print_label(command_name());
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
	argconfig_print_usage();

	return -EINVAL;
}

/* The names an option accepts, below its description */
static void show_value_names(FILE *out, const struct argconfig_opt_val *v)
{
	__cleanup_free char *names = NULL;
	size_t len = sizeof("\nNames:");
	const struct argconfig_opt_val *n;
	char *p;

	if (!v || !v->str)
		return;

	for (n = v; n->str; n++)
		len += strlen(n->str) + 2;

	names = malloc(len);
	if (!names)
		return;

	p = names + sprintf(names, "\nNames:");
	for (n = v; n->str; n++)
		p += sprintf(p, " %s%s", n->str, n[1].str ? "," : "");

	shr_print_word_wrapped(names, 44, 44, out);
}

static void show_option(FILE *out,
			const struct argconfig_commandline_options *option)
{
	char buffer[0x1000];
	char *b = buffer;

	b += sprintf(b, "  [ ");
	if (option->option) {
		b += sprintf(b, " --%s", option->option);
		if (option->argument_type == ARGCONFIG_ARG_OPTIONAL)
			b += sprintf(b, "[=<%s>]", option->meta ? option->meta : "arg");
		if (option->argument_type == ARGCONFIG_ARG_REQUIRED)
			b += sprintf(b, "=<%s>", option->meta ? option->meta : "arg");
		if (option->short_option)
			b += sprintf(b, ",");
	}
	if (option->short_option) {
		b += sprintf(b, " -%c", option->short_option);
		if (option->argument_type == ARGCONFIG_ARG_OPTIONAL)
			b += sprintf(b, " [<%s>]", option->meta ? option->meta : "arg");
		if (option->argument_type == ARGCONFIG_ARG_REQUIRED)
			b += sprintf(b, " <%s>", option->meta ? option->meta : "arg");
	}
	b += sprintf(b, " ] ");

	fprintf(out, "%s", buffer);
	if (option->help) {
		shr_print_word_wrapped("--- ", 40, b - buffer, out);
		shr_print_word_wrapped(option->help, 44, 44, out);
		show_value_names(out, option->opt_val);
	}
	fprintf(out, "\n");
}

/*
 * Escape sequences for bold and colors go only to a terminal, and not
 * when NO_COLOR is set to a non-empty value (https://no-color.org/).
 */
const char *argconfig_esc(FILE *out, const char *seq)
{
	const char *no_color = getenv("NO_COLOR");

	if (!isatty(fileno(out)) || (no_color && *no_color))
		return "";

	return seq;
}

/* "WARNING:" on stderr, in yellow on a terminal */
void argconfig_print_warning(void)
{
	fprintf(stderr, "%sWARNING:%s", argconfig_esc(stderr, ARGCONFIG_YELLOW),
		argconfig_esc(stderr, ARGCONFIG_RESET));
}

/* A heading, in bold on a terminal */
void argconfig_print_heading(FILE *out, const char *fmt, const char *text)
{
	fputs(argconfig_esc(out, ARGCONFIG_BOLD), out);
	fprintf(out, fmt, text);
	fputs(argconfig_esc(out, ARGCONFIG_RESET), out);
}

/* A group header is printed before the first option which follows it */
static void print_options(FILE *out, struct argconfig_commandline_options *s,
			  const char *header)
{
	bool header_printed = false;

	for (; s && s->option; s++) {
		if (s->config_type == CFG_INCLUDE) {
			print_options(out, s->default_value, s->help);
			/* the own options after it get their heading again */
			header_printed = false;
			continue;
		}
		if (s->config_type == CFG_GROUP_SEPARATOR) {
			header = s->help;
			header_printed = false;
			continue;
		}
		if (!header_printed) {
			fputc('\n', out);
			argconfig_print_heading(out, "%s:", header);
			fputc('\n', out);
			header_printed = true;
		}
		if (!s->deprecated)
			show_option(out, s);
	}
}

static void show_help(FILE *out, const char *program_desc,
		      struct argconfig_commandline_options *s)
{
	argconfig_print_heading(out, "Usage: %s", append_usage_str);
	fputs("\n\n", out);

	shr_print_word_wrapped(program_desc, 0, 0, out);
	fputc('\n', out);

	print_options(out, s, "Options");
	print_options(out, argconfig_globals(s), "Global options");
}

static bool help_requested;

/* True once argconfig_parse() printed the help -h or --help asked for */
bool argconfig_help_requested(void)
{
	return help_requested;
}

/*
 * strtoul() accepts a sign and negates the result, so "-1" would become the
 * largest value. The value tables of an option can name such a value.
 */
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

	errno = 0;    /* To distinguish success/failure after strtol/stroul call */

	switch (s->config_type) {
	case CFG_BYTE:
	case CFG_SHORT:
	case CFG_POSITIVE:
	case CFG_LONG:
	case CFG_LONG_SUFFIX:
		if (argconfig_negative(arg))
			return -EINVAL;
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
			ret = -EINVAL;
		break;
	case CFG_BYTE: {
		unsigned long tmp = strtoul(arg, &endptr, 0);

		if (errno || tmp >= 1 << 8 || arg == endptr || *endptr)
			ret = -EINVAL;
		else
			*(uint8_t *)value = tmp;
		break;
	}
	case CFG_SHORT: {
		unsigned long tmp = strtoul(arg, &endptr, 0);

		if (errno || tmp >= 1 << 16 || arg == endptr || *endptr)
			ret = -EINVAL;
		else
			*(uint16_t *)value = tmp;
		break;
	}
	case CFG_POSITIVE: {
		unsigned long long tmp = strtoull(arg, &endptr, 0);

		if (errno || tmp > UINT32_MAX || arg == endptr || *endptr)
			ret = -EINVAL;
		else
			*(uint32_t *)value = tmp;
		break;
	}
	case CFG_INCREMENT:
		*(int *)value += 1;
		break;
	case CFG_ENUM:
		/* only the names, which argconfig_parse_val() looked up */
		ret = -EINVAL;
		break;
	case CFG_LONG:
		*(uint64_t *)value = strtoull(arg, &endptr, 0);
		if (errno || arg == endptr || *endptr)
			ret = -EINVAL;
		break;
	case CFG_LONG_SUFFIX:
		ret = shr_suffix_binary_parse(arg, &endptr, (uint64_t *)value);
		break;
	case CFG_DOUBLE:
		*(double *)value = strtod(arg, &endptr);
		if (errno || arg == endptr || *endptr)
			ret = -EINVAL;
		break;
	case CFG_FLAG:
		*(bool *)value = true;
		break;
	case CFG_GROUP_SEPARATOR:
	case CFG_INCLUDE:
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

/*
 * Store the value which @str names in the value table of @s. False if
 * the option has no value of that name.
 */
bool argconfig_set_value_name(struct argconfig_commandline_options *s,
			      const char *str)
{
	struct argconfig_opt_val *v = s->opt_val;

	if (v)
		v = argconfig_match_val(v, str);
	if (!v)
		return false;

	argconfig_set_opt_val(v->type, &v->val, s->default_value);
	return true;
}

static int argconfig_parse_val(struct argconfig_commandline_options *s,
			       char *arg)
{
	if (argconfig_set_value_name(s, arg))
		return 0;

	return argconfig_parse_type(s, arg);
}

/* The non-option arguments of the last successful argconfig_parse() */
static struct {
	char **argv;
	int argc;
} operands;

int argconfig_nr_operands(void)
{
	return operands.argc;
}

char *argconfig_operand(int i)
{
	if (i < 0 || i >= operands.argc)
		return NULL;

	return operands.argv[i];
}

/*
 * The state of one parse. argv is not modified: the operands are collected
 * in their own array, in the order they are given.
 */
struct argconfig_parser {
	int argc;
	char **argv;
	int ind;
	struct argconfig_commandline_options *options;
	/*
	 * Global options stop at the first operand, the subcommand. Their
	 * implicit -h, --help, -V and --version are recorded and the parse
	 * goes on.
	 */
	bool global;
	bool help;
	bool version;
	char **operands;
	int nr_operands;
};

/*
 * Internal result of argconfig_parse_args(): an option was malformed. Like
 * ARGCONFIG_HELP, it prints the help of a command.
 */
#define ARGCONFIG_USAGE	4

/*
 * The parse errors use the wording of glibc's getopt, which printed them
 * before argconfig had its own parser.
 */
static int argconfig_parse_error(struct argconfig_parser *p,
				 const char *fmt, ...)
{
	va_list ap;

	print_label(command_name());
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");

	return ARGCONFIG_USAGE;
}

static struct argconfig_commandline_options *
argconfig_find_long(struct argconfig_commandline_options *s,
		    const char *name, size_t len)
{
	struct argconfig_commandline_options *o;

	for (; s->option; s++) {
		if (s->config_type == CFG_INCLUDE) {
			o = argconfig_find_long(s->default_value, name, len);
			if (o)
				return o;
			continue;
		}
		if (s->config_type == CFG_GROUP_SEPARATOR ||
		    is_null_or_empty(s->option))
			continue;
		if (strlen(s->option) == len && !strncmp(s->option, name, len))
			return s;
		if (s->old_name && strlen(s->old_name) == len &&
		    !strncmp(s->old_name, name, len))
			return s;
	}

	return NULL;
}

static struct argconfig_commandline_options *
argconfig_find_short(struct argconfig_commandline_options *s, char c)
{
	struct argconfig_commandline_options *o;

	for (; s->option; s++) {
		if (s->config_type == CFG_INCLUDE) {
			o = argconfig_find_short(s->default_value, c);
			if (o)
				return o;
			continue;
		}
		if (s->config_type == CFG_GROUP_SEPARATOR)
			continue;
		if (s->short_option == c)
			return s;
	}

	return NULL;
}

/* @s given by its short name @c, or by its long name without, and @arg */
/*
 * The option @s or the global options name, the global ones first: a
 * global option is the same for every command.
 */
static struct argconfig_commandline_options *
argconfig_find_long_any(struct argconfig_commandline_options *s,
			const char *name, size_t len)
{
	struct argconfig_commandline_options *g = argconfig_globals(s);
	struct argconfig_commandline_options *o = NULL;

	if (g)
		o = argconfig_find_long(g, name, len);

	return o ? o : argconfig_find_long(s, name, len);
}

static struct argconfig_commandline_options *
argconfig_find_short_any(struct argconfig_commandline_options *s, char c)
{
	struct argconfig_commandline_options *g = argconfig_globals(s);
	struct argconfig_commandline_options *o = NULL;

	if (g)
		o = argconfig_find_short(g, c);

	return o ? o : argconfig_find_short(s, c);
}

/* What a value of @s has to look like */
static const char *argconfig_expected(struct argconfig_commandline_options *s)
{
	switch (s->config_type) {
	case CFG_BYTE:
		return "a number from 0 to 255";
	case CFG_SHORT:
		return "a number from 0 to 65535";
	case CFG_POSITIVE:
		return "a number from 0 to 4294967295";
	case CFG_LONG:
		return "a number from 0 to 18446744073709551615";
	case CFG_LONG_SUFFIX:
		return "a size such as 4096 or 4Ki";
	default:
		return "a number";
	}
}

/* @arg is no value of @s, given by its short name @c or its long name */
static int argconfig_value_error(struct argconfig_commandline_options *s,
				 char c, const char *arg)
{
	const struct argconfig_opt_val *v;
	int n = 0;

	print_label(command_name());
	fprintf(stderr, "invalid value '%s' for ", arg);
	if (c)
		fprintf(stderr, "-%c", c);
	else
		fprintf(stderr, "--%s", s->option);
	fprintf(stderr, ": expected ");
	if (s->config_type != CFG_ENUM)
		fprintf(stderr, "%s%s", argconfig_expected(s),
			s->opt_val ? " or " : "");

	/* A long list of names would drown the error, the help has them */
	for (v = s->opt_val; v && v->str; v++)
		n++;
	if (n > 8)
		fprintf(stderr, "one of the names in the help");
	for (v = s->opt_val; n <= 8 && v && v->str; v++)
		fprintf(stderr, "%s%s", v == s->opt_val ? "one of: " : ", ",
			v->str);
	fprintf(stderr, "\n");

	return ARGCONFIG_USAGE;
}

static int argconfig_apply(struct argconfig_commandline_options *s, char c,
			   char *arg)
{
	int ret;

	if (s->deprecated && !s->seen) {
		argconfig_print_warning();
		if (c)
			fprintf(stderr, " '-%c'", c);
		else
			fprintf(stderr, " '--%s'", s->option);
		fprintf(stderr,
			" is deprecated and will be removed in the next major version, use '%s' instead\n",
			s->deprecated);
	}
	s->seen = true;

	if (!s->default_value)
		return 0;

	ret = argconfig_parse_val(s, arg);
	if (ret == -EINVAL)
		return argconfig_value_error(s, c, arg);

	return ret;
}

/*
 * A copy of the template table @tmpl, whose options store into the
 * struct at @tmpl_base of @size bytes, bound to the struct of the same
 * type at @base. Commands share the template and parse into their own
 * struct. The caller frees the copy.
 */
struct argconfig_commandline_options *
argconfig_bind(const struct argconfig_commandline_options *tmpl,
	       const void *tmpl_base, size_t size, void *base)
{
	struct argconfig_commandline_options *dst;
	uintptr_t start = (uintptr_t)tmpl_base;
	uintptr_t v;
	size_t n = 0, i;

	while (tmpl[n].option)
		n++;

	dst = calloc(n + 1, sizeof(*dst));
	if (!dst)
		return NULL;
	memcpy(dst, tmpl, (n + 1) * sizeof(*dst));

	for (i = 0; i < n; i++) {
		v = (uintptr_t)tmpl[i].default_value;
		if (v >= start && v < start + size)
			dst[i].default_value = (char *)base + (v - start);
	}

	return dst;
}

/* The name of the enum value @val in the value table @v, or NULL */
const char *argconfig_value_name(const struct argconfig_opt_val *v, int val)
{
	for (; v && v->str; v++) {
		if (v->type == CFG_ENUM && v->val.int_val == val)
			return v->str;
	}

	return NULL;
}

/* The value of a required argument which is not attached to the option */
static char *argconfig_next_arg(struct argconfig_parser *p)
{
	if (p->ind + 1 >= p->argc)
		return NULL;

	return p->argv[++p->ind];
}

/* "--name", "--name=value" or "--name value" */
static int argconfig_parse_long(struct argconfig_parser *p, char *arg)
{
	struct argconfig_commandline_options *s;
	char *name = arg + 2, *value = NULL;
	char *eq = strchr(name, '=');
	size_t len = eq ? (size_t)(eq - name) : strlen(name);

	s = argconfig_find_long_any(p->options, name, len);
	if (!s) {
		bool help = len == 4 && !strncmp(name, "help", 4);
		bool version = len == 7 && !strncmp(name, "version", 7);

		if (help && !p->global)
			return ARGCONFIG_HELP;
		if (!p->global || (!help && !version))
			return argconfig_parse_error(p,
				"unrecognized option '%s'", arg);
		if (eq)
			return argconfig_parse_error(p,
				"option '--%.*s' doesn't allow an argument",
				(int)len, name);
		p->help |= help;
		p->version |= version;
		return 0;
	}

	switch (s->argument_type) {
	case ARGCONFIG_ARG_NONE:
		if (eq)
			return argconfig_parse_error(p,
				"option '--%s' doesn't allow an argument",
				s->option);
		break;
	case ARGCONFIG_ARG_REQUIRED:
		value = eq ? eq + 1 : argconfig_next_arg(p);
		if (!value)
			return argconfig_parse_error(p,
				"option '--%s' requires an argument",
				s->option);
		break;
	case ARGCONFIG_ARG_OPTIONAL:
		/* Only an attached value, "--name value" is an operand */
		if (eq)
			value = eq + 1;
		break;
	}

	if (s->old_name && !s->seen &&
	    (strlen(s->option) != len || strncmp(s->option, name, len))) {
		argconfig_print_warning();
		fprintf(stderr,
			" '--%s' is deprecated and will be removed in the next major version, use '--%s' instead\n",
			s->old_name, s->option);
	}

	return argconfig_apply(s, 0, value);
}

/* "-a", "-abc", "-ovalue", "-o value" */
static int argconfig_parse_short(struct argconfig_parser *p, char *arg)
{
	struct argconfig_commandline_options *s;
	char *c, *value;
	int ret;

	for (c = arg + 1; *c; c++) {
		if (!p->global && (*c == 'h' || *c == '?'))
			return ARGCONFIG_HELP;

		s = argconfig_find_short_any(p->options, *c);
		if (!s && p->global && (*c == 'h' || *c == 'V')) {
			p->help |= *c == 'h';
			p->version |= *c == 'V';
			continue;
		}
		if (!s)
			return argconfig_parse_error(p,
				"invalid option -- '%c'", *c);

		value = NULL;
		switch (s->argument_type) {
		case ARGCONFIG_ARG_NONE:
			break;
		case ARGCONFIG_ARG_REQUIRED:
			value = c[1] ? c + 1 : argconfig_next_arg(p);
			if (!value)
				return argconfig_parse_error(p,
					"option requires an argument -- '%c'",
					*c);
			break;
		case ARGCONFIG_ARG_OPTIONAL:
			if (c[1])
				value = c + 1;
			break;
		}

		ret = argconfig_apply(s, *c, value);
		if (ret || s->argument_type != ARGCONFIG_ARG_NONE)
			return ret;
	}

	return 0;
}

/*
 * Options and operands may be given in any order, "--" ends the options.
 * Returns 0, ARGCONFIG_HELP, ARGCONFIG_USAGE or a negative errno from the
 * value conversion.
 */
/* Forget the options given before, also those of included tables */
static void argconfig_reset_seen(struct argconfig_commandline_options *s)
{
	for (; s->option; s++) {
		if (s->config_type == CFG_INCLUDE)
			argconfig_reset_seen(s->default_value);
		s->seen = false;
	}
}

static int argconfig_parse_args(struct argconfig_parser *p)
{
	char *arg;
	int ret;

	argconfig_reset_seen(p->options);

	for (p->ind = 1; p->ind < p->argc; p->ind++) {
		arg = p->argv[p->ind];

		if (!strcmp(arg, "--")) {
			p->ind++;
			if (p->global)
				return 0;
			while (p->ind < p->argc)
				p->operands[p->nr_operands++] =
					p->argv[p->ind++];
			return 0;
		}

		if (arg[0] != '-' || !arg[1]) {
			if (p->global)
				return 0;
			p->operands[p->nr_operands++] = arg;
			continue;
		}

		if (arg[1] == '-')
			ret = argconfig_parse_long(p, arg);
		else
			ret = argconfig_parse_short(p, arg);
		if (ret)
			return ret;
	}

	return 0;
}

static argconfig_parse_hook_fn argconfig_parse_hook;

void argconfig_set_parse_hook(argconfig_parse_hook_fn hook)
{
	argconfig_parse_hook = hook;
}

/* --verbose, or an alias of it such as --human-readable, was given */
static bool argconfig_check_verbose(struct argconfig_commandline_options *s)
{
	struct argconfig_commandline_options *v;

	v = argconfig_find_long_any(s, "verbose", strlen("verbose"));
	if (!v || v->config_type != CFG_INCREMENT)
		return false;

	return argconfig_given(s, v->default_value);
}

int argconfig_parse(int argc, char *argv[], const char *program_desc,
		    struct argconfig_commandline_options *options)
{
	static char **operand_buf;
	struct argconfig_parser p = {
		.argc = argc,
		.argv = argv,
		.options = options,
	};
	int ret;

	parse_argv0 = argc > 0 ? argv[0] : "";
	free(operand_buf);
	operand_buf = NULL;
	operands.argv = NULL;
	operands.argc = 0;

	if (argconfig_parse_hook)
		return argconfig_parse_hook(argc, argv, program_desc, options);

	p.operands = calloc(argc > 0 ? argc : 1, sizeof(*p.operands));
	if (!p.operands)
		return -ENOMEM;

	ret = argconfig_parse_args(&p);
	if (ret) {
		/*
		 * The help that was asked for goes to stdout, a usage error is
		 * followed by the synopsis on stderr. The command stops
		 * either way: it gets ARGCONFIG_HELP or an error.
		 */
		if (ret == ARGCONFIG_HELP) {
			show_help(stdout, program_desc, options);
			help_requested = true;
		} else if (ret > 0) {
			argconfig_print_usage();
			ret = -EINVAL;
		}
		free(p.operands);
	} else {
		operand_buf = p.operands;
		operands.argv = p.operands;
		operands.argc = p.nr_operands;
	}

	if (!argconfig_check_verbose(options))
		setlocale(LC_ALL, "C");

	return ret;
}

/*
 * Parse global (pre-subcommand) options from argc/argv. Stops at the first
 * non-option argument (i.e. the subcommand name) so that subcommand-specific
 * options are left in place for the subcommand dispatcher. After a successful
 * call, *argind is the index of the first non-option argument (the
 * subcommand), or argc if there is none.
 *
 * Unless the table has its own, -h, --help, -V and --version are accepted
 * like a global option. Returns ARGCONFIG_HELP and ARGCONFIG_VERSION for
 * them, 0 otherwise, or a negative errno on failure. @options may be NULL.
 */
int argconfig_parse_global(int argc, char *argv[],
			   struct argconfig_commandline_options *options,
			   int *argind)
{
	static struct argconfig_commandline_options no_options[] = {
		OPT_END()
	};
	struct argconfig_parser p = {
		.argc = argc,
		.argv = argv,
		.options = options ? options : no_options,
		.global = true,
	};
	int ret;

	parse_argv0 = argc > 0 ? argv[0] : "";
	ret = argconfig_parse_args(&p);
	*argind = p.ind;
	if (ret)
		return ret > 0 ? -EINVAL : ret;

	return (p.help ? ARGCONFIG_HELP : 0) |
	       (p.version ? ARGCONFIG_VERSION : 0);
}

static bool given_in(struct argconfig_commandline_options *s,
		     const void *value)
{
	bool given = false;

	for (; s && s->option; s++) {
		if (s->config_type == CFG_INCLUDE)
			given |= given_in(s->default_value, value);
		else
			given |= s->default_value == value && s->seen;
	}

	return given;
}

/*
 * True if an option which stores to @value was given, in the table or in
 * the global options. Aliases share the variable, so any of them counts.
 */
bool argconfig_given(struct argconfig_commandline_options *s,
		     const void *value)
{
	struct argconfig_commandline_options *g = argconfig_globals(s);

	if (!value)
		return false;

	return given_in(s, value) || given_in(g, value);
}
