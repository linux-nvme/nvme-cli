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
 * each command's table. The command's own options are looked up first, so
 * a command can still use a short or long name of a global option.
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

	fprintf(out, "%s", buffer);
	if (option->help) {
		shr_print_word_wrapped("--- ", 40, b - buffer, out);
		shr_print_word_wrapped(option->help, 44, 44, out);
		show_value_names(out, option->opt_val);
	}
	fprintf(out, "\n");
}

/* A heading, in bold on a terminal */
static void print_heading(FILE *out, const char *fmt, const char *text)
{
	bool tty = isatty(fileno(out));

	fputs(tty ? "\033[1m" : "", out);
	fprintf(out, fmt, text);
	fputs(tty ? "\033[0m" : "", out);
}

/* A group header is printed before the first option which follows it */
static void print_options(FILE *out, struct argconfig_commandline_options *s,
			  const char *header)
{
	bool header_printed = false;

	for (; s && s->option; s++) {
		if (s->config_type == CFG_GROUP_SEPARATOR) {
			header = s->help;
			header_printed = false;
			continue;
		}
		if (!header_printed) {
			fputc('\n', out);
			print_heading(out, "%s:", header);
			fputc('\n', out);
			header_printed = true;
		}
		if (!s->hidden)
			show_option(out, s);
	}
}

static void show_help(FILE *out, const char *program_desc,
		      struct argconfig_commandline_options *s)
{
	print_heading(out, "Usage: %s", append_usage_str);
	fputs("\n\n", out);

	shr_print_word_wrapped(program_desc, 0, 0, out);
	fputc('\n', out);

	print_options(out, s, "Options");
	print_options(out, argconfig_globals(s), "Global options");
}

/* The help after a usage error, on stderr */
void argconfig_print_help(const char *program_desc,
			  struct argconfig_commandline_options *s)
{
	show_help(stderr, program_desc, s);
}

static bool help_requested;

/* True once argconfig_parse() printed the help -h or --help asked for */
bool argconfig_help_requested(void)
{
	return help_requested;
}

static int argconfig_error(char *type, const char *opt, const char *arg)
{
	fprintf(stderr, "Expected %s argument for '%s' but got '%s'!\n", type, opt, arg);
	return -EINVAL;
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
		if (errno || arg == endptr)
			ret = argconfig_error("integer", s->option, arg);
		break;
	case CFG_BYTE: {
		unsigned long tmp = strtoul(arg, &endptr, 0);

		if (errno || tmp >= 1 << 8 || arg == endptr)
			ret = argconfig_error("byte", s->option, arg);
		else
			*(uint8_t *)value = tmp;
		break;
	}
	case CFG_SHORT: {
		unsigned long tmp = strtoul(arg, &endptr, 0);

		if (errno || tmp >= 1 << 16 || arg == endptr)
			ret = argconfig_error("short", s->option, arg);
		else
			*(uint16_t *)value = tmp;
		break;
	}
	case CFG_POSITIVE: {
		unsigned long long tmp = strtoull(arg, &endptr, 0);

		if (errno || tmp > UINT32_MAX || arg == endptr)
			ret = argconfig_error("word", s->option, arg);
		else
			*(uint32_t *)value = tmp;
		break;
	}
	case CFG_INCREMENT:
		*(int *)value += 1;
		break;
	case CFG_LONG:
		*(uint64_t *)value = strtoull(arg, &endptr, 0);
		if (errno || arg == endptr)
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
		if (errno || arg == endptr)
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

/* --verbose counts, a command may have a flag of the same name */
static bool argconfig_check_verbose(struct argconfig_commandline_options *s)
{
	struct argconfig_commandline_options *g = argconfig_globals(s);

	for (; s && s->option; s++) {
		if (!strcmp(s->option, "verbose") &&
		    s->config_type == CFG_INCREMENT)
			return s->seen;
	}
	for (; g && g->option; g++) {
		if (!strcmp(g->option, "verbose") &&
		    g->config_type == CFG_INCREMENT)
			return g->seen;
	}

	return false;
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

	fprintf(stderr, "%s: ", p->argv[0]);
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
	for (; s->option; s++) {
		if (s->config_type == CFG_GROUP_SEPARATOR ||
		    is_null_or_empty(s->option))
			continue;
		if (strlen(s->option) == len && !strncmp(s->option, name, len))
			return s;
	}

	return NULL;
}

static struct argconfig_commandline_options *
argconfig_find_short(struct argconfig_commandline_options *s, char c)
{
	for (; s->option; s++) {
		if (s->config_type == CFG_GROUP_SEPARATOR)
			continue;
		if (s->short_option == c)
			return s;
	}

	return NULL;
}

static int argconfig_apply(struct argconfig_commandline_options *s,
			   char *arg)
{
	s->seen = true;

	if (!s->default_value)
		return 0;

	return argconfig_parse_val(s, arg);
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

	s = argconfig_find_long(p->options, name, len);
	if (!s && argconfig_globals(p->options))
		s = argconfig_find_long(argconfig_globals(p->options), name,
					len);
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
	case no_argument:
		if (eq)
			return argconfig_parse_error(p,
				"option '--%s' doesn't allow an argument",
				s->option);
		break;
	case required_argument:
		value = eq ? eq + 1 : argconfig_next_arg(p);
		if (!value)
			return argconfig_parse_error(p,
				"option '--%s' requires an argument",
				s->option);
		break;
	case optional_argument:
		/* Only an attached value, "--name value" is an operand */
		if (eq)
			value = eq + 1;
		break;
	}

	return argconfig_apply(s, value);
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

		s = argconfig_find_short(p->options, *c);
		if (!s && argconfig_globals(p->options))
			s = argconfig_find_short(argconfig_globals(p->options),
						 *c);
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
		case no_argument:
			break;
		case required_argument:
			value = c[1] ? c + 1 : argconfig_next_arg(p);
			if (!value)
				return argconfig_parse_error(p,
					"option requires an argument -- '%c'",
					*c);
			break;
		case optional_argument:
			if (c[1])
				value = c + 1;
			break;
		}

		ret = argconfig_apply(s, value);
		if (ret || s->argument_type != no_argument)
			return ret;
	}

	return 0;
}

/*
 * Options and operands may be given in any order, "--" ends the options.
 * Returns 0, ARGCONFIG_HELP, ARGCONFIG_USAGE or a negative errno from the
 * value conversion.
 */
static int argconfig_parse_args(struct argconfig_parser *p)
{
	struct argconfig_commandline_options *s;
	char *arg;
	int ret;

	for (s = p->options; s->option; s++)
		s->seen = false;

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
		 * The help that was asked for goes to stdout, the one after a
		 * malformed option to stderr. A bad value prints no help.
		 * The command stops either way: it gets ARGCONFIG_HELP or an
		 * error.
		 */
		if (ret == ARGCONFIG_HELP) {
			show_help(stdout, program_desc, options);
			help_requested = true;
		} else if (ret > 0) {
			argconfig_print_help(program_desc, options);
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

	ret = argconfig_parse_args(&p);
	*argind = p.ind;
	if (ret)
		return ret > 0 ? -EINVAL : ret;

	return (p.help ? ARGCONFIG_HELP : 0) |
	       (p.version ? ARGCONFIG_VERSION : 0);
}

/*
 * True if an option which stores to @value was given, in the table or in
 * the global options. Aliases share the variable, so any of them counts.
 */
bool argconfig_given(struct argconfig_commandline_options *s,
		     const void *value)
{
	struct argconfig_commandline_options *g = argconfig_globals(s);
	bool given = false;

	if (!value)
		return false;

	for (; s && s->option; s++)
		given |= s->default_value == value && s->seen;
	for (; g && g->option; g++)
		given |= g->default_value == value && g->seen;

	return given;
}
