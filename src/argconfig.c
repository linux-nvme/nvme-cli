// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2014 PMC-Sierra, Inc.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Logan Gunthorpe <logang@deltatee.com>
 *          Daniel Wagner <dwagner@suse.de>
 */

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <locale.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libnvme.h>

#include <shared/parse-util.h>
#include <shared/string-util.h>
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

/* The entries of a root, see argconfig_root() */
#define ARGCONFIG_ROOT_LEN	3

/*
 * The options a command accepts: its table @options and the global
 * options, each as an include with the heading of the help. The global
 * options are included last, as root[1]. The table of the global options
 * themselves includes nothing else.
 */
static void argconfig_root(struct argconfig_commandline_options *root,
			   struct argconfig_commandline_options *options)
{
	struct argconfig_commandline_options r[ARGCONFIG_ROOT_LEN] = {
		OPT_INCLUDE(options, "Options"),
		OPT_INCLUDE(global_options, "Global options"),
		OPT_END()
	};
	struct argconfig_commandline_options end[] = { OPT_END() };

	memcpy(root, r, sizeof(r));
	if (!global_options || options == global_options)
		memcpy(&root[1], end, sizeof(end));
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

	p = names + snprintf(names, len, "\nNames:");
	for (n = v; n->str; n++)
		p += snprintf(p, len - (p - names), " %s%s", n->str,
			      n[1].str ? "," : "");

	shr_print_word_wrapped(names, 44, 44, out);
}

static void show_option(FILE *out,
			const struct argconfig_commandline_options *option)
{
	const char *meta = option->meta ? option->meta : "arg";
	enum argconfig_argument arg = option->argument_type;
	char buffer[0x1000];
	size_t len = 0;

	buffer[0] = '\0';
	shr_snprintf_append(buffer, sizeof(buffer), &len, "  [ ");
	if (option->option) {
		shr_snprintf_append(buffer, sizeof(buffer), &len, " --%s",
				    option->option);
		if (arg == ARGCONFIG_ARG_OPTIONAL)
			shr_snprintf_append(buffer, sizeof(buffer), &len,
					    "[=<%s>]", meta);
		if (arg == ARGCONFIG_ARG_REQUIRED)
			shr_snprintf_append(buffer, sizeof(buffer), &len,
					    "=<%s>", meta);
		if (option->short_option)
			shr_snprintf_append(buffer, sizeof(buffer), &len, ",");
	}
	if (option->short_option) {
		shr_snprintf_append(buffer, sizeof(buffer), &len, " -%c",
				    option->short_option);
		if (arg == ARGCONFIG_ARG_OPTIONAL)
			shr_snprintf_append(buffer, sizeof(buffer), &len,
					    " [<%s>]", meta);
		if (arg == ARGCONFIG_ARG_REQUIRED)
			shr_snprintf_append(buffer, sizeof(buffer), &len,
					    " <%s>", meta);
	}
	shr_snprintf_append(buffer, sizeof(buffer), &len, " ] ");

	fprintf(out, "%s", buffer);
	if (option->help) {
		shr_print_word_wrapped("--- ", 40, len, out);
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
		      struct argconfig_commandline_options *root)
{
	argconfig_print_heading(out, "Usage: %s", append_usage_str);
	fputs("\n\n", out);

	shr_print_word_wrapped(program_desc, 0, 0, out);
	fputc('\n', out);

	print_options(out, root, "Options");
}

static bool help_requested;

/* True once argconfig_parse() printed the help -h or --help asked for */
bool argconfig_help_requested(void)
{
	return help_requested;
}

static bool argconfig_is_string(enum argconfig_types type)
{
	return type == CFG_STRING || type == CFG_FILE || type == CFG_DIR;
}

/* @u is in the range of @s, if it has one */
bool argconfig_in_range(const struct argconfig_commandline_options *s,
			uint64_t u)
{
	return !s->max || (u >= s->min && u <= s->max);
}

static struct argconfig_opt_val *
argconfig_match_val(struct argconfig_opt_val *v, const char *str);

/* The bits the names in the comma-separated list @arg stand for */
static int argconfig_parse_enum_list(struct argconfig_commandline_options *s,
				     const char *arg, uint32_t *bits)
{
	__cleanup_free char *list = strdup(arg);
	struct argconfig_opt_val *v;
	char *p = list, *name;

	if (!list)
		return -ENOMEM;

	*bits = 0;
	while ((name = shr_strsep(&p, ",")) != NULL) {
		v = s->opt_val ? argconfig_match_val(s->opt_val, name) : NULL;
		if (!v)
			return -EINVAL;
		*bits |= (uint32_t)v->val.int_val;
	}

	return 0;
}

/* An unsigned number up to @max, in the range of @s */
static int argconfig_parse_u64(struct argconfig_commandline_options *s,
			       const char *arg, uint64_t max, uint64_t *u)
{
	int ret = shr_parse_u64(arg, max, u);

	if (!ret && !argconfig_in_range(s, *u))
		return -ERANGE;

	return ret;
}

static int argconfig_parse_type(struct argconfig_commandline_options *s,
				char *arg)
{
	void *value = s->default_value;
	uint64_t u;
	int64_t i;
	double d;
	int ret = 0;

	/* only a string option can do without a value */
	if (!arg && !argconfig_is_string(s->config_type) &&
	    s->config_type != CFG_FLAG && s->config_type != CFG_INCREMENT)
		return -EINVAL;

	switch (s->config_type) {
	case CFG_STRING:
	case CFG_FILE:
	case CFG_DIR:
		*(char **)value = arg;
		break;
	case CFG_INT:
		ret = shr_parse_s64(arg, INT_MIN, INT_MAX, &i);
		if (!ret)
			*(int *)value = i;
		break;
	case CFG_BYTE:
		ret = argconfig_parse_u64(s, arg, UINT8_MAX, &u);
		if (!ret)
			*(uint8_t *)value = u;
		break;
	case CFG_SHORT:
		ret = argconfig_parse_u64(s, arg, UINT16_MAX, &u);
		if (!ret)
			*(uint16_t *)value = u;
		break;
	case CFG_POSITIVE:
		ret = argconfig_parse_u64(s, arg, UINT32_MAX, &u);
		if (!ret)
			*(uint32_t *)value = u;
		break;
	case CFG_INCREMENT:
		*(int *)value += 1;
		break;
	case CFG_ENUM:
		/* only the names, which argconfig_parse_val() looked up */
		ret = -EINVAL;
		break;
	case CFG_ENUM_LIST: {
		uint32_t bits;

		ret = argconfig_parse_enum_list(s, arg, &bits);
		if (!ret)
			*(uint32_t *)value |= bits;
		break;
	}
	case CFG_LONG:
		ret = argconfig_parse_u64(s, arg, UINT64_MAX, &u);
		if (!ret)
			*(uint64_t *)value = u;
		break;
	case CFG_LONG_SUFFIX: {
		char *endptr;

		/* the suffix parser takes whitespace and a sign */
		if (!isdigit((unsigned char)*arg))
			return -EINVAL;
		ret = shr_suffix_binary_parse(arg, &endptr, &u);
		if (!ret && !argconfig_in_range(s, u))
			ret = -ERANGE;
		if (!ret)
			*(uint64_t *)value = u;
		break;
	}
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
	case CFG_FILE:
	case CFG_DIR:
		*(char **)val = opt_val->string;
		break;
	case CFG_ENUM_LIST:
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

	/* an empty value is a prefix of every name */
	if (!len)
		return NULL;

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
	/* the names of a list are looked up one by one */
	if (arg && s->config_type != CFG_ENUM_LIST &&
	    argconfig_set_value_name(s, arg))
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
	/* the table of the command, the global options included */
	struct argconfig_commandline_options root[ARGCONFIG_ROOT_LEN];
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

/*
 * The option of @root with the long name @name, a global option first: a
 * global option is the same for every command. &root[1] is the include
 * of the global options alone.
 */
static struct argconfig_commandline_options *
argconfig_find_long_any(struct argconfig_commandline_options *root,
			const char *name, size_t len)
{
	struct argconfig_commandline_options *o;

	o = argconfig_find_long(&root[1], name, len);

	return o ? o : argconfig_find_long(root, name, len);
}

static struct argconfig_commandline_options *
argconfig_find_short_any(struct argconfig_commandline_options *root, char c)
{
	struct argconfig_commandline_options *o;

	o = argconfig_find_short(&root[1], c);

	return o ? o : argconfig_find_short(root, c);
}

/* What a value of @s has to look like */
static const char *argconfig_expected(struct argconfig_commandline_options *s)
{
	static char range[64];

	if (s->max) {
		snprintf(range, sizeof(range), "a number from %" PRIu64
			 " to %" PRIu64, s->min, s->max);
		return range;
	}

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
	__cleanup_free char *e = arg ? shr_escape(arg) : NULL;
	bool list = s->config_type == CFG_ENUM_LIST;
	const struct argconfig_opt_val *v;
	int n = 0;

	print_label(command_name());
	fprintf(stderr, "invalid value '%s' for ", e ? e : "");
	if (c)
		fprintf(stderr, "-%c", c);
	else
		fprintf(stderr, "--%s", s->option);
	fprintf(stderr, ": expected ");
	if (list)
		fprintf(stderr, "a comma-separated list of ");
	else if (s->config_type != CFG_ENUM)
		fprintf(stderr, "%s%s", argconfig_expected(s),
			s->opt_val ? " or " : "");

	/* A long list of names would drown the error, the help has them */
	for (v = s->opt_val; v && v->str; v++)
		n++;
	if (n > 8)
		fprintf(stderr, "%sthe names in the help",
			list ? "" : "one of ");
	for (v = s->opt_val; n <= 8 && v && v->str; v++)
		fprintf(stderr, "%s%s", v != s->opt_val ? ", " :
			list ? "" : "one of: ", v->str);
	fprintf(stderr, "\n");

	/* "010" was octal once, say what to write instead */
	if (arg && !list && s->config_type != CFG_ENUM &&
	    shr_has_leading_zero(arg)) {
		const char *d = arg;

		while (d[0] == '0' && d[1])
			d++;
		fprintf(stderr,
			"a number must not start with 0: write %s, or 0x%s for hexadecimal\n",
			d, d);
	}

	return ARGCONFIG_USAGE;
}

/* @s given by its short name @c, or by its long name without, and @arg */
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
	if (ret == -EINVAL || ret == -ERANGE)
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

	s = argconfig_find_long_any(p->root, name, len);
	if (!s) {
		bool help = len == 4 && !strncmp(name, "help", 4);
		bool version = len == 7 && !strncmp(name, "version", 7);

		if (help && !p->global)
			return ARGCONFIG_HELP;
		if (!p->global || (!help && !version)) {
			__cleanup_free char *e = shr_escape(arg);

			return argconfig_parse_error(p,
				"unrecognized option '%s'", e ? e : "");
		}
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

		s = argconfig_find_short_any(p->root, *c);
		if (!s && p->global && (*c == 'h' || *c == 'V')) {
			p->help |= *c == 'h';
			p->version |= *c == 'V';
			continue;
		}
		if (!s) {
			char bad[2] = { *c, '\0' };
			__cleanup_free char *e = shr_escape(bad);

			return argconfig_parse_error(p,
				"invalid option -- '%s'", e ? e : "");
		}

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

	/*
	 * The global options keep theirs: they may have been given before
	 * the command name.
	 */
	argconfig_reset_seen(p->root[0].default_value);

	/* argv ends at argc or at a NULL, whichever comes first */
	for (p->ind = 1; p->ind < p->argc && p->argv[p->ind]; p->ind++) {
		arg = p->argv[p->ind];

		if (!strcmp(arg, "--")) {
			p->ind++;
			if (p->global)
				return 0;
			while (p->ind < p->argc && p->argv[p->ind])
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

/* --verbose, or an alias of it such as --human-readable, was given */
static bool argconfig_check_verbose(struct argconfig_commandline_options *root)
{
	struct argconfig_commandline_options *v;

	v = argconfig_find_long_any(root, "verbose", strlen("verbose"));
	if (!v || v->config_type != CFG_INCREMENT)
		return false;

	return given_in(root, v->default_value);
}

int argconfig_parse(int argc, char *argv[], const char *program_desc,
		    struct argconfig_commandline_options *options)
{
	static char **operand_buf;
	struct argconfig_parser p = {
		.argc = argc,
		.argv = argv,
	};
	int ret;

	argconfig_root(p.root, options);
	parse_argv0 = argc > 0 ? argv[0] : "";
	free(operand_buf);
	operand_buf = NULL;
	operands.argv = NULL;
	operands.argc = 0;

	if (argconfig_parse_hook)
		return argconfig_parse_hook(argc, argv, program_desc, p.root);

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
			show_help(stdout, program_desc, p.root);
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

	if (!argconfig_check_verbose(p.root))
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
		.global = true,
	};
	int ret;

	argconfig_root(p.root, options ? options : no_options);

	parse_argv0 = argc > 0 ? argv[0] : "";
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
	struct argconfig_commandline_options root[ARGCONFIG_ROOT_LEN];

	if (!value)
		return false;
	argconfig_root(root, s);

	return given_in(root, value);
}
