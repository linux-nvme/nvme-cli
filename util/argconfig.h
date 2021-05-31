/*
 *
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
 *   Author: Logan Gunthorpe <logang@deltatee.com>
 *           Logan Gunthorpe
 *
 *   Date:   Oct 23 2014
 *
 *   Description:
 *     Header file for argconfig.c
 *
 */

#ifndef argconfig_H
#define argconfig_H

#include <string.h>
#include <getopt.h>
#include <stdarg.h>

enum argconfig_types {
	CFG_NONE,
	CFG_STRING,
	CFG_INT,
	CFG_SIZE,
	CFG_LONG,
	CFG_LONG_SUFFIX,
	CFG_DOUBLE,
	CFG_BOOL,
	CFG_BYTE,
	CFG_SHORT,
	CFG_POSITIVE,
	CFG_INCREMENT,
	CFG_SUBOPTS,
	CFG_FILE_A,
	CFG_FILE_W,
	CFG_FILE_R,
	CFG_FILE_AP,
	CFG_FILE_WP,
	CFG_FILE_RP,
};

#define OPT_ARGS(n) \
	const struct argconfig_commandline_options n[]

#define OPT_END() { NULL }

#define OPT_FLAG(l, s, v, d) \
	{l, s, NULL, CFG_NONE, v, no_argument, d}

#define OPT_SUFFIX(l, s, v, d) \
	{l, s, "IONUM", CFG_LONG_SUFFIX, v, required_argument, d}

#define OPT_LONG(l, s, v, d) \
	{l, s, "NUM", CFG_LONG, v, required_argument, d}

#define OPT_UINT(l, s, v, d) \
	{l, s, "NUM", CFG_POSITIVE, v, required_argument, d}

#define OPT_INT(l, s, v, d) \
	{l, s, "NUM", CFG_INT, v, required_argument, d}

#define OPT_LONG(l, s, v, d) \
	{l, s, "NUM", CFG_LONG, v, required_argument, d}

#define OPT_DOUBLE(l, s, v, d) \
	{l, s, "NUM", CFG_DOUBLE, v, required_argument, d}

#define OPT_BYTE(l, s, v, d) \
	{l, s, "NUM", CFG_BYTE, v, required_argument, d}

#define OPT_SHRT(l, s, v, d) \
	{l, s, "NUM", CFG_SHORT, v, required_argument, d}

#define OPT_STRING(l, s, m, v, d) \
	{l, s, m, CFG_STRING, v, required_argument, d}

#define OPT_FMT(l, s, v, d)  OPT_STRING(l, s, "FMT", v, d)
#define OPT_FILE(l, s, v, d) OPT_STRING(l, s, "FILE", v, d)
#define OPT_LIST(l, s, v, d) OPT_STRING(l, s, "LIST", v, d)

struct argconfig_commandline_options {
	const char *option;
	const char short_option;
	const char *meta;
	enum argconfig_types config_type;
	void *default_value;
	int argument_type;
	const char *help;
};

#define CFG_MAX_SUBOPTS 500
#define MAX_HELP_FUNC 20

typedef void argconfig_help_func();
void argconfig_append_usage(const char *str);
void argconfig_print_help(const char *program_desc,
			  const struct argconfig_commandline_options *options);
int argconfig_parse(int argc, char *argv[], const char *program_desc,
		    const struct argconfig_commandline_options *options);
int argconfig_parse_subopt_string(char *string, char **options,
				  size_t max_options);
int argconfig_parse_comma_sep_array(char *string, int *ret,
					 unsigned max_length);
int argconfig_parse_comma_sep_array_long(char *string,
					      unsigned long long *ret,
					      unsigned max_length);
void argconfig_register_help_func(argconfig_help_func * f);

void print_word_wrapped(const char *s, int indent, int start);
#endif
