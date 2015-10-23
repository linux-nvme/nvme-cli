////////////////////////////////////////////////////////////////////////
//
// Copyright 2014 PMC-Sierra, Inc.
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//
////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////
//
//   Author: Logan Gunthorpe <logang@deltatee.com>
//           Logan Gunthorpe
//
//   Date:   Oct 23 2014
//
//   Description:
//     Header file for argconfig.c
//
////////////////////////////////////////////////////////////////////////

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

//Deprecated
#define NO_DEFAULT     CFG_NONE
#define DEFAULT_STRING CFG_STRING
#define DEFAULT_INT    CFG_INT
#define DEFAULT_SIZE   CFG_SIZE
#define DEFAULT_DOUBLE CFG_DOUBLE

struct argconfig_commandline_options {
    const char *option;
    const char *meta;
    enum argconfig_types config_type;
    const void *default_value;
    int        argument_type;
    const char *help;
};

#define CFG_MAX_SUBOPTS 500
#define MAX_HELP_FUNC 20

struct argconfig_sub_options {
    const char *option;
    const char *meta;
    enum argconfig_types config_type;
    const void *default_value;
    const char *help;
};


#ifdef __cplusplus
extern "C" {
#endif


typedef void argconfig_help_func();
void argconfig_append_usage(const char *str);
void argconfig_print_help(char *command, const char *program_desc,
			  const struct argconfig_commandline_options *options);
int argconfig_parse(int argc, char *argv[], const char *program_desc,
                    const struct argconfig_commandline_options *options,
		    const void *config_default, void *config_out, size_t config_size);
int argconfig_parse_subopt_string (char *string, char **options,
                                size_t max_options);
unsigned argconfig_parse_comma_sep_array(char *string,int *ret,
				      unsigned max_length);
unsigned argconfig_parse_comma_sep_array_long(char *string, unsigned long long *ret,
				      unsigned max_length);
void argconfig_register_help_func(argconfig_help_func * f);

void argconfig_print_subopt_help(const struct argconfig_sub_options * options,
                              int indent);

void argconfig_parse_subopt(char * const opts[], const char *module,
			   const struct argconfig_sub_options *options,
                           const void *config_default, void *config_out,
                           size_t config_size);

int argconfig_set_subopt(const char *opt,
                         const struct argconfig_sub_options *options,
                         const void *config_default, void *config_out, va_list arg);
int argconfig_get_subopt(const char *opt,
                         const struct argconfig_sub_options *options,
                         const void *config_default, void *config_out, va_list arg);

#ifdef __cplusplus
}
#endif


#endif
