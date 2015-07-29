////////////////////////////////////////////////////////////////////////
//
// Copyright 2014 PMC-Sierra, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you
// may not use this file except in compliance with the License. You may
// obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0 Unless required by
// applicable law or agreed to in writing, software distributed under the
// License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
// CONDITIONS OF ANY KIND, either express or implied. See the License for
// the specific language governing permissions and limitations under the
// License.
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
			  const char *options_list);
int argconfig_parse(int argc, char *argv[], const char *program_desc,
		    const char *options_list,
                    const struct argconfig_commandline_options *options,
		    const unsigned int opt_arr_len, const void *config_default,
		    void *config_out, size_t config_size);
int argconfig_parse_subopt_string (char *string, char **options,
                                size_t max_options);
unsigned argconfig_parse_comma_sep_array(char *string,int *ret,
				      unsigned max_length);
void argconfig_register_help_func(argconfig_help_func * f);

void argconfig_print_subopt_help(const struct argconfig_sub_options * options,
                              int indent);

int argconfig_parse_subopt(char * const opts[], const char *module,
			   const char *program_desc, const char *options_list,
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
