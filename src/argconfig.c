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
//   Author: Logan Gunthorpe
//
//   Date:   Oct 23 2014
//
//   Description:
//     Functions for parsing command line options.
//
////////////////////////////////////////////////////////////////////////

#include "argconfig.h"
#include "suffix.h"

#include <string.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdarg.h>

#define MAX_HELP_FUNC 20
static argconfig_help_func *help_funcs[MAX_HELP_FUNC] = {NULL};

char END_DEFAULT[] = "__end_default__";

static int print_word_wrapped(const char *s, int indent, int start)
{
    const int width = 76;
    const char *c;
    int next_space = -1;
    int last_line = indent;

    for (c = s; *c != 0; c++) {
        if (*c == ' ' || next_space < 0) {
            next_space = 0;
            for (const char *t = c+1; *t != 0 && *t != ' '; t++)
                next_space++;
            if ( ((int)(c-s)+start+next_space) > (last_line-indent+width)) {
                last_line = (int) (c-s) + start;

                putchar('\n');
                for (int i = 0; i < indent; i++)
                    putchar(' ');

                start = indent;
                continue;
            }
        }

        putchar(*c);
    }

    return (int) (c - s) + start - last_line + indent;
}

const char *append_usage_str = "";

void argconfig_append_usage(const char *str)
{
    append_usage_str = str;
}

void argconfig_print_help(char *command, const char *program_desc,
                          const struct argconfig_commandline_options * options)
{
    const struct argconfig_commandline_options *s;
    const int bufsize = 120;
    char buf[bufsize];
    int  last_line, nodefault;

    printf("Usage: %s [OPTIONS] %s\n\n", command, append_usage_str);
    print_word_wrapped(program_desc, 0, 0);
    printf("\n\nOptions:\n");

    buf[0] = ' ';
    buf[1] = ' ';
    buf[2] = 0;

    for (s = options; s->option != 0; s++) {
        if (s->option[0] == '=') {
            const char *c = s->option;
            while (*c == '=') c++;
            printf("\n%s\n", c);
            continue;
        }

        strcat(buf, "-");
        strcat(buf, s->option);
        strcat(buf, " ");
        strcat(buf, s->meta);

        if (s->help == NULL) {
            strcat(buf, ", ");
            continue;
        }

        printf("%-30s", buf);
        if (strlen(buf) > 29)
            printf("%-31s", "\n");

        last_line = print_word_wrapped(s->help, 30, 30);

        nodefault = 0;
        if (s->config_type == CFG_STRING) {
            if (*((char **) s->default_value)) {
                sprintf(&buf[3], " - default: '%s'", *((char **) s->default_value));
                nodefault = strlen(*((char **) s->default_value)) == 0;
            } else {
                nodefault = 1;
            }
        } else if (s->config_type == CFG_INT || s->config_type == CFG_POSITIVE){
            sprintf(&buf[3], " - default: %d", *((int *) s->default_value));
        } else if (s->config_type == CFG_LONG){
            sprintf(&buf[3], " - default: %ld", *((long *) s->default_value));
        } else if (s->config_type == CFG_LONG_SUFFIX){
            long long val = *((long *) s->default_value);
            const char *s = suffix_binary_get(&val);
            sprintf(&buf[3], " - default: %lld%s", val, s);
        } else if (s->config_type == CFG_SIZE){
            sprintf(&buf[3], " - default: %zd", *((size_t *) s->default_value));
        } else if (s->config_type == CFG_DOUBLE){
            sprintf(&buf[3], " - default: %.2f", *((double *) s->default_value));
        } else {
            sprintf(&buf[3], " ");
        }


        if (!nodefault && s->config_type != CFG_NONE)
            print_word_wrapped(&buf[3], 30, last_line);

        putchar('\n');

        buf[2] = 0;
    }

    for (int i = 0; i < MAX_HELP_FUNC; i++) {
        if (help_funcs[i] == NULL) break;
        putchar('\n');
        help_funcs[i]();
    }

    putchar('\n');
}

int argconfig_parse(int argc, char *argv[], const char *program_desc,
                    const struct argconfig_commandline_options *options,
                    const void *config_default, void *config_out,
                    size_t config_size)
{
    int c;
    int option_index = 0, short_index = 0;
    int options_count = 0;
    struct option *long_opts;
    char * short_opts;
    const struct argconfig_commandline_options *s;
    void *value_addr;

    errno = 0;

    memcpy(config_out, config_default, config_size);

    for (s = options; s->option != 0; s++)
        options_count++;

    long_opts = malloc(sizeof(struct option)* (options_count + 1));
    short_opts = malloc(sizeof(*short_opts) * (options_count*2 + 2));
    short_opts[short_index++] = '-';

    if (long_opts == NULL) {
        fprintf(stderr,  "Unable to allocate memory!\n");
        exit(1);
    }

    for (s = options; s->option != 0; s++) {
        if (strlen(s->option) == 1) {
            short_opts[short_index++] = s->option[0];
            if (s->argument_type == required_argument) {
                short_opts[short_index++] = ':';
            }
        }

        long_opts[option_index].name    = s->option;
        long_opts[option_index].has_arg = s->argument_type;
        if (s->argument_type == no_argument &&
            s->default_value != NULL)
        {
            value_addr = (void *) ((char *) s->default_value -
                                   (char *) config_default +
                                   (char *) config_out);
            long_opts[option_index].flag    = value_addr;
            long_opts[option_index].val     = 1;
        } else {
            long_opts[option_index].flag    = NULL;
            long_opts[option_index].val     = 0;
        }
        option_index++;
    }
    long_opts[option_index].name = NULL;
    long_opts[option_index].flag = NULL;
    long_opts[option_index].val  = 0;
    short_opts[short_index] = 0;

    int non_opt_args = 0;

    while ((c = getopt_long_only(argc, argv, short_opts, long_opts,
                                 &option_index)) != -1)
    {
        if (c == '?' || c == 'h' || c == ':' ||
            (c == 0 &&
             (!strcmp(long_opts[option_index].name, "h") ||
              !strcmp(long_opts[option_index].name, "help") ||
              !strcmp(long_opts[option_index].name, "-help"))))
        {
            argconfig_print_help(argv[0], program_desc, options);
            exit(1);
        } else if (c == 1) {
            argv[1+non_opt_args] = optarg;
            non_opt_args++;
            continue;
        } else if (c){
            for (option_index = 0; options[option_index].option[0] != c ||
                 options[option_index].option[1] != 0; option_index++);
            if (long_opts[option_index].flag != NULL)
                *long_opts[option_index].flag = 1;
        }

        s = &options[option_index];
        while(s->default_value == NULL) s++;
        value_addr = (void *) ((char *) s->default_value -
                               (char *) config_default +
                               (char *) config_out);


        if (s->config_type == CFG_STRING) {
            *((char **) value_addr) = optarg;
        } else if (s->config_type == CFG_SIZE) {
            *((size_t *) value_addr) = strtol(optarg, NULL, 0);
            if (errno) {
                fprintf(stderr, "Expected integer argument for '%s' but got '%s'!\n",
                        long_opts[option_index].name, optarg);
                exit(1);
            }
        } else if (s->config_type == CFG_INT) {
            *((int *) value_addr) = strtol(optarg, NULL, 0);
            if (errno) {
                fprintf(stderr, "Expected integer argument for '%s' but got '%s'!\n",
                        long_opts[option_index].name, optarg);
                exit(1);
            }
        } else if (s->config_type == CFG_BOOL) {
            int tmp = strtol(optarg, NULL, 0);
            if (errno || tmp < 0 || tmp > 1) {
                fprintf(stderr, "Expected 0 or 1 argument for '%s' but got '%s'!\n",
                        long_opts[option_index].name, optarg);
                exit(1);
            }
            *((int *) value_addr) = tmp;
        } else if (s->config_type == CFG_POSITIVE) {
            int tmp = strtol(optarg, NULL, 0);
            if (errno || tmp < 0) {
                fprintf(stderr, "Expected positive argument for '%s' but got '%s'!\n",
                        long_opts[option_index].name, optarg);
                exit(1);
            }
            *((int *) value_addr) = tmp;
        } else if (s->config_type == CFG_INCREMENT) {
            (*((int *) value_addr))++;
        } else if (s->config_type == CFG_LONG) {
            *((long *) value_addr) = strtol(optarg, NULL, 0);
            if (errno) {
                fprintf(stderr, "Expected long integer argument for '%s' but got '%s'!\n",
                        long_opts[option_index].name, optarg);
                exit(1);
            }
        } else if (s->config_type == CFG_LONG_SUFFIX) {
            *((long *) value_addr) = suffix_binary_parse(optarg);
            if (errno) {
                fprintf(stderr, "Expected long suffixed integer argument for '%s' but got '%s'!\n",
                        long_opts[option_index].name, optarg);
                exit(1);
            }
        } else if (s->config_type == CFG_DOUBLE) {
            *((double *) value_addr) = strtod(optarg, NULL);
            if (errno) {
                fprintf(stderr, "Expected float argument for '%s' but got '%s'!\n",
                        long_opts[option_index].name, optarg);
                exit(1);
            }
        } else if (s->config_type == CFG_SUBOPTS) {
            char **opts = ((char **) value_addr);
            int remaining_space = CFG_MAX_SUBOPTS;
            int enddefault = 0;
            while (0 && *opts != NULL) {
                if (*opts == END_DEFAULT)
                    enddefault = 1;
                remaining_space--;
                opts++;
            }

            if (!enddefault) {
                *opts = END_DEFAULT;
                remaining_space -= 2;
                opts += 2;
            }

            int r = argconfig_parse_subopt_string(optarg, opts, remaining_space);
            if (r == 2) {
                fprintf(stderr, "Error Parsing Sub-Options: Too many options!\n");
                exit(1);
            } else if (r) {
                fprintf(stderr, "Error Parsing Sub-Options\n");
                exit(1);
            }
        } else if (s->config_type == CFG_FILE_A ||
                   s->config_type == CFG_FILE_R ||
                   s->config_type == CFG_FILE_W ||
                   s->config_type == CFG_FILE_AP ||
                   s->config_type == CFG_FILE_RP ||
                   s->config_type == CFG_FILE_WP)
        {
            const char *fopts = "";
            if (s->config_type == CFG_FILE_A)
                fopts = "a";
            else if (s->config_type == CFG_FILE_R)
                fopts = "r";
            else if (s->config_type == CFG_FILE_W)
                fopts = "w";
            else if (s->config_type == CFG_FILE_AP)
                fopts = "a+";
            else if (s->config_type == CFG_FILE_RP)
                fopts = "r+";
            else if (s->config_type == CFG_FILE_WP)
                fopts = "w+";

            FILE *f = fopen(optarg, fopts);
            if (f == NULL) {
                fprintf(stderr, "Unable to open %s file: %s\n", s->option,
                        optarg);
                exit(1);
            }

            *((FILE **) value_addr) = f;
        }
    }

    free(short_opts);
    free(long_opts);

    for (int i = optind; i < argc; i++) {
        argv[1+non_opt_args] = argv[i];
        non_opt_args++;
    }

    return non_opt_args;
}


int argconfig_parse_subopt_string (char *string, char **options,
                                   size_t max_options)
{
    char **o = options;
    char *tmp;

    if (!strlen(string) || string == NULL) {
        *(o++) = NULL;
        *(o++) = NULL;
        return 0;
    }

    tmp = calloc(strlen(string)+2, 1);
    if (tmp == NULL) {
        fprintf(stderr,  "Unable to allocate memory!\n");
        exit(1);
    }
    strcpy(tmp, string);

    size_t toklen;
    toklen = strcspn(tmp, "=");
    if (!toklen) return 1;
    *(o++) = tmp;
    tmp[toklen] = 0;
    tmp += toklen + 1;


    while (1) {
        if (*tmp == '"' || *tmp == '\'' || *tmp == '[' || *tmp == '(' ||
            *tmp == '{') {

            tmp++;
            toklen = strcspn(tmp, "\"'])}");

            if (!toklen) return 1;
            *(o++) = tmp;
            tmp[toklen] = 0;
            tmp += toklen + 1;

            toklen = strcspn(tmp, ";:,");
            tmp[toklen] = 0;
            tmp += toklen + 1;
        } else {
            toklen = strcspn(tmp, ";:,");
            if (!toklen) return 1;
            *(o++) = tmp;
            tmp[toklen] = 0;
            tmp += toklen + 1;
        }


        toklen = strcspn(tmp, "=");
        if (!toklen) break;
        *(o++) = tmp;
        tmp[toklen] = 0;
        tmp += toklen + 1;

        if ((o - options) > (max_options-2))
            return 2;
    }

    *(o++) = NULL;
    *(o++) = NULL;

    return 0;
}

unsigned argconfig_parse_comma_sep_array(char *string,int *val,unsigned max_length)
{
  unsigned ret = 0;
  char *tmp;
  char *p;

  if (!strlen(string) || string == NULL)
    return -1;

  tmp = malloc(strlen(string)+1);
  if (tmp==NULL) {
    fprintf(stderr,  "Unable to allocate memory!\n");
    exit(1);}

  tmp = strtok(string,",");
  if (tmp==NULL)
    return -1;

  val[ret] = strtol(tmp,&p,0);
  if (*p!=0)
    return -1;
  ret++;

  while(1) {
    tmp = strtok(NULL,",");
    if (tmp==NULL)
      return ret;
    if (ret>=max_length)
      return -1;
    val[ret] = strtol(tmp,&p,0);
    if (*p!=0)
      return -1;
    ret++;
    }

}

unsigned argconfig_parse_comma_sep_arrayd(char *string,double *val,unsigned max_length)
{
  unsigned ret = 0;
  char *tmp;
  char *p;

  if (!strlen(string) || string == NULL)
    return -1;

  tmp = malloc(strlen(string)+1);
  if (tmp==NULL) {
    fprintf(stderr,  "Unable to allocate memory!\n");
    exit(1);}

  tmp = strtok(string,",");
  if (tmp==NULL)
    return -1;

  val[ret] = strtod(tmp,&p);
  if (*p!=0)
    return -1;
  ret++;

  while(1) {
    tmp = strtok(NULL,",");
    if (tmp==NULL)
      return ret;
    if (ret>=max_length)
      return -1;
    val[ret] = strtod(tmp,&p);
    if (*p!=0)
      return -1;
    ret++;
    }

}

void argconfig_register_help_func(argconfig_help_func * f) {
    for (int i = 0; i < MAX_HELP_FUNC; i++) {
        if (help_funcs[i] == NULL) {
            help_funcs[i] = f;
            help_funcs[i+1] = NULL;
            break;
        }
    }
}

void argconfig_print_subopt_help(const struct argconfig_sub_options * options,
                                 int indent)
{
    const struct argconfig_sub_options *s;
    const int bufsize = 120;
    char buf[bufsize];
    int  last_line, nodefault;

    buf[0] = ' ';
    buf[1] = ' ';
    buf[2] = 0;

    for (s = options; s->option != 0; s++) {
        if (s->option[0] == '=') {
            const char *c = s->option;
            while (*c == '=') c++;
            printf("\n%*s%s", indent, "", c);
            continue;
        }

        strcat(buf, s->option);
        strcat(buf, "=");
        strcat(buf, s->meta);

        if (s->help == NULL) {
            strcat(buf, ", ");
            continue;
        }

        printf("%*s%-*s", indent, "", 30-indent, buf);
        if (strlen(buf) > 29-indent)
            printf("%-31s", "\n");

        last_line = print_word_wrapped(s->help, 30-indent, 30-indent);

        nodefault = 0;
        if (s->config_type == CFG_STRING) {
            sprintf(&buf[3], " - default: '%s'", *((char **) s->default_value));
            nodefault = strlen(*((char **) s->default_value)) == 0;
        } else if (s->config_type == CFG_INT || s->config_type == CFG_BOOL){
            sprintf(&buf[3], " - default: %d", *((int *) s->default_value));
        } else if (s->config_type == CFG_LONG){
            sprintf(&buf[3], " - default: %ld", *((long *) s->default_value));
        } else if (s->config_type == CFG_LONG_SUFFIX){
            long long val = *((long *) s->default_value);
            const char *s = suffix_binary_get(&val);
            sprintf(&buf[3], " - default: %lld%s", val, s);
        } else if (s->config_type == CFG_SIZE){
            sprintf(&buf[3], " - default: %zd", *((size_t *) s->default_value));
        } else if (s->config_type == CFG_DOUBLE){
            sprintf(&buf[3], " - default: %.2f", *((double *) s->default_value));
        } else {
            sprintf(&buf[3], " ");
        }


        if (!nodefault && s->config_type != CFG_NONE)
            print_word_wrapped(&buf[3], 30, last_line);

        putchar('\n');

        buf[2] = 0;
    }
}

void argconfig_parse_subopt(char * const opts[], const char *module,
                            const struct argconfig_sub_options *options,
                            const void *config_default, void *config_out,
                            size_t config_size)
{
    memcpy(config_out, config_default, config_size);
    int enddefault = 0;

    const struct argconfig_sub_options *s;
    errno = 0;

    for (char * const *o = opts; o != NULL && *o != NULL; o += 2) {
        if (*o == END_DEFAULT) {
            enddefault = 1;
            continue;
        }

        for (s = options; s->option != NULL; s++)
            if (strcmp(o[0], s->option) == 0)
                break;

        if (s->option == NULL && enddefault) {
            fprintf(stderr, "%s: Invalid option '%s'.\n", module, o[0]);
        } else if (s->option == NULL) {
            continue;
        }

        void *value_addr = (void *) ((char *) s->default_value -
                                     (char *) config_default +
                                     (char *) config_out);

        if (s->config_type == CFG_STRING) {
            *((char **) value_addr) = o[1];
        } else if (s->config_type == CFG_INT) {
            *((int *) value_addr) = (int) strtol(o[1], NULL, 0);
        } else if (s->config_type == CFG_SIZE) {
            *((size_t *) value_addr) = (size_t) strtol(o[1], NULL, 0);
        } else if (s->config_type == CFG_LONG) {
            *((long *) value_addr) = strtol(o[1], NULL, 0);
        } else if (s->config_type == CFG_LONG_SUFFIX) {
            *((long *) value_addr) = suffix_binary_parse(o[1]);
        } else if (s->config_type == CFG_DOUBLE) {
            *((double *) value_addr) = strtod(o[1], NULL);
        } else if (s->config_type == CFG_BOOL) {
            int tmp = strtol(o[1], NULL, 0);
            if (tmp < 0 || tmp > 1) errno = 1;
            *((int *) value_addr) = (int) tmp;
        } else if (s->config_type == CFG_POSITIVE) {
            int tmp = strtol(o[1], NULL, 0);
            if (tmp < 0) errno = 1;
            *((int *) value_addr) = (int) tmp;
        } else if (s->config_type == CFG_FILE_A ||
                   s->config_type == CFG_FILE_R ||
                   s->config_type == CFG_FILE_W ||
                   s->config_type == CFG_FILE_AP ||
                   s->config_type == CFG_FILE_RP ||
                   s->config_type == CFG_FILE_WP)
        {
            const char *fopts = "";
            if (s->config_type == CFG_FILE_A)
                fopts = "a";
            else if (s->config_type == CFG_FILE_R)
                fopts = "r";
            else if (s->config_type == CFG_FILE_W)
                fopts = "w";
            else if (s->config_type == CFG_FILE_AP)
                fopts = "a+";
            else if (s->config_type == CFG_FILE_RP)
                fopts = "r+";
            else if (s->config_type == CFG_FILE_WP)
                fopts = "w+";

            FILE *f = fopen(o[1], fopts);
            if (f == NULL) {
                fprintf(stderr, "Unable to open %s file: %s\n", s->option,
                        o[1]);
                exit(1);
            }

            *((FILE **) value_addr) = f;
        }


        if (errno) {
            fprintf(stderr, "%s: Invalid value '%s' for option '%s'.\n", module,
                    o[1], o[0]);
            exit(1);
        }
    }

}

int argconfig_set_subopt(const char *opt,
                         const struct argconfig_sub_options *options,
                         const void *config_default, void *config_out, va_list argp)
{
    const struct argconfig_sub_options *s;
    for (s = options; s->option != NULL; s++)
        if (strcmp(opt, s->option) == 0)
            break;

    if (s->option == NULL)
        return 1;

    void *value_addr = (void *) ((char *) s->default_value -
                                 (char *) config_default +
                                 (char *) config_out);

    if (s->config_type == CFG_STRING) {
        *((char **) value_addr) = va_arg(argp, char *);
    } else if (s->config_type == CFG_INT ||
               s->config_type == CFG_BOOL ||
               s->config_type == CFG_POSITIVE)
    {
        *((int *) value_addr) = va_arg(argp, int);
    } else if (s->config_type == CFG_SIZE) {
        *((size_t *) value_addr) = va_arg(argp, size_t);
    } else if (s->config_type == CFG_LONG) {
        *((long *) value_addr) = va_arg(argp, long);
    } else if (s->config_type == CFG_LONG_SUFFIX) {
        *((long *) value_addr) = va_arg(argp, long);
    } else if (s->config_type == CFG_DOUBLE) {
        *((double *) value_addr) = va_arg(argp, double);
    } else if (s->config_type == CFG_FILE_A ||
               s->config_type == CFG_FILE_R ||
               s->config_type == CFG_FILE_W ||
               s->config_type == CFG_FILE_AP ||
               s->config_type == CFG_FILE_RP ||
               s->config_type == CFG_FILE_WP)
    {

        *((FILE **) value_addr) = va_arg(argp, FILE *);
    }

    return 0;
}


int argconfig_get_subopt(const char *opt,
                         const struct argconfig_sub_options *options,
                         const void *config_default, void *config_out, va_list argp)
{
    const struct argconfig_sub_options *s;
    for (s = options; s->option != NULL; s++)
        if (strcmp(opt, s->option) == 0)
            break;

    if (s->option == NULL)
        return 1;

    void *value_addr = (void *) ((char *) s->default_value -
                                 (char *) config_default +
                                 (char *) config_out);

    if (s->config_type == CFG_STRING) {
        *va_arg(argp, char **) = *((char **) value_addr);
    } else if (s->config_type == CFG_INT ||
               s->config_type == CFG_BOOL ||
               s->config_type == CFG_POSITIVE)
    {
        *va_arg(argp, int *) = *((int *) value_addr);
    } else if (s->config_type == CFG_SIZE) {
        *va_arg(argp, size_t *) = *((size_t *) value_addr);
    } else if (s->config_type == CFG_LONG) {
        *va_arg(argp, long *) = *((long *) value_addr);
    } else if (s->config_type == CFG_LONG_SUFFIX) {
        *va_arg(argp, long *) = *((long *) value_addr);
    } else if (s->config_type == CFG_DOUBLE) {
        *va_arg(argp, double *) = *((double *) value_addr);
    } else if (s->config_type == CFG_FILE_A ||
               s->config_type == CFG_FILE_R ||
               s->config_type == CFG_FILE_W ||
               s->config_type == CFG_FILE_AP ||
               s->config_type == CFG_FILE_RP ||
               s->config_type == CFG_FILE_WP)
    {
        *va_arg(argp, FILE **) = *((FILE **) value_addr);
    }

    return 0;
}
