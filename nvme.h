/*
 * Definitions for the NVM Express interface
 * Copyright (c) 2011-2014, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */

#ifndef _NVME_H
#define _NVME_H

#include <dirent.h>
#include <stdbool.h>
#include <stdint.h>
#include <endian.h>
#include <sys/time.h>

#include "plugin.h"
#ifdef LIBJSONC
#include <json-c/json.h>

#define json_create_object(o) json_object_new_object(o)
#define json_create_array(a) json_object_new_array(a)
#define json_free_object(o) json_object_put(o)
#define json_free_array(a) json_object_put(a)
#define json_object_add_value_uint(o, k, v) \
	json_object_object_add(o, k, json_object_new_int(v))
#define json_object_add_value_int(o, k, v) \
	json_object_object_add(o, k, json_object_new_int(v))
#define json_object_add_value_float(o, k, v) \
	json_object_object_add(o, k, json_object_new_double(v))
#define json_object_add_value_string(o, k, v) \
	json_object_object_add(o, k, json_object_new_string(v))
#define json_object_add_value_array(o, k, v) \
	json_object_object_add(o, k, v)
#define json_object_add_value_object(o, k, v) \
	json_object_object_add(o, k, v)
#define json_array_add_value_object(o, k) \
	json_object_array_add(o, k)
#define json_print_object(o, u)						\
	printf("%s", json_object_to_json_string_ext(o, JSON_C_TO_STRING_PRETTY))
#else
#include "util/json.h"
#endif
#include "util/argconfig.h"

enum nvme_print_flags {
	NORMAL	= 0,
	VERBOSE	= 1 << 0,	/* verbosely decode complex values for humans */
	JSON	= 1 << 1,	/* display in json format */
	VS	= 1 << 2,	/* hex dump vendor specific data areas */
	BINARY	= 1 << 3,	/* binary dump raw bytes */
};

#define SYS_NVME "/sys/class/nvme"

void register_extension(struct plugin *plugin);
int parse_and_open(int argc, char **argv, const char *desc,
	const struct argconfig_commandline_options *clo);

extern const char *devicename;
extern const char *output_format;

enum nvme_print_flags validate_output_format(const char *format);
int __id_ctrl(int argc, char **argv, struct command *cmd,
	struct plugin *plugin, void (*vs)(uint8_t *vs, struct json_object *root));
char *nvme_char_from_block(char *block);

extern int current_index;
void *nvme_alloc(size_t len, bool *huge);
void nvme_free(void *p, bool huge);

unsigned long long elapsed_utime(struct timeval start_time,
					struct timeval end_time);

/* nvme-print.c */
const char *nvme_select_to_string(int sel);

void d(unsigned char *buf, int len, int width, int group);
void d_raw(unsigned char *buf, unsigned len);
uint64_t int48_to_long(uint8_t *data);

#endif /* _NVME_H */
