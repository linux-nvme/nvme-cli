/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Helpers for the JSON printers in nvme and the plugins. A printer either
 * adds its members to the JSON document of the command (json_root()), or
 * creates its own object with obj_create() and prints it with obj_print(),
 * which adds it to the document if there is one.
 */
#pragma once

#include <stdbool.h>

#include "nvme-json.h"

#define array_add_obj json_array_add_value_object
#define array_add_str json_array_add_value_string

#define obj_add_array json_object_add_value_array
#define obj_add_bool json_object_add_value_bool
#define obj_add_int json_object_add_value_int
#define obj_add_obj json_object_add_value_object
#define obj_add_uint json_object_add_value_uint
#define obj_add_uint128 json_object_add_value_uint128
#define obj_add_uint64 json_object_add_value_uint64
#define obj_add_uint_02x json_object_add_uint_02x
#define obj_add_uint_0x json_object_add_uint_0x
#define obj_add_byte_array json_object_add_byte_array
#define obj_add_nprix64 json_object_add_nprix64
#define obj_add_uint_0nx json_object_add_uint_0nx
#define obj_add_0nprix64 json_object_add_0nprix64
#define obj_add_str json_object_add_value_string

/* JSON document of the current command, or NULL */
struct json_object *json_root(void);
/* True if verbose output (-v) was requested */
bool json_verbose_mode(void);

struct json_object *obj_create(const char *k);
void obj_print(struct json_object *o);
void obj_d(struct json_object *o, const char *k, unsigned char *buf, int len,
	   int width, int group);
void obj_add_uint_nx(struct json_object *o, const char *k, __u32 v);
void obj_add_result(struct json_object *o, const char *v, ...)
	__attribute__((format(printf, 2, 3)));
void obj_add_key(struct json_object *o, const char *k, const char *v, ...)
	__attribute__((format(printf, 3, 4)));

/* log */
void json_feature_show_fields(enum nvme_features_id fid, unsigned int result,
			      unsigned char *buf);
void json_timestamp(struct json_object *r, struct nvme_timestamp *ts);
