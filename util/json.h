/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __JSON__H
#define __JSON__H

#ifdef CONFIG_JSONC
#include <json.h>
#include "util/types.h"

/* Wrappers around json-c's API */

#define json_create_object(o) json_object_new_object(o)
#define json_create_array(a) json_object_new_array(a)
#define json_free_object(o) json_object_put(o)
#define json_free_array(a) json_object_put(a)
#define json_object_add_value_uint(o, k, v) \
	json_object_object_add(o, k, json_object_new_uint64(v))
#define json_object_add_value_int(o, k, v) \
	json_object_object_add(o, k, json_object_new_int(v))
#ifndef CONFIG_JSONC_14
#define json_object_new_uint64(v) util_json_object_new_uint64(v)
#define json_object_get_uint64(v) util_json_object_get_uint64(v)
#endif
#define json_object_add_value_uint64(o, k, v) \
	json_object_object_add(o, k, json_object_new_uint64(v))
#define json_object_add_value_uint128(o, k, v) \
	json_object_object_add(o, k, util_json_object_new_uint128(v))
#define json_object_add_value_double(o, k, v) \
	json_object_object_add(o, k, util_json_object_new_double(v))
#define json_object_add_value_float(o, k, v) \
	json_object_object_add(o, k, json_object_new_double(v))
static inline int json_object_add_value_string(struct json_object *o, const char *k, const char *v) {
	return json_object_object_add(o, k, v ? json_object_new_string(v) : NULL);
}
#define json_object_add_value_array(o, k, v) \
	json_object_object_add(o, k, v)
#define json_object_add_value_object(o, k, v) \
	json_object_object_add(o, k, v)
#define json_array_add_value_object(o, k) \
	json_object_array_add(o, k)
static inline int json_array_add_value_string(struct json_object *o, const char *v) {
	return json_object_array_add(o, v ? json_object_new_string(v) : NULL);
}
#define json_print_object(o, u)						\
	printf("%s", json_object_to_json_string_ext(o,			\
		JSON_C_TO_STRING_PRETTY |				\
		JSON_C_TO_STRING_NOSLASHESCAPE))

struct json_object *util_json_object_new_double(long double d);
struct json_object *util_json_object_new_uint64(uint64_t i);
struct json_object *util_json_object_new_uint128(nvme_uint128_t val);
struct json_object *util_json_object_new_uint128(nvme_uint128_t val);

uint64_t util_json_object_get_uint64(struct json_object *obj);

#else /* !CONFIG_JSONC */

struct json_object;

#endif

#endif
