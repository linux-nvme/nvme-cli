/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __JSON__H
#define __JSON__H

#ifdef CONFIG_JSONC
#include <json.h>
#include "util/types.h"

/* Wrappers around json-c's API */

#define json_create_object(o) json_object_new_object(o)
#define json_free_object(o) json_object_put(o)
#define json_free_array(a) json_object_put(a)
#define json_object_add_value_uint(o, k, v) json_object_object_add(o, k, json_object_new_uint64(v))
#define json_object_add_value_int(o, k, v) json_object_object_add(o, k, json_object_new_int(v))
#ifndef CONFIG_JSONC_14
#define json_object_new_uint64(v) util_json_object_new_uint64(v)
#define json_object_get_uint64(v) util_json_object_get_uint64(v)
#endif /* CONFIG_JSONC_14 */
#define json_object_add_value_uint64(o, k, v) \
	json_object_object_add(o, k, json_object_new_uint64(v))
#define json_object_add_value_uint128(o, k, v) \
	json_object_object_add(o, k, util_json_object_new_uint128(v))
#define json_object_add_value_double(o, k, v) \
	json_object_object_add(o, k, util_json_object_new_double(v))
#define json_object_add_value_float(o, k, v) json_object_object_add(o, k, json_object_new_double(v))

static inline int json_object_add_value_string(struct json_object *o, const char *k, const char *v)
{
	return json_object_object_add(o, k, v ? json_object_new_string(v) : NULL);
}

#define json_array_add_value_object(o, k) json_object_array_add(o, k)

static inline int json_array_add_value_string(struct json_object *o, const char *v)
{
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
#else /* CONFIG_JSONC */
struct json_object;

#define json_object_add_value_string(o, k, v)
#define json_create_object(o) NULL
#define json_free_object(o) ((void)(o))
#define json_object_add_value_uint(o, k, v) ((void)(v))
#define json_object_add_value_int(o, k, v) ((void)(v))
#define json_object_add_value_uint64(o, k, v) ((void)(v))
#define json_object_add_value_uint128(o, k, v)
#define json_object_add_value_double(o, k, v)
#define json_object_add_value_float(o, k, v)
#define json_array_add_value_object(o, k) ((void)(k))
#define json_print_object(o, u) ((void)(o))
#define json_object_object_add(o, k, v) ((void)(v))
#define json_object_new_int(v)
#define json_object_new_array(a) NULL
#define json_object_array_add(o, k) ((void)(k))
#endif /* CONFIG_JSONC */

#define json_create_array(a) json_object_new_array(a)
#define json_object_add_value_array(o, k, v) json_object_object_add(o, k, v)
#define json_object_add_value_object(o, k, v) json_object_object_add(o, k, v)

void json_object_add_uint_02x(struct json_object *o, const char *k, __u32 v);
void json_object_add_uint_0x(struct json_object *o, const char *k, __u32 v);
void json_object_add_byte_array(struct json_object *o, const char *k, unsigned char *buf, int len);
void json_object_add_nprix64(struct json_object *o, const char *k, uint64_t v);
void json_object_add_uint_0nx(struct json_object *o, const char *k, __u32 v, int width);
void json_object_add_0nprix64(struct json_object *o, const char *k, uint64_t v, int width);
void json_object_add_string(struct json_object *o, const char *k, const char *format, ...);

#endif /* __JSON__H */
