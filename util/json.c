// SPDX-License-Identifier: GPL-2.0-or-later
#include <stdio.h>
#include <errno.h>
#include <stdarg.h>

#include "json.h"
#include "types.h"
#include "cleanup.h"

struct json_object *util_json_object_new_double(long double d)
{
	struct json_object *obj;
	char *str;

	if (asprintf(&str, "%Lf", d) < 0)
		return NULL;

	obj = json_object_new_string(str);

	free(str);
	return obj;

}

struct json_object *util_json_object_new_uint64(uint64_t i)
{
	struct json_object *obj;
	char *str;

	if (asprintf(&str, "%" PRIu64, i) < 0)
		return NULL;

	obj = json_object_new_string(str);

	free(str);
	return obj;

}

static int util_json_object_string_to_number(struct json_object *jso,
					     struct printbuf *pb, int level,
					     int flags)
{
	ssize_t len = json_object_get_string_len(jso);

	printbuf_memappend(pb, json_object_get_string(jso), len);

	return 0;
}

struct json_object *util_json_object_new_uint128(nvme_uint128_t  val)
{
	struct json_object *obj;

	obj = json_object_new_string(uint128_t_to_string(val));
	json_object_set_serializer(obj, util_json_object_string_to_number, NULL, NULL);

	return obj;
}

uint64_t util_json_object_get_uint64(struct json_object *obj)
{
	uint64_t val = 0;

	if (json_object_is_type(obj, json_type_string)) {
		char *end = NULL;
		const char *buf;

		buf = json_object_get_string(obj);
		val = strtoull(buf, &end, 10);
		if ((val == 0 && errno != 0) || (end == buf))
			return 0;
	}

	return val;
}

void json_object_add_uint_02x(struct json_object *o, const char *k, __u32 v)
{
	json_object_add_uint_0nx(o, k, v, 2);
}

void json_object_add_uint_0x(struct json_object *o, const char *k, __u32 v)
{
	char str[STR_LEN];

	sprintf(str, "0x%x", v);
	json_object_add_value_string(o, k, str);
}

void json_object_add_byte_array(struct json_object *o, const char *k, unsigned char *buf, int len)
{
	int i;

	_cleanup_free_ char *value = NULL;

	if (!buf || !len) {
		json_object_add_value_string(o, k, "No information provided");
		return;
	}

	value = calloc(1, (len + 1) * 2 + 1);

	if (!value) {
		json_object_add_value_string(o, k, "Could not allocate string");
		return;
	}

	sprintf(value, "0x");
	for (i = 1; i <= len; i++)
		sprintf(&value[i * 2], "%02x", buf[len - i]);

	json_object_add_value_string(o, k, value);
}

void json_object_add_nprix64(struct json_object *o, const char *k, uint64_t v)
{
	char str[STR_LEN];

	sprintf(str, "%#"PRIx64"", v);
	json_object_add_value_string(o, k, str);
}

void json_object_add_uint_0nx(struct json_object *o, const char *k, __u32 v, int width)
{
	char str[STR_LEN];

	sprintf(str, "0x%0*x", width, v);
	json_object_add_value_string(o, k, str);
}

void json_object_add_0nprix64(struct json_object *o, const char *k, uint64_t v, int width)
{
	char str[STR_LEN];

	sprintf(str, "0x%0*"PRIx64"", width, v);
	json_object_add_value_string(o, k, str);
}

void json_object_add_string(struct json_object *o, const char *k, const char *format, ...)
{
	_cleanup_free_ char *value = NULL;
	va_list ap;

	va_start(ap, format);

	if (vasprintf(&value, format, ap) < 0)
		value = NULL;

	json_object_add_value_string(o, k, value ? value : "Could not allocate string");

	va_end(ap);
}
