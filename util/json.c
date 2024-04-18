// SPDX-License-Identifier: GPL-2.0-or-later
#include <stdio.h>
#include <errno.h>

#include "json.h"
#include "types.h"

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
