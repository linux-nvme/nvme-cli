// SPDX-License-Identifier: GPL-2.0-or-later
#include <stdio.h>

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

struct json_object *util_json_object_new_uint128(nvme_uint128_t val)
{
	struct json_object *obj;
	obj = json_object_new_string(uint128_to_string(val));
	return obj;
}
