// SPDX-License-Identifier: GPL-2.0-or-later
#include <stdio.h>
#include <string.h>

#include "json.h"

struct json_object *util_json_object_new_double(long double d)
{
	struct json_object *obj;
	char *str;

	if (asprintf(&str, "%Lf", d) < 0)
		return NULL;

	for (int i = strlen(str) - 1; i > 0; i--) {	/* Remove trailing zeros */
		if (str[i] == '.') {
			str[i] = '\0';
			break;
		} else if (str[i] != '0') {
			str[i+1] = '\0';
			break;
		}
	}

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

struct json_object *util_json_object_new_uint128(__uint128_t  val)
{
	struct json_object *obj;
	obj = json_object_new_string(uint128_t_to_string(val));
	return obj;
}

char str_uint128[40];
char *uint128_t_to_string(__uint128_t val)
{
	char str_rev[40]; /* __uint128_t  maximum string length is 39 */
	int i, j;

	for (i = 0; val > 0; i++) {
		str_rev[i] = (val % 10) + 48;
		val /= 10;
	}

	for (j = 0; i >= 0;) {
		str_uint128[j++] = str_rev[--i];
	}
	str_uint128[j] = '\0';

	return str_uint128;
}
