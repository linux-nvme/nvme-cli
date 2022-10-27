// SPDX-License-Identifier: MIT
/*
 * Copyright (c) 2022 Solidigm.
 *
 * Author: leonardo.da.cunha@solidigm.com
 */
#include <stdbool.h>
#include "util/json.h"
#include <stdio.h>

// max 16 bit unsigned integer nummber 65535
#define MAX_16BIT_NUM_AS_STRING_SIZE  6

static bool config_get_by_version(const json_object *obj, int version_major,
				  int version_minor, json_object **value)
{
	char str_key[MAX_16BIT_NUM_AS_STRING_SIZE];
	char str_subkey[MAX_16BIT_NUM_AS_STRING_SIZE];

	snprintf(str_key, sizeof(str_key), "%d", version_major);
	snprintf(str_subkey, sizeof(str_subkey), "%d", version_minor);
	json_object *major_obj = NULL;

	if (!json_object_object_get_ex(obj, str_key, &major_obj))
		return false;
	if  (!json_object_object_get_ex(major_obj, str_subkey, value))
		return false;
	return value != NULL;
}

bool solidigm_config_get_by_token_version(const json_object *obj, int token_id,
					  int version_major, int version_minor,
					  json_object **value)
{
	json_object *token_obj = NULL;
	char str_key[MAX_16BIT_NUM_AS_STRING_SIZE];

	snprintf(str_key, sizeof(str_key), "%d", token_id);
	if (!json_object_object_get_ex(obj, str_key, &token_obj))
		return false;
	if  (!config_get_by_version(token_obj, version_major, version_minor, value))
		return false;
	return value != NULL;
}
