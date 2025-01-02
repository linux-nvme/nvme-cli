// SPDX-License-Identifier: MIT
/*
 * Copyright (c) 2022 Solidigm.
 *
 * Author: leonardo.da.cunha@solidigm.com
 */

#include <stdio.h>
#include <string.h>
#include "config.h"

// max 16 bit unsigned integer number 65535
#define MAX_16BIT_NUM_AS_STRING_SIZE  6

#define OBJ_NAME_PREFIX "UID_"
#define NLOG_OBJ_PREFIX OBJ_NAME_PREFIX "NLOG_"

static bool config_get_by_version(const struct json_object *obj, int version_major,
				  int version_minor, struct json_object **value)
{
	char str_key[MAX_16BIT_NUM_AS_STRING_SIZE];
	char str_subkey[MAX_16BIT_NUM_AS_STRING_SIZE];

	snprintf(str_key, sizeof(str_key), "%d", version_major);
	snprintf(str_subkey, sizeof(str_subkey), "%d", version_minor);
	struct json_object *major_obj = NULL;

	if (!json_object_object_get_ex(obj, str_key, &major_obj))
		return false;
	if  (!json_object_object_get_ex(major_obj, str_subkey, value))
		return false;
	return value != NULL;
}

bool solidigm_config_get_struct_by_token_version(const struct json_object *config, int token_id,
					  int version_major, int version_minor,
					  struct json_object **value)
{
	struct json_object *token = NULL;
	char str_key[MAX_16BIT_NUM_AS_STRING_SIZE];

	snprintf(str_key, sizeof(str_key), "%d", token_id);
	if (!json_object_object_get_ex(config, str_key, &token))
		return false;
	if  (!config_get_by_version(token, version_major, version_minor, value))
		return false;
	return value != NULL;
}

const char *solidigm_config_get_nlog_obj_name(const struct json_object *config, uint32_t token)
{
	struct json_object *nlog_names = NULL;
	struct json_object *obj_name;
	char hex_header[STR_HEX32_SIZE];
	const char *name;

	if (!json_object_object_get_ex(config, "TELEMETRY_OBJECT_UIDS", &nlog_names))
		return NULL;
	snprintf(hex_header, STR_HEX32_SIZE, "0x%08X", token);

	if (!json_object_object_get_ex(nlog_names, hex_header, &obj_name))
		return NULL;
	name = json_object_get_string(obj_name);
	if ((!name) || (strncmp(NLOG_OBJ_PREFIX, name, strlen(NLOG_OBJ_PREFIX))))
		return NULL;

	return &name[strlen(OBJ_NAME_PREFIX)];
}

struct json_object *solidigm_config_get_nlog_formats(const struct json_object *config)
{
	struct json_object *nlog_formats = NULL;

	json_object_object_get_ex(config, "NLOG_FORMATS", &nlog_formats);
	return nlog_formats;
}
