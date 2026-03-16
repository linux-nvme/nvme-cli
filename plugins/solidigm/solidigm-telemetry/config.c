// SPDX-License-Identifier: MIT
/*
 * Copyright (c) 2022 Solidigm.
 *
 * Author: leonardo.da.cunha@solidigm.com
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <json.h>

#include "config.h"
#include "telemetry-log.h"

#define NOT_FOUND "NOT_FOUND"

// max 16 bit unsigned integer number 65535
#define MAX_16BIT_NUM_AS_STRING_SIZE  6

#define OBJ_NAME_PREFIX "UID_"
#define NLOG_OBJ_PREFIX OBJ_NAME_PREFIX "NLOG_"

static bool config_get_by_version(const struct json_object *obj,
				   const char *key,
				   int version_major, int version_minor,
				   struct json_object **value)
{
	char str_key[MAX_16BIT_NUM_AS_STRING_SIZE];
	char str_subkey[MAX_16BIT_NUM_AS_STRING_SIZE];

	snprintf(str_key, sizeof(str_key), "%d", version_major);
	snprintf(str_subkey, sizeof(str_subkey), "%d", version_minor);
	struct json_object *major_obj = NULL;

	/* Try exact major version match first */
	if (json_object_object_get_ex(obj, str_key, &major_obj)) {
		/* Try exact minor version match first */
		if (json_object_object_get_ex(major_obj, str_subkey, value))
			return value != NULL;

		/* Try wildcard minor version if exact match failed */
		if (json_object_object_get_ex(major_obj, "*", value))
			return value != NULL;

		SOLIDIGM_LOG_WARNING(
			"Warning: Object %s version major %d found but minor %d not found\n",
			key, version_major, version_minor);
	}

	/* Try wildcard major version if exact major version not found */
	if (json_object_object_get_ex(obj, "*", &major_obj)) {
		/* Try exact minor version match */
		if (json_object_object_get_ex(major_obj, str_subkey, value))
			return value != NULL;

		/* Try wildcard minor version */
		if (json_object_object_get_ex(major_obj, "*", value))
			return value != NULL;
	}

	return false;
}

bool sldm_config_get_struct_by_key_version(const struct json_object *config, char *key,
					  int version_major, int version_minor,
					  struct json_object **value)
{
	struct json_object *token = NULL;

	if (!json_object_object_get_ex(config, key, &token))
		return false;
	if (!config_get_by_version(token, key,
				   version_major, version_minor, value))
		return false;
	return value != NULL;
}

bool solidigm_config_get_struct_by_token_version(const struct json_object *config, int token_id,
					  int version_major, int version_minor,
					  struct json_object **value)
{
	char str_key[MAX_16BIT_NUM_AS_STRING_SIZE];

	snprintf(str_key, sizeof(str_key), "%d", token_id);
	return sldm_config_get_struct_by_key_version(config, str_key,
						      version_major, version_minor, value);
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
	if (!name || strncmp(NLOG_OBJ_PREFIX, name, strlen(NLOG_OBJ_PREFIX)))
		return NULL;

	return &name[strlen(OBJ_NAME_PREFIX)];
}

struct json_object *solidigm_config_get_nlog_formats(const struct json_object *config)
{
	struct json_object *nlog_formats = NULL;

	json_object_object_get_ex(config, "NLOG_FORMATS", &nlog_formats);
	return nlog_formats;
}

/* Enum value lookup helper functions */
static const char *find_enum_value_in_member_list(
					struct json_object *enum_member_list,
					uint64_t value)
{
	if (!json_object_is_type(enum_member_list, json_type_array))
		return UNKNOWN_ENUM_VALUE;

	int enum_array_len = json_object_array_length(enum_member_list);

	for (int j = 0; j < enum_array_len; j++) {
		struct json_object *enum_item =
			json_object_array_get_idx(enum_member_list, j);

		if (!enum_item)
			continue;

		json_object_object_foreach(enum_item, key, val) {
			(void)key; /* Suppress unused variable warning */
			if (json_object_get_uint64(val) == value)
				return key;
		}
	}
	return UNKNOWN_ENUM_VALUE;
}

static bool is_target_enum_field(struct json_object *member,
				   const char *enum_field_name)
{
	struct json_object *name_obj, *enum_obj;

	if (!json_object_object_get_ex(member, "name", &name_obj) ||
	    !json_object_object_get_ex(member, "enum", &enum_obj))
		return false;

	const char *name = json_object_get_string(name_obj);
	int is_enum = json_object_get_int(enum_obj);

	return (strcmp(name, enum_field_name) == 0 && is_enum == 1);
}

static const char *search_enum_in_member(struct json_object *member,
					  const char *enum_field_name,
					  uint64_t value)
{
	if (!is_target_enum_field(member, enum_field_name))
		return NOT_FOUND;

	/* Found the enum field, look for the value in its memberList */
	struct json_object *enum_member_list;

	if (!json_object_object_get_ex(member, "memberList", &enum_member_list))
		return UNKNOWN_ENUM_VALUE;

	return find_enum_value_in_member_list(enum_member_list, value);
}

const char *sldm_get_enum_label_by_value(struct json_object *struct_def,
					  const char *enum_field_name,
					  uint64_t value)
{
	struct json_object *member_list;

	if (!json_object_object_get_ex(struct_def, "memberList", &member_list))
		return UNKNOWN_ENUM_VALUE;

	if (!json_object_is_type(member_list, json_type_array))
		return UNKNOWN_ENUM_VALUE;

	int array_len = json_object_array_length(member_list);

	for (int i = 0; i < array_len; i++) {
		struct json_object *member =
			json_object_array_get_idx(member_list, i);

		if (!member)
			continue;

		/* Try to find enum in this member */
		const char *result = search_enum_in_member(member,
							   enum_field_name,
							   value);

		if (strcmp(result, NOT_FOUND) != 0)
			return result; /* Found it or determined it's unknown */

		/* If this member has nested members, search recursively */
		result = sldm_get_enum_label_by_value(member, enum_field_name,
						      value);
		if (strcmp(result, UNKNOWN_ENUM_VALUE) != 0)
			return result;
	}

	return UNKNOWN_ENUM_VALUE;
}
