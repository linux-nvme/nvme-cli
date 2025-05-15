/* SPDX-License-Identifier: MIT */
/*
 * Copyright (c) 2022 Solidigm.
 *
 * Author: leonardo.da.cunha@solidigm.com
 */
#include <stdbool.h>
#include "util/json.h"

#define STR_HEX32_SIZE sizeof("0x00000000")

bool sldm_config_get_struct_by_key_version(const struct json_object *config, char *key,
					  int version_major, int version_minor,
					  struct json_object **value);
bool solidigm_config_get_struct_by_token_version(const struct json_object *obj,
					  int key, int subkey,
					  int subsubkey,
					  struct json_object **value);

const char *solidigm_config_get_nlog_obj_name(const struct json_object *config, uint32_t token);
struct json_object *solidigm_config_get_nlog_formats(const struct json_object *config);

