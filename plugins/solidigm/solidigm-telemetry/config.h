/* SPDX-License-Identifier: MIT */
/*
 * Copyright (c) 2022 Solidigm.
 *
 * Author: leonardo.da.cunha@solidigm.com
 */
#include <stdbool.h>
#include "util/json.h"

bool solidigm_config_get_by_token_version(const struct json_object *obj,
					  int key, int subkey,
					  int subsubkey,
					  struct json_object **value);
