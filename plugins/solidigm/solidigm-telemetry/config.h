/* SPDX-License-Identifier: MIT-0 */
/*
 * Copyright (c) 2022 Solidigm.
 *
 * Author: leonardo.da.cunha@solidigm.com
 */
#include <stdbool.h>
#include "util/json.h"

bool solidigm_config_get_by_token_version(const json_object *obj, int key, int subkey, int subsubkey, json_object **value);
