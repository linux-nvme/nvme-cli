/* SPDX-License-Identifier: MIT */
/*
 * Copyright (c) 2022 Solidigm.
 *
 * Author: leonardo.da.cunha@solidigm.com
 */

#include "telemetry-log.h"

bool sldm_uint8_array_to_string(const uint8_t *data_ptr, uint32_t array_size,
				 struct json_object **str_obj);
bool solidigm_telemetry_log_header_parse(const struct telemetry_log *tl);
