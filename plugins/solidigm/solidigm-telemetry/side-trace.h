/* SPDX-License-Identifier: MIT */
/*
 * Copyright (c) 2026 Solidigm.
 *
 * Author: leonardo.da.cunha@solidigm.com
 */

#include "telemetry-log.h"

int sldm_parse_side_trace(const struct telemetry_log *tl,
			     uint64_t file_offset,
			     uint32_t size_bytes,
			     struct json_object *output,
			     struct json_object *metadata);

