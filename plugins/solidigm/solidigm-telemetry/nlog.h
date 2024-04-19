/* SPDX-License-Identifier: MIT */
/*
 * Copyright (c) 2023 Solidigm.
 *
 * Author: leonardo.da.cunha@solidigm.com
 */
#include "telemetry-log.h"

int solidigm_nlog_parse(const char *buffer, uint64_t bufer_size,
			struct json_object *formats, struct json_object *metadata,
			struct json_object *output);
