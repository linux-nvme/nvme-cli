/* SPDX-License-Identifier: MIT */
/*
 * Copyright (c) 2025 Solidigm.
 *
 * Author: leonardo.da.cunha@solidigm.com
 */

#ifndef SLDM_DEBUG_INFO_H
#define SLDM_DEBUG_INFO_H

#include "telemetry-log.h"
#include "util/json.h"

/**
 * Parse debug info data from telemetry log

 */
int sldm_debug_info_parse(struct telemetry_log *tl, uint32_t offset, uint32_t size,
			  struct json_object *output);

#endif /* SLDM_DEBUG_INFO_H */
