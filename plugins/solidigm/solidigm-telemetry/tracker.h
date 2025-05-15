/* SPDX-License-Identifier: MIT */
/*
 * Copyright (c) 2025 Solidigm.
 *
 * Author: leonardo.da.cunha@solidigm.com
 */

#ifndef SOLIDIGM_TELEMETRY_TRACKER_H
#define SOLIDIGM_TELEMETRY_TRACKER_H

#include "telemetry-log.h"

void sldm_tracker_parse(struct telemetry_log *tl, uint32_t offset,
			uint32_t size, struct json_object *tracker_obj);
#endif  /* SOLIDIGM_TELEMETRY_TRACKER_H */
