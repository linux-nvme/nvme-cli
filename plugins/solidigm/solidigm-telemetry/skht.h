/* SPDX-License-Identifier: MIT */
/*
 * Copyright (c) 2025 Solidigm.
 *
 * Author: leonardo.da.cunha@solidigm.com
 */
#pragma once

#include "telemetry-log.h"
#include "util/json.h"

#define SKT_VER_MAJOR 47837
#define SKT_VER_MINOR 49374

void sldm_telemetry_check_for_skhT(struct telemetry_log *tl);
void sldm_telemetry_sktT_segment_parse(struct telemetry_log *tl,
					struct json_object *toc_array,
					struct json_object *tele_obj_array);

void sldm_telemetry_skhT_parse(struct telemetry_log *tl);
