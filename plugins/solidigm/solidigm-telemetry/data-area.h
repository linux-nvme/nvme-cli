/* SPDX-License-Identifier: MIT */
/*
 * Copyright (c) 2022 Solidigm.
 *
 * Author: leonardo.da.cunha@solidigm.com
 */
#ifndef __SOLIDIGM_DATA_AREA_H__
#define __SOLIDIGM_DATA_AREA_H__

#include "telemetry-log.h"

#define NUM_BITS_IN_BYTE 8

int solidigm_telemetry_log_data_areas_parse(struct telemetry_log *tl,
					    enum nvme_telemetry_da last_da);
void solidigm_telemetry_log_da1_check_ocp(struct telemetry_log *tl);
int sldm_telemetry_structure_parse(const struct telemetry_log *tl,
					 struct json_object *struct_def,
					 uint64_t parent_offset_bit,
					 struct json_object *output,
					 struct json_object *metadata);

#endif /* __SOLIDIGM_DATA_AREA_H__ */
