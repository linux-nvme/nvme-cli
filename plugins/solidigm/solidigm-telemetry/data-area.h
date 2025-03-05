/* SPDX-License-Identifier: MIT */
/*
 * Copyright (c) 2022 Solidigm.
 *
 * Author: leonardo.da.cunha@solidigm.com
 */
#include "telemetry-log.h"

int solidigm_telemetry_log_data_areas_parse(struct telemetry_log *tl,
					    enum nvme_telemetry_da last_da);
void solidigm_telemetry_log_da1_check_ocp(struct telemetry_log *tl);
