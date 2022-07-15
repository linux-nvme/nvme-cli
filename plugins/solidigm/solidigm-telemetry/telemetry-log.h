// SPDX-License-Identifier: MIT-0
/*
 * Copyright (c) 2022 Solidigm.
 *
 * Author: leonardo.da.cunha@solidigm.com
 */

#ifndef _SOLIDIGM_TELEMETRY_LOG_H
#define _SOLIDIGM_TELEMETRY_LOG_H

#include "libnvme.h"
#include "util/json.h"

struct telemetry_log {
	struct nvme_telemetry_log *log;
	size_t log_size;
	json_object *root;
};

#endif /* _SOLIDIGM_TELEMETRY_LOG_H */