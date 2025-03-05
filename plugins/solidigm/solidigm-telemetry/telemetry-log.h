/* SPDX-License-Identifier: MIT */
/*
 * Copyright (c) 2022 Solidigm.
 *
 * Author: leonardo.da.cunha@solidigm.com
 */

#ifndef _SOLIDIGM_TELEMETRY_LOG_H
#define _SOLIDIGM_TELEMETRY_LOG_H

#include "libnvme.h"
#include "util/json.h"
#include <assert.h>
#include <stdbool.h>

#if !defined __cplusplus
#define static_assert _Static_assert
#endif

#define VA_ARGS(...), ##__VA_ARGS__
#define SOLIDIGM_LOG_WARNING(format, ...) fprintf(stderr, format"\n" VA_ARGS(__VA_ARGS__))

#define MEMBER_SIZE(type, member) sizeof(((type *)0)->member)

struct telemetry_log {
	struct nvme_telemetry_log *log;
	size_t log_size;
	struct json_object *root;
	struct json_object *configuration;
	bool is_ocp;
};

#endif /* _SOLIDIGM_TELEMETRY_LOG_H */
