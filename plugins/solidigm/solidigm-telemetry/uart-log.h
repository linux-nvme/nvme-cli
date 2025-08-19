/* SPDX-License-Identifier: MIT */
/*
 * Copyright (c) 2025 Solidigm.
 *
 * Author: leonardo.da.cunha@solidigm.com
 */

#ifndef SLDM_UART_LOG_H
#define SLDM_UART_LOG_H

#include "telemetry-log.h"
#include "util/json.h"

int sldm_parse_cd_uart_log(struct telemetry_log *tl, uint32_t offset, uint32_t size,
			    struct json_object *output);

#endif /* SLDM_UART_LOG_H */
