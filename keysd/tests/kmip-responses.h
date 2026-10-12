/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

#include "kmip.h"

/* KMIP responses for the tests. Each one initializes @b. */

/*
 * Start a response with protocol version @major.@minor, and a batch item
 * for @op (none if 0) with @status. The caller adds the rest.
 */
void begin_response_version(struct ttlv_buf *b, int32_t major,
		int32_t minor, int32_t batch_count, uint32_t op,
		uint32_t status);

/* Start a KMIP 1.4 response to @op with @status. */
void begin_response(struct ttlv_buf *b, int32_t batch_count,
		uint32_t op, uint32_t status);

void end_response(struct ttlv_buf *b);

/* A successful Locate response with @n Unique Identifiers (at most 2). */
void locate_response(struct ttlv_buf *b, int n);

/*
 * A successful Get response, as in the KMIP 1.4 test case
 * TC-CREATE-SD-1-14.
 */
void get_response(struct ttlv_buf *b, uint32_t obj_type,
		uint32_t obj_tag, uint32_t format, const void *key, size_t len);
