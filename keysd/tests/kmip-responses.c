// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include "kmip-responses.h"

void begin_response_version(struct ttlv_buf *b, int32_t major,
		int32_t minor, int32_t batch_count, uint32_t op,
		uint32_t status)
{
	ttlv_buf_init(b);
	ttlv_begin(b, KMIP_TAG_RESPONSE_MESSAGE);
	ttlv_begin(b, KMIP_TAG_RESPONSE_HEADER);
	ttlv_begin(b, KMIP_TAG_PROTOCOL_VERSION);
	ttlv_add_int(b, KMIP_TAG_PROTOCOL_VERSION_MAJOR, major);
	ttlv_add_int(b, KMIP_TAG_PROTOCOL_VERSION_MINOR, minor);
	ttlv_end(b);
	ttlv_add_date_time(b, KMIP_TAG_TIME_STAMP, 1760000000);
	ttlv_add_int(b, KMIP_TAG_BATCH_COUNT, batch_count);
	ttlv_end(b);
	ttlv_begin(b, KMIP_TAG_BATCH_ITEM);
	if (op)
		ttlv_add_enum(b, KMIP_TAG_OPERATION, op);
	ttlv_add_enum(b, KMIP_TAG_RESULT_STATUS, status);
}

void begin_response(struct ttlv_buf *b, int32_t batch_count,
		uint32_t op, uint32_t status)
{
	begin_response_version(b, 1, 4, batch_count, op, status);
}

void end_response(struct ttlv_buf *b)
{
	ttlv_end(b);	// Batch Item
	ttlv_end(b);	// Response Message
}

void locate_response(struct ttlv_buf *b, int n)
{
	static const char *const uids[] = { "uid-1", "uid-2" };

	begin_response(b, 1, KMIP_OP_LOCATE, KMIP_STATUS_SUCCESS);
	ttlv_begin(b, KMIP_TAG_RESPONSE_PAYLOAD);
	for (int i = 0; i < n; i++)
		ttlv_add_text(b, KMIP_TAG_UNIQUE_IDENTIFIER, uids[i]);
	ttlv_end(b);
	end_response(b);
}

void get_response(struct ttlv_buf *b, uint32_t obj_type,
		uint32_t obj_tag, uint32_t format, const void *key, size_t len)
{
	begin_response(b, 1, KMIP_OP_GET, KMIP_STATUS_SUCCESS);
	ttlv_begin(b, KMIP_TAG_RESPONSE_PAYLOAD);
	ttlv_add_enum(b, KMIP_TAG_OBJECT_TYPE, obj_type);
	ttlv_add_text(b, KMIP_TAG_UNIQUE_IDENTIFIER, "uid-1");
	ttlv_begin(b, obj_tag);
	if (obj_type == KMIP_OBJ_SECRET_DATA)
		ttlv_add_enum(b, 0x420086, 1);	// Secret Data Type: Password
	ttlv_begin(b, KMIP_TAG_KEY_BLOCK);
	ttlv_add_enum(b, KMIP_TAG_KEY_FORMAT_TYPE, format);
	ttlv_begin(b, KMIP_TAG_KEY_VALUE);
	ttlv_add_bytes(b, KMIP_TAG_KEY_MATERIAL, key, len);
	ttlv_end(b);
	ttlv_end(b);
	ttlv_end(b);
	ttlv_end(b);
	end_response(b);
}
